package eudcc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/rs/zerolog/log"
)

// CBOR constants to assign semantic to the data structures
const (
	CBOR_Magic_ID = 55799 // Magic tag number that identifies the data as CBOR-encoded
	COSE_Sign     = 98    // COSE Signed Data Object (multiple signers)
	COSE_Sign1    = 18    // COSE Single Signer Data Object
	CWT_Tag       = 61
)

var spaces string = "| | | | | | | | | | | | | | | | | | | | | | | | | | | | "

// Major types encoding
const (
	MT_INTEGER    = 0
	MT_NEGINTEGER = 1
	MT_BYTES      = 2
	MT_UTF8       = 3
	MT_ARRAY      = 4
	MT_MAP        = 5
	MT_TAG        = 6
	MT_FLOAT      = 7
)

// String representation just for logging
var majorTypes = []string{
	"MT_INTEGER",
	"MT_NEGINTEGER",
	"MT_BYTES",
	"MT_UTF8",
	"MT_ARRAY",
	"MT_MAP",
	"MT_TAG",
	"MT_FLOAT",
}

type MapCBOR []byte
type SignatureCBOR []byte
type ArrayCBOR []byte

type CBORDecoder struct {
	s        []byte
	i        int64 // current reading index
	prevRune int   // index of previous rune; or < 0
	indent   int
}

// Reset resets the Reader to be reading from b (no allocations in reset)
func (r *CBORDecoder) Reset(b []byte) { *r = CBORDecoder{b, 0, -1, 0} }

// NewCBORDecoder returns a new CBOR reading from b.
func NewCBORDecoder(b []byte) *CBORDecoder { return &CBORDecoder{b, 0, -1, 0} }

// ReadUint8 reads one byte and returns it as a int64
func (cb *CBORDecoder) ReadUint8() (int64, error) {
	n, err := cb.ReadByte()
	if err != nil {
		return 0, err
	}
	return int64(n), nil
}

// ReadUint16 reads 2 bytes (big-endian) and returns a int64
func (cb *CBORDecoder) ReadUint16() (int64, error) {
	// Two bytes for a 16-bit unsigned integer
	raw, err := cb.ReadSlice(2)
	if err != nil {
		return 0, err
	}
	return int64(uint64(raw[0])<<8 + uint64(raw[1])), nil
}

// ReadUint32 reads 4 bytes (big-endian) and returns a int64
func (cb *CBORDecoder) ReadUint32() (int64, error) {
	raw, err := cb.ReadSlice(4)
	if err != nil {
		return 0, err
	}
	return int64(uint64(raw[0])<<24 + uint64(raw[1])<<16 + uint64(raw[2])<<8 + uint64(raw[3])), nil
}

// ReadUint64 reads 8 bytes (big-endian) and returns a int64
func (cb *CBORDecoder) ReadUint64() (int64, error) {
	raw, err := cb.ReadSlice(8)
	if err != nil {
		return 0, err
	}
	upper32 := uint64(raw[0])<<24 + uint64(raw[1])<<16 + uint64(raw[2])<<8 + uint64(raw[3])
	lower32 := uint64(raw[4])<<24 + uint64(raw[5])<<16 + uint64(raw[6])<<8 + uint64(raw[7])
	return int64(upper32<<32 + lower32), nil
}

func CBORType(c []byte) int {
	majorType := c[0] >> 5
	return int(majorType)
}

// ReadLength decodes the length field of the CBOR data element
// Uses a variable-size encoding schema
func (cb *CBORDecoder) ReadLength() (int64, error) {

	// Read the initial byte which contains the type of CBOR data element and
	// additional information related to the length
	initialByte, err := cb.ReadByte()
	if err != nil {
		return 0, err
	}
	majorType := initialByte >> 5
	// Additional info is in the least significant 5 bits
	additionalInformation := initialByte & 0x1f

	// For small data items the length is encoded in the initial byte and
	// we have enough information
	if additionalInformation < 24 {
		return int64(additionalInformation), nil
	}

	// For bigger data items we need to read aditional bytes depending on size
	switch additionalInformation {
	case 24:
		// Length is uint8
		return cb.ReadUint8()
	case 25:
		// length is a 16-bit unsigned integer
		return cb.ReadUint16()
	case 26:
		// length is a 32-bit unsigned integer
		return cb.ReadUint32()
	case 27:
		// length is a 64-bit unsigned integer
		return cb.ReadUint64()
	case 31:
		// This is for indefinite legth items (streaming)
		// Check for undefinite lengths (streaming use cases)
		// Streaming is only valid for BYTES, UTF8, ARRAY or MAP
		if (majorType < MT_BYTES) || (MT_MAP < majorType) {
			log.Error().Msg("Invalid length")
			return -1, fmt.Errorf("Invalid length")
		}

		return -1, nil
	}

	log.Error().Uint8("additionalInformation", additionalInformation).Msg("Invalid length encoding")
	return 0, nil
}

// DecodeBstr expects a CBOR bstr and gives an error otherwise
func (cb *CBORDecoder) DecodeBstr() ([]byte, error) {

	// Get the initial byte, which should define a bstr (BYTES) object
	initialByte, err := cb.PeekByte()
	if err != nil {
		return nil, err
	}
	majorType := initialByte >> 5

	// Check for a bstr
	if majorType != MT_BYTES {
		return nil, fmt.Errorf("COSE object should be a CBOR bstr object (%v), but type is %v", MT_BYTES, majorType)
	}

	// Read the length associated to the item
	length, err := cb.ReadLength()
	if err != nil {
		return nil, err
	}

	return cb.ReadSlice(int(length))

}

// DecodeMap expects a CBOR Map and gives an error otherwise
func (cb *CBORDecoder) DecodeMap() (map[any]any, error) {

	// Get the initial byte, which should define a bstr (BYTES) object
	initialByte, err := cb.PeekByte()
	if err != nil {
		return nil, err
	}
	majorType := initialByte >> 5

	// Check for a map
	if majorType != MT_MAP {
		return nil, fmt.Errorf("COSE object should be a CBOR Map object (%v), but type is %v", MT_MAP, majorType)
	}

	ret, err := cb.DecodeItem()
	if err != nil {
		return nil, err
	}

	// We already did the type check, so no need to check for casting error
	return ret.(map[any]any), nil

}

// DecodeItem decodes a CBOR item of unknown data type.
// We look at the first byte to determine type and length of the object.
// It returns any and the caller should use type casting to determine the actual type
func (cb *CBORDecoder) DecodeItem() (any, error) {
	initialByte, err := cb.PeekByte()
	if err != nil {
		return nil, err
	}
	majorType := initialByte >> 5
	//	additionalInformation := initialByte & 0x1f

	if majorType == MT_FLOAT {
		log.Error().Msg("FLOAT not yet supported")
		return nil, fmt.Errorf("FLOAT not yet supported")
		// switch additionalInformation {
		// case 25:
		// 	return cb.readFloat16()
		// case 26:
		// 	return cb.readFloat32()
		// case 27:
		// 	return cb.readFloat64()
		// default:
		// 	fmt.Println("Major Type: FLOAT but additional information is INCORRECT:", additionalInformation)
		// 	return nil
		// }
	}

	// Read the length associated to the item
	length, err := cb.ReadLength()
	if err != nil {
		return nil, err
	}

	// Check for undefinite lengths (streaming use cases)
	// Streaming is only valid for BYTES, UTF8, ARRAY or MAP
	if length < 0 && (majorType < MT_BYTES || MT_MAP < majorType) {
		log.Error().Msg("Invalid length")
		return nil, fmt.Errorf("Invalid length")
	}

	switch majorType {
	case MT_INTEGER:
		// In this case the length is itself the value of the object
		if debug {
			log.Printf("%vDecoding %v (%v)", spaces[:2*cb.indent], majorTypes[majorType], int64(length))
		}
		return length, nil
	case MT_NEGINTEGER:
		// Similar to INTEGER, but we have to negate it
		if debug {
			log.Printf("%vDecoding %v (%v)", spaces[:2*cb.indent], majorTypes[majorType], -1-int64(length))
		}
		return -1 - int64(length), nil
	case MT_BYTES:
		// This is a binary string, that can be returned directly
		s, err := cb.ReadSlice(int(length))
		if debug {
			log.Printf("%vDecoding %v (len %v): %v", spaces[:2*cb.indent], majorTypes[majorType], length, s)
		}
		return s, err
		// if (length < 0) {
		// 	// Handle indefinite length byte array
		// 	var elements = [];
		// 	var fullArrayLength = 0;
		// 	while ((length = readIndefiniteStringLength(majorType)) >= 0) {
		// 		fullArrayLength += length;
		// 		elements.push(readArrayBuffer(length));
		// 	}
		// 	var fullArray = new Uint8Array(fullArrayLength);
		// 	var fullArrayOffset = 0;
		// 	for (i = 0; i < elements.length; ++i) {
		// 		fullArray.set(elements[i], fullArrayOffset);
		// 		fullArrayOffset += elements[i].length;
		// 	}
		// 	return fullArray;
		// }
		// // A normal byte array
		// return readArrayBuffer(length);
	case MT_UTF8:
		// Like MT_BYTES but converted to UTF-8 strings
		rawString, err := cb.ReadSlice(int(length))
		if err != nil {
			return nil, err
		}
		if debug {
			log.Printf("%vDecoding %v (len %v): %v", spaces[:2*cb.indent], majorTypes[majorType], length, string(rawString))
		}
		return string(rawString), nil
		// var utf16data = [];
		// if (length < 0) {
		// 	// Handle indefinite length utf8 strings
		// 	while ((length = readIndefiniteStringLength(majorType)) >= 0)
		// 		appendUtf16Data(utf16data, length);
		// } else {
		// 	// Normal utf8 strings
		// 	appendUtf16Data(utf16data, length);
		// }
		// return String.fromCharCode.apply(null, utf16data);
	case MT_ARRAY:
		if debug {
			log.Printf("%vDecoding %v (%v)", spaces[:2*cb.indent], majorTypes[majorType], length)
		}
		// It is an array of objects, each can be different
		// We call recursively decodeItem for each object in the array
		var retArray []any
		cb.indent += 1
		for i := int64(0); i < length; i++ {
			var item any
			item, err = cb.DecodeItem()
			if err != nil {
				return nil, err
			}
			retArray = append(retArray, item)
		}
		cb.indent -= 1
		return retArray, nil

		// var retArray;
		// if (length < 0) {
		// 	// Handle indefinite length arrays
		// 	console.log("INDEFINITE LENGTH ARRAY");
		// 	retArray = [];
		// 	while (!readBreak()) retArray.push(decodeItem());
		// } else {
		// 	// Normal arrays
		// 	retArray = new Array(length);
		// 	for (i = 0; i < length; ++i) retArray[i] = decodeItem();
		// }
		// return retArray;
	case MT_MAP:
		if debug {
			log.Printf("%vDecoding %v (%v)", spaces[:2*cb.indent], majorTypes[majorType], length)
		}
		// Is an array of key, value objects
		var retMap = make(map[any]any, length)
		cb.indent += 1
		for i := int64(0); i < length; i++ {
			var key, value any
			key, err = cb.DecodeItem()
			if err != nil {
				return nil, err
			}
			value, err = cb.DecodeItem()
			if err != nil {
				return nil, err
			}
			retMap[key] = value
			if debug {
				log.Printf("%v--------", spaces[:2*cb.indent])
			}
		}
		cb.indent -= 1
		return retMap, nil
		// for (i = 0; i < length || (length < 0 && !readBreak()); ++i) {
		// 	var key = decodeItem();
		// 	retMap.set(key, decodeItem());
		// }
		// return retMap;
	case MT_TAG:
		panic("MT_TAG not implemented yet")
		// return tagger(decodeItem(), length);
	case 7:
		switch length {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22:
			return nil, nil
		case 23:
			return nil, nil
		default:
			return nil, nil
		}

		// switch (length) {
		// 	case 20:
		// 		return false;
		// 	case 21:
		// 		return true;
		// 	case 22:
		// 		return null;
		// 	case 23:
		// 		return undefined;
		// 	default:
		// 		return simpleValue(length);
		// }

	default:
		return nil, fmt.Errorf("Major type not recognized")

	}

}

// Len returns the number of bytes of the unread portion of the internal slice.
func (r *CBORDecoder) Len() int {
	if r.i >= int64(len(r.s)) {
		return 0
	}
	return int(int64(len(r.s)) - r.i)
}

// Size returns the original length of the underlying byte slice.
// Size is the number of bytes available for reading via ReadAt.
// The returned value is always the same and is not affected by calls
// to any other method.
func (r *CBORDecoder) Size() int64 { return int64(len(r.s)) }

// Read implements the io.Reader interface.
func (r *CBORDecoder) Read(b []byte) (n int, err error) {
	if r.i >= int64(len(r.s)) {
		return 0, io.EOF
	}
	r.prevRune = -1
	n = copy(b, r.s[r.i:])
	r.i += int64(n)
	return
}

// ReadSlice does not copy. Must be used only if original buffer is immutable.
func (r *CBORDecoder) ReadSlice(n int) (s []byte, err error) {
	if r.i+int64(n) > int64(len(r.s)) {
		return nil, io.EOF
	}
	r.prevRune = -1
	s = r.s[r.i : r.i+int64(n)]
	r.i += int64(n)
	return
}

// ReadAt implements the io.ReaderAt interface.
func (r *CBORDecoder) ReadAt(b []byte, off int64) (n int, err error) {
	// cannot modify state - see io.ReaderAt
	if off < 0 {
		return 0, errors.New("bytes.Reader.ReadAt: negative offset")
	}
	if off >= int64(len(r.s)) {
		return 0, io.EOF
	}
	n = copy(b, r.s[off:])
	if n < len(b) {
		err = io.EOF
	}
	return
}

// ReadByte implements the io.ByteReader interface.
func (r *CBORDecoder) ReadByte() (byte, error) {
	r.prevRune = -1
	if r.i >= int64(len(r.s)) {
		return 0, io.EOF
	}
	b := r.s[r.i]
	r.i++
	return b, nil
}

// PeekByte returns one byte without consuming it.
func (r *CBORDecoder) PeekByte() (byte, error) {
	r.prevRune = -1
	if r.i >= int64(len(r.s)) {
		return 0, io.EOF
	}
	b := r.s[r.i]
	return b, nil
}

// UnreadByte complements ReadByte in implementing the io.ByteScanner interface.
func (r *CBORDecoder) UnreadByte() error {
	if r.i <= 0 {
		return errors.New("bytes.Reader.UnreadByte: at beginning of slice")
	}
	r.prevRune = -1
	r.i--
	return nil
}

// ReadRune implements the io.RuneReader interface.
func (r *CBORDecoder) ReadRune() (ch rune, size int, err error) {
	if r.i >= int64(len(r.s)) {
		r.prevRune = -1
		return 0, 0, io.EOF
	}
	r.prevRune = int(r.i)
	if c := r.s[r.i]; c < utf8.RuneSelf {
		r.i++
		return rune(c), 1, nil
	}
	ch, size = utf8.DecodeRune(r.s[r.i:])
	r.i += int64(size)
	return
}

// UnreadRune complements ReadRune in implementing the io.RuneScanner interface.
func (r *CBORDecoder) UnreadRune() error {
	if r.i <= 0 {
		return errors.New("bytes.Reader.UnreadRune: at beginning of slice")
	}
	if r.prevRune < 0 {
		return errors.New("bytes.Reader.UnreadRune: previous operation was not ReadRune")
	}
	r.i = int64(r.prevRune)
	r.prevRune = -1
	return nil
}

// Seek implements the io.Seeker interface.
func (r *CBORDecoder) Seek(offset int64, whence int) (int64, error) {
	r.prevRune = -1
	var abs int64
	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = r.i + offset
	case io.SeekEnd:
		abs = int64(len(r.s)) + offset
	default:
		return 0, errors.New("bytes.Reader.Seek: invalid whence")
	}
	if abs < 0 {
		return 0, errors.New("bytes.Reader.Seek: negative position")
	}
	r.i = abs
	return abs, nil
}

// WriteTo implements the io.WriterTo interface.
func (r *CBORDecoder) WriteTo(w io.Writer) (n int64, err error) {
	r.prevRune = -1
	if r.i >= int64(len(r.s)) {
		return 0, nil
	}
	b := r.s[r.i:]
	m, err := w.Write(b)
	if m > len(b) {
		panic("bytes.Reader.WriteTo: invalid Write count")
	}
	r.i += int64(m)
	n = int64(m)
	if m != len(b) && err == nil {
		err = io.ErrShortWrite
	}
	return
}

// 	MT_INTEGER    = 0
// 	MT_NEGINTEGER = 1
// 	MT_BYTES      = 2
// 	MT_UTF8       = 3
// 	MT_ARRAY      = 4
// 	MT_MAP        = 5
// 	MT_TAG        = 6
// 	MT_FLOAT      = 7

type CBOREncoder struct {
	t         bytes.Buffer
	lastError error
}

func NewCBOREncoder() *CBOREncoder {
	enc := &CBOREncoder{}
	return enc
}

func (ce *CBOREncoder) Reset() *CBOREncoder {
	ce.t.Reset()
	ce.lastError = nil
	return ce
}

func (ce *CBOREncoder) Bytes() []byte {
	return ce.t.Bytes()
}

func (ce *CBOREncoder) EncodeAny(item any) *CBOREncoder {
	switch item.(type) {
	case int64:
		ce.EncodeInteger(item.(int64))
	case int:
		ce.EncodeInteger(int64(item.(int)))
	case []byte:
		ce.EncodeBytes(item.([]byte))
	case string:
		ce.EncodeString(item.(string))
	case []any:
		ce.EncodeArray(item.([]any))
	case map[any]any:
		ce.EncodeMap(item.(map[any]any))
	case MapCBOR:
		// Nothing to do, just write to the buffer
		b := []byte(item.(MapCBOR))
		if debug {
			log.Debug().Msgf("Encode MapCBOR: %v", b)
		}
		ce.t.Write(b)
	default:
		ce.lastError = fmt.Errorf("Unrecognized type %T for encoding", item)
		log.Error().Err(ce.lastError).Msg("")
	}

	return ce
}

func (ce *CBOREncoder) EncodeArray(sourceArray []any) *CBOREncoder {
	majorType := byte(MT_ARRAY << 5)
	length := len(sourceArray)
	if debug {
		log.Debug().Msgf("Enter EncodeArray of length %v", length)
		defer log.Debug().Msgf("Exit EncodeArray")
	}
	ce.encodeLength(majorType, int64(length))

	for i := range sourceArray {
		ce.EncodeAny(sourceArray[i])
	}

	return ce
}

func (ce *CBOREncoder) EncodeBytes(sourceBstr []byte) *CBOREncoder {
	majorType := byte(MT_BYTES << 5)
	length := len(sourceBstr)
	if debug {
		log.Debug().Msgf("Encoding Bytes of length %v: %v", length, sourceBstr)
	}
	ce.encodeLength(majorType, int64(length))
	ce.t.Write(sourceBstr)

	return ce
}

func (ce *CBOREncoder) EncodeString(sourceString string) *CBOREncoder {
	majorType := byte(MT_UTF8 << 5)
	length := len(sourceString)
	if debug {
		log.Debug().Msgf("Encoding String of length %v: %v", length, sourceString)
	}
	ce.encodeLength(majorType, int64(length))
	ce.t.WriteString(sourceString)

	return ce
}

func (ce *CBOREncoder) EncodeMap(sourceMap map[any]any) *CBOREncoder {
	majorType := byte(MT_MAP << 5)
	length := len(sourceMap)
	if debug {
		log.Debug().Msgf("Enter EncodeMap of length %v", length)
		defer log.Debug().Msgf("Exit EncodeMap")
	}
	ce.encodeLength(majorType, int64(length))

	for k, v := range sourceMap {
		if debug {
			log.Debug().Msgf("Encoding key: (%v)", k)
		}
		ce.EncodeAny(k)
		if debug {
			log.Debug().Msgf("Finished Encoding key: (%v)", k)
		}
		if debug {
			log.Debug().Msgf("Encoding value: (%v)", v)
		}
		ce.EncodeAny(v)
		if debug {
			log.Debug().Msgf("Finished Encoding value: (%v)", v)
		}
	}

	return ce
}

func (ce *CBOREncoder) EncodeInteger(val int64) *CBOREncoder {
	var headArray [9]byte
	head := headArray[:]
	var majorType byte

	if debug {
		log.Debug().Msgf("Encoding Integer: %v", val)
	}

	majorType = MT_INTEGER << 5

	if val < 0 {
		majorType = MT_NEGINTEGER << 5
		val = -1 - val
	}

	switch {
	case val < 24:
		if debug {
			log.Debug().Msgf("Encoding Integer in 0 byte: %v", val)
		}
		ce.t.WriteByte(majorType + byte(val))
	case val <= 0xFF:
		if debug {
			log.Debug().Msgf("Encoding Integer in 1 byte: %v", val)
		}
		head[0] = majorType + 0x18
		head[1] = byte(val)
		ce.t.Write(head[:2])
	case val <= 0xFFFF:
		head[0] = majorType + 0x19
		log.Debug().Msgf("Head[0]: %v", head[0])

		binary.BigEndian.PutUint16(head[1:], uint16(val))
		if debug {
			log.Debug().Msgf("Encoding %v in 2 bytes: %v", val, head[:3])
		}
		ce.t.Write(head[:3])
	case val <= 0xFFFFFFFF:
		head[0] = majorType + 0x1A
		binary.BigEndian.PutUint32(head[1:], uint32(val))
		if debug {
			log.Debug().Msgf("Encoding %v in 4 bytes: %v", val, head[:5])
		}
		ce.t.Write(head[:5])
	default:
		head[0] = majorType + 0x1B
		binary.BigEndian.PutUint64(head[1:], uint64(val))
		if debug {
			log.Debug().Msgf("Encoding %v in 8 bytes: %v", val, head[:9])
		}
		ce.t.Write(head[:9])
	}

	if debug {
		log.Debug().Msgf("Updated Buffer: %v", ce.Bytes())
	}

	return ce
}

func (ce *CBOREncoder) encodeLength(majorType byte, length int64) {
	var headArray [9]byte
	head := headArray[:]
	if debug {
		log.Debug().Msgf("Major type: %v", majorType)
	}

	switch {
	case length < 24:
		if debug {
			log.Debug().Msgf("Encoding length in 0 byte: %v", length)
		}
		ce.t.WriteByte(majorType + byte(length))
	case length <= 0xFF:
		if debug {
			log.Debug().Msgf("Encoding length in 1 byte: %v", length)
		}
		head[0] = majorType + 0x18
		head[1] = byte(length)
		ce.t.Write(head[:2])
	case length <= 0xFFFF:
		head[0] = majorType + 0x19
		log.Debug().Msgf("Head[0]: %v", head[0])

		binary.BigEndian.PutUint16(head[1:], uint16(length))
		if debug {
			log.Debug().Msgf("Encoding %v in 2 bytes: %v", length, head[:3])
		}
		ce.t.Write(head[:3])
	case length <= 0xFFFFFFFF:
		head[0] = majorType + 0x1A
		binary.BigEndian.PutUint32(head[1:], uint32(length))
		if debug {
			log.Debug().Msgf("Encoding %v in 4 bytes: %v", length, head[:5])
		}
		ce.t.Write(head[:5])
	default:
		head[0] = majorType + 0x1B
		binary.BigEndian.PutUint64(head[1:], uint64(length))
		if debug {
			log.Debug().Msgf("Encoding %v in 8 bytes: %v", length, head[:9])
		}
		ce.t.Write(head[:9])
	}
}
