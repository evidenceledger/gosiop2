package eudcc

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog/log"
)

// Protected headers numeric claim types
const CWT_ALG = 1
const CWT_KID = 4

// String representation of the header claims, for decoding into familiar JWT names
var headerNameMapping = map[uint64]any{
	CWT_ALG: "alg",
	CWT_KID: "kid",
}

// Mapping from COSE/CWT numeric claims to string algorithm name
var algsFromCWTtoJWT = map[int64]string{
	-7:  "ES256",
	-37: "RSA",
}

var algsFromJWTtoCWT = map[string]int{
	"ES256": -7,
	"RSA":   -37,
}

// CWT is the basic structure for CWT functionality.
// It can be used by embedding it in a struct defining the additional claims required
// by the application.
type CWT struct {

	// The raw token.  Populated when you Parse a token
	Raw []byte `json:"-"`

	// These are the 4 components of a CWT, as per the specification
	CBORProtectedHeaders   MapCBOR       `json:"-"` // The headers as a CBOR bstr
	CBORUnprotectedHeaders map[any]any   `json:"-"` // The unprotected headers as a map
	CBORPayload            MapCBOR       `json:"-"` // The payload as a bstr
	CBORSignature          SignatureCBOR `json:"-"` // The signature as a bstr

	// The headers as a JWT-style map, once they are decoded from CBOR binary
	// ProtectedHeaders map[string]string
	ProtectedHeaders *ProtectedHeaders

	// The signing method, both for verifying and signing
	Method Signer

	// Is the token valid?  Populated when you Parse/Verify a token
	Valid bool // Is the token valid?  Populated when you Parse/Verify a token
}

type ProtectedHeaders struct {
	Alg string
	Kid string
	// The signing method, both for verifying and signing
	Method Signer
}

func ProtectedHeadersFromCBOR(CBORProtectedHeaders MapCBOR) (ph *ProtectedHeaders) {

	ph = &ProtectedHeaders{}

	// Convert headers from CBOR format to a map
	if debug {
		log.Printf("Decoding Protected Headers: %v", CBORProtectedHeaders)
	}
	intermediateHeaders, err := NewCBORDecoder(CBORProtectedHeaders).DecodeMap()
	if err != nil {
		return ph
	}
	if debug {
		log.Printf("Type of Protected Headers: %T", intermediateHeaders)
	}

	for k, v := range intermediateHeaders {
		// Keys are always int64
		switch k.(int64) {
		case CWT_ALG:
			// This is the method used to sign the CWT

			// Convert the numeric code to the string equivalent in JWT
			alg := algsFromCWTtoJWT[v.(int64)]

			// Check if the method is available in the binary
			method := GetSigner(alg)
			if !method.Available() {
				log.Error().Str("method", alg).Msg("Signing method is not available")
			}

			// Store the alg and method for later use in verifying the signature
			ph.Alg = alg
			ph.Method = method

		case CWT_KID:
			// This is the key identifier, used to retrieve the Public Key

			// Must encode raw bytes of the Kid to Base64
			rawKid := v.([]byte)
			if debug {
				log.Printf(">>>>>>>>>>>>>>>>>>>>>KID: %v", rawKid)
			}
			encodedKid := base64.URLEncoding.EncodeToString(rawKid)

			if debug {
				log.Printf(">>>>>>>>>>>>>>>>>>>>>Encoded KID: %v", encodedKid)
			}
			ph.Kid = encodedKid

		default:
			// Unrecognized header, just ignore it
			log.Printf("Protected header invalid: %v\n", k.(int64))
		}

	}

	return ph
}

func (ph *ProtectedHeaders) ToCBOR() MapCBOR {

	// Convert from JSON headers to numeric CBOR-style headers
	CWTHeaders := make(map[any]any)

	CWTHeaders[int64(CWT_ALG)] = algsFromJWTtoCWT[ph.Alg]
	// The kid is encoded in B64
	fmt.Printf("KID before decoding: %v\n", ph.Kid)
	decodedKid, err := base64.URLEncoding.DecodeString(ph.Kid)
	if err != nil {
		log.Err(err).Msg("")
		return nil
	}
	CWTHeaders[int64(CWT_KID)] = decodedKid

	// Encode to CBOR map and then to a bstr
	phh := NewCBOREncoder().EncodeMap(CWTHeaders).Bytes()
	//phhb := NewCBOREncoder().EncodeBytes(phh).Bytes()

	return phh

}

// decodeCWTHeadersAsJWT decodes the CWT headers into a Go map for easy consumption
// by the application. The numeric claims in the headers are converted into a
// string representation compatible with the JSON format in JWT.
// func (cwt *CWT) decodeCWTHeadersAsJWT() error {

// 	// Convert headers from CBOR format to a map
// 	cb := NewCBORDecoder(cwt.CBORProtectedHeaders)
// 	protectedHeaders, err := cb.DecodeItem()
// 	if err != nil {
// 		return err
// 	}
// 	if debug {
// 		log.Printf("Decoding Protected Headers: %v", cwt.CBORProtectedHeaders)
// 		log.Printf("Type of Protected Headers: %T", protectedHeaders)
// 	}
// 	ph := protectedHeaders.(map[any]any)

// 	// Initialise the decoded headers map
// 	cwt.ProtectedHeaders = make(map[string]string)

// 	// Convert numeric claims into JWT string representations.
// 	for k, v := range ph {
// 		// Keys are always uint64
// 		switch k.(int64) {
// 		case CWT_ALG:
// 			// This is the method used to sign the CWT

// 			// Convert the numeric code to the string equivalent in JWT
// 			cwt.ProtectedHeaders["alg"] = algsFromCWTtoJWT[v.(int64)]

// 			// Check if the method is available in the binary
// 			method := GetSigner(cwt.ProtectedHeaders["alg"])
// 			if !method.Available() {
// 				log.Error().Str("method", cwt.ProtectedHeaders["alg"]).Msg("Signing method is not available")
// 			}

// 			// Store the method for later use in verifying the signature
// 			cwt.Method = method

// 		case CWT_KID:
// 			// This is the key identifier, used to retrieve the Public Key

// 			// Must encode raw bytes of the Kid to Base64
// 			rawKid := v.([]byte)
// 			encodedKid := base64.StdEncoding.EncodeToString(rawKid)
// 			cwt.ProtectedHeaders["kid"] = encodedKid

// 		default:
// 			// Unrecognized header, just ignore it
// 			log.Printf("Protected header invalid: %v\n", k.(int64))
// 		}

// 	}

// 	return nil
// }

// encodeJWTHeadersAsCWT encodes a Go map into a CWT protected header for a CWT.
// The JSON-style string headers are converted to CBOR numeric claims and values
// func (cwt *CWT) encodeJWTHeadersAsCWT() error {

// 	// Convert from JSON headers to numeric CBOR-style headers
// 	numericHeaders := make(map[any]any)

// 	for k, v := range cwt.ProtectedHeaders {
// 		switch k {
// 		case "alg":
// 			numericHeaders[CWT_ALG] = algsFromJWTtoCWT[v]

// 		case "kid":
// 			numericHeaders[CWT_KID] = 3

// 			// The kid is encoded in B64
// 			decodedKid, err := base64.StdEncoding.DecodeString(v)
// 			if err != nil {
// 				log.Err(err).Msg("")
// 				return err
// 			}
// 			numericHeaders[CWT_KID] = decodedKid

// 		default:
// 			// Unrecognized header, just ignore it
// 			log.Printf("Protected header invalid: %v\n", k)
// 		}
// 	}

// 	// Encode to CBOR map and then to a bstr
// 	ph := NewCBOREncoder().EncodeMap(numericHeaders).Bytes()
// 	cwt.CBORProtectedHeaders = NewCBOREncoder().EncodeBytes(ph).Bytes()

// 	return nil
// }

// SigStructure is used to sign a CWT or verify its signature
// It is here just for documentation, it is not actually used
type SigStructure struct {
	preamble         []byte
	protectedHeaders []byte
	zeroBstr         []byte
	payload          []byte
}

// Verify checks the signature of the CWT against the provided PublicKey
func (cwt *CWT) Verify(key *crypto.PublicKey) (bool, error) {

	err := cwt.Method.Verify(cwt.SigningBytes(), cwt.CBORSignature, key)
	if err != nil {
		log.Err(err).Msg("")
		return false, err
	}

	return true, nil
}

// Sign signs the CWT with the provided PrivateKey and stores the signature
func (cwt *CWT) Sign(key *crypto.PrivateKey) ([]byte, error) {

	signature, err := cwt.Method.Sign(cwt.SigningBytes(), key)
	if err != nil {
		log.Err(err).Msg("")
		return nil, err
	}

	cwt.CBORSignature = signature
	return signature, nil
}

// SigningBytes generates the signing byte array.
func (cwt *CWT) SigningBytes() []byte {

	// We create an array from the raw CBOR components
	toBeSigned := make([]any, 4)
	toBeSigned[0] = "Signature1"
	toBeSigned[1] = []byte(cwt.CBORProtectedHeaders)
	toBeSigned[2] = []byte("")
	toBeSigned[3] = []byte(cwt.CBORPayload)

	// And encode it as a byte array
	signing := NewCBOREncoder().EncodeArray(toBeSigned).Bytes()
	return signing
}

func (cwt *CWT) Dump() string {

	b, err := json.MarshalIndent(cwt, "", "   ")
	if err != nil {
		log.Err(err).Msg("")
	}

	return string(b)
}
