package eudcc

import (
	"bytes"
	"compress/zlib"
	"encoding/json"
	"fmt"
	"io"

	"github.com/rs/zerolog/log"

	"github.com/adrianrudnik/base45-go"

	"github.com/evidenceledger/gosiop2/jwt"
)

//var eudcc EUDCC

const debug = true

// Set the accepted validation methods. The EUDCC is very restrictive
var ValidMethods = map[string]bool{
	"ES256": true,
	"ES384": true,
	"ES512": true,
}

type EUDCC struct {
	CWT
	ValidMethods map[string]bool
	Payload      *EUDCCPayload
}

type EUDCCPayload struct {
	Issuer                 string
	IssuedAt               int64
	ExpiresAt              int64
	Version                string
	DateOfBirth            string
	Surname                string
	SurnameTransliterated  string
	Forename               string
	ForenameTransliterated string
	VaccinationCert        *VaccinationCert `json:"v,omitempty"`
	//	TestCert               *VaccinationCert `json:"t,omitempty"`
}

func NewEUDCC(payload *EUDCCPayload, alg string) (*EUDCC, error) {

	// Check if the algorithm is one of the accepted ones
	if !ValidMethods[alg] {
		return nil, fmt.Errorf("Invalid algorithm specified: %v", alg)
	}

	// Create a new EUDCC structure and initialise it with the payload
	eu := &EUDCC{}
	eu.Payload = payload

	// Get the method function that will be used to sign
	eu.Method = GetSigner(alg)
	if eu.Method == nil {
		return nil, fmt.Errorf("signing algorithm %v not found", alg)
	}

	// Set the algorithm in the header map
	eu.ProtectedHeaders.Alg = alg
	//	eu.ProtectedHeaders["alg"] = alg

	return eu, nil
}

// DecodeEU_DCC_QR converts a raw string in QR format to a EUDCC native Go structure
func DecodeEU_DCC_QR(qrCode []byte) (*EUDCC, error) {

	// Convert from the QR code to a clean CWT
	// Strips the prefix, decodes B65 and unzips the QR code string
	raw, err := FromQRCodeToRaw(qrCode)
	if err != nil {
		log.Err(err).Msg("")
		return nil, err
	}

	// Decode the CWT as a EU DCC struct
	return EUDCCFromSerializedCWT(raw)

}

// FromQRCodeToRaw converts from the QR code to a clean byte array with the CWT data
// Strips the prefix, decodes B65 and unzips the QR code string
func FromQRCodeToRaw(qrCode []byte) ([]byte, error) {

	// The EU DCC QR code is a string that starts with the prefix "HC1:"
	// The remaining is a Base45-encoded byte array.
	// After removing the prefix and decoding with Base45 we get a zlib-encoded byte array.
	// After decompressing using zlib we get a byte array in COSE format.

	// Check the prefix and skip over it
	if string(qrCode[:4]) != "HC1:" {
		return nil, fmt.Errorf("qrcode does not start with 'HC1:'")
	}
	certB45 := qrCode[4:]

	// Decode from B45 and the result is a ZIP packet
	certZipped, err := base45.Decode(certB45)
	if err != nil {
		return nil, err
	}

	// UnZip the packet and the result is a COSE CWT
	zippedInputBuf := bytes.NewBuffer(certZipped)
	zippedReader, err := zlib.NewReader(zippedInputBuf)
	if err != nil {
		return nil, err
	}

	// Allocate an array of reasonable size to minimise allocations
	outputBuf := make([]byte, 0, 4000)
	unzippedBuf := bytes.NewBuffer(outputBuf)
	_, err = io.Copy(unzippedBuf, zippedReader)
	if err != nil {
		return nil, err
	}
	zippedReader.Close()

	// get the result as an array of bytes
	raw := unzippedBuf.Bytes()
	if debug {
		log.Printf("The CWT:\n%v", raw)
	}

	// The EUDCC CWT is a CWT with the following structure:
	// - Protected Header
	//    - Signature Algorithm (alg, label 1)
	//    - Key Identifier (kid, label 4)
	// - Payload
	//    - Issuer (iss, claim key 1, optional, ISO 3166-1 alpha-2 of issuer)
	//    - Issued At (iat, claim key 6)
	//    - Expiration Time (exp, claim key 4)
	//    - Health Certificate (hcert, claim key -260)
	//       - EU Digital Covid Certificate v1 (eu_dcc_v1 aka eu_dgc_v1, claim key 1)
	// - Signature

	// We will first decode a "standard" CWT/COSE object and then convert the result
	// into a more manageable structure, mapping key/values to JSON strings specific
	// to the EU DCC Certificate

	// When validating a CWT, the following steps are performed. The order
	// of the steps is not significant in cases where there are no
	// dependencies between the inputs and outputs of the steps. If any of
	// the listed steps fail, then the CWT MUST be rejected -- that is,
	// treated by the application as invalid input.

	// 1.  Verify that the CWT is a valid CBOR object.
	// Get the initial byte
	initialByte := raw[0]
	majorType := initialByte >> 5
	additionalInformation := initialByte & 0x1f

	// 2.  If the object begins with the CWT CBOR tag, remove it and verify
	// 	that one of the COSE CBOR tags follows it.
	// #6.61(CWT_Tag)
	if majorType == MT_TAG && additionalInformation == CWT_Tag {
		if debug {
			log.Debug().Str("MajorType", majorTypes[majorType]).Uint8("AdditionalInfo", additionalInformation).Msg("")
		}

		// Get rid of the tag for further processing
		raw = raw[1:]

		// Get again the initial byte
		initialByte := raw[0]
		majorType = initialByte >> 5
		additionalInformation = initialByte & 0x1f

		// We only support COSE_Sign1_Tagged = #6.18(COSE_Sign1)
		if majorType == MT_TAG && additionalInformation != COSE_Sign1 {
			return nil, fmt.Errorf("Tagged COSE is not a COSE Single signature, tag: %v", additionalInformation)
		}
	}

	// 3.  If the object is tagged with one of the COSE CBOR tags, remove it
	// 	and use it to determine the type of the CWT, COSE_Sign/
	// 	COSE_Sign1, COSE_Mac/COSE_Mac0, or COSE_Encrypt/COSE_Encrypt0.
	// 	If the object does not have a COSE CBOR tag, the COSE message
	// 	type is determined from the application context.

	// COSE_Sign1_Tagged = #6.18(COSE_Sign1)
	if majorType == MT_TAG && additionalInformation == COSE_Sign1 {
		if debug {
			log.Debug().Str("COSE_Sign1_Tagged", majorTypes[majorType]).Uint8("AdditionalInfo", additionalInformation).Msg("")
		}

		// Get rid of the tag for further processing
		raw = raw[1:]

		// Get again the initial byte
		initialByte := raw[0]
		majorType = initialByte >> 5
		additionalInformation = initialByte & 0x1f
	}

	return raw, nil

}

// EUDCCFromSerializedCWT decodes a raw EUDCC certificate into a Go structure.
// It does NOT perform signature validation.
func EUDCCFromSerializedCWT(raw []byte) (*EUDCC, error) {
	cert := &EUDCC{}

	// Store the raw bytes of the certificate
	cert.Raw = raw

	// Decode WITHOUT signature verification
	// The results are put into the corresponding struct fields of cert
	err := cert.DecodeUntaggedCOSE()
	if debug {
		log.Err(err).Msg("Certificate decoded")
	}

	return cert, err
}

func (eu *EUDCC) Dump() string {

	b, err := json.MarshalIndent(eu, "", "   ")
	if err != nil {
		log.Panic().Err(err).Msg("")
	}

	return string(b)
}

// DecodeUntaggedCOSE decodes a raw EUDCC certificate into a Go structure.
// It dos not perform validation of the signature.
func (eu *EUDCC) DecodeUntaggedCOSE() error {

	// Get the initial byte, which should define an array of 4 elements
	initialByte := eu.Raw[0]
	majorType := initialByte >> 5
	// For a very small array, the additionalInformation bits are the length of the array
	length := initialByte & 0x1f

	// Check for an array
	if majorType != MT_ARRAY {
		return fmt.Errorf("COSE should be a CBOR Array object (%v), but type is %v", MT_ARRAY, majorType)
	}

	// Check for exactly 4 elements in the array.
	if length != 4 {
		return fmt.Errorf("COSE array should have 4 elements, got %v", length)
	}

	// Decode CBOR top-level array
	cb := NewCBORDecoder(eu.Raw)
	ar, err := cb.DecodeItem()
	if err != nil {
		return err
	}
	CBORarray := ar.([]any)

	if debug {
		log.Printf("Type of received ARRAY: %T", CBORarray)
		for i := 0; i < len(CBORarray); i++ {

			if v, ok := (CBORarray[i]).([]byte); ok {
				log.Printf("  (%v): %T, len %v -> %v", i, CBORarray[i], len(v), v[:5])
			} else {
				log.Printf("  (%v): %T", i, CBORarray[i])
			}

		}
	}

	// Verify that each component is of the right type

	// Header is a bstr
	if _, ok := (CBORarray[0]).([]byte); !ok {
		err := fmt.Errorf("Protected Header is not of the correct type")
		log.Err(err).Msg("")
		return err
	}
	// UnprotectedHeaders is a map
	if _, ok := (CBORarray[1]).(map[any]any); !ok {
		err := fmt.Errorf("UnprotectedHeaders is not of the correct type")
		log.Err(err).Msg("")
		return err
	}
	// Payload is a bstr
	if _, ok := (CBORarray[2]).([]byte); !ok {
		err := fmt.Errorf("Payload is not of the correct type")
		log.Err(err).Msg("")
		return err
	}
	// Signature is a bstr
	if _, ok := (CBORarray[3]).([]byte); !ok {
		err := fmt.Errorf("Signature is not of the correct type")
		log.Err(err).Msg("")
		return err
	}

	// Store the components in raw format into the structure, for later decoding
	eu.CBORProtectedHeaders = (CBORarray[0]).([]byte)
	eu.CBORUnprotectedHeaders = (CBORarray[1]).(map[any]any)
	eu.CBORPayload = (CBORarray[2]).([]byte)
	eu.CBORSignature = (CBORarray[3]).([]byte)

	// Decode the headers into JWT-style map
	// err = eu.decodeCWTHeadersAsJWT()
	eu.ProtectedHeaders = ProtectedHeadersFromCBOR(eu.CBORProtectedHeaders)
	eu.Method = eu.ProtectedHeaders.Method
	// if err != nil {
	// 	return err
	// }

	// Decode payload
	err = eu.decodeCBORPayload()
	if err != nil {
		return err
	}

	return nil

}

type PublicKeyResolution func(*EUDCC) (*jwt.JWK_EC, error)

type PrivateKeyResolution func(*EUDCC) (*jwt.JWK_EC, error)

// VerifyWith uses the public key provided by the keyFunc argument to verify the signature
// of a previously decoded EUDCC structure
func (eu *EUDCC) VerifyWith(publicKeyFunc PublicKeyResolution) (bool, error) {

	if publicKeyFunc == nil {
		err := fmt.Errorf("no Keyfunc was provided")
		log.Err(err).Msg("")
		return false, err
	}

	// Retrieve the Public Key using the KeyResolution function provided
	keyJWK, err := publicKeyFunc(eu)
	if err != nil {
		log.Err(err).Msg("")
		return false, err
	}
	publicKey, err := keyJWK.GetPublicKey()
	if err != nil {
		log.Err(err).Msg("")
		return false, err
	}

	// Verify the signature of the EUDCC structure
	sgb := eu.SigningBytes()
	if debug {
		log.Printf("Method: %v", eu.Method)
		log.Printf("SignBytes: %v", sgb)
		log.Printf("CBORSignature: %v", eu.CBORSignature)
	}

	err = eu.Method.Verify(eu.SigningBytes(), eu.CBORSignature, &publicKey)
	if err != nil {
		log.Err(err).Msg("")
		return false, err
	}

	return true, nil
}

func (eu *EUDCC) EncodeAndSign(privateKeyFunc PrivateKeyResolution) ([]byte, error) {

	if privateKeyFunc == nil {
		err := fmt.Errorf("no Keyfunc was provided")
		log.Err(err).Msg("")
		return nil, err
	}

	// Retrieve the Private Key using the KeyResolution function provided
	keyJWK, err := privateKeyFunc(eu)
	if err != nil {
		log.Err(err).Msg("")
		return nil, err
	}
	privatekey, err := keyJWK.GetPrivateKey()

	// Set the key identifier in the protected headers
	kid := keyJWK.GetKid()
	eu.ProtectedHeaders.Kid = kid
	//	eu.ProtectedHeaders["kid"] = kid

	// Create and encode protected headers
	eu.CBORProtectedHeaders = eu.ProtectedHeaders.ToCBOR()
	//	eu.encodeJWTHeadersAsCWT()

	// Encode payload
	eu.CBORPayload = PayloadAsCWT(eu.Payload)

	// Sign
	eu.CBORSignature, err = eu.Sign(&privatekey)
	if err != nil {
		log.Err(err).Msg("")
		return nil, err
	}

	// Return CWT
	nilMap := MapCBOR([]byte{0xa0})

	rawArray := make([]any, 4)
	rawArray[0] = []byte(eu.CBORProtectedHeaders)
	rawArray[1] = nilMap
	rawArray[2] = []byte(eu.CBORPayload)
	rawArray[3] = []byte(eu.CBORSignature)

	// And encode it as a byte array
	encoded := NewCBOREncoder().EncodeArray(rawArray).Bytes()
	if debug {
		log.Printf("++++++++++++++++++++++++++Result Raw Array: %v", encoded)
	}
	return encoded, nil

}

// decodeCBORPayload converts a raw CBOR array into a specific EUDCC structure.
// This EUDCC structure can represent Vaccination, Test or Recovery certificates.
func (eu *EUDCC) decodeCBORPayload() error {

	// Decode the raw bytes as a CBOR Map, otherwise it is an error
	cb := NewCBORDecoder(eu.CBORPayload)
	payload, err := cb.DecodeMap()
	if err != nil {
		return err
	}

	if debug {
		log.Printf("Decoding Payload: %v", eu.CBORPayload[:20])
		log.Printf("Type of Payload: %T", payload)

		for k, v := range payload {
			log.Printf("  Key %v(%T) Value %T: %v", k, k, v, v)
		}
	}

	// Transform to a EU DCC map encoding
	eu.Payload = PayloadAsJWT(payload)

	return nil
}

const (
	EUDCC_ISSUER     = int64(1)
	EUDCC_ISSUED_AT  = int64(6)
	EUDCC_EXPIRES_AT = int64(4)
	EUDCC_HCERT      = int64(-260)
	EUDCC_V1         = int64(1)
)

func PayloadAsJWT(p map[any]any) *EUDCCPayload {
	var eup EUDCCPayload

	// The format is the following:
	// - Issuer (iss, claim key 1, optional, ISO 3166-1 alpha-2 of issuer)
	// - Issued At (iat, claim key 6)
	// - Expiration Time (exp, claim key 4)
	// - Health Certificate (hcert, claim key -260)
	//    - EU Digital Covid Certificate v1 (eu_dcc_v1 aka eu_dgc_v1, claim key 1)

	for k, value := range p {
		key := int64(k.(int64))
		switch key {
		case EUDCC_ISSUER:
			eup.Issuer = value.(string)
		case EUDCC_ISSUED_AT:
			eup.IssuedAt = value.(int64)
		case EUDCC_EXPIRES_AT:
			eup.ExpiresAt = value.(int64)
		case EUDCC_HCERT:
			for m, n := range value.(map[any]any) {
				if m.(int64) == EUDCC_V1 {
					decodeEUDCCCovidCert(&eup, n.(map[any]any))
				}
			}
		}

	}

	return &eup

}

type EUDCCPayload_ struct {
	Issuer                 string
	IssuedAt               int64
	ExpiresAt              int64
	Version                string
	DateOfBirth            string
	Surname                string
	SurnameTransliterated  string
	Forename               string
	ForenameTransliterated string
	VaccinationCert        *VaccinationCert `json:"v,omitempty"`
	//	TestCert               *VaccinationCert `json:"t,omitempty"`
}

func PayloadAsCWT(eu *EUDCCPayload) []byte {

	// The format is the following:
	// - Issuer (iss, claim key 1, optional, ISO 3166-1 alpha-2 of issuer)
	// - Issued At (iat, claim key 6)
	// - Expiration Time (exp, claim key 4)
	// - Health Certificate (hcert, claim key -260)
	//    - EU Digital Covid Certificate v1 (eu_dcc_v1 aka eu_dgc_v1, claim key 1)

	// Encode the eu_dgc_v1 map
	eu_dgc_v1 := make(map[any]any)
	eu_dgc_v1["dob"] = eu.DateOfBirth
	eu_dgc_v1["ver"] = eu.Version

	// Encode the patient names as an embedded Map
	names := make(map[any]any)
	names["fn"] = eu.Surname
	names["fnt"] = eu.SurnameTransliterated
	names["gn"] = eu.Forename
	names["gnt"] = eu.ForenameTransliterated
	eu_dgc_v1["nam"] = names

	// Encode the embedded Vaccination data
	vaccData := eu.VaccinationCert.ToIntermediateCBOR()
	eu_dgc_v1["v"] = vaccData

	// Create and encode the HCERT map with only one member, the eu_dgc_v1 cert
	hcert := make(map[any]any)
	hcert[EUDCC_V1] = eu_dgc_v1

	// Create and populate the EUDCC CWT Map with the payload
	eu_cwt_payload := make(map[any]any)

	eu_cwt_payload[EUDCC_ISSUER] = eu.Issuer
	eu_cwt_payload[EUDCC_ISSUED_AT] = eu.IssuedAt
	eu_cwt_payload[EUDCC_EXPIRES_AT] = eu.ExpiresAt

	eu_cwt_payload[EUDCC_HCERT] = hcert

	// Encode the map to CBOR
	eu_cwt_payload_CBOR := NewCBOREncoder().EncodeMap(eu_cwt_payload).Bytes()

	return eu_cwt_payload_CBOR

}

func decodeEUDCCCovidCert(eup *EUDCCPayload, cert map[any]any) {
	for k, value := range cert {
		key := k.(string)
		switch key {
		case "dob":
			eup.DateOfBirth = value.(string)
		case "ver":
			eup.Version = value.(string)
		case "nam":
			names := value.(map[any]any)
			for n, nv := range names {
				name := n.(string)
				nameValue := nv.(string)
				switch name {
				case "fn":
					eup.Surname = nameValue
				case "fnt":
					eup.SurnameTransliterated = nameValue
				case "gn":
					eup.Forename = nameValue
				case "gnt":
					eup.ForenameTransliterated = nameValue
				}
			}
		case "v":
			eup.VaccinationCert = FromIntermediateCBOR(value)
		}

	}
}

// ***********************************
// Vaccination Certificate
// ***********************************

type VaccinationCert struct {
	DiseaseAgentTargeted    string // "tg"
	VaccineProphylaxis      string // "vp"
	VaccineMedicinalProduct string // "mp"
	VaccineMahManf          string // "ma"
	DoseNumber              int64  // "dn"
	DoseTotal               int64  // "sd"
	DateVaccination         string // "dt"
	CountryCode             string // "co"
	CertificateIssuer       string // "is"
	CertificateIdentifier   string // "ci"
}

func FromIntermediateCBOR(vdata any) *VaccinationCert {

	// Create an empty Vaccination certificate
	vc := &VaccinationCert{}

	// The EUDCC spec says that it should be an array of vaccination items,
	// even if currently there can be only one
	certs, ok := vdata.([]any)
	if !ok {
		// Return the zero vale certificate
		return vc
	}
	if len(certs) == 0 {
		// Do nothing if there is not at least one certificate
		return vc
	}

	// Try to get the first certificate as a map
	cert, ok := (certs[0]).(map[any]any)
	if !ok {
		// Return the zero vale certificate
		return vc
	}

	// Iterate the map
	for k, value := range cert {
		// All keys should be strings
		key, _ := k.(string)
		if debug {
			log.Printf("Item (%v) of type (%T): %v", key, value, value)
		}

		switch key {
		case "tg":
			vc.DiseaseAgentTargeted, _ = value.(string)
		case "vp":
			vc.VaccineProphylaxis, _ = value.(string)
		case "mp":
			vc.VaccineMedicinalProduct, _ = value.(string)
		case "ma":
			vc.VaccineMahManf, _ = value.(string)
		case "dn":
			vc.DoseNumber, _ = value.(int64)
		case "sd":
			vc.DoseTotal, _ = value.(int64)
		case "dt":
			vc.DateVaccination, _ = value.(string)
		case "co":
			vc.CountryCode, _ = value.(string)
		case "is":
			vc.CertificateIssuer, _ = value.(string)
		case "ci":
			vc.CertificateIdentifier, _ = value.(string)
		}
	}

	return vc

}

func (vc *VaccinationCert) ToIntermediateCBOR() []any {

	// Create a map with the fields of the structure
	m := make(map[any]any)

	m["tg"] = vc.DiseaseAgentTargeted
	m["vp"] = vc.VaccineProphylaxis
	m["mp"] = vc.VaccineMedicinalProduct
	m["ma"] = vc.VaccineMahManf
	m["dn"] = vc.DoseNumber
	m["sd"] = vc.DoseTotal
	m["dt"] = vc.DateVaccination
	m["co"] = vc.CountryCode
	m["is"] = vc.CertificateIssuer
	m["ci"] = vc.CertificateIdentifier

	// The EUDCC spec says that it should be an array of vaccination items,
	// even if currently there can be only one
	var vcArray [1]any
	vcArray[0] = m
	return vcArray[:]

}
