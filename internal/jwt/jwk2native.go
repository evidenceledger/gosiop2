package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"strings"
)

const (
	// ktyEC is the key type (kty) in the JWT header for ECDSA.
	ktyEC = "EC"

	// p256 represents a 256-bit cryptographic elliptical curve type.
	p256 = "P-256"

	// p384 represents a 384-bit cryptographic elliptical curve type.
	p384 = "P-384"

	// p521 represents a 521-bit cryptographic elliptical curve type.
	p521 = "P-521"
)

type JWK_EC struct {
	Use string `json:"use"`
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Crv string `json:"crv"`
	Alg string `json:"alg"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d"`
}

func NewJWKFromFile(location string) (*JWK_EC, error) {

	// Read the key from the file as a text string
	keyData, err := ioutil.ReadFile(location)
	if err != nil {
		return nil, err
	}

	// Convert to a JWK structure
	j := &JWK_EC{}
	err = json.Unmarshal(keyData, j)
	if err != nil {
		return nil, err
	}

	return j, nil
}

func (key *JWK_EC) GetKid() string {
	return key.Kid
}

func (key *JWK_EC) GetPublicKey() (publicKeyEC crypto.PublicKey, err error) {

	if key.X == "" || key.Y == "" || key.Crv == "" {
		return nil, fmt.Errorf("Missing fields in the JWK")
	}

	// Decode the X coordinate from Base64.
	//
	// According to RFC 7518, this is a Base64 URL unsigned integer.
	// https://tools.ietf.org/html/rfc7518#section-6.3
	xCoordinate, err := base64urlTrailingPadding(key.X)
	if err != nil {
		return nil, err
	}
	yCoordinate, err := base64urlTrailingPadding(key.Y)
	if err != nil {
		return nil, err
	}

	publicKey := &ecdsa.PublicKey{}
	// Turn the X coordinate into *big.Int.
	//
	// According to RFC 7517, these numbers are in big-endian format.
	// https://tools.ietf.org/html/rfc7517#appendix-A.1
	publicKey.X = big.NewInt(0).SetBytes(xCoordinate)
	publicKey.Y = big.NewInt(0).SetBytes(yCoordinate)

	switch key.Crv {
	case p256:
		publicKey.Curve = elliptic.P256()
	case p384:
		publicKey.Curve = elliptic.P384()
	case p521:
		publicKey.Curve = elliptic.P521()
	}

	return publicKey, nil
}

func (key *JWK_EC) GetPrivateKey() (privateKeyEC crypto.PrivateKey, err error) {

	if key.X == "" || key.Y == "" || key.D == "" || key.Crv == "" {
		return nil, fmt.Errorf("Missing fields in the JWK")
	}

	// Decode the X coordinate from Base64.
	//
	// According to RFC 7518, this is a Base64 URL unsigned integer.
	// https://tools.ietf.org/html/rfc7518#section-6.3
	xCoordinate, err := base64urlTrailingPadding(key.X)
	if err != nil {
		return nil, err
	}
	yCoordinate, err := base64urlTrailingPadding(key.Y)
	if err != nil {
		return nil, err
	}

	privateKey := &ecdsa.PrivateKey{}
	// Turn the X coordinate into *big.Int.
	//
	// According to RFC 7517, these numbers are in big-endian format.
	// https://tools.ietf.org/html/rfc7517#appendix-A.1
	privateKey.X = big.NewInt(0).SetBytes(xCoordinate)
	privateKey.Y = big.NewInt(0).SetBytes(yCoordinate)

	switch key.Crv {
	case p256:
		privateKey.Curve = elliptic.P256()
	case p384:
		privateKey.Curve = elliptic.P384()
	case p521:
		privateKey.Curve = elliptic.P521()
	}

	var dCoordinate []byte
	if len(key.D) > 0 {
		dCoordinate, err = base64urlTrailingPadding(key.D)
		if err != nil {
			return nil, err
		}
		privateKey.D = big.NewInt(0).SetBytes(dCoordinate)
	}

	return privateKey, nil

}

func LoadECPublicKeyFromJWKFile(location string) crypto.PublicKey {
	keyData, e := ioutil.ReadFile(location)
	if e != nil {
		panic(e.Error())
	}

	j := JWK_EC{}
	json.Unmarshal(keyData, &j)

	key, e := JWK2PublicECDSA(j)
	if e != nil {
		panic(e.Error())
	}
	return key
}

func LoadECPrivateKeyFromJWKFile(location string) crypto.PrivateKey {
	keyData, e := ioutil.ReadFile(location)
	if e != nil {
		panic(e.Error())
	}

	j := JWK_EC{}
	json.Unmarshal(keyData, &j)

	key, e := JWK2PrivateECDSA(j)
	if e != nil {
		panic(e.Error())
	}
	return key
}

// JWK2PublicECDSA parses a jsonWebKey and turns it into an ECDSA public key.
func JWK2PublicECDSA(j JWK_EC) (publicKey *ecdsa.PublicKey, err error) {
	if j.X == "" || j.Y == "" || j.Crv == "" {
		return nil, fmt.Errorf("Missing fields in the JWK")
	}

	// Decode the X coordinate from Base64.
	//
	// According to RFC 7518, this is a Base64 URL unsigned integer.
	// https://tools.ietf.org/html/rfc7518#section-6.3
	xCoordinate, err := base64urlTrailingPadding(j.X)
	if err != nil {
		return nil, err
	}
	yCoordinate, err := base64urlTrailingPadding(j.Y)
	if err != nil {
		return nil, err
	}

	publicKey = &ecdsa.PublicKey{}
	// Turn the X coordinate into *big.Int.
	//
	// According to RFC 7517, these numbers are in big-endian format.
	// https://tools.ietf.org/html/rfc7517#appendix-A.1
	publicKey.X = big.NewInt(0).SetBytes(xCoordinate)
	publicKey.Y = big.NewInt(0).SetBytes(yCoordinate)

	switch j.Crv {
	case p256:
		publicKey.Curve = elliptic.P256()
	case p384:
		publicKey.Curve = elliptic.P384()
	case p521:
		publicKey.Curve = elliptic.P521()
	}

	return

}

// JWK2PrivateECDSA parses a jsonWebKey and turns it into an ECDSA private key.
func JWK2PrivateECDSA(j JWK_EC) (privateKey *ecdsa.PrivateKey, err error) {
	if j.X == "" || j.Y == "" || j.D == "" || j.Crv == "" {
		return nil, fmt.Errorf("Missing fields in the JWK")
	}

	// Decode the X coordinate from Base64.
	//
	// According to RFC 7518, this is a Base64 URL unsigned integer.
	// https://tools.ietf.org/html/rfc7518#section-6.3
	xCoordinate, err := base64urlTrailingPadding(j.X)
	if err != nil {
		return nil, err
	}
	yCoordinate, err := base64urlTrailingPadding(j.Y)
	if err != nil {
		return nil, err
	}

	privateKey = &ecdsa.PrivateKey{}
	// Turn the X coordinate into *big.Int.
	//
	// According to RFC 7517, these numbers are in big-endian format.
	// https://tools.ietf.org/html/rfc7517#appendix-A.1
	privateKey.X = big.NewInt(0).SetBytes(xCoordinate)
	privateKey.Y = big.NewInt(0).SetBytes(yCoordinate)

	switch j.Crv {
	case p256:
		privateKey.Curve = elliptic.P256()
	case p384:
		privateKey.Curve = elliptic.P384()
	case p521:
		privateKey.Curve = elliptic.P521()
	}

	var dCoordinate []byte
	if len(j.D) > 0 {
		dCoordinate, err = base64urlTrailingPadding(j.D)
		if err != nil {
			return nil, err
		}
		privateKey.D = big.NewInt(0).SetBytes(dCoordinate)
	}

	return privateKey, nil

}

// base64urlTrailingPadding removes trailing padding before decoding a string from base64url. Some non-RFC compliant
// JWKS contain padding at the end values for base64url encoded public keys.
//
// Trailing padding is required to be removed from base64url encoded keys.
// RFC 7517 defines base64url the same as RFC 7515 Section 2:
// https://datatracker.ietf.org/doc/html/rfc7517#section-1.1
// https://datatracker.ietf.org/doc/html/rfc7515#section-2
func base64urlTrailingPadding(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	return base64.RawURLEncoding.DecodeString(s)
}
