package eudcc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"hash"
	"math/big"
)

// SignerECDSA implements the ECDSA family of signing methods.
// Expects *ecdsa.PrivateKey for signing and *ecdsa.PublicKey for verification
type SignerECDSA struct {
	Name      string
	Hash      crypto.Hash
	Hasher    hash.Hash
	KeySize   int
	CurveBits int
}

// Specific instances for EC256 and company
var (
	SignerES256 *SignerECDSA
	SignerES384 *SignerECDSA
	SignerES512 *SignerECDSA
)

// init registers signers only if respective hashers are available
func init() {

	// ES256
	SignerES256 = &SignerECDSA{"ES256", crypto.SHA256, nil, 32, 256}
	RegisterSigner(SignerES256.Alg(), SignerES256)

	// ES384
	SignerES384 = &SignerECDSA{"ES384", crypto.SHA384, nil, 48, 384}
	RegisterSigner(SignerES384.Alg(), SignerES384)

	// ES512
	SignerES512 = &SignerECDSA{"ES512", crypto.SHA512, nil, 66, 521}
	RegisterSigner(SignerES512.Alg(), SignerES512)
}

func (m *SignerECDSA) Alg() string {
	return m.Name
}

func (m *SignerECDSA) Available() bool {
	return m.Hash.Available()
}

// Verify implements token verification for the SigningMethod.
// For this verify method, key must be an ecdsa.PublicKey struct
func (m *SignerECDSA) Verify(signingBytes, signature []byte, key *crypto.PublicKey) error {

	// Check that the key is ecdsa
	ecdsaKey, ok := (*key).(*ecdsa.PublicKey)
	if !ok {
		return ErrECDSAVerification
	}

	if len(signature) != 2*m.KeySize {
		return ErrECDSAVerification
	}

	// Get the r and s components from the signature byte array
	r := big.NewInt(0).SetBytes(signature[:m.KeySize])
	s := big.NewInt(0).SetBytes(signature[m.KeySize:])

	// Avoid allocations by creating the hasher only if this is the first time
	if m.Hasher == nil {
		m.Hasher = m.Hash.New()
	} else {
		m.Hasher.Reset()
	}

	m.Hasher.Write([]byte(signingBytes))

	// And verify the signature
	ok = ecdsa.Verify(ecdsaKey, m.Hasher.Sum(nil), r, s)
	if ok {
		return nil
	}

	return ErrECDSAVerification
}

// Sign implements token signing for the SigningMethod.
// For this signing method, key must be an ecdsa.PrivateKey struct
func (m *SignerECDSA) Sign(signingBytes []byte, key *crypto.PrivateKey) ([]byte, error) {

	// Check that key is not nil
	if key == nil {
		return nil, fmt.Errorf("Key is nil")
	}
	// Check that the key is ecdsa
	ecdsaKey, ok := (*key).(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("Invalid Private Key supplied")
	}

	// Avoid allocations by creating the hasher only if this is the first time
	if m.Hasher == nil {
		m.Hasher = m.Hash.New()
	} else {
		m.Hasher.Reset()
	}

	m.Hasher.Write(signingBytes)

	// Sign the byte array and return r, s
	if r, s, err := ecdsa.Sign(rand.Reader, ecdsaKey, m.Hasher.Sum(nil)); err == nil {
		curveBits := ecdsaKey.Curve.Params().BitSize

		if m.CurveBits != curveBits {
			return nil, ErrInvalidKey
		}

		keyBytes := curveBits / 8
		if curveBits%8 > 0 {
			keyBytes += 1
		}

		// We serialize the outputs (r and s) into big-endian byte arrays
		// padded with zeros on the left to make sure the sizes work out.
		// Output must be 2*keyBytes long.
		out := make([]byte, 2*keyBytes)
		r.FillBytes(out[0:keyBytes]) // r is assigned to the first half of output.
		s.FillBytes(out[keyBytes:])  // s is assigned to the second half of output.

		return out, nil
	} else {
		return nil, err
	}
}
