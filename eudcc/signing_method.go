package eudcc

import "crypto"

var signers = map[string]Signer{}

// Signer can be used add new methods for signing or verifying tokens.
type Signer interface {
	Available() bool                                                          // Returns true if the crypto functions are available
	Verify(signingBytes, signature []byte, publicKey *crypto.PublicKey) error // Returns nil if signature is valid
	Sign(signingBytes []byte, privateKey *crypto.PrivateKey) ([]byte, error)  // Returns encoded signature or error
	Alg() string                                                              // returns the alg identifier for this method (example: 'HS256')
}

// RegisterSigner registers the "alg" name and a signing method.
// This is typically done during init() in the method's implementation.
// In any case, this is NOT thread safe.
func RegisterSigner(alg string, s Signer) {
	signers[alg] = s
}

// GetSigner retrieves a signing method from an "alg" string
func GetSigner(alg string) (s Signer) {
	if signer, ok := signers[alg]; ok {
		s = signer
	}
	return
}

// GetAlgorithms returns a list of registered "alg" names
func GetAlgorithms() (algs []string) {

	for alg := range signers {
		algs = append(algs, alg)
	}
	return
}
