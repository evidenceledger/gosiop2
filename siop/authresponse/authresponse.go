package authresponse

import (
	"encoding/json"
	"os"
	"time"

	"github.com/evidenceledger/gosiop2/jwt"
	"github.com/evidenceledger/gosiop2/siop"
	"github.com/evidenceledger/gosiop2/siop/authrequest"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func init() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	log.Logger = log.With().Caller().Logger()
}

// The AuthenticationResponse structure that SIOP sends and RPs receive
type AuthenticationResponse struct {
	jwt.RegisteredClaims // The standard JWT claims
	//	Id_token             IDToken         `json:"id_token"`      // id_token in standard OIDC
	Client_id     string          `json:"client_id"`     // client_id of the RP
	Response_type string          `json:"response_type"` // response_type for SIOP
	Response_mode string          `json:"response_mode"`
	Scopes        []string        `json:"scope"`
	Nonce         string          `json:"nonce"`
	Vp_token      json.RawMessage `json:"vp_token"` // vp_token in new OIDC4VP extension
}

// IDToken is an OpenID Connect extension that provides a predictable representation
// of an authorization event.
//
// The ID Token only holds fields OpenID Connect requires. To access additional
// claims returned by the server, use the Claims method.
type IDToken struct {
	// The URL of the server which issued this token. OpenID Connect
	// requires this value always be identical to the URL used for
	// initial discovery.
	//
	// Note: Because of a known issue with Google Accounts' implementation
	// this value may differ when using Google.
	//
	// See: https://developers.google.com/identity/protocols/OpenIDConnect#obtainuserinfo
	Issuer string `json:"iss,omitempty"`

	// The client ID, or set of client IDs, that this token is issued for. For
	// common uses, this is the client that initialized the auth flow.
	//
	// This package ensures the audience contains an expected value.
	Audience []string `json:"aud,omitempty"`

	// A unique string which identifies the end user.
	Subject string `json:"sub,omitempty"`

	// Expiry of the token. Ths package will not process tokens that have
	// expired unless that validation is explicitly turned off.
	Expiry time.Time `json:"exp,omitempty"`
	// When the token was issued by the provider.
	IssuedAt time.Time `json:"iat,omitempty"`

	// Initial nonce provided during the authentication redirect.
	//
	// This package does NOT provided verification on the value of this field
	// and it's the user's responsibility to ensure it contains a valid value.
	Nonce string `json:"nonce,omitempty"`

	// at_hash claim, if set in the ID token. Callers can verify an access token
	// that corresponds to the ID token using the VerifyAccessToken method.
	AccessTokenHash string `json:"at_hash,omitempty"`

	// signature algorithm used for ID token, needed to compute a verification hash of an
	// access token
	sigAlgorithm string

	// Raw payload of the id_token.
	claims []byte
}

// New is used by SIOP to create an AuthorizationResponse from the AuthorizationRequest received
// from the RP. It includes the vp_token created by SIOP to send the Verifiable Presentation.
// This is self-issued, so Issuer and Subject are set to the ID of the SIOP user (normally a DID)
func New(client_id string, authRequest *authrequest.AuthenticationRequest, vp_token json.RawMessage) *AuthenticationResponse {

	standardClaims := jwt.RegisteredClaims{
		Issuer:   client_id,
		Subject:  client_id,
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}

	// id_token := IDToken{
	// 	Issuer:   client_id,
	// 	Subject:  client_id,
	// 	IssuedAt: standardClaims.IssuedAt.Time,
	// }

	ar := &AuthenticationResponse{
		//		Id_token:      id_token,
		Vp_token:      vp_token,
		Client_id:     client_id,
		Response_type: "vp_token",
		Response_mode: "post",
		Scopes:        []string{siop.ScopeOpenID},
		Nonce:         authRequest.Nonce,
	}
	ar.RegisteredClaims = standardClaims
	return ar
}

// ParseAndValidate is intended for RPs to validate AuthorizationResponse from SIOP.
// ParseAndValidate generates an AuthorizationResponse from a JWT, validating the signature
// keyFunc is a function that receives a JWT and retrieves the corresponding public key using
// the key id in the header of the JWT
func ParseAndValidate(tokenString string, keyFunc jwt.Keyfunc) (*AuthenticationResponse, error) {

	// Parse and validate the JWT
	token, err := jwt.ParseWithClaims(tokenString, &AuthenticationResponse{}, keyFunc)
	if err != nil {
		log.Error().Err(err).Send()
		return nil, err
	}

	// The Claims segment of the decoded JWT should be the AuthorizationResponse
	claims, ok := token.Claims.(*AuthenticationResponse)
	if ok && token.Valid {
		return claims, nil
	} else {
		log.Error().Err(err).Send()
		return nil, err
	}
}

// func NewFromSerializedJWT(tokenString string, verifySignature bool) (ar *AuthorizationResponse, verified bool, err error) {

// 	// A JWT token is composed of 3 parts concatenated by dots (".")
// 	parts := strings.Split(tokenString, ".")
// 	if len(parts) != 3 {
// 		return nil, false, jwt.NewValidationError("token contains an invalid number of segments", jwt.ValidationErrorMalformed)
// 	}

// 	// Initialize the Token struct
// 	token := &jwt.Token{Raw: tokenString}

// 	// Parse Header
// 	var headerBytes []byte
// 	if headerBytes, err = jwt.DecodeSegment(parts[0]); err != nil {
// 		return nil, false, &jwt.ValidationError{Inner: err, Errors: jwt.ValidationErrorMalformed}
// 	}
// 	if err = json.Unmarshal(headerBytes, &token.Header); err != nil {
// 		return nil, false, &jwt.ValidationError{Inner: err, Errors: jwt.ValidationErrorMalformed}
// 	}

// 	// TODO: verify header for minimum requirements, eg alg and kid

// 	// Lookup signature alg
// 	alg, ok := token.Header["alg"].(string)
// 	if !ok {
// 		return nil, false, jwt.NewValidationError("signing method (alg) not in token header.", jwt.ValidationErrorUnverifiable)
// 	}

// 	// Lookup signature kid
// 	_, ok = token.Header["kid"].(string)
// 	if !ok {
// 		return nil, false, jwt.NewValidationError("signing method (alg) not in token header.", jwt.ValidationErrorUnverifiable)
// 	}

// 	// // Get the key for verification
// 	// jwk, err := w.QueryKeyByID(kid)
// 	// if err != nil {
// 	// 	return nil, false, err
// 	// }

// 	// // Convert the key to native
// 	// key, err := jwk.GetPublicKey()
// 	// if err != nil {
// 	// 	return nil, false, err
// 	// }

// 	// Decode claims part from B64Url
// 	var claimBytes []byte
// 	if claimBytes, err = jwt.DecodeSegment(parts[1]); err != nil {
// 		return nil, false, &jwt.ValidationError{Inner: err, Errors: jwt.ValidationErrorMalformed}
// 	}

// 	// JSON Decode, decoding to Number instead of floats
// 	dec := json.NewDecoder(bytes.NewBuffer(claimBytes))
// 	dec.UseNumber()

// 	ar = &AuthorizationResponse{}
// 	err = dec.Decode(ar)
// 	if err != nil {
// 		return nil, false, &jwt.ValidationError{Inner: err, Errors: jwt.ValidationErrorMalformed}
// 	}

// 	// Validate the registered claims exp, iat, nbf
// 	if err = ar.Valid(); err != nil {
// 		return nil, false, err
// 	}

// 	// All is valid (except signature), set the field in the token
// 	token.Claims = ar

// 	// TODO: verify claims for minimum requirements

// 	if token.Method = jwt.GetSigningMethod(alg); token.Method == nil {
// 		return nil, false, jwt.NewValidationError("signing method (alg) is unavailable.", jwt.ValidationErrorUnverifiable)
// 	}

// 	// // Concatenate headers and claims as undecoded strings
// 	// signingString := strings.Join(parts[0:2], ".")

// 	// // The signature part is the third
// 	// token.Signature = parts[2]

// 	// // Verify signature
// 	// if err = token.Method.Verify(signingString, token.Signature, key); err != nil {
// 	// 	return nil, false, jwt.NewValidationError("signature not verified.", jwt.ValidationErrorSignatureInvalid)
// 	// }

// 	// All validations performed, reply with success
// 	return ar, true, nil

// }
