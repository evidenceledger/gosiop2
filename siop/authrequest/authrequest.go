package authrequest

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"io"
	"time"

	"github.com/evidenceledger/gosiop2/jwt"
	"github.com/evidenceledger/gosiop2/siop"
)

type VPToken struct {
	Presentation_definition PresentationDefinition `json:"presentation_definition" mapstructure:"presentation_definition"`
}

type PresentationDefinition struct {
	Id                string                       `json:"id"`
	Format            PresentationDefinitionFormat `json:"format" mapstructure:"format"`
	Input_descriptors []InputDescriptor            `json:"input_descriptors"`
}

type PresentationDefinitionFormat struct {
	Jwt_vc JWT_VC_Format `json:"jtw_vc" mapstructure:"jwt_vc"`
}

type JWT_VC_Format struct {
	Alg []string `json:"alg"`
}

type InputDescriptor struct {
	Id          string                     `json:"id"`
	Name        string                     `json:"name"`
	Purpose     string                     `json:"purpose"`
	Constraints InputDescriptorConstraints `json:"constraints" mapstructure:"constraints"`
}

type InputDescriptorConstraints struct {
	Fields []ConstraintsField `json:"fields"`
}

type ConstraintsField struct {
	Path   []string               `json:"path"`
	Filter ConstraintsFieldFilter `json:"filter" mapstructure:"filter"`
}

type ConstraintsFieldFilter struct {
	Type    string   `json:"type"`
	Pattern []string `json:"pattern"`
}

type Registration struct {
	Subject_syntax_types_supported []string `json:"subject_syntax_types_supported"`
}

type AuthenticationRequest struct {
	jwt.RegisteredClaims
	Type                    string                 `json:"type"`
	Client_id               string                 `json:"client_id"`
	Redirect_uri            string                 `json:"redirect_uri"`
	Response_type           string                 `json:"response_type"`
	Response_mode           string                 `json:"response_mode"`
	Scopes                  []string               `json:"scope"`
	Nonce                   string                 `json:"nonce"`
	Presentation_definition PresentationDefinition `json:"presentation_definition"`
	Registration            Registration           `json:"registration"`
}

func New(client_id string, redirect_uri string, pd PresentationDefinition, registration Registration) *AuthenticationRequest {

	stdCl := jwt.RegisteredClaims{
		Issuer:   client_id,
		Subject:  client_id,
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}

	ar := &AuthenticationRequest{
		RegisteredClaims:        stdCl,
		Type:                    "siop",
		Client_id:               client_id,
		Redirect_uri:            redirect_uri,
		Response_type:           "vp_token",
		Response_mode:           "post",
		Scopes:                  []string{siop.ScopeOpenID},
		Nonce:                   GenerateNonce(),
		Presentation_definition: pd,
		Registration:            registration,
	}
	return ar
}

// Parse is used by the SIOP to verify an Authentication Request received from a RP
func Parse(tokenString string, keyFunc jwt.Keyfunc) (*AuthenticationRequest, error) {

	// Verify signature and parse into Authentication Request struct
	token, err := jwt.ParseWithClaims(tokenString, &AuthenticationRequest{}, keyFunc)
	if err != nil {
		return nil, err
	}

	// Verify the standard JWT claims.
	// Later we should verify the rest of the fields of the Auth Request
	claims, ok := token.Claims.(*AuthenticationRequest)
	if ok && token.Valid {
		return claims, nil
	} else {
		return nil, err
	}
}

func GenerateNonce() string {
	b := make([]byte, 16)
	io.ReadFull(rand.Reader, b)
	nonce := base64.RawURLEncoding.EncodeToString(b)
	return nonce
}

// AsSerializedJWT returns the AuthorizationRequest as a JWT signed by the private key
func (ar *AuthenticationRequest) AsSerializedJWT(privateKey crypto.PrivateKey, state string) (string, error) {

	// Regenerate time-dependent fields
	ar.IssuedAt = jwt.NewNumericDate(time.Now())

	// Update the Nonce field
	ar.Nonce = GenerateNonce()

	// Create a token with the specified signing methods and claims
	token := jwt.NewWithClaims(jwt.SigningMethodES256, ar)

	// Sign with our private key
	ss, err := token.SignedString(privateKey)

	return ss, err
}

// // SIOPAuthRequestAsURL returns a SIOP Authentication Request formatted as a URL
// func (s *SIOPConfig) SIOPAuthRequestAsURL(state string, nonce string) string {
// 	var buf bytes.Buffer
// 	buf.WriteString(s.Schema)
// 	v := url.Values{
// 		"scope":         {"openid"},
// 		"response_type": {"id_token"},
// 		"response_mode": {"post"},
// 		"client_id":     {s.AuthRequest.Client_id},
// 		"redirect_uri":  {s.AuthRequest.Redirect_uri},
// 		"state":         {state},
// 		"nonce":         {nonce},
// 	}

// 	if len(s.AuthRequest.Scopes) > 0 {
// 		v.Set("scope", strings.Join(s.AuthRequest.Scopes, " "))
// 	}

// 	if strings.Contains(s.Schema, "?") {
// 		buf.WriteByte('&')
// 	} else {
// 		buf.WriteByte('?')
// 	}
// 	buf.WriteString(v.Encode())
// 	return buf.String()
// }
