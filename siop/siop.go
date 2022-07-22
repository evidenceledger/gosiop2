// Package siop implements Self-Issued OpenID Connect client logic on top of the golang.org/x/oauth2 package.
package siop

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io/ioutil"
	"mime"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// JOSE asymmetric signing algorithm values as defined by RFC 7518
//
// see: https://tools.ietf.org/html/rfc7518#section-3.1
const (
	RS256 = "RS256" // RSASSA-PKCS-v1.5 using SHA-256
	RS384 = "RS384" // RSASSA-PKCS-v1.5 using SHA-384
	RS512 = "RS512" // RSASSA-PKCS-v1.5 using SHA-512
	ES256 = "ES256" // ECDSA using P-256 and SHA-256
	ES384 = "ES384" // ECDSA using P-384 and SHA-384
	ES512 = "ES512" // ECDSA using P-521 and SHA-512
	PS256 = "PS256" // RSASSA-PSS using SHA256 and MGF1-SHA256
	PS384 = "PS384" // RSASSA-PSS using SHA384 and MGF1-SHA384
	PS512 = "PS512" // RSASSA-PSS using SHA512 and MGF1-SHA512
)

const (
	ScopeOpenID      = "openid"
	SIOPResponseType = "id_token"
)

var (
	errNoAtHash      = errors.New("id token did not have an access token hash")
	errInvalidAtHash = errors.New("access token hash does not match value in ID token")
)

// supportedAlgorithms is a list of algorithms explicitly supported by this
// package. If a provider supports other algorithms, such as HS256 or none,
// those values won't be passed to the IDTokenVerifier.
var supportedAlgorithms = map[string]bool{
	RS256: true,
	RS384: true,
	RS512: true,
	ES256: true,
	ES384: true,
	ES512: true,
	PS256: true,
	PS384: true,
	PS512: true,
}

// DefaultPreferredAlgorithm is the algorithm used by default by this package
var DefaultPreferredAlgorithm = ES256

//*****************************************************************
//*****************************************************************
//*****************************************************************
//*****************************************************************
//*****************************************************************
//*****************************************************************
//*****************************************************************
//*****************************************************************

type contextKey int

var issuerURLKey contextKey

// ClientContext returns a new Context that carries the provided HTTP client.
//
// This method sets the same context key used by the golang.org/x/oauth2 package,
// so the returned context works for that package too.
//
//    myClient := &http.Client{}
//    ctx := oidc.ClientContext(parentContext, myClient)
//
//    // This will use the custom client
//    provider, err := oidc.NewProvider(ctx, "https://accounts.example.com")
//
func ClientContext(ctx context.Context, client *http.Client) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, client)
}

// cloneContext copies a context's bag-of-values into a new context that isn't
// associated with its cancellation. This is used to initialize remote keys sets
// which run in the background and aren't associated with the initial context.
func cloneContext(ctx context.Context) context.Context {
	cp := context.Background()
	if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		cp = ClientContext(cp, c)
	}
	return cp
}

// InsecureIssuerURLContext allows discovery to work when the issuer_url reported
// by upstream is mismatched with the discovery URL. This is meant for integration
// with off-spec providers such as Azure.
//
//    discoveryBaseURL := "https://login.microsoftonline.com/organizations/v2.0"
//    issuerURL := "https://login.microsoftonline.com/my-tenantid/v2.0"
//
//    ctx := oidc.InsecureIssuerURLContext(parentContext, issuerURL)
//
//    // Provider will be discovered with the discoveryBaseURL, but use issuerURL
//    // for future issuer validation.
//    provider, err := oidc.NewProvider(ctx, discoveryBaseURL)
//
// This is insecure because validating the correct issuer is critical for multi-tenant
// proivders. Any overrides here MUST be carefully reviewed.
func InsecureIssuerURLContext(ctx context.Context, issuerURL string) context.Context {
	return context.WithValue(ctx, issuerURLKey, issuerURL)
}

func doRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	client := http.DefaultClient
	if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		client = c
	}
	return client.Do(req.WithContext(ctx))
}

// Provider represents an OpenID Connect server's configuration.
type Provider struct {
	issuer      string
	authURL     string
	tokenURL    string
	userInfoURL string
	algorithms  []string

	// Raw claims returned by the server.
	rawClaims []byte

	remoteKeySet KeySet
}

type providerJSON struct {
	Issuer      string   `json:"issuer"`
	AuthURL     string   `json:"authorization_endpoint"`
	TokenURL    string   `json:"token_endpoint"`
	JWKSURL     string   `json:"jwks_uri"`
	UserInfoURL string   `json:"userinfo_endpoint"`
	Algorithms  []string `json:"id_token_signing_alg_values_supported"`
}

// ProviderConfig allows creating providers when discovery isn't supported. It's
// generally easier to use NewProvider directly.
// type ProviderConfig struct {
// 	// IssuerURL is the identity of the provider, and the string it uses to sign
// 	// ID tokens with. For example "https://accounts.google.com". This value MUST
// 	// match ID tokens exactly.
// 	IssuerURL string
// 	// AuthURL is the endpoint used by the provider to support the OAuth 2.0
// 	// authorization endpoint.
// 	AuthURL string
// 	// TokenURL is the endpoint used by the provider to support the OAuth 2.0
// 	// token endpoint.
// 	TokenURL string
// 	// UserInfoURL is the endpoint used by the provider to support the OpenID
// 	// Connect UserInfo flow.
// 	//
// 	// https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
// 	UserInfoURL string
// 	// JWKSURL is the endpoint used by the provider to advertise public keys to
// 	// verify issued ID tokens. This endpoint is polled as new keys are made
// 	// available.
// 	JWKSURL string

// 	// Algorithms, if provided, indicate a list of JWT algorithms allowed to sign
// 	// ID tokens. If not provided, this defaults to the algorithms advertised by
// 	// the JWK endpoint, then the set of algorithms supported by this package.
// 	Algorithms []string
// }

// NewProvider initializes a provider from a set of endpoints, rather than
// through discovery.
// func (p *ProviderConfig) NewProvider(ctx context.Context) *Provider {
// 	return &Provider{
// 		issuer:       p.IssuerURL,
// 		authURL:      p.AuthURL,
// 		tokenURL:     p.TokenURL,
// 		userInfoURL:  p.UserInfoURL,
// 		algorithms:   p.Algorithms,
// 		remoteKeySet: NewRemoteKeySet(cloneContext(ctx), p.JWKSURL),
// 	}
// }

// NewProvider uses the OpenID Connect discovery mechanism to construct a Provider.
//
// The issuer is the URL identifier for the service. For example: "https://accounts.google.com"
// or "https://login.salesforce.com".
func NewProvider(ctx context.Context, issuer string) (*Provider, error) {
	wellKnown := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequest("GET", wellKnown, nil)
	if err != nil {
		return nil, err
	}
	resp, err := doRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", resp.Status, body)
	}

	var p providerJSON
	err = unmarshalResp(resp, body, &p)
	if err != nil {
		return nil, fmt.Errorf("oidc: failed to decode provider discovery object: %v", err)
	}

	issuerURL, skipIssuerValidation := ctx.Value(issuerURLKey).(string)
	if !skipIssuerValidation {
		issuerURL = issuer
	}
	if p.Issuer != issuerURL && !skipIssuerValidation {
		return nil, fmt.Errorf("oidc: issuer did not match the issuer returned by provider, expected %q got %q", issuer, p.Issuer)
	}
	var algs []string
	for _, a := range p.Algorithms {
		if supportedAlgorithms[a] {
			algs = append(algs, a)
		}
	}
	return &Provider{
		issuer:       issuerURL,
		authURL:      p.AuthURL,
		tokenURL:     p.TokenURL,
		userInfoURL:  p.UserInfoURL,
		algorithms:   algs,
		rawClaims:    body,
		remoteKeySet: NewRemoteKeySet(cloneContext(ctx), p.JWKSURL),
	}, nil
}

// Claims unmarshals raw fields returned by the server during discovery.
//
//    var claims struct {
//        ScopesSupported []string `json:"scopes_supported"`
//        ClaimsSupported []string `json:"claims_supported"`
//    }
//
//    if err := provider.Claims(&claims); err != nil {
//        // handle unmarshaling error
//    }
//
// For a list of fields defined by the OpenID Connect spec see:
// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
func (p *Provider) Claims(v interface{}) error {
	if p.rawClaims == nil {
		return errors.New("oidc: claims not set")
	}
	return json.Unmarshal(p.rawClaims, v)
}

// Endpoint returns the OAuth2 auth and token endpoints for the given provider.
func (p *Provider) Endpoint() oauth2.Endpoint {
	return oauth2.Endpoint{AuthURL: p.authURL, TokenURL: p.tokenURL}
}

// UserInfo represents the OpenID Connect userinfo claims.
type UserInfo struct {
	Subject       string `json:"sub"`
	Profile       string `json:"profile"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`

	claims []byte
}

type userInfoRaw struct {
	Subject string `json:"sub"`
	Profile string `json:"profile"`
	Email   string `json:"email"`
	// Handle providers that return email_verified as a string
	// https://forums.aws.amazon.com/thread.jspa?messageID=949441&#949441 and
	// https://discuss.elastic.co/t/openid-error-after-authenticating-against-aws-cognito/206018/11
	EmailVerified stringAsBool `json:"email_verified"`
}

// Claims unmarshals the raw JSON object claims into the provided object.
func (u *UserInfo) Claims(v interface{}) error {
	if u.claims == nil {
		return errors.New("oidc: claims not set")
	}
	return json.Unmarshal(u.claims, v)
}

// UserInfo uses the token source to query the provider's user info endpoint.
func (p *Provider) UserInfo(ctx context.Context, tokenSource oauth2.TokenSource) (*UserInfo, error) {
	if p.userInfoURL == "" {
		return nil, errors.New("oidc: user info endpoint is not supported by this provider")
	}

	req, err := http.NewRequest("GET", p.userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc: create GET request: %v", err)
	}

	token, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("oidc: get access token: %v", err)
	}
	token.SetAuthHeader(req)

	resp, err := doRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", resp.Status, body)
	}

	ct := resp.Header.Get("Content-Type")
	mediaType, _, parseErr := mime.ParseMediaType(ct)
	if parseErr == nil && mediaType == "application/jwt" {
		payload, err := p.remoteKeySet.VerifySignature(ctx, string(body))
		if err != nil {
			return nil, fmt.Errorf("oidc: invalid userinfo jwt signature %v", err)
		}
		body = payload
	}

	var userInfo userInfoRaw
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("oidc: failed to decode userinfo: %v", err)
	}
	return &UserInfo{
		Subject:       userInfo.Subject,
		Profile:       userInfo.Profile,
		Email:         userInfo.Email,
		EmailVerified: bool(userInfo.EmailVerified),
		claims:        body,
	}, nil
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
	Issuer string

	// The client ID, or set of client IDs, that this token is issued for. For
	// common uses, this is the client that initialized the auth flow.
	//
	// This package ensures the audience contains an expected value.
	Audience []string

	// A unique string which identifies the end user.
	Subject string

	// Expiry of the token. Ths package will not process tokens that have
	// expired unless that validation is explicitly turned off.
	Expiry time.Time
	// When the token was issued by the provider.
	IssuedAt time.Time

	// Initial nonce provided during the authentication redirect.
	//
	// This package does NOT provided verification on the value of this field
	// and it's the user's responsibility to ensure it contains a valid value.
	Nonce string

	// at_hash claim, if set in the ID token. Callers can verify an access token
	// that corresponds to the ID token using the VerifyAccessToken method.
	AccessTokenHash string

	// signature algorithm used for ID token, needed to compute a verification hash of an
	// access token
	sigAlgorithm string

	// Raw payload of the id_token.
	claims []byte

	// Map of distributed claim names to claim sources
	distributedClaims map[string]claimSource
}

// Claims unmarshals the raw JSON payload of the ID Token into a provided struct.
//
//		idToken, err := idTokenVerifier.Verify(rawIDToken)
//		if err != nil {
//			// handle error
//		}
//		var claims struct {
//			Email         string `json:"email"`
//			EmailVerified bool   `json:"email_verified"`
//		}
//		if err := idToken.Claims(&claims); err != nil {
//			// handle error
//		}
//
func (i *IDToken) Claims(v interface{}) error {
	if i.claims == nil {
		return errors.New("oidc: claims not set")
	}
	return json.Unmarshal(i.claims, v)
}

// VerifyAccessToken verifies that the hash of the access token that corresponds to the iD token
// matches the hash in the id token. It returns an error if the hashes  don't match.
// It is the caller's responsibility to ensure that the optional access token hash is present for the ID token
// before calling this method. See https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
func (i *IDToken) VerifyAccessToken(accessToken string) error {
	if i.AccessTokenHash == "" {
		return errNoAtHash
	}
	var h hash.Hash
	switch i.sigAlgorithm {
	case RS256, ES256, PS256:
		h = sha256.New()
	case RS384, ES384, PS384:
		h = sha512.New384()
	case RS512, ES512, PS512:
		h = sha512.New()
	default:
		return fmt.Errorf("oidc: unsupported signing algorithm %q", i.sigAlgorithm)
	}
	h.Write([]byte(accessToken)) // hash documents that Write will never return an error
	sum := h.Sum(nil)[:h.Size()/2]
	actual := base64.RawURLEncoding.EncodeToString(sum)
	if actual != i.AccessTokenHash {
		return errInvalidAtHash
	}
	return nil
}

type idToken struct {
	Issuer       string                 `json:"iss"`
	Subject      string                 `json:"sub"`
	Audience     audience               `json:"aud"`
	Expiry       jsonTime               `json:"exp"`
	IssuedAt     jsonTime               `json:"iat"`
	NotBefore    *jsonTime              `json:"nbf"`
	Nonce        string                 `json:"nonce"`
	AtHash       string                 `json:"at_hash"`
	ClaimNames   map[string]string      `json:"_claim_names"`
	ClaimSources map[string]claimSource `json:"_claim_sources"`
}

type claimSource struct {
	Endpoint    string `json:"endpoint"`
	AccessToken string `json:"access_token"`
}

type stringAsBool bool

func (sb *stringAsBool) UnmarshalJSON(b []byte) error {
	switch string(b) {
	case "true", `"true"`:
		*sb = true
	case "false", `"false"`:
		*sb = false
	default:
		return errors.New("invalid value for boolean")
	}
	return nil
}

type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*a = audience{s}
		return nil
	}
	var auds []string
	if err := json.Unmarshal(b, &auds); err != nil {
		return err
	}
	*a = auds
	return nil
}

type jsonTime time.Time

func (j *jsonTime) UnmarshalJSON(b []byte) error {
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	var unix int64

	if t, err := n.Int64(); err == nil {
		unix = t
	} else {
		f, err := n.Float64()
		if err != nil {
			return err
		}
		unix = int64(f)
	}
	*j = jsonTime(time.Unix(unix, 0))
	return nil
}

func unmarshalResp(r *http.Response, body []byte, v interface{}) error {
	err := json.Unmarshal(body, &v)
	if err == nil {
		return nil
	}
	ct := r.Header.Get("Content-Type")
	mediaType, _, parseErr := mime.ParseMediaType(ct)
	if parseErr == nil && mediaType == "application/json" {
		return fmt.Errorf("got Content-Type = application/json, but could not unmarshal as JSON: %v", err)
	}
	return fmt.Errorf("expected Content-Type = application/json, got %q: %v", ct, err)
}

const (
	issuerGoogleAccounts         = "https://accounts.google.com"
	issuerGoogleAccountsNoScheme = "accounts.google.com"
)

// KeySet is a set of publc JSON Web Keys that can be used to validate the signature
// of JSON web tokens. This is expected to be backed by a remote key set through
// provider metadata discovery or an in-memory set of keys delivered out-of-band.
type KeySet interface {
	// VerifySignature parses the JSON web token, verifies the signature, and returns
	// the raw payload. Header and claim fields are validated by other parts of the
	// package. For example, the KeySet does not need to check values such as signature
	// algorithm, issuer, and audience since the IDTokenVerifier validates these values
	// independently.
	//
	// If VerifySignature makes HTTP requests to verify the token, it's expected to
	// use any HTTP client associated with the context through ClientContext.
	VerifySignature(ctx context.Context, jwt string) (payload []byte, err error)
}

// IDTokenVerifier provides verification for ID Tokens.
type IDTokenVerifier struct {
	keySet KeySet
	config *Config
	issuer string
}

// NewVerifier returns a verifier manually constructed from a key set and issuer URL.
//
// It's easier to use provider discovery to construct an IDTokenVerifier than creating
// one directly. This method is intended to be used with provider that don't support
// metadata discovery, or avoiding round trips when the key set URL is already known.
//
// This constructor can be used to create a verifier directly using the issuer URL and
// JSON Web Key Set URL without using discovery:
//
//		keySet := oidc.NewRemoteKeySet(ctx, "https://www.googleapis.com/oauth2/v3/certs")
//		verifier := oidc.NewVerifier("https://accounts.google.com", keySet, config)
//
// Since KeySet is an interface, this constructor can also be used to supply custom
// public key sources. For example, if a user wanted to supply public keys out-of-band
// and hold them statically in-memory:
//
//		// Custom KeySet implementation.
//		keySet := newStatisKeySet(publicKeys...)
//
//		// Verifier uses the custom KeySet implementation.
//		verifier := oidc.NewVerifier("https://auth.example.com", keySet, config)
//
func NewVerifier(issuerURL string, keySet KeySet, config *Config) *IDTokenVerifier {
	return &IDTokenVerifier{keySet: keySet, config: config, issuer: issuerURL}
}

// Config is the configuration for an IDTokenVerifier.
type Config struct {
	// Expected audience of the token. For a majority of the cases this is expected to be
	// the ID of the client that initialized the login flow. It may occasionally differ if
	// the provider supports the authorizing party (azp) claim.
	//
	// If not provided, users must explicitly set SkipClientIDCheck.
	ClientID string
	// If specified, only this set of algorithms may be used to sign the JWT.
	//
	// If the IDTokenVerifier is created from a provider with (*Provider).Verifier, this
	// defaults to the set of algorithms the provider supports. Otherwise this values
	// defaults to RS256.
	SupportedSigningAlgs []string

	// If true, no ClientID check performed. Must be true if ClientID field is empty.
	SkipClientIDCheck bool
	// If true, token expiry is not checked.
	SkipExpiryCheck bool

	// SkipIssuerCheck is intended for specialized cases where the the caller wishes to
	// defer issuer validation. When enabled, callers MUST independently verify the Token's
	// Issuer is a known good value.
	//
	// Mismatched issuers often indicate client mis-configuration. If mismatches are
	// unexpected, evaluate if the provided issuer URL is incorrect instead of enabling
	// this option.
	SkipIssuerCheck bool

	// Time function to check Token expiry. Defaults to time.Now
	Now func() time.Time
}

// Verifier returns an IDTokenVerifier that uses the provider's key set to verify JWTs.
//
// The returned IDTokenVerifier is tied to the Provider's context and its behavior is
// undefined once the Provider's context is canceled.
func (p *Provider) Verifier(config *Config) *IDTokenVerifier {
	if len(config.SupportedSigningAlgs) == 0 && len(p.algorithms) > 0 {
		// Make a copy so we don't modify the config values.
		cp := &Config{}
		*cp = *config
		cp.SupportedSigningAlgs = p.algorithms
		config = cp
	}
	return NewVerifier(p.issuer, p.remoteKeySet, config)
}

func parseJWT(p string) ([]byte, error) {
	parts := strings.Split(p, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("oidc: malformed jwt, expected 3 parts got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt payload: %v", err)
	}
	return payload, nil
}

func contains(sli []string, ele string) bool {
	for _, s := range sli {
		if s == ele {
			return true
		}
	}
	return false
}

// Returns the Claims from the distributed JWT token
func resolveDistributedClaim(ctx context.Context, verifier *IDTokenVerifier, src claimSource) ([]byte, error) {
	req, err := http.NewRequest("GET", src.Endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("malformed request: %v", err)
	}
	if src.AccessToken != "" {
		req.Header.Set("Authentication", "Bearer "+src.AccessToken)
	}

	resp, err := doRequest(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("oidc: Request to endpoint failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: request failed: %v", resp.StatusCode)
	}

	token, err := verifier.Verify(ctx, string(body))
	if err != nil {
		return nil, fmt.Errorf("malformed response body: %v", err)
	}

	return token.claims, nil
}

// Verify parses a raw ID Token, verifies it's been signed by the provider, performs
// any additional checks depending on the Config, and returns the payload.
//
// Verify does NOT do nonce validation, which is the callers responsibility.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
//
//    oauth2Token, err := oauth2Config.Exchange(ctx, r.URL.Query().Get("code"))
//    if err != nil {
//        // handle error
//    }
//
//    // Extract the ID Token from oauth2 token.
//    rawIDToken, ok := oauth2Token.Extra("id_token").(string)
//    if !ok {
//        // handle error
//    }
//
//    token, err := verifier.Verify(ctx, rawIDToken)
//
func (v *IDTokenVerifier) Verify(ctx context.Context, rawIDToken string) (*IDToken, error) {
	return &IDToken{}, nil
	// 	jws, err := jose.ParseSigned(rawIDToken)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("oidc: malformed jwt: %v", err)
	// 	}

	// 	// Throw out tokens with invalid claims before trying to verify the token. This lets
	// 	// us do cheap checks before possibly re-syncing keys.
	// 	payload, err := parseJWT(rawIDToken)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("oidc: malformed jwt: %v", err)
	// 	}
	// 	var token idToken
	// 	if err := json.Unmarshal(payload, &token); err != nil {
	// 		return nil, fmt.Errorf("oidc: failed to unmarshal claims: %v", err)
	// 	}

	// 	distributedClaims := make(map[string]claimSource)

	// 	//step through the token to map claim names to claim sources"
	// 	for cn, src := range token.ClaimNames {
	// 		if src == "" {
	// 			return nil, fmt.Errorf("oidc: failed to obtain source from claim name")
	// 		}
	// 		s, ok := token.ClaimSources[src]
	// 		if !ok {
	// 			return nil, fmt.Errorf("oidc: source does not exist")
	// 		}
	// 		distributedClaims[cn] = s
	// 	}

	// 	t := &IDToken{
	// 		Issuer:            token.Issuer,
	// 		Subject:           token.Subject,
	// 		Audience:          []string(token.Audience),
	// 		Expiry:            time.Time(token.Expiry),
	// 		IssuedAt:          time.Time(token.IssuedAt),
	// 		Nonce:             token.Nonce,
	// 		AccessTokenHash:   token.AtHash,
	// 		claims:            payload,
	// 		distributedClaims: distributedClaims,
	// 	}

	// 	// Check issuer.
	// 	if !v.config.SkipIssuerCheck && t.Issuer != v.issuer {
	// 		// Google sometimes returns "accounts.google.com" as the issuer claim instead of
	// 		// the required "https://accounts.google.com". Detect this case and allow it only
	// 		// for Google.
	// 		//
	// 		// We will not add hooks to let other providers go off spec like this.
	// 		if !(v.issuer == issuerGoogleAccounts && t.Issuer == issuerGoogleAccountsNoScheme) {
	// 			return nil, fmt.Errorf("oidc: id token issued by a different provider, expected %q got %q", v.issuer, t.Issuer)
	// 		}
	// 	}

	// 	// If a client ID has been provided, make sure it's part of the audience. SkipClientIDCheck must be true if ClientID is empty.
	// 	//
	// 	// This check DOES NOT ensure that the ClientID is the party to which the ID Token was issued (i.e. Authorized party).
	// 	if !v.config.SkipClientIDCheck {
	// 		if v.config.ClientID != "" {
	// 			if !contains(t.Audience, v.config.ClientID) {
	// 				return nil, fmt.Errorf("oidc: expected audience %q got %q", v.config.ClientID, t.Audience)
	// 			}
	// 		} else {
	// 			return nil, fmt.Errorf("oidc: invalid configuration, clientID must be provided or SkipClientIDCheck must be set")
	// 		}
	// 	}

	// 	// If a SkipExpiryCheck is false, make sure token is not expired.
	// 	if !v.config.SkipExpiryCheck {
	// 		now := time.Now
	// 		if v.config.Now != nil {
	// 			now = v.config.Now
	// 		}
	// 		nowTime := now()

	// 		if t.Expiry.Before(nowTime) {
	// 			return nil, fmt.Errorf("oidc: token is expired (Token Expiry: %v)", t.Expiry)
	// 		}

	// 		// If nbf claim is provided in token, ensure that it is indeed in the past.
	// 		if token.NotBefore != nil {
	// 			nbfTime := time.Time(*token.NotBefore)
	// 			// Set to 5 minutes since this is what other OpenID Connect providers do to deal with clock skew.
	// 			// https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/blob/6.12.2/src/Microsoft.IdentityModel.Tokens/TokenValidationParameters.cs#L149-L153
	// 			leeway := 5 * time.Minute

	// 			if nowTime.Add(leeway).Before(nbfTime) {
	// 				return nil, fmt.Errorf("oidc: current time %v before the nbf (not before) time: %v", nowTime, nbfTime)
	// 			}
	// 		}
	// 	}

	// 	switch len(jws.Signatures) {
	// 	case 0:
	// 		return nil, fmt.Errorf("oidc: id token not signed")
	// 	case 1:
	// 	default:
	// 		return nil, fmt.Errorf("oidc: multiple signatures on id token not supported")
	// 	}

	// 	sig := jws.Signatures[0]
	// 	supportedSigAlgs := v.config.SupportedSigningAlgs
	// 	if len(supportedSigAlgs) == 0 {
	// 		supportedSigAlgs = []string{RS256}
	// 	}

	// 	if !contains(supportedSigAlgs, sig.Header.Algorithm) {
	// 		return nil, fmt.Errorf("oidc: id token signed with unsupported algorithm, expected %q got %q", supportedSigAlgs, sig.Header.Algorithm)
	// 	}

	// 	t.sigAlgorithm = sig.Header.Algorithm

	// 	gotPayload, err := v.keySet.VerifySignature(ctx, rawIDToken)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("failed to verify signature: %v", err)
	// 	}

	// 	// Ensure that the payload returned by the square actually matches the payload parsed earlier.
	// 	if !bytes.Equal(gotPayload, payload) {
	// 		return nil, errors.New("oidc: internal error, payload parsed did not match previous payload")
	// 	}

	// 	return t, nil
}

// Nonce returns an auth code option which requires the ID Token created by the
// OpenID Connect provider to contain the specified nonce.
func Nonce(nonce string) oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("nonce", nonce)
}
