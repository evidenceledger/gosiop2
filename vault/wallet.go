package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/evidenceledger/gosiop2/ent"
	"github.com/evidenceledger/gosiop2/ent/account"
	"github.com/evidenceledger/gosiop2/jwt"
	"github.com/evidenceledger/gosiop2/vault/key"

	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
)

func init() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zlog.Logger = zlog.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	zlog.Logger = zlog.With().Caller().Logger()
}

type Wallet struct {
	client *ent.Client
	ctx    context.Context
}

var mutexForNew sync.Mutex

func New(driverName string, dataSourceName string) (w *Wallet, err error) {

	// Make sure only one thread performs initialization of the database,
	// including migrations
	mutexForNew.Lock()
	defer mutexForNew.Unlock()

	w = &Wallet{}

	w.client, err = ent.Open(driverName, dataSourceName)
	if err != nil {
		zlog.Error().Err(err).Msg("failed opening database")
		return nil, err
	}
	w.ctx = context.Background()

	// Run the auto migration tool.
	if err := w.client.Schema.Create(w.ctx); err != nil {
		zlog.Error().Err(err).Msg("failed creating schema resources")
		return nil, err
	}

	return w, nil
}

func (w *Wallet) CreateAccountWithKey(name string) (*ent.Account, error) {

	// Check if the account already exists
	num := w.client.Account.Query().Where(account.Name(name)).CountX(w.ctx)
	if num > 0 {
		return nil, fmt.Errorf("account already exists")
	}

	// Create a new private key.
	privKey, err := key.NewECDSA()
	if err != nil {
		zlog.Error().Err(err).Msg("failed creating new native ECDSA key")
		return nil, err
	}

	// Convert to JSON-JWK
	asJSON, err := privKey.AsJSON()
	if err != nil {
		zlog.Error().Err(err).Msg("failed converting key to json")
		return nil, err
	}

	// Store in DB
	kid := privKey.GetKid()
	dbKey, err := w.client.PrivateKey.
		Create().
		SetID(kid).
		SetKty("EC").
		SetJwk(asJSON).
		Save(w.ctx)
	if err != nil {
		zlog.Error().Err(err).Msg("failed storing key")
		return nil, err
	}
	zlog.Info().Str("kid", kid).Msg("key created")

	// Create new acount
	account, err := w.client.Account.
		Create().
		SetName(name).
		AddKeys(dbKey).
		Save(w.ctx)

	zlog.Info().Str("name", name).Msg("account created")

	return account, nil

}

func (w *Wallet) AddKeyToAccount(name string) (*ent.PrivateKey, error) {

	// Get the account
	acc, err := w.client.Account.Query().Where(account.Name(name)).Only(w.ctx)
	if err != nil {
		return nil, err
	}

	// Create a new private key.
	privKey, err := key.NewECDSA()
	if err != nil {
		zlog.Error().Err(err).Msg("failed creating new native ECDSA key")
		return nil, err
	}

	// Convert to JSON-JWK
	asJSON, err := privKey.AsJSON()
	if err != nil {
		zlog.Error().Err(err).Msg("failed converting key to json")
		return nil, err
	}

	// Store in DB
	kid := privKey.GetKid()
	dbKey, err := w.client.PrivateKey.
		Create().
		SetID(kid).
		SetKty("EC").
		SetJwk(asJSON).
		Save(w.ctx)
	if err != nil {
		zlog.Error().Err(err).Msg("failed storing key")
		return nil, err
	}
	zlog.Info().Str("kid", kid).Msg("key created")

	acc.Update().AddKeys(dbKey).Save(w.ctx)

	zlog.Info().Str("name", name).Msg("account updated")

	return dbKey, nil

}

func (w *Wallet) QueryAccount(name string) (acc *ent.Account, err error) {
	a, err := w.client.Account.
		Query().
		Where(account.Name(name)).
		// `Only` fails if no user found,
		// or more than 1 user returned.
		Only(w.ctx)
	if _, ok := err.(*ent.NotFoundError); ok {
		zlog.Debug().Err(err).Str("name", name).Msg("account not found")
		return nil, err
	}
	if err != nil {
		zlog.Error().Err(err).Str("name", name).Msg("failed querying account")
		return nil, fmt.Errorf("failed querying user: %w", err)
	}
	zlog.Info().Str("name", name).Msg("account retrieved")
	return a, nil

}

func (w *Wallet) QueryKeysForAccount(name string) (keys []*key.JWK, err error) {

	acc, err := w.QueryAccount(name)
	if err != nil {
		zlog.Error().Err(err).Str("name", name).Send()
		return nil, err
	}

	entKeys, err := acc.QueryKeys().All(w.ctx)
	if err != nil {
		zlog.Error().Err(err).Str("name", name).Send()
		return nil, err
	}

	keys = make([]*key.JWK, len(entKeys))

	for i, k := range entKeys {
		jwkKey, err := key.NewFromBytes(k.Jwk)
		if err != nil {
			continue
		}
		keys[i] = jwkKey
	}

	return keys, nil
}

func (w *Wallet) QueryKeyByID(id string) (jwk *key.JWK, err error) {

	// Retrieve key by its ID, which should be unique
	k, err := w.client.PrivateKey.Get(w.ctx, id)
	if err != nil {
		return nil, err
	}

	// Convert to JWK format
	jwk, err = key.NewFromBytes(k.Jwk)
	if err != nil {
		return nil, err
	}

	return jwk, err
}

func (w *Wallet) VerifySerializedJWT(tokenString string) (verified bool, err error) {

	// A JWT token is composed of 3 parts concatenated by dots (".")
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return false, jwt.NewValidationError("token contains an invalid number of segments", jwt.ValidationErrorMalformed)
	}

	// Initialize the Token struct
	token := &jwt.Token{Raw: tokenString}

	// Parse Header
	var headerBytes []byte
	if headerBytes, err = jwt.DecodeSegment(parts[0]); err != nil {
		return false, &jwt.ValidationError{Inner: err, Errors: jwt.ValidationErrorMalformed}
	}
	if err = json.Unmarshal(headerBytes, &token.Header); err != nil {
		return false, &jwt.ValidationError{Inner: err, Errors: jwt.ValidationErrorMalformed}
	}

	// TODO: verify header for minimum requirements, eg alg and kid

	// Lookup signature alg
	alg, ok := token.Header["alg"].(string)
	if !ok {
		return false, jwt.NewValidationError("signing method (alg) not in token header.", jwt.ValidationErrorUnverifiable)
	}

	// Lookup signature kid
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return false, jwt.NewValidationError("signing method (alg) not in token header.", jwt.ValidationErrorUnverifiable)
	}

	// Get the key for verification
	jwk, err := w.QueryKeyByID(kid)
	if err != nil {
		return false, err
	}

	// Convert the key to native
	key, err := jwk.GetPublicKey()
	if err != nil {
		return false, err
	}

	// parse Claims
	var claimBytes []byte
	var claims = make(jwt.MapClaims)
	token.Claims = claims
	if claimBytes, err = jwt.DecodeSegment(parts[1]); err != nil {
		return false, &jwt.ValidationError{Inner: err, Errors: jwt.ValidationErrorMalformed}
	}

	// JSON Decode
	dec := json.NewDecoder(bytes.NewBuffer(claimBytes))
	dec.UseNumber()
	err = dec.Decode(&claims)
	if err != nil {
		return false, &jwt.ValidationError{Inner: err, Errors: jwt.ValidationErrorMalformed}
	}

	// TODO: verify claims for minimum requirements

	if token.Method = jwt.GetSigningMethod(alg); token.Method == nil {
		return false, jwt.NewValidationError("signing method (alg) is unavailable.", jwt.ValidationErrorUnverifiable)
	}

	// Concatenate headers and claims as undecoded strings
	signingString := strings.Join(parts[0:2], ".")

	// The signature part is the third
	token.Signature = parts[2]

	// Verify signature
	if err = token.Method.Verify(signingString, token.Signature, key); err != nil {
		return false, jwt.NewValidationError("signature not verified.", jwt.ValidationErrorSignatureInvalid)
	}

	// All validations performed, reply with success
	return true, nil

}

func (w *Wallet) SignJWT(token *jwt.Token) (signedString string, err error) {

	var toBeSigned string

	// Convert token to a serialized string to be signed
	if toBeSigned, err = token.SigningString(); err != nil {
		return "", err
	}

	// Get the key id used in this token
	kid := (token.Header["kid"]).(string)

	// Get the algorithm used to sign
	alg := (token.Header["alg"]).(string)

	signedString, err = w.SignString(toBeSigned, alg, kid)

	return signedString, err

}

func (w *Wallet) SignString(toBeSigned string, alg string, kid string) (signedString string, err error) {

	var signature string

	// Get the method for signing
	method := jwt.GetSigningMethod(alg)

	// Get the private key for signing
	jwk, err := w.QueryKeyByID(kid)
	if err != nil {
		return "", err
	}

	// Convert the key to native
	key, err := jwk.GetPrivateKey()
	if err != nil {
		return "", err
	}

	// Sign the string
	if signature, err = method.Sign(toBeSigned, key); err != nil {
		return "", err
	}

	// Concatenate the signature with a "." as specified in the JWT standards
	return strings.Join([]string{toBeSigned, signature}, "."), nil

}

// *****************************************************
// *****************************************************

func (w *Wallet) VerifySignature(signedString string, signature string, alg string, kid string) (err error) {

	// Get the key for verification
	jwk, err := w.QueryKeyByID(kid)
	if err != nil {
		return err
	}

	// Convert the key to native
	key, err := jwk.GetPublicKey()
	if err != nil {
		return err
	}

	// Get the method to verify
	method := jwt.GetSigningMethod(alg)
	if method == nil {
		return fmt.Errorf("signing method (alg) is unavailable.")
	}

	// Verify signature
	if err = method.Verify(signedString, signature, key); err != nil {
		return err
	}

	// Verification performed, reply with success
	return nil

}
