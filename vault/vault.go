package vault

import (
	"context"
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

type Vault struct {
	client *ent.Client
	ctx    context.Context
}

var mutexForNew sync.Mutex

func New(driverName string, dataSourceName string) (v *Vault, err error) {

	// Make sure only one thread performs initialization of the database,
	// including migrations
	mutexForNew.Lock()
	defer mutexForNew.Unlock()

	v = &Vault{}

	v.client, err = ent.Open(driverName, dataSourceName)
	if err != nil {
		zlog.Error().Err(err).Msg("failed opening database")
		return nil, err
	}
	v.ctx = context.Background()

	// Run the auto migration tool.
	if err := v.client.Schema.Create(v.ctx); err != nil {
		zlog.Error().Err(err).Msg("failed creating schema resources")
		return nil, err
	}

	return v, nil
}

func (v *Vault) CreateAccountWithKey(name string) (*ent.Account, error) {

	// Check if the account already exists
	num := v.client.Account.Query().Where(account.Name(name)).CountX(v.ctx)
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
	dbKey, err := v.client.PrivateKey.
		Create().
		SetID(kid).
		SetKty("EC").
		SetJwk(asJSON).
		Save(v.ctx)
	if err != nil {
		zlog.Error().Err(err).Msg("failed storing key")
		return nil, err
	}
	zlog.Info().Str("kid", kid).Msg("key created")

	// Create new acount
	account, err := v.client.Account.
		Create().
		SetName(name).
		AddKeys(dbKey).
		Save(v.ctx)

	zlog.Info().Str("name", name).Msg("account created")

	return account, nil

}

func (v *Vault) AddKeyToAccount(name string) (*ent.PrivateKey, error) {

	// Get the account
	acc, err := v.client.Account.Query().Where(account.Name(name)).Only(v.ctx)
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
	dbKey, err := v.client.PrivateKey.
		Create().
		SetID(kid).
		SetKty("EC").
		SetJwk(asJSON).
		Save(v.ctx)
	if err != nil {
		zlog.Error().Err(err).Msg("failed storing key")
		return nil, err
	}
	zlog.Info().Str("kid", kid).Msg("key created")

	acc.Update().AddKeys(dbKey).Save(v.ctx)

	zlog.Info().Str("name", name).Msg("account updated")

	return dbKey, nil

}

func (v *Vault) QueryAccount(name string) (acc *ent.Account, err error) {
	a, err := v.client.Account.
		Query().
		Where(account.Name(name)).
		// `Only` fails if no user found,
		// or more than 1 user returned.
		Only(v.ctx)
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

func (v *Vault) QueryKeysForAccount(name string) (keys []*key.JWK, err error) {

	acc, err := v.QueryAccount(name)
	if err != nil {
		zlog.Error().Err(err).Str("name", name).Send()
		return nil, err
	}

	entKeys, err := acc.QueryKeys().All(v.ctx)
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

func (v *Vault) QueryKeyByID(id string) (jwk *key.JWK, err error) {

	// Retrieve key by its ID, which should be unique
	k, err := v.client.PrivateKey.Get(v.ctx, id)
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

// SignJWT signs the JWT using the algorithm and key ID in its header
func (v *Vault) SignJWT(token *jwt.Token) (signedString string, err error) {

	var toBeSigned string

	// Convert token to a serialized string to be signed
	if toBeSigned, err = token.SigningString(); err != nil {
		return "", err
	}

	// Perform the signature
	signedString, err = v.SignString(toBeSigned, token.Alg(), token.Kid())

	return signedString, err

}

// SignString signs the string using the key with given ID and using algorithm alg
func (v *Vault) SignString(toBeSigned string, alg string, kid string) (signedString string, err error) {

	var signature string

	// Get the method for signing
	method := jwt.GetSigningMethod(alg)

	// Get the private key for signing
	jwk, err := v.QueryKeyByID(kid)
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

// VerifySignature verifies that a signature corresponds to a signed string given a jey ID and algorithm
func (v *Vault) VerifySignature(signedString string, signature string, alg string, kid string) (err error) {

	// Get the key for verification
	jwk, err := v.QueryKeyByID(kid)
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
