package vault

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/evidenceledger/gosiop2/ent"
	"github.com/evidenceledger/gosiop2/ent/account"
	"github.com/evidenceledger/gosiop2/internal/jwt"

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
	Client *ent.Client
	Ctx    context.Context
}

var mutexForNew sync.Mutex

func New(driverName string, dataSourceName string) (v *Vault, err error) {

	// Make sure only one thread performs initialization of the database,
	// including migrations
	mutexForNew.Lock()
	defer mutexForNew.Unlock()

	v = &Vault{}

	v.Client, err = ent.Open(driverName, dataSourceName)
	if err != nil {
		zlog.Error().Err(err).Msg("failed opening database")
		return nil, err
	}
	v.Ctx = context.Background()

	// Run the auto migration tool.
	if err := v.Client.Schema.Create(v.Ctx); err != nil {
		zlog.Error().Err(err).Str("dataSourceName", dataSourceName).Msg("failed creating schema resources")
		return nil, err
	}

	return v, nil
}

func NewFromDBClient(entClient *ent.Client) (v *Vault) {

	v = &Vault{}
	v.Client = entClient
	v.Ctx = context.Background()

	return v
}

func (v *Vault) CreateAccountWithKey(name string) (acc *ent.Account, err error) {

	// Check if the account already exists
	num := v.Client.Account.Query().Where(account.Name(name)).CountX(v.Ctx)
	if num > 0 {
		return nil, fmt.Errorf("account already exists")
	}

	// Create new acount
	acc, err = v.Client.Account.
		Create().
		SetName(name).
		Save(v.Ctx)
	if err != nil {
		return nil, err
	}

	_, err = v.AddKeyToAccount(name)
	if err != nil {
		return nil, err
	}

	zlog.Info().Str("name", name).Msg("account created")

	return acc, nil

}

func (v *Vault) AddKeyToAccount(name string) (*ent.PrivateKey, error) {

	// Get the account
	acc, err := v.Client.Account.Query().Where(account.Name(name)).Only(v.Ctx)
	if err != nil {
		return nil, err
	}

	// Create a new private key, of the preferred type
	privKey, err := jwt.NewECDSA()
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
	dbKey, err := v.Client.PrivateKey.
		Create().
		SetID(kid).
		SetKty("EC").
		SetJwk(asJSON).
		SetAccount(acc).
		Save(v.Ctx)
	if err != nil {
		zlog.Error().Err(err).Msg("failed storing key")
		return nil, err
	}
	zlog.Info().Str("kid", kid).Msg("key created")

	acc.Update().AddKeys(dbKey).Save(v.Ctx)

	zlog.Info().Str("name", name).Msg("account updated")

	return dbKey, nil

}

func (v *Vault) QueryAccount(name string) (acc *ent.Account, err error) {
	a, err := v.Client.Account.
		Query().
		Where(account.Name(name)).
		// `Only` fails if no user found,
		// or more than 1 user returned.
		Only(v.Ctx)
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

func (v *Vault) QueryJWKSForAccount(name string) (keys []*jwt.JWK, err error) {

	acc, err := v.QueryAccount(name)
	if err != nil {
		zlog.Error().Err(err).Str("name", name).Send()
		return nil, err
	}

	entKeys, err := acc.QueryKeys().All(v.Ctx)
	if err != nil {
		zlog.Error().Err(err).Str("name", name).Send()
		return nil, err
	}

	keys = make([]*jwt.JWK, len(entKeys))

	for i, k := range entKeys {
		jwkKey, err := jwt.NewFromBytes(k.Jwk)
		if err != nil {
			continue
		}
		keys[i] = jwkKey
	}

	return keys, nil
}

func (v *Vault) QueryJWKByID(id string) (jwkKey *jwt.JWK, err error) {

	// Retrieve key by its ID, which should be unique
	k, err := v.Client.PrivateKey.Get(v.Ctx, id)
	if err != nil {
		return nil, err
	}

	// Convert to JWK format
	jwkKey, err = jwt.NewFromBytes(k.Jwk)
	if err != nil {
		return nil, err
	}

	return jwkKey, err
}

// SignJWT signs the JWT using the algorithm and key ID in its header
func (v *Vault) SignWithJWK(k *jwt.JWK, claims any) (signedString string, err error) {

	var jsonValue []byte
	var toBeSigned string

	// Create the headerMap
	headerMap := map[string]string{
		"typ": "JWT",
		"alg": k.GetAlg(),
		"kid": k.GetKid(),
	}

	if jsonValue, err = json.Marshal(headerMap); err != nil {
		return "", err
	}
	header := base64.RawURLEncoding.EncodeToString(jsonValue)

	if jsonValue, err = json.Marshal(claims); err != nil {
		return "", err
	}
	claim := base64.RawURLEncoding.EncodeToString(jsonValue)

	toBeSigned = strings.Join([]string{header, claim}, ".")

	// Perform the signature
	signedString, err = v.SignString(toBeSigned, headerMap["kid"])

	return signedString, err

}

// SignJWT signs the JWT using the algorithm and key ID in its header
func (v *Vault) SignJWT(token *jwt.Token) (signedString string, err error) {

	var toBeSigned string

	// Convert token to a serialized string to be signed
	if toBeSigned, err = token.SigningString(); err != nil {
		return "", err
	}

	// Perform the signature
	signedString, err = v.SignString(toBeSigned, token.Kid())

	return signedString, err

}

// SignString signs the string using the key with given ID and using algorithm alg
func (v *Vault) SignString(toBeSigned string, kid string) (signedString string, err error) {

	var signature string

	// Get the private key for signing
	jwkKey, err := v.QueryJWKByID(kid)
	if err != nil {
		return "", err
	}

	// Convert the key to native
	key, err := jwkKey.GetPrivateKey()
	if err != nil {
		return "", err
	}

	// Get the algorithm from the JWK (it is compulsory for our application)
	alg := jwkKey.GetAlg()

	// Get the method for signing
	method := jwt.GetSigningMethod(alg)

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
	jwkKey, err := v.QueryJWKByID(kid)
	if err != nil {
		return err
	}

	// Check that the externally specified 'alg' matches the 'alg' in the JWK
	if jwkKey.GetAlg() != alg {
		return fmt.Errorf("alg does not match with alg in the JWK")
	}

	// Convert the key to native
	key, err := jwkKey.GetPublicKey()
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
