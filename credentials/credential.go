package credentials

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	"github.com/evidenceledger/gosiop2/ent"
	"github.com/evidenceledger/gosiop2/internal/gyaml"
	"github.com/evidenceledger/gosiop2/internal/jwt"
	"github.com/evidenceledger/gosiop2/vault"
	"github.com/google/uuid"
	zlog "github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"github.com/tidwall/gjson"
)

type CredentialData struct {
	Jti                string `json:"jti" yaml:"jti"`
	CredName           string `json:"cred_name"`
	IssuerDID          string `json:"iss"`
	SubjectDID         string `json:"did"`
	Name               string `json:"name"`
	Given_name         string `json:"given_name"`
	Family_name        string `json:"family_name"`
	Preferred_username string `json:"preferred_username"`
	Email              string `json:"email"`
}

var credentialExamples = []*CredentialData{
	{
		Jti:                "https://pdc.i4trust.fiware.io/credentials/1872",
		CredName:           "employee",
		IssuerDID:          "did:elsi:EU.EORI.NLPACKETDELIVERY",
		SubjectDID:         "did:uuid:09b8a75c-6e8a-4992-ad47-362311595ec5",
		Name:               "Perico Perez",
		Given_name:         "Perico",
		Family_name:        "Perez",
		Preferred_username: "Pepe",
		Email:              "pepe.perez@gmaily.com",
	},
	{
		Jti:                "https://pdc.i4trust.fiware.io/credentials/2765",
		CredName:           "customer",
		IssuerDID:          "did:elsi:EU.EORI.NLHAPPYPETS",
		SubjectDID:         "did:uuid:09b8a75c-6e8a-4992-ad47-362311595ec5",
		Name:               "Perico Perez",
		Given_name:         "Perico",
		Family_name:        "Perez",
		Preferred_username: "Pepe",
		Email:              "pepe.perez@gmaily.com",
	},
}

var t *template.Template

func init() {

	myfuncs := make(template.FuncMap, 10)
	myfuncs["saludaA"] = saludaA
	t = template.Must(template.New("base").Funcs(myfuncs).Funcs(sprig.TxtFuncMap()).ParseGlob("/home/jesus/gosrc/gosiop2/credentials/templates/*.tpl"))

}

type CredentialStore struct {
	Client *ent.Client
	Ctx    context.Context
}

func saludaA(in string) string {
	return "Hola que tal estas " + in
}

var mutexForNew sync.Mutex

func New(cfg *viper.Viper) (c *CredentialStore, err error) {

	if cfg == nil {
		return nil, fmt.Errorf("no configuration received")
	}

	// Make sure only one thread performs initialization of the database,
	// including migrations
	mutexForNew.Lock()
	defer mutexForNew.Unlock()

	// Get the configured parameters for the database
	driverName := cfg.GetString("db.driverName")
	dataSourceName := cfg.GetString("db.dataSourceName")
	zlog.Info().Str("driverName", driverName).Str("dataSourceName", dataSourceName).Msg("opening credentials")

	c = &CredentialStore{}

	// Open connection to the database
	c.Client, err = ent.Open(driverName, dataSourceName)
	if err != nil {
		zlog.Logger.Error().Err(err).Msg("failed opening database")
		return nil, err
	}
	c.Ctx = context.Background()

	// Run the auto migration tool.
	if err := c.Client.Schema.Create(c.Ctx); err != nil {
		zlog.Logger.Error().Err(err).Msg("failed creating schema resources")
		return nil, err
	}

	return c, nil
}

func NewFromDBClient(entClient *ent.Client) (c *CredentialStore) {

	c = &CredentialStore{}
	c.Client = entClient
	c.Ctx = context.Background()

	return c
}

func GetCredentials(credName string, v *vault.Vault) (json.RawMessage, error) {
	var b bytes.Buffer

	credData := credentialExamples[1]
	fmt.Println(credData)

	err := t.ExecuteTemplate(&b, credName, credData)
	if err != nil {
		return nil, err
	}
	fmt.Println("*******************************************************")
	fmt.Println(string(b.Bytes()))
	fmt.Println("*******************************************************")
	return b.Bytes(), nil
}

func (c *CredentialStore) TestCred(credData *CredentialData) (rawJsonCred json.RawMessage, err error) {

	// Generate the id as a UUID
	jti, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	// Set the unique id in the credential
	credData.Jti = jti.String()

	// Generate the credential from the template
	var b bytes.Buffer
	err = t.ExecuteTemplate(&b, credData.CredName, credData)
	if err != nil {
		return nil, err
	}

	// The serialized credential
	rawJsonCred = b.Bytes()

	// Validate the generated JSON, just in case the template is malformed
	if !gjson.ValidBytes(b.Bytes()) {
		zlog.Error().Msg("Error validating JSON")
		return nil, nil
	}
	m, ok := gjson.ParseBytes(b.Bytes()).Value().(map[string]interface{})
	if !ok {
		return nil, nil
	}

	rj, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}

	zlog.Info().Msgf("Value: %T\n\n%v", rj, string(rj))

	// cc := make(map[string]any)

	return nil, nil

}

func (c *CredentialStore) CreateCredential(credData *CredentialData) (rawJsonCred json.RawMessage, err error) {

	// Check if the issuer has already an account
	v := vault.NewFromDBClient(c.Client)
	acc, err := v.QueryAccount(credData.IssuerDID)
	if err != nil {
		return nil, err
	}

	// Good to proceed

	// Generate the id as a UUID
	jti, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	// Set the unique id in the credential
	credData.Jti = jti.String()

	// Generate the credential from the template
	var b bytes.Buffer
	err = t.ExecuteTemplate(&b, credData.CredName, credData)
	if err != nil {
		return nil, err
	}

	// The serialized credential
	rawJsonCred = b.Bytes()

	// Validate the generated JSON, just in case the template is malformed
	m, ok := gjson.ParseBytes(b.Bytes()).Value().(map[string]interface{})
	if !ok {
		zlog.Error().Msg("Error validating JSON")
		return nil, nil
	}

	// Generate a compact JSON string
	rj, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}

	// Store in DB
	_, err = c.Client.Credential.
		Create().
		SetID(credData.Jti).
		SetRaw(rj).
		SetAccount(acc).
		Save(c.Ctx)
	if err != nil {
		zlog.Error().Err(err).Msg("failed storing credential")
		return nil, err
	}
	zlog.Info().Str("jti", credData.Jti).Msg("credential created")

	return rj, nil

}

func (c *CredentialStore) CreateCredentialFromMap(credData map[string]string) (rawJsonCred json.RawMessage, err error) {

	// Check if the issuer has already an account
	v := vault.NewFromDBClient(c.Client)
	acc, err := v.QueryAccount(credData["issuerDID"])
	if err != nil {
		return nil, err
	}

	// If credential ID specified in the input data, do not generate a new one
	if _, ok := credData["Jti"]; !ok {

		// Generate the id as a UUID
		jti, err := uuid.NewRandom()
		if err != nil {
			return nil, err
		}

		// Set the unique id in the credential
		credData["Jti"] = jti.String()

	}

	// Generate the credential from the template
	var b bytes.Buffer
	err = t.ExecuteTemplate(&b, credData["credName"], credData)
	if err != nil {
		return nil, err
	}

	// The serialized credential
	rawJsonCred = b.Bytes()

	// Validate the generated JSON, just in case the template is malformed
	m, ok := gjson.ParseBytes(b.Bytes()).Value().(map[string]interface{})
	if !ok {
		zlog.Error().Msg("Error validating JSON")
		return nil, nil
	}

	// Generate a compact JSON string
	rj, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}

	// Store in DB
	_, err = c.Client.Credential.
		Create().
		SetID(credData["Jti"]).
		SetRaw(rj).
		SetAccount(acc).
		Save(c.Ctx)
	if err != nil {
		zlog.Error().Err(err).Msg("failed storing credential")
		return nil, err
	}
	zlog.Info().Str("jti", credData["Jti"]).Msg("credential created")

	return rj, nil

}

type CredRawData struct {
	Type    string `json:"type"`
	Encoded string `json:"encoded"`
}

func (c *CredentialStore) GetAllCredentials() (creds []*CredRawData) {

	entCredentials, err := c.Client.Credential.Query().All(c.Ctx)
	if err != nil {
		return nil
	}

	credentials := make([]*CredRawData, len(entCredentials))

	for i, cred := range entCredentials {
		credentials[i].Type = cred.Type
		credentials[i].Encoded = string(cred.Raw)
	}

	return credentials

}

func (c *CredentialStore) CreateOrGetCredential(credData *CredentialData) (rawJsonCred json.RawMessage, err error) {

	// Check if the credential already exists
	cred, err := c.Client.Credential.Get(c.Ctx, credData.Jti)
	if err == nil {
		// Credential found, just return it
		return cred.Raw, nil
	}
	if !ent.IsNotFound(err) {
		// Continue only if the error was that the credential was not found
		return nil, err
	}

	// Generate the credential from the template
	var b bytes.Buffer
	err = t.ExecuteTemplate(&b, credData.CredName, credData)
	if err != nil {
		return nil, err
	}

	// The serialized credential
	rawJsonCred = b.Bytes()

	// Store in DB
	_, err = c.Client.Credential.
		Create().
		SetID(credData.Jti).
		SetRaw(rawJsonCred).
		Save(c.Ctx)
	if err != nil {
		zlog.Error().Err(err).Msg("failed storing credential")
		return nil, err
	}
	zlog.Info().Str("jti", credData.Jti).Msg("credential created")

	return rawJsonCred, nil

}

func (c *CredentialStore) InitializeDB() (err error) {

	c.Client.Credential.Delete().ExecX(c.Ctx)

	for _, cred := range credentialExamples {

		_, err = c.CreateCredential(cred)
		if err != nil {
			zlog.Logger.Error().Err(err).Send()
		}

	}

	return nil

}

func (c *CredentialStore) CreateCredentialFromMap2(credData map[string]any) (rawJsonCred json.RawMessage, err error) {

	cd := gyaml.New(credData)

	// Check if the issuer has already an account
	issuer := cd.DString(".issuerDID")
	v := vault.NewFromDBClient(c.Client)
	_, err = v.QueryAccount(issuer)
	if err != nil {
		return nil, err
	}

	var jwk *jwt.JWK
	// Get the private key ID. If not specified, get the first one
	if keyID, err := cd.String(".issuerKeyID"); err == nil {

		// KeyID specified, try to get it from the store
		jwk, err = v.QueryJWKByID(keyID)
		if err != nil {
			return nil, err
		}

	} else {

		// KeyID was not specified, look for the first one
		jwks, err := v.QueryJWKSForAccount(issuer)
		if err != nil {
			return nil, err
		}
		jwk = jwks[0]
	}

	fmt.Println(jwk)

	// If credential ID specified in the input data, do not generate a new one
	if _, ok := credData["jti"]; !ok {

		// Generate the id as a UUID
		jti, err := uuid.NewRandom()
		if err != nil {
			return nil, err
		}

		// Set the unique id in the credential
		credData["jti"] = jti.String()

	}

	// Generate the credential from the template
	var b bytes.Buffer
	err = t.ExecuteTemplate(&b, cd.DString("credName"), credData)
	if err != nil {
		zlog.Logger.Error().Err(err).Send()
		return nil, err
	}

	// The serialized credential
	rawJsonCred = b.Bytes()
	fmt.Printf("%v\n\n", string(rawJsonCred))

	// Parse the resulting byte string
	data, err := gyaml.ParseYamlBytes(rawJsonCred)
	if err != nil {
		zlog.Logger.Error().Err(err).Send()
		return nil, err
	}

	// Generate a formatted JSON string
	// rj, err := json.MarshalIndent(data.Data(), "", "  ")
	// if err != nil {
	// 	zlog.Logger.Error().Err(err).Send()
	// 	return nil, err
	// }

	// // Validate the generated JSON, just in case the template is malformed
	// m, ok := gjson.ParseBytes(b.Bytes()).Value().(map[string]interface{})
	// if !ok {
	// 	zlog.Error().Msg("Error validating JSON")
	// 	return nil, nil
	// }

	signedString, err := v.SignWithJWK(jwk, data.Data())

	fmt.Println("\nVerifying the credential")
	_, err = c.CredentialFromJWT(signedString)
	if err != nil {
		zlog.Logger.Error().Err(err).Send()
		return nil, err
	}

	return []byte(signedString), nil

}

type CredentialDecoded struct {
	jwt.RegisteredClaims
	Other map[string]any
}

func (c *CredentialStore) CredentialFromJWT(credSerialized string) (rawJsonCred json.RawMessage, err error) {

	v := vault.NewFromDBClient(c.Client)

	cred := &CredentialDecoded{}

	// Parse the serialized string into the structure, no signature validation yet
	token, err := jwt.NewParser().ParseUnverified2(credSerialized, cred)
	if err != nil {
		return nil, err
	}

	// Enable for Debugging
	zlog.Debug().Msg("Parsed Token")
	if out, err := json.MarshalIndent(token, "", "   "); err == nil {
		zlog.Debug().Msg(string(out))
	}

	// Verify the signature
	err = v.VerifySignature(token.ToBeSignedString, token.Signature, token.Alg(), token.Kid())
	if err != nil {
		return nil, err
	}

	// Debugging
	out, err := json.MarshalIndent(cred, "", "   ")
	if err != nil {
		return nil, err
	}

	fmt.Println(string(out))
	return nil, nil

}
