package main

import (
	"encoding/json"
	"fmt"

	"github.com/evidenceledger/gosiop2/credentials"
	"github.com/evidenceledger/gosiop2/ent"
	"github.com/evidenceledger/gosiop2/internal/gyaml"
	"github.com/evidenceledger/gosiop2/internal/jwt"
	zlog "github.com/rs/zerolog/log"
)

type CredentialClaims struct {
	jwt.RegisteredClaims
	Other map[string]any
}

func main() {

	// Open connection to the database
	db, err := ent.Open("sqlite3", "file:/home/jesus/.siop2/vaultdb.sqlite?mode=rwc&cache=shared&_fk=1")
	if err != nil {
		panic(err)
	}
	c := credentials.NewFromDBClient(db)

	// Parse credential data
	data, err := gyaml.ParseYamlFile("/home/jesus/gosrc/gosiop2/cmd/creds/sampledata/employee_data.yaml")
	_, err = json.MarshalIndent(data.Data(), "", "  ")
	if err != nil {
		panic(err)
	}

	// Get the top-level list (the list of credentials)
	creds, err := data.List("")
	if err != nil {
		panic(err)
	}

	// Iterate through the list creating each credential which will use its own template
	for _, item := range creds {

		cred, _ := item.(map[string]any)

		rawCred, err := c.CreateCredentialFromMap2(cred)
		if err != nil {
			zlog.Logger.Error().Err(err).Send()
		}
		fmt.Println(string(rawCred))

		// Check that the content is correct
		b := &CredentialClaims{}
		_, err = jwt.NewParser().ParseUnverified2(string(rawCred), b)
		if err != nil {
			zlog.Logger.Error().Err(err).Send()
			continue
		}
		out, err := json.MarshalIndent(b.Other, "", "  ")
		if err != nil {
			zlog.Logger.Error().Err(err).Send()
			continue
		}
		fmt.Println(string(out))

	}

}
