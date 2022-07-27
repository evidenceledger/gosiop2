package main

import (
	"os"

	"github.com/evidenceledger/gosiop2/credentials"
	"github.com/evidenceledger/gosiop2/ent"
	zlog "github.com/rs/zerolog/log"
	"gopkg.in/yaml.v2"
)

func main() {

	// Open connection to the database
	db, err := ent.Open("sqlite3", "file:/home/jesus/.siop2/vaultdb.sqlite?mode=rwc&cache=shared&_fk=1")
	if err != nil {
		panic(err)
	}
	c := credentials.NewFromDBClient(db)

	// Read the YAML file with data for the credential
	data, err := os.ReadFile("/home/jesus/gosrc/gosiop2/credentials/sampledata/employee.yaml")
	if err != nil {
		panic(err)
	}

	// Parse the YAML data as an array of credentia data (map of strings)
	credDataArray := make([]map[string]string, 10)
	err = yaml.Unmarshal(data, &credDataArray)
	if err != nil {
		panic(err)
	}

	// Iterate though the array creating each credential from the template
	for _, cred := range credDataArray {

		_, err = c.CreateCredentialFromMap(cred)
		if err != nil {
			zlog.Logger.Error().Err(err).Send()
		}

	}

}
