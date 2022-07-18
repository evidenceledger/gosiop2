package credentials

import (
	"bytes"
	"encoding/json"
	"fmt"
	"text/template"

	"github.com/evidenceledger/gosiop2/vault"
)

type CredentialData struct {
	IssuerDID          string `json:"iss"`
	SubjectDID         string `json:"did"`
	Name               string `json:"name"`
	Given_name         string `json:"given_name"`
	Family_name        string `json:"family_name"`
	Preferred_username string `json:"preferred_username"`
	Email              string `json:"email"`
}

var credentialExamples = []CredentialData{
	{
		IssuerDID:          "did:elsi:packetdeliveryco",
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
	t = template.Must(template.ParseGlob("credentials/templates/*.tpl"))
}

func GetCredentials(v *vault.Wallet) (json.RawMessage, error) {
	var b bytes.Buffer

	credData := credentialExamples[0]
	fmt.Println(credData)

	err := t.ExecuteTemplate(&b, "employee", credData)
	if err != nil {
		return nil, err
	}
	fmt.Println("*******************************************************")
	fmt.Println(string(b.Bytes()))
	fmt.Println("*******************************************************")
	return b.Bytes(), nil
}
