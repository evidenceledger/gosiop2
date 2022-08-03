package admin

import (
	"fmt"
	"os"

	"github.com/evidenceledger/gosiop2/credentials"
	"github.com/evidenceledger/gosiop2/ent"
	"github.com/evidenceledger/gosiop2/ent/account"
	"github.com/evidenceledger/gosiop2/ent/credential"
	"github.com/evidenceledger/gosiop2/internal/menusystem"
	"github.com/evidenceledger/gosiop2/vault"
	"github.com/pterm/pterm"
	zlog "github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

var credentialExamples = []*credentials.CredentialData{
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

type CredentialsMenu struct {
	menusystem.Menu
	vault *vault.Vault
	creds *credentials.CredentialStore
	acc   *ent.Account
}

func NewCredentialsMenu(v *vault.Vault, acc *ent.Account) *CredentialsMenu {

	var m = &CredentialsMenu{}
	m.vault = v
	m.acc = acc
	m.creds = credentials.NewFromDBClient(m.vault.Client)
	m.Title = "Credentials for account: " + acc.Name

	m.NumberColor = pterm.FgWhite
	m.LabelColor = pterm.FgCyan
	m.MenuItems = []menusystem.MenuItem{
		{
			Title:  "Reset and Initialise the database",
			Action: m.resetCredentialsDB,
		},
		{
			Title:  "List All Credentials",
			Action: m.listAllCredentials,
		},
		{
			Title:  "Test credential creation",
			Action: m.testCred,
		},
		{
			Title:  "Delete an Account and All associated Keys",
			Action: menusystem.MenuItemNotImplemented,
		},
	}

	return m
}

func (m *CredentialsMenu) testCred(values ...any) error {

	b := make([]*credentials.CredentialData, 10)

	data, err := os.ReadFile("credentials/sampledata/employee.yaml")
	if err != nil {
		zlog.Logger.Error().Err(err).Msg("failed opening file")
		return err
	}
	fmt.Println(string(data))

	err = yaml.Unmarshal(data, &b)
	if err != nil {
		zlog.Logger.Error().Err(err).Msg("failed unmarshalling")
		return err
	}

	for _, c := range b {
		fmt.Printf("->%v\n", c.Jti)
	}

	out, err := yaml.Marshal(b)
	if err != nil {
		zlog.Logger.Error().Err(err).Msg("failed marshalling")
		return err
	}

	zlog.Logger.Info().Msgf("%v", out)

	menusystem.WaitAnyKey()
	return nil

}

func (m *CredentialsMenu) createCredential(values ...any) error {

	menusystem.WaitAnyKey()
	return nil

}

func (m *CredentialsMenu) resetCredentialsDB(values ...any) error {

	m.creds.Client.Credential.Delete().ExecX(m.creds.Ctx)

	for _, cred := range credentialExamples {

		cred.IssuerDID = m.acc.Name

		_, err := m.creds.CreateCredential(cred)
		if err != nil {
			zlog.Logger.Error().Err(err).Send()
		}

	}

	menusystem.WaitAnyKey()
	return nil

}

func (m *CredentialsMenu) listAllCredentials(values ...any) error {

	creds := m.creds.Client.Credential.Query().Where(credential.HasAccountWith(account.NameEQ(m.acc.Name))).AllX(m.creds.Ctx)
	for _, cred := range creds {
		zlog.Logger.Info().Str("type", cred.Type).Str("encoded", string(cred.Raw)).Send()
	}

	menusystem.WaitAnyKey()
	return nil

}
