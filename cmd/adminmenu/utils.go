package adminmenu

import (
	"github.com/AlecAivazis/survey/v2"
	"github.com/evidenceledger/gosiop2/credentials"
	"github.com/evidenceledger/gosiop2/menusystem"
	"github.com/evidenceledger/gosiop2/vault"
	"github.com/pterm/pterm"
	"github.com/rs/zerolog/log"
)

func menuItemNotImplemented(values ...any) error {
	pterm.Warning.Printfln("This menu option is not yet implemented")
	menusystem.WaitAnyKey()
	return nil
}

func askPassword() (password string) {

	// The promt with the help text
	prompt := &survey.Input{
		Message: "Enter the password for the account",
		Help:    "Enter the password for the account",
	}

	// Prepare the question
	qs := []*survey.Question{
		{
			Name:   "name",
			Prompt: prompt,
		},
	}

	// Perform the actual question
	err := survey.Ask(qs, &password)
	if err != nil {
		log.Error().Err(err).Msg("")
		return ""
	}

	return

}

func askText(promptText string, helpText string) (theText string) {

	// The promt with the help text
	prompt := &survey.Input{
		Message: promptText,
		Help:    helpText,
	}

	// Prepare the question
	qs := []*survey.Question{
		{
			Name:   "name",
			Prompt: prompt,
		},
	}

	// Perform the actual question
	err := survey.Ask(qs, &theText)
	if err != nil {
		log.Error().Err(err).Msg("")
		return ""
	}

	return

}

func mustGetWallet(values ...any) *vault.Vault {

	var w *vault.Vault
	var ok bool

	// We need the wallet instance to be passed as a parameter
	if values == nil {
		panic("expecting at least one parameter")
	}

	// Cast to the Wallet type
	w, ok = (values[0]).(*vault.Vault)
	if !ok {
		panic("expecting parameter of type Wallet")
	}

	return w

}

func mustGetCredentialStore(values ...any) *credentials.CredentialStore {

	var w *vault.Vault
	var ok bool

	// We need the wallet instance to be passed as a parameter
	if values == nil {
		panic("expecting at least one parameter")
	}

	// Cast to the Wallet type
	w, ok = (values[0]).(*vault.Vault)
	if !ok {
		panic("expecting parameter of type Wallet")
	}

	return credentials.NewFromDBClient(w.Client)

}
