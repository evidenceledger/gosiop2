package menusystem

import (
	"github.com/AlecAivazis/survey/v2"
	"github.com/pterm/pterm"
	"github.com/rs/zerolog/log"
)

func MenuItemNotImplemented(values ...any) error {
	pterm.Warning.Printfln("This menu option is not yet implemented")
	WaitAnyKey()
	return nil
}

func AskPassword() (password string) {

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

func AskText(promptText string, helpText string) (theText string) {

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
