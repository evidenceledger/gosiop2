package menusystem

import (
	"fmt"
	"os"
	"reflect"
	"strconv"

	"github.com/AlecAivazis/survey/v2"
	"github.com/pterm/pterm"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	zlog "github.com/rs/zerolog/log"
)

func init() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zlog.Logger = zlog.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	zlog.Logger = zlog.With().Caller().Logger()
}

type MenuItem struct {
	Title  string
	Action HandlerFunc
}

type Menu struct {
	Title         string
	NumberColor   pterm.Color
	LabelColor    pterm.Color
	MenuItems     []MenuItem
	PromptOptions []survey.AskOpt
	parentMenu    *Menu
}

// The HandlerFunc type is an adapter to allow the use of
// ordinary functions as Menu handlers. If f is a function
// with the appropriate signature, HandlerFunc(f) is a
// Handler that calls f.
type HandlerFunc func(...any) error

// ServeHTTP calls f(w, r).
func (f HandlerFunc) CallF(values ...any) error {
	return f(values...)
}

// ValidMenuOption requires a valid number or the empty string (pressing Enter)
func ValidMenuOption(length int) survey.Validator {
	// return a validator that checks that
	return func(val interface{}) error {
		str, ok := val.(string)
		if !ok {
			return fmt.Errorf("response is of the wrong type %v", reflect.TypeOf(val).Name())
		}

		// Check for empty string, which is a valid input to get back from the menu to the parent
		if str == "" {
			return nil
		}

		// Try to convert to an integer
		sel, err := strconv.Atoi(str)
		if err != nil {
			return fmt.Errorf("must be a number between 1 to %v and you entered <%v>", length, str)
		}
		if sel <= 0 || sel > length {
			return fmt.Errorf("must be a number be between 1 to %v", length)
		}

		// the input is fine
		return nil
	}
}

func (m *Menu) PrintMenu(values ...any) error {

	for {

		// Print the Title
		Clear()
		pterm.DefaultHeader.Println(m.Title)
		pterm.Println()

		// Print the options, numbering them
		for i := range m.MenuItems {
			item := m.MenuItems[i]
			num := i + 1
			pterm.Println(pterm.Red("("+strconv.Itoa(num)+") ") + pterm.Green(item.Title))
		}
		pterm.Println()

		// Wait for selected option
		selected := ""

		prompt := &survey.Input{
			Message: "Select option or press Enter to exit",
			Help:    "Enter the number of the menu option and press Enter",
		}

		qs := []*survey.Question{
			{
				Name:     "name",
				Prompt:   prompt,
				Validate: ValidMenuOption(len(m.MenuItems)),
			},
		}

		err := survey.Ask(qs, &selected)
		if err != nil {
			pterm.Println(err)
		}

		// selected is either an item number (as a string) or the empty string.
		if selected == "" {
			break
		}

		sel, _ := strconv.Atoi(selected)
		m.MenuItems[sel-1].Action(values...)
		//WaitAnyKey()

	}

	return nil
}

func Clear() {
	print("\033[H\033[2J")
}

func WaitAnyKey() {
	fmt.Println("\nPress Enter to continue")
	fmt.Scanln()
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

func askText(promptText string) (theText string) {

	// The promt with the help text
	prompt := &survey.Input{
		Message: promptText,
		Help:    promptText,
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
