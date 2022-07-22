package vault

import (
	"fmt"

	"github.com/AlecAivazis/survey/v2"
	"github.com/rs/zerolog/log"
	zlog "github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/evidenceledger/gosiop2/ent"
	"github.com/evidenceledger/gosiop2/menusystem"
	"github.com/pterm/pterm"
)

type Config struct {
	DriverName     string `json:"driverName"`
	DataDir        string `json:"dataDir"`
	DataSourceName string `json:"dataSourceName"`
}

// *************************************************
// Menu Definitions
// *************************************************

var mainMenu = menusystem.Menu{
	Title:       "Management of Accounts",
	NumberColor: pterm.FgWhite,
	LabelColor:  pterm.FgCyan,
	MenuItems: []menusystem.MenuItem{
		{
			Title:  "List Accounts",
			Action: menuItemListAccounts,
		},
		{
			Title:  "Query an Account",
			Action: menuItemAccountForName,
		},
		{
			Title:  "Add Account",
			Action: menuItemAddAccount,
		},
		{
			Title:  "Add Private Key to Account",
			Action: menuItemAddKeyToAccount,
		},
		{
			Title:  "Dangerous actions",
			Action: dangerousMenu.PrintMenu,
		},
	},
}

var dangerousMenu = menusystem.Menu{
	Title:       "Dangerous actions 1",
	NumberColor: pterm.FgWhite,
	LabelColor:  pterm.FgCyan,
	MenuItems: []menusystem.MenuItem{
		{
			Title:  "Delete a Key from an Account",
			Action: menuItemNotImplemented,
		},
		{
			Title:  "Delete an Account and All associated Keys",
			Action: menuItemNotImplemented,
		},
	},
}

// *************************************************
// *************************************************
// *************************************************

func Start(cmd *cobra.Command, args []string) {

	// Prepare to read the configuration for the Vault
	// We accept config files in the current directory or in HOME/.config/vault
	cfg := viper.New()
	cfg.SetConfigName("vaultconfig.yaml")
	cfg.SetConfigType("yaml")
	cfg.AddConfigPath("$HOME/.config/vault")
	cfg.AddConfigPath(".")

	// Read the configuration values
	err := cfg.ReadInConfig()
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; ignore error if desired
			panic(fmt.Errorf("Fatal error config file: %w \n", err))
		} else {
			panic(fmt.Errorf("Fatal error config file: %w \n", err))
		}
	}

	// Unmarshall in a configuration structure
	var config Config
	err = cfg.Unmarshal(&config)
	if err != nil {
		panic(err)
	}

	// You have to make sure that the database is accessible.
	// For example, in the case of SQLite, the directory where the database file
	// will reside has to exist and with th eproper permissions

	// Open the wallet and store it in a global variable as a default wallet
	w, err := New(config.DriverName, config.DataSourceName)
	if err != nil {
		zlog.Fatal().Err(err).Msg("")
	}

	// Invoke the main menu
	mainMenu.PrintMenu(w)

}

func menuItemNotImplemented(values ...any) error {
	pterm.Warning.Printfln("This menu option is not yet implemented")
	return nil
}

func menuItemAddAccount(values ...any) error {

	w := mustGetWallet(values...)

	// Ask for the name of the account to be created
	name := askText("Name of account")

	acc, err := w.CreateAccountWithKey(name)
	if err != nil {
		zlog.Error().Err(err).Msg("adding account")
		return err
	}
	pterm.Success.Printfln("%v", acc)
	return nil
}

func menuItemAddKeyToAccount(values ...any) error {

	w := mustGetWallet(values...)

	// Ask for the name of the account to be created
	name := askText("Name of account")

	key, err := w.AddKeyToAccount(name)
	if err != nil {
		zlog.Error().Err(err).Msg("adding key")
		return err
	}
	pterm.Success.Printfln("%v", key)
	return nil
}

func menuItemAccountForName(values ...any) error {

	w := mustGetWallet(values...)

	// Will receive the account name selected by the user
	accountName := ""

	// The promt with the help text
	prompt := &survey.Input{
		Message: "Enter an account name to query",
		Help:    "The account name (case-sensitive) to query in the vault and get the account data",
	}

	// Prepare the question
	qs := []*survey.Question{
		{
			Name:   "name",
			Prompt: prompt,
		},
	}

	// Perform the actual question
	err := survey.Ask(qs, &accountName)
	if err != nil {
		log.Error().Err(err).Msg("")
		return err
	}

	// Check if account name was entered.
	if accountName == "" {
		return nil
	}

	// Query the vault
	acc, err := w.QueryAccount(accountName)
	if _, ok := err.(*ent.NotFoundError); ok {
		pterm.Printfln("Account %v not found", accountName)
		return nil
	}

	if err != nil {
		log.Error().Err(err).Msg("")
		return nil
	}

	pterm.Info.Println("Account:", acc)

	keys := acc.QueryKeys().AllX(w.ctx)
	if len(keys) == 1 {
		pterm.Info.Printfln("Account has 1 key")
	} else {
		pterm.Info.Printfln("Account has %v keys", len(keys))
	}

	for _, key := range keys {
		pterm.Info.Printfln("%v", string(key.Jwk))
	}

	return nil

}

func menuItemListAccounts(values ...any) error {

	w := mustGetWallet(values...)

	accounts := w.client.Account.Query().AllX(w.ctx)
	if len(accounts) == 0 {
		pterm.Info.Printfln("The wallet is empty!")
	} else if len(accounts) == 1 {
		pterm.Info.Printfln("There is 1 account:")
	} else {
		pterm.Info.Printfln("There are %v accounts:", len(accounts))
	}

	for _, acc := range accounts {
		pterm.Info.Printfln("  %v", acc.Name)
	}

	return nil

	// keyString, err := w.PrivateKey("Timestamper")
	// if err != nil {
	// 	log.Fatal().Err(err).Msg("")
	// }

	// pterm.Println(keyString)

	// key, err := keystore.DecryptKey([]byte(keyString), "ThePassword")
	// if err != nil {
	// 	log.Fatal().Err(err).Msg("")
	// }
	// pterm.Println(key)

	// raw, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	// if err != nil {
	// 	pterm.Printf("failed to generate new ECDSA private key: %s\n", err)
	// 	menusystem.WaitAnyKey()
	// 	return nil
	// }

	// keyEth, err := jwk.FromRaw(raw)
	// if err != nil {
	// 	pterm.Printf("failed to create symmetric key: %s\n", err)
	// 	menusystem.WaitAnyKey()
	// 	return nil
	// }
	// pterm.Printfln("FromRaw went OK: %+v", keyEth)
	// if _, ok := keyEth.(jwk.ECDSAPrivateKey); !ok {
	// 	pterm.Printf("expected jwk.SymmetricKey, got %T\n", keyEth)
	// 	menusystem.WaitAnyKey()
	// 	return nil
	// }

	// buf, err := json.MarshalIndent(keyEth, "", "  ")
	// if err != nil {
	// 	pterm.Printf("failed to marshal key into JSON: %s\n", err)
	// 	return nil
	// }
	// pterm.Printf("%s\n", buf)

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

func mustGetWallet(values ...any) *Vault {

	var w *Vault
	var ok bool

	// We need the wallet instance to be passed as a parameter
	if values == nil {
		panic("expecting at least one parameter")
	}

	// Cast to the Wallet type
	w, ok = (values[0]).(*Vault)
	if !ok {
		panic("expecting parameter of type Wallet")
	}

	return w

}
