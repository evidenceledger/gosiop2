package admin

import (
	"fmt"

	"github.com/rs/zerolog/log"
	zlog "github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/evidenceledger/gosiop2/ent"
	"github.com/evidenceledger/gosiop2/internal/menusystem"
	"github.com/evidenceledger/gosiop2/vault"
	"github.com/pterm/pterm"
)

type Config struct {
	DriverName     string `json:"driverName"`
	DataDir        string `json:"dataDir"`
	DataSourceName string `json:"dataSourceName"`
}

type SIOPMenu struct {
	vault *vault.Vault
	menusystem.Menu
}

func NewSIOPMenu(v *vault.Vault) *SIOPMenu {

	m := &SIOPMenu{}
	m.vault = v

	mi := []menusystem.MenuItem{
		{
			Title:  "List Accounts",
			Action: m.listAccounts,
		},
		{
			Title:  "Add Account",
			Action: m.addAccount,
		},
		{
			Title:  "Account Management",
			Action: m.manageAccountMenu,
		},
		{
			Title:  "Dangerous actions",
			Action: dangerousMenu.PrintMenu,
		},
	}

	m.MenuItems = mi
	m.Title = "SIOP System Administration"

	return m
}

func (m *SIOPMenu) manageAccountMenu(values ...any) error {

	v := m.vault

	accounts := v.Client.Account.Query().AllX(v.Ctx)
	if len(accounts) == 0 {
		pterm.Info.Printfln("The wallet is empty!")
	} else if len(accounts) == 1 {
		pterm.Info.Printfln("There is 1 account")
	} else {
		pterm.Info.Printfln("There are %v accounts", len(accounts))
	}

	options := []string{"**Exit**"}

	for _, acc := range accounts {
		options = append(options, acc.Name)
	}

	accountName, _ := pterm.DefaultInteractiveSelect.
		WithOptions(options).
		WithDefaultText("Select an account to manage").
		Show()

	// Check if account name was entered.
	if accountName == "**Exit**" {
		return nil
	}

	// Query the vault
	acc, err := v.QueryAccount(accountName)
	if _, ok := err.(*ent.NotFoundError); ok {
		pterm.Printfln("Account %v not found", accountName)
		return nil
	}

	if err != nil {
		log.Error().Err(err).Msg("")
		return nil
	}

	accountMenu := NewAccountMenu(v, acc)
	accountMenu.PrintMenu(v)

	return nil

}

// *************************************************
// *************************************************
// *************************************************

func (m *SIOPMenu) listAccounts(values ...any) error {

	accounts := m.vault.Client.Account.Query().AllX(m.vault.Ctx)
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

	menusystem.WaitAnyKey()
	return nil

}

func (m *SIOPMenu) addAccount(values ...any) error {

	v := m.vault

	// Ask for the name of the account to be created
	name := menusystem.AskText("Name of account", "The name of the account to be created")
	if len(name) == 0 {
		return nil
	}

	acc, err := v.CreateAccountWithKey(name)
	if err != nil {
		zlog.Error().Err(err).Msg("adding account")
		return err
	}
	pterm.Success.Printfln("%v", acc)

	menusystem.WaitAnyKey()
	return nil
}

func Start(cmd *cobra.Command, args []string) {

	// Prepare to read the configuration for the Vault
	// We accept config files in the current directory or in HOME/.config/vault
	cfg := viper.New()
	cfg.SetConfigName("vaultconfig.yaml")
	cfg.SetConfigType("yaml")
	cfg.AddConfigPath(".")
	cfg.AddConfigPath("./configs")
	cfg.AddConfigPath("$HOME/.config/vault")

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
	w, err := vault.New(config.DriverName, config.DataSourceName)
	if err != nil {
		zlog.Fatal().Err(err).Msg("")
	}

	// Invoke the main menu
	m := NewSIOPMenu(w)
	m.PrintMenu()

}
