package adminmenu

import (
	"github.com/evidenceledger/gosiop2/ent"
	"github.com/evidenceledger/gosiop2/internal/menusystem"
	"github.com/evidenceledger/gosiop2/vault"
	"github.com/pterm/pterm"
	zlog "github.com/rs/zerolog/log"
)

type AccountMenu struct {
	menusystem.Menu
	vault *vault.Vault
	acc   *ent.Account
}

func NewAccountMenu(v *vault.Vault, acc *ent.Account) *AccountMenu {

	var m = &AccountMenu{}
	m.vault = v
	m.acc = acc
	m.Title = "Account: " + acc.Name
	m.NumberColor = pterm.FgWhite
	m.LabelColor = pterm.FgCyan
	m.MenuItems = []menusystem.MenuItem{
		{
			Title:  "Select Another Account",
			Action: m.selectAnotherAccount,
		},
		{
			Title:  "Display Account Info",
			Action: m.displayInfo,
		},
		{
			Title:  "Add Account",
			Action: m.addAccount,
		},
		{
			Title:  "Add Private Key to Account",
			Action: m.addKeyToAccount,
		},
		{
			Title:  "Credential Management",
			Action: m.credentialsManagement,
		},
		{
			Title:  "Example menu item 2",
			Action: menuItemNotImplemented,
		},
	}

	return m
}

func (m *AccountMenu) credentialsManagement(values ...any) error {
	NewCredentialsMenu(m.vault, m.acc).PrintMenu()
	return nil
}

func (m *AccountMenu) selectAnotherAccount(values ...any) error {

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
		zlog.Error().Err(err).Msg("")
		return nil
	}

	m.acc = acc
	m.Title = "Account: " + acc.Name

	return nil

}

func (m *AccountMenu) addAccount(values ...any) error {

	v := m.vault

	// Ask for the name of the account to be created
	name := askText("Name of account", "The name of the account to be created")
	if len(name) == 0 {
		return nil
	}

	acc, err := v.CreateAccountWithKey(name)
	if err != nil {
		zlog.Error().Err(err).Msg("adding account")
		return err
	}
	pterm.Success.Printfln("%v", acc)

	m.acc = acc
	m.Title = "Account: " + acc.Name

	menusystem.WaitAnyKey()
	return nil
}

func (m *AccountMenu) addKeyToAccount(values ...any) error {

	key, err := m.vault.AddKeyToAccount(m.acc.Name)
	if err != nil {
		zlog.Error().Err(err).Msg("adding key")
		return err
	}
	pterm.Success.Printfln("%v", key)
	menusystem.WaitAnyKey()
	return nil
}

func (m *AccountMenu) displayInfo(values ...any) error {

	v := m.vault
	acc := m.acc

	pterm.Info.Println("Account:", acc)

	keys := acc.QueryKeys().AllX(v.Ctx)
	if len(keys) == 1 {
		pterm.Info.Printfln("Account has 1 key")
	} else {
		pterm.Info.Printfln("Account has %v keys", len(keys))
	}

	for _, key := range keys {
		pterm.Info.Printfln("%v", string(key.Jwk))
	}

	menusystem.WaitAnyKey()
	return nil

}

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
