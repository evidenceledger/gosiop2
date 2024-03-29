package admin

import (
	"github.com/evidenceledger/gosiop2/internal/menusystem"
	"github.com/pterm/pterm"
)

var dangerousMenu = menusystem.Menu{
	Title:       "Dangerous actions 1",
	NumberColor: pterm.FgWhite,
	LabelColor:  pterm.FgCyan,
	MenuItems: []menusystem.MenuItem{
		{
			Title:  "Delete a Key from an Account",
			Action: menusystem.MenuItemNotImplemented,
		},
		{
			Title:  "Delete an Account and All associated Keys",
			Action: menusystem.MenuItemNotImplemented,
		},
	},
}
