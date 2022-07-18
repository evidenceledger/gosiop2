/*
Copyright © 2022 Jesus Ruiz <hesus.ruiz@gmail.com>

*/
package cmd

import (
	"github.com/evidenceledger/gosiop2/vault"
	"github.com/spf13/cobra"
)

// siopCmd represents the siop command
var vaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "A vault to generate keys and sign/verify data",
	Long:  `A vault to generate keys and sign/verify data.`,
	Run:   vault.Start,
}

func init() {
	rootCmd.AddCommand(vaultCmd)
}
