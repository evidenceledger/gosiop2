/*
Copyright © 2022 Jesus Ruiz <hesus.ruiz@gmail.com>

*/
package cmd

import (
	"github.com/evidenceledger/gosiop2/cmd/siopwallet"
	"github.com/spf13/cobra"
)

// siopCmd represents the siop command
var siopCmd = &cobra.Command{
	Use:   "siop",
	Short: "Starts a SIOP instance",
	Long: `Starts a SIOP instance at a default port (that can be configured), to implement the SIOP 
flow with a Relying Party that supports the SIOP.`,
	Run: siopwallet.Start,
}

func init() {
	rootCmd.AddCommand(siopCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// siopCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// siopCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
