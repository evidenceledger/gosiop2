/*
Copyright © 2022 Jesus Ruiz <hesus.ruiz@gmail.com>

*/
package main

import (
	"github.com/evidenceledger/gosiop2/cmd/siop/rpserver"
	"github.com/spf13/cobra"
)

// rpCmd represents the rp command
var rpCmd = &cobra.Command{
	Use:   "rp",
	Short: "Starts a Relying Party instance",
	Long:  `Starts a Relying Party instance.`,
	Run:   rpserver.Start,
}

func init() {
	rootCmd.AddCommand(rpCmd)

}
