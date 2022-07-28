/*
Copyright © 2022 Jesus Ruiz <hesus.ruiz@gmail.com>

*/
package main

import (
	"github.com/evidenceledger/gosiop2/cmd/siop/webserver"
	"github.com/spf13/cobra"
)

// siopCmd represents the siop command
var webCmd = &cobra.Command{
	Use:   "web",
	Short: "Starts a Web server instance",
	Long:  `Starts a Web server instance.`,
	Run:   webserver.Start,
}

func init() {
	rootCmd.AddCommand(webCmd)
}
