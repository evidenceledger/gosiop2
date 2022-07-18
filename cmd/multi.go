/*
Copyright © 2022 Jesus Ruiz <hesus.ruiz@gmail.com>

*/
package cmd

import (
	"github.com/evidenceledger/gosiop2/rpserver"
	"github.com/evidenceledger/gosiop2/siopwallet"
	"github.com/spf13/cobra"
)

// siopCmd represents the siop command
var multiCmd = &cobra.Command{
	Use:   "multi",
	Short: "Starts both SIOP and RP",
	Long: `Starts a SIOP instance at a default port (that can be configured), to implement the SIOP 
flow with a Relying Party that supports the SIOP.`,
	Run: StartMulti,
}

func init() {
	rootCmd.AddCommand(multiCmd)

}

func StartMulti(cmd *cobra.Command, args []string) {
	go rpserver.Start(cmd, args)
	// time.Sleep(time.Second)
	siopwallet.Start(cmd, args)
}
