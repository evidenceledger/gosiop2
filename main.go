/*
Copyright © 2022 Jesus Ruiz <hesus.ruiz@gmail.com>

*/
package main

import (
	"os"

	"github.com/evidenceledger/gosiop2/cmd"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func init() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	log.Logger = log.With().Caller().Logger()
}

func main() {
	cmd.Execute()
}
