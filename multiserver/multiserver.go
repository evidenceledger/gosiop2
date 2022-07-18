/*
Copyright © 2022 Jesus Ruiz <hesus.ruiz@gmail.com>

*/
package multiserver

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
	"github.com/spf13/cobra"
)

func Start(cmd *cobra.Command, args []string) {

	// Echo instance
	e := echo.New()
	e.Logger.SetLevel(log.INFO)

	go startSIOPFlow(e)

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Routes
	e.GET("/", hello)

	e.Logger.Info("SIOP server starting")

	// Start server
	e.Logger.Fatal(e.Start(":1301"))
}

// Handler
func hello(c echo.Context) error {
	return c.String(http.StatusOK, "Hello, World!")
}

func startSIOPFlow(e *echo.Echo) {
	fmt.Println("Starting SIOP flow contacting RP server")

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get("http://127.0.0.1:1300/startsiop")

	if err != nil {
		e.Logger.Fatal("Error contacting Relying Party", err)
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if resp.StatusCode > 299 {
		log.Fatalf("Response failed with status code: %d and\nbody: %s\n", resp.StatusCode, body)
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s", body)

}
