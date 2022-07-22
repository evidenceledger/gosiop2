/*
Copyright © 2022 Jesus Ruiz <hesus.ruiz@gmail.com>

*/
package siopwallet

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"text/template"
	"time"

	"github.com/evidenceledger/gosiop2/credentials"
	"github.com/evidenceledger/gosiop2/jwt"
	"github.com/evidenceledger/gosiop2/siop/authrequest"
	"github.com/evidenceledger/gosiop2/siop/authresponse"
	"github.com/evidenceledger/gosiop2/vault"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/labstack/gommon/log"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	// Initialize the log and its format
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zlog.Logger = zlog.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	zlog.Logger = zlog.With().Caller().Logger()
}

type Template struct {
	templates *template.Template
}

func (t *Template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

type WalletServer struct {
	cfg         *viper.Viper
	vault       *vault.Vault
	authRequest *authrequest.AuthenticationRequest
}

// handleHome is the HTTP handler for the home page of the wallet
func handleHome(c echo.Context) error {

	return c.Render(http.StatusOK, "wallethome", "")
}

// handleStartSIOP is the HTTP handler for starting the SIOP flow
// We call the RP and receive an AuthorizationRequest, and display it to the user
func (w *WalletServer) handleStartSIOP(c echo.Context) (err error) {

	// Call the endpoint in the RP to retrieve the Authentication Request
	// TODO: use discovery for getting the endpoint
	startURL := w.cfg.GetString("relyingPartyAddress") + "/startsiop"
	err, body := doGET(startURL)
	if err != nil {
		zlog.Error().Err(err).Send()
		return err
	}

	// Parse the body into a SIOP Authentication Request, validating the signature
	aur := &authrequest.AuthenticationRequest{}
	if err != nil {
		return err
	}

	// Parse the serialized string into the structure, no signature validation yet
	token, err := jwt.NewParser().ParseUnverified2(string(body), aur)
	if err != nil {
		return err
	}

	// Store temporarily the request in the server structure
	// We will need it to send the corresponding Authentication Response to the RP
	// TODO: make the implementation multi-user. Now the wallet server is for only one user
	w.authRequest = aur

	// Enable for Debugging
	zlog.Debug().Msg("Parsed Token")
	if out, err := json.MarshalIndent(token, "", "   "); err == nil {
		zlog.Debug().Msg(string(out))
	}

	// Verify the signature
	err = w.vault.VerifySignature(token.ToBeSignedString, token.Signature, token.Alg(), token.Kid())
	if err != nil {
		return err
	}

	// Debugging
	out, err := json.MarshalIndent(aur, "", "   ")
	if err != nil {
		return err
	}

	// Display Authentication Request to the wallet user
	// The user can then choose to send the credential(s) to the RP aor not
	return c.Render(http.StatusOK, "walletauthrequest", string(out))
}

// handleSendAuthorizationResponse is the HTTP handler for sending the Authentication Response to the RP
func (w *WalletServer) handleSendAuthorizationResponse(c echo.Context) error {

	// Get our keyID from the config file
	kid := w.cfg.GetString("clientKeyID")

	// Get the Verifiable Presentation (unsigned) with the required VCs inside
	vp_token, err := credentials.GetCredentials(w.vault)
	if err != nil {
		return err
	}

	// Create the Authentication Response (unsigned) to be sent to the RP
	authResponse := authresponse.New(w.cfg.GetString("clientID"), w.authRequest, vp_token)

	// Create a JWT (unsigned) with key ID and algorithm in the headers
	token := jwt.NewWithClaims(jwt.SigningMethodES256, authResponse)
	token.Header["kid"] = kid

	// Ask the Vault to sign the JWT with the private key corresponding to the key ID
	ss, err := w.vault.SignJWT(token)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	// Send the Authentication Response to the RP as a POST
	err, _ = doPOST(w.authRequest.Redirect_uri, ss)
	if err != nil {
		return err
	}

	// For debugging: Pretty-format the json data to display to the end user of the wallet
	out, err := json.MarshalIndent(authResponse, "", "   ")
	if err == nil {
		fmt.Println(string(out))
	}

	// render the page to the wallet user
	return c.Render(http.StatusOK, "walletauthresponse", string(out))
}

// Start is invoked from the CLI and starts a web server for the Relying Party
func Start(cmd *cobra.Command, args []string) {

	// My default client ID if no config file exists
	var clientID = "MyID"

	// Prepare to read the configuration for the Relying Party server
	// We accept config files in the current directory or in HOME/.config/rpserver
	cfg := viper.New()
	cfg.SetConfigName("walletconfig.yaml")
	cfg.SetConfigType("yaml")
	cfg.AddConfigPath("$HOME/.config/wallet")
	cfg.AddConfigPath(".")

	// Read the configuration values
	err := cfg.ReadInConfig()
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; ignore error if desired
			zlog.Warn().Str("config", "walletconfig.yaml").Msg("Config file not found")
		} else {
			panic(fmt.Errorf("Fatal error config file: %w \n", err))
		}
	}

	zlog.Info().Msg("Starting Wallet")

	// Get our client identity
	clientID = cfg.GetString("clientID")
	zlog.Info().Str("ClientID", clientID).Msg("")

	// Initialize the Vault
	v, err := vault.New(cfg.GetString("vault.driverName"), cfg.GetString("vault.dataSourceName"))
	if err != nil {
		panic(err)
	}

	wallet := WalletServer{}
	wallet.cfg = cfg
	wallet.vault = v

	// Echo instance
	e := echo.New()
	e.HideBanner = true
	e.Logger.SetLevel(log.INFO)

	// Serve static files
	e.Static("/static", "static")

	// Precompile templates
	t := &Template{
		templates: template.Must(template.ParseGlob("cmd/siopwallet/templates/*.html")),
	}
	// register middleware to render templates
	e.Renderer = t

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.BodyLimit("1M"))
	e.Use(middleware.Secure())
	e.Use(middleware.Recover())

	// Setup the routes
	e.GET("/", handleHome)
	e.GET("/startsiop", wallet.handleStartSIOP)
	e.GET("/sendresponse", wallet.handleSendAuthorizationResponse)

	e.Logger.Info("SIOP server starting")

	// Start server and block forever
	err = e.Start(cfg.GetString("listenAddress"))

	// Should never reach here unless some fatal error happened
	if err != nil {
		e.Logger.Fatal(err)
	}
}

// doGET is a utility function to make simpler HTTP GET
func doGET(url string) (error, []byte) {

	// Get an HTTP client that timeouts after 5 seconds
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return err, nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return echo.NewHTTPError(resp.StatusCode), nil
	}
	if resp.StatusCode > 299 {
		return echo.NewHTTPError(resp.StatusCode), nil
	}
	return nil, body
}

// doPOST is a utility function to make simpler HTTP POST
func doPOST(url string, payload string) (error, []byte) {

	// Get an HTTP client that timeouts after 5 seconds
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Send the POST with the payload
	resp, err := client.Post(url, "text/plain", bytes.NewBuffer([]byte(payload)))
	if err != nil {
		return err, nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return echo.NewHTTPError(resp.StatusCode), nil
	}
	if resp.StatusCode > 299 {
		return echo.NewHTTPError(resp.StatusCode), nil
	}

	return nil, body
}
