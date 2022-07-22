/*
Copyright © 2022 Jesus Ruiz <hesus.ruiz@gmail.com>

*/
package rpserver

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/evidenceledger/gosiop2/jwt"
	"github.com/evidenceledger/gosiop2/siop"
	"github.com/evidenceledger/gosiop2/siop/authrequest"
	"github.com/evidenceledger/gosiop2/siop/authresponse"
	"github.com/evidenceledger/gosiop2/vault"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"

	qrcode "github.com/skip2/go-qrcode"
)

func init() {
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

type RPServer struct {
	cfg         *viper.Viper
	vault       *vault.Vault
	authRequest *authrequest.AuthenticationRequest
}

// handleHome presents the home page to the user
func handleHome(c echo.Context) error {

	// Construct the URL to be included in the QR
	myURL := "http://" + c.Request().Host + "/startsiop"

	zlog.Info().Msg(myURL)

	// Encode the URL into a QR
	var png []byte
	png, err := qrcode.Encode(myURL, qrcode.Medium, 256)
	if err != nil {
		zlog.Error().Err(err).Send()
		return err
	}

	// Convert to DataURL format so it can be included in an <img> tag
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(png)))
	base64.StdEncoding.Encode(dst, png)

	// Render the template for the home page
	return c.Render(http.StatusOK, "home", string(dst))
}

// HandleStartSIOP is the HTTP handler for the route used by the wallet to start the SIOP flow
func (rp *RPServer) HandleStartSIOP(c echo.Context) error {

	// Generate the application state for checking when receiving the Authentication Response
	state, err := randString(16)
	if err != nil {
		zlog.Error().Err(err).Send()
		return echo.NewHTTPError(http.StatusInternalServerError, "Error generating state")
	}

	// Set a cookie in the reply so it will be sent back to us
	setSession(c, "state", state)

	// We create an Authentication Request specific for SIOP flows.
	// In case of SIOP the AuthRequest travels as a response to an HTTP request from
	// the wallet, instead of being sent from the RP to the OP as a redirection.
	// So instead of a URL-formatted request we send back an object in JSON serialization format:
	// https://openid.net/specs/openid-connect-core-1_0.html#JSONSerialization
	// In addition the request object is sent as a signed JWT so the SIOP can have a higher trust level

	// Create a JWT (unsigned) with key ID and algorithm in the headers
	signingMethod := jwt.GetSigningMethod(siop.DefaultPreferredAlgorithm)
	token := jwt.NewWithClaims(signingMethod, rp.authRequest)
	token.Header["kid"] = rp.cfg.GetString("clientKeyID")

	// Ask the Vault to sign the JWT with the private key corresponding to the key ID
	authorizationRequest, err := rp.vault.SignJWT(token)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	// And send it back to the caller
	// return c.String(http.StatusOK, authorizationRequest)
	return c.Blob(http.StatusOK, "application/jwt", []byte(authorizationRequest))

}

// HandleReceiveVP is called by the wallet sending the AthorizationResponse
func (rp *RPServer) HandleReceiveVP(c echo.Context) (err error) {

	// Read the body from the request
	body, err := io.ReadAll(c.Request().Body)
	if err != nil {
		zlog.Error().Err(err).Send()
		return echo.NewHTTPError(http.StatusInternalServerError, "Error reading body")
	}

	// Parse the body into a SIOP Authentication Response, validating the signature
	aur := &authresponse.AuthenticationResponse{}
	if err != nil {
		return err
	}

	token, err := jwt.NewParser().ParseUnverified2(string(body), aur)
	if err != nil {
		return err
	}

	zlog.Info().Msg("Parsed Token")
	fmt.Println(token)
	if out, err := json.MarshalIndent(token, "", "   "); err == nil {
		fmt.Println(string(out))
	}

	// err = rp.vault.VerifySignature(headerPlusClaims, parts[2], alg, kid)
	err = rp.vault.VerifySignature(token.ToBeSignedString, token.Signature, token.Alg(), token.Kid())
	if err != nil {
		return err
	}

	// Here we have completed successfully the SIOPv2 and OIDC4VP flows and we have
	// received a Verifiable Presentation in the vp_token.
	// For a complete business scenario, we would pass the VP to a backend application
	// via an API so the backend can perform aditional authentication and authorisation
	// tasks using the contents of the one or more Verifiable Credentials included inside
	// the VP.
	// This RP implementation deals ONLY with the OIDC flows for transporting in a secure
	// and interoperable way Verifiable Credentials.
	// It does not include logic for acting on the contents of the Verifiable Credentials
	// and delegates to a backend system for those tasks.

	if out, err := json.MarshalIndent(aur, "", "   "); err == nil {
		fmt.Println(string(out))
	}

	return c.JSON(http.StatusOK, "success")
}

// Start is invoked from the CLI and starts a web server for the Relying Party
func Start(cmd *cobra.Command, args []string) {

	// Prepare to read the configuration for the Relying Party server
	// We accept config files in the current directory or in HOME/.config/rpserver
	cfg := viper.New()
	cfg.SetConfigName("rpconfig.yaml")
	cfg.SetConfigType("yaml")
	cfg.AddConfigPath("$HOME/.config/rpserver")
	cfg.AddConfigPath(".")

	// Read the configuration values
	err := cfg.ReadInConfig()
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; ignore error if desired
			panic(fmt.Errorf("Fatal error config file: %w \n", err))
		} else {
			panic(fmt.Errorf("Fatal error config file: %w \n", err))
		}
	}

	zlog.Info().Msg("Starting RP server")

	// Get our client identity
	clientID := cfg.GetString("clientID")
	zlog.Info().Str("ClientID", clientID).Msg("")

	// Initialize the Vault
	v, err := vault.New(cfg.GetString("vault.driverName"), cfg.GetString("vault.dataSourceName"))
	if err != nil {
		panic(err)
	}

	rp := RPServer{}
	rp.cfg = cfg
	rp.vault = v

	// Echo instance
	e := echo.New()
	e.HideBanner = true
	e.Logger.SetLevel(log.INFO)

	// Serve static files
	e.Static("/static", "static")

	// Precompile templates
	t := &Template{
		templates: template.Must(template.ParseGlob("cmd/rpserver/templates/*.html")),
	}
	// register middleware to render templates
	e.Renderer = t

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.BodyLimit("1M"))
	e.Use(middleware.Secure())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())
	e.Use(middleware.TimeoutWithConfig(middleware.TimeoutConfig{
		Timeout: 30 * time.Second,
	}))
	//TODO: generate a cryptographic secret for the session
	e.Use(session.Middleware(sessions.NewCookieStore([]byte("EraseUnaVezUnSecretoAVoces"))))

	// Create a pre-configured Authentication Request (unsigned), specifying:
	// - our identity, as a DID
	// - the URL where the wallet should send us the Authentication Response with the vp_token
	// - the OIDC4VP presentation_definition specifying the type of Credential that we want
	// - the SIOP2 registration with the DID Methods that we support, so the credential can be verified
	redirect_uri := cfg.GetString("redirect_uri")

	var presentation_definition authrequest.PresentationDefinition
	err = cfg.UnmarshalKey("presentation_definition", &presentation_definition)
	if err != nil {
		panic(err)
	}
	var registration authrequest.Registration
	err = cfg.UnmarshalKey("registration", &registration)
	// err = viper.UnmarshalKey("registration", &registration)
	if err != nil {
		panic(err)
	}

	// Create the Authentication Request object
	rp.authRequest = authrequest.New(clientID, redirect_uri, presentation_definition, registration)

	// Setup the routes
	e.GET("/", handleHome)
	e.GET("/startsiop", rp.HandleStartSIOP)
	e.POST("/auth/receive_vp", rp.HandleReceiveVP)

	e.Logger.Info("SIOP server starting")

	// Start server and block forever
	err = e.Start(cfg.GetString("listenAddress"))

	// Should never reach here unless some fatal error happened
	if err != nil {
		e.Logger.Fatal(err)
	}
}

func randString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func setSession(c echo.Context, name string, value string) {

	sess, _ := session.Get("siopsession", c)
	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: true,
	}
	sess.Values["name"] = "value"
	sess.Save(c.Request(), c.Response())

}

func getSession(c echo.Context, name string) (value string) {

	sess, _ := session.Get("siopsession", c)
	return (sess.Values["name"]).(string)

}
