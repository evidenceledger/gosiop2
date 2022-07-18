package rpserver

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/labstack/gommon/log"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func TestJWTGeneration(te *testing.T) {
	const aLongLongTimeAgo = 233431200

	t := jwt.New()
	t.Set(jwt.IssuedAtKey, time.Unix(aLongLongTimeAgo, 0))

	t.Set(jwt.SubjectKey, `https://github.com/lestrrat-go/jwx/v2/jwt`)
	t.Set(jwt.AudienceKey, `Golang Users`)

	t.Set("response_type", "id_token")
	t.Set("scope", "openid")

	buf, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		fmt.Printf("failed to generate JSON: %s\n", err)
		return
	}

	fmt.Printf("%s\n", buf)
	fmt.Printf("aud -> '%s'\n", t.Audience())
	fmt.Printf("iat -> '%s'\n", t.IssuedAt().Format(time.RFC3339))
	if v, ok := t.Get(`privateClaimKey`); ok {
		fmt.Printf("privateClaimKey -> '%s'\n", v)
	}
	fmt.Printf("sub -> '%s'\n", t.Subject())

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("failed to generate private key: %s", err)
		return
	}

	// Signing a token (using raw rsa.PrivateKey)
	signed, err := jwt.Sign(t, jwt.WithKey(jwa.RS256, key))
	if err != nil {
		fmt.Printf("failed to sign token: %s\n", err)
		return
	}
	_ = signed
}
