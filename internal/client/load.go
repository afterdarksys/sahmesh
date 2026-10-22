package client

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/afterdarksys/sahmesh/internal/config"
	"github.com/afterdarksys/sahmesh/internal/token"
)

// LoadAuth is sahconnect's credential choice, copied so it cannot drift into
// sending a bearer to a different origin. A token file that fails its checks
// is an error. A token for another origin is never placed on the request; an
// API key may be used instead only when one is set, and the caller is told.
func LoadAuth(cfg *config.Config, base *url.URL) (auth Auth, note string, err error) {
	if cfg == nil || base == nil {
		return Auth{}, "", code("credentials_missing")
	}
	tf, found, err := token.Read(cfg.TokenFile)
	if err != nil {
		return Auth{}, "", err
	}
	origin := token.Origin(base)
	switch {
	case found && tf.Origin == origin:
		if cfg.APIKey != "" {
			note = "credential: bearer from the token file (it wins over SYSTEMAPI_API_KEY)"
		}
		return Auth{Bearer: tf.Token, BearerOrigin: tf.Origin}, note, nil
	case found && cfg.APIKey != "":
		return Auth{APIKey: cfg.APIKey}, "credential: SYSTEMAPI_API_KEY (the token file is for " + tf.Origin + ", not " + origin + ")", nil
	case found:
		return Auth{}, "", fmt.Errorf("the token file is for %s, not %s: run sahconnect login --url %s, or set SYSTEMAPI_API_KEY", tf.Origin, origin, origin)
	case cfg.APIKey != "":
		return Auth{APIKey: cfg.APIKey}, "", nil
	}
	return Auth{}, "", errors.New("not logged in: run sahconnect login, or set SYSTEMAPI_API_KEY")
}
