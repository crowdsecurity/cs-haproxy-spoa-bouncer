package cookie

import (
	"fmt"
	"net/http"

	"github.com/crowdsecurity/go-cs-lib/ptr"
	log "github.com/sirupsen/logrus"
)

// Generator handles cookie configuration and generation for captcha
// Note: This struct handles HTTP cookie attributes only (Secure, HttpOnly, etc.)
// JWT signing is handled at the Captcha level using signing_key
type Generator struct {
	Secure   string     `yaml:"secure"`    // Secure sets the secure flag on the cookie, valid arguments are "auto", "always", "never". "auto" relies on the `ssl_fc` flag from HAProxy
	HTTPOnly *bool      `yaml:"http_only"` // HttpOnly sets the HttpOnly flag on the cookie
	Name     string     `yaml:"-"`         // Name of the cookie, usually set by the remediation. EG "crowdsec_captcha"
	logger   *log.Entry `yaml:"-"`         // logger passed from the remediation
}

func (g *Generator) Init(logger *log.Entry, name string) {
	g.logger = logger.WithField("type", "cookie")
	g.Name = name
	g.SetDefaults()
}

func (g *Generator) SetDefaults() {
	if g.Secure == "" {
		g.Secure = "auto"
	}
	if g.HTTPOnly == nil {
		g.HTTPOnly = ptr.Of(true)
	}
}

// resolveSecure determines the secure flag value based on configuration and SSL state
func (g *Generator) resolveSecure(ssl *bool) bool {
	switch g.Secure {
	case "always":
		return true
	case "auto":
		if ssl != nil {
			return *ssl
		}
		return false
	default: // "never" or any other value
		return false
	}
}

// GenerateUnset creates a cookie deletion header
func (g *Generator) GenerateUnset(ssl *bool) *http.Cookie {
	return &http.Cookie{
		Name:     g.Name,
		Value:    "",
		MaxAge:   -1,
		HttpOnly: *g.HTTPOnly,
		Secure:   g.resolveSecure(ssl),
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	}
}

// Generate generates an HTTP cookie with the provided signed token value
// This is called by Captcha.GenerateCookie() which handles the JWT signing
func (g *Generator) Generate(signedToken string, ssl *bool) (*http.Cookie, error) {
	cookie := &http.Cookie{
		Name:     g.Name,
		Value:    signedToken,
		MaxAge:   0, // Session cookie
		HttpOnly: *g.HTTPOnly,
		Secure:   g.resolveSecure(ssl),
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	}

	if len(cookie.String()) > 4096 {
		return nil, fmt.Errorf("cookie value too long")
	}

	return cookie, nil
}
