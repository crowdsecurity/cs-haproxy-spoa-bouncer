package cookie

import (
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/crowdsecurity/go-cs-lib/ptr"
	log "github.com/sirupsen/logrus"
)

// CookieGenerator is an interface to generate cookies
type CookieGenerator struct {
	Secure   string     `yaml:"secure"`    // Secure sets the secure flag on the cookie, valid arguments are "auto", "always", "never". "auto" relies on the `ssl_fc` flag from HAProxy
	HTTPOnly *bool      `yaml:"http_only"` // HttpOnly sets the HttpOnly flag on the cookie
	Secret   string     `yaml:"secret"`    // Secret used for signing cookies (required for stateless cookies)
	Name     string     `yaml:"-"`         // Name of the cookie, usually set by the remediation. EG "crowdsec_captcha"
	logger   *log.Entry `yaml:"-"`         // logger passed from the remediation
}

func (c *CookieGenerator) Init(logger *log.Entry, name, secret string) {
	c.logger = logger.WithField("type", "cookie")
	c.Name = name
	if c.Secret == "" {
		c.Secret = secret
	}
	c.SetDefaults()
}

func (c *CookieGenerator) SetDefaults() {
	// Default Secure to auto
	if c.Secure == "" {
		c.Secure = "auto"
	}
	// Default httpOnly to true
	if c.HTTPOnly == nil {
		c.HTTPOnly = ptr.Of(true)
	}
	// Note: Cookies are always signed (required for stateless design)
}

func (c *CookieGenerator) IsValid() error {
	//TODO
	return nil
}

func (c *CookieGenerator) GenerateUnsetCookie(ssl *bool) (*http.Cookie, error) {
	cookie := &http.Cookie{
		Name:     c.Name,
		Value:    "",
		MaxAge:   -1,
		HttpOnly: *c.HTTPOnly,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	}

	switch c.Secure {
	case "auto":
		if ssl != nil {
			cookie.Secure = *ssl
		} else {
			c.logger.Warn("ssl flag not set, defaulting to false")
		}
	case "always":
		cookie.Secure = true
	}

	return cookie, urlEncodeValue(cookie)
}

func urlEncodeValue(cookie *http.Cookie) error {
	cookie.Value = base64.URLEncoding.EncodeToString([]byte(cookie.Value))
	if len(cookie.String()) > 4096 {
		return fmt.Errorf("cookie value too long")
	}
	return nil
}
