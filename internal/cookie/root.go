package cookie

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/crowdsecurity/crowdsec-spoa/internal/session"
	log "github.com/sirupsen/logrus"
)

// CookieGenerator is an interface to generate cookies
type CookieGenerator struct {
	SignCookies *bool      `yaml:"sign_cookies"` // SignCookies signs the cookie value
	Secure      string     `yaml:"secure"`       // Secure sets the secure flag on the cookie, valid arguments are "auto", "always", "never". "auto" relies on the `ssl_fc` flag from HAProxy
	HttpOnly    *bool      `yaml:"http_only"`    // HttpOnly sets the HttpOnly flag on the cookie
	Secret      string     `yaml:"secret"`       // Secret used for signed/encrypted cookies defaults to the secret key of the remediation
	Name        string     `yaml:"-"`            // Name of the cookie, usually set by the remediation. EG "crowdsec_captcha"
	logger      *log.Entry `yaml:"-"`            // logger passed from the remediation
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
	// Default to sign cookies
	if c.SignCookies == nil {
		c.SignCookies = new(bool)
		*c.SignCookies = true
	}
	// Default Secure to auto
	if c.Secure == "" {
		c.Secure = "auto"
	}
	// Default httpOnly to true
	if c.HttpOnly == nil {
		c.HttpOnly = new(bool)
		*c.HttpOnly = true
	}
}

func (c *CookieGenerator) IsValid() error {
	//TODO
	return nil
}

func (c CookieGenerator) GenerateUnsetCookie() *http.Cookie {
	return &http.Cookie{
		Name:     c.Name,
		Value:    "",
		MaxAge:   -1,
		HttpOnly: *c.HttpOnly,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
	}
}

// Generate cookie from a session
func (c *CookieGenerator) GenerateCookie(session *session.Session, ssl *bool) (*http.Cookie, error) {
	cookie := &http.Cookie{
		Name:     c.Name,
		Value:    session.Uuid,
		MaxAge:   int(time.Until(time.Unix(session.ExpiryTime, 0)).Seconds()),
		HttpOnly: *c.HttpOnly,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
	}

	if c.Secure == "auto" {
		if ssl != nil {
			cookie.Secure = *ssl
		} else {
			c.logger.Warn("ssl flag not set, defaulting to false")
		}
	} else if c.Secure == "always" {
		cookie.Secure = true
	}

	if c.SignCookies != nil && *c.SignCookies {
		c.signCookie(cookie)
	}

	return cookie, c.urlEncodeValue(cookie)
}

func (c *CookieGenerator) ValidateCookie(b64Value string) (string, error) {
	value, err := base64.URLEncoding.DecodeString(b64Value)
	if err != nil {
		return "", err
	}

	if c.SignCookies != nil && *c.SignCookies {
		return c.validateSignedCookieValue(string(value))
	}

	return string(value), nil
}

func (c CookieGenerator) urlEncodeValue(cookie *http.Cookie) error {
	cookie.Value = base64.URLEncoding.EncodeToString([]byte(cookie.Value))
	if len(cookie.String()) > 4096 {
		return fmt.Errorf("cookie value too long")
	}
	return nil
}

func (c CookieGenerator) signCookie(cookie *http.Cookie) {
	mac := hmac.New(sha256.New, []byte(c.Secret))
	mac.Write([]byte(cookie.Name))
	mac.Write([]byte(cookie.Value))
	signature := mac.Sum(nil)
	cookie.Value = string(signature) + cookie.Value
}

func (c CookieGenerator) validateSignedCookieValue(signedValue string) (string, error) {
	if signedValue == "" {
		return "", fmt.Errorf("invalid signature")
	}

	if len(signedValue) < sha256.Size {
		return "", fmt.Errorf("invalid signature")
	}

	signature := signedValue[:sha256.Size]
	value := signedValue[sha256.Size:]

	mac := hmac.New(sha256.New, []byte(c.Secret))
	mac.Write([]byte(c.Name))
	mac.Write([]byte(value))
	expectedSignature := mac.Sum(nil)

	if !hmac.Equal([]byte(signature), expectedSignature) {
		return "", fmt.Errorf("invalid signature")
	}

	return value, nil
}
