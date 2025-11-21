package captcha

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec-spoa/internal/cookie"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	"github.com/google/uuid"
	"github.com/negasus/haproxy-spoe-go/action"
	log "github.com/sirupsen/logrus"
)

const (
	Pending = "pending"
	Valid   = "valid"

	// DefaultTimeout is the default HTTP timeout in seconds
	DefaultTimeout = 5
	// MaxTimeout is the maximum allowed timeout in seconds
	MaxTimeout = 300
)

type Captcha struct {
	Provider            string                 `yaml:"provider"`             // Captcha Provider
	SecretKey           string                 `yaml:"secret_key"`           // Captcha Provider Secret Key
	SiteKey             string                 `yaml:"site_key"`             // Captcha Provider Site Key
	FallbackRemediation string                 `yaml:"fallback_remediation"` // if captcha configuration is invalid what should we fallback too
	Timeout             int                    `yaml:"timeout"`              // HTTP client timeout in seconds (default: 5)
	CookieGenerator     cookie.CookieGenerator `yaml:"cookie"`               // CookieGenerator to generate cookies
	PendingTTL          string                 `yaml:"pending_ttl"`          // TTL for pending captcha tokens (default: 30m)
	PassedTTL           string                 `yaml:"passed_ttl"`           // TTL for passed captcha tokens (default: 24h)
	CookieSecret        string                 `yaml:"cookie_secret"`        // Secret for signing captcha cookies (defaults to secret_key if not set)
	logger              *log.Entry             `yaml:"-"`
	client              *http.Client           `yaml:"-"`
	parsedPendingTTL    time.Duration          `yaml:"-"`
	parsedPassedTTL     time.Duration          `yaml:"-"`
}

func (c *Captcha) Init(logger *log.Entry) error {
	c.InitLogger(logger)

	// Clone the default transport to preserve proxy settings and other defaults
	transport := http.DefaultTransport.(*http.Transport).Clone()

	// Override only the specific settings we need
	transport.MaxIdleConns = 10
	transport.MaxIdleConnsPerHost = 2
	transport.IdleConnTimeout = 30 * time.Second
	transport.DisableKeepAlives = false
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.DialContext = (&net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext

	c.client = &http.Client{
		Transport: transport,
		// HTTP client timeout as safety net - should match or exceed context timeout
		Timeout: time.Duration(c.getTimeout()) * time.Second,
	}

	if c.FallbackRemediation == "" {
		c.logger.Info("no fallback remediation specified defaulting to ban")
		c.FallbackRemediation = "ban"
	}

	// Parse TTLs
	if c.PendingTTL == "" {
		c.PendingTTL = "30m"
	}
	if c.PassedTTL == "" {
		c.PassedTTL = "24h"
	}

	var err error
	c.parsedPendingTTL, err = time.ParseDuration(c.PendingTTL)
	if err != nil {
		c.logger.WithError(err).WithField("pending_ttl", c.PendingTTL).Warn("failed to parse pending_ttl, using default")
		c.parsedPendingTTL = DefaultPendingTTL
	}

	c.parsedPassedTTL, err = time.ParseDuration(c.PassedTTL)
	if err != nil {
		c.logger.WithError(err).WithField("passed_ttl", c.PassedTTL).Warn("failed to parse passed_ttl, using default")
		c.parsedPassedTTL = DefaultPassedTTL
	}

	if err := c.IsValid(); err != nil {
		return err
	}

	// Determine cookie secret (use cookie_secret if set, otherwise fall back to secret_key)
	cookieSecret := c.CookieSecret
	if cookieSecret == "" {
		cookieSecret = c.SecretKey
	}

	// Initialize cookie generator
	c.CookieGenerator.Init(c.logger, "crowdsec_captcha_cookie", cookieSecret)

	return nil
}

func (c *Captcha) InitLogger(logger *log.Entry) {
	c.logger = logger.WithField("module", "captcha")
}

// getTimeout returns the configured timeout with validation and bounds checking
func (c *Captcha) getTimeout() int {
	if c.Timeout <= 0 {
		return DefaultTimeout
	}
	if c.Timeout > MaxTimeout {
		c.logger.WithField("configured_timeout", c.Timeout).WithField("max_timeout", MaxTimeout).
			Warn("configured timeout exceeds maximum, using maximum")
		return MaxTimeout
	}
	return c.Timeout
}

// Inject key values injects the captcha provider key values into the HAProxy transaction
func (c *Captcha) InjectKeyValues(actions *action.Actions) error {

	// We check if the captcha configuration is valid for the front-end
	if err := c.IsFrontEndValid(); err != nil {
		return err
	}

	actions.SetVar(action.ScopeTransaction, "captcha_site_key", c.SiteKey)
	actions.SetVar(action.ScopeTransaction, "captcha_frontend_key", providers[c.Provider].key)
	actions.SetVar(action.ScopeTransaction, "captcha_frontend_js", providers[c.Provider].js)

	return nil
}

type CaptchaResponse struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes"`
}

// Validate tries to validate the captcha response and returns true if the captcha is valid
func (c *Captcha) Validate(ctx context.Context, tokenUUID, toParse string) (bool, error) {
	clog := c.logger.WithField("uuid", tokenUUID)

	if len(toParse) == 0 {
		clog.Warn("captcha validation called with empty request body - form may be submitting without captcha response")
		return false, fmt.Errorf("empty captcha request body")
	}

	values, err := url.ParseQuery(toParse)
	if err != nil {
		clog.WithError(err).Error("failed to parse captcha response")
		return false, fmt.Errorf("failed to parse captcha response: %w", err)
	}

	response := values.Get(fmt.Sprintf("%s-response", providers[c.Provider].key))

	if response == "" {
		clog.Debug("user submitted empty captcha response")
		return false, fmt.Errorf("empty captcha response field")
	}

	body := url.Values{}
	body.Add("secret", c.SecretKey)
	body.Add("response", response)

	// Create a context with timeout for the request
	reqCtx, cancel := context.WithTimeout(ctx, time.Duration(c.getTimeout())*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, providers[c.Provider].validate, strings.NewReader(body.Encode()))
	if err != nil {
		clog.WithError(err).Error("failed to create captcha validation request")
		return false, fmt.Errorf("failed to create captcha validation request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := c.client.Do(req)

	if err != nil {
		// Check for specific error types and log appropriately
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			clog.WithError(err).WithField("timeout_seconds", c.getTimeout()).Error("captcha validation context deadline exceeded")
			return false, fmt.Errorf("captcha validation timeout: %w", err)
		case errors.Is(err, context.Canceled):
			clog.WithError(err).Warn("captcha validation request was canceled")
			return false, fmt.Errorf("captcha validation canceled: %w", err)
		default:
			// Check if it's a network timeout
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				clog.WithError(err).WithField("timeout_seconds", c.getTimeout()).Error("captcha validation network timeout")
				return false, fmt.Errorf("captcha validation network timeout: %w", err)
			} else {
				clog.WithError(err).Error("failed to validate captcha")
				return false, fmt.Errorf("captcha validation failed: %w", err)
			}
		}
	}

	defer func() {
		if closeErr := res.Body.Close(); closeErr != nil {
			clog.WithError(closeErr).Error("failed to close response body")
		}
	}()

	// Log HTTP status code for debugging but don't fail on non-200 since most providers return 200 regardless
	clog.WithField("status_code", res.StatusCode).Debug("captcha provider response status")

	contentType := res.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		clog.WithField("content_type", contentType).Debug("invalid response content type, expected application/json")
		return false, fmt.Errorf("invalid response content type: %s, expected application/json", contentType)
	}

	captchaRes := &CaptchaResponse{}
	if err := json.NewDecoder(res.Body).Decode(captchaRes); err != nil {
		clog.WithError(err).Error("failed to decode captcha response")
		return false, fmt.Errorf("failed to decode captcha response: %w", err)
	}

	// Create log fields once and reuse logger entry
	logFields := log.Fields{
		"success": captchaRes.Success,
	}

	// Add error codes if present
	if len(captchaRes.ErrorCodes) > 0 {
		logFields["error_codes"] = captchaRes.ErrorCodes
	}

	// Create logger entry once with all fields
	l := clog.WithFields(logFields)

	if captchaRes.Success {
		l.Info("captcha validation successful")
		return true, nil
	}

	// Log failure with error codes for troubleshooting
	var errorMsg string
	if len(captchaRes.ErrorCodes) > 0 {
		l.Warn("captcha validation failed with provider error codes")
		errorMsg = fmt.Sprintf("captcha validation failed with error codes: %v", captchaRes.ErrorCodes)
	} else {
		l.Warn("captcha validation failed without error codes")
		errorMsg = "captcha validation failed without error codes"
	}
	return false, fmt.Errorf("%s", errorMsg)
}

// IsFrontEndValid checks if the captcha configuration is valid for the front-end
func (c *Captcha) IsFrontEndValid() error {
	if c.Provider == "" {
		return fmt.Errorf("empty captcha provider")
	}

	if !ValidProvider(c.Provider) {
		return fmt.Errorf("invalid captcha provider %s", c.Provider)
	}

	if c.SiteKey == "" {
		return fmt.Errorf("empty captcha site key")
	}

	tRem := remediation.FromString(c.FallbackRemediation)
	if tRem != remediation.Ban && tRem != remediation.Allow {
		return fmt.Errorf("invalid fallback remediation %s", c.FallbackRemediation)
	}

	return nil
}

// IsValid checks if the captcha configuration is valid for the back-end most notably the secret key
func (c *Captcha) IsValid() error {
	if err := c.IsFrontEndValid(); err != nil {
		return err
	}

	if c.SecretKey == "" {
		return fmt.Errorf("empty captcha secret key")
	}

	return nil
}

// GetCookieSecret returns the secret used for signing captcha cookies
// Returns cookie_secret if set, otherwise falls back to secret_key
func (c *Captcha) GetCookieSecret() string {
	if c.CookieSecret != "" {
		return c.CookieSecret
	}
	return c.SecretKey
}

// NewPendingToken creates a new pending captcha token using the host's configured TTL
func (c *Captcha) NewPendingToken() (CaptchaToken, error) {
	tokenUUID, err := uuid.NewRandom()
	if err != nil {
		return CaptchaToken{}, fmt.Errorf("failed to generate UUID: %w", err)
	}

	now := time.Now().Unix()
	return CaptchaToken{
		UUID: tokenUUID.String(),
		St:   Pending,
		Iat:  now,
		Exp:  now + int64(c.parsedPendingTTL.Seconds()),
	}, nil
}

// NewPassedToken creates a new passed captcha token using the host's configured TTL
// Reuses the UUID from the existing token for traceability
func (c *Captcha) NewPassedToken(existingToken *CaptchaToken) CaptchaToken {
	now := time.Now().Unix()
	tokenUUID := ""
	if existingToken != nil && existingToken.UUID != "" {
		tokenUUID = existingToken.UUID
	} else {
		// Generate new UUID if none exists (shouldn't happen in normal flow)
		if newUUID, err := uuid.NewRandom(); err == nil {
			tokenUUID = newUUID.String()
		}
	}

	return CaptchaToken{
		UUID: tokenUUID,
		St:   Valid,
		Iat:  now,
		Exp:  now + int64(c.parsedPassedTTL.Seconds()),
	}
}

// GenerateCookie generates an HTTP cookie from a captcha token using the host's configuration
func (c *Captcha) GenerateCookie(tok CaptchaToken, ssl *bool) (*http.Cookie, error) {
	secure := false
	if ssl != nil {
		secure = *ssl
	}
	if c.CookieGenerator.Secure == "always" {
		secure = true
	}

	return GenerateCaptchaCookie(
		tok,
		c.GetCookieSecret(),
		c.CookieGenerator.Name,
		*c.CookieGenerator.HTTPOnly,
		secure,
	)
}

// ValidateCookie validates a base64-encoded captcha cookie value using the host's secret
func (c *Captcha) ValidateCookie(b64Value string) (*CaptchaToken, error) {
	return ValidateCaptchaCookie(b64Value, c.GetCookieSecret())
}
