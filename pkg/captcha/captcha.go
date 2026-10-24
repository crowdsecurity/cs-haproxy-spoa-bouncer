package captcha

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec-spoa/internal/captcha/cookie"
	"github.com/crowdsecurity/crowdsec-spoa/internal/captcha/jwt"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	"github.com/dropmorepackets/haproxy-go/pkg/encoding"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

const (
	// Re-export constants from jwt package for backward compatibility
	Pending = jwt.Pending
	Valid   = jwt.Valid

	// DefaultTimeout is the default HTTP timeout in seconds
	DefaultTimeout = 5
	// MaxTimeout is the maximum allowed timeout in seconds
	MaxTimeout = 300

	// maxVerifyResponseBytes bounds how much of the verification response is read
	maxVerifyResponseBytes = 64 << 10
)

// Token is a type alias for jwt.Token to provide a clean public API
type Token = jwt.Token

type Captcha struct {
	Provider            string           `yaml:"provider"`             // Captcha Provider
	SecretKey           string           `yaml:"secret_key"`           // Captcha Provider Secret Key (for API validation)
	SiteKey             string           `yaml:"site_key"`             // Captcha Provider Site Key
	Custom              CustomConfig     `yaml:"custom"`               // Settings of the generic provider (only with provider: custom)
	FallbackRemediation string           `yaml:"fallback_remediation"` // if captcha configuration is invalid what should we fallback too
	Timeout             int              `yaml:"timeout"`              // HTTP client timeout in seconds (default: 5)
	Cookie              cookie.Generator `yaml:"cookie"`               // Cookie configuration (HTTP attributes like Secure, HttpOnly). Do not access directly, use GenerateCookie/GenerateUnsetCookie methods
	PendingTTL          string           `yaml:"pending_ttl"`          // TTL for pending captcha tokens (default: 30m)
	PassedTTL           string           `yaml:"passed_ttl"`           // TTL for passed captcha tokens (default: 24h)
	SigningKey          string           `yaml:"signing_key"`          // Key for signing JWT captcha tokens (required, minimum 32 bytes) - breaking change in 0.3.0
	logger              *log.Entry       `yaml:"-"`
	client              *http.Client     `yaml:"-"`
	parsedPendingTTL    time.Duration    `yaml:"-"`
	parsedPassedTTL     time.Duration    `yaml:"-"`
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

	if c.Provider == CustomProvider {
		// The verification URL comes from the configuration: never follow a redirect to somewhere else
		// with the secret key in the request body.
		c.client.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
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
		c.parsedPendingTTL = jwt.DefaultPendingTTL
	}

	c.parsedPassedTTL, err = time.ParseDuration(c.PassedTTL)
	if err != nil {
		c.logger.WithError(err).WithField("passed_ttl", c.PassedTTL).Warn("failed to parse passed_ttl, using default")
		c.parsedPassedTTL = jwt.DefaultPassedTTL
	}

	if err := c.IsValid(); err != nil {
		return err
	}

	// Initialize cookie generator (cookie_secret is validated in IsValid())
	c.Cookie.Init(c.logger, "crowdsec_captcha_cookie")

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
// Validates configuration before injecting values
func (c *Captcha) InjectKeyValues(writer *encoding.ActionWriter) error {
	// Validate configuration before injecting values
	if err := c.IsValid(); err != nil {
		return err
	}

	spec, err := c.spec()
	if err != nil {
		return err
	}

	for name, value := range c.frontendVars(&spec) {
		_ = writer.SetString(encoding.VarScopeTransaction, name, value)
	}

	return nil
}

// frontendVars returns the HAProxy transaction variables used by the captcha page template.
func (c *Captcha) frontendVars(spec *providerSpec) map[string]string {
	return map[string]string{
		// Both are written in HTML attributes: escape so that e.g. "&copy;" in a URL is not read as an entity
		"captcha_site_key":         html.EscapeString(c.SiteKey),
		"captcha_frontend_key":     spec.class,
		"captcha_frontend_js":      html.EscapeString(spec.js),
		"captcha_frontend_js_type": spec.jsType,
		"captcha_frontend_tag":     spec.tag,
		"captcha_frontend_attrs":   spec.attrs,
		"captcha_response_field":   spec.responseField,
	}
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

	spec, err := c.spec()
	if err != nil {
		return false, err
	}

	// The https policy protects the secret key: do not rely on the caller having validated the configuration.
	if spec.custom {
		if err := c.Custom.validate(); err != nil {
			return false, err
		}
	}

	response := values.Get(spec.responseField)

	if response == "" {
		clog.Debug("user submitted empty captcha response")
		return false, fmt.Errorf("empty captcha response field")
	}

	payload, contentType, err := encodeVerifyRequest(spec.verifyFormat, c.SecretKey, response)
	if err != nil {
		clog.WithError(err).Error("failed to encode captcha validation request")
		return false, fmt.Errorf("failed to encode captcha validation request: %w", err)
	}

	// Create a context with timeout for the request
	reqCtx, cancel := context.WithTimeout(ctx, time.Duration(c.getTimeout())*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, spec.verifyURL, strings.NewReader(payload))
	if err != nil {
		clog.WithError(err).Error("failed to create captcha validation request")
		return false, fmt.Errorf("failed to create captcha validation request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")

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

	// Redirects are only left unfollowed for the custom provider (see Init)
	if res.StatusCode >= http.StatusMultipleChoices && res.StatusCode < http.StatusBadRequest {
		clog.WithField("status_code", res.StatusCode).Error("captcha verification endpoint answered with a redirect, check verify_url")
		return false, fmt.Errorf("unexpected redirect (HTTP %d) from the captcha verification endpoint", res.StatusCode)
	}

	respContentType := res.Header.Get("Content-Type")
	if mediaType, _, _ := mime.ParseMediaType(respContentType); mediaType != "application/json" {
		l := clog.WithFields(log.Fields{"content_type": respContentType, "status_code": res.StatusCode})
		switch {
		// Some self-hosted verifiers (e.g. wicketkeeper) reject a bad solution with a plain text 400/403
		case spec.custom && (res.StatusCode == http.StatusBadRequest || res.StatusCode == http.StatusForbidden):
			l.Warn("captcha response rejected by the verification endpoint")
			return false, fmt.Errorf("captcha response rejected by the verification endpoint (HTTP %d)", res.StatusCode)
		case spec.custom:
			l.Error("invalid response content type from the captcha verification endpoint, expected application/json, check custom.verify_url")
		default:
			l.Debug("invalid response content type, expected application/json")
		}
		return false, fmt.Errorf("invalid response content type: %s (HTTP %d), expected application/json", respContentType, res.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(res.Body, maxVerifyResponseBytes+1))
	if err != nil {
		clog.WithError(err).Error("failed to read captcha response")
		return false, fmt.Errorf("failed to read captcha response: %w", err)
	}

	if len(body) > maxVerifyResponseBytes {
		clog.Error("captcha verification response is too large")
		return false, fmt.Errorf("captcha verification response is larger than %d bytes", maxVerifyResponseBytes)
	}

	// Unmarshal, unlike Decoder.Decode, also rejects data after the JSON document
	captchaRes := &CaptchaResponse{}
	if err := json.Unmarshal(body, captchaRes); err != nil {
		clog.WithError(err).Error("failed to decode captcha response")
		return false, fmt.Errorf("failed to decode captcha response: %w", err)
	}

	// Self-hosted verifiers may reject a token with an error status (Cap answers 400/403/404 with
	// {"success": false}), which is a normal failure. A success with an error status (gateway, WAF) is never trusted.
	if spec.custom && res.StatusCode != http.StatusOK && captchaRes.Success {
		clog.WithField("status_code", res.StatusCode).Error("captcha verification endpoint answered success with an unexpected status, check custom.verify_url")
		return false, fmt.Errorf("unexpected HTTP status %d from the captcha verification endpoint", res.StatusCode)
	}

	// Create log fields once and reuse logger entry
	logFields := log.Fields{
		"success":     captchaRes.Success,
		"status_code": res.StatusCode,
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

// IsValid checks if the captcha configuration is valid (frontend and backend)
func (c *Captcha) IsValid() error {
	// Frontend validation
	if c.Provider == "" {
		return fmt.Errorf("empty captcha provider")
	}

	if !ValidProvider(c.Provider) {
		return fmt.Errorf("invalid captcha provider %s, supported providers are %s, %s, %s and %s", c.Provider,
			HcaptchaProvider, RecaptchaProvider, TurnstileProvider, CustomProvider)
	}

	if c.Provider == CustomProvider {
		if err := c.Custom.validate(); err != nil {
			return err
		}
	} else if !c.Custom.isZero() {
		return fmt.Errorf("the custom settings can only be used with provider %q, not %q", CustomProvider, c.Provider)
	}

	// Some self-hosted captchas have no site key (e.g. the key is part of the endpoint URL)
	if c.SiteKey == "" && c.Provider != CustomProvider {
		return fmt.Errorf("empty captcha site key")
	}

	tRem := remediation.FromString(c.FallbackRemediation)
	if tRem != remediation.Ban && tRem != remediation.Allow {
		return fmt.Errorf("invalid fallback remediation %s", c.FallbackRemediation)
	}

	// Backend validation
	if c.SecretKey == "" {
		return fmt.Errorf("empty captcha secret key")
	}

	// Require explicit signing_key configuration (breaking change in 0.3.0)
	// This ensures proper secret management and compliance requirements
	if c.SigningKey == "" {
		return fmt.Errorf("signing_key is required for JWT token signing (minimum 32 bytes). This is a breaking change in 0.3.0")
	}

	// Validate signing_key meets minimum security requirements
	if len(c.SigningKey) < 32 {
		return fmt.Errorf("signing_key must be at least 32 bytes for security. Current length: %d bytes. Please use a cryptographically secure random key of at least 32 bytes", len(c.SigningKey))
	}

	return nil
}

// NewPendingToken creates a new pending captcha token using the host's configured TTL
func (c *Captcha) NewPendingToken() (jwt.Token, error) {
	tokenUUID, err := uuid.NewRandom()
	if err != nil {
		return jwt.Token{}, fmt.Errorf("failed to generate UUID: %w", err)
	}

	now := time.Now().Unix()
	return jwt.Token{
		UUID: tokenUUID.String(),
		St:   Pending,
		Iat:  now,
		Exp:  now + int64(c.parsedPendingTTL.Seconds()),
	}, nil
}

// NewPassedToken creates a new passed captcha token using the host's configured TTL
// Reuses the UUID from the existing token for traceability
func (c *Captcha) NewPassedToken(existingToken *jwt.Token) jwt.Token {
	now := time.Now().Unix()
	tokenUUID := ""
	if existingToken != nil && existingToken.UUID != "" {
		tokenUUID = existingToken.UUID
	} else {
		// Generate new UUID if none exists (shouldn't happen in normal flow)
		newUUID, err := uuid.NewRandom()
		if err != nil {
			c.logger.WithError(err).Error("Failed to generate UUID for passed token")
		} else {
			tokenUUID = newUUID.String()
		}
	}

	return jwt.Token{
		UUID: tokenUUID,
		St:   Valid,
		Iat:  now,
		Exp:  now + int64(c.parsedPassedTTL.Seconds()),
	}
}

// GenerateCookie generates an HTTP cookie from a captcha token using the host's configuration
func (c *Captcha) GenerateCookie(tok jwt.Token, ssl *bool) (*http.Cookie, error) {
	signedToken, err := jwt.Sign(tok, []byte(c.SigningKey))
	if err != nil {
		return nil, fmt.Errorf("failed to sign captcha token: %w", err)
	}

	return c.Cookie.Generate(signedToken, ssl)
}

// GenerateUnsetCookie generates a cookie deletion header for clearing the captcha cookie
func (c *Captcha) GenerateUnsetCookie(ssl *bool) *http.Cookie {
	return c.Cookie.GenerateUnset(ssl)
}

// ValidateCookie validates a JWT captcha cookie value using the host's signing key
func (c *Captcha) ValidateCookie(cookieValue string) (*jwt.Token, error) {
	return jwt.ParseAndVerify(cookieValue, []byte(c.SigningKey))
}

// IsCaptchaSubmission checks if the body appears to be a captcha form submission
// by looking for the provider-specific response field (e.g., "g-recaptcha-response", "h-captcha-response",
// or the configured custom.response_field)
// This prevents treating unrelated form submissions as captcha validation attempts
func (c *Captcha) IsCaptchaSubmission(body string) bool {
	if body == "" {
		return false
	}
	values, err := url.ParseQuery(body)
	if err != nil {
		return false
	}
	spec, err := c.spec()
	if err != nil {
		return false
	}
	return values.Has(spec.responseField)
}

// encodeVerifyRequest builds the body of the verification request in the requested format and returns
// it along with the matching Content-Type.
func encodeVerifyRequest(format, secret, response string) (string, string, error) {
	if format == VerifyFormatJSON {
		payload, err := json.Marshal(map[string]string{"secret": secret, "response": response})
		if err != nil {
			return "", "", fmt.Errorf("failed to marshal verification request: %w", err)
		}

		return string(payload), "application/json", nil
	}

	body := url.Values{}
	body.Add("secret", secret)
	body.Add("response", response)

	return body.Encode(), "application/x-www-form-urlencoded", nil
}
