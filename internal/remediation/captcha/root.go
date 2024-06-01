package captcha

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec-spoa/internal/cookie"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	"github.com/crowdsecurity/crowdsec-spoa/internal/session"
	"github.com/negasus/haproxy-spoe-go/action"
	log "github.com/sirupsen/logrus"
)

const (
	Pending = "pending"
	Valid   = "valid"
)

type Captcha struct {
	Provider            string                 `yaml:"provider"`             // Captcha Provider
	SecretKey           string                 `yaml:"secret_key"`           // Captcha Provider Secret Key
	SiteKey             string                 `yaml:"site_key"`             // Captcha Provider Site Key
	FallbackRemediation string                 `yaml:"fallback_remediation"` // if captcha configuration is invalid what should we fallback too
	CookieGenerator     cookie.CookieGenerator `yaml:"cookie"`               // CookieGenerator to generate cookies from sessions
	Sessions            session.Sessions       `yaml:",inline"`              // sessions that are being traced for captcha
	logger              *log.Entry             `yaml:"-"`
	client              *http.Client           `yaml:"-"`
	Cancel              context.CancelFunc     `yaml:"-"`
}

func (c *Captcha) Init(logger *log.Entry, ctx context.Context) error {
	c.InitLogger(logger)

	var cancelCtx context.Context
	cancelCtx, c.Cancel = context.WithCancel(ctx)

	c.client = &http.Client{
		Transport: &http.Transport{MaxIdleConns: 10, IdleConnTimeout: 30 * time.Second},
		Timeout:   5 * time.Second,
	}

	if c.FallbackRemediation == "" {
		c.logger.Info("no fallback remediation specified defaulting to ban")
		c.FallbackRemediation = "ban"
	}

	if err := c.IsValid(); err != nil {
		return err
	}

	c.Sessions.Init(c.logger, cancelCtx)
	c.CookieGenerator.Init(c.logger, "crowdsec_captcha_cookie", c.SecretKey)

	return nil
}

func (c *Captcha) InitLogger(logger *log.Entry) {
	c.logger = logger.WithField("module", "captcha")
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
	Success bool `json:"success"`
}

// Validate tries to validate the captcha response and sets the session status to valid if the captcha is valid
func (c *Captcha) Validate(uuid, toParse string) bool {
	clog := c.logger.WithField("session", uuid)

	if len(toParse) == 0 {
		return false
	}

	values, err := url.ParseQuery(toParse)
	if err != nil {
		clog.WithError(err).Error("failed to parse captcha response")
		return false
	}

	response := values.Get(fmt.Sprintf("%s-response", providers[c.Provider].key))

	if response == "" {
		clog.Debug("user submitted empty captcha response")
		return false
	}

	// if tries := s.Get(session.CAPTCHA_TRIES); tries != nil {
	// 	s.Set(session.CAPTCHA_TRIES, tries.(int)+1)
	// } else {
	// 	s.Set(session.CAPTCHA_TRIES, 1)
	// }

	body := url.Values{}
	body.Add("secret", c.SecretKey)
	body.Add("response", response)

	res, err := c.client.PostForm(providers[c.Provider].validate, body)

	if err != nil {
		clog.WithError(err).Error("failed to validate captcha")
		return false
	}

	defer func() {
		if err = res.Body.Close(); err != nil {
			clog.WithError(err).Error("failed to close response body")
		}
	}()

	if !strings.Contains(res.Header.Get("Content-Type"), "application/json") {
		clog.Debug("invalid response content type")
		return false
	}

	captchaRes := &CaptchaResponse{}
	if err := json.NewDecoder(res.Body).Decode(captchaRes); err != nil {
		clog.WithError(err).Error("failed to decode captcha response")
		return false
	}

	clog.WithField("response", captchaRes.Success).Debug("captcha response")

	return captchaRes.Success
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
