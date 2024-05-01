package captcha

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

type Captcha struct {
	Provider     string             `yaml:"provider"`
	SecretKey    string             `yaml:"secret_key"`
	SiteKey      string             `yaml:"site_key"`
	TemplatePath string             `yaml:"template_path"`
	template     *template.Template `yaml:"-"`
	logger       *log.Entry         `yaml:"-"`
	client       *http.Client       `yaml:"-"`
}

func (c *Captcha) Init(logger *log.Entry) error {
	c.InitLogger(logger)
	c.client = &http.Client{
		Transport: &http.Transport{MaxIdleConns: 10, IdleConnTimeout: 30 * time.Second},
		Timeout:   5 * time.Second,
	}
	return nil
}

func (c *Captcha) InitLogger(logger *log.Entry) {
	c.logger = logger.WithField("type", "captcha")
}

func (c *Captcha) InitTemplate() error {
	// check if user provided a custom template
	if c.TemplatePath != "" {
		b, err := os.ReadFile(c.TemplatePath)
		if err != nil {
			return err
		}
		c.template, err = template.New("captcha").Parse(string(b))
		if err != nil {
			return err
		}
	}

	// if template is nil the user did not provide a template
	if c.template == nil {
		var err error
		c.template, err = template.New("captcha").Parse(DefaultCaptchaTemplate)
		if err != nil {
			return err
		}
	}

	if err := c.IsValid(); err != nil {
		c.template = nil
		c.logger.WithError(err).Error("invalid captcha configuration")
	}

	return nil
}

type CaptchaResponse struct {
	Success bool `json:"success"`
}

func (c *Captcha) Validate(r *http.Request) (bool, error) {
	if r.Method != http.MethodPost {
		c.logger.Debug("invalid method")
		return false, nil
	}
	response := r.FormValue(fmt.Sprintf("%s-response", providers[c.Provider].key))
	if response == "" {
		c.logger.Debug("empty response")
		return false, nil
	}
	body := url.Values{}
	body.Add("secret", c.SecretKey)
	body.Add("response", response)
	res, err := c.client.PostForm(providers[c.Provider].validate, body)
	if err != nil {
		return false, err
	}
	defer func() {
		if err = res.Body.Close(); err != nil {
			c.logger.WithError(err).Error("failed to close response body")
		}
	}()
	if !strings.Contains(res.Header.Get("Content-Type"), "application/json") {
		c.logger.Debug("invalid response content type")
		return false, nil
	}
	captchaRes := &CaptchaResponse{}
	if err := json.NewDecoder(res.Body).Decode(captchaRes); err != nil {
		return false, err
	}
	return captchaRes.Success, nil
}

func (c *Captcha) IsValid() error {

	if c.Provider == "" {
		return fmt.Errorf("empty captcha provider")
	}

	if !ValidProvider(c.Provider) {
		return fmt.Errorf("invalid captcha provider %s", c.Provider)
	}

	if c.SecretKey == "" {
		return fmt.Errorf("empty captcha secret key")
	}

	if c.SiteKey == "" {
		return fmt.Errorf("empty captcha site key")
	}

	return nil
}

func (c *Captcha) Render(wr *os.File) error {
	if c.template == nil {
		c.logger.Debug("no template to render")
		return nil
	}

	c.logger.Debug("rendering captcha template")

	return c.template.ExecuteTemplate(wr, "captcha", map[string]string{
		"SiteKey":     c.SiteKey,
		"FrontendJS":  providers[c.Provider].js,
		"FrontendKey": providers[c.Provider].key,
	})
}
