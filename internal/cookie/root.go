package cookie

import (
	"net/http"

	log "github.com/sirupsen/logrus"
)

// CookieGenerator is an interface to generate cookies
type CookieGenerator struct {
	Type   string     `yaml:"type"`
	name   string     `yaml:"-"`
	secure bool       `yaml:"-"`
	maxAge int        `yaml:"-"`
	logger *log.Entry `yaml:"-"`
}

func (c *CookieGenerator) Init(logger *log.Entry) {
	c.logger = logger.WithField("sub_type", "cookie")
	c.SetDefaults()
}

func (c *CookieGenerator) SetDefaults() {
	if c.Type == "" {
		c.Type = "signed"
	}
}

func (c *CookieGenerator) IsValid() error {
	//TODO
	return nil
}

func (c *CookieGenerator) GenerateCookie() (*http.Cookie, error) {
	//TODO
	switch c.Type {
	case "encrypted":
		return nil, nil
	case "signed":
		return nil, nil
	}
	return nil, nil
}
