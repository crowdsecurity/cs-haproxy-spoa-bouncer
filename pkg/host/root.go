package host

import (
	"path/filepath"

	"github.com/crowdsecurity/crowdsec-spoa/pkg/appsec"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/ban"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/captcha"
	log "github.com/sirupsen/logrus"
)

type Host struct {
	Host    string          `yaml:"host"`
	Captcha captcha.Captcha `yaml:"captcha"`
	Ban     ban.Ban         `yaml:"ban"`
	AppSec  appsec.AppSec   `yaml:"appsec"`
	logger  *log.Entry      `yaml:"-"`
}

type Hosts []*Host

func (h *Hosts) MatchFirstHost(toMatch string) *Host {
	for _, host := range *h {
		matched, err := filepath.Match(host.Host, toMatch)
		if matched && err == nil {
			host.logger.WithField("value", toMatch).Debug("matched host")
			return host
		}
	}
	return nil
}

// Init initializes the logger for the hosts
func (h *Hosts) Init() {
	for _, host := range *h {
		host.logger = log.WithField("host", host.Host)
		if err := host.Captcha.Init(host.logger); err != nil {
			host.logger.Error(err)
		}
		if err := host.Ban.Init(host.logger); err != nil {
			host.logger.Error(err)
		}
		if err := host.AppSec.Init(host.logger); err != nil {
			host.logger.Error(err)
		}
	}
}
