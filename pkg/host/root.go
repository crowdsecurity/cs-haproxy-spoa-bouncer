package host

import (
	"context"
	"path/filepath"

	"github.com/crowdsecurity/crowdsec-spoa/internal/appsec"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation/ban"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation/captcha"
	cslogging "github.com/crowdsecurity/crowdsec-spoa/pkg/logging"
	log "github.com/sirupsen/logrus"
)

type Host struct {
	Host     string          `yaml:"host"`
	Captcha  captcha.Captcha `yaml:"captcha"`
	Ban      ban.Ban         `yaml:"ban"`
	AppSec   appsec.AppSec   `yaml:"appsec"`
	LogLevel *log.Level      `yaml:"log_level"`
	logger   *log.Entry      `yaml:"-"`
}

type Hosts []*Host

func (h Hosts) MatchFirstHost(toMatch string) *Host {
	for _, host := range h {
		matched, err := filepath.Match(host.Host, toMatch)
		if matched && err == nil {
			host.logger.WithField("value", toMatch).Debug("matched host")
			return host
		}
	}
	return nil
}

// Init initializes the logger for the hosts
func (h *Hosts) Init(ctx context.Context, loggingConfig *cslogging.LoggingConfig) {
	for _, host := range *h {
		clog := log.New()

		loggingConfig.ConfigureLogger(clog)

		if host.LogLevel != nil {
			clog.SetLevel(*host.LogLevel)
		}

		host.logger = clog.WithField("host", host.Host)
		if err := host.Captcha.Init(host.logger, ctx); err != nil {
			host.logger.Error(err)
		}
		if err := host.Ban.Init(host.logger); err != nil {
			host.logger.Error(err)
		}
		if err := host.AppSec.Init(host.logger, ctx); err != nil {
			host.logger.Error(err)
		}
	}
}
