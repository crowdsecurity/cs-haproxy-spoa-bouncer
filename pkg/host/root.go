package host

import (
	"os"
	"path/filepath"

	"github.com/crowdsecurity/crowdsec-spoa/pkg/ban"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/captcha"
	log "github.com/sirupsen/logrus"
)

type Host struct {
	Host    string          `yaml:"host"`
	Captcha captcha.Captcha `yaml:"captcha"`
	Ban     ban.Ban         `yaml:"ban"`
	logger  *log.Entry      `yaml:"-"`
}

type Hosts []*Host

func (h *Hosts) MatchFirstHost(toMatch string) *Host {
	for _, host := range *h {
		matched, err := filepath.Match(host.Host, toMatch)
		if matched && err == nil {
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
	}
}

// Render pages initializes the templates for the hosts and renders the captcha and ban pages.
func (h *Hosts) RenderPages(dir string) error {
	for _, host := range *h {
		if err := host.Ban.InitTemplate(); err != nil {
			return err
		}
		if err := host.Captcha.InitTemplate(); err != nil {
			return err
		}
		parentDir := filepath.Join(dir, host.Host)
		if err := os.Mkdir(parentDir, 0755); err != nil {
			return err
		}
		f, err := os.OpenFile(filepath.Join(parentDir, "captcha.html"), os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		if err := host.Captcha.Render(f); err != nil {
			return err
		}
		f.Close()
		f, err = os.OpenFile(filepath.Join(parentDir, "ban.html"), os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		if err := host.Ban.Render(f); err != nil {
			return err
		}
		f.Close()
	}
	return nil
}
