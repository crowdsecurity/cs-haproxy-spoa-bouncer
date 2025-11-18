package cfg

import (
	"fmt"
	"io"

	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec-spoa/internal/geo"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/host"
	cslogging "github.com/crowdsecurity/crowdsec-spoa/pkg/logging"
	"github.com/crowdsecurity/go-cs-lib/csyaml"
)

type PrometheusConfig struct {
	Enabled       bool   `yaml:"enabled"`
	ListenAddress string `yaml:"listen_addr"`
	ListenPort    string `yaml:"listen_port"`
}

type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type HTTPTemplateServerConfig struct {
	Enabled         bool      `yaml:"enabled"`
	ListenAddress   string    `yaml:"listen_addr"`
	ListenPort      string    `yaml:"listen_port"`
	TLS             TLSConfig `yaml:"tls"`
	BanTemplate     string    `yaml:"ban_template_path"`
	CaptchaTemplate string    `yaml:"captcha_template_path"`
}

type BouncerConfig struct {
	Logging            cslogging.LoggingConfig  `yaml:",inline"`
	Hosts              []*host.Host             `yaml:"hosts"`
	HostsDir           string                   `yaml:"hosts_dir"`
	Geo                geo.GeoDatabase          `yaml:",inline"`
	ListenTCP          string                   `yaml:"listen_tcp"`
	ListenUnix         string                   `yaml:"listen_unix"`
	PrometheusConfig   PrometheusConfig         `yaml:"prometheus"`
	HTTPTemplateServer HTTPTemplateServerConfig `yaml:"http_template_server"`
}

// MergedConfig() returns the byte content of the patched configuration file (with .yaml.local).
func MergedConfig(configPath string) ([]byte, error) {
	patcher := csyaml.NewPatcher(configPath, ".local")

	data, err := patcher.MergedPatchContent()
	if err != nil {
		return nil, err
	}

	return data, nil
}

func NewConfig(reader io.Reader) (*BouncerConfig, error) {
	config := &BouncerConfig{}

	fcontent, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(fcontent, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %w", err)
	}

	if err = config.Logging.Setup("crowdsec-spoa-bouncer.log"); err != nil {
		return nil, fmt.Errorf("failed to setup logging: %w", err)
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	return config, nil
}

func (c *BouncerConfig) Validate() error {
	if c == nil {
		return fmt.Errorf("configuration is nil")
	}

	if c.ListenTCP == "" && c.ListenUnix == "" {
		return fmt.Errorf("configuration requires at least one listener: set listen_tcp or listen_unix")
	}

	// Validate HTTP template server configuration if enabled
	if c.HTTPTemplateServer.Enabled {
		if c.HTTPTemplateServer.ListenAddress == "" {
			return fmt.Errorf("http_template_server.listen_addr is required when http_template_server.enabled is true")
		}
		if c.HTTPTemplateServer.ListenPort == "" {
			return fmt.Errorf("http_template_server.listen_port is required when http_template_server.enabled is true")
		}
		if c.HTTPTemplateServer.TLS.Enabled {
			if c.HTTPTemplateServer.TLS.CertFile == "" {
				return fmt.Errorf("http_template_server.tls.cert_file is required when http_template_server.tls.enabled is true")
			}
			if c.HTTPTemplateServer.TLS.KeyFile == "" {
				return fmt.Errorf("http_template_server.tls.key_file is required when http_template_server.tls.enabled is true")
			}
		}
	}

	return nil
}
