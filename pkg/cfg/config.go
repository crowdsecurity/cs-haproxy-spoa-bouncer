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

type BouncerConfig struct {
	Logging          cslogging.LoggingConfig `yaml:",inline"`
	Hosts            []*host.Host            `yaml:"hosts"`
	HostsDir         string                  `yaml:"hosts_dir"`
	Geo              geo.GeoDatabase         `yaml:",inline"`
	ListenTCP        string                  `yaml:"listen_tcp"`
	ListenUnix       string                  `yaml:"listen_unix"`
	PrometheusConfig PrometheusConfig        `yaml:"prometheus"`
	AdminSocket      string                  `yaml:"admin_socket"`
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

	return config, nil
}
