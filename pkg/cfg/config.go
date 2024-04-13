package cfg

import (
	"fmt"
	"io"

	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/go-cs-lib/yamlpatch"
)

type PrometheusConfig struct {
	Enabled       bool   `yaml:"enabled"`
	ListenAddress string `yaml:"listen_addr"`
	ListenPort    string `yaml:"listen_port"`
}

type BouncerConfig struct {
	Logging      LoggingConfig `yaml:",inline"`
	ListenAddr   string        `yaml:"listen_addr"`
	ListenSocket string        `yaml:"listen_socket"`

	PrometheusConfig PrometheusConfig `yaml:"prometheus"`
}

// MergedConfig() returns the byte content of the patched configuration file (with .yaml.local).
func MergedConfig(configPath string) ([]byte, error) {
	patcher := yamlpatch.NewPatcher(configPath, ".local")

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

	if err = config.Logging.setup("crowdsec-spoa-bouncer.log"); err != nil {
		return nil, fmt.Errorf("failed to setup logging: %w", err)
	}

	if config.ListenAddr == "" && config.ListenSocket == "" {
		return nil, fmt.Errorf("listen_addr or listen_socket must be set")
	}

	return config, nil
}
