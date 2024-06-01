package cfg

import (
	"fmt"
	"io"
	"os/user"
	"strconv"
	"strings"

	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec-spoa/internal/geo"
	"github.com/crowdsecurity/crowdsec-spoa/internal/worker"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/host"
	cslogging "github.com/crowdsecurity/crowdsec-spoa/pkg/logging"
	"github.com/crowdsecurity/go-cs-lib/yamlpatch"
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
	Workers          []*worker.Worker        `yaml:"workers"`
	WorkerUser       string                  `yaml:"worker_user"`
	WorkerGroup      string                  `yaml:"worker_group"`
	PrometheusConfig PrometheusConfig        `yaml:"prometheus"`
	AdminSocket      string                  `yaml:"admin_socket"`
	WorkerSocketDir  string                  `yaml:"worker_socket"`
	WorkerUid        int                     `yaml:"-"`
	WorkerGid        int                     `yaml:"-"`
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

	if err = config.Logging.Setup("crowdsec-spoa-bouncer.log"); err != nil {
		return nil, fmt.Errorf("failed to setup logging: %w", err)
	}

	u, err := user.Lookup(config.WorkerUser)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup user %s: %w", config.WorkerUser, err)
	}

	config.WorkerUid, err = strconv.Atoi(u.Uid)
	if err != nil {
		return nil, fmt.Errorf("failed to convert uid %s: %w", u.Uid, err)
	}

	g, err := user.LookupGroup(config.WorkerGroup)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup group %s: %w", config.WorkerGroup, err)
	}

	config.WorkerGid, err = strconv.Atoi(g.Gid)
	if err != nil {
		return nil, fmt.Errorf("failed to convert gid %s: %w", g.Gid, err)
	}

	for _, w := range config.Workers {
		w.Gid = config.WorkerGid
		w.Uid = config.WorkerUid
	}

	if config.WorkerSocketDir == "" {
		config.WorkerSocketDir = "/run/"
	}

	if !strings.HasSuffix(config.WorkerSocketDir, "/") {
		config.WorkerSocketDir = config.WorkerSocketDir + "/"
	}

	return config, nil
}
