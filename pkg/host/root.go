package host

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"text/template"

	"github.com/crowdsecurity/crowdsec-spoa/internal/appsec"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation/ban"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation/captcha"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

const (
	OpAdd    Op = "add"
	OpRemove Op = "remove"
	OpPatch  Op = "patch"
)

type Op string

type HostOp struct {
	Host *Host
	Op   Op
}

type Host struct {
	Host     string          `yaml:"host"`
	Captcha  captcha.Captcha `yaml:"captcha"`
	Ban      ban.Ban         `yaml:"ban"`
	AppSec   appsec.AppSec   `yaml:"appsec"`
	LogLevel *log.Level      `yaml:"log_level"`
	logger   *log.Entry      `yaml:"-"`
}

type Manager struct {
	Hosts  []*Host
	Chan   chan HostOp
	Logger *log.Entry
	cache  map[string]*Host
	sync.RWMutex
}

const t = `
{{ range .Hosts -}}
Host: {{ .Host }}
{{ end -}}
`

func (h *Manager) String() string {
	tmpl, err := template.New("test").Parse(t)
	if err != nil {
		return ""
	}
	var b strings.Builder
	if err := tmpl.Execute(&b, h); err != nil {
		return ""
	}
	return b.String()
}

func NewManager(l *log.Entry) *Manager {
	return &Manager{
		Hosts:  make([]*Host, 0),
		Chan:   make(chan HostOp),
		Logger: l,
		cache:  make(map[string]*Host),
	}
}

func (h *Manager) MatchFirstHost(toMatch string) *Host {
	h.RLock()
	defer h.RUnlock()

	if len(h.Hosts) == 0 {
		return nil
	}

	if host, ok := h.cache[toMatch]; ok {
		host.logger.WithField("requested_host", toMatch).Debug("matched host from cache")
		return host
	}

	for _, host := range h.Hosts {
		matched, err := filepath.Match(host.Host, toMatch)
		if matched && err == nil {
			host.logger.WithField("requested_host", toMatch).Debug("matched host pattern")
			h.cache[toMatch] = host
			return host
		}
	}
	h.Logger.WithField("requested_host", toMatch).Debug("no matching host found")
	return nil
}

func (h *Manager) Run(ctx context.Context) {
	for {
		select {
		case instruction := <-h.Chan:
			h.Lock()
			switch instruction.Op {
			case OpRemove:
				h.cache = make(map[string]*Host)
				h.removeHost(instruction.Host)
			case OpAdd:
				h.cache = make(map[string]*Host)
				h.addHost(ctx, instruction.Host)
				h.sort()
			case OpPatch:
				h.patchHost(instruction.Host)
			}
			h.Unlock()
		case <-ctx.Done():
			return
		}
	}
}

func (h *Manager) LoadFromDirectory(path string) error {
	files, err := filepath.Glob(filepath.Join(path, "*.yaml"))
	if err != nil {
		return err
	}
	for _, file := range files {
		host, err := LoadHostFromFile(file)
		if err != nil {
			return err
		}
		h.Chan <- HostOp{
			Host: host,
			Op:   OpAdd,
		}
	}
	return nil
}

func LoadHostFromFile(path string) (*Host, error) {
	host := &Host{}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Unmarshal the YAML content into the struct
	err = yaml.Unmarshal(content, &host)
	if err != nil {
		return nil, err
	}
	return host, nil
}

func (h *Manager) sort() {
	// If there are less than 2 hosts, no need to sort
	if len(h.Hosts) < 2 {
		return
	}

	// Sort the slice of hosts
	sort.Slice(h.Hosts, func(i, j int) bool {
		// Check for wildcards
		iWildcard := strings.Contains(h.Hosts[i].Host, "*")
		jWildcard := strings.Contains(h.Hosts[j].Host, "*")

		// If both or neither names contain wildcards, sort by length
		if iWildcard == jWildcard {
			return len(h.Hosts[i].Host) > len(h.Hosts[j].Host)
		}

		// If only one name contains a wildcard, it should come later
		return !iWildcard
	})
}

func (h *Manager) removeHost(host *Host) {
	for i, th := range h.Hosts {
		if th == host {
			host.Captcha.Cancel()
			if i == len(h.Hosts)-1 {
				h.Hosts = h.Hosts[:i]
			} else {
				h.Hosts = append(h.Hosts[:i], h.Hosts[i+1:]...)
			}
			return
		}
	}
}

func (h *Manager) patchHost(host *Host) {
	//TODO
}

// createHostLogger creates a logger for a host that inherits from the base logger
// while allowing host-specific overrides like log level
func (h *Manager) createHostLogger(host *Host) *log.Entry {
	// If the host specifies a custom log level, create a new logger instance
	if host.LogLevel != nil {
		// Create a new logger with the host-specific level
		// We need to create a new logger instance to avoid affecting the base logger
		hostLogger := log.NewEntry(h.Logger.Logger)
		hostLogger.Logger.SetLevel(*host.LogLevel)

		// Copy the base logger's fields but exclude "component" since hosts should have their own context
		for k, v := range h.Logger.Data {
			if k != "component" {
				hostLogger = hostLogger.WithField(k, v)
			}
		}

		// Add the host field
		return hostLogger.WithField("host", host.Host)
	}

	// For normal case, create a new logger entry without the "component" field
	hostLogger := log.NewEntry(h.Logger.Logger)

	// Copy the base logger's fields but exclude "component"
	for k, v := range h.Logger.Data {
		if k != "component" {
			hostLogger = hostLogger.WithField(k, v)
		}
	}

	return hostLogger.WithField("host", host.Host)
}

func (h *Manager) addHost(ctx context.Context, host *Host) {
	// Create a logger for this host that inherits base logger values
	host.logger = h.createHostLogger(host)

	// Add additional useful fields for host context
	host.logger = host.logger.WithFields(log.Fields{
		"has_captcha": host.Captcha.Provider != "",
		"has_ban":     true, // Ban is always available
	})

	if err := host.Captcha.Init(host.logger, ctx); err != nil {
		host.logger.Error(err)
	}
	if err := host.Ban.Init(host.logger); err != nil {
		host.logger.Error(err)
	}
	if err := host.AppSec.Init(host.logger, ctx); err != nil {
		host.logger.Error(err)
	}
	h.Hosts = append(h.Hosts, host)
}
