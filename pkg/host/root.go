package host

import (
	"fmt"
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

type Host struct {
	Host     string          `yaml:"host"`
	Captcha  captcha.Captcha `yaml:"captcha"`
	Ban      ban.Ban         `yaml:"ban"`
	AppSec   appsec.AppSec   `yaml:"appsec"`
	LogLevel *log.Level      `yaml:"log_level"`
	logger   *log.Entry      `yaml:"-"`
}

// InitComponents initializes all components (captcha, ban, appsec) for the host.
// This should be called after the host logger has been set.
func (h *Host) InitComponents() {
	if err := h.Captcha.Init(h.logger); err != nil {
		h.logger.Error(err)
	}
	if err := h.Ban.Init(h.logger); err != nil {
		h.logger.Error(err)
	}
	if err := h.AppSec.Init(h.logger); err != nil {
		h.logger.Error(err)
	}
}

type Manager struct {
	Hosts    []*Host
	Logger   *log.Entry
	cache    map[string]*Host
	hostsDir string
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
		Logger: l,
		cache:  make(map[string]*Host),
	}
}

func (h *Manager) MatchFirstHost(toMatch string) *Host {
	h.RLock()
	// Fast path: check cache first
	if host, ok := h.cache[toMatch]; ok {
		h.RUnlock()
		host.logger.WithField("requested_host", toMatch).Debug("matched host from cache")
		return host
	}

	// Check if we have any hosts
	if len(h.Hosts) == 0 {
		h.RUnlock()
		h.Logger.WithField("requested_host", toMatch).Debug("no matching host found")
		return nil
	}

	// Search for matching host
	var matchedHost *Host
	for _, host := range h.Hosts {
		matched, err := filepath.Match(host.Host, toMatch)
		if matched && err == nil {
			matchedHost = host
			break
		}
	}
	h.RUnlock()

	if matchedHost == nil {
		h.Logger.WithField("requested_host", toMatch).Debug("no matching host found")
		return nil
	}

	// Cache the result (need write lock for this)
	h.Lock()
	h.cache[toMatch] = matchedHost
	h.Unlock()

	matchedHost.logger.WithField("requested_host", toMatch).Debug("matched host pattern")
	return matchedHost
}

// loadHostsFromSources loads hosts from both directory and config, merging them.
// Config hosts take precedence over directory hosts.
// Returns a slice of hosts and an error if directory loading fails (config errors are ignored during reload).
func (h *Manager) loadHostsFromSources(configHosts []*Host, hostsDir string, continueOnError bool) ([]*Host, error) {
	allHosts := make(map[string]*Host)

	// First, load from directory if provided
	if hostsDir != "" {
		// Store hostsDir for future reloads
		h.hostsDir = hostsDir
		files, err := filepath.Glob(filepath.Join(hostsDir, "*.yaml"))
		if err != nil {
			return nil, fmt.Errorf("failed to glob host files: %w", err)
		}
		for _, file := range files {
			host, err := LoadHostFromFile(file)
			if err != nil {
				if continueOnError {
					h.Logger.WithError(err).WithField("file", file).Error("Failed to load host file")
					continue
				}
				return nil, err
			}
			allHosts[host.Host] = host
		}
	}

	// Then, add config hosts (they override directory hosts)
	for _, host := range configHosts {
		allHosts[host.Host] = host
	}

	// Convert map to slice
	hostsSlice := make([]*Host, 0, len(allHosts))
	for _, host := range allHosts {
		hostsSlice = append(hostsSlice, host)
	}

	return hostsSlice, nil
}

// SetHosts sets hosts from both config and directory, merging them (config takes precedence).
func (h *Manager) SetHosts(configHosts []*Host, hostsDir string) error {
	hostsSlice, err := h.loadHostsFromSources(configHosts, hostsDir, false)
	if err != nil {
		return err
	}

	// Replace hosts directly with locking
	h.Lock()
	h.cache = make(map[string]*Host)
	h.replaceHosts(hostsSlice)
	h.Unlock()

	return nil
}

// Reload reloads hosts from the configured hosts directory and/or main config file.
// It builds the desired state from both sources (config takes precedence) and syncs to it.
// Uses bulk replace for efficiency when there are many hosts.
// Errors loading individual files are logged but don't stop the reload.
func (h *Manager) Reload(configHosts []*Host) error {
	h.Logger.Info("Reloading host configuration")

	// Load hosts from both sources (continue on error for individual files during reload)
	hostsSlice, err := h.loadHostsFromSources(configHosts, h.hostsDir, true)
	if err != nil {
		return err
	}

	// Replace hosts directly with locking
	h.Logger.WithField("host_count", len(hostsSlice)).Info("Replacing hosts")
	h.Lock()
	h.cache = make(map[string]*Host)
	h.replaceHosts(hostsSlice)
	h.Unlock()

	h.Logger.Info("Host reload completed")
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

// replaceHosts replaces the entire host list with a new set of hosts.
// This is used for bulk updates to avoid many individual add/remove operations.
// Sessions are managed globally and persist independently of host objects.
func (h *Manager) replaceHosts(newHosts []*Host) {
	// Initialize all new hosts
	for _, host := range newHosts {
		host.logger = h.createHostLogger(host)
		host.logger = host.logger.WithFields(log.Fields{
			"has_captcha": host.Captcha.Provider != "",
			"has_ban":     true,
		})

		// Initialize all components
		host.InitComponents()
	}

	// Replace the entire slice
	h.Hosts = newHosts
	h.sort()
}
