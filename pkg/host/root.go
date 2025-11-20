package host

import (
	"context"
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

type Manager struct {
	Hosts    []*Host
	Logger   *log.Entry
	cache    map[string]*Host
	hostsDir string
	ctx      context.Context // Base service context for goroutines (not reload context)
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

// SetContext sets the base service context for host goroutines (captcha, appsec).
// This should be called once during initialization with the main service context.
func (h *Manager) SetContext(ctx context.Context) {
	h.ctx = ctx
}

// SetHosts sets hosts from both config and directory, merging them (config takes precedence).
func (h *Manager) SetHosts(configHosts []*Host, hostsDir string) error {
	allHosts := make(map[string]*Host)

	// First, load from directory if provided
	if hostsDir != "" {
		h.hostsDir = hostsDir
		files, err := filepath.Glob(filepath.Join(hostsDir, "*.yaml"))
		if err != nil {
			return err
		}
		for _, file := range files {
			host, err := LoadHostFromFile(file)
			if err != nil {
				return err
			}
			allHosts[host.Host] = host
		}
	}

	// Then, add config hosts (they override directory hosts)
	for _, host := range configHosts {
		allHosts[host.Host] = host
	}

	// Convert to slice
	hostsSlice := make([]*Host, 0, len(allHosts))
	for _, host := range allHosts {
		hostsSlice = append(hostsSlice, host)
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
// Note: Uses the base service context (set via SetContext), not a reload-specific context.
func (h *Manager) Reload(configHosts []*Host) error {
	h.Logger.Info("Reloading host configuration")

	// Build desired state: config hosts + directory hosts (config takes precedence)
	desiredHosts := make(map[string]*Host)

	// First, add directory hosts
	if h.hostsDir != "" {
		files, err := filepath.Glob(filepath.Join(h.hostsDir, "*.yaml"))
		if err != nil {
			return fmt.Errorf("failed to glob host files: %w", err)
		}
		for _, file := range files {
			host, err := LoadHostFromFile(file)
			if err != nil {
				h.Logger.WithError(err).WithField("file", file).Error("Failed to load host file during reload")
				continue
			}
			desiredHosts[host.Host] = host
		}
	}

	// Then, add config hosts (they override directory hosts)
	for _, host := range configHosts {
		desiredHosts[host.Host] = host
	}

	// Convert map to slice
	desiredHostsSlice := make([]*Host, 0, len(desiredHosts))
	for _, host := range desiredHosts {
		desiredHostsSlice = append(desiredHostsSlice, host)
	}

	// Replace hosts directly with locking
	h.Logger.WithField("host_count", len(desiredHostsSlice)).Info("Replacing hosts")
	h.Lock()
	h.cache = make(map[string]*Host)
	h.replaceHosts(desiredHostsSlice)
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
// Uses the base service context (h.ctx) so goroutines are tied to service lifecycle, not reload.
// Preserves existing Host objects when host string matches to maintain sessions/state.
func (h *Manager) replaceHosts(newHosts []*Host) {
	// Build map of existing hosts by host string
	existingHosts := make(map[string]*Host)
	for _, host := range h.Hosts {
		existingHosts[host.Host] = host
	}

	// Build map of new hosts by host string
	newHostsMap := make(map[string]*Host)
	for _, host := range newHosts {
		newHostsMap[host.Host] = host
	}

	// Remove hosts that are no longer needed
	// Note: Sessions persist in global manager, so no cleanup needed
	for hostStr := range existingHosts {
		if _, exists := newHostsMap[hostStr]; !exists {
			// Host removed - sessions will be garbage collected by global session manager
		}
	}

	// Process new hosts - update existing or create new
	finalHosts := make([]*Host, 0, len(newHosts))
	for _, newHost := range newHosts {
		if existingHost, exists := existingHosts[newHost.Host]; exists {
			// Host already exists - preserve it completely to maintain sessions/state
			// Configuration changes require a service restart to take effect
			// This ensures active captcha sessions are not lost during reload
			finalHosts = append(finalHosts, existingHost)
		} else {
			// New host - initialize it
			newHost.logger = h.createHostLogger(newHost)
			newHost.logger = newHost.logger.WithFields(log.Fields{
				"has_captcha": newHost.Captcha.Provider != "",
				"has_ban":     true,
			})

			if err := newHost.Captcha.Init(newHost.logger); err != nil {
				newHost.logger.Error(err)
			}
			if err := newHost.Ban.Init(newHost.logger); err != nil {
				newHost.logger.Error(err)
			}
			if err := newHost.AppSec.Init(newHost.logger); err != nil {
				newHost.logger.Error(err)
			}
			finalHosts = append(finalHosts, newHost)
		}
	}

	// Replace the entire slice
	h.Hosts = finalHosts
	h.sort()
}
