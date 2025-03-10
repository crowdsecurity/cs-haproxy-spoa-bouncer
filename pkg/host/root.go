package host

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"text/template"

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
	LogLevel *log.Level      `yaml:"log_level"`
	logger   *log.Entry      `yaml:"-"`
}

type Manager struct {
	Hosts []*Host
	ctx   context.Context
	Chan  chan HostOp
	cache map[string]*Host
	sync.RWMutex
}

const t = `
{{ range .Hosts -}}
Host: {{ .Host }}
{{ end -}}
`

func (m *Manager) String() string {
	tmpl, err := template.New("test").Parse(t)
	if err != nil {
		return ""
	}
	var b strings.Builder
	if err := tmpl.Execute(&b, m); err != nil {
		return ""
	}
	return b.String()
}

func NewManager(ctx context.Context) *Manager {
	return &Manager{
		ctx:   ctx,
		Hosts: make([]*Host, 0),
		Chan:  make(chan HostOp),
		cache: make(map[string]*Host),
	}
}

func (h *Manager) MatchFirstHost(toMatch string) *Host {
	h.RLock()
	defer h.RUnlock()

	if host, ok := h.cache[toMatch]; ok {
		host.logger.WithField("value", toMatch).Debug("matched host from cache")
		return host
	}

	for _, host := range h.Hosts {
		matched, err := filepath.Match(host.Host, toMatch)
		if matched && err == nil {
			host.logger.WithField("value", toMatch).Debug("matched host")
			h.cache[toMatch] = host
			return host
		}
	}
	return nil
}

func (h *Manager) Run() {
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
				h.addHost(instruction.Host)
				h.sort()
			case OpPatch:
				h.patchHost(instruction.Host)
			}
			h.Unlock()
		case <-h.ctx.Done():
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

func (hM *Manager) removeHost(host *Host) {
	for i, h := range hM.Hosts {
		if h == host {
			host.Captcha.Cancel()
			if i == len(hM.Hosts)-1 {
				hM.Hosts = hM.Hosts[:i]
			} else {
				hM.Hosts = append(hM.Hosts[:i], hM.Hosts[i+1:]...)
			}
			return
		}
	}
}

func (h *Manager) patchHost(host *Host) {
	//TODO
}

func (h *Manager) addHost(host *Host) {
	clog := log.New()

	if host.LogLevel != nil {
		clog.SetLevel(*host.LogLevel)
	}

	host.logger = clog.WithField("host", host.Host)

	if err := host.Captcha.Init(host.logger, h.ctx); err != nil {
		host.logger.Error(err)
	}
	if err := host.Ban.Init(host.logger); err != nil {
		host.logger.Error(err)
	}
	h.Hosts = append(h.Hosts, host)
}
