package host

import (
	"context"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/crowdsecurity/crowdsec-spoa/internal/appsec"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation/ban"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation/captcha"
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

type Manager struct {
	Hosts      []*Host `yaml:"-"`
	ctx        context.Context
	CreateChan chan *Host
	cache      map[string]*Host
	sync.RWMutex
}

func NewManager(ctx context.Context) *Manager {
	return &Manager{
		ctx:        ctx,
		Hosts:      make([]*Host, 0),
		CreateChan: make(chan *Host),
		cache:      make(map[string]*Host),
	}
}

func (h *Manager) MatchFirstHost(toMatch string) *Host {
	h.RLock()
	defer h.RUnlock()

	if host, ok := h.cache[toMatch]; ok {
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
		case host := <-h.CreateChan:
			h.Lock()
			h.cache = make(map[string]*Host) //reset cache before adding new host
			h.AddHost(host)
			h.Sort()
			h.Unlock()
		case <-h.ctx.Done():
			return
		}
	}
}

func (h *Manager) Sort() {
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

func (hM *Manager) RemoveHost(host *Host) {
	hM.Lock()
	defer hM.Unlock()

	for i, h := range hM.Hosts {
		if h == host {
			if i == len(hM.Hosts)-1 {
				hM.Hosts = hM.Hosts[:i]
			} else {
				hM.Hosts = append(hM.Hosts[:i], hM.Hosts[i+1:]...)
			}
			return
		}
	}
}

func (h *Manager) AddHost(host *Host) {
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
	if err := host.AppSec.Init(host.logger, h.ctx); err != nil {
		host.logger.Error(err)
	}
	h.Hosts = append(h.Hosts, host)
}
