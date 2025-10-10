package worker

import (
	"context"
	"fmt"
	"time"

	"github.com/crowdsecurity/crowdsec-spoa/internal/geo"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/dataset"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/host"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/spoa"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

// WorkerConfig holds configuration for a single SPOA worker
type WorkerConfig struct {
	Name     string     `yaml:"name" json:"name"`
	LogLevel *log.Level `yaml:"log_level" json:"log_level"`
	TcpAddr  string     `yaml:"listen_addr" json:"listen_addr"`
	UnixAddr string     `yaml:"listen_socket" json:"listen_socket"`
}

// Manager manages goroutine-based SPOA workers
type Manager struct {
	workers     []*spoa.Spoa
	dataset     *dataset.DataSet
	hostManager *host.Manager
	geoDatabase *geo.GeoDatabase
	logger      *log.Entry
	g           *errgroup.Group
	gCtx        context.Context //nolint:containedctx // Context from errgroup.WithContext, needed for worker goroutines
}

// NewManager creates a new worker manager
func NewManager(ctx context.Context, dataset *dataset.DataSet, hostManager *host.Manager, geoDatabase *geo.GeoDatabase, logger *log.Entry) *Manager {
	g, gCtx := errgroup.WithContext(ctx)

	return &Manager{
		workers:     make([]*spoa.Spoa, 0),
		dataset:     dataset,
		hostManager: hostManager,
		geoDatabase: geoDatabase,
		logger:      logger,
		g:           g,
		gCtx:        gCtx,
	}
}

// AddWorker adds a new SPOA worker goroutine
func (m *Manager) AddWorker(config WorkerConfig) error {
	spoaConfig := &spoa.SpoaConfig{
		TcpAddr:     config.TcpAddr,
		UnixAddr:    config.UnixAddr,
		Name:        config.Name,
		LogLevel:    config.LogLevel,
		Dataset:     m.dataset,
		HostManager: m.hostManager,
		GeoDatabase: m.geoDatabase,
		Logger:      m.logger, // Pass manager's logger to worker
	}

	worker, err := spoa.New(spoaConfig)
	if err != nil {
		return fmt.Errorf("failed to create SPOA worker %s: %w", config.Name, err)
	}

	m.workers = append(m.workers, worker)

	// Launch TCP server in goroutine
	if config.TcpAddr != "" {
		m.g.Go(func() error {
			log.Infof("Starting SPOA worker %s on TCP %s", config.Name, config.TcpAddr)
			if err := worker.ServeTCP(m.gCtx); err != nil {
				return fmt.Errorf("worker %s TCP server failed: %w", config.Name, err)
			}
			return nil
		})
	}

	// Launch Unix server in goroutine
	if config.UnixAddr != "" {
		m.g.Go(func() error {
			log.Infof("Starting SPOA worker %s on Unix socket %s", config.Name, config.UnixAddr)
			if err := worker.ServeUnix(m.gCtx); err != nil {
				return fmt.Errorf("worker %s Unix server failed: %w", config.Name, err)
			}
			return nil
		})
	}

	return nil
}

// Wait waits for all workers to finish
func (m *Manager) Wait() error {
	return m.g.Wait()
}

// Stop stops all workers
func (m *Manager) Stop() error {
	// Context cancellation will stop all workers
	// Individual workers handle graceful shutdown via their Shutdown methods
	log.Info("Stopping all SPOA workers")

	for _, worker := range m.workers {
		func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			if err := worker.Shutdown(shutdownCtx); err != nil {
				log.Errorf("Failed to shutdown worker: %v", err)
			}
		}()
	}

	return nil
}
