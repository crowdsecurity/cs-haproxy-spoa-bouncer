package worker

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec-spoa/internal/geo"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/dataset"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/host"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// getFreePort returns a free TCP port for testing
func getFreePort(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	addr := listener.Addr().(*net.TCPAddr)
	return fmt.Sprintf("127.0.0.1:%d", addr.Port)
}

func TestNewManager(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ds := dataset.New()
	hm := host.NewManager(log.WithField("test", "manager"))
	gdb := &geo.GeoDatabase{}
	logger := log.WithField("component", "worker")

	manager := NewManager(ctx, ds, hm, gdb, logger)

	assert.NotNil(t, manager, "manager should not be nil")
	assert.NotNil(t, manager.dataset, "dataset should be set")
	assert.NotNil(t, manager.hostManager, "hostManager should be set")
	assert.NotNil(t, manager.geoDatabase, "geoDatabase should be set")
	assert.NotNil(t, manager.logger, "logger should be set")
	assert.NotNil(t, manager.workers, "workers slice should be initialized")
	assert.Empty(t, manager.workers, "workers slice should be empty initially")
}

func TestAddWorker(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ds := dataset.New()
	hm := host.NewManager(log.WithField("test", "manager"))
	gdb := &geo.GeoDatabase{}
	logger := log.WithField("component", "worker")

	manager := NewManager(ctx, ds, hm, gdb, logger)

	// Create a worker config with TCP listener
	config := WorkerConfig{
		Name:     "test-worker-1",
		TcpAddr:  getFreePort(t),
		UnixAddr: "",
	}

	err := manager.AddWorker(config)
	require.NoError(t, err, "adding worker should not return error")

	// Give worker goroutine time to start
	time.Sleep(100 * time.Millisecond)

	assert.Len(t, manager.workers, 1, "should have 1 worker")
	assert.Equal(t, "test-worker-1", config.Name, "worker name should match")

	// Cancel context to stop workers
	cancel()

	// Wait for workers to finish (context cancellation causes workers to return nil)
	_ = manager.Wait()
}

func TestAddMultipleWorkers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ds := dataset.New()
	hm := host.NewManager(log.WithField("test", "manager"))
	gdb := &geo.GeoDatabase{}
	logger := log.WithField("component", "worker")

	manager := NewManager(ctx, ds, hm, gdb, logger)

	// Add multiple workers
	configs := []WorkerConfig{
		{
			Name:     "worker-1",
			TcpAddr:  getFreePort(t),
			UnixAddr: "",
		},
		{
			Name:     "worker-2",
			TcpAddr:  getFreePort(t),
			UnixAddr: "",
		},
	}

	for _, config := range configs {
		err := manager.AddWorker(config)
		require.NoError(t, err, "adding worker should not return error")
	}

	// Give workers time to start
	time.Sleep(100 * time.Millisecond)

	assert.Len(t, manager.workers, 2, "should have 2 workers")

	// Cancel context to stop workers
	cancel()

	// Wait for workers to finish
	_ = manager.Wait()
}

func TestAddWorkerWithUnixSocket(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tmpDir := t.TempDir()

	ds := dataset.New()
	hm := host.NewManager(log.WithField("test", "manager"))
	gdb := &geo.GeoDatabase{}
	logger := log.WithField("component", "worker")

	manager := NewManager(ctx, ds, hm, gdb, logger)

	config := WorkerConfig{
		Name:     "unix-worker",
		TcpAddr:  "",
		UnixAddr: tmpDir + "/test.sock",
	}

	err := manager.AddWorker(config)
	require.NoError(t, err, "adding worker with unix socket should not return error")

	// Give worker time to start
	time.Sleep(100 * time.Millisecond)

	assert.Len(t, manager.workers, 1, "should have 1 worker")

	// Cancel context to stop workers
	cancel()

	// Wait for workers to finish
	_ = manager.Wait()
}

func TestManagerStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ds := dataset.New()
	hm := host.NewManager(log.WithField("test", "manager"))
	gdb := &geo.GeoDatabase{}
	logger := log.WithField("component", "worker")

	manager := NewManager(ctx, ds, hm, gdb, logger)

	config := WorkerConfig{
		Name:     "stoppable-worker",
		TcpAddr:  getFreePort(t),
		UnixAddr: "",
	}

	err := manager.AddWorker(config)
	require.NoError(t, err, "adding worker should not return error")

	// Give worker time to start
	time.Sleep(100 * time.Millisecond)

	// Stop manager
	err = manager.Stop()
	require.NoError(t, err, "stopping manager should not return error")

	// Cancel context
	cancel()

	// Wait for completion
	_ = manager.Wait()
}

func TestWorkerWithLogLevel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ds := dataset.New()
	hm := host.NewManager(log.WithField("test", "manager"))
	gdb := &geo.GeoDatabase{}
	logger := log.WithField("component", "worker")

	manager := NewManager(ctx, ds, hm, gdb, logger)

	debugLevel := log.DebugLevel
	config := WorkerConfig{
		Name:     "debug-worker",
		TcpAddr:  getFreePort(t),
		UnixAddr: "",
		LogLevel: &debugLevel,
	}

	err := manager.AddWorker(config)
	require.NoError(t, err, "adding worker with log level should not return error")

	// Give worker time to start
	time.Sleep(100 * time.Millisecond)

	assert.Len(t, manager.workers, 1, "should have 1 worker")

	// Cancel context to stop workers
	cancel()

	// Wait for workers to finish
	_ = manager.Wait()
}
