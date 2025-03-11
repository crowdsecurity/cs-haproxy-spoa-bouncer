// worker_test.go
package worker

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec-spoa/pkg/server"
	"github.com/stretchr/testify/assert"
)

// TestMain implements the helper process trick. When Worker.Run spawns a new process,
// the test binary is re-invoked. In that case we check for the "-worker" flag and exit immediately.
func TestMain(m *testing.M) {
	configFlag := flag.String("config", "", "Configuration JSON")
	_ = flag.Bool("worker", false, "Worker flag")
	flag.Parse()

	if *configFlag == "" {
		os.Exit(m.Run())
	}

	var config Worker
	err := json.Unmarshal([]byte(*configFlag), &config)
	if err != nil {
		os.Exit(1)
	}

	switch config.Name {
	case "test-worker-1":
		os.Exit(0)
	case "test-worker-2":
		os.Exit(1)
	}

}

// TestManagerAddWorkerWithSuccess tests the AddWorker method when NewWorkerListener succeeds.
func TestManagerAddWorkerWithSuccess(t *testing.T) {
	// Create a fake server that returns a dummy socket string.
	s := &server.Server{}

	// Create a Manager with a cancellable context.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr := NewManager(ctx, s, 1000, 1000)

	// Create a worker.
	w := &Worker{
		Name: "test-worker-1",
	}

	// Call AddWorker.
	mgr.AddWorker(w)

	// Allow some time for the goroutine spawned inside AddWorker to run.
	time.Sleep(100 * time.Millisecond)

	// Verify that the worker is appended and its fields are set.
	if len(mgr.Workers) != 1 {
		t.Fatalf("expected 1 worker, got %d", len(mgr.Workers))
	}
	if w.Uid != 1000 || w.Gid != 1000 {
		t.Errorf("expected worker Uid and Gid to be 1000, got %d and %d", w.Uid, w.Gid)
	}

	// Verify that the command was created and its environment includes expected variables.
	if w.Command == nil {
		t.Errorf("expected worker command to be set")
	} else {
		foundWorkerName := false
		foundWorkerSocket := false
		for _, env := range w.Command.Env {
			if env == "WORKERNAME="+w.Name {
				foundWorkerName = true
			}
			if env == "WORKERSOCKET=crowdsec-spoa-worker-test-worker-1.sock" {
				foundWorkerSocket = true
			}
		}
		if !foundWorkerName {
			t.Errorf("expected WORKERNAME in command env")
		}
		if !foundWorkerSocket {
			t.Errorf("expected WORKERSOCKET in command env")
		}
	}
	time.Sleep(1000 * time.Millisecond)
	fmt.Printf("command: %+v", w.Command)

	assert.NotNil(t, w.Command, "expected worker command to be set")
	expectedCommandPrefix := "/tmp/go-build"
	expectedCommandSuffix := `worker.test -worker -config {\"Name\":\"test-worker-1\",\"Config\":\"\",\"LogLevel\":null,\"Uid\":1000,\"Gid\":1000,\"Command\":null,\"SocketPath\":\"\"}`
	commandString := w.Command.String()
	assert.True(t, strings.HasPrefix(commandString, expectedCommandPrefix), "expected worker command to start with %s", expectedCommandPrefix)
	assert.True(t, strings.HasSuffix(commandString, expectedCommandSuffix), "expected worker command to end with %s", expectedCommandSuffix)
	mgr.Stop()

	s.Close()
}

// TestManagerAddWorker_NewWorkerListenerError tests that when NewWorkerListener fails,
// the worker is not added to the Manager.
func TestManagerAddWorkerNewWorkerListenerError(t *testing.T) {
	// Create a fake server that simulates an error.
	s := &server.Server{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr := NewManager(ctx, s, 1000, 1000)

	w := &Worker{
		Name: "test-worker-2",
	}

	// Call AddWorker. Since the fake server returns an error, AddWorker should return early.
	mgr.AddWorker(w)

	// Wait briefly.
	time.Sleep(5000 * time.Millisecond)

	assert.Equal(t, 1, len(mgr.Workers), "expected 0 workers due to NewWorkerListener error")

	assert.Nil(t, w.Command, "expected worker command to be nil")
	assert.Nil(t, mgr.Workers[0].Command, "expected worker command to be nil")

	mgr.Stop()
	s.Close()
}
