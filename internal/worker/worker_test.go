// worker_test.go
package worker

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec-spoa/pkg/server"
	"github.com/stretchr/testify/assert"
)

// func TestMain implements the helper process trick. When Worker.Run spawns a new process,
// the test binary is re-invoked. In that case we check for the "-worker" flag and exit immediately.
func TestMain(m *testing.M) {
	configFlag := flag.String("config", "", "Configuration JSON")
	workerFlag := flag.Bool("worker", false, "Worker flag")
	flag.Parse()

	if *workerFlag {
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
		case "test-worker-3":
			// Create a channel to receive OS signals.
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

			// Block until a signal is received.
			sig := <-sigChan
			fmt.Printf("Received signal: %s, exiting...\n", sig)
			os.Exit(0)
		}
	}

	os.Exit(m.Run())
}

// TestManagerAddWorkerWithSuccess tests the AddWorker method when NewWorkerListener succeeds.
func TestManagerAddWorkerWithSuccess(t *testing.T) {
	// Create a fake server that returns a dummy socket string.
	s := &server.Server{}

	uid := os.Getuid()
	gid := os.Getgid()

	// Create a Manager with a cancellable context.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr := NewManager(ctx, s, uid, gid)

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
	if w.UID != uid || w.GID != gid {
		t.Errorf("expected worker Uid and Gid to be %d and %d, got %d and %d", uid, gid, w.UID, w.GID)
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

	assert.NotNil(t, w.Command, "expected worker command to be set")
	expectedCommandPrefix := "/tmp/go-build"
	expectedCommandSuffix := fmt.Sprintf(`worker.test -worker -config {"Name":"test-worker-1","Config":"","LogLevel":null,"Uid":%d,"Gid":%d,"Command":null,"SocketPath":""}`, uid, gid)
	commandString := w.Command.String()
	assert.True(t, strings.HasPrefix(commandString, expectedCommandPrefix), "expected worker command to start with %s", expectedCommandPrefix)
	assert.True(t, strings.HasSuffix(commandString, expectedCommandSuffix), "expected worker command to end with %s", expectedCommandSuffix)
	mgr.Stop()

	s.Close()
}

// TestManagerAddWorker_NewWorkerListenerError tests that when NewWorkerListener fails,
// the worker is not added to the Manager.
func TestManagerAddWorkerNewWorkerListenerError(t *testing.T) {
	s := &server.Server{}

	uid := os.Getuid()
	gid := os.Getgid()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr := NewManager(ctx, s, uid, gid)

	w := &Worker{
		Name: "test-worker-2",
	}

	// Call AddWorker. Since the fake server returns an error, AddWorker should return early.
	mgr.AddWorker(w)
	time.Sleep(100 * time.Millisecond)

	// Wait briefly.

	assert.Equal(t, 1, len(mgr.Workers), "expected 1 worker even it failed to start")
	if len(mgr.Workers) == 0 {
		t.Fatalf("expected 1 worker, got %d", len(mgr.Workers))
	}
	assert.NotNil(t, mgr.Workers, "expected worker command to be set")
	assert.Nil(t, w.Command, "expected worker command to be nil")
	assert.Nil(t, mgr.Workers[0].Command, "expected worker command to be nil")

	mgr.Stop()
	s.Close()
	t.Logf("Don't care any consideration of the error")
}

// TestManagerAddWorker_NewWorkerListenerError tests that when NewWorkerListener fails,
// the worker is not added to the Manager.
func TestManagerAddWorkersNewWorkerListenerError(t *testing.T) {
	fmt.Println("TestManagerAddWorkersNewWorkerListenerError")

	uid := os.Getuid()
	gid := os.Getgid()

	s := &server.Server{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr := NewManager(ctx, s, uid, gid)

	w3 := &Worker{
		Name: "test-worker-3",
	}
	mgr.AddWorker(w3)

	w2 := &Worker{
		Name: "test-worker-2",
	}
	// Call AddWorker. Since the fake server returns an error, AddWorker should return early.
	mgr.AddWorker(w2)
	time.Sleep(100 * time.Millisecond)
	fmt.Printf("workers: %v\n", mgr.Workers[0].Command)
	// Wait briefly.
	mgr.Stop()

	assert.Equal(t, 2, len(mgr.Workers), "expected 2 workers due to NewWorkerListener error")
	assert.NotNil(t, mgr.Workers, "expected workers to be set")
	assert.Nil(t, w2.Command, "expected worker command to be nil")
	assert.Nil(t, mgr.Workers[1].Command, "expected worker command to be nil")
	expectedCommandPrefix := "/tmp/go-build"
	expectedCommandSuffix := fmt.Sprintf(`worker.test -worker -config {"Name":"test-worker-3","Config":"","LogLevel":null,"Uid":%d,"Gid":%d,"Command":null,"SocketPath":""}`, uid, gid)
	commandString := w3.Command.String()
	assert.True(t, strings.HasPrefix(commandString, expectedCommandPrefix), "expected worker command to start with %s", expectedCommandPrefix)
	assert.True(t, strings.HasSuffix(commandString, expectedCommandSuffix), "expected worker command to end with %s", expectedCommandSuffix)

	s.Close()

}
