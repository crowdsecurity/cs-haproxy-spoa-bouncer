package server

import (
	"context"
	"encoding/gob"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/crowdsecurity/crowdsec-spoa/internal/api/messages"
	apipermission "github.com/crowdsecurity/crowdsec-spoa/internal/api/perms"
	log "github.com/sirupsen/logrus"
)

var (
	// serverGobTypesRegistered ensures gob types are registered only once on server side
	serverGobTypesRegistered sync.Once
)

// registerServerGobTypes registers types for server-side gob encoding
func registerServerGobTypes() {
	serverGobTypesRegistered.Do(func() {
		// Register all message and response types
		messages.RegisterGobTypes()
	})
}

const (
	WorkerSocketPrefix = "crowdsec-spoa-worker-"
	AdminSocketPrefix  = "crowdsec-spoa-admin-"
)

// Server manages unix socket listeners and their lifecycle
// It contains a context for proper lifecycle management tied to errgroup
//nolint:containedctx // Server owns its lifecycle and manages listener goroutines via errgroup
type Server struct {
	listeners       []*net.Listener             // Listener
	permission      apipermission.APIPermission // Worker or Admin
	logger          *log.Entry                  // Logger
	connChan        chan SocketConn             // Channel to send new connections
	workerSocketDir string                      // Directory for worker sockets
	ctx             context.Context             // Context for lifecycle management
	g               *errgroup.Group             // Error group for listener goroutines
}

type SocketConn struct {
	Conn       net.Conn                    // underlying connection
	Permission apipermission.APIPermission // Permission of the socket admin|worker
	Encoder    *gob.Encoder                // Unique encoder for socket connection
	Decoder    *gob.Decoder                // Unique decoder for socket connection
	WorkerName string                      // Worker name (only set for worker connections)
}

func NewAdminSocket(ctx context.Context, connChan chan SocketConn) (*Server, error) {
	g, ctx := errgroup.WithContext(ctx)

	as := &Server{
		permission: apipermission.AdminPermission,
		logger:     log.New().WithField("server", "admin"),
		connChan:   connChan,
		ctx:        ctx,
		g:          g,
	}

	return as, nil
}

func NewWorkerSocket(ctx context.Context, connChan chan SocketConn, dir string) (*Server, error) {
	g, ctx := errgroup.WithContext(ctx)

	ws := &Server{
		permission:      apipermission.WorkerPermission,
		logger:          log.New().WithField("server", "worker"),
		connChan:        connChan,
		workerSocketDir: dir,
		ctx:             ctx,
		g:               g,
	}

	return ws, nil
}

// extractWorkerNameFromListener extracts worker name from the listener's address
func (s *Server) extractWorkerNameFromListener(l *net.Listener) string {
	if s.permission != apipermission.WorkerPermission {
		return ""
	}

	addr := (*l).Addr()
	if addr == nil {
		return ""
	}

	// Use type assertion to get Unix socket path
	unixAddr, ok := addr.(*net.UnixAddr)
	if !ok {
		return ""
	}

	socketPath := unixAddr.Name

	// Extract filename from path
	filename := filepath.Base(socketPath)

	// Remove prefix and suffix to get worker name
	// Format: crowdsec-spoa-worker-{name}.sock
	if strings.HasPrefix(filename, WorkerSocketPrefix) && strings.HasSuffix(filename, ".sock") {
		workerName := strings.TrimPrefix(filename, WorkerSocketPrefix)
		workerName = strings.TrimSuffix(workerName, ".sock")
		return workerName
	}

	return ""
}

func (s *Server) Run(l *net.Listener) error {
	// Register gob types before creating encoder
	registerServerGobTypes()

	// Extract worker name for worker connections
	workerName := s.extractWorkerNameFromListener(l)

	// Close listener when context is canceled
	go func() {
		<-s.ctx.Done()
		(*l).Close()
	}()

	for {
		conn, err := (*l).Accept()
		if err != nil {
			// Check if error is due to context cancellation
			if s.ctx.Err() != nil {
				return s.ctx.Err()
			}
			return err
		}

		s.connChan <- SocketConn{
			Conn:       conn,
			Permission: s.permission,
			Encoder:    gob.NewEncoder(conn),
			Decoder:    gob.NewDecoder(conn),
			WorkerName: workerName,
		}
	}
}

func (s *Server) NewAdminListener(path string) error {
	l, err := newUnixSocket(path)

	if err != nil {
		return err
	}

	if err := configAdminSocket(path); err != nil {
		return err
	}

	s.listeners = append(s.listeners, &l)

	// Launch listener in errgroup
	s.g.Go(func() error {
		return s.Run(&l)
	})

	return nil
}

func (s *Server) NewWorkerListener(name string, gid int) (string, error) {
	socketString := fmt.Sprintf("%s%s%s.sock", s.workerSocketDir, WorkerSocketPrefix, name)

	l, err := newUnixSocket(socketString)

	if err != nil {
		return "", err
	}

	if err := configWorkerSocket(socketString, gid); err != nil {
		return "", err
	}

	s.listeners = append(s.listeners, &l)

	// Launch listener in errgroup
	s.g.Go(func() error {
		return s.Run(&l)
	})

	return socketString, nil
}

func newUnixSocket(path string) (net.Listener, error) {
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	return l, nil
}

func configWorkerSocket(path string, gid int) error {
	if err := os.Chown(path, os.Getuid(), gid); err != nil {
		return err
	}

	if err := os.Chmod(path, 0o660); err != nil {
		return err
	}

	return nil
}

func configAdminSocket(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	return nil
}

// Wait waits for all listener goroutines to finish
// When the context is canceled, all listeners will be closed and this will return
func (s *Server) Wait() error {
	return s.g.Wait()
}
