package admin

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/coreos/go-systemd/v22/activation"
	"golang.org/x/sync/errgroup"

	"github.com/crowdsecurity/crowdsec-spoa/internal/geo"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/dataset"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/host"
	log "github.com/sirupsen/logrus"
)

// Server manages admin socket and handles admin commands
type Server struct {
	listener    net.Listener
	hostManager *host.Manager
	dataset     *dataset.DataSet
	geoDatabase *geo.GeoDatabase
	logger      *log.Entry
	ctx         context.Context //nolint:containedctx // Context from errgroup.WithContext, needed for command handlers
	g           *errgroup.Group
}

type Config struct {
	SocketPath  string // Config path (optional if systemd)
	HostManager *host.Manager
	Dataset     *dataset.DataSet
	GeoDatabase *geo.GeoDatabase
}

func NewServer(ctx context.Context, cfg Config) (*Server, error) {
	g, ctx := errgroup.WithContext(ctx)

	s := &Server{
		hostManager: cfg.HostManager,
		dataset:     cfg.Dataset,
		geoDatabase: cfg.GeoDatabase,
		logger:      log.New().WithField("server", "admin"),
		ctx:         ctx,
		g:           g,
	}

	// Setup listeners (systemd or manual)
	if err := s.setupListeners(cfg.SocketPath); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *Server) setupListeners(configPath string) error {
	// Detect if we're running under systemd
	isSystemd := os.Getenv("LISTEN_FDS") != "" || os.Getenv("NOTIFY_SOCKET") != ""

	// Try systemd socket activation first
	listeners, err := activation.Listeners()
	if err != nil {
		log.Debugf("Failed to get systemd listeners: %v", err)
	} else if len(listeners) > 0 {
		// Use the first systemd-provided socket (admin socket)
		log.Infof("Using systemd socket activation for admin socket")
		s.listener = listeners[0]
		return nil
	}

	// If running under systemd but no socket activation, do NOT fallback
	// This prevents security downgrade (root socket -> user socket)
	if isSystemd && configPath != "" {
		log.Warn("Running under systemd with admin_socket configured, but no socket activation detected")
		log.Warn("Enable the admin socket unit: systemctl enable crowdsec-spoa-bouncer-admin.socket")
		log.Warn("Skipping admin socket to prevent security downgrade (would create as crowdsec-spoa instead of root)")
		return nil
	}

	// If no systemd and no path configured, skip admin socket
	if configPath == "" {
		log.Debug("No admin socket configured, skipping")
		return nil
	}

	// Only create manual socket if NOT running under systemd (e.g., Docker, standalone)
	log.Infof("Creating admin socket at %s (non-systemd environment)", configPath)
	l, err := s.createUnixSocket(configPath)
	if err != nil {
		return err
	}

	// Set permissions to 0600 (owner read/write only)
	if err := os.Chmod(configPath, 0o600); err != nil {
		return err
	}

	s.listener = l
	return nil
}

func (s *Server) createUnixSocket(path string) (net.Listener, error) {
	// Remove stale socket file if it exists
	if _, err := os.Stat(path); err == nil {
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("failed to remove stale socket file %s: %w", path, err)
		}
	}

	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	return l, nil
}

// HasListeners returns true if the server has an active listener
func (s *Server) HasListeners() bool {
	return s.listener != nil
}

// Run starts the admin server
func (s *Server) Run() error {
	if s.listener == nil {
		log.Debug("No admin socket listener, skipping admin server")
		return nil
	}

	s.g.Go(func() error {
		return s.acceptConnections(s.listener)
	})

	return s.g.Wait()
}

func (s *Server) acceptConnections(l net.Listener) error {
	// Close listener when context is canceled
	go func() {
		<-s.ctx.Done()
		l.Close()
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			// Check if error is due to context cancellation
			if s.ctx.Err() != nil {
				return s.ctx.Err()
			}
			return err
		}

		// Handle connection with SO_PEERCRED check
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	// SO_PEERCRED check for Unix sockets - only allow root (UID 0)
	if unixConn, ok := conn.(*net.UnixConn); ok {
		f, err := unixConn.File()
		if err != nil {
			log.Errorf("Failed to get file descriptor: %v", err)
			return
		}
		defer f.Close()

		ucred, err := syscall.GetsockoptUcred(int(f.Fd()), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			log.Errorf("Failed to get peer credentials: %v", err)
			return
		}

		if ucred.Uid != 0 {
			log.Warnf("Rejecting admin connection from non-root user (UID: %d)", ucred.Uid)
			return
		}

		log.Debugf("Accepted admin connection from root (UID: %d)", ucred.Uid)
	}

	// Use buffered reader for line-based protocol
	reader := bufio.NewReader(conn)

	// Handle admin commands using string protocol
	for {
		// Check if context is canceled
		select {
		case <-s.ctx.Done():
			log.Debug("Context canceled, shutting down admin connection handler")
			return
		default:
		}

		// Read line (admin commands are line-based)
		line, err := reader.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				// Client closed connection gracefully
				break
			}
			log.Error("Read error:", err)
			return
		}

		// Trim whitespace and skip empty lines
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse and execute command
		response := s.parseAndExecuteCommand(line)

		// Write response
		if _, err := fmt.Fprintf(conn, "%s\n", response); err != nil {
			log.Errorf("Error writing response: %v", err)
			return
		}
	}
}

func (s *Server) parseAndExecuteCommand(line string) string {
	apiCommand, args, err := s.parseAdminCommand(line)
	if err != nil {
		return fmt.Sprintf("ERROR [INVALID_REQUEST]: %s", err.Error())
	}

	if len(apiCommand) == 0 {
		return "ERROR [INVALID_REQUEST]: Empty command"
	}

	// Handle command
	response := s.handleAdminCommand(apiCommand, args)

	if !response.Success {
		return fmt.Sprintf("ERROR [%s]: %s", response.Error.Code, response.Error.Message)
	}

	return fmt.Sprintf("%v", response.Data)
}
