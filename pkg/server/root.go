package server

import (
	"net"
	"os"

	log "github.com/sirupsen/logrus"
)

const (
	WorkerPermission SocketPermission = iota
	AdminPermission
)

type SocketPermission int

type Server struct {
	listener      *net.Listener    // Listener
	permission    SocketPermission // Worker or Admin
	maxBufferSize int              // To protect against DoS if socket is compromised
	logger        *log.Entry       // Logger
}

func NewAdminSocket(path string) (*Server, error) {
	as := &Server{
		permission:    AdminPermission,
		logger:        log.New().WithField("server", "admin"),
		maxBufferSize: 1024 * 4,
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}

	// Admin socket has strict permissions
	if err := os.Chmod(path, 0600); err != nil {
		return nil, err
	}

	as.listener = &l

	return as, nil
}

func NewWorkerSocket(path string, gid int) (*Server, error) {
	ws := &Server{
		permission:    WorkerPermission,
		logger:        log.New().WithField("server", "worker"),
		maxBufferSize: 1024 * 4,
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}

	// Allow the worker group to access the socket
	if err := os.Chown(path, os.Getuid(), gid); err != nil {
		return nil, err
	}

	if err := os.Chmod(path, 0660); err != nil {
		return nil, err
	}

	ws.listener = &l
	return ws, nil
}

func (s *Server) Run() error {
	for {
		conn, err := (*s.listener).Accept()
		if err != nil {
			return err
		}
		go s.handleConnection(conn)
	}
}

func (s *Server) Close() error {
	return (*s.listener).Close()
}

func (s *Server) handleConnection(conn net.Conn) {
	buffer := make([]byte, 1024)
	var data []byte
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			// handle error
			break
		}
		data = append(data, buffer[:n]...)
		if n < len(buffer) {
			break
		}
		if len(data) >= s.maxBufferSize {
			break
		}
	}
	s.logger.Infof("Received: %s", string(data))
	conn.Close()
}
