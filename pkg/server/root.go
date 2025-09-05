package server

import (
	"encoding/gob"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"

	apipermission "github.com/crowdsecurity/crowdsec-spoa/internal/api/perms"
	"github.com/crowdsecurity/crowdsec-spoa/internal/api/types"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	log "github.com/sirupsen/logrus"
)

var (
	// serverGobTypesRegistered ensures gob types are registered only once on server side
	serverGobTypesRegistered sync.Once
)

// registerServerGobTypes registers types for server-side gob encoding
func registerServerGobTypes() {
	serverGobTypesRegistered.Do(func() {
		// Register types that will be sent as interface{} through gob
		gob.Register(&types.HostResponse{})
		gob.Register(http.Cookie{})
		gob.Register(remediation.Remediation(0))
	})
}

const (
	WorkerSocketPrefix = "crowdsec-spoa-worker-"
	AdminSocketPrefix  = "crowdsec-spoa-admin-"
)

type Server struct {
	listeners       []*net.Listener             // Listener
	permission      apipermission.APIPermission // Worker or Admin
	logger          *log.Entry                  // Logger
	connChan        chan SocketConn             // Channel to send new connections
	workerSocketDir string                      // Directory for worker sockets
}

type SocketConn struct {
	Conn       net.Conn                    // underlying connection
	Permission apipermission.APIPermission // Permission of the socket admin|worker
	Encoder    *gob.Encoder                // Unique encoder for socket connection
}

func NewAdminSocket(connChan chan SocketConn) (*Server, error) {
	as := &Server{
		permission: apipermission.AdminPermission,
		logger:     log.New().WithField("server", "admin"),
		connChan:   connChan,
	}

	return as, nil
}

func NewWorkerSocket(connChan chan SocketConn, dir string) (*Server, error) {
	ws := &Server{
		permission:      apipermission.WorkerPermission,
		logger:          log.New().WithField("server", "worker"),
		connChan:        connChan,
		workerSocketDir: dir,
	}

	return ws, nil
}

func (s *Server) Run(l *net.Listener) error {
	// Register gob types before creating encoder
	registerServerGobTypes()

	for {
		conn, err := (*l).Accept()
		if err != nil {
			return err
		}

		s.connChan <- SocketConn{
			Conn:       conn,
			Permission: s.permission,
			Encoder:    gob.NewEncoder(conn),
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

	//TODO: improve the error handling here
	go s.Run(&l) //nolint

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

	//TODO: improve the error handling here
	go s.Run(&l) //nolint

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

func (s *Server) Close() error {
	for _, l := range s.listeners {
		if err := (*l).Close(); err != nil {
			return err
		}
	}
	return nil
}
