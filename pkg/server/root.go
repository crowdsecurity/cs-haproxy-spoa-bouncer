package server

import (
	"fmt"
	"net"
	"os"
	"sync"

	apiPermission "github.com/crowdsecurity/crowdsec-spoa/internal/api/perms"
	log "github.com/sirupsen/logrus"
)

var (
	WORKER_SOCKET_PREFIX = "crowdsec-spoa-worker-"
	ADMIN_SOCKET_PREFIX  = "crowdsec-spoa-admin-"
)

type Server struct {
	listeners       []*net.Listener             // Listener
	permission      apiPermission.ApiPermission // Worker or Admin
	maxBufferSize   int                         // To protect against DoS if socket is compromised
	logger          *log.Entry                  // Logger
	connChan        chan SocketConn
	mutex           *sync.Mutex
	workerSocketDir string
}

type SocketConn struct {
	Conn       net.Conn
	Permission apiPermission.ApiPermission
	MaxBuffer  int
}

func NewAdminSocket(connChan chan SocketConn) (*Server, error) {
	as := &Server{
		permission:    apiPermission.AdminPermission,
		logger:        log.New().WithField("server", "admin"),
		maxBufferSize: 1024,
		connChan:      connChan,
	}

	return as, nil
}

func NewWorkerSocket(connChan chan SocketConn, dir string) (*Server, error) {
	ws := &Server{
		permission:      apiPermission.WorkerPermission,
		logger:          log.New().WithField("server", "worker"),
		maxBufferSize:   128,
		mutex:           &sync.Mutex{},
		connChan:        connChan,
		workerSocketDir: dir,
	}

	return ws, nil
}

func (s *Server) Run(l *net.Listener) error {
	for {
		conn, err := (*l).Accept()
		if err != nil {
			return err
		}
		s.connChan <- SocketConn{
			Conn:       conn,
			Permission: s.permission,
			MaxBuffer:  s.maxBufferSize,
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

	go s.Run(&l)

	return nil
}

func (s *Server) NewWorkerListener(name string, gid int) (string, error) {
	socketString := fmt.Sprintf("%s%s%s.sock", s.workerSocketDir, WORKER_SOCKET_PREFIX, name)

	l, err := newUnixSocket(socketString)
	if err != nil {
		return "", err
	}
	if err := configWorkerSocket(socketString, gid); err != nil {
		return "", err
	}
	s.listeners = append(s.listeners, &l)

	go s.Run(&l)

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

	if err := os.Chmod(path, 0660); err != nil {
		return err
	}

	return nil
}

func configAdminSocket(path string) error {
	if err := os.Chmod(path, 0600); err != nil {
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

// func (s *Server) handleConnection(conn net.Conn) {
// 	defer conn.Close()
// 	s.mutex.Lock()
// 	defer s.mutex.Unlock()
// 	buffer := make([]byte, 32)
// 	var data []byte
// 	for {
// 		n, err := conn.Read(buffer)
// 		if err != nil {
// 			// handle error
// 			break
// 		}
// 		data = append(data, buffer[:n]...)
// 		if n < len(buffer) {
// 			break
// 		}
// 		if len(data) >= s.maxBufferSize {
// 			break
// 		}
// 	}
// 	apiCommand := []string{}
// 	args := []string{}
// 	_b := make([]byte, 0)
// 	for {
// 		for i, b := range data {
// 			if b == ' ' {
// 				if len(apiCommand) == 0 {
// 					verb := string(_b)
// 					if !api.IsValidVerb(verb) {
// 						conn.Write([]byte("invalid verb please use help\n"))
// 						return
// 					}
// 					apiCommand = append(apiCommand, verb)
// 					data = data[len(_b)+1:]
// 					_b = make([]byte, 0)
// 					break
// 				}
// 				if len(apiCommand) == 1 {
// 					module := string(_b)
// 					if !api.IsValidModule(module) {
// 						conn.Write([]byte("invalid module please use help\n"))
// 						return
// 					}
// 					apiCommand = append(apiCommand, module)
// 					data = data[len(_b)+1:]
// 					_b = make([]byte, 0)
// 					break
// 				}
// 				if len(apiCommand) == 2 && len(args) == 1 {
// 					subModule := string(_b)
// 					apiCommand = append(apiCommand, subModule)
// 					data = data[len(_b)+1:]
// 					_b = make([]byte, 0)
// 					break
// 				}
// 				args = append(args, string(_b))
// 				data = data[len(_b)+1:]
// 				_b = make([]byte, 0)
// 				break
// 			}

// 			// ignore newlines
// 			if b != '\n' && b != '\r' {
// 				_b = append(_b, b)
// 			}

// 			if i == len(data)-1 {
// 				if len(apiCommand) == 2 && len(args) == 1 {
// 					subModule := string(_b)
// 					apiCommand = append(apiCommand, subModule)
// 					data = data[len(_b):]
// 					_b = make([]byte, 0)
// 					break
// 				}
// 				args = append(args, string(_b))
// 				data = data[len(_b):]
// 				break
// 			}
// 		}

// 		if len(data) == 0 {
// 			break
// 		}
// 	}

// 	log.Info("Received command: ", apiCommand, args)
// 	if len(apiCommand) < 2 {
// 		conn.Write([]byte("invalid command\n"))
// 		return
// 	}
// 	value, err := s.api.HandleCommand(strings.Join(apiCommand, ":"), args, s.permission)
// 	if err != nil {
// 		conn.Write([]byte(err.Error() + "\n"))
// 	}
// 	conn.Write([]byte(value + "\n"))
// }
