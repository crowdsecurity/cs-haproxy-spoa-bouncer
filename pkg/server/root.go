package server

import (
	"net"
	"os"
	"strings"

	"github.com/crowdsecurity/crowdsec-spoa/internal/api"
	log "github.com/sirupsen/logrus"
)

type Server struct {
	listener      *net.Listener     // Listener
	permission    api.ApiPermission // Worker or Admin
	maxBufferSize int               // To protect against DoS if socket is compromised
	logger        *log.Entry        // Logger
	api           *api.Api
}

func NewAdminSocket(path string, apiServer *api.Api) (*Server, error) {
	as := &Server{
		permission:    api.AdminPermission,
		logger:        log.New().WithField("server", "admin"),
		maxBufferSize: 1024 * 2,
		api:           apiServer,
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

func NewWorkerSocket(path string, gid int, apiServer *api.Api) (*Server, error) {
	ws := &Server{
		permission:    api.WorkerPermission,
		logger:        log.New().WithField("server", "worker"),
		maxBufferSize: 1024,
		api:           apiServer,
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
	defer conn.Close()
	buffer := make([]byte, 32)
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
	apiCommand := []string{}
	args := []string{}
	_b := make([]byte, 0)
	for {
		for i, b := range data {
			if b == ' ' {
				if len(apiCommand) == 0 {
					verb := string(_b)
					if !api.IsValidVerb(verb) {
						conn.Write([]byte("invalid verb please use help\n"))
						return
					}
					apiCommand = append(apiCommand, verb)
					data = data[len(_b)+1:]
					_b = make([]byte, 0)
					break
				}
				if len(apiCommand) == 1 {
					module := string(_b)
					if !api.IsValidModule(module) {
						conn.Write([]byte("invalid module please use help\n"))
						return
					}
					apiCommand = append(apiCommand, module)
					data = data[len(_b)+1:]
					_b = make([]byte, 0)
					break
				}
				if len(apiCommand) == 2 && len(args) == 1 {
					subModule := string(_b)
					apiCommand = append(apiCommand, subModule)
					data = data[len(_b)+1:]
					_b = make([]byte, 0)
					break
				}
				args = append(args, string(_b))
				data = data[len(_b)+1:]
				_b = make([]byte, 0)
				break
			}

			_b = append(_b, b)

			if i == len(data)-1 {
				if len(apiCommand) == 2 && len(args) == 1 {
					subModule := string(_b)
					apiCommand = append(apiCommand, subModule)
					data = data[len(_b):]
					_b = make([]byte, 0)
					break
				}
				args = append(args, string(_b))
				data = data[len(_b):]
				break
			}
		}

		if len(data) == 0 {
			break
		}
	}

	log.Info("Received command: ", apiCommand, args)
	if len(apiCommand) < 2 {
		conn.Write([]byte("invalid command\n"))
		return
	}
	value, err := s.api.HandleCommand(strings.Join(apiCommand, ":"), args, s.permission)
	if err != nil {
		conn.Write([]byte(err.Error() + "\n"))
	}
	conn.Write([]byte(value))
}
