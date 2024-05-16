package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	apiPermission "github.com/crowdsecurity/crowdsec-spoa/internal/api/perms"
	"github.com/crowdsecurity/crowdsec-spoa/internal/geo"
	"github.com/crowdsecurity/crowdsec-spoa/internal/worker"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/dataset"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/host"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/server"
	log "github.com/sirupsen/logrus"
)

const (
	GET ApiVerb = "get"
	SET ApiVerb = "set"
	DEL ApiVerb = "del"
	VAL ApiVerb = "val"

	// only ApiVerb over 3 chars
	HELP ApiVerb = "help"
)

type ApiVerb string

func IsValidVerb(s string) bool {
	for _, v := range ValidVerb {
		if ApiVerb(s) == v {
			return true
		}
	}
	return false
}

func IsValidModule(s string) bool {
	for _, v := range ValidModule {
		if ApiModule(s) == v {
			return true
		}
	}
	return false
}

const (
	IP      ApiModule = "ip"
	GEO     ApiModule = "geo"
	CN      ApiModule = "cn"
	HOSTS   ApiModule = "hosts"
	WORKERS ApiModule = "workers"
	HOST    ApiModule = "host"
	WORKER  ApiModule = "worker"
)

type ApiModule string

var (
	ValidVerb   = []ApiVerb{GET, SET, DEL, VAL, HELP}
	ValidModule = []ApiModule{IP, CN, HOSTS, WORKERS, HOST, WORKER, GEO}
)

type ApiHandler struct {
	handle func(permission apiPermission.ApiPermission, args ...string) (string, error)
}

type Api struct {
	Handlers      map[string]ApiHandler
	WorkerManager *worker.Manager
	HostManager   *host.Manager
	Dataset       *dataset.DataSet
	GeoDatabase   *geo.GeoDatabase
	ConnChan      chan server.SocketConn
}

func (a *Api) HandleCommand(command string, args []string, permission apiPermission.ApiPermission) (string, error) {
	if handler, ok := a.Handlers[command]; ok {
		return handler.handle(permission, args...)
	}
	return "", fmt.Errorf("invalid command")
}

func NewApi(WorkerManager *worker.Manager, HostManager *host.Manager, dataset *dataset.DataSet, geoDatabase *geo.GeoDatabase, socketChan chan server.SocketConn) *Api {
	a := &Api{
		WorkerManager: WorkerManager,
		HostManager:   HostManager,
		Dataset:       dataset,
		GeoDatabase:   geoDatabase,
		ConnChan:      socketChan,
	}

	a.Handlers = map[string]ApiHandler{
		"get:hosts": {
			handle: func(permission apiPermission.ApiPermission, args ...string) (string, error) {

				if len(args) == 0 && permission == apiPermission.WorkerPermission {
					return "", fmt.Errorf("permission denied")
				}

				if len(args) == 0 && permission == apiPermission.AdminPermission {
					sb := strings.Builder{}
					for _, host := range a.HostManager.Hosts {
						sb.WriteString(host.Host)
						sb.WriteString("\n")
					}
					return sb.String(), nil
				}

				if err := ArgsCheck(args, 1, 1); err != nil {
					return "", err
				}

				host := a.HostManager.MatchFirstHost(args[0])

				if host == nil {
					return "", nil
				}

				return host.Host, nil
			},
		},
		"get:ip": {
			handle: func(_ apiPermission.ApiPermission, args ...string) (string, error) {
				if err := ArgsCheck(args, 1, 1); err != nil {
					return "", err
				}

				log.Infof("Checking IP %s", args[0])
				val := net.ParseIP(args[0])
				if val == nil {
					return "", fmt.Errorf("invalid IP")
				}
				r := a.Dataset.CheckIP(&val)
				return r.String(), nil
			},
		},
		"get:cn": {
			handle: func(_ apiPermission.ApiPermission, args ...string) (string, error) {
				if err := ArgsCheck(args, 1, 1); err != nil {
					return "", err
				}
				if args[0] == "" {
					return "", fmt.Errorf("invalid argument")
				}
				r := a.Dataset.CheckCN(args[0])
				return r.String(), nil
			},
		},
		"get:geo:iso": {
			handle: func(_ apiPermission.ApiPermission, args ...string) (string, error) {

				if err := ArgsCheck(args, 1, 1); err != nil {
					return "", err
				}

				log.Infof("Checking IP %s", args[0])
				val := net.ParseIP(args[0])
				if val == nil {
					return "", fmt.Errorf("invalid IP")
				}
				record, err := a.GeoDatabase.GetCity(&val)
				if err != nil && !errors.Is(err, geo.NotValidConfig) {
					log.Error(err)
				}
				iso := geo.GetIsoCodeFromRecord(record)
				return iso, nil
			},
		},
	}

	return a
}

func (a *Api) Run(ctx context.Context) {
	for {
		select {
		case sc := <-a.ConnChan:
			go a.handleConnection(sc)
		case <-ctx.Done():
			return
		}
	}
}

func ArgsCheck(args []string, min int, max int) error {
	if len(args) < min {
		return fmt.Errorf("missing argument")
	}
	if len(args) > max {
		return fmt.Errorf("too many arguments")
	}
	return nil
}

func (a *Api) handleConnection(sc server.SocketConn) {
	defer sc.Conn.Close()
	buffer := make([]byte, sc.MaxBuffer)
	var data []byte

	for {
		n, err := sc.Conn.Read(buffer)
		if err != nil {
			if err == io.EOF {
				// Client closed the connection gracefully
				break
			}
			fmt.Println("Read error:", err)
			return
		}

		data = append(data, buffer[:n]...)

		// Process the accumulated data
		for len(data) > 0 {
			apiCommand, args, remainingData, err := parseCommand(data)
			if err != nil {
				sc.Conn.Write([]byte("error processing command\n"))
				data = remainingData
				continue
			}

			if apiCommand == nil {
				// Command is not complete yet, wait for more data
				break
			}

			data = remainingData

			// Handle the command
			value, err := a.HandleCommand(strings.Join(apiCommand, ":"), args, sc.Permission)
			if err != nil {
				sc.Conn.Write([]byte(err.Error() + "\n"))
			} else {
				sc.Conn.Write([]byte(value + "\n"))
			}
		}
	}
}

// parseCommand processes the data buffer and extracts the command and arguments.
// It returns the command, arguments, remaining unprocessed data, and any error encountered.
func parseCommand(data []byte) ([]string, []string, []byte, error) {
	apiCommand := []string{}
	args := []string{}
	_b := make([]byte, 0)

	for i, b := range data {
		if b == ' ' {
			if len(apiCommand) == 0 {
				verb := string(_b)
				if !IsValidVerb(verb) {
					return nil, nil, data[i+1:], fmt.Errorf("invalid verb please use help")
				}
				apiCommand = append(apiCommand, verb)
				_b = make([]byte, 0)
				continue
			}
			if len(apiCommand) == 1 {
				module := string(_b)
				if !IsValidModule(module) {
					return nil, nil, data[i+1:], fmt.Errorf("invalid module please use help")
				}
				apiCommand = append(apiCommand, module)
				_b = make([]byte, 0)
				continue
			}
			if len(apiCommand) == 2 && len(args) == 1 {
				subModule := string(_b)
				apiCommand = append(apiCommand, subModule)
				_b = make([]byte, 0)
				continue
			}
			args = append(args, string(_b))
			_b = make([]byte, 0)
			continue
		}

		// ignore newlines
		if b != '\n' && b != '\r' {
			_b = append(_b, b)
		}

		if i == len(data)-1 {
			if len(apiCommand) == 2 && len(args) == 1 {
				subModule := string(_b)
				apiCommand = append(apiCommand, subModule)
				return apiCommand, args, nil, nil
			}
			args = append(args, string(_b))
			return apiCommand, args, nil, nil
		}
	}

	if len(_b) > 0 {
		if len(apiCommand) == 2 && len(args) == 1 {
			subModule := string(_b)
			apiCommand = append(apiCommand, subModule)
			return apiCommand, args, nil, nil
		}
		args = append(args, string(_b))
	}

	return apiCommand, args, nil, nil
}

/*
// Admin only permissions
set hosts <host> ...key=value // add new host
del hosts <host> // remove host

get hosts // list all hosts

get workers <worker> // find function
set workers <worker> ...key=value // add new worker
del workers <worker> // remove worker

get host <host> // get host details
set host <host> ...key=value // set host details
get host <host> sessions // get all sessions for host

help host // this help
help hosts // this help
help workers // this help

// Worker permissions
get ip <ip> // get remediation for ip
get cn <cn>  // get remediation for country

get geo <ip> iso // get geo for ip

get hosts <host> // find function return host.Host

get host <host> cookie // get cookie for host
val host <host> cookie <cookie> // validate cookie for host

val host <host> remediation <remediation> // validate remediation for host

get host <host> session <uuid> <key> // get session key against kv store
set host <host> session <uuid> <key> <value> // set session key against kv store

help host session // this help
help host cookie // this help
help host remediation // this help
help // this help

*/
