package api

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	apiPermission "github.com/crowdsecurity/crowdsec-spoa/internal/api/perms"
	"github.com/crowdsecurity/crowdsec-spoa/internal/geo"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation/captcha"
	"github.com/crowdsecurity/crowdsec-spoa/internal/session"
	"github.com/crowdsecurity/crowdsec-spoa/internal/worker"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/dataset"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/host"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/server"
	"github.com/crowdsecurity/go-cs-lib/ptr"
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
	handle func(conn net.Conn, permission apiPermission.ApiPermission, args ...string)
}

type Api struct {
	Handlers      map[string]ApiHandler
	WorkerManager *worker.Manager
	HostManager   *host.Manager
	Dataset       *dataset.DataSet
	GeoDatabase   *geo.GeoDatabase
	ConnChan      chan server.SocketConn
	ctx           context.Context
}

func (a *Api) HandleCommand(conn net.Conn, command string, args []string, permission apiPermission.ApiPermission) {
	if handler, ok := a.Handlers[command]; ok {
		handler.handle(conn, permission, args...)
		return
	}
	conn.Write([]byte("command not found\n"))
}

func NewApi(ctx context.Context, WorkerManager *worker.Manager, HostManager *host.Manager, dataset *dataset.DataSet, geoDatabase *geo.GeoDatabase, socketChan chan server.SocketConn) *Api {
	a := &Api{
		WorkerManager: WorkerManager,
		HostManager:   HostManager,
		Dataset:       dataset,
		GeoDatabase:   geoDatabase,
		ConnChan:      socketChan,
		ctx:           ctx,
	}

	a.Handlers = map[string]ApiHandler{
		"val:host:cookie": {
			handle: func(conn net.Conn, permission apiPermission.ApiPermission, args ...string) {
				if err := ArgsCheck(args, 2, 2); err != nil {
					conn.Write([]byte(err.Error() + "\n"))
					return
				}

				h := a.HostManager.MatchFirstHost(args[0])
				if h == nil {
					conn.Write([]byte("host not found\n"))
					return
				}

				uuid, err := h.Captcha.CookieGenerator.ValidateCookie(args[1])
				if err != nil {
					conn.Write([]byte("invalid cookie\n"))
					return
				}

				conn.Write([]byte(uuid + "\n"))
			},
		},
		"get:host:cookie": {
			handle: func(conn net.Conn, permission apiPermission.ApiPermission, args ...string) {
				if err := ArgsCheck(args, 2, 2); err != nil {
					conn.Write([]byte(err.Error() + "\n"))
					return
				}

				h := a.HostManager.MatchFirstHost(args[0])
				ses, err := h.Captcha.Sessions.NewRandomSession()
				if err != nil {
					conn.Write([]byte("error generating cookie\n"))
					return
				}

				cookie, err := h.Captcha.CookieGenerator.GenerateCookie(ses, ptr.Of(args[1] == "true"))
				if err != nil {
					conn.Write([]byte("error generating cookie\n"))
					return
				}

				ses.Set(session.CAPTCHA_STATUS, captcha.Pending)
				conn.Write([]byte(cookie.String() + "\n"))
			},
		},
		"get:hosts": {
			handle: func(conn net.Conn, permission apiPermission.ApiPermission, args ...string) {
				hostGob := gob.NewEncoder(conn)

				if len(args) == 0 && permission == apiPermission.WorkerPermission {
					conn.Write([]byte("permission denied\n"))
					return
				}

				if len(args) == 0 && permission == apiPermission.AdminPermission {
					hostGob.Encode(a.HostManager.Hosts)
					return
				}

				if err := ArgsCheck(args, 1, 1); err != nil {
					conn.Write([]byte(err.Error() + "\n"))
					return
				}

				log.Info("Checking host", args[0])

				h := a.HostManager.MatchFirstHost(args[0])

				if h == nil {
					conn.Write([]byte("\n"))
					return
				}

				// Encode a host object with gob, omits the sensitive data
				hostGob.Encode(&host.Host{
					Host: h.Host,
					Captcha: captcha.Captcha{
						SiteKey:             h.Captcha.SiteKey,
						Provider:            h.Captcha.Provider,
						FallbackRemediation: h.Captcha.FallbackRemediation,
					},
					Ban: h.Ban,
				})
			},
		},
		"get:ip": {
			handle: func(conn net.Conn, permission apiPermission.ApiPermission, args ...string) {
				if err := ArgsCheck(args, 1, 1); err != nil {
					conn.Write([]byte(err.Error() + "\n"))
					return
				}

				log.Infof("Checking IP %s", args[0])
				val := net.ParseIP(args[0])
				if val == nil {
					conn.Write([]byte("invalid IP\n"))
					return
				}
				r := a.Dataset.CheckIP(&val)
				if permission == apiPermission.WorkerPermission {
					rGob := gob.NewEncoder(conn)
					rGob.Encode(r)
					return
				}
				conn.Write([]byte(r.String() + "\n"))
			},
		},
		"get:cn": {
			handle: func(conn net.Conn, permission apiPermission.ApiPermission, args ...string) {
				if err := ArgsCheck(args, 1, 1); err != nil {
					conn.Write([]byte(err.Error() + "\n"))
					return
				}
				if args[0] == "" {
					conn.Write([]byte("invalid country\n"))
					return
				}
				r := a.Dataset.CheckCN(args[0])
				if permission == apiPermission.WorkerPermission {
					rGob := gob.NewEncoder(conn)
					rGob.Encode(r)
					return
				}
				conn.Write([]byte(r.String() + "\n"))
			},
		},
		"get:geo:iso": {
			handle: func(conn net.Conn, _ apiPermission.ApiPermission, args ...string) {
				geoGob := gob.NewEncoder(conn)
				if err := ArgsCheck(args, 1, 1); err != nil {
					conn.Write([]byte(err.Error() + "\n"))
					return
				}

				log.Infof("Checking IP %s", args[0])
				val := net.ParseIP(args[0])
				if val == nil {
					conn.Write([]byte("invalid IP\n"))
					return
				}
				record, err := a.GeoDatabase.GetCity(&val)
				if err != nil && !errors.Is(err, geo.NotValidConfig) {
					log.Error(err)
				}
				iso := geo.GetIsoCodeFromRecord(record)
				geoGob.Encode(iso)
			},
		},
	}

	return a
}

func (a *Api) Run() error {
	for {
		select {
		case sc := <-a.ConnChan:
			log.Info("New connection")
			go a.handleConnection(sc)
		case <-a.ctx.Done():
			return nil
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

func flushConn(conn net.Conn) error {
	buffer := make([]byte, 1024)
	for {
		// Set a short read deadline to avoid blocking indefinitely
		conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

		// Try to read data into the buffer
		n, err := conn.Read(buffer)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				// If we hit a timeout, it likely means the buffer is flushed
				break
			}
			if err == io.EOF {
				// If we hit EOF, the buffer is flushed
				break
			}
			return err
		}
		if n == 0 {
			break
		}
	}
	// Reset the read deadline after flushing
	conn.SetReadDeadline(time.Time{})
	return nil
}

func (a *Api) handleConnection(sc server.SocketConn) {
	defer func() {
		err := sc.Conn.Close()
		if err != nil {
			log.Error("Error closing connection:", err)
		}
	}()

	// Flush any leftover data in the connection buffer
	err := flushConn(sc.Conn)
	if err != nil {
		log.Error("Error flushing connection buffer:", err)
		return
	}

	headerBuffer := make([]byte, 16)
	dataBuffer := make([]byte, 0)

	var (
		dataLen   int
		verb      string
		module    string
		subModule string
	)

	resetState := func() {
		dataLen = 0
		verb = ""
		module = ""
		subModule = ""
	}

	for {
		n, err := sc.Conn.Read(headerBuffer)
		if err != nil {
			if err == io.EOF {
				// Client closed the connection gracefully
				break
			}
			log.Error("Read error:", err)
			return
		}
		if n == 0 {
			continue
		}
		headerStr := cleanNullBytes(headerBuffer[:n])
		log.Info("Header:", headerStr)

		switch {
		case dataLen == 0:
			dataLen, err = strconv.Atoi(headerStr)
			if err != nil {
				log.Error("Error parsing data length:", err)
				resetState()
				if flushErr := flushConn(sc.Conn); flushErr != nil {
					log.Error("Error flushing connection buffer:", flushErr)
					return
				}
				continue
			}
			log.Info("Data length:", dataLen)

		case verb == "":
			verb = headerStr
			if !IsValidVerb(verb) {
				log.Error("Invalid verb:", verb)
				resetState()
				if flushErr := flushConn(sc.Conn); flushErr != nil {
					log.Error("Error flushing connection buffer:", flushErr)
					return
				}
				continue
			}
			log.Info("Verb:", verb)

		case module == "":
			module = headerStr
			if !IsValidModule(module) {
				log.Error("Invalid module:", module)
				resetState()
				if flushErr := flushConn(sc.Conn); flushErr != nil {
					log.Error("Error flushing connection buffer:", flushErr)
					return
				}
			}
			continue

		default:
			subModule = headerStr

			dataBuffer = make([]byte, dataLen)
			n, err := sc.Conn.Read(dataBuffer)
			if err != nil {
				log.Error("Read error:", err)
				return
			}
			if n == 0 {
				resetState()
				if flushErr := flushConn(sc.Conn); flushErr != nil {
					log.Error("Error flushing connection buffer:", flushErr)
					return
				}
				continue
			}

			command := verb + ":" + module
			if subModule != "" {
				command += ":" + subModule
			}
			dataParts := strings.Split(string(dataBuffer[:n]), " ")
			log.Infof("data: %+v", dataParts)
			a.HandleCommand(sc.Conn, command, dataParts, sc.Permission)

			resetState()
		}
	}
}

func cleanNullBytes(b []byte) string {
	return string(bytes.ReplaceAll(b, []byte{0}, []byte{}))
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

val host <host> session <uuid> <response> // validate captcha response for host
get host <host> session <uuid> <key> // get session key against kv store
set host <host> session <uuid> <key> <value> // set session key against kv store

help host session // this help
help host cookie // this help
help host remediation // this help
help // this help

*/
