package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	apiPermission "github.com/crowdsecurity/crowdsec-spoa/internal/api/perms"
	"github.com/crowdsecurity/crowdsec-spoa/internal/geo"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation/captcha"
	"github.com/crowdsecurity/crowdsec-spoa/internal/session"
	"github.com/crowdsecurity/crowdsec-spoa/internal/worker"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/dataset"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/host"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/metrics"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/server"
	"github.com/crowdsecurity/go-cs-lib/ptr"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

const (
	GET APIVerb = "get"
	SET APIVerb = "set"
	DEL APIVerb = "del"
	VAL APIVerb = "val"

	// only ApiVerb over 3 chars
	HELP APIVerb = "help"
)

type APIVerb string

func IsValidVerb(s string) bool {
	for _, v := range ValidVerb {
		if APIVerb(s) == v {
			return true
		}
	}
	return false
}

func IsValidModule(s string) bool {
	for _, v := range ValidModule {
		if APIModule(s) == v {
			return true
		}
	}
	return false
}

const (
	IP      APIModule = "ip"
	GEO     APIModule = "geo"
	CN      APIModule = "cn"
	HOSTS   APIModule = "hosts"
	WORKERS APIModule = "workers"
	HOST    APIModule = "host"
	WORKER  APIModule = "worker"
)

type APIModule string

var (
	ValidVerb   = []APIVerb{GET, SET, DEL, VAL, HELP}
	ValidModule = []APIModule{IP, CN, HOSTS, WORKERS, HOST, WORKER, GEO}
)

type APIHandler struct {
	handle func(permission apiPermission.APIPermission, args ...string) (interface{}, error)
}

type API struct {
	Handlers      map[string]APIHandler
	WorkerManager *worker.Manager
	HostManager   *host.Manager
	Dataset       *dataset.DataSet
	GeoDatabase   *geo.GeoDatabase
	ConnChan      chan server.SocketConn
}

func (a *API) HandleCommand(command string, args []string, permission apiPermission.APIPermission) (interface{}, error) {
	if handler, ok := a.Handlers[command]; ok {
		return handler.handle(permission, args...)
	}
	return nil, fmt.Errorf("command not found")
}

func NewAPI(WorkerManager *worker.Manager, HostManager *host.Manager, dataset *dataset.DataSet, geoDatabase *geo.GeoDatabase, socketChan chan server.SocketConn) *API {
	a := &API{
		WorkerManager: WorkerManager,
		HostManager:   HostManager,
		Dataset:       dataset,
		GeoDatabase:   geoDatabase,
		ConnChan:      socketChan,
	}

	a.Handlers = map[string]APIHandler{
		"val:host:cookie": {
			handle: func(permission apiPermission.APIPermission, args ...string) (interface{}, error) {
				if err := ArgsCheck(args, 2, 2); err != nil {
					return "", err
				}

				h := a.HostManager.MatchFirstHost(args[0])
				if h == nil {
					return "", nil
				}

				uuid, err := h.Captcha.CookieGenerator.ValidateCookie(args[1])
				if err != nil {
					return "", err
				}

				sess := h.Captcha.Sessions.GetSession(uuid)

				if sess == nil {
					return "", nil
				}

				return uuid, nil
			},
		},
		"val:host:captcha": {
			handle: func(permission apiPermission.APIPermission, args ...string) (interface{}, error) {
				if err := ArgsCheck(args, 3, 3); err != nil {
					return "", err
				}

				h := a.HostManager.MatchFirstHost(args[0])
				if h == nil {
					return "", nil
				}

				return h.Captcha.Validate(args[1], args[2]), nil
			},
		},
		"del:host:session": {
			handle: func(permission apiPermission.APIPermission, args ...string) (interface{}, error) {
				if err := ArgsCheck(args, 3, 3); err != nil {
					return "", err
				}

				h := a.HostManager.MatchFirstHost(args[0])
				if h == nil {
					return false, nil
				}

				ses := h.Captcha.Sessions.GetSession(args[1])

				if ses == nil {
					return false, nil
				}

				ses.Delete(args[2])

				return true, nil
			},
		},
		"del:hosts": {
			handle: func(permission apiPermission.APIPermission, args ...string) (interface{}, error) {
				if permission == apiPermission.WorkerPermission {
					return nil, fmt.Errorf("permission denied")
				}

				if err := ArgsCheck(args, 1, 1); err != nil {
					return nil, err
				}

				h := a.HostManager.MatchFirstHost(args[0])

				if h == nil {
					return false, nil
				}

				a.HostManager.Chan <- host.HostOp{
					Host: h,
					Op:   host.OpRemove,
				}

				return true, nil
			},
		},
		"set:host:session": {
			handle: func(permission apiPermission.APIPermission, args ...string) (interface{}, error) {
				if err := ArgsCheck(args, 4, 4); err != nil {
					return nil, err
				}

				h := a.HostManager.MatchFirstHost(args[0])
				if h == nil {
					return false, nil
				}

				ses := h.Captcha.Sessions.GetSession(args[1])

				if ses == nil {
					return false, nil
				}

				ses.Set(args[2], args[3])
				return true, nil
			},
		},
		"get:host:session": {
			handle: func(permission apiPermission.APIPermission, args ...string) (interface{}, error) {
				if err := ArgsCheck(args, 3, 3); err != nil {
					return "", err
				}

				h := a.HostManager.MatchFirstHost(args[0])
				if h == nil {
					return "", nil
				}

				ses := h.Captcha.Sessions.GetSession(args[1])

				if ses == nil {
					return "", nil
				}

				val := ses.Get(args[2])

				if val == nil {
					val = ""
				}

				return val, nil
			},
		},
		"get:host:cookie": {
			handle: func(permission apiPermission.APIPermission, args ...string) (interface{}, error) {
				if err := ArgsCheck(args, 2, 2); err != nil {
					return nil, err
				}

				h := a.HostManager.MatchFirstHost(args[0])
				ses, err := h.Captcha.Sessions.NewRandomSession()

				if err != nil {
					return nil, err
				}

				cookie, err := h.Captcha.CookieGenerator.GenerateCookie(ses, ptr.Of(args[1] == "true"))
				if err != nil {
					return nil, err
				}

				ses.Set(session.CaptchaStatus, captcha.Pending)
				return cookie, nil
			},
		},
		"get:hosts": {
			handle: func(permission apiPermission.APIPermission, args ...string) (interface{}, error) {
				if len(args) == 0 && permission == apiPermission.WorkerPermission {
					return &host.Host{}, fmt.Errorf("permission denied")
				}

				if len(args) == 0 && permission == apiPermission.AdminPermission {
					return a.HostManager.String(), nil
				}

				if err := ArgsCheck(args, 1, 1); err != nil {
					return &host.Host{}, err
				}

				h := a.HostManager.MatchFirstHost(args[0])

				// We cant return nil, so we return an empty host
				if h == nil {
					return &host.Host{}, nil
				}

				// return a new host derived from the host object to redact sensitive information
				return &host.Host{
					Host: h.Host,
					Captcha: captcha.Captcha{
						SiteKey:             h.Captcha.SiteKey,
						Provider:            h.Captcha.Provider,
						FallbackRemediation: h.Captcha.FallbackRemediation,
					},
					Ban: h.Ban,
				}, nil
			},
		},
		"get:ip": {
			handle: func(permission apiPermission.APIPermission, args ...string) (interface{}, error) {
				if err := ArgsCheck(args, 1, 1); err != nil {
					return nil, err
				}

				log.Infof("Checking IP %s", args[0])

				r, origin, err := a.Dataset.CheckIP(args[0])

				if err != nil {
					return nil, err
				}

				if permission == apiPermission.WorkerPermission {
					//Only count processed requests if coming from worker
					ipType := "ipv4"
					if strings.Contains(args[0], ":") {
						ipType = "ipv6"
					}

					metrics.TotalProcessedRequests.With(prometheus.Labels{"ip_type": ipType}).Inc()

					if r > remediation.Unknown {
						metrics.TotalBlockedRequests.With(prometheus.Labels{"ip_type": ipType, "origin": origin, "remediation": r.String()}).Inc()
					}

					return r, nil
				}

				return r.String(), nil
			},
		},
		"get:cn": {
			handle: func(permission apiPermission.APIPermission, args ...string) (interface{}, error) {
				if err := ArgsCheck(args, 2, 2); err != nil {
					return nil, err
				}
				if args[0] == "" {
					return nil, fmt.Errorf("invalid argument")
				}
				r, origin := a.Dataset.CheckCN(args[0])

				if permission == apiPermission.WorkerPermission {
					if r > remediation.Unknown {
						ipType := "ipv4"
						if strings.Contains(args[1], ":") {
							ipType = "ipv6"
						}
						metrics.TotalBlockedRequests.With(prometheus.Labels{"ip_type": ipType, "origin": origin, "remediation": r.String()}).Inc()
					}
					return r, nil
				}

				return r.String(), nil
			},
		},
		"get:geo:iso": {
			handle: func(_ apiPermission.APIPermission, args ...string) (interface{}, error) {
				if err := ArgsCheck(args, 1, 1); err != nil {
					return nil, err
				}

				if !a.GeoDatabase.IsValid() {
					return "", nil
				}

				log.Tracef("Checking geo:iso IP %s", args[0])
				val := net.ParseIP(args[0])

				if val == nil {
					return nil, fmt.Errorf("invalid IP")
				}

				record, err := a.GeoDatabase.GetCity(&val)

				if err != nil && !errors.Is(err, geo.ErrNotValidConfig) {
					return nil, err
				}

				if record == nil {
					return nil, nil
				}

				return geo.GetIsoCodeFromRecord(record), nil
			},
		},
	}

	return a
}

func (a *API) Run(ctx context.Context) error {
	for {
		select {
		case sc := <-a.ConnChan:
			log.Info("New connection")
			if sc.Permission == apiPermission.WorkerPermission {
				go a.handleWorkerConnection(sc)
				continue
			}
			go a.handleAdminConnection(sc)
		case <-ctx.Done():
			return nil
		}
	}
}

func ArgsCheck(args []string, minValue int, maxValue int) error {
	if len(args) < minValue {
		return fmt.Errorf("missing argument")
	}
	if len(args) > maxValue {
		return fmt.Errorf("too many arguments")
	}
	return nil
}

func flushConn(conn net.Conn) error {
	var ne net.Error
	buffer := make([]byte, 1024)
	for {
		// Set a short read deadline to avoid blocking indefinitely
		err := conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if err != nil {
			return fmt.Errorf("error setting read deadline: %w", err)
		}

		// Try to read data into the buffer
		n, err := conn.Read(buffer)
		if err != nil {
			switch {
			case errors.As(err, &ne) && ne.Timeout():
				break
			case errors.Is(err, io.EOF):
				break
			default:
				return err
			}
		}
		if n == 0 {
			break
		}
	}
	// Reset the read deadline after flushing
	err := conn.SetReadDeadline(time.Time{})
	if err != nil {
		return fmt.Errorf("error setting read deadline: %w", err)
	}
	return nil
}

func (a *API) handleWorkerConnection(sc server.SocketConn) {
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
	// headerBuffer is 4 parts of 16 bytes each
	headerBuffer := make([]byte, 52)

	for {
		n, err := sc.Conn.Read(headerBuffer)
		if err != nil {
			if errors.Is(err, io.EOF) {
				// Client closed the connection gracefully
				break
			}
			log.Error("Read error:", err)
			return
		}

		if n == 0 {
			continue
		}

		_dl, _v, _m, _sm, err := readHeaderFromBytes(headerBuffer)

		log.Debugf("received header bytes: datalength: %d | verb: %s, | module: %s | submodule: %s", _dl, _v, _m, _sm)

		if err != nil || !IsValidVerb(_v) || !IsValidModule(_m) {
			log.Error("Error reading header:", err)
			if flushErr := flushConn(sc.Conn); flushErr != nil {
				log.Error("Error flushing connection buffer:", flushErr)
				return
			}
			continue
		}

		dataBuffer := make([]byte, _dl)
		n, err = sc.Conn.Read(dataBuffer)

		if err != nil || n == 0 {
			if flushErr := flushConn(sc.Conn); flushErr != nil {
				log.Error("Error flushing connection buffer:", flushErr)
				return
			}
			continue
		}

		command := _v + ":" + _m
		if _sm != "" {
			command += ":" + _sm
		}

		var dataParts []string

		// We have to handle appsec request differently as we don't know what bytes are contained within the body of the request
		if _sm == "appsec" {
			// We know the first null bytes separates the host from the rest of the data
			dataParts = splitBytesByNullN(dataBuffer[:n], 2)
		} else {
			dataParts = splitBytesByNull(dataBuffer[:n])
		}

		log.Debugf("data: %+v", dataParts)
		log.Debugf("calling command %s with data: %+v and permissions %d", command, dataParts, sc.Permission)

		value, err := a.HandleCommand(command, dataParts, sc.Permission)

		log.Debugf("command %s returned %+v", command, value)
		if err != nil {
			//TODO handle error
			log.Error("Error handling command:", err)
			continue
		}

		if value == nil {
			// nil cannot be encoded, so we send an empty string
			value = ""
		}

		if err := sc.Encoder.Encode(value); err != nil {
			log.Error("Error encoding response:", err)
		}
	}
}

func (a *API) handleAdminConnection(sc server.SocketConn) {
	defer func() {
		err := sc.Conn.Close()
		if err != nil {
			log.Error("Error closing connection:", err)
		}
	}()

	dataBuffer := make([]byte, 10240)
	for {
		n, err := sc.Conn.Read(dataBuffer)
		if err != nil {
			if errors.Is(err, io.EOF) {
				// Client closed the connection gracefully
				break
			}
			log.Error("Read error:", err)
			return
		}

		if n == 0 {
			continue
		}

		apiCommand, args, _, err := parseCommand(dataBuffer[:n])
		if err != nil {
			log.Error("Error parsing command:", err)
			continue
		}

		if len(apiCommand) == 0 {
			log.Error("Empty command")
			continue
		}

		value, err := a.HandleCommand(strings.Join(apiCommand, ":"), args, sc.Permission)

		if err != nil {
			log.Errorf("%+v, %+v", apiCommand, args)
			log.Error("Error handling command:", err)
			_, err2 := fmt.Fprintf(sc.Conn, "%v\n", err) // We return the error message back to admin sockets

			log.Errorf("error returning the error back to admin socket: %v", err2)
			continue
		}

		_, err = fmt.Fprintf(sc.Conn, "%v\n", value)
		log.Errorf("error writing server: %v", err)

	}
}

// readHeaderFromBytes reads the header bytes and returns the data length, verb, module, and sub-module.
func readHeaderFromBytes(hb []byte) (int, string, string, string, error) {
	dataLen, err := strconv.Atoi(cleanNullBytes(hb[:16]))
	if err != nil {
		return 0, "", "", "", err
	}
	verb := cleanNullBytes(hb[16:20])
	module := cleanNullBytes(hb[20:36])
	subModule := cleanNullBytes(hb[36:52])
	return dataLen, verb, module, subModule, nil
}

// cleanNullBytes removes null bytes from a byte slice and returns a string.
func cleanNullBytes(b []byte) string {
	return string(bytes.ReplaceAll(b, []byte{0}, []byte{}))
}

func splitBytesByNull(b []byte) []string {
	s := bytes.Split(b, []byte{0})
	str := make([]string, 0)
	for _, v := range s {
		if len(v) > 0 {
			str = append(str, string(v))
		}
	}
	return str
}

func splitBytesByNullN(b []byte, n int) []string {
	s := bytes.SplitN(b, []byte{0}, n)
	str := make([]string, 0)
	for _, v := range s {
		if len(v) > 0 {
			str = append(str, string(v))
		}
	}
	return str
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
			if len(apiCommand) == 1 {
				module := string(_b)
				if !IsValidModule(module) {
					return nil, nil, nil, fmt.Errorf("invalid module please use help")
				}
				apiCommand = append(apiCommand, module)
				return apiCommand, args, nil, nil
			}
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

val host <host> captcha <response> // validate captcha response for host

get host <host> session <uuid> <key> // get session key against kv store
set host <host> session <uuid> <key> <value> // set session key against kv store
del host <host> session <uuid> <key> // delete session key against kv store

help host session // this help
help host cookie // this help
help host remediation // this help
help // this help

*/
