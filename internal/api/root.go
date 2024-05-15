package api

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/crowdsecurity/crowdsec-spoa/internal/geo"
	"github.com/crowdsecurity/crowdsec-spoa/internal/worker"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/dataset"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/host"
	log "github.com/sirupsen/logrus"
)

const (
	WorkerPermission ApiPermission = iota
	AdminPermission
)

type ApiPermission int

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
	handle func(permission ApiPermission, args ...string) (string, error)
}

type Api struct {
	Handlers      map[string]ApiHandler
	WorkerManager *worker.Manager
	HostManager   *host.Manager
	Dataset       *dataset.DataSet
	GeoDatabase   *geo.GeoDatabase
}

func (a *Api) HandleCommand(command string, args []string, permission ApiPermission) (string, error) {
	if handler, ok := a.Handlers[command]; ok {
		return handler.handle(permission, args...)
	}
	return "", fmt.Errorf("invalid command")
}

func NewApi(WorkerManager *worker.Manager, HostManager *host.Manager, dataset *dataset.DataSet, geoDatabase *geo.GeoDatabase) *Api {
	a := &Api{
		WorkerManager: WorkerManager,
		HostManager:   HostManager,
		Dataset:       dataset,
		GeoDatabase:   geoDatabase,
	}

	a.Handlers = map[string]ApiHandler{
		"get:hosts": {
			handle: func(permission ApiPermission, args ...string) (string, error) {

				if len(args) == 0 && permission == WorkerPermission {
					return "", fmt.Errorf("permission denied")
				}

				if len(args) == 0 && permission == AdminPermission {
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
			handle: func(_ ApiPermission, args ...string) (string, error) {
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
			handle: func(_ ApiPermission, args ...string) (string, error) {
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
			handle: func(_ ApiPermission, args ...string) (string, error) {

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

func ArgsCheck(args []string, min int, max int) error {
	if len(args) < min {
		return fmt.Errorf("missing argument")
	}
	if len(args) > max {
		return fmt.Errorf("too many arguments")
	}
	return nil
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
