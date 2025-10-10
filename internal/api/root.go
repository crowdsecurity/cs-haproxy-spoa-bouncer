package api

import (
	"context"
	"fmt"

	apiPermission "github.com/crowdsecurity/crowdsec-spoa/internal/api/perms"
	"github.com/crowdsecurity/crowdsec-spoa/internal/api/types"
	"github.com/crowdsecurity/crowdsec-spoa/internal/geo"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/dataset"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/host"
	"github.com/crowdsecurity/crowdsec-spoa/pkg/server"
	log "github.com/sirupsen/logrus"
)

type API struct {
	HostManager *host.Manager
	Dataset     *dataset.DataSet
	GeoDatabase *geo.GeoDatabase
	ConnChan    chan server.SocketConn
}

// APIConfig holds the configuration for creating a new API instance
type APIConfig struct {
	HostManager *host.Manager
	Dataset     *dataset.DataSet
	GeoDatabase *geo.GeoDatabase
	SocketChan  chan server.SocketConn
}

// NewAPI creates a new API instance and initializes it with the provided configuration
func NewAPI(config APIConfig) *API {
	a := &API{
		HostManager: config.HostManager,
		Dataset:     config.Dataset,
		GeoDatabase: config.GeoDatabase,
		ConnChan:    config.SocketChan,
	}

	return a
}

func (a *API) Run(ctx context.Context) error {
	for {
		select {
		case sc := <-a.ConnChan:
			log.Info("New admin connection")
			if sc.Permission == apiPermission.AdminPermission {
				go a.handleAdminConnection(ctx, sc)
			} else {
				log.Warnf("Unexpected connection with permission %v, closing", sc.Permission)
				sc.Conn.Close()
			}
		case <-ctx.Done():
			return nil
		}
	}
}

// ArgsCheckResponse returns a proper API response for argument validation
func ArgsCheckResponse(args []string, minValue int, maxValue int) *types.APIResponse {
	if len(args) < minValue {
		return types.NewAPIError(types.ErrCodeMissingArgument, "Missing required arguments",
			fmt.Sprintf("expected at least %d arguments, got %d", minValue, len(args)))
	}
	if len(args) > maxValue {
		return types.NewAPIError(types.ErrCodeTooManyArguments, "Too many arguments",
			fmt.Sprintf("expected at most %d arguments, got %d", maxValue, len(args)))
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

val host <host> captcha <response> // validate captcha response for host

get host <host> session <uuid> <key> // get session key against kv store
set host <host> session <uuid> <key> <value> // set session key against kv store
del host <host> session <uuid> <key> // delete session key against kv store

help host session // this help
help host cookie // this help
help host remediation // this help
help // this help

*/
