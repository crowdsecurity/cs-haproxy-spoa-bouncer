package messages

import (
	"encoding/gob"
	"net/http"

	"github.com/crowdsecurity/crowdsec-spoa/internal/api/types"
	"github.com/crowdsecurity/crowdsec-spoa/internal/remediation"
)

// APIRequest is the unified request message for both worker and admin communication
// This eliminates duplication while keeping the handlers separate
type APIRequest struct {
	Command APICommand  `gob:"cmd"`
	Data    interface{} `gob:"data"`
}

// APICommand represents different worker API commands
type APICommand string

// All current worker API commands as constants
const (
	GetIP              APICommand = "get:ip"
	GetCN              APICommand = "get:cn"
	GetGeoIso          APICommand = "get:geo:iso"
	GetHosts           APICommand = "get:hosts"
	GetHostCookie      APICommand = "get:host:cookie"
	GetHostUnsetCookie APICommand = "get:host:unset-cookie"
	GetHostSession     APICommand = "get:host:session"
	ValHostCookie      APICommand = "val:host:cookie"
	ValHostCaptcha     APICommand = "val:host:captcha"
	SetHostSession     APICommand = "set:host:session"
	DelHostSession     APICommand = "del:host:session"
	DelHosts           APICommand = "del:hosts"

	// Future AppSec command
	ValHostAppSec APICommand = "val:host:appsec"
)

// Request data types for each command

// IPRequest for get:ip command
type IPRequest struct {
	IP string `gob:"ip"`
}

// CNRequest for get:cn command
type CNRequest struct {
	CountryCode string `gob:"country_code"`
	IP          string `gob:"ip"` // for metrics tracking
}

// GeoRequest for get:geo:iso command
type GeoRequest struct {
	IP string `gob:"ip"`
}

// HostsRequest for get:hosts command
type HostsRequest struct {
	Host string `gob:"host,omitempty"` // empty for list all hosts (admin only)
}

// HostCookieRequest for get:host:cookie command
type HostCookieRequest struct {
	Host string `gob:"host"`
	SSL  bool   `gob:"ssl"`
}

// HostCookieValidationRequest for val:host:cookie command
type HostCookieValidationRequest struct {
	Host   string `gob:"host"`
	Cookie string `gob:"cookie"`
}

// HostSessionRequest for get/set/del:host:session commands
type HostSessionRequest struct {
	Host  string `gob:"host"`
	UUID  string `gob:"uuid"`
	Key   string `gob:"key"`
	Value string `gob:"value,omitempty"` // only used for SET operations
}

// HostCaptchaValidationRequest for val:host:captcha command
type HostCaptchaValidationRequest struct {
	Host     string `gob:"host"`
	UUID     string `gob:"uuid"`
	Response string `gob:"response"`
}

// AppSecRequest for future val:host:appsec command
type AppSecRequest struct {
	Host    string      `gob:"host"`
	Method  string      `gob:"method"`
	URL     string      `gob:"url"`
	Headers http.Header `gob:"headers"`
	Body    []byte      `gob:"body"`

	// Additional context from SPOE
	RemoteIP  string `gob:"remote_ip"`
	UserAgent string `gob:"user_agent,omitempty"`
	Version   string `gob:"version,omitempty"` // HTTP version from HAProxy (e.g., "1.1", "2.0")
}

// RegisterGobTypes registers all message types for GOB encoding/decoding
// This must be called before any encoding/decoding operations
func RegisterGobTypes() {
	// Register request types
	gob.Register(IPRequest{})
	gob.Register(CNRequest{})
	gob.Register(GeoRequest{})
	gob.Register(HostsRequest{})
	gob.Register(HostCookieRequest{})
	gob.Register(HostCookieValidationRequest{})
	gob.Register(HostSessionRequest{})
	gob.Register(HostCaptchaValidationRequest{})
	gob.Register(AppSecRequest{})

	// Register response types that will be sent as interface{} through gob
	gob.Register(&types.HostResponse{})
	gob.Register(http.Cookie{})
	gob.Register(remediation.Remediation(0))

	// Register http.Header type used in AppSecRequest
	gob.Register(http.Header{})
}

// CommandFromString converts a string command to APICommand for backward compatibility
func CommandFromString(cmd string) APICommand {
	return APICommand(cmd)
}

// String returns the string representation of the command
func (c APICommand) String() string {
	return string(c)
}
