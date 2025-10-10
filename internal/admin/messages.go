package admin

// APICommand represents different admin API commands
type APICommand string

// All admin API commands as constants
const (
	GetIP          APICommand = "get:ip"
	GetCN          APICommand = "get:cn"
	GetGeoIso      APICommand = "get:geo:iso"
	GetHosts       APICommand = "get:hosts"
	GetHostCookie  APICommand = "get:host:cookie"
	GetHostSession APICommand = "get:host:session"
	ValHostCookie  APICommand = "val:host:cookie"
	ValHostCaptcha APICommand = "val:host:captcha"
	SetHostSession APICommand = "set:host:session"
	DelHostSession APICommand = "del:host:session"
	DelHosts       APICommand = "del:hosts"

	// Future AppSec command
	ValHostAppSec APICommand = "val:host:appsec"
)

// CommandFromString converts a string command to APICommand
func CommandFromString(cmd string) APICommand {
	return APICommand(cmd)
}

// String returns the string representation of the command
func (c APICommand) String() string {
	return string(c)
}
