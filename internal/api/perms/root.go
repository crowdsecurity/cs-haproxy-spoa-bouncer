package apipermission

const (
	WorkerPermission APIPermission = iota
	AdminPermission
)

type APIPermission int
