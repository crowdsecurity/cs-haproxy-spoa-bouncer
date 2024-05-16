package apiPermission

const (
	WorkerPermission ApiPermission = iota
	AdminPermission
)

type ApiPermission int
