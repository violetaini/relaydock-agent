package chitanda

import "github.com/violetaini/chitanda/pkg/server"

// Bound idle receive buffers and goroutines across physical associations.
const maxNativeUDPRoutes = server.MaxUDPTargets
const maxNativeUDPUserRoutes = server.MaxUserUDPTargets

func reserveNativeRoute(user string) (func(), bool) {
	return server.ReserveUDPTarget(user)
}
