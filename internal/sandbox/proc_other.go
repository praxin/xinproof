//go:build !unix

package sandbox

// processAlive can't be checked portably here, so orphans are left to the TTL.
func processAlive(pid int) bool { return true }
