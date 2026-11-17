package engine

import "strings"

// Hooks let tests inject faults at precise points. Production code leaves them nil.
type Hooks struct {
	// BeforeRestore runs with the sandbox container's name just before the restore starts.
	BeforeRestore func(container string)
}

// sandboxFaults are tool messages that mean the sandbox broke, not the backup:
// the database server crashed or was killed, or the sandbox ran out of space.
var sandboxFaults = []struct{ needle, reason string }{
	{"no space left on device", "the sandbox ran out of disk space (use a bigger --tmpfs, or none)"},
	{"server closed the connection unexpectedly", "the sandbox database crashed during restore (out of memory? raise --memory)"},
	{"terminating connection because of crash of another server process", "the sandbox database crashed during restore (out of memory? raise --memory)"},
	{"the database system is in recovery mode", "the sandbox database crashed during restore (out of memory? raise --memory)"},
	{"the database system is shutting down", "the sandbox database shut down during restore"},
	{"lost connection to mysql server", "the sandbox database crashed during restore (out of memory? raise --memory)"},
	{"mysql server has gone away", "the sandbox database crashed during restore (out of memory? raise --memory)"},
	{"can't connect to mysql server", "the sandbox database stopped accepting connections during restore"},
	{"can't connect to local server", "the sandbox database stopped accepting connections during restore"},
	{"got error 28 ", "the sandbox ran out of disk space (use a bigger --tmpfs, or none)"},
	// MongoDB refuses index builds with less than 500 MB free.
	{"(outofdiskspace)", "the sandbox ran out of disk space (MongoDB needs 500 MB free to build indexes; use a bigger --tmpfs, or none)"},
}

// SandboxFault returns why a tool failure was the sandbox's fault (→ ERROR),
// or "" if it should be blamed on the backup (→ FAIL).
func SandboxFault(stderr string) string {
	low := strings.ToLower(stderr)
	for _, f := range sandboxFaults {
		if strings.Contains(low, f.needle) {
			return f.reason
		}
	}
	return ""
}
