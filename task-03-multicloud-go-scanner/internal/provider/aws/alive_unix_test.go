//go:build unix

package aws

import "syscall"

// processAlive reports whether pid is a running process. Killed helpers
// are reaped (by exec.Cmd.Wait or, for orphaned children, by init), so a
// dead helper does not linger as a zombie for long.
func processAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}
