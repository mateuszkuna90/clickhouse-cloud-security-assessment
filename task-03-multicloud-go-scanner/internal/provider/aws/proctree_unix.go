//go:build unix

package aws

import (
	"os/exec"
	"syscall"
)

// containProcessTree starts the helper in a new process group and, on
// cancellation, kills the whole group, so children the shell or helper
// started are stopped too. A descendant that leaves the group on purpose
// (setsid/setpgid) is not covered; WaitDelay still bounds cmd.Wait.
func containProcessTree(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// The group ID is the helper's PID (Setpgid with Pgid 0).
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		return nil
	}
}
