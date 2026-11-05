//go:build !unix && !windows

package aws

import "os/exec"

// containProcessTree keeps exec.CommandContext's default cancellation (kill
// the helper process) on platforms without process groups or the Windows
// process snapshot API. WaitDelay still bounds cmd.Wait.
func containProcessTree(*exec.Cmd) {}
