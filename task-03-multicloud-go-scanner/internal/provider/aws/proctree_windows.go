//go:build windows

package aws

import (
	"os/exec"
	"syscall"
	"unsafe"
)

// containProcessTree makes cancellation kill the helper's descendants
// before the helper itself. credential_process runs as cmd.exe /C <command>,
// so the real helper is a child of cmd.exe, and killing cmd.exe alone (the
// exec.CommandContext default) would leave it running.
//
// Descendants are found with process snapshots (CreateToolhelp32Snapshot).
// A parent link is trusted only if the child was created no earlier than
// its parent, so a reused PID of an unrelated process is not followed.
// Creation times of every process found are remembered, so a child whose
// parent was already killed is still recognised in the next round. The
// snapshot is repeated so that a child started during the walk is also
// found. A descendant started after the last round is not covered;
// WaitDelay still bounds cmd.Wait.
func containProcessTree(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		killDescendants(uint32(cmd.Process.Pid))
		_ = cmd.Process.Kill()
		return nil
	}
}

const (
	processQueryLimitedInformation = 0x1000
	snapshotRounds                 = 3
)

func killDescendants(root uint32) {
	rootCreated, ok := createdAt(root)
	if !ok {
		return
	}
	known := map[uint32]int64{root: rootCreated}
	for range snapshotRounds {
		found := newDescendants(known)
		if len(found) == 0 {
			return
		}
		for _, pid := range found {
			terminate(pid)
		}
	}
}

// newDescendants adds to known every running process that descends from a
// known process, and returns the ones added.
func newDescendants(known map[uint32]int64) []uint32 {
	parents := snapshotParents()
	var out []uint32
	for changed := true; changed; {
		changed = false
		for pid, ppid := range parents {
			if _, ok := known[pid]; ok || pid == ppid {
				continue
			}
			parentCreated, ok := known[ppid]
			if !ok {
				continue
			}
			created, ok := createdAt(pid)
			if !ok || created < parentCreated {
				continue // exited, or a reused PID: not a real descendant
			}
			known[pid] = created
			out = append(out, pid)
			changed = true
		}
	}
	return out
}

// snapshotParents maps every running PID to its parent PID.
func snapshotParents() map[uint32]uint32 {
	snap, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer syscall.CloseHandle(snap)
	var e syscall.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	if syscall.Process32First(snap, &e) != nil {
		return nil
	}
	out := map[uint32]uint32{}
	for {
		out[e.ProcessID] = e.ParentProcessID
		if syscall.Process32Next(snap, &e) != nil {
			return out
		}
	}
}

// createdAt returns a process's creation time in 100ns units.
func createdAt(pid uint32) (int64, bool) {
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, pid)
	if err != nil {
		return 0, false
	}
	defer syscall.CloseHandle(h)
	var created, exited, kernel, user syscall.Filetime
	if syscall.GetProcessTimes(h, &created, &exited, &kernel, &user) != nil {
		return 0, false
	}
	return created.Nanoseconds() / 100, true
}

func terminate(pid uint32) {
	h, err := syscall.OpenProcess(syscall.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return
	}
	defer syscall.CloseHandle(h)
	_ = syscall.TerminateProcess(h, 1)
}
