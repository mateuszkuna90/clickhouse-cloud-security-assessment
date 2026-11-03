//go:build windows

package aws

import "syscall"

// processAlive reports whether pid is a running process.
func processAlive(pid int) bool {
	const synchronize = 0x00100000
	h, err := syscall.OpenProcess(synchronize|processQueryLimitedInformation, false, uint32(pid))
	if err != nil {
		return false // no such process (or not ours to see)
	}
	defer syscall.CloseHandle(h)
	ev, err := syscall.WaitForSingleObject(h, 0)
	return err == nil && ev == uint32(syscall.WAIT_TIMEOUT)
}
