//go:build !unix && !windows

package aws

func processAlive(int) bool { return false }
