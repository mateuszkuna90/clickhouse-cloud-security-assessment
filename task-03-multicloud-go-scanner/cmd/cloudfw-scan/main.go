// Command cloudfw-scan scans AWS Security Groups, GCP VPC firewall rules and
// Azure Network Security Groups for inbound rules open to 0.0.0.0/0 and
// writes a JSON report. See the README for usage and exit codes.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/cli"
)

func main() {
	os.Exit(run())
}

// run wires the process to the command. An interrupt (Ctrl-C or SIGTERM)
// cancels the scan; scopes still running fail with kind timeout and the
// report is still written (exit 2).
func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return cli.Run(ctx, os.Args[1:], cli.DefaultEnv())
}
