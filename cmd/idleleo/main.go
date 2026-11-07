// Command idleleo is the Phase 01 Go candidate. It is not installed over the
// Bash manager and does not touch a real VPS in this phase.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	code := cli.Run(ctx, os.Args[1:], cli.Options{
		In:  os.Stdin,
		Out: os.Stdout,
		Err: os.Stderr,
		TTY: isTTY(os.Stdin) && isTTY(os.Stdout),
	})
	os.Exit(code)
}

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
