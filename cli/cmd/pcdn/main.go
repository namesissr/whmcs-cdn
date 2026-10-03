// Command pcdn is the command line client for the Pasargad CDN customer API (SPEC §16.2).
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/namesissr/whmcs-cdn/cli/internal/cli"
)

// Set at build time by GoReleaser: -X main.version=... -X main.commit=...
var (
	version = "dev"
	commit  = ""
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	v := version
	if commit != "" {
		v += " (" + commit + ")"
	}
	code := cli.Run(ctx, os.Args[1:], cli.Env{
		Stdin:   os.Stdin,
		Stdout:  os.Stdout,
		Stderr:  os.Stderr,
		Version: v,
	})
	stop()
	os.Exit(code)
}
