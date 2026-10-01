// Package cli implements the `pcdn` command (SPEC §16.2): a thin command line front end for the
// Pasargad CDN customer API (`/capi/v1`). Every command acts on the one site the API key belongs to.
//
// Configuration mirrors the Terraform provider: --endpoint / --api-key, or the PCDN_ENDPOINT /
// PCDN_API_KEY environment variables. The key is never printed (not in errors, not in --verbose).
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/namesissr/whmcs-cdn/cli/internal/client"
)

const (
	envEndpoint = "PCDN_ENDPOINT"
	envAPIKey   = "PCDN_API_KEY"
	envOutput   = "PCDN_OUTPUT"

	// exit codes
	exitOK    = 0
	exitError = 1 // API, network or input error
	exitUsage = 2 // bad command line
)

// Env is everything Run needs from the outside world (injectable for tests).
type Env struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// Getenv reads the environment (os.Getenv when nil).
	Getenv func(string) string
	// Version is the build version (ldflags).
	Version string
	// HTTPClient overrides the transport (tests).
	HTTPClient *http.Client
	// noSleep disables retry backoff waits (tests).
	noSleep bool
}

// usageError is a bad command line: printed with a hint to --help and exit code 2.
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

func usagef(format string, args ...any) error { return &usageError{msg: fmt.Sprintf(format, args...)} }

// globals are the options every command accepts, before or after the command words.
type globals struct {
	endpoint   string
	apiKey     string
	output     string
	timeout    time.Duration
	maxRetries int
	verbose    bool
}

// register binds the global flags to fs, using the values parsed so far as defaults (flag.*Var
// resets the target to the default, so re-registering on a sub-command FlagSet must not lose a
// value given before the command word).
func (g *globals) register(fs *flag.FlagSet) {
	fs.StringVar(&g.endpoint, "endpoint", g.endpoint, "controller URL, e.g. https://cdn-api.example.com (env "+envEndpoint+")")
	fs.StringVar(&g.apiKey, "api-key", g.apiKey, "customer API key pcdn_... (env "+envAPIKey+"; prefer the env variable: flags are visible in `ps`)")
	fs.StringVar(&g.output, "output", g.output, "output format: table or json (env "+envOutput+")")
	fs.StringVar(&g.output, "o", g.output, "shorthand for --output")
	fs.DurationVar(&g.timeout, "timeout", g.timeout, "timeout of one HTTP attempt")
	fs.IntVar(&g.maxRetries, "max-retries", g.maxRetries, "retries after the first attempt (429 always; 5xx/network errors only for idempotent calls)")
	fs.BoolVar(&g.verbose, "verbose", g.verbose, "log requests and retries to stderr (the API key is never logged)")
	fs.BoolVar(&g.verbose, "v", g.verbose, "shorthand for --verbose")
}

// app is one invocation.
type app struct {
	env     Env
	g       globals
	getenv  func(string) string
	version string
	stdout  io.Writer
	stderr  io.Writer
}

// Run executes the pcdn command line args (without the program name) and returns the exit code.
func Run(ctx context.Context, args []string, env Env) int {
	a := &app{env: env, getenv: env.Getenv, version: env.Version, stdout: env.Stdout, stderr: env.Stderr}
	if a.getenv == nil {
		a.getenv = os.Getenv
	}
	if a.version == "" {
		a.version = "dev"
	}
	if a.stdout == nil {
		a.stdout = io.Discard
	}
	if a.stderr == nil {
		a.stderr = io.Discard
	}
	a.g = globals{output: a.getenv(envOutput), timeout: client.DefaultTimeout, maxRetries: 5}
	if a.g.output == "" {
		a.g.output = "table"
	}
	err := a.run(ctx, args)
	if err == nil {
		return exitOK
	}
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	var ue *usageError
	if errors.As(err, &ue) {
		fmt.Fprintf(a.stderr, "pcdn: %s\nRun 'pcdn help' for usage.\n", ue.msg)
		return exitUsage
	}
	fmt.Fprintf(a.stderr, "Error: %s\n", err)
	var apiErr *client.APIError
	if errors.As(err, &apiErr) {
		if h := apiErr.Hint(); h != "" {
			fmt.Fprintf(a.stderr, "Hint: %s\n", h)
		}
	}
	return exitError
}

func (a *app) run(ctx context.Context, args []string) error {
	// global flags before the command word
	fs := a.flagSet("pcdn", topUsage)
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprint(a.stderr, topUsage)
		return usagef("no command given")
	}
	cmd, rest := rest[0], rest[1:]
	switch cmd {
	case "site":
		return a.cmdSite(ctx, rest)
	case "records", "record":
		return a.cmdRecords(ctx, rest)
	case "config":
		return a.cmdConfig(ctx, rest)
	case "purge":
		return a.cmdPurge(ctx, rest)
	case "analytics":
		return a.cmdAnalytics(ctx, rest)
	case "tunnel":
		return a.cmdTunnel(ctx, rest)
	case "version":
		fmt.Fprintf(a.stdout, "pcdn %s\n", a.version)
		return nil
	case "help":
		fmt.Fprint(a.stdout, topUsage)
		return nil
	}
	return usagef("unknown command %q", cmd)
}

// flagSet returns a FlagSet with the global flags registered and errors/usage going to stderr.
func (a *app) flagSet(name, usage string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	a.g.register(fs)
	fs.Usage = func() {
		fmt.Fprint(a.stderr, usage)
		fmt.Fprintln(a.stderr, "\nGlobal flags: --endpoint, --api-key, --output/-o table|json, --timeout, --max-retries, --verbose/-v")
	}
	return fs
}

// parse parses flags interspersed with positional arguments ("records update 12 --ttl 600") and
// returns the positionals. A bare "--" ends flag parsing.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, err
			}
			return nil, &usageError{msg: err.Error()}
		}
		rest := fs.Args()
		// flag.Parse consumed a "--" terminator if len(args) - consumed lands after it
		consumed := len(args) - len(rest)
		if consumed > 0 && args[consumed-1] == "--" {
			return append(pos, rest...), nil
		}
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

// parseExact parses fs and requires exactly n positionals.
func parseExact(fs *flag.FlagSet, args []string, n int, what string) ([]string, error) {
	pos, err := parse(fs, args)
	if err != nil {
		return nil, err
	}
	if len(pos) != n {
		if n == 0 {
			return nil, usagef("%s takes no arguments, got %q", what, strings.Join(pos, " "))
		}
		return nil, usagef("%s expects %d argument(s), got %d", what, n, len(pos))
	}
	return pos, nil
}

// client builds the API client from the flags / environment. It validates --output first so a
// typo fails before any request.
func (a *app) client() (*client.Client, error) {
	if err := a.checkOutput(); err != nil {
		return nil, err
	}
	endpoint := strings.TrimSpace(a.g.endpoint)
	if endpoint == "" {
		endpoint = strings.TrimSpace(a.getenv(envEndpoint))
	}
	if endpoint == "" {
		return nil, usagef("no controller endpoint: pass --endpoint or set %s (e.g. https://cdn-api.example.com)", envEndpoint)
	}
	key := strings.TrimSpace(a.g.apiKey)
	if key == "" {
		key = strings.TrimSpace(a.getenv(envAPIKey))
	}
	if key == "" {
		return nil, usagef("no API key: set %s (or pass --api-key) to a customer key pcdn_...", envAPIKey)
	}
	if a.g.maxRetries < 0 {
		return nil, usagef("--max-retries must be >= 0")
	}
	cfg := client.Config{
		Endpoint:   endpoint,
		APIKey:     key,
		UserAgent:  "pcdn-cli/" + a.version,
		Timeout:    a.g.timeout,
		MaxRetries: a.g.maxRetries,
		HTTPClient: a.env.HTTPClient,
	}
	if a.env.noSleep {
		cfg.MinBackoff, cfg.MaxBackoff = time.Millisecond, time.Millisecond
	}
	if a.g.verbose {
		cfg.Logf = func(format string, args ...any) { fmt.Fprintf(a.stderr, "[pcdn] "+format+"\n", args...) }
	}
	c, err := client.New(cfg)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (a *app) checkOutput() error {
	switch a.g.output {
	case "table", "json":
		return nil
	}
	return usagef("--output must be table or json, got %q", a.g.output)
}

func (a *app) jsonOut() bool { return a.g.output == "json" }

func (a *app) warn(format string, args ...any) {
	fmt.Fprintf(a.stderr, "Warning: "+format+"\n", args...)
}

const topUsage = `pcdn — command line client for the Pasargad CDN customer API (/capi/v1)

Usage:
  pcdn [global flags] <command> [arguments] [flags]

Commands:
  site                                   show the site of the API key (domain, status, plan, CNAME target)
  records list                           list DNS records                          (scope dns)
  records add --type T --content C ...   add a record                              (scope dns)
  records update <id> [--field ...]      change fields of a record                 (scope dns)
  records delete <id>                    delete a record                           (scope dns)
  config get <section>                   print a config section as JSON            (scope dns)
  config set <section> [file|-]          replace a section from a JSON file/stdin  (scope dns)
  purge --url U | --prefix P | --everything
                                         purge the cache                           (scope purge)
  analytics [--period 24h|7d|30d]        traffic analytics                         (scope stats)
  analytics live [--minutes N]           per-minute live analytics (1..1440)       (scope stats)
  tunnel quality [--hours N]             tunnel quality per path / edge (1..744)   (scope stats)
  tunnel usage [--days N]                daily tunnel usage + month forecast       (scope stats)
  tunnel health                          origin health of the tunnel paths         (scope stats)
  version                                print the version

Global flags (anywhere on the line):
  --endpoint URL      controller URL (env PCDN_ENDPOINT); https only, http only for localhost
  --api-key KEY       customer API key (env PCDN_API_KEY — preferred; never printed)
  -o, --output FMT    table (default) or json (env PCDN_OUTPUT)
  --timeout D         timeout of one HTTP attempt (default 30s)
  --max-retries N     retries (default 5): 429 always, 5xx/network errors only for idempotent calls
  -v, --verbose       log requests and retries to stderr

Run 'pcdn <command> -h' for the flags of a command.
`
