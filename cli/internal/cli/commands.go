package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/namesissr/whmcs-cdn/cli/internal/client"
)

// ---------------------------------------------------------------- site

func (a *app) cmdSite(ctx context.Context, args []string) error {
	fs := a.flagSet("site", "Usage: pcdn site\n\nShows the site the API key belongs to (works with any key scope).\n")
	if _, err := parseExact(fs, args, 0, "site"); err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	raw, err := c.SiteRaw(ctx)
	if err != nil {
		return err
	}
	if a.jsonOut() {
		return a.printJSON(raw)
	}
	return renderSite(a.stdout, raw)
}

// ---------------------------------------------------------------- records

const recordsUsage = `Usage:
  pcdn records list
  pcdn records add --type A --content 203.0.113.10 [--name www] [--ttl 300] [--proxied] ...
  pcdn records update <id> [--name N] [--type T] [--content C] [--ttl S] [--proxied=false] ...
  pcdn records delete <id>

Record flags (add / update):
  --name N            relative name, "@" for the apex (add default "@")
  --type T            A, AAAA, CNAME, MX, TXT, ... (required for add)
  --content C         value (required for add)
  --ttl S             TTL in seconds, 60..86400 (add default 300)
  --priority N        MX/SRV priority ("none" clears it)
  --proxied           serve through the CDN (use --proxied=false to turn off)
  --pool P            origin pool name ("none" clears it)
  --origin-port N     origin port 1..65535 ("none" clears it)
  --health-check      enable the origin health check (--health-check=false to turn off)
  --health-port N     health check port ("none" clears it)
  --weight N          weight 0..100 in a weighted/failover set ("none" clears it)
  --health-protocol P controller probe: tcp, http or https ("none" clears it)
  --health-path P     probe path for http(s), e.g. /healthz ("none" clears it)

'update' reads the record, applies only the flags you pass and sends the full record back
(fields it does not know are kept as stored).
`

func (a *app) cmdRecords(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(a.stderr, recordsUsage)
		if len(args) == 0 {
			return usagef("records needs a sub-command: list, add, update or delete")
		}
		return flag.ErrHelp
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list", "ls":
		return a.recordsList(ctx, rest)
	case "add", "create":
		return a.recordsAdd(ctx, rest)
	case "update", "set":
		return a.recordsUpdate(ctx, rest)
	case "delete", "rm", "remove":
		return a.recordsDelete(ctx, rest)
	}
	return usagef("unknown records sub-command %q (list, add, update, delete)", sub)
}

func (a *app) recordsList(ctx context.Context, args []string) error {
	fs := a.flagSet("records list", recordsUsage)
	if _, err := parseExact(fs, args, 0, "records list"); err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	raw, err := c.ListRecordsRaw(ctx)
	if err != nil {
		return err
	}
	if a.jsonOut() {
		return a.printJSON(raw)
	}
	var recs []client.Record
	if err := json.Unmarshal(raw, &recs); err != nil {
		return fmt.Errorf("unexpected /records reply: %v", err)
	}
	renderRecords(a.stdout, recs)
	return nil
}

// optInt is a nullable integer flag: a number, or "none"/"null" for null.
type optInt struct {
	v   *int64
	set bool
}

func (o *optInt) String() string {
	if o == nil || o.v == nil {
		return ""
	}
	return strconv.FormatInt(*o.v, 10)
}

func (o *optInt) Set(s string) error {
	o.set = true
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "none", "null":
		o.v = nil
		return nil
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return fmt.Errorf("not a number (use \"none\" to clear)")
	}
	o.v = &n
	return nil
}

// optStr is a nullable string flag: "none"/"null" (or empty) means null.
type optStr struct {
	v   *string
	set bool
}

func (o *optStr) String() string {
	if o == nil || o.v == nil {
		return ""
	}
	return *o.v
}

func (o *optStr) Set(s string) error {
	o.set = true
	s = strings.TrimSpace(s)
	switch strings.ToLower(s) {
	case "", "none", "null":
		o.v = nil
		return nil
	}
	o.v = &s
	return nil
}

type recordFlags struct {
	name, typ, content          string
	ttl                         int64
	proxied, healthCheck        bool
	priority, originPort, port  optInt
	weight                      optInt
	pool, healthProto, hlthPath optStr
}

func (r *recordFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&r.name, "name", "@", `relative record name ("@" = apex)`)
	fs.StringVar(&r.typ, "type", "", "record type (A, AAAA, CNAME, MX, TXT, ...)")
	fs.StringVar(&r.content, "content", "", "record value")
	fs.Int64Var(&r.ttl, "ttl", 300, "TTL in seconds (60..86400)")
	fs.BoolVar(&r.proxied, "proxied", false, "serve through the CDN")
	fs.BoolVar(&r.healthCheck, "health-check", false, "enable the origin health check")
	fs.Var(&r.priority, "priority", `priority (MX/SRV), "none" clears`)
	fs.Var(&r.originPort, "origin-port", `origin port, "none" clears`)
	fs.Var(&r.port, "health-port", `health check port, "none" clears`)
	fs.Var(&r.pool, "pool", `origin pool, "none" clears`)
	fs.Var(&r.weight, "weight", `weight 0..100 of a weighted/failover set, "none" clears`)
	fs.Var(&r.healthProto, "health-protocol", `health probe protocol tcp|http|https, "none" clears`)
	fs.Var(&r.hlthPath, "health-path", `health probe path for http(s), e.g. /healthz, "none" clears`)
}

// recordFields maps each record flag to its JSON field.
var recordFields = map[string]string{"name": "name", "type": "type", "content": "content", "ttl": "ttl",
	"proxied": "proxied", "health-check": "health_check", "priority": "priority", "origin-port": "origin_port",
	"health-port": "health_port", "pool": "pool", "weight": "weight", "health-protocol": "health_protocol",
	"health-path": "health_path"}

// apply sets the fields of the flags the user actually passed on body (a RecordIn document).
func (r *recordFlags) apply(fs *flag.FlagSet, body map[string]any) {
	fs.Visit(func(f *flag.Flag) {
		var v any
		switch f.Name {
		case "name":
			v = strings.TrimSpace(r.name)
		case "type":
			v = strings.ToUpper(strings.TrimSpace(r.typ))
		case "content":
			v = r.content
		case "ttl":
			v = r.ttl
		case "proxied":
			v = r.proxied
		case "health-check":
			v = r.healthCheck
		case "priority":
			v = r.priority.v
		case "origin-port":
			v = r.originPort.v
		case "health-port":
			v = r.port.v
		case "weight":
			v = r.weight.v
		case "pool":
			v = r.pool.v
		case "health-protocol":
			if r.healthProto.v != nil {
				l := strings.ToLower(*r.healthProto.v)
				v = &l
			} else {
				v = nil
			}
		case "health-path":
			v = r.hlthPath.v
		default:
			return
		}
		body[recordFields[f.Name]] = v
	})
}

func anyRecordFlag(fs *flag.FlagSet) bool {
	found := false
	fs.Visit(func(f *flag.Flag) { _, ok := recordFields[f.Name]; found = found || ok })
	return found
}

func (a *app) recordsAdd(ctx context.Context, args []string) error {
	fs := a.flagSet("records add", recordsUsage)
	var rf recordFlags
	rf.register(fs)
	if _, err := parseExact(fs, args, 0, "records add"); err != nil {
		return err
	}
	// fields not given are left out, so the controller's defaults apply
	body := map[string]any{"name": "@", "ttl": 300}
	rf.apply(fs, body)
	typ, _ := body["type"].(string)
	content, _ := body["content"].(string)
	if typ == "" || strings.TrimSpace(content) == "" {
		return usagef("records add needs --type and --content")
	}
	if n, _ := body["name"].(string); n == "" {
		body["name"] = "@"
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	raw, err := c.CreateRecordRaw(ctx, body)
	if err != nil {
		return err
	}
	return a.recordResult(raw)
}

// readOnlyRecordFields are fields of a listed record that are not part of RecordIn.
var readOnlyRecordFields = []string{"id", "health", "dns_error"}

func (a *app) recordsUpdate(ctx context.Context, args []string) error {
	fs := a.flagSet("records update", recordsUsage)
	var rf recordFlags
	rf.register(fs)
	pos, err := parseExact(fs, args, 1, "records update")
	if err != nil {
		return err
	}
	id, err := recordID(pos[0])
	if err != nil {
		return err
	}
	if !anyRecordFlag(fs) {
		return usagef("records update: pass at least one field flag (--name, --type, --content, --ttl, ...)")
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	// PATCH takes the FULL record: start from the stored one as a generic document, so fields this
	// CLI version does not know about (added to the API later) are sent back unchanged, not reset
	cur, err := c.GetRecordRaw(ctx, id)
	if err != nil {
		return err
	}
	body := map[string]any{}
	for k, v := range cur {
		body[k] = v
	}
	for _, k := range readOnlyRecordFields {
		delete(body, k)
	}
	rf.apply(fs, body)
	raw, err := c.UpdateRecordRaw(ctx, id, body)
	if err != nil {
		return err
	}
	return a.recordResult(raw)
}

func recordID(s string) (int64, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || id <= 0 {
		return 0, usagef("record id must be a positive number, got %q (see 'pcdn records list')", s)
	}
	return id, nil
}

func (a *app) recordResult(raw json.RawMessage) error {
	var res client.RecordResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return fmt.Errorf("unexpected record reply: %v", err)
	}
	if res.DNSError != nil && *res.DNSError != "" {
		a.warn("record saved, but DNS sync failed (the controller retries): %s", *res.DNSError)
	}
	if a.jsonOut() {
		return a.printJSON(raw)
	}
	renderRecords(a.stdout, []client.Record{res.Record})
	return nil
}

func (a *app) recordsDelete(ctx context.Context, args []string) error {
	fs := a.flagSet("records delete", recordsUsage)
	pos, err := parseExact(fs, args, 1, "records delete")
	if err != nil {
		return err
	}
	id, err := recordID(pos[0])
	if err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	dnsErr, err := c.DeleteRecord(ctx, id)
	if err != nil {
		return err
	}
	if dnsErr != nil && *dnsErr != "" {
		a.warn("record deleted, but DNS sync failed (the controller retries): %s", *dnsErr)
	}
	if a.jsonOut() {
		return a.printValue(map[string]any{"ok": true, "deleted": id, "dns_error": dnsErr})
	}
	fmt.Fprintf(a.stdout, "Deleted record %d.\n", id)
	return nil
}

// ---------------------------------------------------------------- config

const configUsage = `Usage:
  pcdn config get <section>             print the section as JSON
  pcdn config set <section> [file|-]    replace the section with a JSON object from file (or stdin)
  pcdn config history [--limit N] [--before V]
                                        settings history: who changed which sections when (scope config)
  pcdn config diff <version> [--against current|V] [--section S]
                                        what changed between <version> and the current config (or V)
  pcdn config restore <version> [--section S ...] [--dry-run]
                                        restore sections of an older version (all that differ by default);
                                        --dry-run shows what would be applied / dropped without writing

The section document is always JSON (independent of --output), so
  pcdn config get waf > waf.json && $EDITOR waf.json && pcdn config set waf waf.json
round-trips. Non-blocking warnings of the controller are printed to stderr. For the webhooks
section the reply may contain new signing secrets: they are shown only once.

History values are redacted by the controller (secrets, auth headers): a restore never changes stored
secrets, and sections the current plan does not allow are dropped (listed in the reply).
`

var sectionRe = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

func (a *app) cmdConfig(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(a.stderr, configUsage)
		if len(args) == 0 {
			return usagef("config needs a sub-command: get, set, history, diff or restore")
		}
		return flag.ErrHelp
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "get":
		fs := a.flagSet("config get", configUsage)
		pos, err := parseExact(fs, rest, 1, "config get")
		if err != nil {
			return err
		}
		if !sectionRe.MatchString(pos[0]) {
			return usagef("invalid section name %q", pos[0])
		}
		c, err := a.client()
		if err != nil {
			return err
		}
		raw, err := c.GetSection(ctx, pos[0])
		if err != nil {
			return err
		}
		return a.printJSON(raw)
	case "set", "put":
		fs := a.flagSet("config set", configUsage)
		pos, err := parse(fs, rest)
		if err != nil {
			return err
		}
		if len(pos) < 1 || len(pos) > 2 {
			return usagef("config set expects <section> [file|-]")
		}
		if !sectionRe.MatchString(pos[0]) {
			return usagef("invalid section name %q", pos[0])
		}
		src := "-"
		if len(pos) == 2 {
			src = pos[1]
		}
		body, err := a.readJSONObject(src)
		if err != nil {
			return err
		}
		c, err := a.client()
		if err != nil {
			return err
		}
		res, err := c.PutSection(ctx, pos[0], body)
		if err != nil {
			return err
		}
		for _, w := range res.Warnings {
			a.warn("%s", w)
		}
		if !a.jsonOut() {
			fmt.Fprintf(a.stderr, "Section %q updated.\n", pos[0])
		}
		return a.printJSON(res.Body)
	case "history":
		return a.configHistory(ctx, rest)
	case "diff":
		return a.configDiff(ctx, rest)
	case "restore":
		return a.configRestore(ctx, rest)
	}
	return usagef("unknown config sub-command %q (get, set, history, diff, restore)", sub)
}

// configVersion parses a history version number (1..999999999).
func configVersion(s string) (int64, error) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 1 || n > 999999999 {
		return 0, usagef("invalid version %q (a positive number from 'pcdn config history')", s)
	}
	return n, nil
}

func (a *app) configHistory(ctx context.Context, args []string) error {
	fs := a.flagSet("config history", configUsage)
	limit := fs.Int("limit", 50, "versions to show (1..200)")
	before := fs.Int64("before", 0, "only versions older than this one (paging)")
	if _, err := parseExact(fs, args, 0, "config history"); err != nil {
		return err
	}
	if *limit < 1 || *limit > 200 {
		return usagef("--limit must be between 1 and 200")
	}
	if *before < 0 || *before > 999999999 {
		return usagef("--before must be a version number")
	}
	return a.fetchAndRender(func(c *client.Client) (json.RawMessage, error) {
		return c.ConfigHistory(ctx, *limit, *before)
	}, renderHistory)
}

func (a *app) configDiff(ctx context.Context, args []string) error {
	fs := a.flagSet("config diff", configUsage)
	against := fs.String("against", "current", "compare with: current or a version number")
	section := fs.String("section", "", "only this section")
	pos, err := parseExact(fs, args, 1, "config diff")
	if err != nil {
		return err
	}
	v, err := configVersion(pos[0])
	if err != nil {
		return err
	}
	if *against != "current" {
		if _, err := configVersion(*against); err != nil {
			return usagef("--against must be current or a version number")
		}
	}
	if *section != "" && !sectionRe.MatchString(*section) {
		return usagef("invalid section name %q", *section)
	}
	return a.fetchAndRender(func(c *client.Client) (json.RawMessage, error) {
		return c.ConfigDiff(ctx, v, *against, *section)
	}, renderDiff)
}

func (a *app) configRestore(ctx context.Context, args []string) error {
	fs := a.flagSet("config restore", configUsage)
	var sections stringList
	fs.Var(&sections, "section", "section to restore (repeatable; default: every section that differs)")
	dry := fs.Bool("dry-run", false, "show what would be restored / dropped without writing")
	pos, err := parseExact(fs, args, 1, "config restore")
	if err != nil {
		return err
	}
	v, err := configVersion(pos[0])
	if err != nil {
		return err
	}
	in := client.RestoreInput{DryRun: *dry}
	for _, s := range sections {
		for _, part := range strings.Split(s, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if !sectionRe.MatchString(part) {
				return usagef("invalid section name %q", part)
			}
			in.Sections = append(in.Sections, part)
		}
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	raw, err := c.ConfigRestore(ctx, v, in)
	if err != nil {
		return err
	}
	if a.jsonOut() {
		return a.printJSON(raw)
	}
	return renderRestore(a.stdout, raw, *dry)
}

// readJSONObject reads src ("-" = stdin) and requires one JSON object.
func (a *app) readJSONObject(src string) (json.RawMessage, error) {
	var (
		data []byte
		err  error
		name = src
	)
	if src == "-" {
		name = "stdin"
		if a.env.Stdin == nil {
			return nil, usagef("no input: give a file name or pipe JSON to stdin")
		}
		data, err = io.ReadAll(io.LimitReader(a.env.Stdin, 8<<20))
	} else {
		data, err = os.ReadFile(src)
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %v", name, err)
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")) // tolerate a UTF-8 BOM from Windows editors
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("%s is empty: expected a JSON object", name)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &obj); err != nil || obj == nil {
		if err == nil {
			err = fmt.Errorf("null")
		}
		return nil, fmt.Errorf("%s is not a JSON object: %v", name, err)
	}
	return json.RawMessage(trimmed), nil
}

// ---------------------------------------------------------------- purge

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

const purgeUsage = `Usage:
  pcdn purge --url https://example.com/a.css [--url ...]
  pcdn purge --prefix https://example.com/static/ [--prefix ...]
  pcdn purge --everything

--url and --prefix may be repeated and combined; --everything cannot be combined with them.
`

func (a *app) cmdPurge(ctx context.Context, args []string) error {
	fs := a.flagSet("purge", purgeUsage)
	var urls, prefixes stringList
	var everything bool
	fs.Var(&urls, "url", "URL to purge (repeatable)")
	fs.Var(&prefixes, "prefix", "URL prefix to purge (repeatable)")
	fs.BoolVar(&everything, "everything", false, "purge the whole cache of the site")
	if _, err := parseExact(fs, args, 0, "purge"); err != nil {
		return err
	}
	if everything && (len(urls) > 0 || len(prefixes) > 0) {
		return usagef("--everything cannot be combined with --url / --prefix")
	}
	if !everything && len(urls) == 0 && len(prefixes) == 0 {
		return usagef("purge needs --url, --prefix or --everything")
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	raw, err := c.PurgeRaw(ctx, client.PurgeInput{URLs: urls, Prefixes: prefixes, Everything: everything})
	if err != nil {
		return err
	}
	if a.jsonOut() {
		return a.printJSON(raw)
	}
	var res client.PurgeResult
	_ = json.Unmarshal(raw, &res)
	if q := res.QueuedString(); q == "all" {
		fmt.Fprintln(a.stdout, "Purge queued: entire cache.")
	} else {
		fmt.Fprintf(a.stdout, "Purge queued: %s item(s).\n", q)
	}
	return nil
}

// ---------------------------------------------------------------- analytics

const analyticsUsage = `Usage:
  pcdn analytics [--period 24h|7d|30d]   totals, top countries / paths / status codes
  pcdn analytics live [--minutes N]      per-minute series of the last N minutes (1..1440, default 60)
`

func (a *app) cmdAnalytics(ctx context.Context, args []string) error {
	if len(args) > 0 && args[0] == "live" {
		fs := a.flagSet("analytics live", analyticsUsage)
		minutes := fs.Int("minutes", 60, "minutes to show (1..1440)")
		if _, err := parseExact(fs, args[1:], 0, "analytics live"); err != nil {
			return err
		}
		if *minutes < 1 || *minutes > 1440 {
			return usagef("--minutes must be between 1 and 1440")
		}
		c, err := a.client()
		if err != nil {
			return err
		}
		raw, err := c.AnalyticsLive(ctx, *minutes)
		if err != nil {
			return err
		}
		if a.jsonOut() {
			return a.printJSON(raw)
		}
		return renderLive(a.stdout, raw)
	}
	fs := a.flagSet("analytics", analyticsUsage)
	period := fs.String("period", "24h", "24h, 7d or 30d")
	if _, err := parseExact(fs, args, 0, "analytics"); err != nil {
		return err
	}
	switch *period {
	case "24h", "7d", "30d":
	default:
		return usagef("--period must be 24h, 7d or 30d")
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	raw, err := c.Analytics(ctx, *period)
	if err != nil {
		return err
	}
	if a.jsonOut() {
		return a.printJSON(raw)
	}
	return renderAnalytics(a.stdout, raw)
}

// ---------------------------------------------------------------- tunnel

const tunnelUsage = `Usage:
  pcdn tunnel quality [--hours N]   per-path / per-edge quality of the last N hours (1..744, default 24)
  pcdn tunnel usage [--days N]      daily tunnel traffic of the last N days (1..90, default 30) + month forecast
  pcdn tunnel health                origin health of the tunnel paths as seen by the edges
`

func (a *app) cmdTunnel(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(a.stderr, tunnelUsage)
		if len(args) == 0 {
			return usagef("tunnel needs a sub-command: quality, usage or health")
		}
		return flag.ErrHelp
	}
	sub, rest := args[0], args[1:]
	fs := a.flagSet("tunnel "+sub, tunnelUsage)
	switch sub {
	case "quality":
		hours := fs.Int("hours", 24, "hours to cover (1..744)")
		if _, err := parseExact(fs, rest, 0, "tunnel quality"); err != nil {
			return err
		}
		if *hours < 1 || *hours > 744 {
			return usagef("--hours must be between 1 and 744")
		}
		return a.fetchAndRender(func(c *client.Client) (json.RawMessage, error) { return c.TunnelQuality(ctx, *hours) }, renderQuality)
	case "usage":
		days := fs.Int("days", 30, "days to cover (1..90)")
		if _, err := parseExact(fs, rest, 0, "tunnel usage"); err != nil {
			return err
		}
		if *days < 1 || *days > 90 {
			return usagef("--days must be between 1 and 90")
		}
		return a.fetchAndRender(func(c *client.Client) (json.RawMessage, error) { return c.TunnelUsage(ctx, *days) }, renderUsage)
	case "health":
		if _, err := parseExact(fs, rest, 0, "tunnel health"); err != nil {
			return err
		}
		return a.fetchAndRender(func(c *client.Client) (json.RawMessage, error) { return c.TunnelHealth(ctx) }, renderHealth)
	}
	return usagef("unknown tunnel sub-command %q (quality, usage, health)", sub)
}

func (a *app) fetchAndRender(get func(*client.Client) (json.RawMessage, error), render func(io.Writer, json.RawMessage) error) error {
	c, err := a.client()
	if err != nil {
		return err
	}
	raw, err := get(c)
	if err != nil {
		return err
	}
	if a.jsonOut() {
		return a.printJSON(raw)
	}
	return render(a.stdout, raw)
}
