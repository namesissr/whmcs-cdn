package cli

import (
	"strings"
	"testing"
)

const historyJSON = `{"versions":[
 {"version":14,"at":"2026-10-02T08:30:00Z","actor":{"kind":"api_key","label":"ci","id":"7"},"source":"capi",
  "sections":["cache","waf"],"restored_from":null,"restorable":true},
 {"version":13,"at":"2026-10-01T10:00:00Z","actor":{"kind":"collaborator","label":null,"id":"55"},"source":"api",
  "sections":["firewall"],"restored_from":9,"restorable":true},
 {"version":12,"at":"2026-09-30T10:00:00Z","actor":{"kind":"system","label":"waf_learning","id":null},
  "source":"waf_learning","sections":["functions"],"restored_from":null,"restorable":false}],
 "current":14,"retention":{"max_versions":100,"days":90}}`

func TestConfigHistory(t *testing.T) {
	f := newFake()
	f.on("GET", "/capi/v1/config/history", fakeReply{body: historyJSON})
	r := run(t, f, "", nil, "config", "history", "--limit", "20", "--before", "15")
	must(t, r, 0)
	for _, want := range []string{"VERSION", "14", "2026-10-02 08:30:00", "API key ci", "current",
		"collaborator #55", "restored from 9", "system (waf_learning)", "not restorable", "cache,waf",
		"newest 100 versions younger than 90 days"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("missing %q in:\n%s", want, r.stdout)
		}
	}
	c := f.callList()[0]
	if c.query != "before=15&limit=20" {
		t.Errorf("query %q", c.query)
	}
	r = run(t, f, "", nil, "config", "history", "-o", "json")
	must(t, r, 0)
	if !strings.Contains(r.stdout, `"current": 14`) {
		t.Errorf("json: %s", r.stdout)
	}
	if q := f.callList()[1].query; q != "limit=50" {
		t.Errorf("default query %q", q)
	}
	f.on("GET", "/capi/v1/config/history", fakeReply{body: `{"versions":[],"current":null}`})
	r = run(t, f, "", nil, "config", "history")
	must(t, r, 0)
	if !strings.Contains(r.stdout, "No settings history") {
		t.Error(r.stdout)
	}
	n := len(f.callList())
	for _, args := range [][]string{{"--limit", "0"}, {"--limit", "201"}, {"--before", "-1"}, {"extra"}} {
		must(t, run(t, f, "", nil, append([]string{"config", "history"}, args...)...), 2)
	}
	if len(f.callList()) != n {
		t.Error("invalid input was sent")
	}
}

func TestConfigDiff(t *testing.T) {
	f := newFake()
	f.on("GET", "/capi/v1/config/history/9/diff", fakeReply{body: `{"from":9,"to":"current","redacted":true,
	 "sections":{"waf":[{"op":"replace","path":"/mode","old":"log","new":"block"}],
	  "headers":[{"op":"replace","path":"/rules/[id=h1]/value","old":"[redacted]","new":"[redacted]","redacted":true}],
	  "cache":[{"op":"add","path":"/rules/0","new":{"path":"/static/*","ttl":3600}},
	           {"op":"remove","path":"/rules/1","old":{"path":"/x"}}],
	  "dns":[]}}`})
	r := run(t, f, "", nil, "config", "diff", "9")
	must(t, r, 0)
	for _, want := range []string{"Changes from version 9 to current", "[waf]", `~ /mode: "log" -> "block"`,
		`+ /rules/0: {"path":"/static/*","ttl":3600}`, `- /rules/1: {"path":"/x"}`,
		"(secret value changed; hidden)", `"[redacted]"`} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("missing %q in:\n%s", want, r.stdout)
		}
	}
	if strings.Contains(r.stdout, "[dns]") {
		t.Error("empty section printed")
	}
	if c := f.callList()[0]; c.query != "against=current" {
		t.Errorf("query %q", c.query)
	}
	f.on("GET", "/capi/v1/config/history/9/diff", fakeReply{body: `{"from":9,"to":12,"sections":{},"redacted":false}`})
	r = run(t, f, "", nil, "config", "diff", "9", "--against", "12", "--section", "waf")
	must(t, r, 0)
	if !strings.Contains(r.stdout, "No differences") || f.callList()[1].query != "against=12&section=waf" {
		t.Errorf("%s %q", r.stdout, f.callList()[1].query)
	}
	n := len(f.callList())
	for _, args := range [][]string{{}, {"0"}, {"x"}, {"9", "--against", "latest"}, {"9", "--section", "../x"}, {"9", "10"}} {
		must(t, run(t, f, "", nil, append([]string{"config", "diff"}, args...)...), 2)
	}
	if len(f.callList()) != n {
		t.Error("invalid input was sent")
	}
	f.on("GET", "/capi/v1/config/history/99/diff", fakeReply{status: 404, body: `{"detail":"version not found"}`})
	must(t, run(t, f, "", nil, "config", "diff", "99"), 1)
}

func TestConfigRestore(t *testing.T) {
	f := newFake()
	f.on("POST", "/capi/v1/config/history/9/restore",
		fakeReply{body: `{"version":null,"restored_from":9,"applied":["cache"],"unchanged":["waf"],
		 "dropped":[{"section":"tunnel","reason":"feature_missing","feature":"tunnel"},
		  {"section":"firewall","reason":"limit","feature":"max_firewall_rules","kept":20,"removed":5},
		  {"section":"pools","reason":"invalid","detail":"bad pool"}],
		 "warnings":["این بخش به قابلیتی نیاز دارد که در پلن فعلی نیست"]}`},
		fakeReply{status: 503, body: `{"detail":"down"}`})
	r := run(t, f, "", nil, "config", "restore", "9", "--dry-run", "--section", "cache,waf", "--section", "tunnel")
	must(t, r, 0)
	for _, want := range []string{"Dry run: restoring version 9 would apply: cache", "Unchanged: waf",
		"Dropped: tunnel (feature_missing), plan feature tunnel", "kept 20 / removed 5", "pools (invalid): bad pool",
		"Warning: این بخش"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("missing %q in:\n%s", want, r.stdout)
		}
	}
	if b := f.callList()[0].body; b != `{"sections":["cache","waf","tunnel"],"dry_run":true}` {
		t.Errorf("body %s", b)
	}
	// a real restore is not retried after a 5xx (each restore writes a version)
	r = run(t, f, "", nil, "config", "restore", "9")
	must(t, r, 1)
	calls := f.callList()
	if len(calls) != 2 || calls[1].body != `{"sections":null,"dry_run":false}` {
		t.Errorf("calls %+v", calls)
	}
	f.on("POST", "/capi/v1/config/history/9/restore", fakeReply{body: `{"version":15,"restored_from":9,"applied":["cache"],"unchanged":[],"dropped":[],"warnings":[]}`})
	r = run(t, f, "", nil, "config", "restore", "9")
	must(t, r, 0)
	if !strings.Contains(r.stdout, "Restored version 9 as new version 15") {
		t.Error(r.stdout)
	}
	must(t, run(t, f, "", nil, "config", "restore", "9", "--section", "a b"), 2)
	must(t, run(t, f, "", nil, "config", "restore"), 2)
}
