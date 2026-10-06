package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const testKey = "pcdn_0123456789abcdef0123456789abcdef01234567"

// fakeController is an in-memory /capi/v1 with a scripted reply per "METHOD path".
type fakeController struct {
	mu      sync.Mutex
	routes  map[string][]fakeReply // popped in order; the last one repeats
	calls   []call
	records []map[string]any
}

type fakeReply struct {
	status int
	body   string
	header map[string]string
}

type call struct {
	method, path, query, body, auth, ua string
}

func newFake() *fakeController {
	return &fakeController{routes: map[string][]fakeReply{}}
}

func (f *fakeController) on(method, path string, replies ...fakeReply) {
	f.routes[method+" "+path] = replies
}

func (f *fakeController) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, _ := io.ReadAll(r.Body)
	f.calls = append(f.calls, call{method: r.Method, path: r.URL.Path, query: r.URL.RawQuery, body: string(b),
		auth: r.Header.Get("Authorization"), ua: r.Header.Get("User-Agent")})
	k := r.Method + " " + r.URL.Path
	reps, ok := f.routes[k]
	if !ok || len(reps) == 0 {
		w.WriteHeader(404)
		_, _ = io.WriteString(w, `{"detail":"Not Found"}`)
		return
	}
	rep := reps[0]
	if len(reps) > 1 {
		f.routes[k] = reps[1:]
	}
	for hk, hv := range rep.header {
		w.Header().Set(hk, hv)
	}
	if rep.status == 0 {
		rep.status = 200
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(rep.status)
	_, _ = io.WriteString(w, rep.body)
}

func (f *fakeController) callList() []call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]call(nil), f.calls...)
}

type result struct {
	code           int
	stdout, stderr string
}

// run executes pcdn against the fake with PCDN_ENDPOINT/PCDN_API_KEY set (unless env overrides).
func run(t *testing.T, f *fakeController, stdin string, env map[string]string, args ...string) result {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	vars := map[string]string{envEndpoint: srv.URL, envAPIKey: testKey}
	for k, v := range env {
		vars[k] = v
	}
	var out, errb bytes.Buffer
	code := Run(context.Background(), args, Env{
		Stdin:   strings.NewReader(stdin),
		Stdout:  &out,
		Stderr:  &errb,
		Getenv:  func(k string) string { return vars[k] },
		Version: "1.2.3",
		noSleep: true,
	})
	r := result{code: code, stdout: out.String(), stderr: errb.String()}
	if strings.Contains(r.stdout+r.stderr, testKey) {
		t.Fatalf("API key leaked in output:\n%s\n%s", r.stdout, r.stderr)
	}
	return r
}

func must(t *testing.T, r result, code int) {
	t.Helper()
	if r.code != code {
		t.Fatalf("exit code %d, want %d\nstdout:\n%s\nstderr:\n%s", r.code, code, r.stdout, r.stderr)
	}
}

const siteJSON = `{"domain":"example.com","status":"active","suspended":false,
 "plan":{"bandwidth_limit_gb":500,"max_records":50,"ssl_allowed":true,"rate_limit_rps":100,
  "features":{"waf":true,"tunnel":false}},
 "nameservers":["ns1.pcdn.ir","ns2.pcdn.ir"],"cname_target":"example.com","ssl_status":"active"}`

func TestSiteTableAndJSON(t *testing.T) {
	f := newFake()
	f.on("GET", "/capi/v1/site", fakeReply{body: siteJSON})
	r := run(t, f, "", nil, "site")
	must(t, r, 0)
	for _, want := range []string{"example.com", "ns1.pcdn.ir, ns2.pcdn.ir", "500 GB/month", "Features on", "waf", "tunnel", "100 req/s"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("table output lacks %q:\n%s", want, r.stdout)
		}
	}
	c := f.callList()[0]
	if c.auth != "Bearer "+testKey || c.ua != "pcdn-cli/1.2.3" {
		t.Errorf("headers: auth=%q ua=%q", c.auth, c.ua)
	}

	r = run(t, f, "", nil, "-o", "json", "site")
	must(t, r, 0)
	var v map[string]any
	if err := json.Unmarshal([]byte(r.stdout), &v); err != nil || v["domain"] != "example.com" {
		t.Fatalf("json output: %v\n%s", err, r.stdout)
	}
	// key order of the controller is kept
	if strings.Index(r.stdout, `"domain"`) > strings.Index(r.stdout, `"status"`) {
		t.Errorf("key order changed:\n%s", r.stdout)
	}
}

func TestGlobalFlagsAnywhereAndEnvOutput(t *testing.T) {
	f := newFake()
	f.on("GET", "/capi/v1/site", fakeReply{body: siteJSON})
	r := run(t, f, "", nil, "site", "--output", "json")
	must(t, r, 0)
	if !strings.HasPrefix(r.stdout, "{") {
		t.Errorf("flag after command not honoured:\n%s", r.stdout)
	}
	r = run(t, f, "", map[string]string{envOutput: "json"}, "site")
	must(t, r, 0)
	if !strings.HasPrefix(r.stdout, "{") {
		t.Errorf("PCDN_OUTPUT not honoured:\n%s", r.stdout)
	}
	r = run(t, f, "", nil, "site", "-o", "yaml")
	must(t, r, 2)
	if !strings.Contains(r.stderr, "table or json") {
		t.Errorf("stderr: %s", r.stderr)
	}
}

func TestEndpointAndKeyValidation(t *testing.T) {
	f := newFake()
	// missing configuration -> usage error, exit 2
	r := run(t, f, "", map[string]string{envEndpoint: "", envAPIKey: ""}, "site")
	must(t, r, 2)
	if !strings.Contains(r.stderr, "PCDN_ENDPOINT") {
		t.Errorf("stderr: %s", r.stderr)
	}
	r = run(t, f, "", map[string]string{envAPIKey: ""}, "site")
	must(t, r, 2)
	if !strings.Contains(r.stderr, "PCDN_API_KEY") {
		t.Errorf("stderr: %s", r.stderr)
	}
	// plain http to a non-loopback host is refused before any request
	r = run(t, f, "", map[string]string{envEndpoint: "http://cdn-api.example.com"}, "site")
	must(t, r, 1)
	if !strings.Contains(r.stderr, "https") {
		t.Errorf("stderr: %s", r.stderr)
	}
	// a non-customer key is rejected without echoing it
	secret := "admin-secret-value-123"
	r = run(t, f, "", map[string]string{envAPIKey: secret}, "site")
	must(t, r, 1)
	if strings.Contains(r.stderr, secret) {
		t.Fatalf("key echoed: %s", r.stderr)
	}
	// --endpoint / --api-key flags take precedence over the environment
	f.on("GET", "/capi/v1/site", fakeReply{body: siteJSON})
	srv := httptest.NewServer(f)
	defer srv.Close()
	r = run(t, f, "", map[string]string{envEndpoint: "https://wrong.invalid", envAPIKey: "x"},
		"--endpoint", srv.URL+"/capi/v1/", "--api-key", testKey, "site")
	must(t, r, 0)
	if len(f.callList()) != 1 {
		t.Fatalf("calls: %+v", f.callList())
	}
}

func TestRecordsList(t *testing.T) {
	f := newFake()
	f.on("GET", "/capi/v1/records", fakeReply{body: `[{"id":7,"name":"www","type":"A","content":"203.0.113.10","ttl":300,
		"priority":null,"proxied":true,"pool":null,"origin_port":8080,"health_check":true,"health_port":80}]`})
	r := run(t, f, "", nil, "records", "list")
	must(t, r, 0)
	for _, want := range []string{"ID", "www", "203.0.113.10", "8080", "yes (:80)"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("missing %q:\n%s", want, r.stdout)
		}
	}
	f.on("GET", "/capi/v1/records", fakeReply{body: `[]`})
	r = run(t, f, "", nil, "records", "ls")
	must(t, r, 0)
	if !strings.Contains(r.stdout, "No records") {
		t.Errorf("empty: %s", r.stdout)
	}
}

func TestRecordsAdd(t *testing.T) {
	f := newFake()
	f.on("POST", "/capi/v1/records", fakeReply{status: 201, body: `{"id":9,"name":"api","type":"A","content":"203.0.113.5",
		"ttl":600,"priority":null,"proxied":true,"pool":"eu","origin_port":null,"health_check":false,"health_port":null,
		"dns_error":"powerdns down"}`})
	r := run(t, f, "", nil, "records", "add", "--name", "api", "--type", "a", "--content", "203.0.113.5",
		"--ttl", "600", "--proxied", "--pool", "eu")
	must(t, r, 0)
	var body map[string]any
	if err := json.Unmarshal([]byte(f.callList()[0].body), &body); err != nil {
		t.Fatal(err)
	}
	if body["type"] != "A" || body["name"] != "api" || body["ttl"] != float64(600) || body["proxied"] != true ||
		body["pool"] != "eu" || body["priority"] != nil {
		t.Errorf("body: %v", body)
	}
	if !strings.Contains(r.stderr, "powerdns down") || !strings.Contains(r.stdout, "api") {
		t.Errorf("stdout=%s stderr=%s", r.stdout, r.stderr)
	}
	// defaults: name "@", ttl 300
	f.on("POST", "/capi/v1/records", fakeReply{status: 201, body: `{"id":10,"name":"@","type":"TXT","content":"v=spf1","ttl":300}`})
	r = run(t, f, "", nil, "records", "add", "--type", "TXT", "--content", "v=spf1", "-o", "json")
	must(t, r, 0)
	_ = json.Unmarshal([]byte(f.callList()[1].body), &body)
	if body["name"] != "@" || body["ttl"] != float64(300) {
		t.Errorf("defaults: %v", body)
	}
	if !strings.Contains(r.stdout, `"id": 10`) {
		t.Errorf("json: %s", r.stdout)
	}
	// missing type/content is a usage error without any request
	n := len(f.callList())
	r = run(t, f, "", nil, "records", "add", "--content", "x")
	must(t, r, 2)
	if len(f.callList()) != n {
		t.Error("request sent for invalid input")
	}
}

func TestRecordsAddNotRetriedOn5xxButOn429(t *testing.T) {
	f := newFake()
	f.on("POST", "/capi/v1/records", fakeReply{status: 502, body: `bad gateway`})
	r := run(t, f, "", nil, "records", "add", "--type", "A", "--content", "203.0.113.5")
	must(t, r, 1)
	if len(f.callList()) != 1 {
		t.Fatalf("POST retried on 5xx: %d calls", len(f.callList()))
	}
	f = newFake()
	f.on("POST", "/capi/v1/records",
		fakeReply{status: 429, body: `{"detail":"rate"}`, header: map[string]string{"Retry-After": "0"}},
		fakeReply{status: 201, body: `{"id":1,"name":"@","type":"A","content":"203.0.113.5","ttl":300}`})
	r = run(t, f, "", nil, "records", "add", "--type", "A", "--content", "203.0.113.5")
	must(t, r, 0)
	if len(f.callList()) != 2 {
		t.Fatalf("429 not retried: %d calls", len(f.callList()))
	}
}

func TestRecordsUpdateMergesOnlyGivenFlags(t *testing.T) {
	f := newFake()
	f.on("GET", "/capi/v1/records", fakeReply{body: `[{"id":7,"name":"www","type":"A","content":"203.0.113.10","ttl":300,
		"priority":null,"proxied":true,"pool":"eu","origin_port":8080,"health_check":true,"health_port":80}]`})
	f.on("PATCH", "/capi/v1/records/7",
		fakeReply{status: 503, body: `{"detail":"busy"}`},
		fakeReply{body: `{"id":7,"name":"www","type":"A","content":"203.0.113.10","ttl":600,"proxied":false}`})
	// positional id between flags, --pool none clears, --proxied=false turns off
	r := run(t, f, "", nil, "records", "update", "--ttl", "600", "7", "--proxied=false", "--pool", "none")
	must(t, r, 0)
	calls := f.callList()
	if len(calls) != 3 || calls[1].method != "PATCH" || calls[2].method != "PATCH" {
		t.Fatalf("PATCH (idempotent full record) must be retried on 5xx: %+v", calls)
	}
	var body map[string]any
	_ = json.Unmarshal([]byte(calls[2].body), &body)
	want := map[string]any{"name": "www", "type": "A", "content": "203.0.113.10", "ttl": float64(600), "proxied": false,
		"pool": nil, "origin_port": float64(8080), "health_check": true, "health_port": float64(80), "priority": nil}
	for k, v := range want {
		if body[k] != v {
			t.Errorf("%s = %v, want %v (body %v)", k, body[k], v, body)
		}
	}
	// no field flags -> usage error; unknown id -> 404 from the list
	r = run(t, f, "", nil, "records", "update", "7")
	must(t, r, 2)
	r = run(t, f, "", nil, "records", "update", "99", "--ttl", "600")
	must(t, r, 1)
	if !strings.Contains(r.stderr, "record 99 not found") {
		t.Errorf("stderr: %s", r.stderr)
	}
	r = run(t, f, "", nil, "records", "update", "abc", "--ttl", "600")
	must(t, r, 2)
}

func TestRecordsUpdateKeepsFieldsUnknownToTheCLI(t *testing.T) {
	f := newFake()
	f.on("GET", "/capi/v1/records", fakeReply{body: `[{"id":3,"name":"@","type":"A","content":"203.0.113.1","ttl":300,
		"priority":null,"proxied":false,"pool":null,"origin_port":null,"health_check":true,"health_port":443,
		"weight":10,"health_protocol":"https","health_path":"/healthz","future_field":{"a":1},
		"health":{"ok":true,"ms":12,"fail":0,"at":null,"error":null,"advertised":true}}]`})
	f.on("PATCH", "/capi/v1/records/3", fakeReply{body: `{"id":3,"name":"@","type":"A","content":"203.0.113.2","ttl":300,
		"health_check":true,"health_port":443,"weight":0,"health_protocol":"https","health_path":"/up",
		"health":{"ok":false},"dns_error":null}`})
	r := run(t, f, "", nil, "records", "update", "3", "--content", "203.0.113.2", "--weight", "0",
		"--health-path", "/up", "--health-protocol", "HTTPS")
	must(t, r, 0)
	var body map[string]any
	_ = json.Unmarshal([]byte(f.callList()[1].body), &body)
	if body["future_field"] == nil || body["weight"] != float64(0) || body["health_path"] != "/up" ||
		body["health_protocol"] != "https" || body["content"] != "203.0.113.2" || body["health_port"] != float64(443) {
		t.Errorf("body: %v", body)
	}
	for _, k := range []string{"id", "health"} {
		if _, ok := body[k]; ok {
			t.Errorf("read-only field %q sent: %v", k, body)
		}
	}
	if !strings.Contains(r.stdout, "yes https:443/up DOWN") {
		t.Errorf("table: %s", r.stdout)
	}
	// the listed health result is shown
	r = run(t, f, "", nil, "records", "list")
	must(t, r, 0)
	if !strings.Contains(r.stdout, "yes https:443/healthz up 12ms") || !strings.Contains(r.stdout, "WEIGHT") {
		t.Errorf("list: %s", r.stdout)
	}
	// --output json prints the controller reply verbatim (fields unknown to the CLI included)
	f.on("PATCH", "/capi/v1/records/3", fakeReply{body: `{"id":3,"name":"@","type":"A","content":"x","ttl":300,"future_field":1}`})
	r = run(t, f, "", nil, "-o", "json", "records", "update", "3", "--ttl", "300")
	must(t, r, 0)
	if !strings.Contains(r.stdout, `"future_field": 1`) {
		t.Errorf("json: %s", r.stdout)
	}
}

func TestRecordsDelete(t *testing.T) {
	f := newFake()
	f.on("DELETE", "/capi/v1/records/7", fakeReply{body: `{"ok":true,"dns_error":null}`})
	r := run(t, f, "", nil, "records", "delete", "7")
	must(t, r, 0)
	if !strings.Contains(r.stdout, "Deleted record 7") {
		t.Errorf("stdout: %s", r.stdout)
	}
	r = run(t, f, "", nil, "records", "rm")
	must(t, r, 2)
}

func TestConfigGetAndSet(t *testing.T) {
	f := newFake()
	f.on("GET", "/capi/v1/config/waf", fakeReply{body: `{"enabled":true,"mode":"block"}`})
	r := run(t, f, "", nil, "config", "get", "waf")
	must(t, r, 0)
	if !strings.Contains(r.stdout, `"mode": "block"`) {
		t.Errorf("get: %s", r.stdout)
	}

	f.on("PUT", "/capi/v1/config/waf", fakeReply{body: `{"enabled":false,"mode":"log"}`,
		header: map[string]string{"X-Pcdn-Warnings": `["\u0647\u0634\u062f\u0627\u0631"]`}})
	// from stdin (implicit and "-")
	for _, args := range [][]string{{"config", "set", "waf"}, {"config", "set", "waf", "-"}} {
		r = run(t, f, "\ufeff{\"enabled\": false, \"mode\": \"log\"}\n", nil, args...)
		must(t, r, 0)
		if !strings.Contains(r.stdout, `"mode": "log"`) || !strings.Contains(r.stderr, "هشدار") {
			t.Errorf("set: stdout=%s stderr=%s", r.stdout, r.stderr)
		}
	}
	calls := f.callList()
	if calls[len(calls)-1].body != `{"enabled": false, "mode": "log"}` {
		t.Errorf("body sent: %q", calls[len(calls)-1].body)
	}
	// from a file
	p := filepath.Join(t.TempDir(), "waf.json")
	if err := os.WriteFile(p, []byte(`{"enabled":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	r = run(t, f, "", nil, "config", "set", "waf", p)
	must(t, r, 0)
	calls = f.callList()
	if calls[len(calls)-1].body != `{"enabled":true}` {
		t.Errorf("file body: %q", calls[len(calls)-1].body)
	}
	// invalid input never reaches the controller
	n := len(calls)
	for _, in := range []string{"", "[1,2]", "null", "{bad"} {
		r = run(t, f, in, nil, "config", "set", "waf")
		must(t, r, 1)
	}
	r = run(t, f, "{}", nil, "config", "set", "../admin")
	must(t, r, 2)
	if len(f.callList()) != n {
		t.Error("invalid input was sent")
	}
}

func TestConfigErrorsShowControllerDetail(t *testing.T) {
	f := newFake()
	f.on("PUT", "/capi/v1/config/waf", fakeReply{status: 422, body: `{"detail":[{"loc":["body","mode"],"msg":"حالت نامعتبر"}]}`})
	r := run(t, f, `{"mode":"x"}`, nil, "config", "set", "waf")
	must(t, r, 1)
	if !strings.Contains(r.stderr, "mode: حالت نامعتبر") || !strings.Contains(r.stderr, "HTTP 422") {
		t.Errorf("stderr: %s", r.stderr)
	}
	f.on("GET", "/capi/v1/config/waf", fakeReply{status: 403, body: `{"detail":"این کلید دسترسی «dns» را ندارد"}`})
	r = run(t, f, "", nil, "config", "get", "waf")
	must(t, r, 1)
	if !strings.Contains(r.stderr, "«dns»") || !strings.Contains(r.stderr, "Hint:") {
		t.Errorf("stderr: %s", r.stderr)
	}
}

func TestPurge(t *testing.T) {
	f := newFake()
	f.on("POST", "/capi/v1/purge", fakeReply{body: `{"ok":true,"queued":3}`})
	r := run(t, f, "", nil, "purge", "--url", "https://example.com/a.css", "--url", "https://example.com/b.js",
		"--prefix", "https://example.com/static/")
	must(t, r, 0)
	if !strings.Contains(r.stdout, "3 item(s)") {
		t.Errorf("stdout: %s", r.stdout)
	}
	var body struct {
		URLs       []string `json:"urls"`
		Prefixes   []string `json:"prefixes"`
		Everything bool     `json:"everything"`
	}
	_ = json.Unmarshal([]byte(f.callList()[0].body), &body)
	if len(body.URLs) != 2 || len(body.Prefixes) != 1 || body.Everything {
		t.Errorf("body: %+v", body)
	}

	f.on("POST", "/capi/v1/purge", fakeReply{body: `{"ok":true,"queued":"all"}`})
	r = run(t, f, "", nil, "purge", "--everything")
	must(t, r, 0)
	if !strings.Contains(r.stdout, "entire cache") {
		t.Errorf("stdout: %s", r.stdout)
	}
	if b := f.callList()[1].body; !strings.Contains(b, `"urls":[]`) || !strings.Contains(b, `"everything":true`) {
		t.Errorf("everything body: %s", b)
	}

	n := len(f.callList())
	must(t, run(t, f, "", nil, "purge"), 2)
	must(t, run(t, f, "", nil, "purge", "--everything", "--url", "https://example.com/"), 2)
	if len(f.callList()) != n {
		t.Error("invalid purge was sent")
	}
	// POST /purge is not retried on 5xx
	f = newFake()
	f.on("POST", "/capi/v1/purge", fakeReply{status: 500, body: `{"detail":"boom"}`})
	must(t, run(t, f, "", nil, "purge", "--everything"), 1)
	if len(f.callList()) != 1 {
		t.Errorf("purge retried on 5xx: %d", len(f.callList()))
	}
}

const analyticsJSON = `{"period":"7d","totals":{"requests":1000,"bytes":1073741824,"cache_hits":800,
 "status":{"2xx":900,"3xx":50,"4xx":40,"5xx":10},"security":{"waf":5,"bots":0}},
 "series":[{"t":"2026-09-30T00:00:00Z","requests":400,"bytes":1,"cache_hits":1},{"t":"2026-10-01T00:00:00Z","requests":600,"bytes":1,"cache_hits":1}],
 "countries":[{"code":"IR","requests":700}],"paths":[{"path":"/","requests":300}],"status_codes":[{"code":200,"requests":900}]}`

func TestAnalytics(t *testing.T) {
	f := newFake()
	f.on("GET", "/capi/v1/analytics", fakeReply{body: analyticsJSON})
	r := run(t, f, "", nil, "analytics", "--period", "7d")
	must(t, r, 0)
	if q := f.callList()[0].query; q != "period=7d" {
		t.Errorf("query: %s", q)
	}
	for _, want := range []string{"1,000", "1.0 GiB", "800 (80.0%)", "2xx=900", "waf=5", "IR", "70.0%",
		"600 requests at 2026-10-01T00:00:00Z", "200"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("missing %q:\n%s", want, r.stdout)
		}
	}
	if strings.Contains(r.stdout, "bots=") {
		t.Errorf("zero security counters should be hidden:\n%s", r.stdout)
	}
	must(t, run(t, f, "", nil, "analytics", "--period", "1y"), 2)
	must(t, run(t, f, "", nil, "analytics", "extra"), 2)
}

func TestAnalyticsLive(t *testing.T) {
	f := newFake()
	f.on("GET", "/capi/v1/analytics/live", fakeReply{body: `{"minutes":30,"from":"a","to":"b",
	 "series":[{"t":"2026-10-01T10:00:00Z","requests":10,"bytes":2048,"cache_hits":5,"status":{"2xx":9,"5xx":1}}],
	 "totals":{"requests":10,"bytes":2048,"cache_hits":5,"hit_ratio":0.5,"status":{"2xx":9,"5xx":1}},
	 "top_paths":[["/api",7]],"top_countries":[["IR",10]]}`})
	r := run(t, f, "", nil, "analytics", "live", "--minutes", "30")
	must(t, r, 0)
	if q := f.callList()[0].query; q != "minutes=30" {
		t.Errorf("query: %s", q)
	}
	for _, want := range []string{"30 min", "50.0%", "2.0 KiB", "/api", "IR", "Recent minutes"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("missing %q:\n%s", want, r.stdout)
		}
	}
	must(t, run(t, f, "", nil, "analytics", "live", "--minutes", "0"), 2)
}

func TestTunnelCommands(t *testing.T) {
	f := newFake()
	f.on("GET", "/capi/v1/tunnel/quality", fakeReply{body: `{"hours":6,"paths":[
	  {"id":"p1","path":"/ws","protocol":"ws","sessions":100,"avg_session_s":12.5,"abnormal_pct":2.5,"connect_ms_avg":40.1,
	   "errors":{"origin_refused":3},"error_total":3,"success_pct":97.1,"top_issue":"origin_refused","advice":"پورت را بررسی کنید","removed":false},
	  {"id":"old","path":null,"protocol":null,"sessions":0,"avg_session_s":null,"abnormal_pct":null,"connect_ms_avg":null,
	   "errors":{},"error_total":0,"success_pct":null,"top_issue":null,"advice":null,"removed":true}],
	 "edges":[{"name":"edge-1","sessions":100,"abnormal_pct":2.5,"connect_ms_avg":40.1,"error_total":3}],"series":[]}`})
	r := run(t, f, "", nil, "tunnel", "quality", "--hours", "6")
	must(t, r, 0)
	for _, want := range []string{"p1", "/ws", "97.1%", "40.1 ms", "origin_refused", "پورت را بررسی کنید", "(removed)", "edge-1"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("quality missing %q:\n%s", want, r.stdout)
		}
	}
	if q := f.callList()[0].query; q != "hours=6" {
		t.Errorf("query: %s", q)
	}

	f.on("GET", "/capi/v1/tunnel/usage", fakeReply{body: `{"days":[{"date":"2026-10-01","bytes_up":1024,"bytes_down":3072,
	  "sessions":4,"by_protocol":{"ws":4096},"by_path":{"p1":4096}}],
	 "month":{"used_bytes":5368709120,"limit_bytes":null,"forecast_bytes":10737418240,"forecast_exhaust_date":null,
	  "tunnel_bytes":4096,"month":"2026-10"}}`})
	r = run(t, f, "", nil, "tunnel", "usage", "--days", "1")
	must(t, r, 0)
	for _, want := range []string{"2026-10-01", "4.0 KiB", "ws=4.0 KiB", "5.0 GiB of unlimited", "10.0 GiB", "2026-10"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("usage missing %q:\n%s", want, r.stdout)
		}
	}

	f.on("GET", "/capi/v1/tunnel/health", fakeReply{body: `{"state":"down","since":"2026-10-01T09:00:00Z","last_check":null}`})
	r = run(t, f, "", nil, "tunnel", "health")
	must(t, r, 0)
	if !strings.Contains(r.stdout, "DOWN") || !strings.Contains(r.stdout, "2026-10-01T09:00:00Z") {
		t.Errorf("health: %s", r.stdout)
	}
	r = run(t, f, "", nil, "tunnel", "health", "-o", "json")
	must(t, r, 0)
	if !strings.Contains(r.stdout, `"state": "down"`) {
		t.Errorf("health json: %s", r.stdout)
	}

	must(t, run(t, f, "", nil, "tunnel", "quality", "--hours", "745"), 2)
	must(t, run(t, f, "", nil, "tunnel", "usage", "--days", "91"), 2)
	must(t, run(t, f, "", nil, "tunnel", "speed"), 2)
	must(t, run(t, f, "", nil, "tunnel"), 2)
}

func TestReadsRetriedOn5xxAndVerboseNeverLogsKey(t *testing.T) {
	f := newFake()
	f.on("GET", "/capi/v1/tunnel/health",
		fakeReply{status: 503, body: `{"detail":"later"}`},
		fakeReply{status: 429, body: `{"detail":"rate"}`, header: map[string]string{"Retry-After": "0"}},
		fakeReply{body: `{"state":"up","since":null,"last_check":null}`})
	r := run(t, f, "", nil, "-v", "tunnel", "health")
	must(t, r, 0)
	if len(f.callList()) != 3 {
		t.Fatalf("calls: %d", len(f.callList()))
	}
	if !strings.Contains(r.stderr, "HTTP 503, retrying") || !strings.Contains(r.stderr, "GET /capi/v1/tunnel/health") {
		t.Errorf("verbose log: %s", r.stderr)
	}
	// retries exhausted -> exit 1 with the controller's detail
	f = newFake()
	f.on("GET", "/capi/v1/site", fakeReply{status: 502, body: `<html>bad gateway</html>`})
	r = run(t, f, "", nil, "--max-retries", "2", "site")
	must(t, r, 1)
	if len(f.callList()) != 3 || !strings.Contains(r.stderr, "HTTP 502") {
		t.Errorf("calls=%d stderr=%s", len(f.callList()), r.stderr)
	}
}

func TestUnauthorizedHint(t *testing.T) {
	f := newFake()
	f.on("GET", "/capi/v1/site", fakeReply{status: 401, body: `{"detail":"invalid api key"}`})
	r := run(t, f, "", nil, "site")
	must(t, r, 1)
	if !strings.Contains(r.stderr, "invalid api key") || !strings.Contains(r.stderr, "Hint:") {
		t.Errorf("stderr: %s", r.stderr)
	}
}

func TestUsageAndHelp(t *testing.T) {
	f := newFake()
	r := run(t, f, "", nil)
	must(t, r, 2)
	r = run(t, f, "", nil, "help")
	must(t, r, 0)
	if !strings.Contains(r.stdout, "records list") || !strings.Contains(r.stdout, "tunnel health") {
		t.Errorf("help: %s", r.stdout)
	}
	must(t, run(t, f, "", nil, "bogus"), 2)
	must(t, run(t, f, "", nil, "site", "-h"), 0)
	must(t, run(t, f, "", nil, "records", "--help"), 0)
	must(t, run(t, f, "", nil, "records"), 2)
	must(t, run(t, f, "", nil, "records", "frob"), 2)
	must(t, run(t, f, "", nil, "config"), 2)
	must(t, run(t, f, "", nil, "site", "--no-such-flag"), 2)
	r = run(t, f, "", nil, "version")
	must(t, r, 0)
	if strings.TrimSpace(r.stdout) != "pcdn 1.2.3" {
		t.Errorf("version: %q", r.stdout)
	}
	if len(f.callList()) != 0 {
		t.Errorf("usage errors sent requests: %+v", f.callList())
	}
}

func TestParseInterspersedAndTerminator(t *testing.T) {
	a := &app{stderr: io.Discard}
	fs := a.flagSet("t", "")
	n := fs.Int("n", 0, "")
	pos, err := parse(fs, []string{"a", "-n", "3", "b", "--", "-c", "--n"})
	if err != nil {
		t.Fatal(err)
	}
	if *n != 3 || strings.Join(pos, ",") != "a,b,-c,--n" {
		t.Errorf("n=%d pos=%v", *n, pos)
	}
}

func TestFormatting(t *testing.T) {
	cases := map[int64]string{0: "0", 999: "999", 1000: "1,000", 1234567: "1,234,567", -1234: "-1,234"}
	for in, want := range cases {
		if got := num(in); got != want {
			t.Errorf("num(%d)=%q want %q", in, got, want)
		}
	}
	bcases := map[int64]string{0: "0 B", 1023: "1023 B", 1536: "1.5 KiB", 5 << 30: "5.0 GiB"}
	for in, want := range bcases {
		if got := bytesIEC(in); got != want {
			t.Errorf("bytesIEC(%d)=%q want %q", in, got, want)
		}
	}
	if pct(1, 0) != "-" || pct(1, 4) != "25.0%" {
		t.Error("pct")
	}
}
