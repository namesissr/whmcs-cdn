package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const key = "pcdn_0123456789abcdef0123456789abcdef01234567"

// recorder is a scripted fake controller: each request pops the next reply.
type recorder struct {
	mu      sync.Mutex
	replies []reply
	reqs    []*http.Request
	bodies  []string
}

type reply struct {
	status int
	body   string
	header map[string]string
}

func (r *recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, _ := io.ReadAll(req.Body)
	r.reqs = append(r.reqs, req)
	r.bodies = append(r.bodies, string(b))
	rep := reply{status: 500, body: `{"detail":"script exhausted"}`}
	if len(r.replies) > 0 {
		rep, r.replies = r.replies[0], r.replies[1:]
	}
	for k, v := range rep.header {
		w.Header().Set(k, v)
	}
	w.WriteHeader(rep.status)
	_, _ = io.WriteString(w, rep.body)
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.reqs)
}

// newTestClient returns a client against a scripted server; sleeps are recorded, not slept.
func newTestClient(t *testing.T, replies ...reply) (*Client, *recorder, *[]time.Duration) {
	t.Helper()
	rec := &recorder{replies: replies}
	srv := httptest.NewServer(rec)
	t.Cleanup(srv.Close)
	c, err := New(Config{Endpoint: srv.URL, APIKey: key, UserAgent: "pcdn-cli/1.2.3", MaxRetries: 3})
	if err != nil {
		t.Fatal(err)
	}
	var slept []time.Duration
	c.sleep = func(ctx context.Context, d time.Duration) error {
		slept = append(slept, d)
		return ctx.Err()
	}
	return c, rec, &slept
}

func TestNormalizeEndpoint(t *testing.T) {
	ok := map[string]string{
		"https://cdn-api.example.com":            "https://cdn-api.example.com",
		"https://cdn-api.example.com/":           "https://cdn-api.example.com",
		"https://cdn-api.example.com/capi/v1":    "https://cdn-api.example.com",
		"https://cdn-api.example.com/capi/v1/":   "https://cdn-api.example.com",
		"HTTPS://cdn-api.example.com:8443/cdn/":  "https://cdn-api.example.com:8443/cdn",
		"http://localhost:8000":                  "http://localhost:8000",
		"http://127.0.0.1:9999/capi/v1":          "http://127.0.0.1:9999",
		"http://[::1]:8000":                      "http://[::1]:8000",
		"  https://cdn-api.example.com/x/y/z/  ": "https://cdn-api.example.com/x/y/z",
	}
	for in, want := range ok {
		got, err := NormalizeEndpoint(in)
		if err != nil || got != want {
			t.Errorf("NormalizeEndpoint(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := map[string]string{
		"":                                 "empty",
		"cdn-api.example.com":              "no host",
		"http://cdn-api.example.com":       "must use https",
		"http://127.0.0.2":                 "must use https",
		"http://localhost.example.com":     "must use https",
		"ftp://cdn-api.example.com":        "https URL",
		"https://user:pw@cdn.example.com":  "credentials",
		"https://cdn.example.com/?x=1":     "query",
		"https://":                         "no host",
		"://bad":                           "not a valid URL",
		"https://cdn.example.com/#section": "fragment",
	}
	for in, want := range bad {
		if _, err := NormalizeEndpoint(in); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("NormalizeEndpoint(%q) error = %v; want it to mention %q", in, err, want)
		}
	}
}

func TestNewValidatesKeyWithoutLeakingIt(t *testing.T) {
	admin := "admin-secret-value-123"
	_, err := New(Config{Endpoint: "https://cdn.example.com", APIKey: admin})
	if err == nil || strings.Contains(err.Error(), admin) || !strings.Contains(err.Error(), "pcdn_") {
		t.Fatalf("unexpected error %v", err)
	}
	if _, err := New(Config{Endpoint: "https://cdn.example.com", APIKey: "  "}); err == nil {
		t.Fatal("empty key accepted")
	}
	if _, err := New(Config{Endpoint: "https://cdn.example.com", APIKey: "pcdn_ab cd"}); err == nil {
		t.Fatal("key with whitespace accepted")
	}
	c, err := New(Config{Endpoint: "https://cdn.example.com/capi/v1", APIKey: key + "\n", MaxRetries: -1})
	if err != nil {
		t.Fatal(err)
	}
	if c.apiKey != key || c.Endpoint() != "https://cdn.example.com" || c.maxRetries != DefaultMaxRetries ||
		c.http.Timeout != DefaultTimeout {
		t.Fatalf("defaults not applied: %+v", c)
	}
}

func TestRequestHeadersAndPaths(t *testing.T) {
	c, rec, _ := newTestClient(t,
		reply{status: 201, body: `{"id":7,"name":"www","type":"A","content":"185.1.2.3","ttl":300,"priority":null,"proxied":true,"pool":null,"origin_port":null,"health_check":false,"health_port":null,"dns_error":null}`},
	)
	res, err := c.CreateRecord(context.Background(), RecordInput{Name: "www", Type: "A", Content: "185.1.2.3", TTL: 300, Proxied: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.ID != 7 || res.Name != "www" || !res.Proxied || res.Priority != nil || res.DNSError != nil {
		t.Fatalf("decoded %+v", res)
	}
	r := rec.reqs[0]
	if r.Method != http.MethodPost || r.URL.Path != "/capi/v1/records" {
		t.Errorf("%s %s", r.Method, r.URL.Path)
	}
	if r.Header.Get("Authorization") != "Bearer "+key || r.Header.Get("User-Agent") != "pcdn-cli/1.2.3" ||
		r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Accept") != "application/json" {
		t.Errorf("headers %v", r.Header)
	}
	// the full RecordIn is sent, with explicit nulls
	var body map[string]any
	if err := json.Unmarshal([]byte(rec.bodies[0]), &body); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"name", "type", "content", "ttl", "priority", "proxied", "pool", "origin_port", "health_check", "health_port"} {
		if _, ok := body[k]; !ok {
			t.Errorf("body lacks %q: %s", k, rec.bodies[0])
		}
	}
}

func TestErrorMapping(t *testing.T) {
	cases := []struct {
		name   string
		rep    reply
		status int
		detail string
		msgs   int
		hint   string
	}{
		{"string detail (Persian)", reply{status: 403, body: `{"detail":"این کلید دسترسی «dns» را ندارد"}`}, 403,
			"این کلید دسترسی «dns» را ندارد", 0, "scope"},
		{"fastapi validation list", reply{status: 422, body: `{"detail":[{"type":"missing","loc":["body","content"],"msg":"Field required","input":{}},{"loc":["body","ttl"],"msg":"Input should be greater than or equal to 60"}]}`},
			422, "content: Field required; ttl: Input should be greater than or equal to 60", 2, "rejected"},
		{"section validation list without body prefix", reply{status: 422, body: `{"detail":[{"loc":["rules",0,"id"],"msg":"شناسه قوانین باید یکتا باشد"}]}`},
			422, "rules.0.id: شناسه قوانین باید یکتا باشد", 1, ""},
		{"csv rows", reply{status: 422, body: `{"detail":[{"loc":["csv",3],"line":3,"msg":"bad row"}]}`}, 422, "csv.3: bad row", 1, ""},
		{"list of strings", reply{status: 422, body: `{"detail":["a","b"]}`}, 422, "a; b", 2, ""},
		{"unknown key", reply{status: 401, body: `{"detail":"invalid api key"}`}, 401, "invalid api key", 0, "revoked"},
		{"html from a proxy", reply{status: 404, body: `<html><body>nginx</body></html>`}, 404, "Not Found", 0, "does not exist"},
		{"plain text", reply{status: 400, body: "bad request text"}, 400, "bad request text", 0, ""},
		{"empty body", reply{status: 409, body: ""}, 409, "Conflict", 0, ""},
		{"object detail", reply{status: 422, body: `{"detail":{"x":1}}`}, 422, `{"x":1}`, 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _, _ := newTestClient(t, tc.rep)
			_, err := c.GetSection(context.Background(), "cache")
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("got %T %v", err, err)
			}
			if apiErr.StatusCode != tc.status || apiErr.Detail != tc.detail || len(apiErr.Messages) != tc.msgs {
				t.Fatalf("got status=%d detail=%q msgs=%v", apiErr.StatusCode, apiErr.Detail, apiErr.Messages)
			}
			if tc.hint != "" && !strings.Contains(apiErr.Hint(), tc.hint) {
				t.Errorf("hint %q lacks %q", apiErr.Hint(), tc.hint)
			}
			if !strings.Contains(err.Error(), "GET /capi/v1/config/cache returned HTTP") || strings.Contains(err.Error(), key) {
				t.Errorf("error text %q", err.Error())
			}
		})
	}
}

func TestRetryIdempotentOn5xx(t *testing.T) {
	c, rec, slept := newTestClient(t,
		reply{status: 503, body: "busy"},
		reply{status: 502, body: "<html>bad gateway</html>"},
		reply{status: 200, body: `[]`},
	)
	recs, err := c.ListRecords(context.Background())
	if err != nil || len(recs) != 0 {
		t.Fatalf("%v %v", recs, err)
	}
	if rec.count() != 3 || len(*slept) != 2 {
		t.Fatalf("requests=%d sleeps=%v", rec.count(), *slept)
	}
	// exponential with jitter: attempt n waits within [base*2^n/2, base*2^n]
	if (*slept)[0] < 500*time.Millisecond || (*slept)[0] > time.Second || (*slept)[1] < time.Second || (*slept)[1] > 2*time.Second {
		t.Errorf("backoff %v", *slept)
	}
}

func TestPostNotRetriedOn5xxButOn429(t *testing.T) {
	c, rec, _ := newTestClient(t, reply{status: 500, body: `{"detail":"boom"}`})
	if _, err := c.CreateRecord(context.Background(), RecordInput{Type: "A", Content: "185.1.2.3"}); StatusCode(err) != 500 {
		t.Fatalf("err %v", err)
	}
	if rec.count() != 1 {
		t.Fatalf("POST retried after 500: %d requests", rec.count())
	}

	c, rec, slept := newTestClient(t,
		reply{status: 429, body: `{"detail":"محدودیت نرخ"}`, header: map[string]string{"Retry-After": "7"}},
		reply{status: 200, body: `{"ok":true,"queued":"all"}`},
	)
	res, err := c.Purge(context.Background(), PurgeInput{Everything: true})
	if err != nil || res.QueuedString() != "all" {
		t.Fatalf("%v %v", res, err)
	}
	if rec.count() != 2 || len(*slept) != 1 || (*slept)[0] != 7*time.Second {
		t.Fatalf("requests=%d sleeps=%v (Retry-After not honoured)", rec.count(), *slept)
	}
	// nil lists are sent as [] (PurgeIn has list defaults; explicit [] keeps the body unambiguous)
	if rec.bodies[0] != `{"urls":[],"prefixes":[],"everything":true}` {
		t.Errorf("purge body %s", rec.bodies[0])
	}
}

func TestRetriesExhausted(t *testing.T) {
	c, rec, slept := newTestClient(t,
		reply{status: 429, body: `{"detail":"rate"}`}, reply{status: 429, body: `{"detail":"rate"}`},
		reply{status: 429, body: `{"detail":"rate"}`}, reply{status: 429, body: `{"detail":"still rate limited"}`},
	)
	_, err := c.GetSite(context.Background())
	if StatusCode(err) != 429 || !strings.Contains(err.Error(), "still rate limited") {
		t.Fatalf("err %v", err)
	}
	if rec.count() != 4 || len(*slept) != 3 { // MaxRetries = 3
		t.Fatalf("requests=%d sleeps=%d", rec.count(), len(*slept))
	}
}

func TestRetryStopsOnContextCancel(t *testing.T) {
	c, rec, _ := newTestClient(t, reply{status: 503}, reply{status: 200, body: "[]"})
	ctx, cancel := context.WithCancel(context.Background())
	c.sleep = func(context.Context, time.Duration) error { cancel(); return context.Canceled }
	_, err := c.ListRecords(ctx)
	if StatusCode(err) != 503 || !strings.Contains(err.Error(), "gave up retrying") {
		t.Fatalf("err %v", err)
	}
	if rec.count() != 1 {
		t.Fatalf("requests %d", rec.count())
	}
}

func TestTransportErrorRetriedOnlyWhenIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // connection refused from now on
	c, err := New(Config{Endpoint: url, APIKey: key, MaxRetries: 2})
	if err != nil {
		t.Fatal(err)
	}
	var sleeps int
	c.sleep = func(context.Context, time.Duration) error { sleeps++; return nil }
	_, err = c.ListRecords(context.Background())
	var te *TransportError
	if !errors.As(err, &te) || sleeps != 2 || strings.Contains(err.Error(), key) {
		t.Fatalf("GET: err=%v sleeps=%d", err, sleeps)
	}
	sleeps = 0
	if _, err := c.CreateRecord(context.Background(), RecordInput{}); !errors.As(err, &te) || sleeps != 0 {
		t.Fatalf("POST: err=%v sleeps=%d", err, sleeps)
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	c, rec, _ := newTestClient(t, reply{status: 301, header: map[string]string{"Location": "https://elsewhere.example.net/"}})
	_, err := c.GetSite(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 301 || !strings.Contains(apiErr.Hint(), "redirect") || rec.count() != 1 {
		t.Fatalf("err %v", err)
	}
}

func TestSectionPutWarningsAndRecordHelpers(t *testing.T) {
	c, rec, _ := newTestClient(t,
		reply{status: 200, body: `{"enabled":true}`, header: map[string]string{"X-Pcdn-Warnings": `["هشدار shield"]`}},
		reply{status: 200, body: `[{"id":1,"name":"@","type":"A","content":"185.1.2.3","ttl":300},{"id":2,"name":"www","type":"CNAME","content":"example.com","ttl":300}]`},
		reply{status: 200, body: `[]`},
		reply{status: 404, body: `{"detail":"record not found"}`},
		reply{status: 200, body: `{"ok":true,"dns_error":"pdns down"}`},
	)
	ctx := context.Background()
	w, err := c.PutSection(ctx, "cache", json.RawMessage(`{"enabled":true}`))
	if err != nil || len(w.Warnings) != 1 || w.Warnings[0] != "هشدار shield" {
		t.Fatalf("%+v %v", w, err)
	}
	if rec.reqs[0].Method != http.MethodPut || rec.bodies[0] != `{"enabled":true}` {
		t.Errorf("put %s %s", rec.reqs[0].Method, rec.bodies[0])
	}
	r, err := c.GetRecord(ctx, 2)
	if err != nil || r.Name != "www" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := c.GetRecord(ctx, 9); !IsNotFound(err) {
		t.Fatalf("missing record: %v", err)
	}
	if _, err := c.DeleteRecord(ctx, 9); !IsNotFound(err) {
		t.Fatalf("delete missing: %v", err)
	}
	dnsErr, err := c.DeleteRecord(ctx, 2)
	if err != nil || dnsErr == nil || *dnsErr != "pdns down" {
		t.Fatalf("%v %v", dnsErr, err)
	}
	if rec.reqs[4].Method != http.MethodDelete || rec.reqs[4].URL.Path != "/capi/v1/records/2" {
		t.Errorf("delete %s %s", rec.reqs[4].Method, rec.reqs[4].URL.Path)
	}
	if got := parseWarnings("not json"); len(got) != 1 || got[0] != "not json" {
		t.Errorf("parseWarnings fallback %v", got)
	}
}

func TestQueuedString(t *testing.T) {
	for raw, want := range map[string]string{`3`: "3", `"all"`: "all", `12.0`: "12.0"} {
		p := PurgeResult{Queued: json.RawMessage(raw)}
		if got := p.QueuedString(); got != want {
			t.Errorf("QueuedString(%s) = %q, want %q", raw, got, want)
		}
	}
}

func TestRetryAfterAndBackoff(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	cases := map[string]time.Duration{
		"5":                             5 * time.Second,
		"0":                             0,
		"100000":                        maxRetryAfter,
		"Thu, 01 Oct 2026 12:00:30 GMT": 30 * time.Second,
		"Thu, 01 Oct 2026 11:00:00 GMT": 0,
	}
	for in, want := range cases {
		if got, ok := retryAfter(in, now); !ok || got != want {
			t.Errorf("retryAfter(%q) = %v %v, want %v", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "-1", "soon"} {
		if _, ok := retryAfter(in, now); ok {
			t.Errorf("retryAfter(%q) accepted", in)
		}
	}
	c := &Client{minBackoff: time.Second, maxBackoff: 30 * time.Second}
	for attempt := 0; attempt < 12; attempt++ {
		d := c.backoff(attempt)
		ceil := time.Second << attempt
		if ceil > 30*time.Second || ceil <= 0 {
			ceil = 30 * time.Second
		}
		if d < ceil/2 || d > ceil {
			t.Errorf("backoff(%d) = %v outside [%v, %v]", attempt, d, ceil/2, ceil)
		}
	}
	if scrub("x "+key+" y", key) != "x pcdn_*** y" {
		t.Error("scrub")
	}
}

func TestWritesAreSerialisedReadsAreNot(t *testing.T) {
	var inflight, maxWrites, maxReads atomic.Int32
	track := func(max *atomic.Int32) func() {
		n := inflight.Add(1)
		for {
			m := max.Load()
			if n <= m || max.CompareAndSwap(m, n) {
				break
			}
		}
		return func() { inflight.Add(-1) }
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			defer track(&maxReads)()
		} else {
			defer track(&maxWrites)()
		}
		time.Sleep(20 * time.Millisecond)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer srv.Close()
	c, err := New(Config{Endpoint: srv.URL, APIKey: key})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for _, s := range []string{"cache", "waf", "ddos", "ssl", "headers"} {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			if _, err := c.PutSection(context.Background(), s, json.RawMessage(`{}`)); err != nil {
				t.Error(err)
			}
		}(s)
	}
	wg.Wait()
	if maxWrites.Load() != 1 {
		t.Errorf("%d section PUTs in flight at once, want 1", maxWrites.Load())
	}
	inflight.Store(0)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.GetSection(context.Background(), "cache")
		}()
	}
	wg.Wait()
	if maxReads.Load() < 2 {
		t.Errorf("reads were serialised too (max in flight %d)", maxReads.Load())
	}
	// a write waiting for the lock honours its context
	c.writeSem <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := c.PutSection(ctx, "cache", json.RawMessage(`{}`)); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("blocked write: %v", err)
	}
	<-c.writeSem
}

func TestQueryParamsAndLogNeverContainsKey(t *testing.T) {
	rec := &recorder{replies: []reply{
		{status: 503, body: `{"detail":"later"}`},
		{status: 200, body: `{"hours":5,"paths":[],"edges":[],"series":[]}`},
	}}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	var lines []string
	c, err := New(Config{Endpoint: srv.URL, APIKey: key, MaxRetries: 2,
		Logf: func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }})
	if err != nil {
		t.Fatal(err)
	}
	c.sleep = func(context.Context, time.Duration) error { return nil }
	raw, err := c.TunnelQuality(context.Background(), 5)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(raw) || rec.reqs[1].URL.RawQuery != "hours=5" || rec.reqs[1].URL.Path != "/capi/v1/tunnel/quality" {
		t.Fatalf("raw=%s url=%s", raw, rec.reqs[1].URL)
	}
	if rec.reqs[0].Header.Get("User-Agent") != "pcdn-cli/dev" {
		t.Errorf("default UA: %q", rec.reqs[0].Header.Get("User-Agent"))
	}
	if len(lines) < 4 {
		t.Fatalf("log lines: %v", lines)
	}
	for _, l := range lines {
		if strings.Contains(l, key) {
			t.Fatalf("key logged: %s", l)
		}
	}
	// a reply that is not JSON is an error, not garbage output
	rec.replies = []reply{{status: 200, body: `<html>`}}
	if _, err := c.TunnelHealth(context.Background()); err == nil {
		t.Fatal("non-JSON 200 accepted")
	}
}
