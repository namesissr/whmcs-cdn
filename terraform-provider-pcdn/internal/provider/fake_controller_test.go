package provider

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeController is an in-memory stand-in for the controller's customer API (`/capi/v1`), modelled
// on controller/app/routes_capi.py and the shared admin logic it calls: record normalisation
// (validation.normalize_name / validate_record / _record_from), section PUT/GET with defaults, the
// write-only logs.secret_key, webhook ids + new_secrets, purge validation, scopes and error shapes.
type fakeController struct {
	t      *testing.T
	srv    *httptest.Server
	mu     sync.Mutex
	key    string
	scopes map[string]bool
	domain string

	records map[int64]map[string]any
	nextID  int64

	sections   map[string]map[string]any
	logsSecret string
	hookSecret map[string]string

	purges []map[string]any

	// inject maps "METHOD /path" to statuses returned (in order) before the real handler runs.
	inject map[string][]int
	// calls counts requests per "METHOD /path".
	calls map[string]int
	// dnsError is returned as dns_error from record writes when non-empty.
	dnsError string
	// userAgents seen.
	userAgents map[string]bool

	// overlapping writes: the real controller loses section updates when two PUTs of one site
	// overlap (each rewrites the whole site.config document), so the provider must serialise them
	inflightWrites atomic.Int32
	maxWrites      atomic.Int32
}

const testKey = "pcdn_0123456789abcdef0123456789abcdef01234567"

func newFakeController(t *testing.T) *fakeController {
	t.Helper()
	f := &fakeController{
		t:          t,
		key:        testKey,
		scopes:     map[string]bool{"purge": true, "stats": true, "dns": true},
		domain:     "example.com",
		records:    map[int64]map[string]any{},
		nextID:     100,
		sections:   map[string]map[string]any{},
		hookSecret: map[string]string{},
		inject:     map[string][]int{},
		calls:      map[string]int{},
		userAgents: map[string]bool{},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeController) URL() string { return f.srv.URL }

func (f *fakeController) count(route string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[route]
}

func (f *fakeController) injectStatus(route string, statuses ...int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inject[route] = append(f.inject[route], statuses...)
}

// pending returns how many injected statuses for route are not consumed yet.
func (f *fakeController) pending(route string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.inject[route])
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func detail(w http.ResponseWriter, status int, msg any) {
	writeJSON(w, status, map[string]any{"detail": msg})
}

func (f *fakeController) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		n := f.inflightWrites.Add(1)
		defer f.inflightWrites.Add(-1)
		for m := f.maxWrites.Load(); n > m && !f.maxWrites.CompareAndSwap(m, n); m = f.maxWrites.Load() {
		}
		time.Sleep(3 * time.Millisecond) // widen the window in which an overlapping write would be seen
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	route := r.Method + " " + r.URL.Path
	f.calls[route]++
	f.userAgents[r.Header.Get("User-Agent")] = true

	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		detail(w, 401, "missing bearer token")
		return
	}
	if strings.TrimSpace(auth[7:]) != f.key {
		detail(w, 401, "invalid api key")
		return
	}
	if q := f.inject[route]; len(q) > 0 {
		f.inject[route] = q[1:]
		switch q[0] {
		case 429:
			detail(w, 429, "محدودیت نرخ درخواست (60 در دقیقه) رد شد؛ کمی بعد دوباره تلاش کنید")
		default:
			w.WriteHeader(q[0])
			_, _ = w.Write([]byte("<html><body>upstream error</body></html>"))
		}
		return
	}

	p := strings.TrimPrefix(r.URL.Path, "/capi/v1")
	switch {
	case p == "/site" && r.Method == http.MethodGet:
		writeJSON(w, 200, map[string]any{
			"domain": f.domain, "status": "active", "suspended": false,
			"plan":         map[string]any{"bandwidth_limit_gb": 100, "max_records": 100, "features": map[string]any{"waf": true}},
			"nameservers":  []string{"ns1.pcdn.test", "ns2.pcdn.test"},
			"cname_target": nil, "ssl_status": "active",
		})
	case p == "/purge" && r.Method == http.MethodPost:
		if f.scope(w, "purge") {
			f.purge(w, r)
		}
	case p == "/records":
		if !f.scope(w, "dns") {
			return
		}
		switch r.Method {
		case http.MethodGet:
			out := []map[string]any{}
			for id := int64(0); id <= f.nextID; id++ {
				if rec, ok := f.records[id]; ok {
					out = append(out, rec)
				}
			}
			writeJSON(w, 200, out)
		case http.MethodPost:
			f.writeRecord(w, r, 0)
		default:
			w.WriteHeader(405)
		}
	case strings.HasPrefix(p, "/records/"):
		if !f.scope(w, "dns") {
			return
		}
		id, err := strconv.ParseInt(strings.TrimPrefix(p, "/records/"), 10, 64)
		if err != nil {
			detail(w, 422, []map[string]any{{"loc": []any{"path", "record_id"}, "msg": "Input should be a valid integer"}})
			return
		}
		if _, ok := f.records[id]; !ok {
			detail(w, 404, "record not found")
			return
		}
		switch r.Method {
		case http.MethodPatch:
			f.writeRecord(w, r, id)
		case http.MethodDelete:
			delete(f.records, id)
			writeJSON(w, 200, map[string]any{"ok": true, "dns_error": f.dnsErr()})
		default:
			w.WriteHeader(405)
		}
	case strings.HasPrefix(p, "/config/"):
		if !f.scope(w, "dns") {
			return
		}
		f.config(w, r, strings.TrimPrefix(p, "/config/"))
	default:
		detail(w, 404, "Not Found")
	}
}

func (f *fakeController) scope(w http.ResponseWriter, s string) bool {
	if !f.scopes[s] {
		detail(w, 403, fmt.Sprintf("این کلید دسترسی «%s» را ندارد", s))
		return false
	}
	return true
}

func (f *fakeController) dnsErr() any {
	if f.dnsError == "" {
		return nil
	}
	return f.dnsError
}

// ------------------------------------------------------------------ records

var (
	fakeNameRE = regexp.MustCompile(`^(\*\.)?([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$`)
	fakePoolRE = regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)
	// RecordIn.health_path (SPEC §16.7)
	fakeHealthPathRE = regexp.MustCompile(`^/[^\s"'<>\\]*$`)
)

func (f *fakeController) writeRecord(w http.ResponseWriter, r *http.Request, id int64) {
	var in map[string]any
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		detail(w, 422, []map[string]any{{"loc": []any{"body"}, "msg": "JSON decode error"}})
		return
	}
	// pydantic RecordIn
	var errs []map[string]any
	rtype, ok := in["type"].(string)
	if !ok {
		errs = append(errs, map[string]any{"loc": []any{"body", "type"}, "msg": "Field required"})
	}
	content, ok := in["content"].(string)
	if !ok {
		errs = append(errs, map[string]any{"loc": []any{"body", "content"}, "msg": "Field required"})
	}
	ttl := 300.0
	if v, ok := in["ttl"].(float64); ok {
		ttl = v
	}
	if ttl < 60 || ttl > 86400 {
		errs = append(errs, map[string]any{"loc": []any{"body", "ttl"}, "msg": "Input should be greater than or equal to 60"})
	}
	if pool, ok := in["pool"].(string); ok && !fakePoolRE.MatchString(pool) {
		errs = append(errs, map[string]any{"loc": []any{"body", "pool"}, "msg": "String should match pattern '^[a-z0-9_-]{1,32}$'"})
	}
	// SPEC §16.7 fields: weight 0..100, health_protocol Literal, health_path pattern/max_length
	var weight any
	if v, ok := in["weight"].(float64); ok {
		if v < 0 || v > 100 {
			errs = append(errs, map[string]any{"loc": []any{"body", "weight"}, "msg": "Input should be less than or equal to 100"})
		}
		weight = int64(v)
	}
	proto, _ := in["health_protocol"].(string)
	if _, present := in["health_protocol"]; present && in["health_protocol"] != nil &&
		proto != "tcp" && proto != "http" && proto != "https" {
		errs = append(errs, map[string]any{"loc": []any{"body", "health_protocol"}, "msg": "Input should be 'tcp', 'http' or 'https'"})
	}
	hpath, _ := in["health_path"].(string)
	if hp, ok := in["health_path"].(string); ok && (len(hp) > 512 || !fakeHealthPathRE.MatchString(hp)) {
		errs = append(errs, map[string]any{"loc": []any{"body", "health_path"}, "msg": "String should match pattern"})
	}
	if len(errs) > 0 {
		detail(w, 422, errs)
		return
	}
	name, _ := in["name"].(string)
	if _, present := in["name"]; !present {
		name = "@"
	}
	// validation.normalize_name
	n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if n == "" || n == "@" || n == f.domain {
		n = "@"
	} else {
		n = strings.TrimSuffix(n, "."+f.domain)
		if !fakeNameRE.MatchString(n) {
			detail(w, 422, "نام رکورد نامعتبر است")
			return
		}
	}
	// validation.validate_record
	rtype = strings.ToUpper(strings.TrimSpace(rtype))
	if !map[string]bool{"A": true, "AAAA": true, "CNAME": true, "ALIAS": true, "TXT": true, "MX": true, "NS": true, "SRV": true, "CAA": true}[rtype] {
		detail(w, 422, "نوع رکورد پشتیبانی نمی‌شود")
		return
	}
	content = strings.TrimSpace(content)
	if content == "" {
		detail(w, 422, "مقدار رکورد خالی است")
		return
	}
	proxied, _ := in["proxied"].(bool)
	if proxied && !proxyableTypes[rtype] {
		proxied = false
	}
	var priority any
	if v, ok := in["priority"].(float64); ok {
		priority = int64(v)
	}
	switch rtype {
	case "A", "AAAA":
		a, err := netip.ParseAddr(content)
		if err != nil || (rtype == "A") != a.Is4() {
			detail(w, 422, "آدرس IP نامعتبر است")
			return
		}
		if a.IsPrivate() || a.IsLoopback() || a.IsUnspecified() {
			detail(w, 422, "آدرس IP باید عمومی باشد")
			return
		}
		content = a.String()
	case "CNAME", "NS", "ALIAS", "MX":
		content = strings.TrimSuffix(strings.ToLower(content), ".")
	case "SRV":
		parts := strings.Fields(content)
		if len(parts) != 3 {
			detail(w, 422, "فرمت SRV: weight port target")
			return
		}
		wt, _ := strconv.Atoi(parts[0])
		pt, _ := strconv.Atoi(parts[1])
		content = fmt.Sprintf("%d %d %s", wt, pt, strings.TrimSuffix(strings.ToLower(parts[2]), "."))
	case "TXT":
		content = strings.Trim(content, `"`)
	}
	if rtype == "MX" || rtype == "SRV" {
		if priority == nil {
			priority = int64(10)
		}
	} else {
		priority = nil
	}
	// routes_admin._record_from
	if rtype == "CNAME" && n == "@" && !proxied {
		detail(w, 422, "CNAME روی ریشه دامنه فقط در حالت پروکسی (CDN) مجاز است؛ از ALIAS استفاده کنید")
		return
	}
	weighted := weight != nil
	if weighted && (proxied || (rtype != "A" && rtype != "AAAA" && rtype != "CNAME")) {
		detail(w, 422, "وزن (weight) فقط برای رکوردهای A، AAAA و CNAME بدون پروکسی مجاز است")
		return
	}
	var pool, originPort, healthPort any
	if v, ok := in["pool"].(string); ok && proxied {
		pool = v
	}
	if v, ok := in["origin_port"].(float64); ok && proxied && pool == nil {
		originPort = int64(v)
	}
	hc, _ := in["health_check"].(bool)
	health := hc && !proxied && (rtype == "A" || rtype == "AAAA" || rtype == "CNAME")
	if rtype == "CNAME" && health && !weighted {
		health = false // a lone CNAME has nothing to fail over to
	}
	if v, ok := in["health_port"].(float64); ok && health {
		healthPort = int64(v)
	}
	var protocol, healthPath, healthObj any
	if health && proto != "" {
		protocol = proto
	}
	if protocol == "http" || protocol == "https" {
		if hpath == "" {
			hpath = "/"
		}
		healthPath = hpath
	}
	if health {
		healthObj = map[string]any{"ok": true, "ms": int64(12), "fail": int64(0), "at": "2026-10-01T10:00:00Z",
			"error": nil, "advertised": true}
	}
	status := 200
	if id == 0 {
		f.nextID++
		id = f.nextID
		status = 201
	}
	rec := map[string]any{
		"id": id, "name": n, "type": rtype, "content": content, "ttl": int64(ttl), "priority": priority,
		"proxied": proxied, "pool": pool, "origin_port": originPort, "health_check": health, "health_port": healthPort,
		"weight": weight, "health_protocol": protocol, "health_path": healthPath, "health": healthObj,
	}
	f.records[id] = rec
	out := map[string]any{"dns_error": f.dnsErr()}
	for k, v := range rec {
		out[k] = v
	}
	writeJSON(w, status, out)
}

// addRecord stores a record directly (as if created in the panel) and returns its id.
func (f *fakeController) addRecord(rec map[string]any) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	rec["id"] = f.nextID
	for k, v := range map[string]any{"ttl": int64(300), "priority": nil, "proxied": false, "pool": nil,
		"origin_port": nil, "health_check": false, "health_port": nil, "weight": nil, "health_protocol": nil,
		"health_path": nil, "health": nil} {
		if _, ok := rec[k]; !ok {
			rec[k] = v
		}
	}
	f.records[f.nextID] = rec
	return f.nextID
}

// setRecordField changes a stored record behind Terraform's back (drift).
// setScopes replaces the key's scopes.
func (f *fakeController) setScopes(scopes ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scopes = map[string]bool{}
	for _, s := range scopes {
		f.scopes[s] = true
	}
}

// hookSecretOf returns the controller-side signing secret of a webhook.
func (f *fakeController) hookSecretOf(id string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hookSecret[id]
}

// storedLogsSecret returns the write-only logs.secret_key the controller holds.
func (f *fakeController) storedLogsSecret() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.logsSecret
}

func (f *fakeController) setRecordField(id int64, field string, v any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[id][field] = v
}

func (f *fakeController) deleteRecord(id int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.records, id)
}

func (f *fakeController) record(id int64) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.records[id]
}

func (f *fakeController) recordCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.records)
}

// ------------------------------------------------------------------ sections

func sectionDefaults(name string) (map[string]any, bool) {
	switch name {
	case "cache":
		return map[string]any{
			"enabled": true, "dev_mode": false, "level": "standard", "edge_ttl": 86400.0, "browser_ttl": 0.0,
			"ignore_query": false, "bypass_cookies": []any{"wordpress_logged_in", "wp-postpass", "PHPSESSID"},
			"always_online": true, "shield": false,
		}, true
	case "firewall":
		return map[string]any{"default_action": "allow", "rules": []any{}}, true
	case "logs":
		return map[string]any{
			"enabled": false, "s3_endpoint": "", "region": "us-east-1", "bucket": "", "prefix": "",
			"access_key": "", "secret_key": "", "anonymize_ip": true, "sample_rate": 1.0,
		}, true
	case "webhooks":
		return map[string]any{"items": []any{}}, true
	case "waf", "ddos", "ssl", "headers", "pagerules", "ratelimit", "pools", "hotlink", "image", "errorpages",
		"tunnel", "transform", "redirects", "bots":
		return map[string]any{}, true
	}
	return nil, false
}

func deepCopy(v any) any {
	b, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}

func (f *fakeController) stored(name string) map[string]any {
	if s, ok := f.sections[name]; ok {
		return deepCopy(s).(map[string]any)
	}
	d, _ := sectionDefaults(name)
	return d
}

// view is what GET returns: write-only values blanked, secret_set / secret_key_set added.
func (f *fakeController) view(name string) map[string]any {
	v := f.stored(name)
	switch name {
	case "logs":
		v["secret_key"] = ""
		v["secret_key_set"] = f.logsSecret != ""
	case "webhooks":
		for _, it := range v["items"].([]any) {
			it.(map[string]any)["secret_set"] = true
		}
	}
	return v
}

func (f *fakeController) config(w http.ResponseWriter, r *http.Request, name string) {
	defaults, ok := sectionDefaults(name)
	if !ok {
		detail(w, 404, "بخش نامعتبر است")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, f.view(name))
	case http.MethodPut:
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body == nil {
			detail(w, 422, []map[string]any{{"loc": []any{"body"}, "msg": "Input should be a valid dictionary"}})
			return
		}
		value := defaults
		var errs []map[string]any
		for k, v := range body {
			if _, known := defaults[k]; !known && len(defaults) > 0 {
				if !(name == "webhooks" && k == "items") {
					errs = append(errs, map[string]any{"loc": []any{k}, "msg": "Extra inputs are not permitted"})
					continue
				}
			}
			value[k] = v
		}
		if name == "cache" {
			if ttl, ok := value["edge_ttl"].(float64); ok && (ttl < 60 || ttl > 31536000) {
				errs = append(errs, map[string]any{"loc": []any{"edge_ttl"}, "msg": "Input should be greater than or equal to 60"})
			}
		}
		if len(errs) > 0 {
			detail(w, 422, errs)
			return
		}
		var newSecrets map[string]any
		switch name {
		case "logs":
			if s, _ := value["secret_key"].(string); s != "" {
				f.logsSecret = s
			}
			value["secret_key"] = ""
			delete(value, "secret_key_set")
		case "webhooks":
			newSecrets = map[string]any{}
			keep := map[string]bool{}
			items, _ := value["items"].([]any)
			for _, raw := range items {
				it := raw.(map[string]any)
				delete(it, "secret_set")
				id, _ := it["id"].(string)
				if _, known := f.hookSecret[id]; !known {
					id = "wh_" + randHex(4)
					it["id"] = id
					f.hookSecret[id] = "whsec_" + randHex(20)
					newSecrets[id] = f.hookSecret[id]
				}
				if _, ok := it["enabled"]; !ok {
					it["enabled"] = true
				}
				if _, ok := it["description"]; !ok {
					it["description"] = ""
				}
				keep[id] = true
			}
			for id := range f.hookSecret {
				if !keep[id] {
					delete(f.hookSecret, id)
				}
			}
		}
		f.sections[name] = deepCopy(value).(map[string]any)
		if name == "cache" && value["shield"] == true {
			w.Header().Set("X-Pcdn-Warnings", `["در گروه shield"]`)
		}
		out := f.view(name)
		if len(newSecrets) > 0 {
			out["new_secrets"] = newSecrets
		}
		writeJSON(w, 200, out)
	default:
		w.WriteHeader(405)
	}
}

// setSectionField changes a stored section behind Terraform's back (drift).
func (f *fakeController) setSectionField(name, field string, v any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.stored(name)
	s[field] = v
	f.sections[name] = s
}

func (f *fakeController) sectionField(name, field string) any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stored(name)[field]
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ------------------------------------------------------------------ purge

func (f *fakeController) purge(w http.ResponseWriter, r *http.Request) {
	var in struct {
		URLs       []string `json:"urls"`
		Prefixes   []string `json:"prefixes"`
		Everything bool     `json:"everything"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		detail(w, 422, []map[string]any{{"loc": []any{"body"}, "msg": "JSON decode error"}})
		return
	}
	if len(in.URLs)+len(in.Prefixes) > 100 {
		detail(w, 422, "حداکثر ۱۰۰ مورد در هر درخواست")
		return
	}
	for _, u := range in.URLs {
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			detail(w, 422, "آدرس باید کامل باشد: "+u)
			return
		}
	}
	f.purges = append(f.purges, map[string]any{"urls": in.URLs, "prefixes": in.Prefixes, "everything": in.Everything})
	var queued any = len(in.URLs) + len(in.Prefixes)
	if queued == 0 {
		queued = "all"
	}
	writeJSON(w, 200, map[string]any{"ok": true, "queued": queued})
}

func (f *fakeController) purgeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.purges)
}

func (f *fakeController) lastPurge() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.purges) == 0 {
		return nil
	}
	return f.purges[len(f.purges)-1]
}
