// Package client is a small HTTP client for the Pasargad CDN customer API (`/capi/v1`, SPEC §10.1).
//
// Every call is authenticated with a per-service customer key (`Authorization: Bearer pcdn_...`);
// the key is bound to exactly one site, so no call takes a domain. Errors from the controller
// (`{"detail": "..."}` or FastAPI's `{"detail": [{"loc": [...], "msg": "..."}]}`) are returned as
// *APIError with the controller's messages preserved.
//
// Retries: 429 responses are retried for every method because the controller's rate limiter rejects
// a request before it does anything; 5xx responses and transport errors are retried only for
// idempotent requests (GET, PUT, DELETE and the full-replacement record PATCH). Retry-After is
// honoured. The API key is never logged or included in an error.
//
// Writes are serialised: at most one mutating request (POST/PUT/PATCH/DELETE) per Client is in
// flight. The controller keeps all sections of a site in one JSON document that every section PUT
// reads, modifies and writes back, so concurrent PUTs of different sections can lose updates; config
// writes are also rate-limited per key (CAPI_CONFIG_RATE), so parallel writes gain nothing. Reads
// stay concurrent.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	// APIPrefix is the customer API path below the controller base URL.
	APIPrefix = "/capi/v1"

	DefaultTimeout    = 30 * time.Second
	DefaultMaxRetries = 8
	DefaultMinBackoff = 1 * time.Second
	DefaultMaxBackoff = 30 * time.Second
	// maxRetryAfter caps a server supplied Retry-After so a bogus header cannot stall an apply.
	maxRetryAfter = 120 * time.Second
	// maxErrorBody bounds how much of an error body is read and echoed.
	maxErrorBody = 64 << 10
)

// Config configures a Client.
type Config struct {
	// Endpoint is the controller base URL, e.g. https://cdn-api.example.com. A trailing "/capi/v1"
	// is accepted and stripped. It must be https, except http://localhost / 127.0.0.1 / [::1].
	Endpoint string
	// APIKey is the customer key ("pcdn_" + 40 hex).
	APIKey string
	// UserAgent is sent on every request.
	UserAgent string
	// Timeout bounds a single HTTP attempt (default 30s).
	Timeout time.Duration
	// MaxRetries is the number of retries after the first attempt; 0 disables retries and a
	// negative value selects DefaultMaxRetries.
	MaxRetries int
	// MinBackoff / MaxBackoff bound the exponential backoff between retries (defaults 1s / 30s).
	MinBackoff time.Duration
	MaxBackoff time.Duration
	// HTTPClient overrides the transport (tests). Its Timeout is replaced by Timeout.
	HTTPClient *http.Client
}

// Client talks to one controller with one customer key.
type Client struct {
	base       *url.URL
	apiKey     string
	userAgent  string
	http       *http.Client
	maxRetries int
	minBackoff time.Duration
	maxBackoff time.Duration
	sleep      func(context.Context, time.Duration) error
	// writeSem serialises mutating requests (see the package comment).
	writeSem chan struct{}
}

// NormalizeEndpoint validates the controller base URL and returns it without a trailing slash or
// "/capi/v1" suffix. Plain http is only accepted for loopback hosts (local testing).
func NormalizeEndpoint(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("endpoint is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("endpoint is not a valid URL: %v", err)
	}
	if u.Host == "" || u.Hostname() == "" {
		return "", fmt.Errorf("endpoint %q has no host; use a full URL such as https://cdn-api.example.com", raw)
	}
	if u.User != nil {
		return "", errors.New("endpoint must not contain credentials; use api_key")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("endpoint must not contain a query string or fragment")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return "", fmt.Errorf("endpoint must use https (plain http is only allowed for localhost / 127.0.0.1 / [::1]), got %q", raw)
		}
	default:
		return "", fmt.Errorf("endpoint must be an https URL, got %q", raw)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	p := strings.TrimRight(u.Path, "/")
	p = strings.TrimSuffix(p, APIPrefix)
	u.Path = strings.TrimRight(p, "/")
	u.RawPath = ""
	return u.String(), nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.Equal(net.IPv4(127, 0, 0, 1)) || ip.Equal(net.IPv6loopback))
}

// New validates cfg and returns a Client.
func New(cfg Config) (*Client, error) {
	endpoint, err := NormalizeEndpoint(cfg.Endpoint)
	if err != nil {
		return nil, err
	}
	base, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	key := strings.TrimSpace(cfg.APIKey)
	if key == "" {
		return nil, errors.New("api key is empty")
	}
	if !strings.HasPrefix(key, "pcdn_") {
		// never echo the value: it might be the admin key pasted by mistake
		return nil, errors.New(`api key must be a customer API key starting with "pcdn_" (create one in the WHMCS client area: service → "API و کلیدها")`)
	}
	if strings.ContainsAny(key, " \t\r\n") {
		return nil, errors.New("api key must not contain whitespace")
	}
	hc := &http.Client{}
	if cfg.HTTPClient != nil {
		c := *cfg.HTTPClient
		hc = &c
	}
	hc.Timeout = cfg.Timeout
	if hc.Timeout <= 0 {
		hc.Timeout = DefaultTimeout
	}
	// never follow a redirect: it would either drop the Authorization header (cross-host) or
	// silently turn a PUT/POST into a GET
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	c := &Client{
		base:       base,
		apiKey:     key,
		userAgent:  cfg.UserAgent,
		http:       hc,
		maxRetries: cfg.MaxRetries,
		minBackoff: cfg.MinBackoff,
		maxBackoff: cfg.MaxBackoff,
		sleep:      sleepCtx,
		writeSem:   make(chan struct{}, 1),
	}
	if c.userAgent == "" {
		c.userAgent = "terraform-provider-pcdn/dev"
	}
	if c.maxRetries < 0 {
		c.maxRetries = DefaultMaxRetries
	}
	if c.minBackoff <= 0 {
		c.minBackoff = DefaultMinBackoff
	}
	if c.maxBackoff <= 0 {
		c.maxBackoff = DefaultMaxBackoff
	}
	if c.maxBackoff < c.minBackoff {
		c.maxBackoff = c.minBackoff
	}
	return c, nil
}

// Endpoint returns the normalized controller base URL.
func (c *Client) Endpoint() string { return c.base.String() }

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// response is a successful (2xx) reply.
type response struct {
	Status int
	Header http.Header
	Body   []byte
}

// request describes one API call.
type request struct {
	Method string
	Path   string // below /capi/v1, e.g. "/records"
	Body   any    // JSON encoded when non-nil; json.RawMessage is sent as-is
	// Idempotent marks requests that may be retried after a 5xx or a transport error.
	Idempotent bool
}

func (c *Client) do(ctx context.Context, r request) (*response, error) {
	var payload []byte
	if r.Body != nil {
		var err error
		if raw, ok := r.Body.(json.RawMessage); ok {
			payload = raw
		} else if payload, err = json.Marshal(r.Body); err != nil {
			return nil, fmt.Errorf("encoding request body: %w", err)
		}
	}
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + APIPrefix + r.Path
	target := u.String()
	logPath := APIPrefix + r.Path

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		select {
		case c.writeSem <- struct{}{}:
			defer func() { <-c.writeSem }()
		case <-ctx.Done():
			return nil, fmt.Errorf("%s %s: %w", r.Method, logPath, ctx.Err())
		}
	}

	for attempt := 0; ; attempt++ {
		var body io.Reader
		if payload != nil {
			body = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, r.Method, target, body)
		if err != nil {
			return nil, fmt.Errorf("building request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", c.userAgent)
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		tflog.Debug(ctx, "pcdn API request", map[string]any{"method": r.Method, "path": logPath, "attempt": attempt + 1})
		resp, err := c.http.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("%s %s: %w", r.Method, logPath, ctx.Err())
			}
			// the request may or may not have reached the controller: retry idempotent ones only
			if r.Idempotent && attempt < c.maxRetries {
				wait := c.backoff(attempt)
				tflog.Warn(ctx, "pcdn API transport error, retrying", map[string]any{
					"method": r.Method, "path": logPath, "error": scrub(err.Error(), c.apiKey), "wait": wait.String()})
				if serr := c.sleep(ctx, wait); serr != nil {
					return nil, fmt.Errorf("%s %s: %w", r.Method, logPath, serr)
				}
				continue
			}
			return nil, &TransportError{Method: r.Method, Path: logPath, Err: errors.New(scrub(err.Error(), c.apiKey))}
		}
		data, rerr := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		tflog.Debug(ctx, "pcdn API response", map[string]any{"method": r.Method, "path": logPath, "status": resp.StatusCode})
		if rerr != nil {
			if r.Idempotent && attempt < c.maxRetries {
				if serr := c.sleep(ctx, c.backoff(attempt)); serr != nil {
					return nil, fmt.Errorf("%s %s: %w", r.Method, logPath, serr)
				}
				continue
			}
			return nil, &TransportError{Method: r.Method, Path: logPath, Err: fmt.Errorf("reading response: %v", rerr)}
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return &response{Status: resp.StatusCode, Header: resp.Header, Body: data}, nil
		}

		apiErr := newAPIError(r.Method, logPath, resp.StatusCode, data)
		if c.retryable(r, resp.StatusCode) && attempt < c.maxRetries {
			wait := c.backoff(attempt)
			if ra, ok := retryAfter(resp.Header.Get("Retry-After"), time.Now()); ok {
				wait = ra
			}
			tflog.Warn(ctx, "pcdn API retryable error, retrying", map[string]any{
				"method": r.Method, "path": logPath, "status": resp.StatusCode, "wait": wait.String(), "attempt": attempt + 1})
			if serr := c.sleep(ctx, wait); serr != nil {
				apiErr.Detail += fmt.Sprintf(" (gave up retrying: %v)", serr)
				return nil, apiErr
			}
			continue
		}
		return nil, apiErr
	}
}

// retryable: 429 is safe for every method (the controller rejects before processing); 5xx only
// for idempotent requests, because a non-idempotent one (POST) may already have been applied.
func (c *Client) retryable(r request, status int) bool {
	if status == http.StatusTooManyRequests {
		return true
	}
	return status >= 500 && status <= 599 && status != http.StatusNotImplemented && r.Idempotent
}

// backoff returns an exponential delay with equal jitter for the given (0-based) attempt.
func (c *Client) backoff(attempt int) time.Duration {
	d := c.minBackoff
	for i := 0; i < attempt && d < c.maxBackoff; i++ {
		d *= 2
	}
	if d > c.maxBackoff {
		d = c.maxBackoff
	}
	half := d / 2
	if half <= 0 {
		return d
	}
	return half + time.Duration(rand.Int64N(int64(half)+1))
}

// retryAfter parses a Retry-After header (delta seconds or an HTTP date).
func retryAfter(v string, now time.Time) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	var d time.Duration
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0, false
		}
		d = time.Duration(secs) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = t.Sub(now)
		if d < 0 {
			d = 0
		}
	} else {
		return 0, false
	}
	if d > maxRetryAfter {
		d = maxRetryAfter
	}
	return d, true
}

// scrub removes the API key from a message (defence in depth: net/http errors carry the URL, not
// headers, but a proxy error could echo anything).
func scrub(msg, key string) string {
	if key == "" {
		return msg
	}
	return strings.ReplaceAll(msg, key, "pcdn_***")
}

// ---------------------------------------------------------------- errors

// TransportError is a failure to get any HTTP response.
type TransportError struct {
	Method, Path string
	Err          error
}

func (e *TransportError) Error() string {
	return fmt.Sprintf("%s %s: could not reach the controller: %v", e.Method, e.Path, e.Err)
}

func (e *TransportError) Unwrap() error { return e.Err }

// APIError is a non-2xx reply from the controller.
type APIError struct {
	Method     string
	Path       string
	StatusCode int
	// Detail is the controller's message: the `detail` string, or the `detail` list rendered as
	// "loc: msg" lines, or (for non-JSON bodies) a trimmed excerpt of the body.
	Detail string
	// Messages holds the individual validation messages when `detail` is a list.
	Messages []string
}

func newAPIError(method, path string, status int, body []byte) *APIError {
	e := &APIError{Method: method, Path: path, StatusCode: status}
	if len(body) > maxErrorBody {
		body = body[:maxErrorBody]
	}
	var env struct {
		Detail json.RawMessage `json:"detail"`
	}
	if json.Unmarshal(body, &env) == nil && len(env.Detail) > 0 && string(env.Detail) != "null" {
		var s string
		if json.Unmarshal(env.Detail, &s) == nil {
			e.Detail = s
			return e
		}
		var items []json.RawMessage
		if json.Unmarshal(env.Detail, &items) == nil {
			for _, it := range items {
				e.Messages = append(e.Messages, formatDetailItem(it))
			}
			e.Detail = strings.Join(e.Messages, "; ")
			return e
		}
		e.Detail = string(env.Detail)
		return e
	}
	text := strings.TrimSpace(string(body))
	if strings.HasPrefix(text, "<") {
		// an HTML error page from a reverse proxy: the status text is more useful than the markup
		text = ""
	}
	if len(text) > 300 {
		text = text[:300] + "…"
	}
	if text == "" {
		text = http.StatusText(status)
	}
	e.Detail = text
	return e
}

// formatDetailItem renders one FastAPI validation item ({"loc": [...], "msg": "..."}, optionally
// with "line" for CSV errors) as "loc.path: msg". Unknown shapes are returned as raw JSON.
func formatDetailItem(raw json.RawMessage) string {
	var item struct {
		Loc  []any  `json:"loc"`
		Msg  string `json:"msg"`
		Line *int   `json:"line"`
	}
	if json.Unmarshal(raw, &item) != nil || item.Msg == "" {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return s
		}
		return string(raw)
	}
	var parts []string
	for _, l := range item.Loc {
		switch v := l.(type) {
		case string:
			if v == "body" && len(parts) == 0 {
				continue // FastAPI prefixes body fields with "body"
			}
			parts = append(parts, v)
		case float64:
			parts = append(parts, strconv.FormatInt(int64(v), 10))
		default:
			parts = append(parts, fmt.Sprint(v))
		}
	}
	if len(parts) == 0 {
		return item.Msg
	}
	return strings.Join(parts, ".") + ": " + item.Msg
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s %s returned HTTP %d: %s", e.Method, e.Path, e.StatusCode, e.Detail)
}

// Hint is a short English explanation of the status code for diagnostics.
func (e *APIError) Hint() string {
	switch e.StatusCode {
	case http.StatusUnauthorized:
		return "The API key is missing, invalid or revoked. Create a new customer API key in the WHMCS client area."
	case http.StatusForbidden:
		return "The API key lacks the scope this operation needs (purge, stats or dns), or the site's plan does not allow it."
	case http.StatusNotFound:
		return "The object (or endpoint) does not exist on the controller."
	case http.StatusUnprocessableEntity:
		return "The controller rejected the input."
	case http.StatusTooManyRequests:
		return "The per-key rate limit was exceeded and retries were exhausted; try again later, lower -parallelism, or raise max_retries."
	}
	if e.StatusCode >= 500 {
		return "The controller had an internal or upstream error."
	}
	if e.StatusCode >= 300 && e.StatusCode < 400 {
		return "The endpoint answered with a redirect, which is never followed; check the endpoint URL (scheme, host and path)."
	}
	return ""
}

// IsNotFound reports whether err is an APIError with status 404.
func IsNotFound(err error) bool {
	var e *APIError
	return errors.As(err, &e) && e.StatusCode == http.StatusNotFound
}

// StatusCode returns the HTTP status of an APIError, or 0.
func StatusCode(err error) int {
	var e *APIError
	if errors.As(err, &e) {
		return e.StatusCode
	}
	return 0
}
