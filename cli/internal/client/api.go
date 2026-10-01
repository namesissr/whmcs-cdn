package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Record is a DNS record as returned by the controller (services.record_to_dict).
type Record struct {
	ID          int64   `json:"id"`
	Name        string  `json:"name"`
	Type        string  `json:"type"`
	Content     string  `json:"content"`
	TTL         int64   `json:"ttl"`
	Priority    *int64  `json:"priority"`
	Proxied     bool    `json:"proxied"`
	Pool        *string `json:"pool"`
	OriginPort  *int64  `json:"origin_port"`
	HealthCheck bool    `json:"health_check"`
	HealthPort  *int64  `json:"health_port"`
	// SPEC §16.7 (weighted / failover sets, controller probe); absent on older controllers
	Weight         *int64          `json:"weight,omitempty"`
	HealthProtocol *string         `json:"health_protocol,omitempty"`
	HealthPath     *string         `json:"health_path,omitempty"`
	Health         json.RawMessage `json:"health,omitempty"`
}

// RecordInput is the controller's RecordIn body. POST and PATCH both take the FULL record
// (`type` and `content` are required by RecordIn), so an update always sends every field.
type RecordInput struct {
	Name        string  `json:"name"`
	Type        string  `json:"type"`
	Content     string  `json:"content"`
	TTL         int64   `json:"ttl"`
	Priority    *int64  `json:"priority"`
	Proxied     bool    `json:"proxied"`
	Pool        *string `json:"pool"`
	OriginPort  *int64  `json:"origin_port"`
	HealthCheck bool    `json:"health_check"`
	HealthPort  *int64  `json:"health_port"`
}

// RecordResult is the reply of a record create/update: the stored record plus `dns_error`, a
// non-fatal PowerDNS sync failure (the record is saved; the controller re-syncs later).
type RecordResult struct {
	Record
	DNSError *string `json:"dns_error"`
}

// ListRecords returns every record of the key's site (GET /records).
func (c *Client) ListRecords(ctx context.Context) ([]Record, error) {
	resp, err := c.do(ctx, request{Method: http.MethodGet, Path: "/records", Idempotent: true})
	if err != nil {
		return nil, err
	}
	var out []Record
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return nil, decodeErr(http.MethodGet, "/records", err)
	}
	return out, nil
}

// GetRecord finds one record by id. There is no single-record GET, so this lists and filters; a
// missing id yields an *APIError with status 404 (see IsNotFound).
func (c *Client) GetRecord(ctx context.Context, id int64) (*Record, error) {
	recs, err := c.ListRecords(ctx)
	if err != nil {
		return nil, err
	}
	for i := range recs {
		if recs[i].ID == id {
			return &recs[i], nil
		}
	}
	return nil, &APIError{Method: http.MethodGet, Path: APIPrefix + "/records", StatusCode: http.StatusNotFound,
		Detail: fmt.Sprintf("record %d not found", id)}
}

// CreateRecord adds a record (POST /records → 201). Not retried on 5xx (not idempotent).
func (c *Client) CreateRecord(ctx context.Context, in RecordInput) (*RecordResult, error) {
	resp, err := c.do(ctx, request{Method: http.MethodPost, Path: "/records", Body: in})
	if err != nil {
		return nil, err
	}
	var out RecordResult
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return nil, decodeErr(http.MethodPost, "/records", err)
	}
	return &out, nil
}

// UpdateRecord replaces a record (PATCH /records/{id} with the full RecordIn body). Sending the
// full record makes the call idempotent, so it is retried like a PUT.
func (c *Client) UpdateRecord(ctx context.Context, id int64, in RecordInput) (*RecordResult, error) {
	p := "/records/" + strconv.FormatInt(id, 10)
	resp, err := c.do(ctx, request{Method: http.MethodPatch, Path: p, Body: in, Idempotent: true})
	if err != nil {
		return nil, err
	}
	var out RecordResult
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return nil, decodeErr(http.MethodPatch, p, err)
	}
	return &out, nil
}

// DeleteRecord removes a record. It returns the controller's non-fatal `dns_error`, if any.
func (c *Client) DeleteRecord(ctx context.Context, id int64) (*string, error) {
	p := "/records/" + strconv.FormatInt(id, 10)
	resp, err := c.do(ctx, request{Method: http.MethodDelete, Path: p, Idempotent: true})
	if err != nil {
		return nil, err
	}
	var out struct {
		DNSError *string `json:"dns_error"`
	}
	_ = json.Unmarshal(resp.Body, &out) // the body is informational only
	return out.DNSError, nil
}

// SectionWrite is the reply of a section PUT.
type SectionWrite struct {
	// Body is the stored (normalised) section as returned by the controller; for `webhooks` it
	// may carry `new_secrets`.
	Body json.RawMessage
	// Warnings are the non-blocking messages of the X-Pcdn-Warnings header.
	Warnings []string
}

func sectionPath(name string) string { return "/config/" + url.PathEscape(name) }

// GetSection reads one configuration section (GET /config/{section}).
func (c *Client) GetSection(ctx context.Context, name string) (json.RawMessage, error) {
	resp, err := c.do(ctx, request{Method: http.MethodGet, Path: sectionPath(name), Idempotent: true})
	if err != nil {
		return nil, err
	}
	if !json.Valid(resp.Body) {
		return nil, decodeErr(http.MethodGet, sectionPath(name), fmt.Errorf("invalid JSON"))
	}
	return json.RawMessage(resp.Body), nil
}

// PutSection replaces one configuration section (PUT /config/{section}) with body (a JSON object).
func (c *Client) PutSection(ctx context.Context, name string, body json.RawMessage) (*SectionWrite, error) {
	resp, err := c.do(ctx, request{Method: http.MethodPut, Path: sectionPath(name), Body: body, Idempotent: true})
	if err != nil {
		return nil, err
	}
	if !json.Valid(resp.Body) {
		return nil, decodeErr(http.MethodPut, sectionPath(name), fmt.Errorf("invalid JSON"))
	}
	return &SectionWrite{Body: json.RawMessage(resp.Body), Warnings: parseWarnings(resp.Header.Get("X-Pcdn-Warnings"))}, nil
}

// parseWarnings decodes the X-Pcdn-Warnings header: a JSON list of strings (ASCII escaped).
func parseWarnings(h string) []string {
	h = strings.TrimSpace(h)
	if h == "" {
		return nil
	}
	var list []string
	if json.Unmarshal([]byte(h), &list) == nil {
		return list
	}
	return []string{h}
}

// PurgeInput is the controller's PurgeIn body.
type PurgeInput struct {
	URLs       []string `json:"urls"`
	Prefixes   []string `json:"prefixes"`
	Everything bool     `json:"everything"`
}

// PurgeResult is `{"ok": true, "queued": <n> | "all"}`.
type PurgeResult struct {
	OK     bool            `json:"ok"`
	Queued json.RawMessage `json:"queued"`
}

// QueuedString renders `queued` as text ("3", "all").
func (p *PurgeResult) QueuedString() string {
	var s string
	if json.Unmarshal(p.Queued, &s) == nil {
		return s
	}
	var n json.Number
	if json.Unmarshal(p.Queued, &n) == nil {
		return n.String()
	}
	return strings.TrimSpace(string(p.Queued))
}

// Purge queues a cache purge (POST /purge). Not retried on 5xx; 429 is retried.
func (c *Client) Purge(ctx context.Context, in PurgeInput) (*PurgeResult, error) {
	if in.URLs == nil {
		in.URLs = []string{}
	}
	if in.Prefixes == nil {
		in.Prefixes = []string{}
	}
	resp, err := c.do(ctx, request{Method: http.MethodPost, Path: "/purge", Body: in})
	if err != nil {
		return nil, err
	}
	var out PurgeResult
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return nil, decodeErr(http.MethodPost, "/purge", err)
	}
	return &out, nil
}

// Site is GET /capi/v1/site (SPEC §14.3.5).
type Site struct {
	Domain      string          `json:"domain"`
	Status      string          `json:"status"`
	Suspended   bool            `json:"suspended"`
	Plan        json.RawMessage `json:"plan"`
	Nameservers []string        `json:"nameservers"`
	CNAMETarget *string         `json:"cname_target"`
	SSLStatus   *string         `json:"ssl_status"`
}

// GetSite returns the key's site summary.
func (c *Client) GetSite(ctx context.Context) (*Site, error) {
	resp, err := c.do(ctx, request{Method: http.MethodGet, Path: "/site", Idempotent: true})
	if err != nil {
		return nil, err
	}
	var out Site
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return nil, decodeErr(http.MethodGet, "/site", err)
	}
	return &out, nil
}

func decodeErr(method, path string, err error) error {
	return fmt.Errorf("%s %s%s: unexpected response from the controller: %v", method, APIPrefix, path, err)
}

// getJSON performs an idempotent GET below /capi/v1 and returns the (validated) JSON body as-is,
// so callers can both print it verbatim (--output json, key order preserved) and decode it.
func (c *Client) getJSON(ctx context.Context, path string, q url.Values) (json.RawMessage, error) {
	resp, err := c.do(ctx, request{Method: http.MethodGet, Path: path, Query: q, Idempotent: true})
	if err != nil {
		return nil, err
	}
	if !json.Valid(resp.Body) {
		return nil, decodeErr(http.MethodGet, path, fmt.Errorf("invalid JSON"))
	}
	return json.RawMessage(resp.Body), nil
}

// SiteRaw is GET /site as raw JSON (any scope).
func (c *Client) SiteRaw(ctx context.Context) (json.RawMessage, error) {
	return c.getJSON(ctx, "/site", nil)
}

// ListRecordsRaw is GET /records as raw JSON (scope dns).
func (c *Client) ListRecordsRaw(ctx context.Context) (json.RawMessage, error) {
	return c.getJSON(ctx, "/records", nil)
}

// Analytics is GET /analytics?period= (scope stats); period is 24h, 7d or 30d.
func (c *Client) Analytics(ctx context.Context, period string) (json.RawMessage, error) {
	return c.getJSON(ctx, "/analytics", url.Values{"period": {period}})
}

// AnalyticsLive is GET /analytics/live?minutes= (scope stats, 1..1440).
func (c *Client) AnalyticsLive(ctx context.Context, minutes int) (json.RawMessage, error) {
	return c.getJSON(ctx, "/analytics/live", url.Values{"minutes": {strconv.Itoa(minutes)}})
}

// TunnelQuality is GET /tunnel/quality?hours= (scope stats, 1..744).
func (c *Client) TunnelQuality(ctx context.Context, hours int) (json.RawMessage, error) {
	return c.getJSON(ctx, "/tunnel/quality", url.Values{"hours": {strconv.Itoa(hours)}})
}

// TunnelUsage is GET /tunnel/usage?days= (scope stats, 1..90).
func (c *Client) TunnelUsage(ctx context.Context, days int) (json.RawMessage, error) {
	return c.getJSON(ctx, "/tunnel/usage", url.Values{"days": {strconv.Itoa(days)}})
}

// TunnelHealth is GET /tunnel/health (scope stats).
func (c *Client) TunnelHealth(ctx context.Context) (json.RawMessage, error) {
	return c.getJSON(ctx, "/tunnel/health", nil)
}

// PurgeRaw is Purge returning the reply verbatim (for --output json).
func (c *Client) PurgeRaw(ctx context.Context, in PurgeInput) (json.RawMessage, error) {
	if in.URLs == nil {
		in.URLs = []string{}
	}
	if in.Prefixes == nil {
		in.Prefixes = []string{}
	}
	resp, err := c.do(ctx, request{Method: http.MethodPost, Path: "/purge", Body: in})
	if err != nil {
		return nil, err
	}
	if !json.Valid(resp.Body) {
		return nil, decodeErr(http.MethodPost, "/purge", fmt.Errorf("invalid JSON"))
	}
	return json.RawMessage(resp.Body), nil
}

// GetRecordRaw returns one record (from GET /records) as a generic document, keeping every field the
// controller sent, including ones this client does not model. A missing id is a 404 *APIError.
func (c *Client) GetRecordRaw(ctx context.Context, id int64) (map[string]json.RawMessage, error) {
	raw, err := c.getJSON(ctx, "/records", nil)
	if err != nil {
		return nil, err
	}
	var recs []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &recs); err != nil {
		return nil, decodeErr(http.MethodGet, "/records", err)
	}
	for _, r := range recs {
		var rid int64
		if json.Unmarshal(r["id"], &rid) == nil && rid == id {
			return r, nil
		}
	}
	return nil, &APIError{Method: http.MethodGet, Path: APIPrefix + "/records", StatusCode: http.StatusNotFound,
		Detail: fmt.Sprintf("record %d not found", id)}
}

// CreateRecordRaw is POST /records with an arbitrary RecordIn document; the reply is returned as-is.
// Not retried on 5xx (not idempotent); 429 is retried.
func (c *Client) CreateRecordRaw(ctx context.Context, body any) (json.RawMessage, error) {
	return c.sendJSON(ctx, request{Method: http.MethodPost, Path: "/records", Body: body})
}

// UpdateRecordRaw is PATCH /records/{id} with a FULL RecordIn document (so it is idempotent and
// retried like a PUT); the reply is returned as-is.
func (c *Client) UpdateRecordRaw(ctx context.Context, id int64, body any) (json.RawMessage, error) {
	return c.sendJSON(ctx, request{Method: http.MethodPatch, Path: "/records/" + strconv.FormatInt(id, 10), Body: body,
		Idempotent: true})
}

func (c *Client) sendJSON(ctx context.Context, r request) (json.RawMessage, error) {
	resp, err := c.do(ctx, r)
	if err != nil {
		return nil, err
	}
	if !json.Valid(resp.Body) {
		return nil, decodeErr(r.Method, r.Path, fmt.Errorf("invalid JSON"))
	}
	return json.RawMessage(resp.Body), nil
}
