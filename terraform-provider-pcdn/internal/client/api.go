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
	// SPEC §16.7: weighted / failover sets and the controller's probe (null on older controllers)
	Weight         *int64        `json:"weight"`
	HealthProtocol *string       `json:"health_protocol"`
	HealthPath     *string       `json:"health_path"`
	Health         *RecordHealth `json:"health"`
}

// RecordHealth is the controller's last probe of a record with health_check (read-only; null
// without health_check). Every field may be null before the first probe.
type RecordHealth struct {
	OK         *bool   `json:"ok"`
	MS         *int64  `json:"ms"`
	Fail       *int64  `json:"fail"`
	At         *string `json:"at"`
	Error      *string `json:"error"`
	Advertised *bool   `json:"advertised"`
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
	// SPEC §16.7. Always sent (null = unset): PATCH replaces the whole record, so leaving them out
	// would clear values set elsewhere only by accident of omission.
	Weight         *int64  `json:"weight"`
	HealthProtocol *string `json:"health_protocol"`
	HealthPath     *string `json:"health_path"`
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
