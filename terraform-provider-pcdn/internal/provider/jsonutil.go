package provider

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
)

// decodeJSON parses s for comparison: objects become map[string]any and every number a float64,
// so key order, whitespace and number spelling (1 vs 1.0) never matter.
func decodeJSON(s string) (any, error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader([]byte(s)))
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("trailing data after the JSON value")
	}
	return v, nil
}

// decodeJSONExact parses s for re-encoding: numbers stay json.Number so they are sent verbatim.
func decodeJSONExact(s string) (any, error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader([]byte(s)))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("trailing data after the JSON value")
	}
	return v, nil
}

// jsonEqual reports whether a and b are the same JSON value (semantic equality: key order,
// whitespace and number formatting are ignored). Invalid JSON is only equal to the same text.
func jsonEqual(a, b string) bool {
	if a == b {
		return true
	}
	va, err1 := decodeJSON(a)
	vb, err2 := decodeJSON(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return reflect.DeepEqual(va, vb)
}

// canonicalJSON renders v compactly with sorted object keys (encoding/json sorts map keys).
func canonicalJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "null"
	}
	return string(b)
}

// secretKeys are field names whose non-empty string values are never written to `result`
// (defence in depth: per SPEC §14.3.2/§14.3.3 the controller already never returns them).
var secretKeys = map[string]bool{"secret": true, "secret_key": true}

// redactSection removes everything secret from a section body before it is stored in `result`:
// the top-level `new_secrets` map (webhooks PUT) and any non-empty `secret` / `secret_key` string.
func redactSection(v any) any {
	if m, ok := v.(map[string]any); ok {
		delete(m, "new_secrets")
	}
	return redact(v)
}

func redact(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if s, ok := val.(string); ok && secretKeys[k] && s != "" {
				t[k] = ""
				continue
			}
			t[k] = redact(val)
		}
	case []any:
		for i := range t {
			t[i] = redact(t[i])
		}
	}
	return v
}

// newSecrets extracts `new_secrets` ({hook id: secret}) from a webhooks PUT reply.
func newSecrets(body any) map[string]string {
	m, ok := body.(map[string]any)
	if !ok {
		return nil
	}
	raw, ok := m["new_secrets"].(map[string]any)
	if !ok {
		return nil
	}
	out := map[string]string{}
	for id, s := range raw {
		if str, ok := s.(string); ok && str != "" {
			out[id] = str
		}
	}
	return out
}

// webhookItems returns the `items` list of a webhooks section as objects.
func webhookItems(v any) []map[string]any {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	list, ok := m["items"].([]any)
	if !ok {
		return nil
	}
	var out []map[string]any
	for _, it := range list {
		if obj, ok := it.(map[string]any); ok {
			out = append(out, obj)
		}
	}
	return out
}

// webhookIDs returns the ids present in a webhooks section.
func webhookIDs(v any) map[string]bool {
	ids := map[string]bool{}
	for _, it := range webhookItems(v) {
		if id, ok := it["id"].(string); ok && id != "" {
			ids[id] = true
		}
	}
	return ids
}

// injectWebhookIDs keeps webhook ids (and therefore their signing secrets) stable across updates.
//
// The controller assigns a new id — and a new secret — to every item that arrives without a known
// id, so re-PUTting a config whose items carry no `id` would rotate every secret on any change. For
// each configured item without an id whose `url` matches exactly one item of the previously stored
// section (and whose id is not used by another configured item), that stored id is filled in.
// It reports whether cfg was changed.
func injectWebhookIDs(cfg any, prior any) bool {
	items := webhookItems(cfg)
	if len(items) == 0 {
		return false
	}
	byURL := map[string][]string{}
	for _, it := range webhookItems(prior) {
		id, _ := it["id"].(string)
		u, _ := it["url"].(string)
		if id != "" && u != "" {
			byURL[u] = append(byURL[u], id)
		}
	}
	claimed := map[string]bool{}
	for _, it := range items {
		if id, ok := it["id"].(string); ok && id != "" {
			claimed[id] = true
		}
	}
	changed := false
	for _, it := range items {
		if id, ok := it["id"].(string); ok && id != "" {
			continue
		}
		u, _ := it["url"].(string)
		ids := byURL[u]
		if len(ids) != 1 || claimed[ids[0]] {
			continue
		}
		it["id"] = ids[0]
		claimed[ids[0]] = true
		changed = true
	}
	return changed
}

// driftedConfig builds the `config` value stored in state when the controller's section (current)
// no longer matches what was stored after the last apply (result): the configured object with every
// top-level key whose stored value changed replaced by (or, when not configured, added with) the
// controller's current value. The plan then shows only the drifted keys instead of the whole
// section. Keys that did not change keep the configured spelling, including write-only values such
// as `logs.secret_key`. Anything that is not an object falls back to the current section.
func driftedConfig(config, result string, current any) string {
	cur, ok := current.(map[string]any)
	cfgV, err1 := decodeJSON(config)
	resV, err2 := decodeJSON(result)
	cfg, ok1 := cfgV.(map[string]any)
	res, ok2 := resV.(map[string]any)
	if !ok || err1 != nil || err2 != nil || !ok1 || !ok2 {
		return canonicalJSON(current)
	}
	for k, v := range cur {
		if old, had := res[k]; !had || !reflect.DeepEqual(old, v) {
			cfg[k] = v
		}
	}
	return canonicalJSON(cfg)
}
