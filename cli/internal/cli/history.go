package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Settings history (SPEC §23.4): `pcdn config history|diff|restore` table renderers.

type historyActor struct {
	Kind  string  `json:"kind"`
	Label *string `json:"label"`
	ID    *string `json:"id"`
}

type historyVersion struct {
	Version      int64        `json:"version"`
	At           string       `json:"at"`
	Actor        historyActor `json:"actor"`
	Source       string       `json:"source"`
	Sections     []string     `json:"sections"`
	RestoredFrom *int64       `json:"restored_from"`
	Restorable   *bool        `json:"restorable"`
}

func actorText(a historyActor) string {
	label := ""
	if a.Label != nil && *a.Label != "" {
		label = *a.Label
	} else if a.ID != nil && *a.ID != "" {
		label = "#" + *a.ID
	}
	switch a.Kind {
	case "client":
		return "account owner"
	case "collaborator":
		return strings.TrimSpace("collaborator " + label)
	case "support":
		return "support"
	case "api_key":
		return strings.TrimSpace("API key " + label)
	case "system":
		if label != "" {
			return "system (" + label + ")"
		}
		return "system"
	}
	if a.Kind == "" {
		return "-"
	}
	return a.Kind
}

func renderHistory(w io.Writer, raw json.RawMessage) error {
	var h struct {
		Versions  []historyVersion `json:"versions"`
		Current   *int64           `json:"current"`
		Retention *struct {
			MaxVersions int `json:"max_versions"`
			Days        int `json:"days"`
		} `json:"retention"`
	}
	if err := decode(raw, &h, "/config/history"); err != nil {
		return err
	}
	if len(h.Versions) == 0 {
		fmt.Fprintln(w, "No settings history yet.")
		return nil
	}
	tw := newTable(w)
	fmt.Fprintln(tw, "VERSION\tWHEN (UTC)\tBY\tSOURCE\tSECTIONS\tNOTE")
	for _, v := range h.Versions {
		mark := ""
		if h.Current != nil && *h.Current == v.Version {
			mark = "current"
		}
		if v.RestoredFrom != nil {
			mark = strings.TrimSpace(mark + fmt.Sprintf(" restored from %d", *v.RestoredFrom))
		}
		if v.Restorable != nil && !*v.Restorable {
			mark = strings.TrimSpace(mark + " not restorable")
		}
		if mark == "" {
			mark = "-"
		}
		when := strings.Replace(strings.TrimSuffix(v.At, "Z"), "T", " ", 1)
		if len(when) > 19 {
			when = when[:19]
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\n", v.Version, when, actorText(v.Actor), v.Source,
			strings.Join(v.Sections, ","), mark)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if h.Retention != nil {
		fmt.Fprintf(w, "\nKept: the newest %d versions younger than %d days.\n", h.Retention.MaxVersions, h.Retention.Days)
	}
	return nil
}

type diffOp struct {
	Op       string          `json:"op"`
	Path     string          `json:"path"`
	Old      json.RawMessage `json:"old"`
	New      json.RawMessage `json:"new"`
	Redacted bool            `json:"redacted"`
}

// compactValue renders a JSON value on one line, shortened for the terminal.
func compactValue(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "null"
	}
	var buf strings.Builder
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return string(raw)
	}
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	s := strings.TrimSpace(buf.String())
	if r := []rune(s); len(r) > 120 {
		s = string(r[:117]) + "..."
	}
	return s
}

func renderDiff(w io.Writer, raw json.RawMessage) error {
	var d struct {
		From     json.RawMessage     `json:"from"`
		To       json.RawMessage     `json:"to"`
		Sections map[string][]diffOp `json:"sections"`
		Redacted bool                `json:"redacted"`
	}
	if err := decode(raw, &d, "/config/history/…/diff"); err != nil {
		return err
	}
	fmt.Fprintf(w, "Changes from version %s to %s\n", strings.Trim(string(d.From), `"`), strings.Trim(string(d.To), `"`))
	names := make([]string, 0, len(d.Sections))
	for k := range d.Sections {
		names = append(names, k)
	}
	sort.Strings(names)
	changed := 0
	for _, name := range names {
		ops := d.Sections[name]
		if len(ops) == 0 {
			continue
		}
		changed++
		fmt.Fprintf(w, "\n[%s]\n", name)
		for _, op := range ops {
			note := ""
			if op.Redacted {
				note = "  (secret value changed; hidden)"
			}
			switch op.Op {
			case "add":
				fmt.Fprintf(w, "  + %s: %s%s\n", op.Path, compactValue(op.New), note)
			case "remove":
				fmt.Fprintf(w, "  - %s: %s%s\n", op.Path, compactValue(op.Old), note)
			default:
				fmt.Fprintf(w, "  ~ %s: %s -> %s%s\n", op.Path, compactValue(op.Old), compactValue(op.New), note)
			}
		}
	}
	if changed == 0 {
		fmt.Fprintln(w, "\nNo differences.")
	}
	if d.Redacted {
		fmt.Fprintln(w, "\nSecret values are shown as \"[redacted]\".")
	}
	return nil
}

func renderRestore(w io.Writer, raw json.RawMessage, dry bool) error {
	var r struct {
		Version      *int64            `json:"version"`
		RestoredFrom int64             `json:"restored_from"`
		Applied      []string          `json:"applied"`
		Unchanged    []string          `json:"unchanged"`
		Dropped      []json.RawMessage `json:"dropped"`
		Warnings     []string          `json:"warnings"`
	}
	if err := decode(raw, &r, "/config/history/…/restore"); err != nil {
		return err
	}
	list := func(xs []string) string {
		if len(xs) == 0 {
			return "-"
		}
		return strings.Join(xs, ", ")
	}
	if dry {
		fmt.Fprintf(w, "Dry run: restoring version %d would apply: %s\n", r.RestoredFrom, list(r.Applied))
	} else if r.Version != nil {
		fmt.Fprintf(w, "Restored version %d as new version %d. Applied: %s\n", r.RestoredFrom, *r.Version, list(r.Applied))
	} else {
		fmt.Fprintf(w, "Nothing to restore from version %d.\n", r.RestoredFrom)
	}
	fmt.Fprintf(w, "Unchanged: %s\n", list(r.Unchanged))
	for _, d := range r.Dropped {
		var item map[string]any
		if json.Unmarshal(d, &item) != nil {
			continue
		}
		line := fmt.Sprintf("Dropped: %v (%v)", item["section"], item["reason"])
		if f, ok := item["feature"]; ok && f != nil {
			line += fmt.Sprintf(", plan feature %v", f)
		}
		if k, ok := item["kept"]; ok {
			line += fmt.Sprintf(", kept %v / removed %v", k, item["removed"])
		}
		if det, ok := item["detail"]; ok && det != nil {
			line += fmt.Sprintf(": %v", det)
		}
		fmt.Fprintln(w, line)
	}
	for _, msg := range r.Warnings {
		fmt.Fprintf(w, "Warning: %s\n", msg)
	}
	return nil
}
