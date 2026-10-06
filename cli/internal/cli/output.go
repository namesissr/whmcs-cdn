package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/namesissr/whmcs-cdn/cli/internal/client"
)

// printJSON pretty-prints a raw JSON document, keeping the controller's key order.
func (a *app) printJSON(raw json.RawMessage) error {
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return fmt.Errorf("unexpected reply (not JSON): %v", err)
	}
	buf.WriteByte('\n')
	_, err := a.stdout.Write(buf.Bytes())
	return err
}

// printValue prints v as indented JSON (non-ASCII kept readable, e.g. Persian messages).
func (a *app) printValue(v any) error {
	enc := json.NewEncoder(a.stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func newTable(w io.Writer) *tabwriter.Writer { return tabwriter.NewWriter(w, 0, 0, 2, ' ', 0) }

// ---------------------------------------------------------------- formatting helpers

// num formats an integer with thousands separators: 1234567 -> 1,234,567.
func num(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var b strings.Builder
	for i, r := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

// bytesIEC formats a byte count: 1536 -> "1.5 KiB".
func bytesIEC(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}
	v := float64(n)
	i := -1
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}

func optBytes(n *int64) string {
	if n == nil {
		return "-"
	}
	return bytesIEC(*n)
}

func optFloat(f *float64, suffix string) string {
	if f == nil {
		return "-"
	}
	return strconv.FormatFloat(*f, 'f', -1, 64) + suffix
}

func optInt64(n *int64) string {
	if n == nil {
		return "-"
	}
	return strconv.FormatInt(*n, 10)
}

func optString(s *string) string {
	if s == nil || *s == "" {
		return "-"
	}
	return *s
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func pct(part, total int64) string {
	if total <= 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f%%", float64(part)*100/float64(total))
}

// counts renders {"2xx": 10, "4xx": 1} as "2xx=10 4xx=1" in a stable (preferred, then sorted) order.
func counts(m map[string]int64, order ...string) string {
	seen := map[string]bool{}
	var parts []string
	for _, k := range order {
		if v, ok := m[k]; ok {
			parts = append(parts, k+"="+num(v))
			seen[k] = true
		}
	}
	var rest []string
	for k := range m {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	for _, k := range rest {
		parts = append(parts, k+"="+num(m[k]))
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, " ")
}

func decode(raw json.RawMessage, v any, what string) error {
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("unexpected %s reply: %v", what, err)
	}
	return nil
}

// ---------------------------------------------------------------- site

func renderSite(w io.Writer, raw json.RawMessage) error {
	var s struct {
		Domain    string `json:"domain"`
		Status    string `json:"status"`
		Suspended bool   `json:"suspended"`
		Plan      struct {
			BandwidthLimitGB *int64          `json:"bandwidth_limit_gb"`
			MaxRecords       *int64          `json:"max_records"`
			SSLAllowed       *bool           `json:"ssl_allowed"`
			RateLimitRPS     *int64          `json:"rate_limit_rps"`
			Features         map[string]bool `json:"features"`
		} `json:"plan"`
		Nameservers []string `json:"nameservers"`
		CNAMETarget *string  `json:"cname_target"`
		SSLStatus   *string  `json:"ssl_status"`
	}
	if err := decode(raw, &s, "/site"); err != nil {
		return err
	}
	bw := "unlimited"
	if s.Plan.BandwidthLimitGB != nil && *s.Plan.BandwidthLimitGB > 0 {
		bw = num(*s.Plan.BandwidthLimitGB) + " GB/month"
	}
	var on, off []string
	for k, v := range s.Plan.Features {
		if v {
			on = append(on, k)
		} else {
			off = append(off, k)
		}
	}
	sort.Strings(on)
	sort.Strings(off)
	tw := newTable(w)
	fmt.Fprintf(tw, "Domain\t%s\n", s.Domain)
	fmt.Fprintf(tw, "Status\t%s\n", s.Status)
	fmt.Fprintf(tw, "Suspended\t%s\n", yesNo(s.Suspended))
	fmt.Fprintf(tw, "SSL status\t%s\n", optString(s.SSLStatus))
	fmt.Fprintf(tw, "CNAME target\t%s\n", optString(s.CNAMETarget))
	fmt.Fprintf(tw, "Nameservers\t%s\n", strings.Join(s.Nameservers, ", "))
	fmt.Fprintf(tw, "Bandwidth\t%s\n", bw)
	fmt.Fprintf(tw, "Max records\t%s\n", optInt64(s.Plan.MaxRecords))
	if s.Plan.SSLAllowed != nil {
		fmt.Fprintf(tw, "SSL allowed\t%s\n", yesNo(*s.Plan.SSLAllowed))
	}
	if s.Plan.RateLimitRPS != nil {
		fmt.Fprintf(tw, "Rate limit\t%s req/s\n", num(*s.Plan.RateLimitRPS))
	}
	if len(on) > 0 {
		fmt.Fprintf(tw, "Features on\t%s\n", strings.Join(on, ", "))
	}
	if len(off) > 0 {
		fmt.Fprintf(tw, "Features off\t%s\n", strings.Join(off, ", "))
	}
	return tw.Flush()
}

// ---------------------------------------------------------------- records

func renderRecords(w io.Writer, recs []client.Record) {
	if len(recs) == 0 {
		fmt.Fprintln(w, "No records.")
		return
	}
	tw := newTable(w)
	fmt.Fprintln(tw, "ID\tNAME\tTYPE\tCONTENT\tTTL\tPRIORITY\tPROXIED\tPOOL\tORIGIN PORT\tWEIGHT\tHEALTH CHECK")
	for _, r := range recs {
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.Name, r.Type, r.Content, r.TTL,
			optInt64(r.Priority), yesNo(r.Proxied), optString(r.Pool), optInt64(r.OriginPort), optInt64(r.Weight),
			healthCell(r))
	}
	_ = tw.Flush()
}

// healthCell renders the health check settings and, when the controller reports it, the last result:
// "no", "yes (:80)", "yes https:443/healthz up 12ms".
func healthCell(r client.Record) string {
	if !r.HealthCheck {
		return "no"
	}
	out := "yes"
	var spec string
	if r.HealthProtocol != nil && *r.HealthProtocol != "" {
		spec = *r.HealthProtocol
	}
	if r.HealthPort != nil {
		spec += ":" + strconv.FormatInt(*r.HealthPort, 10)
	}
	if r.HealthPath != nil && *r.HealthPath != "" {
		spec += *r.HealthPath
	}
	if spec != "" {
		if strings.HasPrefix(spec, ":") {
			out += " (" + spec + ")"
		} else {
			out += " " + spec
		}
	}
	var h struct {
		OK *bool  `json:"ok"`
		MS *int64 `json:"ms"`
	}
	if len(r.Health) > 0 && json.Unmarshal(r.Health, &h) == nil && h.OK != nil {
		if *h.OK {
			out += " up"
			if h.MS != nil {
				out += " " + strconv.FormatInt(*h.MS, 10) + "ms"
			}
		} else {
			out += " DOWN"
		}
	}
	return out
}

// ---------------------------------------------------------------- analytics

type ranked struct {
	Key      string
	Requests int64
}

// rankedList decodes both [{"code": "IR", "requests": 3}] / [{"path": ..}] and [["IR", 3]] shapes.
func rankedList(raw json.RawMessage, keyField string) []ranked {
	var out []ranked
	var objs []map[string]json.RawMessage
	if json.Unmarshal(raw, &objs) == nil {
		for _, o := range objs {
			var r ranked
			if v, ok := o[keyField]; ok {
				var s string
				if json.Unmarshal(v, &s) != nil {
					s = strings.TrimSpace(string(v))
				}
				r.Key = s
			}
			_ = json.Unmarshal(o["requests"], &r.Requests)
			out = append(out, r)
		}
		return out
	}
	var pairs [][]json.RawMessage
	if json.Unmarshal(raw, &pairs) == nil {
		for _, p := range pairs {
			if len(p) != 2 {
				continue
			}
			var r ranked
			if json.Unmarshal(p[0], &r.Key) != nil {
				r.Key = strings.TrimSpace(string(p[0]))
			}
			_ = json.Unmarshal(p[1], &r.Requests)
			out = append(out, r)
		}
	}
	return out
}

func renderRanked(w io.Writer, title, col string, items []ranked, total int64) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, title)
	tw := newTable(w)
	fmt.Fprintf(tw, "%s\tREQUESTS\tSHARE\n", col)
	for _, it := range items {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", it.Key, num(it.Requests), pct(it.Requests, total))
	}
	_ = tw.Flush()
}

func renderAnalytics(w io.Writer, raw json.RawMessage) error {
	var s struct {
		Period string `json:"period"`
		Totals struct {
			Requests  int64            `json:"requests"`
			Bytes     int64            `json:"bytes"`
			CacheHits int64            `json:"cache_hits"`
			Status    map[string]int64 `json:"status"`
			Security  map[string]int64 `json:"security"`
		} `json:"totals"`
		Series []struct {
			T        string `json:"t"`
			Requests int64  `json:"requests"`
			Bytes    int64  `json:"bytes"`
		} `json:"series"`
		Countries   json.RawMessage `json:"countries"`
		Paths       json.RawMessage `json:"paths"`
		StatusCodes json.RawMessage `json:"status_codes"`
	}
	if err := decode(raw, &s, "/analytics"); err != nil {
		return err
	}
	t := s.Totals
	var secTotal int64
	for _, v := range t.Security {
		secTotal += v
	}
	tw := newTable(w)
	fmt.Fprintf(tw, "Period\t%s\n", s.Period)
	fmt.Fprintf(tw, "Requests\t%s\n", num(t.Requests))
	fmt.Fprintf(tw, "Bandwidth\t%s\n", bytesIEC(t.Bytes))
	fmt.Fprintf(tw, "Cache hits\t%s (%s)\n", num(t.CacheHits), pct(t.CacheHits, t.Requests))
	fmt.Fprintf(tw, "Status\t%s\n", counts(t.Status, "2xx", "3xx", "4xx", "5xx"))
	fmt.Fprintf(tw, "Blocked/challenged\t%s  %s\n", num(secTotal), counts(nonZero(t.Security)))
	if err := tw.Flush(); err != nil {
		return err
	}
	if len(s.Series) > 0 {
		var peak int64
		peakAt := ""
		for _, p := range s.Series {
			if p.Requests > peak {
				peak, peakAt = p.Requests, p.T
			}
		}
		if peakAt != "" {
			fmt.Fprintf(w, "Peak: %s requests at %s\n", num(peak), peakAt)
		}
	}
	renderRanked(w, "Top countries:", "COUNTRY", rankedList(s.Countries, "code"), t.Requests)
	renderRanked(w, "Top paths:", "PATH", rankedList(s.Paths, "path"), t.Requests)
	renderRanked(w, "Status codes:", "CODE", rankedList(s.StatusCodes, "code"), t.Requests)
	return nil
}

func nonZero(m map[string]int64) map[string]int64 {
	out := map[string]int64{}
	for k, v := range m {
		if v != 0 {
			out[k] = v
		}
	}
	return out
}

func renderLive(w io.Writer, raw json.RawMessage) error {
	var s struct {
		Minutes int    `json:"minutes"`
		From    string `json:"from"`
		To      string `json:"to"`
		Series  []struct {
			T         string           `json:"t"`
			Requests  int64            `json:"requests"`
			Bytes     int64            `json:"bytes"`
			CacheHits int64            `json:"cache_hits"`
			Status    map[string]int64 `json:"status"`
		} `json:"series"`
		Totals struct {
			Requests  int64            `json:"requests"`
			Bytes     int64            `json:"bytes"`
			CacheHits int64            `json:"cache_hits"`
			HitRatio  *float64         `json:"hit_ratio"`
			Status    map[string]int64 `json:"status"`
		} `json:"totals"`
		TopPaths     json.RawMessage `json:"top_paths"`
		TopCountries json.RawMessage `json:"top_countries"`
	}
	if err := decode(raw, &s, "/analytics/live"); err != nil {
		return err
	}
	hit := "-"
	if s.Totals.HitRatio != nil {
		hit = fmt.Sprintf("%.1f%%", *s.Totals.HitRatio*100)
	}
	tw := newTable(w)
	fmt.Fprintf(tw, "Window\t%d min (%s .. %s)\n", s.Minutes, s.From, s.To)
	fmt.Fprintf(tw, "Requests\t%s\n", num(s.Totals.Requests))
	fmt.Fprintf(tw, "Bandwidth\t%s\n", bytesIEC(s.Totals.Bytes))
	fmt.Fprintf(tw, "Hit ratio\t%s\n", hit)
	fmt.Fprintf(tw, "Status\t%s\n", counts(s.Totals.Status, "2xx", "3xx", "4xx", "5xx"))
	if err := tw.Flush(); err != nil {
		return err
	}
	// the most recent minutes (newest last), at most 15 rows
	series := s.Series
	if len(series) > 15 {
		series = series[len(series)-15:]
	}
	if len(series) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Recent minutes:")
		tw = newTable(w)
		fmt.Fprintln(tw, "MINUTE\tREQUESTS\tBANDWIDTH\tHIT\t5XX")
		for _, p := range series {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", p.T, num(p.Requests), bytesIEC(p.Bytes), pct(p.CacheHits, p.Requests),
				num(p.Status["5xx"]))
		}
		_ = tw.Flush()
	}
	renderRanked(w, "Top paths:", "PATH", rankedList(s.TopPaths, "path"), s.Totals.Requests)
	renderRanked(w, "Top countries:", "COUNTRY", rankedList(s.TopCountries, "code"), s.Totals.Requests)
	return nil
}

// ---------------------------------------------------------------- tunnel

func renderQuality(w io.Writer, raw json.RawMessage) error {
	var s struct {
		Hours int `json:"hours"`
		Paths []struct {
			ID           string   `json:"id"`
			Path         *string  `json:"path"`
			Protocol     *string  `json:"protocol"`
			Sessions     int64    `json:"sessions"`
			AvgSessionS  *float64 `json:"avg_session_s"`
			AbnormalPct  *float64 `json:"abnormal_pct"`
			ConnectMsAvg *float64 `json:"connect_ms_avg"`
			ErrorTotal   int64    `json:"error_total"`
			SuccessPct   *float64 `json:"success_pct"`
			TopIssue     *string  `json:"top_issue"`
			Advice       *string  `json:"advice"`
			Removed      bool     `json:"removed"`
		} `json:"paths"`
		Edges []struct {
			Name         string   `json:"name"`
			Sessions     int64    `json:"sessions"`
			AbnormalPct  *float64 `json:"abnormal_pct"`
			ConnectMsAvg *float64 `json:"connect_ms_avg"`
			ErrorTotal   int64    `json:"error_total"`
		} `json:"edges"`
	}
	if err := decode(raw, &s, "/tunnel/quality"); err != nil {
		return err
	}
	fmt.Fprintf(w, "Tunnel quality, last %d hour(s)\n\n", s.Hours)
	if len(s.Paths) == 0 {
		fmt.Fprintln(w, "No tunnel paths configured.")
	} else {
		tw := newTable(w)
		fmt.Fprintln(tw, "PATH ID\tPATH\tPROTOCOL\tSESSIONS\tSUCCESS\tABNORMAL\tCONNECT\tAVG SESSION\tERRORS\tTOP ISSUE")
		for _, p := range s.Paths {
			path := optString(p.Path)
			if p.Removed {
				path = "(removed)"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", p.ID, path, optString(p.Protocol), num(p.Sessions),
				optFloat(p.SuccessPct, "%"), optFloat(p.AbnormalPct, "%"), optFloat(p.ConnectMsAvg, " ms"),
				optFloat(p.AvgSessionS, " s"), num(p.ErrorTotal), optString(p.TopIssue))
		}
		_ = tw.Flush()
		for _, p := range s.Paths {
			if p.Advice != nil && *p.Advice != "" {
				fmt.Fprintf(w, "  • %s: %s\n", p.ID, *p.Advice)
			}
		}
	}
	if len(s.Edges) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Per edge:")
		tw := newTable(w)
		fmt.Fprintln(tw, "EDGE\tSESSIONS\tABNORMAL\tCONNECT\tERRORS")
		for _, e := range s.Edges {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", e.Name, num(e.Sessions), optFloat(e.AbnormalPct, "%"),
				optFloat(e.ConnectMsAvg, " ms"), num(e.ErrorTotal))
		}
		_ = tw.Flush()
	}
	return nil
}

func renderUsage(w io.Writer, raw json.RawMessage) error {
	var s struct {
		Days []struct {
			Date       string           `json:"date"`
			BytesUp    int64            `json:"bytes_up"`
			BytesDown  int64            `json:"bytes_down"`
			Sessions   int64            `json:"sessions"`
			ByProtocol map[string]int64 `json:"by_protocol"`
		} `json:"days"`
		Month struct {
			Month               string  `json:"month"`
			UsedBytes           *int64  `json:"used_bytes"`
			LimitBytes          *int64  `json:"limit_bytes"`
			ForecastBytes       *int64  `json:"forecast_bytes"`
			ForecastExhaustDate *string `json:"forecast_exhaust_date"`
			TunnelBytes         *int64  `json:"tunnel_bytes"`
		} `json:"month"`
	}
	if err := decode(raw, &s, "/tunnel/usage"); err != nil {
		return err
	}
	tw := newTable(w)
	fmt.Fprintln(tw, "DATE\tUP\tDOWN\tTOTAL\tSESSIONS\tBY PROTOCOL")
	var up, down, sessions int64
	for _, d := range s.Days {
		up += d.BytesUp
		down += d.BytesDown
		sessions += d.Sessions
		byProto := "-"
		if len(d.ByProtocol) > 0 {
			keys := make([]string, 0, len(d.ByProtocol))
			for k := range d.ByProtocol {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			parts := make([]string, 0, len(keys))
			for _, k := range keys {
				parts = append(parts, k+"="+bytesIEC(d.ByProtocol[k]))
			}
			byProto = strings.Join(parts, " ")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", d.Date, bytesIEC(d.BytesUp), bytesIEC(d.BytesDown),
			bytesIEC(d.BytesUp+d.BytesDown), num(d.Sessions), byProto)
	}
	fmt.Fprintf(tw, "TOTAL\t%s\t%s\t%s\t%s\t\n", bytesIEC(up), bytesIEC(down), bytesIEC(up+down), num(sessions))
	if err := tw.Flush(); err != nil {
		return err
	}
	m := s.Month
	limit := "unlimited"
	if m.LimitBytes != nil {
		limit = bytesIEC(*m.LimitBytes)
	}
	exhaust := "-"
	if m.ForecastExhaustDate != nil {
		exhaust = *m.ForecastExhaustDate
	}
	fmt.Fprintln(w)
	tw = newTable(w)
	fmt.Fprintf(tw, "Month\t%s\n", m.Month)
	fmt.Fprintf(tw, "Used (all traffic)\t%s of %s\n", optBytes(m.UsedBytes), limit)
	fmt.Fprintf(tw, "Tunnel share\t%s\n", optBytes(m.TunnelBytes))
	fmt.Fprintf(tw, "Month forecast\t%s\n", optBytes(m.ForecastBytes))
	fmt.Fprintf(tw, "Quota exhausted on\t%s\n", exhaust)
	return tw.Flush()
}

func renderHealth(w io.Writer, raw json.RawMessage) error {
	var s struct {
		State     string  `json:"state"`
		Since     *string `json:"since"`
		LastCheck *string `json:"last_check"`
	}
	if err := decode(raw, &s, "/tunnel/health"); err != nil {
		return err
	}
	tw := newTable(w)
	fmt.Fprintf(tw, "Origin\t%s\n", strings.ToUpper(s.State))
	fmt.Fprintf(tw, "Since\t%s\n", optString(s.Since))
	fmt.Fprintf(tw, "Last check\t%s\n", optString(s.LastCheck))
	return tw.Flush()
}
