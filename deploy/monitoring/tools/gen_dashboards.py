#!/usr/bin/env python3
"""Generate the provisioned Grafana dashboards (grafana/dashboards/*.json).

The JSON files are committed; edit THIS file and re-run it instead of editing them by hand:
    python3 deploy/monitoring/tools/gen_dashboards.py
`tools/check_monitoring.py` fails when the committed JSON differs from what this produces.

Only series that really exist are used:
  pcdn_*      controller GET /metrics (controller/app/routes_metrics.py)
  probe_*     blackbox exporter
  pcdn_api_*  optional admin-API bridge (json-exporter, compose profile api-bridge)
"""

import json
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "grafana" / "dashboards"
DS = {"type": "prometheus", "uid": "pcdn-prometheus"}
BRIDGE_NOTE = ("Needs the optional api-bridge profile (json-exporter over the admin API). "
               "Without it these panels show 'No data'. See docs/MONITORING.md.")


class Dash:
    def __init__(self, uid, title, description, tags=(), variables=()):
        self.uid, self.title, self.description = uid, title, description
        self.tags = ["pcdn", *tags]
        self.panels = []
        self.y = 0
        self.x = 0
        self.row_h = 0
        self.next_id = 1
        self.variables = list(variables)

    # layout: panels flow left-to-right on a 24-column grid
    def _pos(self, w, h):
        if self.x + w > 24:
            self.y += self.row_h
            self.x, self.row_h = 0, 0
        pos = {"x": self.x, "y": self.y, "w": w, "h": h}
        self.x += w
        self.row_h = max(self.row_h, h)
        return pos

    def row(self, title, description=None):
        if self.x:
            self.y += self.row_h
            self.x, self.row_h = 0, 0
        p = {"type": "row", "title": title, "collapsed": False, "id": self._id(),
             "gridPos": {"x": 0, "y": self.y, "w": 24, "h": 1}, "panels": []}
        if description:
            p["description"] = description
        self.panels.append(p)
        self.y += 1

    def _id(self):
        i = self.next_id
        self.next_id += 1
        return i

    def add(self, ptype, title, targets, w=6, h=5, description=None, field=None, options=None,
            transformations=None):
        p = {
            "type": ptype, "title": title, "id": self._id(), "datasource": DS,
            "gridPos": self._pos(w, h),
            "targets": [{"datasource": DS, "refId": chr(65 + i), **t} for i, t in enumerate(targets)],
            "fieldConfig": {"defaults": field or {}, "overrides": []},
            "options": options or {},
        }
        if description:
            p["description"] = description
        if transformations:
            p["transformations"] = transformations
        self.panels.append(p)
        return p

    def json(self):
        return {
            "uid": self.uid, "title": self.title, "description": self.description,
            "tags": self.tags, "timezone": "browser", "editable": False, "graphTooltip": 1,
            "schemaVersion": 39, "version": 1, "refresh": "1m",
            "time": {"from": "now-24h", "to": "now"},
            "templating": {"list": self.variables},
            "annotations": {"list": [{
                "builtIn": 1, "datasource": {"type": "grafana", "uid": "-- Grafana --"},
                "enable": True, "hide": True, "iconColor": "rgba(0, 211, 255, 1)",
                "name": "Annotations & Alerts", "type": "dashboard"}]},
            "links": [{"type": "dashboards", "tags": ["pcdn"], "asDropdown": True,
                       "title": "Pasargad CDN", "includeVars": False, "keepTime": True}],
            "panels": self.panels,
        }


# ---------------------------------------------------------------- helpers

def q(expr, legend="", instant=False, fmt=None):
    t = {"expr": expr, "legendFormat": legend or "__auto", "range": not instant, "instant": instant}
    if fmt:
        t["format"] = fmt
    return t


def thresholds(*steps):
    """steps: (value|None, color) ..."""
    return {"mode": "absolute", "steps": [{"value": v, "color": c} for v, c in steps]}


def stat_field(unit="none", steps=((None, "green"),), mappings=None, decimals=None, noValue=None):
    f = {"unit": unit, "thresholds": thresholds(*steps), "color": {"mode": "thresholds"}}
    if mappings:
        f["mappings"] = mappings
    if decimals is not None:
        f["decimals"] = decimals
    if noValue is not None:
        f["noValue"] = noValue
    return f


STAT_OPTS = {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
             "colorMode": "background", "graphMode": "area", "justifyMode": "auto",
             "textMode": "auto", "orientation": "auto"}
UPDOWN = [{"type": "value", "options": {"0": {"text": "DOWN", "color": "red"},
                                        "1": {"text": "UP", "color": "green"}}}]
TS_OPTS = {"legend": {"displayMode": "list", "placement": "bottom", "showLegend": True},
           "tooltip": {"mode": "multi", "sort": "desc"}}


def ts_field(unit="none", stack=False, min_=None, max_=None):
    f = {"unit": unit, "custom": {"lineWidth": 1, "fillOpacity": 10, "showPoints": "never",
                                  "spanNulls": True,
                                  "stacking": {"mode": "normal" if stack else "none", "group": "A"}},
         "color": {"mode": "palette-classic"}}
    if min_ is not None:
        f["min"] = min_
    if max_ is not None:
        f["max"] = max_
    return f


def stat(d, title, expr, w=4, h=4, **kw):
    desc = kw.pop("description", None)
    return d.add("stat", title, [q(expr, instant=False)], w=w, h=h, description=desc,
                 field=stat_field(**kw), options=STAT_OPTS)


def ts(d, title, targets, w=12, h=8, description=None, **kw):
    return d.add("timeseries", title, targets, w=w, h=h, description=description,
                 field=ts_field(**kw), options=TS_OPTS)


def table(d, title, targets, w=24, h=9, description=None, rename=None, units=None, hide=()):
    """Instant queries merged into one row per label set (one column per query)."""
    overrides = []
    for col, unit in (units or {}).items():
        overrides.append({"matcher": {"id": "byName", "options": col},
                          "properties": [{"id": "unit", "value": unit}]})
    p = d.add("table", title, [dict(q(t["expr"], instant=True, fmt="table"), **{"_r": t["ref"]})
                               for t in targets],
              w=w, h=h, description=description,
              field={"custom": {"align": "auto", "cellOptions": {"type": "auto"}}},
              options={"showHeader": True, "cellHeight": "sm", "footer": {"show": False}},
              transformations=[
                  {"id": "merge", "options": {}},
                  {"id": "organize", "options": {
                      "excludeByName": {"Time": True, "__name__": True, "job": True, "instance": True,
                                        "bridge": True, **{h_: True for h_ in hide}},
                      "renameByName": rename or {}}}])
    # Grafana names merged value columns "Value #<refId>"
    for t, target in zip(targets, p["targets"]):
        target.pop("_r")
    p["fieldConfig"]["overrides"] = overrides
    return p


# ---------------------------------------------------------------- dashboards

def overview():
    d = Dash("pcdn-overview", "Pasargad CDN — Platform overview",
             "Controller health, edges, sites, SSL, alerts, backups (controller /metrics + probes).",
             tags=["overview"])
    d.row("Control plane")
    stat(d, "Controller (external probe)", 'min(probe_success{job="pcdn-probe", probe="healthz"})',
         steps=((None, "red"), (1, "green")), mappings=UPDOWN, noValue="no target",
         description="GET /healthz from the monitoring host (blackbox).")
    stat(d, "/metrics scrape", 'min(up{job="pcdn-controller"})',
         steps=((None, "red"), (1, "green")), mappings=UPDOWN, noValue="no target")
    stat(d, "/healthz/deep", 'min(probe_success{job="pcdn-probe-deep"})',
         steps=((None, "orange"), (1, "green")),
         mappings=[{"type": "value", "options": {"0": {"text": "DEGRADED", "color": "orange"},
                                                 "1": {"text": "OK", "color": "green"}}}])
    stat(d, "Scheduler last run", "max(pcdn_scheduler_last_run_age_seconds)", unit="s",
         steps=((None, "green"), (300, "orange"), (600, "red")))
    stat(d, "DNS last clean sync", "max(pcdn_dns_last_sync_age_seconds)", unit="s",
         steps=((None, "green"), (600, "orange"), (900, "red")))
    stat(d, "Last good backup", "max(pcdn_backup_last_success_age_seconds)", unit="s",
         steps=((None, "green"), (26 * 3600, "orange"), (50 * 3600, "red")), noValue="never")

    d.row("Edges & sites")
    stat(d, "Edges online", "sum(pcdn_edges_online)", steps=((None, "red"), (1, "green")))
    stat(d, "Edges registered", "sum(pcdn_edges_total)")
    stat(d, "Edges shed (load)", "sum(pcdn_edges_shed)", steps=((None, "green"), (1, "orange")))
    stat(d, "Edges failing probe", "sum(pcdn_edges_probe_failing)", steps=((None, "green"), (1, "red")))
    stat(d, "Sites", "sum(pcdn_sites_total)")
    stat(d, "Usage batches / min", "sum(rate(pcdn_usage_batches_ingested_total[$__rate_interval])) * 60",
         decimals=1, description="Edge usage reports accepted by the controller.")

    ts(d, "Edges", [q("sum(pcdn_edges_total)", "registered"), q("sum(pcdn_edges_online)", "online"),
                    q("sum(pcdn_edges_shed)", "shed"), q("sum(pcdn_edges_probe_failing)", "probe failing")],
       min_=0)
    d.add("bargauge", "Sites by effective status", [q("sum by (status) (pcdn_sites)", "{{status}}",
                                                       instant=True)],
          w=6, h=8, field={"unit": "none", "color": {"mode": "palette-classic"}},
          options={"orientation": "horizontal", "displayMode": "basic",
                   "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}})
    d.add("bargauge", "SSL certificates by status",
          [q("sum by (status) (pcdn_ssl_certificates)", "{{status}}", instant=True)],
          w=6, h=8, field={"unit": "none", "color": {"mode": "palette-classic"}},
          options={"orientation": "horizontal", "displayMode": "basic",
                   "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}})

    d.row("Alerts & certificates")
    stat(d, "Controller open alerts", "sum(pcdn_active_alerts)", steps=((None, "green"), (1, "orange")))
    stat(d, "Critical alerts open", 'sum(pcdn_active_alerts_by_severity{severity="critical"}) or vector(0)',
         steps=((None, "green"), (1, "red")))
    stat(d, "DNS sync errors", "sum(pcdn_dns_sync_errors)", steps=((None, "green"), (1, "red")))
    stat(d, "Certs failed", 'sum(pcdn_ssl_certificates{status="failed"}) or vector(0)',
         steps=((None, "green"), (1, "orange")))
    stat(d, "Certs expiring (unrenewed)", "sum(pcdn_ssl_certs_expiring)",
         steps=((None, "green"), (1, "orange")))
    stat(d, "Controller TLS expires in", 'min(probe_ssl_earliest_cert_expiry{job=~"pcdn-probe.*"}) - time()',
         unit="s", steps=((None, "red"), (14 * 86400, "orange"), (30 * 86400, "green")), noValue="http only")
    ts(d, "Open controller alerts by severity",
       [q("sum by (severity) (pcdn_active_alerts_by_severity)", "{{severity}}")], stack=True, min_=0)
    ts(d, "Probe latency", [q('probe_duration_seconds{job=~"pcdn-probe.*"}', "{{instance}}")], unit="s",
       description="Blackbox round-trip from the monitoring host.")
    ts(d, "Firing alerts (Prometheus)", [q('sum by (alertname, severity) (ALERTS{alertstate="firing"})',
                                          "{{alertname}} ({{severity}})")], w=24, h=7, min_=0)
    return d


def edges():
    group_var = {
        "name": "group", "label": "Edge group", "type": "query", "datasource": DS,
        "query": {"query": "label_values(pcdn_api_edge_enabled, group)", "refId": "group"},
        "definition": "label_values(pcdn_api_edge_enabled, group)",
        "includeAll": True, "multi": True, "allValue": ".*", "refresh": 2, "sort": 1,
        "current": {"selected": True, "text": ["All"], "value": ["$__all"]},
    }
    d = Dash("pcdn-edges", "Pasargad CDN — Edges",
             "Edge availability, load, capacity and uptime. Per-edge panels: " + BRIDGE_NOTE,
             tags=["edges"], variables=[group_var])
    d.row("Platform counts (controller /metrics)")
    stat(d, "Online", "sum(pcdn_edges_online)", steps=((None, "red"), (1, "green")))
    stat(d, "Registered", "sum(pcdn_edges_total)")
    stat(d, "Enabled", "sum(pcdn_api_edges_enabled)", description=BRIDGE_NOTE)
    stat(d, "Shed", "sum(pcdn_edges_shed)", steps=((None, "green"), (1, "orange")))
    stat(d, "Failing probe", "sum(pcdn_edges_probe_failing)", steps=((None, "green"), (1, "red")))
    stat(d, "With last_error", "sum(pcdn_api_edges_with_errors)", steps=((None, "green"), (1, "orange")),
         description=BRIDGE_NOTE)
    ts(d, "Online vs registered", [q("sum(pcdn_edges_total)", "registered"),
                                   q("sum(pcdn_edges_online)", "online"),
                                   q("sum(pcdn_api_edges_enabled)", "enabled (bridge)")], w=24, h=7, min_=0)

    sel = '{group=~"$group"}'
    d.row("Per edge (api-bridge)", description=BRIDGE_NOTE)
    load = (f"100 * (pcdn_api_edge_tx_mbps{sel} > pcdn_api_edge_rx_mbps{sel} or pcdn_api_edge_rx_mbps{sel})"
            f" / (pcdn_api_edge_capacity_mbps{sel} > 0)")
    table(d, "Edges", [
        {"ref": "A", "expr": f"pcdn_api_edge_online{sel}"},
        {"ref": "B", "expr": f"pcdn_api_edge_shed{sel}"},
        {"ref": "C", "expr": load},
        {"ref": "D", "expr": f"pcdn_api_edge_tx_mbps{sel}"},
        {"ref": "E", "expr": f"pcdn_api_edge_rx_mbps{sel}"},
        {"ref": "F", "expr": f"pcdn_api_edge_capacity_mbps{sel}"},
        {"ref": "G", "expr": f"pcdn_api_edge_connections{sel}"},
        {"ref": "H", "expr": f"pcdn_api_edge_load1{sel} / pcdn_api_edge_cpus{sel}"},
        {"ref": "I", "expr": f"pcdn_api_edge_uptime_24h_percent{sel}"},
        {"ref": "J", "expr": f"pcdn_api_edge_uptime_30d_percent{sel}"},
    ], h=10, description=BRIDGE_NOTE, rename={
        "Value #A": "online", "Value #B": "shed", "Value #C": "capacity used %", "Value #D": "tx Mbps",
        "Value #E": "rx Mbps", "Value #F": "capacity Mbps", "Value #G": "connections",
        "Value #H": "load1 / cpu", "Value #I": "uptime 24h %", "Value #J": "uptime 30d %"},
        units={"capacity used %": "percent", "uptime 24h %": "percent", "uptime 30d %": "percent",
               "load1 / cpu": "percentunit"})
    ts(d, "Capacity used % (max of rx/tx vs capacity_mbps)", [q(load, "{{edge}}")], unit="percent", min_=0,
       description="Above ~100% the controller sheds the edge from DNS. " + BRIDGE_NOTE)
    ts(d, "Throughput tx (Mbps)", [q(f"pcdn_api_edge_tx_mbps{sel}", "{{edge}}")], unit="Mbits", min_=0,
       description=BRIDGE_NOTE)
    ts(d, "Connections", [q(f"pcdn_api_edge_connections{sel}", "{{edge}}")], min_=0, description=BRIDGE_NOTE)
    ts(d, "Load per CPU", [q(f"pcdn_api_edge_load1{sel} / pcdn_api_edge_cpus{sel}", "{{edge}}")],
       unit="percentunit", min_=0, description=BRIDGE_NOTE)
    ts(d, "Uptime 24h %", [q(f"pcdn_api_edge_uptime_24h_percent{sel}", "{{edge}}")], unit="percent",
       max_=100, description=BRIDGE_NOTE)
    ts(d, "Online (1 = heartbeat fresh)", [q(f"pcdn_api_edge_online{sel}", "{{edge}}")], min_=0, max_=1,
       description=BRIDGE_NOTE)

    d.row("Edge groups — 3-day p95 vs capacity (SPEC §15.5)", description=BRIDGE_NOTE)
    d.add("bargauge", "Capacity used (p95, 3 days)",
          [q(f"pcdn_api_group_capacity_used_percent{sel}", "{{group}}", instant=True)],
          w=8, h=7, field={"unit": "percent", "min": 0, "max": 100,
                           "thresholds": thresholds((None, "green"), (70, "orange"), (85, "red")),
                           "color": {"mode": "thresholds"}},
          options={"orientation": "horizontal", "displayMode": "gradient",
                   "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}},
          description=BRIDGE_NOTE)
    ts(d, "p95 vs capacity (Mbps)", [q(f"pcdn_api_group_p95_mbps{sel}", "{{group}} p95"),
                                     q(f"pcdn_api_group_capacity_mbps{sel}", "{{group}} capacity")],
       w=16, h=7, unit="Mbits", min_=0, description=BRIDGE_NOTE)
    return d


def traffic():
    d = Dash("pcdn-traffic", "Pasargad CDN — Traffic & cache",
             "Platform traffic, cache hit ratio and status classes. " + BRIDGE_NOTE, tags=["traffic"])
    d.row("Rolling 24 hours (api-bridge: GET /api/v1/analytics?period=24h)", description=BRIDGE_NOTE)
    stat(d, "Requests (24h)", "sum(pcdn_api_24h_requests)", unit="short")
    stat(d, "Traffic (24h)", "sum(pcdn_api_24h_bytes)", unit="bytes")
    stat(d, "Cache hit ratio (24h)", "sum(pcdn_api_24h_cache_hits) / sum(pcdn_api_24h_requests > 0)",
         unit="percentunit", decimals=1, steps=((None, "red"), (0.5, "orange"), (0.8, "green")))
    stat(d, "5xx ratio (24h)", "sum(pcdn_api_24h_status_requests_5xx) / sum(pcdn_api_24h_requests > 0)",
         unit="percentunit", decimals=2, steps=((None, "green"), (0.01, "orange"), (0.05, "red")))
    stat(d, "Traffic this month", "sum(pcdn_api_month_bytes)", unit="bytes")
    stat(d, "Requests this month", "sum(pcdn_api_month_requests)", unit="short")

    d.row("Last completed hour", description=BRIDGE_NOTE)
    ts(d, "Requests per hour", [q("sum(pcdn_api_last_hour_requests)", "requests"),
                                q("sum(pcdn_api_last_hour_cache_hits)", "cache hits")], min_=0, unit="short")
    ts(d, "Bytes per hour", [q("sum(pcdn_api_last_hour_bytes)", "bytes")], unit="bytes", min_=0)
    ts(d, "Cache hit ratio (hourly)",
       [q("sum(pcdn_api_last_hour_cache_hits) / sum(pcdn_api_last_hour_requests > 0)", "hit ratio"),
        q("sum(pcdn_api_24h_cache_hits) / sum(pcdn_api_24h_requests > 0)", "24h rolling")],
       unit="percentunit", min_=0, max_=1)
    ts(d, "Status classes (24h rolling)", [
        q("sum(pcdn_api_24h_status_requests_2xx)", "2xx"), q("sum(pcdn_api_24h_status_requests_3xx)", "3xx"),
        q("sum(pcdn_api_24h_status_requests_4xx)", "4xx"), q("sum(pcdn_api_24h_status_requests_5xx)", "5xx")],
       stack=True, unit="short", min_=0)

    d.row("Usage pipeline (controller /metrics)")
    ts(d, "Usage batches accepted from edges / min",
       [q("sum(rate(pcdn_usage_batches_ingested_total[$__rate_interval])) * 60", "batches/min")], w=24, h=7,
       min_=0, description="Drops to 0 when edges stop reporting usage (billing data gap).")
    return d


def security():
    d = Dash("pcdn-security", "Pasargad CDN — Security events",
             "Platform-wide security event counts by source (SPEC §4). " + BRIDGE_NOTE, tags=["security"])
    sources = ("waf", "firewall", "ratelimit", "challenge", "ddos", "hotlink", "bots")
    d.row("Last 24 hours (rolling)", description=BRIDGE_NOTE)
    stat(d, "Security events (24h)", " + ".join(f"sum(pcdn_api_24h_security_events_{s})" for s in sources),
         unit="short", w=6)
    stat(d, "Events in last completed hour", "sum(pcdn_api_last_hour_security_events_total)", unit="short",
         w=6)
    stat(d, "4xx ratio (24h)", "sum(pcdn_api_24h_status_requests_4xx) / sum(pcdn_api_24h_requests > 0)",
         unit="percentunit", decimals=2, w=6, steps=((None, "green"), (0.1, "orange"), (0.3, "red")))
    stat(d, "Audit log rows", "sum(pcdn_audit_log_entries)", unit="short", w=6,
         description="Controller audit log size (/metrics).")
    d.add("bargauge", "Events by source (24h)",
          [q(f"sum(pcdn_api_24h_security_events_{s})", s, instant=True) for s in sources],
          w=8, h=9, field={"unit": "short", "color": {"mode": "palette-classic"}},
          options={"orientation": "horizontal", "displayMode": "basic",
                   "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}},
          description=BRIDGE_NOTE)
    ts(d, "Events by source (24h rolling)",
       [q(f"sum(pcdn_api_24h_security_events_{s})", s) for s in sources], w=16, h=9, stack=True,
       unit="short", min_=0, description=BRIDGE_NOTE)
    ts(d, "Events per hour (last completed hour)",
       [q("sum(pcdn_api_last_hour_security_events_total)", "events")], w=24, h=7, unit="short", min_=0,
       description="Per-site events and IPs stay in the admin panel / GET /api/v1/events.")
    return d


def tunnel():
    sel = '{group="tunnel"}'
    d = Dash("pcdn-tunnel", "Pasargad CDN — Tunnel quality",
             "Tunnel edge group (group=tunnel): availability, load, capacity. Per-site tunnel quality "
             "(origin RTT, reconnects) stays per customer in the admin API and is not exported. "
             + BRIDGE_NOTE, tags=["tunnel"])
    d.row("Tunnel edges (api-bridge)", description=BRIDGE_NOTE)
    stat(d, "Tunnel edges online", f"sum(pcdn_api_edge_online{sel})", steps=((None, "red"), (1, "green")))
    stat(d, "Tunnel edges enabled", f"sum(pcdn_api_edge_enabled{sel})")
    stat(d, "Shed", f"sum(pcdn_api_edge_shed{sel})", steps=((None, "green"), (1, "orange")))
    stat(d, "Worst 24h uptime", f"min(pcdn_api_edge_uptime_24h_percent{sel})", unit="percent",
         steps=((None, "red"), (95, "orange"), (99.5, "green")))
    stat(d, "Group p95 (3 days)", f"sum(pcdn_api_group_capacity_used_percent{sel})", unit="percent",
         steps=((None, "green"), (70, "orange"), (85, "red")))
    stat(d, "Connections", f"sum(pcdn_api_edge_connections{sel})", unit="short")
    load = (f"100 * (pcdn_api_edge_tx_mbps{sel} > pcdn_api_edge_rx_mbps{sel} or pcdn_api_edge_rx_mbps{sel})"
            f" / (pcdn_api_edge_capacity_mbps{sel} > 0)")
    ts(d, "Capacity used %", [q(load, "{{edge}}")], unit="percent", min_=0)
    ts(d, "Throughput (Mbps)", [q(f"pcdn_api_edge_tx_mbps{sel}", "{{edge}} tx"),
                                q(f"pcdn_api_edge_rx_mbps{sel}", "{{edge}} rx")], unit="Mbits", min_=0)
    ts(d, "Uptime 24h / 30d %", [q(f"pcdn_api_edge_uptime_24h_percent{sel}", "{{edge}} 24h"),
                                 q(f"pcdn_api_edge_uptime_30d_percent{sel}", "{{edge}} 30d")],
       unit="percent", max_=100)
    ts(d, "Group p95 vs capacity (Mbps)", [q(f"pcdn_api_group_p95_mbps{sel}", "p95"),
                                           q(f"pcdn_api_group_capacity_mbps{sel}", "capacity")],
       unit="Mbits", min_=0)
    return d


def queues():
    d = Dash("pcdn-queues", "Pasargad CDN — Webhooks, log export & jobs",
             "Background queues and scheduler health (controller /metrics).", tags=["queues"])
    d.row("Queues")
    stat(d, "Webhooks pending", 'sum(pcdn_webhook_deliveries{status="pending"})', unit="short",
         steps=((None, "green"), (100, "orange"), (500, "red")))
    stat(d, "Webhooks failed (7d)", 'sum(pcdn_webhook_deliveries{status="failed"})', unit="short",
         steps=((None, "green"), (50, "orange")))
    stat(d, "Log export spooled records", "sum(pcdn_log_export_pending_records)", unit="short",
         steps=((None, "green"), (1e5, "orange"), (1e6, "red")))
    stat(d, "Last good backup", "max(pcdn_backup_last_success_age_seconds)", unit="s",
         steps=((None, "green"), (26 * 3600, "orange"), (50 * 3600, "red")), noValue="never")
    stat(d, "Scheduler last run", "max(pcdn_scheduler_last_run_age_seconds)", unit="s",
         steps=((None, "green"), (300, "orange"), (600, "red")))
    stat(d, "DNS last clean sync", "max(pcdn_dns_last_sync_age_seconds)", unit="s",
         steps=((None, "green"), (600, "orange"), (900, "red")))
    ts(d, "Webhook deliveries held", [q("sum by (status) (pcdn_webhook_deliveries)", "{{status}}")],
       unit="short", min_=0)
    ts(d, "Log export backlog (records)", [q("sum(pcdn_log_export_pending_records)", "spooled")],
       unit="short", min_=0, description="Hourly chunks are uploaded to customer buckets; >72h are dropped.")

    d.row("Scheduler jobs")
    ts(d, "Seconds since each job last completed",
       [q("max by (exported_job) (pcdn_scheduler_job_last_run_age_seconds)", "{{exported_job}}")],
       w=16, h=9, unit="s", min_=0,
       description="Every job runs on each scheduler tick (SCHEDULER_INTERVAL); a growing line = failing job.")
    table(d, "Job age now", [{"ref": "A", "expr": "max by (exported_job) (pcdn_scheduler_job_last_run_age_seconds)"}],
          w=8, h=9, rename={"exported_job": "job", "Value": "age", "Value #A": "age"}, units={"age": "s"})
    d.row("Storage")
    d.add("text", "Object storage", [], w=24, h=3,
          options={"mode": "markdown", "content":
                   "The controller's `/metrics` exposes **no** object-storage (MinIO) queue metrics yet. "
                   "MinIO's own `/minio/v2/metrics/cluster` can be added as a scrape job (bearer token from "
                   "`mc admin prometheus generate`); see docs/MONITORING.md."})
    return d


ALL = [overview, edges, traffic, security, tunnel, queues]


def render() -> dict[str, str]:
    return {f"{fn().uid}.json": json.dumps(fn().json(), indent=2, ensure_ascii=False) + "\n" for fn in ALL}


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    check = "--check" in sys.argv
    stale = []
    for name, text in render().items():
        path = OUT / name
        if check:
            if not path.exists() or path.read_text(encoding="utf-8") != text:
                stale.append(name)
        else:
            path.write_text(text, encoding="utf-8")
            print("wrote", path)
    if stale:
        print("stale dashboards (re-run gen_dashboards.py):", ", ".join(stale))
        sys.exit(1)
