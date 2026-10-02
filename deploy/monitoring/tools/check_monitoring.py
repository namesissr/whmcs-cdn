#!/usr/bin/env python3
"""Static checks for deploy/monitoring (run in CI; stdlib only, promtool optional).

  1. Grafana dashboards: valid JSON, unique uid / panel ids, grid inside 24 columns, every panel on
     the provisioned datasource uid, and identical to what tools/gen_dashboards.py generates.
  2. Every pcdn_* series referenced by a dashboard or an alert rule really exists: either emitted by
     controller/app/routes_metrics.py or mapped by json-exporter/config.yml (api-bridge).
  3. With promtool on PATH (or $PROMTOOL): every dashboard expression parses as PromQL
     (wrapped as recording rules), plus `promtool check rules` on the alert rules.

Usage: python3 deploy/monitoring/tools/check_monitoring.py
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
MON = HERE.parent
REPO = MON.parent.parent
DASH_DIR = MON / "grafana" / "dashboards"
DS_UID = "pcdn-prometheus"
PANEL_TYPES = {"row", "stat", "timeseries", "table", "bargauge", "text", "piechart", "gauge"}

errors: list[str] = []


def err(msg: str):
    errors.append(msg)


def known_metrics() -> tuple[set[str], set[str]]:
    src = (REPO / "controller" / "app" / "routes_metrics.py").read_text(encoding="utf-8")
    controller = set(re.findall(r'out\.metric\(\s*"(pcdn_[a-z0-9_]+)"', src))
    if not controller:
        err("could not read any metric name from controller/app/routes_metrics.py")
    bridge: set[str] = set()
    # tiny YAML scan of json-exporter/config.yml: "- name: X" followed by a values: block
    name = None
    in_values = False
    for line in (MON / "json-exporter" / "config.yml").read_text(encoding="utf-8").splitlines():
        m = re.match(r"\s*- name:\s*(\S+)", line)
        if m:
            name, in_values = m.group(1), False
            continue
        if re.match(r"\s*values:\s*$", line):
            in_values = True
            continue
        m = re.match(r"\s{10}([A-Za-z0-9_]+):\s*'", line)
        if in_values and name and m:
            bridge.add(f"{name}_{m.group(1)}")
        elif in_values and line.strip() and not line.startswith(" " * 10):
            in_values = False
    return controller, bridge


def dashboards() -> list[tuple[str, dict]]:
    out = []
    for path in sorted(DASH_DIR.glob("*.json")):
        try:
            out.append((path.name, json.loads(path.read_text(encoding="utf-8"))))
        except ValueError as e:
            err(f"{path.name}: invalid JSON: {e}")
    if not out:
        err("no dashboards found")
    return out


def check_dashboard(name: str, d: dict) -> list[str]:
    exprs = []
    for key in ("uid", "title", "panels", "schemaVersion"):
        if key not in d:
            err(f"{name}: missing {key}")
    ids = set()
    for p in d.get("panels", []):
        pid = p.get("id")
        if pid in ids:
            err(f"{name}: duplicate panel id {pid}")
        ids.add(pid)
        if p.get("type") not in PANEL_TYPES:
            err(f"{name}: panel {pid} has unexpected type {p.get('type')}")
        g = p.get("gridPos") or {}
        if not all(k in g for k in ("x", "y", "w", "h")) or g["x"] + g["w"] > 24 or g["w"] <= 0:
            err(f"{name}: panel {pid} '{p.get('title')}' has a bad gridPos {g}")
        if p.get("type") in ("row", "text"):
            continue
        if (p.get("datasource") or {}).get("uid") != DS_UID:
            err(f"{name}: panel {pid} '{p.get('title')}' not on datasource {DS_UID}")
        if not p.get("targets"):
            err(f"{name}: panel {pid} '{p.get('title')}' has no targets")
        for t in p.get("targets", []):
            if (t.get("datasource") or {}).get("uid") != DS_UID:
                err(f"{name}: panel {pid} target {t.get('refId')} not on datasource {DS_UID}")
            if not t.get("expr"):
                err(f"{name}: panel {pid} target {t.get('refId')} has no expr")
            else:
                exprs.append(t["expr"])
    for v in d.get("templating", {}).get("list", []):
        if v.get("type") == "query":
            exprs.append(re.sub(r"^label_values\((.*),\s*\w+\)$", r"\1", v.get("definition", "")))
    return exprs


def rule_exprs() -> list[tuple[str, str]]:
    out = []
    for path in sorted((MON / "prometheus" / "rules").glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        # single-line and block (|) expressions
        for m in re.finditer(r"^\s+expr:[ \t]*(?:\|[ \t]*\n((?:[ ]{10,}.*\n)+)|(.+)$)", text, re.M):
            out.append((path.name, (m.group(1) or m.group(2) or "").strip()))
    return out


def substitute(expr: str) -> str:
    return (expr.replace("$__rate_interval", "5m").replace("$__interval", "1m")
            .replace("$group", ".*"))


def main() -> int:
    controller, bridge = known_metrics()
    known = controller | bridge
    all_exprs: list[tuple[str, str]] = []
    uids = set()
    for name, d in dashboards():
        if d.get("uid") in uids:
            err(f"{name}: duplicate dashboard uid {d.get('uid')}")
        uids.add(d.get("uid"))
        all_exprs += [(name, e) for e in check_dashboard(name, d)]
    all_exprs += rule_exprs()

    used = set()
    for where, expr in all_exprs:
        for metric in re.findall(r"\b(pcdn_[a-z0-9_]+)\b", expr):
            used.add(metric)
            if metric not in known:
                err(f"{where}: unknown series {metric} in: {expr[:120]}")

    gen = subprocess.run([sys.executable, str(HERE / "gen_dashboards.py"), "--check"],
                         capture_output=True, text=True)
    if gen.returncode:
        err(gen.stdout.strip() or gen.stderr.strip())

    promtool = os.environ.get("PROMTOOL") or shutil.which("promtool")
    if promtool:
        with tempfile.TemporaryDirectory() as tmp:
            rules = Path(tmp) / "dashboard-exprs.yml"
            lines = ["groups:", "  - name: dashboard-exprs", "    rules:"]
            for i, (where, expr) in enumerate(all_exprs):
                lines.append(f"      - record: check:expr_{i}")
                lines.append(f"        expr: {json.dumps(substitute(expr))}")
            rules.write_text("\n".join(lines) + "\n", encoding="utf-8")
            r = subprocess.run([promtool, "check", "rules", str(rules)], capture_output=True, text=True)
            if r.returncode:
                err("PromQL parse errors in dashboard/rule expressions:\n" + r.stdout + r.stderr)
            r = subprocess.run([promtool, "check", "rules", *map(str, (MON / "prometheus" / "rules").glob("*.yml"))],
                               capture_output=True, text=True)
            if r.returncode:
                err("promtool check rules failed:\n" + r.stdout + r.stderr)
            r = subprocess.run([promtool, "test", "rules", "tests/pcdn-alerts.test.yml"],
                               cwd=MON / "prometheus", capture_output=True, text=True)
            if r.returncode:
                err("promtool test rules failed:\n" + r.stdout + r.stderr)
    else:
        print("note: promtool not found; PromQL syntax not checked (set $PROMTOOL)")

    unused = sorted(controller - used)
    print(f"{len(uids)} dashboards, {len(all_exprs)} expressions, "
          f"{len(controller)} controller + {len(bridge)} bridge series known")
    if unused:
        print("controller series not used by any dashboard/rule:", ", ".join(unused))
    for e in errors:
        print("ERROR:", e)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
