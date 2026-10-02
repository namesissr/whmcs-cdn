"""The per-site njs data (sites.js entries): firewall, WAF, rate limits, bots, challenges and the
other values pcdn.js reads at request time. Only validated / typed values end up here."""

import re

from ..common import (
    FW_ACTIONS, FW_FIELDS, FW_OPS, SAFE_CIDR, SAFE_HEADER, SAFE_ID, SAFE_NAME, SAFE_PATTERN, WAF_GROUPS,
    _int, _sec, wildcard_re,
)
from ..settings import log
from ..validation.regex import regex_unsafe
from ..validation.rules import WAF_PACKS, norm_bots, norm_image_v2, page_rules


def site_js(site: dict, hosts: list, pools: dict, sslo: dict, tunnel: dict | None = None,
            tf_resp: list | None = None, video: dict | None = None) -> dict:
    """Per-site data for njs (sites.js). Only validated / typed values end up here."""
    fw = _sec(site, "firewall")
    rules = []
    for r in fw.get("rules") or []:
        if not isinstance(r, dict):
            continue
        rid = str(r.get("id") or "").lower()
        if r.get("enabled") is False or not SAFE_ID.match(rid) or r.get("action") not in FW_ACTIONS:
            continue
        conds = []
        for c in r.get("conditions") or []:
            if not isinstance(c, dict) or c.get("field") not in FW_FIELDS or c.get("op") not in FW_OPS:
                break
            val = c.get("value")
            val = [str(x) for x in val] if isinstance(val, list) else str(val if val is not None else "")
            if c["op"] == "regex":   # security review H2: re-checked on the edge, unsafe -> rule skipped
                why = next((w for w in (regex_unsafe(x, ascii_only=False) for x in (val if isinstance(val, list) else [val]))
                            if w), None)
                if why:
                    log.warning("site %s: firewall rule %s skipped: unsafe regex (%s)", site.get("id"), rid, why)
                    break
            cond = {"field": c["field"], "op": c["op"], "value": val}
            if c["field"] == "header":
                if not SAFE_HEADER.match(str(c.get("name") or "")):
                    break
                cond["name"] = c["name"]
            conds.append(cond)
        else:  # only rules whose every condition is understood
            if conds:
                rules.append({"id": rid, "action": r["action"], "conditions": conds})

    rl = []
    for r in (_sec(site, "ratelimit").get("rules") or []):
        rid, pat = str(r.get("id") or "").lower(), str(r.get("path") or "/*")
        if r.get("enabled") is False or not SAFE_ID.match(rid) or not SAFE_PATTERN.match(pat):
            continue
        rl.append({"id": rid, "path_re": wildcard_re(pat, js=True),
                   "methods": [str(m).upper() for m in r.get("methods") or [] if re.match(r"^[A-Za-z]{1,16}$", str(m))],
                   "requests": _int(r.get("requests"), 10, 1, 1000000), "period": _int(r.get("period"), 60, 1, 3600),
                   "action": r.get("action") if r.get("action") in ("block", "challenge", "captcha") else "block",
                   "block_seconds": _int(r.get("block_seconds"), 600, 1, 86400)})

    waf = _sec(site, "waf")
    excl = []
    for e in waf.get("exclusions") or []:
        path = e.get("path")
        if path and not SAFE_PATTERN.match(str(path)):
            continue
        excl.append({"rule_id": _int(e.get("rule_id"), 0, 0, 99999999), "path_re": wildcard_re(path, js=True) if path else None})

    hl, dd, im = _sec(site, "hotlink"), _sec(site, "ddos"), _sec(site, "image")
    # SPEC §14.2 additions appear only when used, so sites without them keep a byte-identical entry
    packs = list(dict.fromkeys(p for p in (waf.get("packs") if isinstance(waf.get("packs"), list) else [])
                               if p in WAF_PACKS))
    extra = {}
    bots = norm_bots(site)
    if bots:
        extra["bots"] = bots
    if tf_resp:
        extra["tf_resp"] = tf_resp
    if tunnel:   # SPEC §15.2 (tunnel sites only, so other sites keep a byte-identical entry)
        extra["tunnel_fair"] = bool(tunnel["fair_share"])
    if video and video["prefetch"]:   # SPEC §16.5 (video sites only)
        extra["video"] = {"prefetch": True}
    return dict({
        "domain": site["domain"],
        "secret": str(site.get("secret") or ""),
        "hosts": hosts,
        "blocked_ips": [str(c) for c in (site.get("blocked_ips") or []) if SAFE_CIDR.match(str(c))],
        "min_tls": "1.3" if sslo.get("min_tls") == "1.3" else "1.2",
        "firewall": {"default_action": "block" if fw.get("default_action") == "block" else "allow", "rules": rules},
        "hotlink": {"enabled": bool(hl.get("enabled")),
                    "extensions": [str(e) for e in (hl.get("extensions") or []) if re.match(r"^[A-Za-z0-9]{1,10}$", str(e))],
                    "allowed_referers": [str(h).lower() for h in (hl.get("allowed_referers") or []) if SAFE_NAME.match(str(h).lower())],
                    "allow_empty": hl.get("allow_empty", True) is not False},
        "ratelimit": rl,
        "ddos": {"mode": dd.get("mode") if dd.get("mode") in ("auto", "js", "captcha") else "off",
                 "threshold_rps": _int(dd.get("threshold_rps"), 200, 1, 10000000),
                 "clearance_ttl": _int(dd.get("clearance_ttl"), 3600, 60, 30 * 86400)},
        "waf": dict({"mode": waf.get("mode") if waf.get("mode") in ("detect", "block") else "off",
                     "paranoia": _int(waf.get("paranoia"), 1, 1, 3),
                     "groups": [g for g in (waf.get("groups") or []) if g in WAF_GROUPS],
                     "exclusions": excl,
                     "off_paths": [r["_jre"] for r in page_rules(site) if r.get("waf") is False]},
                    **({"packs": packs} if packs else {})),
        "pools": pools,
        "image": dict({"enabled": bool(im.get("enabled")), "quality": _int(im.get("quality"), 85, 1, 100),
                       "max_width": _int(im.get("max_width"), 2000, 16, 10000)},
                      **{k: v for k, v in norm_image_v2(site).items() if v}),   # SPEC §16.6, only when used
        # prefixes where only firewall allow/block/log rules apply (tunnel mode)
        "tunnel_paths": [p["path"] for p in tunnel["paths"]] if tunnel else [],
    }, **extra)
