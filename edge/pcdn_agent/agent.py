"""The agent loop: state file, bundle version and the Agent (config sync with reload coalescing,
purges, usage, heartbeat, logs)."""

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
import uuid

from .apply import (
    apply_config, ensure_cache_dirs, origin_guard_installed, render_rev, sync_origin_guard_peers,
)
from .capabilities import geoip_present, has_module
from .common import MAX_EVENTS, MAX_ITEMS, _int
from .controller import Controller
from .functions import functions_enabled, read_fn_usage, sync_functions
from .heartbeat import collect_metrics, count_draining_workers, heartbeat_capabilities, net_sample
from .logship import LogShip
from .nodelogs import collect_logs, tunnel_map
from .purge import do_purge
from .reload import cert_digests, global_digest, site_digests
from .render.http import fair_hot, norm_node
from .render.shield import norm_shield
from .render.tree import render_tree
from .settings import AGENT_ERRORS, agent_source_files, log
from .usage import (
    gate_hour_merge, learn_hosts, live_cutoff, live_items, read_l4_usage, read_usage, trim_live_backlog, usage_item,
    video_hosts,
)
from .validation.gates import gate_sites
from .validation.rules import key_infos, with_cached_bot_ranges

HB_WAITING_ROOM = "waiting_room"        # heartbeat: {site_id: {active, queued}} (SPEC §18.1)
HB_ERRORS = "errors_last_hour"          # heartbeat: agent ERROR records of the last hour (SPEC §18.4)
HB_WR_SITES_MAX = 1000


# ----------------------------------------------------------------- main loop

def load_state(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return {}


def save_state(path: str, state: dict):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
        f.flush()
        try:  # F8: durable across power loss, but a filesystem rejecting fsync must not be fatal
            os.fsync(f.fileno())
        except OSError:
            pass
    os.replace(tmp, path)


def _new_batch_id() -> str:
    """Stable idempotency key for a usage batch (F7): the controller dedups on it, and the agent
    reuses it on every retry/replay of the same batch (persisted in the outbox)."""
    return uuid.uuid4().hex


def bundle_version(cfg: dict) -> str | None:
    """The running edge bundle version (SPEC §11.1): the value bootstrap.sh recorded, else a
    stable hash of the installed agent as a fallback. None when neither is available."""
    path = cfg.get("BUNDLE_VERSION_FILE") or ""
    try:
        if path and os.path.isfile(path):
            v = open(path, encoding="utf-8").read().strip()
            if v:
                return v[:64]
    except OSError:
        pass
    try:  # fallback: hash the running agent code (won't match the controller, but is a stable signal)
        h = hashlib.sha256()
        for path in agent_source_files():
            with open(path, "rb") as f:
                h.update(f.read())
        return "agent-" + h.hexdigest()[:10]
    except OSError:
        return None


def wr_heartbeat(raw: bytes, sites: list) -> dict:
    """The heartbeat `waiting_room` object from pcdn.js wrStats ({site domain: {active, queued}}): only
    the configured waiting-room sites, non-negative integers, at most HB_WR_SITES_MAX sites."""
    try:
        data = json.loads(raw or b"{}")
    except ValueError:
        return {}
    if not isinstance(data, dict):
        return {}
    out = {}
    for sid in sites:
        v = data.get(str(sid))
        if not isinstance(v, dict) or len(out) >= HB_WR_SITES_MAX:
            continue
        out[str(sid)] = {k: _int(v.get(k), 0, 0, 10 ** 9) for k in ("active", "queued")}
    return out


class Agent:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.ctl = Controller(cfg["CONTROLLER_URL"], cfg["EDGE_TOKEN"])
        self.state = load_state(cfg["STATE_FILE"])
        self.running = True
        self.last_usage = 0.0
        self.last_heartbeat = 0.0
        self.net_prev = None
        self.wr_stats = None

    @property
    def logship(self) -> LogShip:
        """The log-export sampler / spool / shipper (SPEC §14.3.2), bound to the current state."""
        ls = self.__dict__.get("_logship")
        if ls is None or ls.state is not self.state:
            ls = self.__dict__["_logship"] = LogShip(self.cfg, self.state)
        return ls

    def _reload_min_interval(self) -> float:
        """F5 reload back-pressure: base RELOAD_MIN_INTERVAL, doubled (up to 600 s) while more than
        2×nproc worker generations are still draining, so reloads never outpace worker shutdown."""
        base = _int(self.cfg.get("RELOAD_MIN_INTERVAL"), 120, 0, 3600)
        try:
            if count_draining_workers(self.cfg.get("PROC_DIR", "/proc")) > 2 * (os.cpu_count() or 1):
                return min(600, base * 2)
        except Exception:  # noqa: BLE001
            pass
        return base

    def _foreign_defer(self, body: dict, files: dict) -> int:
        """F21: seconds this change may be deferred because every changed site belongs to another
        edge group; 0 means apply now. Deferral needs a known node GROUP and per-site edge_group from
        the controller; a global-file change, an added/removed site, a status change or a cert
        rotation on any changed site force an immediate apply."""
        group = self.cfg.get("GROUP")
        if not group:
            return 0
        st = self.state
        cur, prev = site_digests(files), st.get("site_digests") or {}
        changed = {sid for sid in set(cur) | set(prev) if cur.get(sid) != prev.get(sid)}
        if not changed:
            return 0
        if global_digest(files) != st.get("global_digest"):
            return 0
        groups = {str(int(s["id"])): s.get("edge_group") for s in body.get("sites", [])}
        statuses = {str(int(s["id"])): s.get("status", "active") for s in body.get("sites", [])}
        cur_certs, prev_certs = cert_digests(files), st.get("cert_digests") or {}
        for sid in changed:
            if groups.get(sid) in (None, group):                       # own or unknown group
                return 0
            if statuses.get(sid) in ("suspended", "over_quota"):       # serving/blocking change
                return 0
            if cur_certs.get(sid) != prev_certs.get(sid):              # cert rotation
                return 0
        return _int(self.cfg.get("FOREIGN_DEFER"), 900, 0, 86400)

    def _store_applied(self, body, files, digest, etag, version, rev):
        st = self.state
        st["etag"], st["version"], st["render_rev"] = etag, version, rev
        st["tree_digest"] = digest
        st["site_digests"], st["cert_digests"] = site_digests(files), cert_digests(files)
        st["global_digest"] = global_digest(files)
        st["keyinfo"] = key_infos(body)   # cache-key shapes for exact-URL purges (SPEC §14.1)
        for k in ("pending_version", "pending_since"):
            st.pop(k, None)
        st["last_reload"] = time.monotonic()

    def sync_config(self):
        cfg, st = self.cfg, self.state
        rev = render_rev(cfg)
        root = cfg["NGINX_DIR"].rstrip("/")
        first_boot = not os.path.isfile(os.path.join(root, "http.conf"))
        headers = {}
        # While a version is pending we re-fetch the full config each poll so we always apply the
        # newest one (F5); the ETag is only used once everything has settled and applied cleanly.
        if (st.get("etag") and os.path.isdir(root) and st.get("render_rev") == rev
                and not st.get("pending_version") and not st.get("last_error")):
            headers["If-None-Match"] = st["etag"]
        code, hdrs, body = self.ctl.call("GET", "/edge/v1/config", headers=headers)
        if code == 304:
            return
        try:   # SPEC §14.3.2: log-export settings are agent-side only (never rendered, no reload)
            self.logship.update_config(body)
        except Exception as e:  # noqa: BLE001 - never let log export break config sync
            log.error("logship config update failed: %s", e)
        try:   # SPEC §15.1/§15.2: agent-side only (abnormal-end attribution, fair-share hot flag)
            st["tunnel_map"] = tunnel_map(body)
            st["node"] = norm_node(body, cfg)
            vh = video_hosts(body)   # SPEC §16.5 usage attribution (agent-side only, never rendered)
            if vh:
                st["video_hosts"] = vh
            else:
                st.pop("video_hosts", None)
            lh = learn_hosts(body)   # SPEC §17.1 waf_learn attribution (agent-side only)
            if lh:
                st["learn_hosts"] = lh
            else:
                st.pop("learn_hosts", None)
            wr = gate_sites(body)["wr"]   # SPEC §18.1 heartbeat waiting-room state (domains; agent-side only)
            if wr:
                st["wr_sites"] = wr
            else:
                st.pop("wr_sites", None)
        except Exception as e:  # noqa: BLE001
            log.error("tunnel map / node block update failed: %s", e)
        try:   # origin guard: private shield peers stay reachable (agent-side only, never rendered)
            sh = norm_shield(body)
            st["shield_peers"] = sh["peers"] if sh else []
        except Exception as e:  # noqa: BLE001
            log.error("shield peer update failed: %s", e)
        try:   # SPEC §16.9: the pcdn-fn code bundle (before the nginx tree: code precedes its route)
            sync_functions(body, cfg, st)
        except Exception as e:  # noqa: BLE001
            log.error("edge functions bundle update failed: %s", e)
        version = body["version"]
        etag = hdrs.get("ETag") or hdrs.get("etag")
        body = with_cached_bot_ranges(body, st)   # SPEC §14.2: keep the last good crawler ranges
        files, digest = render_tree(body, cfg)
        now = time.monotonic()

        # F20: an identical rendered tree needs no write/test/reload (covers controller version bumps
        # for fields the agent never renders, and agent upgrades that change nothing).
        if (digest == st.get("tree_digest") and os.path.isfile(os.path.join(root, "http.conf"))
                and not st.get("last_error")):
            ensure_cache_dirs(body, cfg)
            st["etag"], st["version"], st["render_rev"] = etag, version, rev
            st["keyinfo"] = key_infos(body)
            for k in ("pending_version", "pending_since"):
                st.pop(k, None)
            self._report(version, None)
            return

        def apply_now():
            err = apply_config(body, cfg, files, digest)
            st["last_error"] = err
            if err:
                log.error(err)
                self._report(st.get("version"), err)   # keep etag unset so the next poll retries
                return
            self._store_applied(body, files, digest, etag, version, rev)
            log.info("applied config %s (%d sites)", version[:12], len(body.get("sites", [])))
            self._report(version, None)

        if first_boot or bool(body.get("urgent")) or self._origin_guard_needs_bind(root):
            return apply_now()   # bootstrap / security-relevant / the origin guard just installed: at once

        # F5 coalescing: hold a freshly-seen version until it settles (unchanged across two polls) or
        # has been pending for RELOAD_MIN_INTERVAL, and never reload more often than that interval.
        settled = st.get("pending_version") == version
        if not settled:
            st["pending_version"], st["pending_since"] = version, now
        age = now - st.get("pending_since", now)
        min_interval = self._reload_min_interval()
        debounce = _int(cfg.get("RELOAD_DEBOUNCE"), 5, 0, 3600)
        if age < debounce or not (settled or age >= min_interval):
            return
        if now - st.get("last_reload", 0) < min_interval:
            return
        defer = self._foreign_defer(body, files)   # F21
        if defer and age < defer:
            log.info("deferring foreign-group config %s (%.0fs/%ds)", version[:12], age, defer)
            self._report(st.get("version"), st.get("last_error"))   # heartbeat during the deferral
            return
        apply_now()

    def _report(self, version, error):
        self.ctl.call("POST", "/edge/v1/heartbeat", self._hb(applied_version=version, error=error))

    def sync_purges(self):
        after = int(self.state.get("purge_id", 0))
        _, _, items = self.ctl.call("GET", f"/edge/v1/purges?after={after}")
        if "purge_id" not in self.state:
            # first run: a fresh node has an empty cache, so skip history and remember where we are
            self.state["purge_id"] = items[-1]["id"] if items else 0
            return
        kinfo = self.state.get("keyinfo") or {}
        for it in items or []:
            n = do_purge(it, self.cfg, kinfo.get(str(it.get("site_id"))))
            what = "ALL" if it.get("everything") else (it["urls"] or it.get("prefixes") or "ALL")
            log.info("purge %s %s -> %d entries", it["domain"], what, n)
            self.state["purge_id"] = it["id"]

    def _enqueue_usage(self):
        """Move newly-read pending usage / events into the persisted outbox (F7): each entry gets a
        stable batch_id that is reused on every retry, so a timed-out or replayed POST is deduped by
        the controller instead of double-billing."""
        pending = self.state.setdefault("pending", {})
        events = self.state.setdefault("events", [])
        live = self.state.setdefault("live", {})
        if not pending and not events and not live:
            return
        outbox = self.state.setdefault("outbox", [])
        keys, evs = list(pending), list(events)
        lh = self.state.get("waf_learn_hour")   # SPEC §17.1 hour-to-date statistics (read only here)
        try:   # SPEC §18.1: waiting-room maxima are hour-to-date values
            gate_hour_merge(self.state, pending)
        except Exception as e:  # noqa: BLE001 - never let it block the usage push
            log.error("waiting-room usage merge failed: %s", e)
        now = time.time()
        cutoff = live_cutoff(now)
        entries = []
        while keys or evs:
            bk, keys = keys[:MAX_ITEMS], keys[MAX_ITEMS:]
            be, evs = evs[:MAX_EVENTS], evs[MAX_EVENTS:]
            entries.append({"id": _new_batch_id(), "ts": now, "items": [usage_item(k, pending[k], lh) for k in bk],
                            "events": be})
        # SPEC §14.3.1: the host-minutes ride in the same outbox entry (same batch_id, so a retry stays
        # idempotent); ≤ LIVE_MAX per POST, oldest minutes dropped beyond that (best-effort)
        lv = live_items(live, cutoff)
        if lv:
            if not entries:
                entries.append({"id": _new_batch_id(), "ts": now, "items": [], "events": []})
            entries[0]["live"] = lv
        outbox.extend(entries)
        pending.clear()
        del events[:]
        live.clear()
        trim_live_backlog(outbox, cutoff)

    def push_usage(self):
        ls = self.logship
        ls.begin_pass()
        try:
            read_usage(self.state, self.cfg["ACCESS_LOG"], ship=ls if ls.active else None)
        finally:
            ls.end_pass()   # the partial log-export batch of this read goes to the spool (never raises)
        try:   # SPEC §16.4: L4 sessions from the stream access log (absent on nodes without L4 apps)
            read_l4_usage(self.state, self.cfg.get("L4_ACCESS_LOG") or "/var/log/nginx/pcdn-l4.log")
        except Exception as e:  # noqa: BLE001 - never let L4 accounting break HTTP usage
            log.error("L4 usage read failed: %s", e)
        if functions_enabled(self.cfg):   # SPEC §16.9: pcdn-fn usage lines
            try:
                read_fn_usage(self.state, self.cfg.get("FN_USAGE_LOG") or "/var/log/pcdn-fn/usage.log")
            except Exception as e:  # noqa: BLE001 - never let function accounting break HTTP usage
                log.error("functions usage read failed: %s", e)
        self._enqueue_usage()
        # F8: persist the outbox (with its batch_ids and the advanced log_pos) BEFORE the first POST,
        # so a crash or restart replays the SAME batch rather than a different one. A save failure is
        # non-fatal (skip pushing this tick) so state persistence issues never kill the agent.
        try:
            save_state(self.cfg["STATE_FILE"], self.state)
        except OSError as e:
            log.error("state save before usage push failed, skipping push: %s", e)
            return
        outbox = self.state.setdefault("outbox", [])
        max_age = _int(self.cfg.get("USAGE_OUTBOX_MAX_DAYS"), 6, 1, 60) * 86400
        now, kept = time.time(), []
        for e in outbox:
            if now - e.get("ts", now) > max_age:   # bound by the controller's dedup retention window
                log.warning("dropping usage batch %s older than %d days", e.get("id"), max_age // 86400)
                continue
            kept.append(e)
        outbox[:] = kept
        trim_live_backlog(outbox, live_cutoff(now))   # retried entries never carry minutes older than 24 h
        timeout = _int(self.cfg.get("USAGE_TIMEOUT"), 150, 10, 600)
        for entry in list(outbox):
            body = {"batch_id": entry["id"], "items": entry["items"]}
            if entry["events"]:
                body["events"] = entry["events"]
            if entry.get("live"):
                body["live"] = entry["live"]
            try:
                self.ctl.call("POST", "/edge/v1/usage", body, timeout=timeout)   # retries reuse batch_id
            except urllib.error.HTTPError as e:
                # live data must never hold back the hourly usage: a request the controller rejects as
                # a whole (validation / size) is resent once without `live`, under the same batch_id
                # (a rejected request was not applied, so the dedup row does not exist yet)
                if e.code not in (400, 413, 422) or "live" not in body:
                    raise
                log.warning("usage batch %s rejected (HTTP %d) with live data; resending without it",
                            entry["id"], e.code)
                entry.pop("live", None)
                body.pop("live")
                self.ctl.call("POST", "/edge/v1/usage", body, timeout=timeout)
            outbox.remove(entry)

    def metrics(self) -> dict:
        """Current load; the first call measures the network rate over one second."""
        try:
            if self.net_prev is None or time.monotonic() - self.net_prev[0] < 1:
                self.net_prev = net_sample(self.cfg)
                time.sleep(1)
            cur = net_sample(self.cfg)
        except Exception:  # noqa: BLE001
            cur = None
        m = collect_metrics(self.cfg, self.net_prev, cur)
        if cur:
            self.net_prev = cur
        return m

    def _hb(self, **over) -> dict:
        """Base heartbeat body: bundle version + (when configured) region/role, so a fresh node
        self-registers into the right pool (SPEC §11.1). Overrides fill applied_version/error/metrics."""
        body: dict = {"bundle_version": bundle_version(self.cfg), "geoip": geoip_present(self.cfg),
                      "capabilities": heartbeat_capabilities(self.cfg)}   # SPEC §14.1
        if self.cfg.get("REGION"):
            body["region"] = self.cfg["REGION"]
        if self.cfg.get("GROUP"):
            body["group"] = self.cfg["GROUP"]
        body[HB_ERRORS] = AGENT_ERRORS.last_hour()   # SPEC §18.4
        body.update(over)
        return body

    def heartbeat(self):
        """Periodic heartbeat with load metrics (keeps applied_version / last error as reported) and
        the log-export spool state (SPEC §14.3.2: dropped records are counted here)."""
        extra = {}
        try:
            extra["logship"] = self.logship.stats()
        except Exception:  # noqa: BLE001 - informational only
            pass
        m = self.metrics()
        self.wr_stats = None
        try:
            self.fair_signal(m)
        except Exception as e:  # noqa: BLE001 - fair share is best-effort and fails open
            log.debug("fair share signal: %s", e)
        if self.wr_stats:   # SPEC §18.1: per-site waiting-room state of this node
            extra[HB_WAITING_ROOM] = self.wr_stats
        self.ctl.call("POST", "/edge/v1/heartbeat", self._hb(applied_version=self.state.get("version"),
                                                             error=self.state.get("last_error"),
                                                             metrics=m, **extra))

    def fair_signal(self, m: dict):
        """SPEC §15.2: tell nginx (localhost /__pcdn/fair, pcdn.js tunnelFair) whether the node is hot:
        tx_mbps >= 85 % of the node capacity; it stays hot until tx drops below 80 %. Sent on every
        heartbeat; the flag expires in nginx (180 s zone timeout) if the agent stops sending it."""
        if not has_module(self.cfg, "njs"):
            return
        node = self.state.get("node") or norm_node({}, self.cfg)
        was = bool(self.state.get("fair_hot"))
        self.state["fair_hot"] = hot = fair_hot(m.get("tx_mbps") or 0, node["capacity_mbps"], was)
        if hot != was:
            log.info("node %s (tx %.0f of %d Mbps): tunnel fair share %s", "hot" if hot else "no longer hot",
                     m.get("tx_mbps") or 0, node["capacity_mbps"],
                     f"active at {node['fair_share_pct']} %" if hot else "idle")
        port = _int(self.cfg.get("HTTP_PORT"), 80, 1, 65535)
        wr_sites = self.state.get("wr_sites") or []
        url = (f"http://127.0.0.1:{port}/__pcdn/fair?hot={node['fair_share_pct'] if hot else 0}"
               + ("&wr=1" if wr_sites else ""))
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(url, timeout=2) as r:
            raw = r.read(1 << 20)
        if wr_sites:   # SPEC §18.1: the same localhost call returns the waiting-room state (pcdn.js wrStats)
            self.wr_stats = wr_heartbeat(raw, wr_sites)

    def ship_logs(self):
        """Ship new WARN/ERROR/crit lines to the controller (SPEC §11.2). Fail-soft: never raises."""
        lines = collect_logs(self.state, self.cfg)
        if lines:
            self.ctl.call("POST", "/edge/v1/logs", {"lines": lines})

    def _origin_guard_needs_bind(self, root: str) -> bool:
        """The origin guard is installed but nginx still runs a tree from before INTERNAL_SRC
        (proxy_bind): its loopback-service hops would be rejected until the next apply, so the
        upgrade applies at once instead of waiting for the reload coalescing."""
        if not origin_guard_installed(self.cfg):
            return False
        try:
            with open(os.path.join(root, "http.conf")) as f:
                text = f.read()
        except OSError:
            return False
        return "$pcdn_rz_bind" not in text and "no image resizer" not in text

    def tick(self):
        for step in (self.sync_config, self.sync_purges):
            try:
                step()
            except Exception as e:  # noqa: BLE001
                log.error("%s failed: %s", step.__name__, e)
        try:
            sync_origin_guard_peers(self.cfg, self.state, self.state.get("shield_peers") or [])
        except Exception as e:  # noqa: BLE001 - never let the guard sync break the loop
            log.error("origin guard peer sync failed: %s", e)
        if time.time() - self.last_heartbeat >= int(self.cfg.get("HEARTBEAT_INTERVAL") or 60):
            try:
                self.heartbeat()
                self.last_heartbeat = time.time()
            except Exception as e:  # noqa: BLE001
                log.error("heartbeat failed: %s", e)
            try:
                self.ship_logs()
            except Exception as e:  # noqa: BLE001 - log shipping must never break the heartbeat
                log.error("log shipping failed: %s", e)
        if time.time() - self.last_usage >= int(self.cfg["USAGE_INTERVAL"]):
            try:
                self.push_usage()
                self.last_usage = time.time()
            except Exception as e:  # noqa: BLE001 - pending usage stays in state for next try
                log.error("usage push failed: %s", e)
        # SPEC §14.3.2: log export last, on its own cadence and time budget, so it never delays the
        # config sync, purges, heartbeat or usage of this tick (LogShip.ship)
        try:
            self.logship.ship(self.ctl)
        except Exception as e:  # noqa: BLE001 - log export is best-effort
            log.error("logship failed: %s", e)
        try:  # F8: a persistence failure must not exit the process (systemd would restart-and-replay)
            save_state(self.cfg["STATE_FILE"], self.state)
        except OSError as e:
            log.error("state save failed: %s", e)

    def loop(self):
        while self.running:
            self.tick()
            for _ in range(int(self.cfg["POLL_INTERVAL"])):
                if not self.running:
                    break
                time.sleep(1)
