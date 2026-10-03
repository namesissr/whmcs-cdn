"""Log export (SPEC §14.3.2): sampled, anonymised access-log records spooled on disk in batches and
shipped to the controller with retry-safe batch ids."""

import hashlib
import ipaddress
import json
import os
import re
import time
import urllib.error
import urllib.parse
import uuid
from datetime import datetime

from .common import TUNNEL_PROTOCOLS, _int
from .settings import log
from .usage import _CC


# ----------------------------------------------------------------- log export (SPEC §14.3.2)
#
# Per site the edge config carries `logs: {enabled, sample_rate, anonymize_ip}` (never the bucket or
# keys). While the agent reads the access log for usage it samples the records of enabled sites,
# builds the export record (anonymizing the IP first), and appends it to a batch; full batches (5000
# records or ~2 MiB) and, after each read, the partial one are written to the on-disk spool, one file
# per batch whose name carries its batch_id. Shipping runs on its own cadence after config / purges /
# usage in the same loop: oldest batch first, `POST /edge/v1/logship {batch_id, records}`, the file is
# deleted only on success and the SAME batch_id is resent on any retry (the controller dedups it).

LOGSHIP_MAX_RECORDS = 5000               # per batch = per POST (SPEC §14.3.2)
LOGSHIP_BATCH_BYTES = 2 * 1024 * 1024    # a batch is also closed at ~2 MiB, so one POST stays short
LOGSHIP_MAX_AGE = 72 * 3600              # the controller drops older records; so does the spool
LOGSHIP_RUN_BUDGET = 5.0                 # seconds per run after which no new POST is started
# CPU seconds record building may take per access-log read pass (that pass has 5 s for everything):
# beyond it the sampled records of the pass are dropped (counted), so export never slows usage
LOGSHIP_SAMPLE_BUDGET = 2.0
LOGSHIP_BACKOFF = (30, 900)              # first / max seconds between attempts after a failure
LOGSHIP_WARN_EVERY = 600                 # at most one "dropped" warning per 10 minutes
SPOOL_FILE = re.compile(r"^(\d{13})-([0-9a-f]{32})-(\d{1,6})\.jsonl$")


_IP_MEMO: dict = {}   # (address, anonymize) -> export value; visitors repeat, parsing an IP does not
_ISO_MEMO: list = [None, ""]
_JSON_LINE = json.JSONEncoder(ensure_ascii=False, separators=(",", ":"), check_circular=False)


def anonymize_ip(value) -> str:
    """IPv4: last octet zeroed; IPv6: only the first 48 bits kept (an IPv4-mapped IPv6 address is
    treated as IPv4); "" when not an IP. Idempotent, like the controller's re-application."""
    try:
        ip = ipaddress.ip_address(str(value or "").strip().strip("[]"))
    except ValueError:
        return ""
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.version == 4:
        return str(ipaddress.IPv4Address(int(ip) & 0xFFFFFF00))
    return str(ipaddress.IPv6Address(int(ip) >> 80 << 80))   # drops any %zone as well


def _clean_ip(value) -> str:
    try:
        return str(ipaddress.ip_address(str(value or "").strip().strip("[]")))
    except ValueError:
        return ""


def _s(v, n: int) -> str:
    """Visitor-controlled text, truncated to n characters. nginx logs non-UTF-8 bytes raw and
    json.loads(bytes) decodes them with surrogatepass, so a lone surrogate is replaced (U+FFFD): the
    record must stay encodable as UTF-8 all the way into the customer's export."""
    s = ("" if v is None else str(v))[:n]
    return s if s.isascii() else s.encode("utf-8", "surrogatepass").decode("utf-8", "replace")[:n]


def _no_query(v, n: int) -> str:
    """Path / URL without query string and fragment, truncated to n characters."""
    return _s(("" if v is None else str(v)).split("?", 1)[0].split("#", 1)[0], n)


def _num(v, cast, default=0):
    try:
        x = cast(v)
    except (TypeError, ValueError):
        return default
    return x if x == x and 0 <= x < 10 ** 15 else default   # NaN / negative / absurd -> default


def _export_ip(value, anonymize: bool) -> str:
    key = (value, anonymize)
    v = _IP_MEMO.get(key)
    if v is None:
        v = anonymize_ip(value) if anonymize else _clean_ip(value)
        if len(_IP_MEMO) >= 65536:
            _IP_MEMO.clear()
        _IP_MEMO[key] = v
    return v


def log_record(e: dict, host: str, dt: datetime, anonymize: bool) -> dict:
    """The export record of one access-log line (SPEC §14.3.2), IP already anonymized when asked.
    Keys in the order the controller writes them to the customer's objects."""
    cc = str(e.get("cc") or "").upper()
    if _ISO_MEMO[0] != dt:
        _ISO_MEMO[0], _ISO_MEMO[1] = dt, dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    ip = e.get("ip")
    return {"t": _ISO_MEMO[1], "host": _s(host, 253),
            "ip": _export_ip(ip if isinstance(ip, str) else str(ip or ""), anonymize),
            "method": _s(e.get("m"), 16), "scheme": _s(e.get("sc"), 8), "path": _no_query(e.get("u"), 2048),
            "status": _num(e.get("s"), int), "bytes": _num(e.get("b"), int),
            "rt": round(_num(e.get("rt"), float, 0.0), 3), "cache": _s(e.get("c"), 16),
            "country": cc if _CC.match(cc) else "", "ua": _s(e.get("ua"), 512),
            "referer": _no_query(e.get("rf"), 1024), "proto": _s(e.get("pr"), 16)}


def sample_point(raw: bytes) -> float:
    """Deterministic sampling key in [0, 1): a hash of the raw log line. The same line always gets
    the same decision (a re-read after a restart samples identically, tests are reproducible) and
    distinct lines are spread uniformly, so `sample_point(line) < sample_rate` keeps that fraction."""
    return int.from_bytes(hashlib.blake2b(raw, digest_size=8).digest(), "big") / 18446744073709551616.0


def _internal_path(uri: str) -> bool:
    """/__pcdn/... (health, challenge verification, captcha, ...) also when percent-encoded or
    with extra leading slashes; never exported."""
    head = uri[:64]
    if "%" in head:
        head = urllib.parse.unquote(head)
    return head.lstrip("/").startswith("__pcdn/") or head.lstrip("/") == "__pcdn"


def logship_sites(body: dict) -> dict:
    """{domain: [sample_rate, anonymize_ip] | None} from the edge config: every site with
    logs.enabled (rate clamped to 0.01..1, anonymize unless explicitly false), plus - as None - the
    disabled sites nested under an enabled domain, so the longest-suffix host -> site mapping (the
    controller's) never attributes their hosts to the enabled parent."""
    enabled, off = {}, set()
    for s in body.get("sites") or []:
        if not isinstance(s, dict):
            continue
        dom = str(s.get("domain") or "").lower().rstrip(".")
        if not dom or len(dom) > 253:
            continue
        lg = s.get("logs")
        if isinstance(lg, dict) and lg.get("enabled") is True:
            rate = _num(lg.get("sample_rate", 1.0), float, 1.0)
            enabled[dom] = [min(1.0, max(0.01, rate)), lg.get("anonymize_ip") is not False]
        else:
            off.add(dom)
    out: dict = dict(enabled)
    for dom in off:
        parts = dom.split(".")
        if dom not in out and any(".".join(parts[i:]) in enabled for i in range(1, len(parts))):
            out[dom] = None
    return out


class LogShip:
    """Sampling, spool and shipping of the log export (SPEC §14.3.2). Persistent bits live in
    state["logship"]: sites (logship_sites), cfg (last config version seen), off (config version at
    which the controller answered 404: shipping stays off until the version changes) and dropped
    (records dropped by the spool cap / age / a rejected batch, reported in the heartbeat)."""

    def __init__(self, cfg: dict, state: dict):
        self.cfg, self.state = cfg, state
        st = state.get("logship")
        if not isinstance(st, dict):
            st = state["logship"] = {}
        self.st = st
        self.dir = cfg.get("LOGSHIP_SPOOL_DIR") or os.path.join(
            os.path.dirname(cfg.get("STATE_FILE") or "/var/lib/pcdn/state.json"), "logship")
        try:
            mb = float(cfg.get("LOGSHIP_SPOOL_MAX_MB") or 256)
        except (TypeError, ValueError):
            mb = 256.0
        self.cap = int(min(max(mb, 0.001), 1e6) * 1024 * 1024)
        self.buf: list[str] = []
        self.buf_bytes = 0
        self.memo: dict = {}          # host -> (rate, anonymize) | None
        self.next_run = 0.0           # monotonic: shipping cadence / backoff
        self.backoff = 0
        self.last_warn = 0.0
        self.last_ms = 0              # batch names sort in creation order, also within one millisecond
        self.spent = 0.0              # record-building seconds in the current read pass
        self.over = 0                 # records not built this pass (sampling budget exhausted)
        self._dir_ok = False

    # ---- configuration
    def update_config(self, body: dict):
        """Called with every full config body (not on 304): new site settings, and a new version
        re-enables shipping after a 404."""
        self.st["sites"] = logship_sites(body)
        self.memo = {}
        ver = str(body.get("version") or "")
        if "off" in self.st and self.st["off"] != ver:
            self.st.pop("off", None)
            self.next_run = 0.0
            log.info("logship: config changed, shipping re-enabled")
        self.st["cfg"] = ver

    @property
    def active(self) -> bool:
        """Some site exports its logs (otherwise the reader skips the sampler entirely)."""
        return any(self.st.get("sites", {}).values())

    def site_for(self, host: str):
        """(sample_rate, anonymize_ip) of the site serving `host`, or None (longest domain suffix,
        like the controller's host -> site mapping)."""
        v = self.memo.get(host, False)
        if v is not False:
            return v
        sites = self.st.get("sites") or {}
        parts = host.split(".")
        v = None
        for i in range(len(parts) - 1):
            d = ".".join(parts[i:])
            if d in sites:
                v = tuple(sites[d]) if sites[d] else None
                break
        if len(self.memo) < 10000:
            self.memo[host] = v
        return v

    # ---- sampling
    def begin_pass(self):
        self.spent, self.over = 0.0, 0

    def end_pass(self):
        """After a read pass: spool the partial batch, count what the sampling budget skipped."""
        if self.over:
            self._dropped(self.over, f"sampling budget {LOGSHIP_SAMPLE_BUDGET:.0f} s per read pass")
            self.over = 0
        self.flush()

    def offer(self, e: dict, host: str, dt: datetime, raw: bytes | None):
        """Sample one access-log record: only sites with logs.enabled, never tunnel traffic or the
        edge's own /__pcdn/ endpoints; kept when sample_point(line) < sample_rate."""
        st = self.site_for(host)
        if st is None or e.get("tn") in TUNNEL_PROTOCOLS:
            return
        rate, anonymize = st
        if rate < 1.0:
            key = raw if raw is not None else json.dumps(e, sort_keys=True).encode()
            if sample_point(key) >= rate:
                return
        if _internal_path(str(e.get("u") or "")):
            return
        if self.spent > LOGSHIP_SAMPLE_BUDGET:
            self.over += 1
            return
        t0 = time.monotonic()
        line = _JSON_LINE.encode(log_record(e, host, dt, anonymize))
        self.buf.append(line)
        self.buf_bytes += len(line) + 1
        if len(self.buf) >= LOGSHIP_MAX_RECORDS or self.buf_bytes >= LOGSHIP_BATCH_BYTES:
            self.flush()
        self.spent += time.monotonic() - t0

    def flush(self):
        """Write the pending records as one spooled batch (never raises: export is best-effort)."""
        if not self.buf:
            return
        lines, self.buf, self.buf_bytes = self.buf, [], 0
        try:
            self._ensure_dir()
            self.last_ms = max(int(time.time() * 1000), self.last_ms + 1)
            name = f"{self.last_ms:013d}-{uuid.uuid4().hex}-{len(lines)}.jsonl"
            tmp = os.path.join(self.dir, ".tmp-" + name)
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
            os.replace(tmp, os.path.join(self.dir, name))
        except OSError as e:
            self._dropped(len(lines), f"spool write failed ({e})")
            return
        self.enforce()

    # ---- spool
    def _ensure_dir(self):
        if not self._dir_ok:
            os.makedirs(self.dir, mode=0o700, exist_ok=True)
            os.chmod(self.dir, 0o700)
            self._dir_ok = True

    def batches(self) -> list[tuple]:
        """Spooled batches oldest first: (name, ms, batch_id, records, size). Stale temp files of
        an interrupted write are removed."""
        try:
            names = os.listdir(self.dir)
        except OSError:
            return []
        out = []
        for n in names:
            p = os.path.join(self.dir, n)
            m = SPOOL_FILE.match(n)
            try:
                if m:
                    out.append((n, int(m.group(1)), m.group(2), int(m.group(3)), os.path.getsize(p)))
                elif n.startswith(".tmp-") and time.time() - os.path.getmtime(p) > 600:
                    os.unlink(p)
            except OSError:
                pass
        out.sort()
        return out

    def enforce(self) -> list[tuple]:
        """Drop batches older than 72 h, then the oldest ones while the spool exceeds its cap;
        returns what is left (oldest first)."""
        files = self.batches()
        total = sum(f[4] for f in files)
        old = (time.time() - LOGSHIP_MAX_AGE) * 1000
        keep, dropped = [], 0
        for f in files:
            if f[1] < old or total > self.cap:
                try:
                    os.unlink(os.path.join(self.dir, f[0]))
                except FileNotFoundError:
                    pass
                except OSError:
                    keep.append(f)
                    continue
                total -= f[4]
                dropped += f[3]
            else:
                keep.append(f)
        if dropped:
            self._dropped(dropped, f"spool cap {self.cap // (1024 * 1024)} MB / age {LOGSHIP_MAX_AGE // 3600} h")
        return keep

    def _dropped(self, n: int, why: str):
        self.st["dropped"] = int(self.st.get("dropped") or 0) + n
        now = time.monotonic()
        if now - self.last_warn >= LOGSHIP_WARN_EVERY or not self.last_warn:
            self.last_warn = now
            log.warning("logship: dropped %d records (%s); %d dropped in total", n, why, self.st["dropped"])

    def stats(self) -> dict:
        """Heartbeat block: spool size, drops, whether shipping is off after a 404."""
        files = self.batches()
        return {"sites": sum(1 for v in (self.st.get("sites") or {}).values() if v),
                "spool_batches": len(files), "spool_records": sum(f[3] for f in files),
                "spool_bytes": sum(f[4] for f in files), "dropped": int(self.st.get("dropped") or 0),
                "disabled": "off" in self.st}

    # ---- shipping
    def _read(self, name: str) -> list | None:
        try:
            with open(os.path.join(self.dir, name), encoding="utf-8") as f:
                text = f.read()
        except FileNotFoundError:
            return None
        except OSError:
            return []
        out = []
        for ln in text.splitlines():
            try:
                rec = json.loads(ln)
            except ValueError:
                continue
            if isinstance(rec, dict):
                out.append(rec)
        return out[:LOGSHIP_MAX_RECORDS]

    def _remove(self, name: str):
        try:
            os.unlink(os.path.join(self.dir, name))
        except OSError:
            pass

    def due(self) -> bool:
        return "off" not in self.st and time.monotonic() >= self.next_run

    def ship(self, ctl) -> int:
        """One shipping run: POST spooled batches oldest first until the spool is empty or
        LOGSHIP_RUN_BUDGET has passed (no new POST is started after it; each POST is time-boxed by
        LOGSHIP_TIMEOUT). The next run is at least LOGSHIP_INTERVAL and 3x this run's duration away,
        so shipping takes a bounded share of the loop. Returns the number of batches delivered.
          * 2xx -> the batch file is deleted;
          * 404 -> an old controller without the endpoint: shipping stops until the config version
            changes (the spool is kept, capped and aged as usual);
          * 400 / 413 / 422 -> this batch can never be accepted: dropped (counted), next batch;
          * anything else (timeout, connection error, 5xx, 401, 429) -> exponential backoff
            (30 s .. 15 min); the batch is retried later with the SAME batch_id."""
        if not self.due():
            return 0
        start = time.monotonic()
        interval = _int(self.cfg.get("LOGSHIP_INTERVAL"), 30, 1, 3600)
        timeout = _int(self.cfg.get("LOGSHIP_TIMEOUT"), 30, 3, 600)
        sent = 0
        failed = False
        for name, _, bid, count, _ in self.enforce():
            if time.monotonic() - start > LOGSHIP_RUN_BUDGET:
                break
            records = self._read(name)
            if records is None:          # vanished (dropped by the cap meanwhile)
                continue
            if not records:              # unreadable / corrupt: never retried forever
                self._remove(name)
                self._dropped(count, "unreadable spool batch")
                continue
            try:
                ctl.call("POST", "/edge/v1/logship", {"batch_id": bid, "records": records}, timeout=timeout)
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    self.st["off"] = str(self.st.get("cfg") or "")
                    log.warning("logship: the controller has no /edge/v1/logship (404); "
                                "shipping is off until the next config change")
                    return sent
                if e.code in (400, 413, 422):
                    self._remove(name)
                    self._dropped(len(records), f"batch rejected with HTTP {e.code}")
                    continue
                failed = True
                log.warning("logship: POST failed: HTTP %s", e.code)
                break
            except Exception as e:  # noqa: BLE001 - timeouts, connection errors: retry later
                failed = True
                log.warning("logship: POST failed: %s", e)
                break
            self._remove(name)
            sent += 1
        took = time.monotonic() - start
        if failed:
            self.backoff = min(LOGSHIP_BACKOFF[1], self.backoff * 2 if self.backoff else LOGSHIP_BACKOFF[0])
            self.next_run = time.monotonic() + self.backoff
        else:
            self.backoff = 0
            self.next_run = time.monotonic() + max(interval, 3 * took)
        return sent
