"""Agent settings: the agent.conf defaults (DEFAULTS), load_config, installed-asset lookup, the
agent logger and the buffer of its own WARN/ERROR lines shipped with the node logs (SPEC §11.2)."""

import collections
import logging
import os
from datetime import datetime, timezone


log = logging.getLogger("pcdn-agent")
# the package directory (pcdn_agent/) and the edge tree it sits in: HERE is the checkout's edge/
# directory (the source-tree fallback of asset()), /usr/local/lib/pcdn on an installed edge
PKG_DIR = os.path.dirname(os.path.abspath(__file__))
HERE = os.path.dirname(PKG_DIR)


def agent_source_files() -> list[str]:
    """The agent's own source files, in a stable order: hashed into render_rev and the fallback
    bundle version, so an agent upgrade is noticed."""
    out = []
    for dirpath, dirnames, filenames in os.walk(PKG_DIR):
        dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
        out += [os.path.join(dirpath, n) for n in sorted(filenames) if n.endswith(".py")]
    return out


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class LogBuffer(logging.Handler):
    """Keeps the agent's own recent WARNING+ records so they can be shipped to the controller
    with the nginx error log (SPEC §11.2). Bounded; never raises into the caller."""

    def __init__(self, maxlen: int = 200):
        super().__init__(level=logging.WARNING)
        self.records: collections.deque = collections.deque(maxlen=maxlen)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            level = {"WARNING": "warn", "ERROR": "error", "CRITICAL": "crit"}.get(record.levelname, "warn")
            self.records.append({"t": _now_iso(), "level": level, "msg": record.getMessage()})
        except Exception:  # noqa: BLE001 - logging must never crash the agent
            pass

    def drain(self) -> list:
        out = list(self.records)
        self.records.clear()
        return out


AGENT_LOGS = LogBuffer()

DEFAULTS = {
    "CONTROLLER_URL": "",
    "EDGE_TOKEN": "",
    "NGINX_DIR": "/etc/nginx/pcdn",
    "CACHE_DIR": "/var/cache/pcdn",
    "STATE_FILE": "/var/lib/pcdn/state.json",
    "ACCESS_LOG": "/var/log/nginx/pcdn-access.log",
    # centralized node logs (SPEC §11.2): the nginx error log the agent tails for WARN/ERROR/crit
    "ERROR_LOG": "/var/log/nginx/error.log",
    # running bundle version file written by bootstrap.sh; reported in the heartbeat (SPEC §11.1)
    "BUNDLE_VERSION_FILE": "/etc/pcdn/bundle.version",
    # region / role (edge group): reported on first heartbeat so a fresh node self-registers
    "REGION": "",
    "GROUP": "",
    "PAGES_DIR": "/usr/share/pcdn/pages",
    "NJS_FILE": "/usr/share/pcdn/njs/pcdn.js",
    "BASE_TEMPLATE": "/usr/share/pcdn/nginx/pcdn-base.conf",
    "GEOIP_DB": "/usr/share/pcdn/geo/country.mmdb",
    "CA_BUNDLE": "/etc/ssl/certs/ca-certificates.crt",
    "RESOLVER": "1.1.1.1 8.8.8.8",
    "HTTP_PORT": "80",
    "HTTPS_PORT": "443",
    "RESIZE_PORT": "8089",
    # SPEC §16.8: loopback port (127.0.0.1 only) where the image resizer fetches originals of hosts
    # whose origin is an object-storage bucket (rendered only while such a host has images on)
    "STORAGE_FETCH_PORT": "8091",
    "DICT_SIZE": "32m",
    "CACHE_MAX_SIZE": "10g",
    "CACHE_KEYS_ZONE": "5m",
    "CACHE_INACTIVE": "7d",
    # cap on cache files scanned for a prefix purge; beyond it, fall back to a full-site purge
    "PURGE_SCAN_MAX": "500000",
    "NGINX_TEST_CMD": "nginx -t -q",
    "NGINX_RELOAD_CMD": "nginx -s reload",
    "NGINX_USER": "www-data",
    "LISTEN_IPV6": "yes",
    "POLL_INTERVAL": "20",
    "USAGE_INTERVAL": "60",
    "HEARTBEAT_INTERVAL": "60",
    # idle upstream connections kept per worker to each tunnel origin (gRPC/h2/XHTTP): a warm
    # connection removes a TCP+TLS round-trip from the border on the next stream/request
    "TUNNEL_KEEPALIVE": "64",
    # F3: per-stream client body buffer for HTTP/2 tunnel uploads (gRPC/h2/XHTTP). The default h2
    # window is 64k; this raises in-flight upload capacity per stream. Cost ~= concurrent streams ×
    # size, so install.sh --role tunnel can raise it and low-RAM nodes should lower it to 128k.
    "TUNNEL_H2_BODY_BUFFER": "256k",
    # F14: relay buffer for the tunnel data path (proxy_buffer_size / grpc_buffer_size /
    # http2_chunk_size) and the ssl_buffer_size on pure-tunnel (decoy/404) hosts.
    "TUNNEL_RELAY_BUFFER": "16k",
    # F14: http-level ssl_buffer_size; install.sh sets 16k on --role tunnel nodes, 4k elsewhere for
    # faster TLS first byte on general web traffic.
    "SSL_BUFFER_SIZE": "4k",
    # F12: connect timeout for both proxy_pass and grpc_pass tunnel origins (seconds, 3-30).
    "TUNNEL_CONNECT_TIMEOUT": "10",
    # N2/F27: client-facing HTTP/2 stream cap per connection on tunnel hosts (a low value forces a
    # mid-session GOAWAY + reconnect for stream-heavy XHTTP/gRPC tunnels).
    "TUNNEL_KEEPALIVE_REQUESTS": "10000000",
    # F5: reload coalescing. A config version is applied only once it has settled (seen on two polls)
    # or has been pending for RELOAD_MIN_INTERVAL, and never more often than RELOAD_MIN_INTERVAL,
    # so a burst of site edits collapses into one nginx reload (one GOAWAY to all h2 tunnels).
    "RELOAD_MIN_INTERVAL": "120",
    # F5: a freshly-seen version waits at least this long before applying, so sub-debounce bursts of
    # different versions coalesce.
    "RELOAD_DEBOUNCE": "5",
    # F29: seconds the agent polls /__pcdn/confver after a reload before treating it as not applied.
    "RELOAD_VERIFY": "yes",
    # F7: usage POST timeout (seconds); strictly greater than Caddy's 120 s header timeout so the
    # agent never gives up just as the controller responds and replays a batch.
    "USAGE_TIMEOUT": "150",
    # F7: drop (and log) an unacknowledged usage batch older than this many days, comfortably inside
    # the controller's 7-day batch_id dedup window, so a stuck batch cannot be re-applied after its
    # dedup row is purged.
    "USAGE_OUTBOX_MAX_DAYS": "6",
    # F21: defer a reload up to this many seconds when every changed site belongs to another edge
    # group (and no global file changed and no site was added/removed/suspended or had its cert
    # rotated), so a tunnel-role node does not reload for general-website edits.
    "FOREIGN_DEFER": "900",
    # SPEC §14.1: nginx binary probed once per agent start with `-V` (version, --with-http_v3_module,
    # modules path) and the directory whose module .so files decide which optional directives
    # (geoip2, brotli, njs, image_filter) are rendered. Empty = the --modules-path nginx reports.
    "NGINX_BIN": "nginx",
    "NGINX_MODULES_DIR": "",
    # origin shield hop port on the shield peers (empty = this node's HTTPS_PORT); hops are TLS only
    "SHIELD_HTTPS_PORT": "",
    # TCP congestion control written by install.sh --cc (informational for the agent)
    "TCP_CC": "bbr",
    # SPEC §14.3.2 log export: sampled access-log records of sites with logs.enabled are spooled
    # here (0700 dir, 0600 files; empty = "logship" next to STATE_FILE) and POSTed to
    # /edge/v1/logship. The spool is capped (oldest batches dropped beyond it, counted) so a long
    # controller outage can never fill the disk.
    "LOGSHIP_SPOOL_DIR": "",
    "LOGSHIP_SPOOL_MAX_MB": "256",
    # seconds between shipping runs (own cadence, after config / purges / usage in the same loop)
    "LOGSHIP_INTERVAL": "30",
    # per-POST timeout (seconds); a run starts no new POST after LOGSHIP_RUN_BUDGET seconds
    "LOGSHIP_TIMEOUT": "30",
    # SPEC §15.2 tunnel fair share / §15.6 speed test. The controller's node block
    # ({"node": {"capacity_mbps", "fair_share_pct", "name"}}) wins; these are the fallbacks.
    # CAPACITY_MBPS 0 = unknown: the node is never "hot" and fair share never refuses anything.
    "CAPACITY_MBPS": "0",
    "FAIR_SHARE_PCT": "25",
    # node name hashed into the speed-test X-Pcdn-Node header (empty = the system host name)
    "NODE_NAME": "",
    # SPEC §15.6 speed-test random file (10 MiB + 64 B, written once; empty = speed.bin next to STATE_FILE)
    "SPEED_FILE": "",
    # SPEC §16.4 L4 proxy: the port range edge_port must fall into (the operator opens it in the host /
    # provider firewall), the JSON stream access log the agent bills from, and the nginx.conf that must
    # include NGINX_DIR/l4/*.conf at the main context (install.sh adds it) before stream {} is rendered
    "L4_PORT_RANGE": "20000-29999",
    "L4_ACCESS_LOG": "/var/log/nginx/pcdn-l4.log",
    "NGINX_CONF": "/etc/nginx/nginx.conf",
    # SPEC §16.6 images v2: the loopback image transformer (`pcdn-agent imaged`, service pcdn-imaged)
    # IMAGED auto = used when python3-pil is importable; no = never (nginx image_filter only)
    "IMAGED": "auto",
    "IMAGE_PORT": "8090",
    "IMAGE_WORKERS": "2",           # concurrent transforms; more wait up to 5 s, then 503 -> fallback
    "IMAGE_MAX_SOURCE_MB": "20",    # originals larger than this are not transformed (fallback)
    # SPEC §16.3 host hardening (install.sh --harden-net renders /etc/pcdn/guard.nft from these with
    # `pcdn-agent guard`; the agent itself only reports whether the guard is installed)
    "GUARD": "no",
    "GUARD_SSH_PORTS": "22",
    "GUARD_ALLOW": "",              # extra never-limited CIDRs (comma/space separated)
    "GUARD_SYN_RATE": "1000",       # new TCP connections / s per source /24 (IPv6: /64; CGNAT-safe)
    "GUARD_SYN_BURST": "2000",
    "GUARD_SYN_GLOBAL": "50000",    # new TCP connections / s for the whole host
    "GUARD_UDP_RATE": "20000",      # UDP/<HTTPS_PORT> (QUIC) packets / s per source address
    "GUARD_ICMP_RATE": "100",       # ICMP echo requests / s (host-wide)
    "GUARD_SYNPROXY": "auto",       # auto (install.sh probes kernel support) | no
    # SPEC §16.9 edge functions (install.sh --functions): pcdn-fn runs customer JS in sandboxed QuickJS
    # workers. The agent writes the code bundle to FN_DIR (group FN_GROUP, default NGINX_USER's group),
    # routes bound paths to FN_SOCKET, serves fetch() to the site's own origin on FN_FETCH_SOCKET, reads
    # pcdn-fn's self-test from FN_STATUS and bills FN_USAGE_LOG. FN_WALL_MS mirrors pcdn-fn's cap.
    "FUNCTIONS": "no",
    "FN_DIR": "/var/lib/pcdn-fn",
    "FN_GROUP": "",
    "FN_SOCKET": "/run/pcdn-fn/fn.sock",
    "FN_FETCH_SOCKET": "/run/pcdn-fnfetch/fetch.sock",
    "FN_STATUS": "/run/pcdn-fn/status.json",
    "FN_USAGE_LOG": "/var/log/pcdn-fn/usage.log",
    "FN_WALL_MS": "5000",
    # Origin address policy (security review: customer origins on internal addresses). Render time:
    # IP-literal origins must be public unless covered by ORIGIN_PRIVATE_ALLOW (CIDRs, comma/space
    # separated; e.g. the provider's own private network where its customers' origins live).
    # Connect time: install.sh renders `pcdn-agent origin-guard` into /etc/pcdn/origin-guard.nft
    # (table inet pcdn_origin_guard; ORIGIN_GUARD=yes by default, --no-origin-guard removes it):
    # the nginx workers' (NGINX_USER) connections to loopback / private / link-local / CGNAT / ULA /
    # multicast / reserved addresses are rejected, except DNS to RESOLVER, ORIGIN_PRIVATE_ALLOW, the
    # shield peers and the edge's own loopback services, which nginx reaches from INTERNAL_SRC
    # (proxy_bind) so a customer origin resolving to 127.0.0.1 cannot reach them.
    "ORIGIN_PRIVATE_ALLOW": "",
    "ORIGIN_GUARD": "no",
    "ORIGIN_GUARD_FILE": "/etc/pcdn/origin-guard.nft",
    "INTERNAL_SRC": "127.0.0.2",
}


def load_config(path: str) -> dict:
    cfg = dict(DEFAULTS)
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip().strip('"').strip("'")
    for k in DEFAULTS:
        if os.getenv("PCDN_" + k):
            cfg[k] = os.environ["PCDN_" + k]
    return cfg


def asset(cfg: dict, key: str, rel: str) -> str:
    """Installed asset path, falling back to the source tree (running from a checkout)."""
    p = cfg.get(key) or ""
    return p if os.path.exists(p) else os.path.join(HERE, rel)
