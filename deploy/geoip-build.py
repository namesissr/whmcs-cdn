#!/usr/bin/env python3
"""Build the country database PowerDNS uses for GeoDNS (python3 stdlib only).

DB-IP's free country database places part of Iran's address space in other
countries (about 5% of the ranges RIPE has registered to Iran, e.g. leased
ranges announced from Germany), so visitors from those ranges were sent to the
foreign edges. This tool takes DB-IP as the base and forces every range that
RIPE NCC registered to the home country (and any line of an overrides file) to
that country, then writes a MaxMind-format database for the PowerDNS geoip
backend. Nothing to install: no pip, no libmaxminddb.

  geoip-build.py --dbip dbip-country-lite.mmdb --ripe delegated-ripencc-extended-latest \
                 --country IR [--overrides dns/geo/overrides.txt] --out dns/geo/country.mmdb

overrides.txt: one "CIDR  CC" per line (# comments), e.g. "203.0.113.0/24 IR".
Later lines win. Use it for ranges you know better than both sources.

  geoip-build.py --lookup dns/geo/country.mmdb 2.176.0.1 8.8.8.8   # check a database
"""

import argparse
import ipaddress
import struct
import sys
import time
from array import array

MARKER = b"\xab\xcd\xefMaxMind.com"


# ------------------------------------------------------------------ reading


class Reader:
    def __init__(self, path: str):
        with open(path, "rb") as f:
            self.buf = f.read()
        i = self.buf.rfind(MARKER)
        if i < 0:
            raise ValueError(f"{path}: not a MaxMind DB file")
        self.meta, _ = self._decode(i + len(MARKER), base=i + len(MARKER))
        self.nodes = self.meta["node_count"]
        self.rsize = self.meta["record_size"]
        if self.rsize not in (24, 28, 32):
            raise ValueError(f"unsupported record size {self.rsize}")
        self.tree_size = self.nodes * self.rsize // 4
        self.data = self.tree_size + 16
        self.ip_version = self.meta["ip_version"]
        self._cache: dict[int, object] = {}

    def record(self, node: int, bit: int) -> int:
        b = self.buf
        if self.rsize == 24:
            o = node * 6 + bit * 3
            return (b[o] << 16) | (b[o + 1] << 8) | b[o + 2]
        if self.rsize == 28:
            o = node * 7
            if bit == 0:
                return ((b[o + 3] & 0xF0) << 20) | (b[o] << 16) | (b[o + 1] << 8) | b[o + 2]
            return ((b[o + 3] & 0x0F) << 24) | (b[o + 4] << 16) | (b[o + 5] << 8) | b[o + 6]
        o = node * 8 + bit * 4
        return struct.unpack(">I", b[o:o + 4])[0]

    def value(self, rec: int):
        off = rec - self.nodes - 16
        if off not in self._cache:
            self._cache[off] = self._decode(self.data + off, base=self.data)[0]
        return self._cache[off]

    def _decode(self, pos: int, base: int):
        b = self.buf
        ctrl = b[pos]
        pos += 1
        t = ctrl >> 5
        if t == 1:  # pointer
            ss, v = (ctrl >> 3) & 3, ctrl & 7
            if ss == 0:
                p = (v << 8) | b[pos]
            elif ss == 1:
                p = ((v << 16) | (b[pos] << 8) | b[pos + 1]) + 2048
            elif ss == 2:
                p = ((v << 24) | (b[pos] << 16) | (b[pos + 1] << 8) | b[pos + 2]) + 526336
            else:
                p = struct.unpack(">I", b[pos:pos + 4])[0]
            val, _ = self._decode(base + p, base)
            return val, pos + ss + 1
        if t == 0:
            t = 7 + b[pos]
            pos += 1
        size = ctrl & 0x1F
        if size == 29:
            size = 29 + b[pos]
            pos += 1
        elif size == 30:
            size = 285 + ((b[pos] << 8) | b[pos + 1])
            pos += 2
        elif size == 31:
            size = 65821 + ((b[pos] << 16) | (b[pos + 1] << 8) | b[pos + 2])
            pos += 3
        if t == 2:
            return b[pos:pos + size].decode("utf-8"), pos + size
        if t == 3:
            return struct.unpack(">d", b[pos:pos + 8])[0], pos + 8
        if t == 4:
            return bytes(b[pos:pos + size]), pos + size
        if t in (5, 6, 9, 10):
            return int.from_bytes(b[pos:pos + size], "big"), pos + size
        if t == 8:
            return int.from_bytes(b[pos:pos + size].rjust(4, b"\0"), "big", signed=True), pos + size
        if t == 7:
            out = {}
            for _ in range(size):
                k, pos = self._decode(pos, base)
                v, pos = self._decode(pos, base)
                out[k] = v
            return out, pos
        if t == 11:
            out = []
            for _ in range(size):
                v, pos = self._decode(pos, base)
                out.append(v)
            return out, pos
        if t == 14:
            return bool(size), pos
        if t == 15:
            return struct.unpack(">f", b[pos:pos + 4])[0], pos + 4
        raise ValueError(f"unsupported data type {t}")

    def walk(self):
        """Yield (key, prefix_len, record) of every range in a 128-bit key space
        (IPv4 at ::/96, once: the ::ffff:0:0/96 and 2002::/16 aliases are skipped)."""
        bits = 128 if self.ip_version == 6 else 32
        pad = 0 if bits == 128 else 96
        stack = [(0, 0, 0)]
        while stack:
            node, val, depth = stack.pop()
            for bit in (0, 1):
                v = (val << 1) | bit
                rec = self.record(node, bit)
                if rec == self.nodes:
                    continue
                d = depth + 1
                if bits == 128 and ((d == 96 and v == 0xFFFF) or (d == 16 and v == 0x2002)):
                    continue
                if rec > self.nodes:
                    yield v << (bits - d), d + pad, rec
                elif d < bits:
                    stack.append((rec, v, d))

    def networks(self):
        """Yield (network, data) for every range; IPv4 once, as IPv4Network."""
        bits = 128 if self.ip_version == 6 else 32
        stack = [(0, 0, 0)]  # node, prefix value, depth
        while stack:
            node, val, depth = stack.pop()
            for bit in (0, 1):
                v = (val << 1) | bit
                rec = self.record(node, bit)
                if rec == self.nodes:
                    continue
                d = depth + 1
                if bits == 128:
                    # skip the IPv4 aliases (::ffff:0:0/96, 2002::/16): IPv4 is read at ::/96
                    if d == 96 and v == 0xFFFF:
                        continue
                    if d == 16 and v == 0x2002:
                        continue
                if rec > self.nodes:
                    shift = bits - d
                    addr = v << shift
                    if bits == 128 and d >= 96 and addr >> 32 == 0:
                        net = ipaddress.IPv4Network((addr, d - 96))
                    elif bits == 128:
                        net = ipaddress.IPv6Network((addr, d))
                    else:
                        net = ipaddress.IPv4Network((addr, d))
                    yield net, self.value(rec)
                elif d < bits:
                    stack.append((rec, v, d))

    def lookup(self, ip: str):
        addr = ipaddress.ip_address(ip)
        if self.ip_version == 6:
            n = int(addr) if addr.version == 6 else int(addr)
            bits = 128
        else:
            if addr.version == 6:
                return None
            n, bits = int(addr), 32
        node = 0
        for i in range(bits):
            if node >= self.nodes:
                break
            node = self.record(node, (n >> (bits - 1 - i)) & 1)
        if node > self.nodes:
            return self.value(node)
        return None


# ------------------------------------------------------------------ writing


def _ctrl(t: int, size: int) -> bytes:
    if size < 29:
        head, extra = size, b""
    elif size < 285:
        head, extra = 29, bytes([size - 29])
    elif size < 65821:
        head, extra = 30, (size - 285).to_bytes(2, "big")
    else:
        head, extra = 31, (size - 65821).to_bytes(3, "big")
    if t <= 7:
        return bytes([(t << 5) | head]) + extra
    return bytes([head, t - 7]) + extra


def encode(v) -> bytes:
    if isinstance(v, bool):
        return _ctrl(14, int(v))
    if isinstance(v, str):
        raw = v.encode("utf-8")
        return _ctrl(2, len(raw)) + raw
    if isinstance(v, dict):
        return _ctrl(7, len(v)) + b"".join(encode(k) + encode(x) for k, x in v.items())
    if isinstance(v, list):
        return _ctrl(11, len(v)) + b"".join(encode(x) for x in v)
    if isinstance(v, tuple):  # (type, int): explicit unsigned width
        t, n = v
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
        return _ctrl(t, len(raw)) + raw
    raise TypeError(type(v))


class Trie:
    """Binary trie over 128-bit keys; leaves hold a small int (data id)."""

    def __init__(self):
        # child value: >0 node index, 0 empty, <0 leaf -(data_id + 1)
        self.left = array("l", [0])
        self.right = array("l", [0])

    def insert(self, key: int, plen: int, data_id: int):
        leaf = -(data_id + 1)
        node = 0
        for i in range(plen):
            bit = (key >> (127 - i)) & 1
            side = self.right if bit else self.left
            child = side[node]
            if i == plen - 1:
                side[node] = leaf  # replaces whatever was below
                return
            if child <= 0:
                # empty or leaf: create a node, pushing an existing leaf down to both halves
                self.left.append(child)
                self.right.append(child)
                side[node] = child = len(self.left) - 1
            node = child
        raise ValueError("zero-length prefix")

    def compact(self):
        """Merge sibling leaves with the same value, then renumber the live nodes."""
        n = len(self.left)
        # children always have larger indexes than their parent: walk backwards
        for i in range(n - 1, -1, -1):
            for side in (self.left, self.right):
                c = side[i]
                if c > 0 and self.left[c] <= 0 and self.left[c] == self.right[c]:
                    side[i] = self.left[c]
        order = array("l")
        stack = [0]
        while stack:
            i = stack.pop()
            order.append(i)
            for c in (self.right[i], self.left[i]):
                if c > 0:
                    stack.append(c)
        index = array("l", bytes(8 * n)) if array("l").itemsize == 8 else array("l", [0]) * n
        for new, old in enumerate(order):
            index[old] = new
        return order, index


class Builder:
    """Collects ranges (later ones win) and writes the database."""

    def __init__(self):
        self.trie = Trie()
        self.ids: dict[bytes, int] = {}
        self.blobs: list[bytes] = []

    def data_id(self, data: dict) -> int:
        blob = encode(data)
        did = self.ids.get(blob)
        if did is None:
            did = self.ids[blob] = len(self.blobs)
            self.blobs.append(blob)
        return did

    def add_key(self, key: int, plen: int, did: int):
        self.trie.insert(key, plen, did)

    def add(self, net, data: dict):
        if net.version == 4:
            key, plen = int(net.network_address), 96 + net.prefixlen
        else:
            key, plen = int(net.network_address), net.prefixlen
            if key >> 96 == 0 or key >> 32 == 0xFFFF or key >> 112 == 0x2002:
                return  # IPv4 space is written from the IPv4 ranges
        self.trie.insert(key, plen, self.data_id(data))

    def write(self, path: str, description: str) -> int:
        return _write(path, self.trie, self.blobs, description)


def write_mmdb(path: str, entries, description: str):
    """entries: iterable of (network, data dict) in insertion order (later wins)."""
    b = Builder()
    for net, data in entries:
        b.add(net, data)
    return b.write(path, description)


def _write(path: str, trie: "Trie", blobs: list, description: str) -> int:
    order, index = trie.compact()
    node_count = len(order)
    offsets, pos = [], 0
    for b in blobs:
        offsets.append(pos)
        pos += len(b)
    data_section = b"".join(blobs)
    rsize = 24 if node_count + 16 + len(data_section) < (1 << 24) else 32

    def rec(c: int) -> int:
        if c > 0:
            return index[c]
        if c == 0:
            return node_count
        return node_count + 16 + offsets[-c - 1]

    out = bytearray()
    for i in order:
        l, r = rec(trie.left[i]), rec(trie.right[i])
        if rsize == 24:
            out += l.to_bytes(3, "big") + r.to_bytes(3, "big")
        else:
            out += l.to_bytes(4, "big") + r.to_bytes(4, "big")
    meta = {
        "binary_format_major_version": (5, 2),
        "binary_format_minor_version": (5, 0),
        "build_epoch": (9, int(time.time())),
        "database_type": "DBIP-Country-Lite",
        "description": {"en": description},
        "ip_version": (5, 6),
        "languages": ["en"],
        "node_count": (6, node_count),
        "record_size": (5, rsize),
    }
    with open(path, "wb") as f:
        f.write(bytes(out))
        f.write(b"\0" * 16)
        f.write(data_section)
        f.write(MARKER)
        f.write(encode(meta))
    return node_count


# ------------------------------------------------------------------ sources


def ripe_networks(path: str, country: str):
    """Ranges RIPE NCC registered to `country` (delegated-ripencc-[extended-]latest)."""
    out = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            p = line.strip().split("|")
            if len(p) < 7 or p[1] != country or p[6] not in ("allocated", "assigned"):
                continue
            if p[2] == "ipv4":
                start = ipaddress.IPv4Address(p[3])
                out.extend(ipaddress.summarize_address_range(start, start + int(p[4]) - 1))
            elif p[2] == "ipv6":
                out.append(ipaddress.IPv6Network(f"{p[3]}/{p[4]}"))
    return out


def override_networks(path: str):
    out = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) != 2 or len(parts[1]) != 2:
                raise ValueError(f"{path}:{n}: expected 'CIDR CC', got {line!r}")
            out.append((ipaddress.ip_network(parts[0], strict=False), parts[1].upper()))
    return out


def slim(data) -> dict:
    """Keep only what PowerDNS reads (country + continent codes)."""
    out = {}
    cc = (data.get("country") or data.get("registered_country") or {}).get("iso_code")
    if cc:
        out["country"] = {"iso_code": cc}
    cont = (data.get("continent") or {}).get("code")
    if cont:
        out["continent"] = {"code": cont}
    return out


def build(a) -> int:
    src = Reader(a.dbip)
    out = Builder()
    continents: dict[str, str] = {}
    by_record: dict[int, int] = {}
    base = 0
    for key, plen, rec in src.walk():
        did = by_record.get(rec)
        if did is None:
            d = slim(src.value(rec))
            did = out.data_id(d) if d else -1
            by_record[rec] = did
            if "continent" in d:
                continents.setdefault(d["country"]["iso_code"], d["continent"]["code"])
        if did >= 0:
            out.add_key(key, plen, did)
            base += 1
    del src, by_record

    def forced(cc: str) -> dict:
        d = {"country": {"iso_code": cc}}
        if cc in continents:
            d["continent"] = {"code": continents[cc]}
        return d

    checks: list[tuple[str, str]] = []  # (ip, expected country)
    ripe = 0
    if a.ripe:
        for net in ripe_networks(a.ripe, a.country):
            out.add(net, forced(a.country))
            checks.append((str(net.network_address), a.country))
            ripe += 1
        if ripe == 0:
            print(f"error: no {a.country} ranges found in {a.ripe}", file=sys.stderr)
            return 1
    over = 0
    if a.overrides:
        for net, cc in override_networks(a.overrides):
            out.add(net, forced(cc))
            checks.append((str(net.network_address), cc))
            over += 1
    # later overrides win over earlier ones for the same address
    expected = dict(checks)
    for ip in a.expect or []:
        want_ip, _, want_cc = ip.partition("=")
        expected[want_ip] = want_cc.upper()
    nodes = out.write(a.out, f"DB-IP Country Lite (CC BY 4.0) + RIPE NCC {a.country} registrations")
    print(f"{a.out}: {base} DB-IP ranges, {ripe} RIPE {a.country} ranges, {over} overrides -> {nodes} nodes")
    # self-check: re-open the result and compare with the inputs
    chk = Reader(a.out)
    bad = []
    for ip, want in expected.items():
        got = (chk.lookup(ip) or {}).get("country", {}).get("iso_code")
        if got != want:
            bad.append(f"{ip} -> {got} (want {want})")
    if bad:
        print("self-check FAILED:\n  " + "\n  ".join(bad[:20]), file=sys.stderr)
        return 1
    print("self-check ok")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dbip", help="DB-IP country lite .mmdb (uncompressed)")
    p.add_argument("--ripe", help="RIPE NCC delegated stats file")
    p.add_argument("--country", default="IR", help="country whose RIPE registrations win (default IR)")
    p.add_argument("--overrides", help="file of 'CIDR CC' lines applied last")
    p.add_argument("--out", help="output .mmdb")
    p.add_argument("--expect", action="append", help="IP=CC that must hold in the result (repeatable)")
    p.add_argument("--lookup", nargs="+", metavar=("DB", "IP"), help="print the country of IPs in DB")
    a = p.parse_args(argv)
    if a.lookup:
        r = Reader(a.lookup[0])
        for ip in a.lookup[1:]:
            d = r.lookup(ip) or {}
            print(ip, d.get("country", {}).get("iso_code", "--"))
        return 0
    if not (a.dbip and a.out):
        p.error("--dbip and --out are required")
    return build(a)


if __name__ == "__main__":
    sys.exit(main())
