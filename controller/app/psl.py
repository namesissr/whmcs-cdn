"""Public suffix list (ICANN section) — which names are registry suffixes, not customer domains.

Used by site creation (a site may not BE a public suffix such as ``co.ir`` or ``com``) and by the
NS check (where a domain's registered parent zone starts). The data is a snapshot of the ICANN
section of https://publicsuffix.org/list/public_suffix_list.dat bundled in
``app/data/public_suffix_list.dat`` (the private section — github.io, blog hosts … — is left out on
purpose: such names are ordinary customer domains here, and the parent/child site rule in
tenancy.py already keeps tenants apart below them).

Updating the snapshot (docs/SECURITY.md): download the official list and rebuild the bundled file::

    curl -fsSLo /tmp/psl.dat https://publicsuffix.org/list/public_suffix_list.dat
    python -m app.psl /tmp/psl.dat          # rewrites app/data/public_suffix_list.dat

The Iranian suffixes below are always included, even with a missing or truncated data file.
"""

import functools
import os
import sys

DATA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "public_suffix_list.dat")

# always public suffixes, whatever the data file says (the .ir registry's second levels, SPEC §1)
BUILTIN = ("ir", "co.ir", "ac.ir", "gov.ir", "org.ir", "net.ir", "sch.ir", "id.ir",
           "ایران", "ايران", "ایران.ir", "ايران.ir",
           "com", "net", "org", "edu", "gov", "int", "mil", "arpa")


def _ascii(label_rule: str) -> str | None:
    try:
        return ".".join(part if part == "*" else part.encode("idna").decode("ascii")
                        for part in label_rule.lower().strip(".").split("."))
    except UnicodeError:
        return None


def _norm(rule: str) -> str | None:
    rule = rule.strip().lower()
    if not rule or rule.startswith("//"):
        return None
    rule = rule.split()[0]
    exception = rule.startswith("!")
    body = rule[1:] if exception else rule
    out = _ascii(body)
    if out is None:
        return None
    return ("!" + out) if exception else out


@functools.lru_cache(maxsize=1)
def rules() -> frozenset[str]:
    """Every rule (ASCII form): plain suffixes, '*.' wildcards and '!' exceptions."""
    out: set[str] = set()
    try:
        with open(DATA_FILE, encoding="utf-8") as fh:
            for line in fh:
                r = _norm(line)
                if r:
                    out.add(r)
    except OSError:
        pass
    for r in BUILTIN:
        n = _norm(r)
        if n:
            out.add(n)
    return frozenset(out)


def public_suffix(domain: str) -> str:
    """The public suffix of an ASCII domain (PSL algorithm; unlisted TLD -> the TLD itself)."""
    labels = domain.lower().strip(".").split(".")
    r = rules()
    best = labels[-1:]  # default rule "*"
    for i in range(len(labels)):
        cand = ".".join(labels[i:])
        if "!" + cand in r:
            return ".".join(labels[i + 1:])  # exception: the suffix is one label shorter
        wild = "*." + ".".join(labels[i + 1:]) if i + 1 < len(labels) else None
        if cand in r or (wild and wild in r):
            if len(labels) - i > len(best):
                best = labels[i:]
    return ".".join(best)


def is_public_suffix(domain: str) -> bool:
    d = domain.lower().strip(".")
    return bool(d) and public_suffix(d) == d


def registrable(domain: str) -> str | None:
    """The registrable domain (public suffix + one label); None for a public suffix itself."""
    d = domain.lower().strip(".")
    suffix = public_suffix(d)
    if suffix == d:
        return None
    head = d[: -(len(suffix) + 1)]
    return f"{head.rsplit('.', 1)[-1]}.{suffix}"


def rebuild(src: str, dst: str = DATA_FILE) -> int:
    """Rewrite the bundled snapshot from an official public_suffix_list.dat (ICANN section only)."""
    text = open(src, encoding="utf-8").read()
    begin, end = "// ===BEGIN ICANN DOMAINS===", "// ===END ICANN DOMAINS==="
    if begin not in text or end not in text:
        raise ValueError("not a public_suffix_list.dat (ICANN markers missing)")
    head = [ln for ln in text[: text.index(begin)].splitlines() if ln.startswith("//")]
    body = []
    for ln in text[text.index(begin): text.index(end)].splitlines():
        ln = ln.strip()
        if ln and not ln.startswith("//"):
            body.append(ln.split()[0])
    missing = [s for s in ("ir", "co.ir", "com") if s not in body]
    if missing or len(body) < 1000:
        raise ValueError(f"refusing a suspicious list ({len(body)} rules, missing {missing})")
    with open(dst, "w", encoding="utf-8") as fh:
        fh.write("\n".join(head) + "\n// ICANN section only (private-section rules are not used, see app/psl.py)\n"
                 + begin + "\n" + "\n".join(body) + "\n" + end + "\n")
    rules.cache_clear()
    return len(body)


if __name__ == "__main__":  # python -m app.psl /path/to/public_suffix_list.dat
    if len(sys.argv) != 2:
        print("usage: python -m app.psl /path/to/public_suffix_list.dat", file=sys.stderr)
        sys.exit(2)
    print(f"{rebuild(sys.argv[1])} ICANN rules written to {DATA_FILE}")
