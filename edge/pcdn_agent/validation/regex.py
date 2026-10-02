"""Customer regex safety (security review H2, edge side): regex_unsafe / pcre_regex re-check every
customer regex before it is rendered into nginx or njs and SKIP the ones that could backtrack
catastrophically. The controller's sections.regex_safe must give the same verdict
(controller/tests/test_regex_parity.py)."""

import re
import warnings

from ..settings import log


# --- customer regex safety (security review H2, edge side) ----------------------------------------
# nginx (PCRE) and njs (PCRE2 behind a JS front end) are backtracking engines and run customer
# regexes on every request, on values the visitor chooses. The controller validates them too, but
# the edge re-checks every customer regex before rendering it (an older / buggy controller must not
# be able to stall the nginx workers every tenant shares) and SKIPS an unsafe one with a warning:
#   * length <= REGEX_MAX_LEN, printable characters only;
#   * no back-references / conditionals;
#   * no quantified group that itself contains a quantifier unless a mandatory character the inner
#     quantifiers can never consume separates the repetitions (`(a+)+`, `(.*a)*`, `(\w+\s?)*` are
#     rejected, `(?:/[a-z]+)*` is fine), and no repeated alternation whose alternatives can start
#     alike (`(a|ab)*`): exponential backtracking (mirrors controller/app/sections.py _safe_regex);
#   * polynomial backtracking bounded: wide quantifiers (unbounded, or bounded above
#     REGEX_WIDE_REPEAT) that follow each other without a separating mandatory character form a
#     chain; its length, plus one for an unanchored pattern (every start position is tried), is the
#     degree of the worst case and must stay <= REGEX_MAX_DEGREE (`a.*b.*c`: 3, rejected - a PCRE2
#     match of `a.*a.*b$` over 2000 bytes was measured at 18 s); at most REGEX_MAX_UNBOUNDED;
# and the input is capped where the edge evaluates customer regexes: njs tests at most the first
# REGEX_INPUT_MAX_NJS characters of a value, nginx skips the regex redirect / rewrite maps for
# request paths longer than REGEX_INPUT_MAX_PATH ($pcdn_rxlong in render_http).
REGEX_MAX_LEN = 256
REGEX_MAX_UNBOUNDED = 10
REGEX_MAX_DEGREE = 2
REGEX_WIDE_REPEAT = 32
REGEX_INPUT_MAX_NJS = 1024     # must match RE_INPUT_MAX in njs/pcdn.js
REGEX_INPUT_MAX_PATH = 2048

try:  # Python 3.11+
    from re import _constants as _sre_c
    from re import _parser as _sre_p
except ImportError:  # pragma: no cover - older Pythons
    import sre_constants as _sre_c
    import sre_parse as _sre_p

_REPEAT_OPS = {_sre_c.MAX_REPEAT, _sre_c.MIN_REPEAT} | (
    {_sre_c.POSSESSIVE_REPEAT} if hasattr(_sre_c, "POSSESSIVE_REPEAT") else set())
_ATOMIC = getattr(_sre_c, "ATOMIC_GROUP", None)
# characters tried when testing whether two character sets overlap (case-folded both ways: njs
# compiles firewall regexes with the `i` flag, nginx page-rule locations are `~*`)
_RX_SAMPLE = list(range(0x20, 0x7f)) + [0x09, 0x0a, 0xa0, 0xe9, 0x627, 0x6cc, 0x4e00]


class _RxUnsafe(ValueError):
    pass


def _rx_children(op, av) -> list:
    if op in _REPEAT_OPS:
        return [av[2]]
    if op == _sre_c.SUBPATTERN:
        return [av[-1]]
    if op == _sre_c.BRANCH:
        return list(av[1])
    if op in (_sre_c.ASSERT, _sre_c.ASSERT_NOT):
        return [av[1]]
    if _ATOMIC is not None and op == _ATOMIC:
        return [av]
    return []


def _rx_cat(cat, c: int) -> bool:
    ch = chr(c)
    word = ch.isalnum() or ch == "_"
    return {_sre_c.CATEGORY_DIGIT: ch.isdigit(), _sre_c.CATEGORY_NOT_DIGIT: not ch.isdigit(),
            _sre_c.CATEGORY_SPACE: ch.isspace(), _sre_c.CATEGORY_NOT_SPACE: not ch.isspace(),
            _sre_c.CATEGORY_WORD: word, _sre_c.CATEGORY_NOT_WORD: not word}.get(cat, True)


def _rx_in_item(item, c: int) -> bool:
    op, av = item
    if op == _sre_c.LITERAL:
        return c == av
    if op == _sre_c.RANGE:
        return av[0] <= c <= av[1]
    if op == _sre_c.CATEGORY:
        return _rx_cat(av, c)
    return True


def _rx_pred(op, av):
    """Predicate "can this one-character element match code point c" (case-insensitive), or None
    for any other element."""
    if op == _sre_c.ANY:
        return lambda c: True
    if op == _sre_c.LITERAL:
        def base(c):
            return c == av
    elif op == _sre_c.NOT_LITERAL:
        def base(c):
            return c != av
    elif op == _sre_c.IN:
        items = list(av)
        neg = bool(items) and items[0][0] == _sre_c.NEGATE
        items = items[1:] if neg else items

        def base(c):
            hit = any(_rx_in_item(i, c) for i in items)
            return not hit if neg else hit
    else:
        return None

    def pred(c):
        if base(c):
            return True
        ch = chr(c)
        return any(base(ord(x)) for x in (ch.lower(), ch.upper()) if len(x) == 1 and x != ch)
    return pred


def _rx_consumable(sub) -> list:
    """Predicates of every single-character element anywhere inside `sub`."""
    out = []
    for op, av in sub:
        p = _rx_pred(op, av)
        if p is not None:
            out.append(p)
        for child in _rx_children(op, av):
            out.extend(_rx_consumable(child))
    return out


def _rx_separators(sub) -> list:
    """Mandatory one-character elements at the top of `sub` (plain groups too), as predicates."""
    out = []
    for op, av in sub:
        if op in (_sre_c.LITERAL, _sre_c.IN):
            out.append(_rx_pred(op, av))
        elif op == _sre_c.SUBPATTERN:
            out.extend(_rx_separators(av[-1]))
    return out


def _rx_overlap(a: list, b: list) -> bool:
    return any(any(p(c) for p in a) and any(q(c) for q in b) for c in _RX_SAMPLE)


def _rx_repeats(sub):
    for op, av in sub:
        if op in _REPEAT_OPS:
            yield av
        for child in _rx_children(op, av):
            yield from _rx_repeats(child)


def _rx_ambiguous(body) -> bool:
    """A repeated `body` holding an inner quantifier and no separator the inner ones never consume."""
    inner = [r for r in _rx_repeats(body) if r[1] > 1]
    if not inner:
        return False
    preds = [p for r in inner for p in _rx_consumable(r[2])]
    for sep in _rx_separators(body):
        if not any(sep(c) and any(p(c) for p in preds) for c in _RX_SAMPLE):
            return False
    return True


def _rx_first(sub) -> tuple[list, bool]:
    """Predicates for the first character `sub` can consume, and whether `sub` can match empty."""
    preds: list = []
    for op, av in sub:
        p = _rx_pred(op, av)
        if p is not None:
            return preds + [p], False
        if op in (_sre_c.AT, _sre_c.ASSERT, _sre_c.ASSERT_NOT):
            continue
        if op == _sre_c.SUBPATTERN:
            fp, nullable = _rx_first(av[-1])
        elif op in _REPEAT_OPS:
            fp, nullable = _rx_first(av[2])
            nullable = nullable or av[0] == 0
        elif op == _sre_c.BRANCH:
            fp, nullable = [], False
            for b in av[1]:
                bp, bn = _rx_first(b)
                fp += bp
                nullable = nullable or bn
        else:
            return preds + [lambda c: True], False
        preds += fp
        if not nullable:
            return preds, False
    return preds, True


def _rx_alternations(v: str) -> list[list[str]]:
    """Alternatives of every group of the raw pattern that is repeated more than once (`(a|ab)+`
    -> [["a", "ab"]]): Python's parser merges alternatives, PCRE backtracks through each one."""
    out, stack, i, n, in_class = [], [], 0, len(v), False
    while i < n:
        ch = v[i]
        if ch == "\\":
            i += 2
            continue
        if in_class:
            in_class = ch != "]"
            i += 1
            continue
        if ch == "[":
            in_class, i = True, i + 1
            if v[i:i + 1] == "^":
                i += 1
            if v[i:i + 1] == "]":
                i += 1
            continue
        if ch == "(":
            stack.append((i, []))
        elif ch == "|" and stack:
            stack[-1][1].append(i)
        elif ch == ")" and stack:
            start, bars = stack.pop()
            rest = v[i + 1:]
            m = re.match(r"\{(\d*)(,?)(\d*)\}", rest)
            if rest[:1] in ("*", "+"):
                hi = 2
            elif m:
                hi = int(m.group(3)) if m.group(3) else (2 if m.group(2) else int(m.group(1) or 0))
            else:
                hi = 0
            if hi > 1 and bars:
                body = start + 1
                pre = re.match(r"\?(?:[:=!>|]|<[=!]|[a-zA-Z-]+:|P<\w+>)", v[body:i])
                body += pre.end() if pre else 0
                parts, prev = [], body
                for b in bars:
                    parts.append(v[prev:b])
                    prev = b + 1
                parts.append(v[prev:i])
                out.append(parts)
        i += 1
    return out


def _rx_alts_overlap(parts: list[str]) -> bool:
    firsts = []
    for part in parts:
        try:
            preds, nullable = _rx_first(_sre_p.parse(part))
        except Exception:  # noqa: BLE001 - not parseable on its own: assume the worst
            return True
        if nullable:
            return True   # an empty alternative inside a repeat
        firsts.append(preds)
    return any(_rx_overlap(firsts[a], firsts[b]) for a in range(len(firsts)) for b in range(a + 1, len(firsts)))


def _rx_chain(sub, chain: list, length: int, state: dict) -> tuple[list, int]:
    """Walk `sub` as a sequence, carrying the current chain of wide quantifiers (the predicates of
    what they consume, and how many); state["degree"] keeps the longest chain seen."""
    for op, av in sub:
        if op in _REPEAT_OPS and (av[1] == _sre_c.MAXREPEAT or av[1] >= REGEX_WIDE_REPEAT):
            preds = _rx_consumable(av[2]) or [lambda c: True]
            if chain and _rx_overlap(chain, preds):
                chain, length = chain + preds, length + 1
            else:
                chain, length = list(preds), 1
            state["degree"] = max(state["degree"], length)
            _rx_chain(av[2], [], 0, state)   # a body with its own inner quantifier: _rx_ambiguous
        elif op in _REPEAT_OPS:   # optional / small bounded repeat: its body continues the sequence
            for _ in range(max(1, min(av[1], 3))):
                chain, length = _rx_chain(av[2], chain, length, state)
        elif op == _sre_c.SUBPATTERN:
            chain, length = _rx_chain(av[-1], chain, length, state)
        elif _ATOMIC is not None and op == _ATOMIC:
            chain, length = _rx_chain(av, chain, length, state)
        elif op == _sre_c.BRANCH:
            # any alternative may be the one taken: the union of what they leave, the longest chain
            outs = [_rx_chain(b, list(chain), length, state) for b in av[1]]
            chain, length = [p for c2, _ in outs for p in c2], max([l2 for _, l2 in outs] + [0])
        elif op in (_sre_c.ASSERT, _sre_c.ASSERT_NOT):
            _rx_chain(av[1], [], 0, state)   # runs at each position on its own
        else:
            p = _rx_pred(op, av)
            if p is not None and chain and not any(p(c) and any(q(c) for q in chain) for c in _RX_SAMPLE):
                chain, length = [], 0   # a mandatory character the chain never consumes splits it
    return chain, length


def regex_unsafe(src, max_len: int = REGEX_MAX_LEN, ascii_only: bool = True) -> str | None:
    """Why the customer regex `src` must not run on this edge, or None when it may. Never raises.
    ascii_only: printable ASCII only (regexes rendered into the nginx config)."""
    if not isinstance(src, str) or not src:
        return "empty"
    if len(src) > max_len:
        return f"longer than {max_len} characters"
    if any(ord(ch) < 0x20 or 0x7f <= ord(ch) < 0xa0 for ch in src) or (
            ascii_only and not re.match(r"^[\x20-\x7e]+$", src)):
        return "control or non-ASCII characters"
    try:
        with warnings.catch_warnings():   # FutureWarning on "[[" / "--" etc.: not ours to report
            warnings.simplefilter("ignore")
            re.compile(src)
            tree = _sre_p.parse(src)
    except (re.error, RecursionError, OverflowError, ValueError, TypeError) as e:
        return f"does not compile ({e})"
    state = {"unbounded": 0, "degree": 0}

    def walk(sub):
        for op, av in sub:
            if op in (_sre_c.GROUPREF, _sre_c.GROUPREF_EXISTS):
                raise _RxUnsafe("back-reference or conditional")
            if op in _REPEAT_OPS:
                if av[1] == _sre_c.MAXREPEAT:
                    state["unbounded"] += 1
                if av[1] > 1 and _rx_ambiguous(av[2]):
                    raise _RxUnsafe("nested quantifier (catastrophic backtracking)")
            for child in _rx_children(op, av):
                walk(child)
    try:
        walk(tree)
        if state["unbounded"] > REGEX_MAX_UNBOUNDED:
            return f"more than {REGEX_MAX_UNBOUNDED} unbounded quantifiers"
        if any(_rx_alts_overlap(parts) for parts in _rx_alternations(src)):
            return "repeated group whose alternatives start alike (catastrophic backtracking)"
        _rx_chain(tree, [], 0, state)
    except _RxUnsafe as e:
        return str(e)
    except RecursionError:
        return "too deeply nested"
    anchored = src.startswith("^")
    if state["degree"] + (0 if anchored else 1) > REGEX_MAX_DEGREE:
        return (f"{state['degree']} chained wide quantifiers{'' if anchored else ' in an unanchored pattern'}"
                " (polynomial backtracking)")
    return None


def pcre_regex(src, max_len: int = REGEX_MAX_LEN):
    """A customer regex that PCRE (nginx) will run: printable ASCII, compiles in Python, none of
    the Python-only syntax PCRE rejects (\\N \\u \\U \\l \\L escapes, inline flags other than imsx)
    and safe to backtrack over (regex_unsafe). Returns the compiled Python pattern (for its group
    count), or None (with a warning naming the reason for an unsafe one)."""
    if not isinstance(src, str) or not 0 < len(src) <= max_len or not re.match(r"^[\x20-\x7e]+$", src):
        return None
    if re.search(r"\\[NuUlL]", src):
        return None
    for m in re.finditer(r"\(\?([A-Za-z-]+)[:)]", src):
        if set(m.group(1)) - set("imsx-"):
            return None
    why = regex_unsafe(src, max_len)
    if why:
        log.warning("customer regex %r skipped: %s", src[:80], why)
        return None
    try:
        return re.compile(src)
    except (re.error, RecursionError, OverflowError, ValueError):
        return None
