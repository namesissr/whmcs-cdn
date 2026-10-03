"""Visitor-facing pages (njs/pcdn.js page() / gatePage() and pages/*.html): one design system.

Every page type is rendered with node (mocked r / ngx, the real pcdn.js code paths) and checked for
the shared footer, well-formed self-contained markup, no external resources and the size budget.
`render_all()` is also used to take screenshots of the pages.
"""

import html.parser
import json
import pathlib
import re
import shutil
import subprocess

import pytest

HERE = pathlib.Path(__file__).resolve().parent
EDGE = HERE.parent
pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

FOOTER_LINK = "https://pasargadmizban.com"
POWERED_FA = "قدرت گرفته از پاسارگاد سی‌دی‌ان"
POWERED_EN = "Powered by Pasargad CDN"
BUDGET = 8 * 1024          # bytes of HTML incl. CSS / SVG
BUDGET_CHALLENGE = 12 * 1024   # challenge script / captcha SVG

SITE = {"domain": "x.test", "secret": "k", "hosts": ["x.test"], "blocked_ips": [], "min_tls": "1.2",
        "firewall": {"default_action": "allow", "rules": []}, "hotlink": {"enabled": False}, "ratelimit": [],
        "ddos": {"mode": "off"}, "waf": {"mode": "off", "groups": [], "exclusions": [], "off_paths": []},
        "pools": {}, "image": {"enabled": False}}

HARNESS = r"""
import m from './pcdn.mjs';
import { T } from './pcdn.mjs';
const store = {};
const dict = { get: k => store[k], set: (k, v) => { store[k] = v; }, incr: (k, d, i) => (store[k] = (store[k] === undefined ? i : store[k]) + d),
  delete: k => { delete store[k]; } };
globalThis.ngx = { shared: { pcdn_cnt: dict, pcdn_blk: dict, pcdn_hc: dict, pcdn_fair: dict, pcdn_wr: dict } };
function req(o) {
  const vars = Object.assign({ pcdn_site: 's1', remote_addr: '203.0.113.7', request_uri: '/shop/cart?x=1', args: '', host: 'x.test',
    pcdn_country: 'IR', ssl_protocol: '', scheme: 'https' }, o.vars || {});
  const hin = Object.assign({ 'User-Agent': 'Mozilla/5.0', Accept: 'text/html', 'Accept-Language': o.lang === 'en' ? 'en-US,en' : 'fa-IR,fa' },
    o.headers || {});
  const res = {};
  const r = { uri: '/', method: o.method || 'GET', variables: vars, headersIn: hin, headersOut: {}, args: o.args || {},
    requestText: o.body || '', error: () => {}, log: () => {},
    return: (code, body) => { res.code = code; res.html = body === undefined ? '' : String(body); } };
  res.r = r;
  return res;
}
function done(res) { return { code: res.code, headers: res.r.headersOut, html: res.html }; }
const out = {};
function deny(name, verdict, o) {
  const res = req(o || {}); res.r.variables.pcdn_verdict = verdict; m.deny(res.r); out[name] = done(res);
}
deny('block', 'block:waf:913120');
deny('ratelimit', 'block:ratelimit:r1', { vars: { pcdn_site: '' } });
deny('challenge', 'challenge:ddos:x');
deny('captcha', 'captcha:ddos:x');
deny('queue', 'wr:q:3:120');
deny('queue_en', 'wr:q:1:120', { lang: 'en' });
deny('access_denied', 'acc:deny:admin');
let res = req({ args: { t: 'bad', n: '1', r: '/back' } }); m.verify(res.r); out.verify_failed = done(res);
res = req({ method: 'POST', body: 't=1.2.3&r=%2Fback&a=XYZ' }); m.captcha(res.r); out.captcha_error = done(res);
const app = { id: 'admin', name: 'Admin <panel>', otp: true };
function gate(name, code, lang, Tx, form, h) { const res = req({ lang: lang }); T.gatePage(res.r, code, lang, Tx, form, h); out[name] = done(res); }
gate('access_login', 200, 'fa', T.accT('email', app.name), T.emailForm('fa', app, '/admin/'), {});
gate('access_login_en', 200, 'en', T.accT('email', app.name), T.emailForm('en', app, '/admin/'), {});
gate('access_sent', 200, 'fa', T.accT('sent', '', { icon: 'mail' }), T.codeForm('fa', app, 'x1@corp.test', '/admin/'), {});
gate('access_bad', 401, 'fa', T.accT('bad', '', { pill: '401 Unauthorized' }), T.codeForm('fa', app, 'x1@corp.test', '/admin/'), {});
gate('access_locked', 429, 'fa', T.accT('locked', '', { pill: '429 Too Many Requests', rows: [['Retry after', '540 s']] }), '',
  { 'Retry-After': '540' });
gate('access_many', 429, 'fa', T.accT('many', '', { pill: '429 Too Many Requests', rows: [['Retry after', '60 s']] }), '',
  { 'Retry-After': '60' });
out.CSS = T.CSS;
console.log(JSON.stringify(out));
"""


def render_all(tmp_path) -> dict:
    """{page type: {"code", "headers", "html"}} plus "CSS" and the static pages (code 503)."""
    tmp_path = pathlib.Path(tmp_path)
    src = (EDGE / "njs/pcdn.js").read_text().replace("from 'sites.js'", "from './sites.mjs'")
    src += "\nexport const T = { gatePage, accT, emailForm, codeForm, CSS };\n"
    (tmp_path / "pcdn.mjs").write_text(src)
    (tmp_path / "sites.mjs").write_text("export default " + json.dumps({"s1": SITE}) + ";\n")
    (tmp_path / "h.mjs").write_text(HARNESS)
    p = subprocess.run(["node", str(tmp_path / "h.mjs")], capture_output=True, text=True, cwd=tmp_path)
    assert p.returncode == 0, p.stderr
    out = json.loads(p.stdout)
    for name in ("suspended", "over_quota"):
        out[name] = {"code": 503, "headers": {}, "html": (EDGE / "pages" / f"{name}.html").read_text()}
    return out


@pytest.fixture(scope="module")
def pages(tmp_path_factory):
    return render_all(tmp_path_factory.mktemp("pages"))


VOID = {"meta", "input", "br", "link", "img", "hr", "circle", "path", "rect"}


class Checker(html.parser.HTMLParser):
    """Tag balance + every URL-bearing attribute."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack, self.errors, self.urls, self.tags = [], [], [], []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))
        for k, v in attrs:
            if k in ("href", "src", "action", "srcset", "xlink:href", "poster", "data"):
                self.urls.append(v or "")
        if tag not in VOID:
            self.stack.append(tag)

    def handle_startendtag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))
        for k, v in attrs:
            if k in ("href", "src", "action"):
                self.urls.append(v or "")

    def handle_endtag(self, tag):
        if tag in VOID:
            return
        if not self.stack or self.stack[-1] != tag:
            self.errors.append(f"unexpected </{tag}> (open: {self.stack[-3:]})")
            return
        self.stack.pop()


def check(html: str) -> Checker:
    c = Checker()
    c.feed(html)
    c.close()
    return c


TYPES = ["block", "ratelimit", "challenge", "captcha", "captcha_error", "verify_failed", "queue", "queue_en",
         "access_denied", "access_login", "access_login_en", "access_sent", "access_bad", "access_locked",
         "access_many", "suspended", "over_quota"]


@pytest.mark.parametrize("name", TYPES)
def test_page_design_contract(pages, name):
    pg = pages[name]
    h = pg["html"]
    assert h.startswith("<!doctype html>\n<html lang=")
    c = check(h)
    assert not c.errors and not c.stack, (c.errors, c.stack)
    # the shared footer, link + «قدرت گرفته از پاسارگاد سی‌دی‌ان»
    foot = h[h.index("<footer>"):h.index("</footer>")]
    assert f'<a href="{FOOTER_LINK}" rel="noopener" target="_blank">' in foot
    assert "پاسارگاد میزبان" in foot and "pasargadmizban.com" in foot
    assert POWERED_FA in foot and POWERED_EN in foot
    # self-contained: no external resources; the only absolute URLs are the operator's own links
    for u in c.urls:
        assert not u.startswith("//"), u
        if re.match(r"^[a-z][a-z0-9+.-]*:", u, re.I):
            assert u == FOOTER_LINK or (name in ("suspended", "over_quota") and u == "https://my.pasargadmizban.com"), u
    assert not re.search(r"<(?:link|img|iframe|object|embed)\b", h) and "@import" not in h and "url(" not in h
    assert "<script src" not in h
    # accessible basics
    assert re.search(r'<html lang="(fa|en)" dir="(rtl|ltr)">', h) and "<h1>" in h and "<main>" in h
    assert 'name="viewport"' in h and "prefers-color-scheme:dark" in h
    # the challenge script and the captcha image come on top of the page itself
    assert len(h.encode()) < (BUDGET_CHALLENGE if name.startswith(("challenge", "captcha")) else BUDGET), len(h.encode())
    bare = re.sub(r"<script>.*?</script>|<svg xmlns=.*?</svg>", "", h, flags=re.S)
    assert len(bare.encode()) < BUDGET, len(bare.encode())


@pytest.mark.parametrize("name", [t for t in TYPES if t not in ("suspended", "over_quota")])
def test_dynamic_pages_keep_headers_and_details(pages, name):
    pg = pages[name]
    assert pg["headers"]["Cache-Control"] == "no-store"
    assert pg["headers"]["Content-Type"] == "text/html; charset=utf-8"
    assert "جزئیات فنی" in pg["html"] and "203.0.113.7" in pg["html"] and " UTC</dd>" in pg["html"]


def test_status_codes_and_behavioural_markup(pages):
    codes = {k: pages[k]["code"] for k in TYPES}
    assert codes == {"block": 403, "ratelimit": 429, "challenge": 403, "captcha": 403, "captcha_error": 403,
                     "verify_failed": 403, "queue": 200, "queue_en": 200, "access_denied": 403, "access_login": 200,
                     "access_login_en": 200, "access_sent": 200, "access_bad": 401, "access_locked": 429,
                     "access_many": 429, "suspended": 503, "over_quota": 503}
    assert "block:waf:913120" in pages["block"]["html"] and "دسترسی مسدود شد" in pages["block"]["html"]
    assert pages["ratelimit"]["headers"]["Retry-After"] == "60" and "Too many requests" in pages["ratelimit"]["html"]
    ch = pages["challenge"]["html"]
    assert re.search(r'<script id="pcdn-challenge" type="application/json">\{.*?\}</script><script>function S\(', ch)
    assert "/__pcdn/verify?t=" in ch and "<noscript>" in ch
    cap = pages["captcha"]["html"]
    assert '<form method="post" action="/__pcdn/captcha">' in cap and 'name="t"' in cap and 'name="r" value="/shop/cart?x=1"' in cap
    assert 'name="a"' in cap and '<svg xmlns="http://www.w3.org/2000/svg"' in cap and "<text" not in cap
    assert "Incorrect" in pages["captcha_error"]["html"] and 'name="r" value="/back"' in pages["captcha_error"]["html"]
    assert 'href="/back"' in pages["verify_failed"]["html"]
    for k in ("queue", "queue_en"):
        q = pages[k]
        assert int(q["headers"]["Retry-After"]) >= 15
        assert f'<meta http-equiv="refresh" content="{q["headers"]["Retry-After"]}">' in q["html"]
    assert "position in the queue: 1" in pages["queue_en"]["html"] and '<html lang="en"' in pages["queue_en"]["html"]
    assert "جایگاه تقریبی شما در صف: 3" in pages["queue"]["html"]
    assert 'action="/__pcdn/access/send"' in pages["access_login"]["html"] and "Admin &lt;panel&gt;" in pages["access_login"]["html"]
    assert 'action="/__pcdn/access/verify"' in pages["access_sent"]["html"] and 'value="x1@corp.test"' in pages["access_sent"]["html"]
    assert pages["access_locked"]["headers"]["Retry-After"] == "540"


@pytest.mark.parametrize("name", ["queue", "queue_en", "access_denied", "access_login", "access_sent", "access_bad",
                                  "access_locked", "access_many"])
def test_gate_pages_keep_strict_csp(pages, name):
    pg = pages[name]
    csp = pg["headers"]["Content-Security-Policy"]
    nonce = re.search(r"style-src 'nonce-([0-9a-f]{32})'", csp).group(1)
    assert csp.startswith("default-src 'none'; ") and "script-src" not in csp and "unsafe" not in csp
    assert f'<style nonce="{nonce}">' in pg["html"] and pg["html"].count("<style") == 1
    assert "<script" not in pg["html"] and " style=" not in pg["html"] and not re.search(r"<[^>]+\son[a-z]+=", pg["html"])
    assert pg["headers"]["X-Frame-Options"] == "DENY"


def test_static_pages_share_the_njs_css(pages):
    for name in ("suspended", "over_quota"):
        m = re.search(r"<style>(.*?)</style>", pages[name]["html"], re.S)
        assert m and m.group(1) == pages["CSS"], f"pages/{name}.html: copy CSS from njs/pcdn.js"



def test_integration_markers_stay_on_the_pages():
    # tests/integration/test_e2e.py tells the suspended page apart by this sentence
    src = (EDGE.parent / "tests" / "integration" / "test_e2e.py").read_text()
    mark = re.search(r'^SUSPENDED_MARK = "([^"]+)"', src, re.M).group(1)
    assert mark in (EDGE / "pages" / "suspended.html").read_text()
    assert mark not in (EDGE / "pages" / "over_quota.html").read_text()

def test_decoy_stays_neutral():
    h = (EDGE / "pages" / "decoy.html").read_text()
    for word in ("cdn", "pasargad", "proxy", "nginx", "tunnel", "vpn"):
        assert word not in h.lower()
    assert not check(h).errors
