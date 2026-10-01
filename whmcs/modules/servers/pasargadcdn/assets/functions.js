/*
 * Pasargad CDN — client app: «توابع لبه» edge functions (docs/SPEC.md §16.9, docs/WHMCS.md).
 *
 * Registers PCDN.pages.functions:
 *   - section `functions` {enabled, on_error, items: [{id, route, code, enabled, timeout_ms, memory_mb, on_error}]}
 *     edited as one config-section form (save bar). The site object carries the section WITHOUT code
 *     (code_bytes + sha256 only), so the page always reads GET config/functions first and edits that;
 *     before saving it reads it again and asks before overwriting a version changed elsewhere;
 *   - list (route, id, on/off switch, size, CPU / memory limits, on_error), editor drawer with a small
 *     dependency-free code editor (line numbers, Tab indentation, auto-indent), ready templates,
 *     client-side validation mirroring controller/app/sections.py (ids, routes, code <= 256 KiB,
 *     limits, unique ids / routes, nesting with tunnel paths, decoy / 404 tunnel fallback, plan max);
 *   - usage card (GET functions/stats?hours=24|168: invocations, error %, CPU ms, chart);
 *   - a static «how to test» panel (WHMCS never runs customer code) and the API / limits reference.
 *
 * Feature detection: the page exists only when the controller's plan features carry edge_functions
 * (an older controller never sees a functions call); it is locked (upsell) while edge_functions is off.
 * Read-only team members and inactive services can open every function and read its code; every write
 * control is disabled. Data reaches the DOM only through textContent / createElement / .value.
 */
(function () {
  'use strict';
  var P = window.PCDN = window.PCDN || {};
  var t = P.t;  // i18n.js (SPEC §16.10)
  var pages = P.pages = P.pages || {};
  if (!P.h) return;
  var h = P.h, append = P.append, clear = P.clear, icon = P.icon, ltr = P.ltr, num = P.num, clone = P.clone;

  function A() { return P.app; }
  function S() { return P.app.S; }
  function site() { return P.app.S.site; }
  function has(o, k) { return !!o && typeof o === 'object' && Object.prototype.hasOwnProperty.call(o, k); }
  function feats(s) { return (s && s.plan && s.plan.features) || {}; }
  /** The controller knows edge functions (plan features carry edge_functions, or the site has the section). */
  function known(s) {
    var c = s && s.config && s.config.functions;
    return has(feats(s), 'edge_functions') || (!!c && typeof c === 'object' && !Array.isArray(c));
  }
  function canWrite() { return !!S().active && !A().readonly; }

  // ------------------------------------------------------------------ rules (controller/app/sections.py FunctionItem / Functions)

  var ID_RE = /^[a-z0-9_-]{1,32}$/;
  var ROUTE_RE = /^\/[A-Za-z0-9._~\/-]{0,255}$/;     // FUNCTION_ROUTE_RE (fullmatch)
  var CODE_MAX = 256 * 1024;                          // FUNCTION_CODE_MAX (UTF-8 bytes)
  var HARD_MAX = 32;                                  // FUNCTIONS_MAX
  var TIMEOUT = [1, 200], MEMORY = [8, 128], DEF_TIMEOUT = 50, DEF_MEMORY = 32;
  var BODY_MAX = 9437184;                             // ClientApi::MAX_BODY_FUNCTIONS (9 MB)
  var OUT_KEYS = ['code_bytes', 'sha256'];

  function maxFns() { var m = Number(feats(site()).max_functions); return Math.min(HARD_MAX, m > 0 ? Math.floor(m) : 0); }

  /** UTF-8 length of a string (lone surrogates count 3 bytes, like Python's surrogatepass). */
  function utf8Len(s) {
    s = String(s || '');
    var n = 0;
    for (var i = 0; i < s.length; i++) {
      var c = s.charCodeAt(i);
      if (c < 0x80) n += 1;
      else if (c < 0x800) n += 2;
      else if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length && (s.charCodeAt(i + 1) & 0xfc00) === 0xdc00) { n += 4; i++; }
      else n += 3;
    }
    return n;
  }
  function kb(bytes) { return P.num1(bytes / 1024) + t(' کیلوبایت'); }

  /** Why the edge would skip this route (function_route_problem), or ''. */
  function routeProblem(r) {
    r = String(r === null || r === undefined ? '' : r);
    if (!r) return t('مسیر تابع را وارد کنید (مثل /api/hello).');
    if (!ROUTE_RE.test(r)) return t('مسیر باید با / شروع شود و فقط حروف انگلیسی، عدد و . _ ~ / - داشته باشد (حداکثر ۲۵۶ کاراکتر، مثل /api/auth).');
    if (r.toLowerCase().indexOf('/__pcdn') === 0) return t('مسیرهای /__pcdn رزرو شده‌اند.');
    var segs = r.split('/').slice(1);
    if (r.charAt(r.length - 1) === '/') segs.pop();
    if (r.indexOf('//') >= 0 || segs.some(function (x) { return x === '.' || x === '..'; })) return t('مسیر نباید // یا بخش‌های . و .. داشته باشد.');
    return '';
  }
  /** routes_nest: plain string prefixes in either direction. */
  function nests(a, b) { return a.indexOf(b) === 0 || b.indexOf(a) === 0; }
  function tunnelSec() { var c = site() && site().config && site().config.tunnel; return c && typeof c === 'object' ? c : { enabled: false, paths: [] }; }
  /** The tunnel path a route equals / nests with, or null. */
  function tunnelClash(route) {
    var ps = Array.isArray(tunnelSec().paths) ? tunnelSec().paths : [];
    for (var i = 0; i < ps.length; i++) if (ps[i] && typeof ps[i].path === 'string' && route && nests(route, ps[i].path)) return ps[i];
    return null;
  }
  function decoyFallback() { var tn = tunnelSec(); return !!tn.enabled && (tn.fallback || 'origin') !== 'origin'; }
  function live(d) { return !!d.enabled && (d.items || []).some(function (i) { return i.enabled !== false; }); }

  /** Problems of one function ([{path, msg}], paths relative to the item); `others` = the other items. */
  function itemProblems(it, others) {
    var out = [];
    function bad(p, m) { out.push({ path: p, msg: m }); }
    if (!ID_RE.test(String(it.id || ''))) bad('id', t('شناسه باید ۱ تا ۳۲ کاراکتر از حروف کوچک انگلیسی، رقم، - و _ باشد.'));
    else if (others.some(function (x) { return x.id === it.id; })) bad('id', t('تابع دیگری همین شناسه را دارد.'));
    var rp = routeProblem(it.route);
    if (rp) bad('route', rp);
    else if (others.some(function (x) { return x.route === it.route; })) bad('route', t('تابع دیگری به همین مسیر وصل است؛ مسیر هر تابع باید یکتا باشد.'));
    else {
      var tp = tunnelClash(it.route);
      if (tp) bad('route', t('این مسیر با مسیر تونل {0} هم‌پوشانی دارد (یکی پیشوند دیگری است)؛ مسیر دیگری انتخاب کنید.', tp.path));
    }
    if (typeof it.code !== 'string') bad('code', t('کد این تابع دریافت نشده است؛ صفحه را دوباره بارگذاری کنید.'));
    else if (!it.code.trim()) bad('code', t('کد تابع خالی است.'));
    else if (utf8Len(it.code) > CODE_MAX) bad('code', t('کد هر تابع حداکثر ۲۵۶ کیلوبایت است (اکنون {0}).', kb(utf8Len(it.code))));
    var tm = it.timeout_ms, mm = it.memory_mb;
    if (typeof tm !== 'number' || tm % 1 !== 0 || tm < TIMEOUT[0] || tm > TIMEOUT[1]) bad('timeout_ms', t('سقف CPU باید عددی بین ۱ و ۲۰۰ میلی‌ثانیه باشد.'));
    if (typeof mm !== 'number' || mm % 1 !== 0 || mm < MEMORY[0] || mm > MEMORY[1]) bad('memory_mb', t('سقف حافظه باید عددی بین ۸ و ۱۲۸ مگابایت باشد.'));
    if ([null, '502', 'origin'].indexOf(it.on_error === undefined ? null : it.on_error) < 0) bad('on_error', t('رفتار هنگام خطا نامعتبر است.'));
    return out;
  }
  /** Problems of the whole section ([{path, msg}] for the form). */
  function problems(d) {
    var out = [], items = d.items || [];
    items.forEach(function (it, i) {
      itemProblems(it, items.slice(0, i)).forEach(function (x) {
        out.push({ path: 'items.' + i + '.' + x.path, msg: t('تابع {0}: ', it.id || num(i + 1)) + x.msg });
      });
    });
    var max = maxFns();
    if (items.length > max) out.push({ path: 'items', msg: t('پلن شما حداکثر {0} تابع را مجاز می‌داند.', num(max)) });
    if (live(d) && decoyFallback()) {
      out.push({ path: 'enabled', msg: t('تونل این سایت به مسیرهای ناشناخته پاسخ decoy یا 404 می‌دهد و در این حالت توابع اجرا نمی‌شوند؛ ابتدا در صفحهٔ تونل «پاسخ پیش‌فرض» را «سرور اصلی» کنید یا توابع را خاموش بگذارید.') });
    }
    return out;
  }
  /** Section as sent: no output-only keys (code_bytes, sha256), fixed key order. */
  function serialize(d) {
    return {
      enabled: !!d.enabled, on_error: d.on_error === 'origin' ? 'origin' : '502',
      items: (d.items || []).map(function (i) {
        return { id: i.id, route: i.route, code: i.code, enabled: i.enabled !== false, timeout_ms: i.timeout_ms, memory_mb: i.memory_mb,
          on_error: i.on_error === '502' || i.on_error === 'origin' ? i.on_error : null };
      })
    };
  }
  /** What the controller stores now (ids, routes, code hashes, settings) — detects a change made elsewhere. */
  function fingerprint(fn) {
    fn = fn || {};
    return JSON.stringify([!!fn.enabled, fn.on_error || '502', (fn.items || []).map(function (i) {
      return [i.id, i.route, i.sha256 || null, i.enabled !== false, i.timeout_ms, i.memory_mb, i.on_error || null];
    })]);
  }
  function valid(fn) {
    return !!fn && typeof fn === 'object' && Array.isArray(fn.items) && fn.items.every(function (i) { return i && typeof i.code === 'string'; });
  }
  function newId(items) {
    var used = {};
    items.forEach(function (i) { used[i.id] = 1; });
    for (var n = 1; n < 1000; n++) if (!used['fn' + n]) return 'fn' + n;
    return 'fn' + Date.now().toString(36).slice(-6);
  }
  function errLabel(v, sec) {
    if (v === 'origin') return t('ارسال به سرور اصلی');
    if (v === '502') return t('خطای ۵۰۲');
    return t('مثل تنظیم کلی ({0})', errLabel(sec || '502'));
  }

  // ------------------------------------------------------------------ templates (code is English; visible texts follow the app language)

  function jsStr(s) { return "'" + String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n') + "'"; }
  function htmlEsc(s) { return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }

  function templates() {
    var lang = P.isEn ? 'en' : 'fa', dir = P.isEn ? 'ltr' : 'rtl';
    var mTitle = htmlEsc(t('در حال به‌روزرسانی هستیم')), mText = htmlEsc(t('سایت تا چند دقیقهٔ دیگر در دسترس خواهد بود. از شکیبایی شما سپاسگزاریم.'));
    return [
      { id: 'country', title: t('ریدایرکت بر اساس کشور'), route: '/', desc: t('بازدیدکنندگان چند کشور را به نسخهٔ مخصوص خودشان می‌فرستد؛ بقیه به سرور اصلی می‌روند.'),
        code: [
          '// Redirect visitors from some countries to their own version of the site;',
          '// everyone else continues to the origin (return null = pass).',
          'const TARGETS = { DE: \'/de/\', FR: \'/fr/\', TR: \'/tr/\' };',
          '',
          'async function handleRequest(request) {',
          '  const country = request.client.country;   // ISO code such as "DE" ("" when unknown)',
          '  const target = TARGETS[country];',
          '  const url = new URL(request.url);',
          '  if (target && !url.pathname.startsWith(target)) {',
          '    return Response.redirect(url.origin + target + url.search, 302);',
          '  }',
          '  return null;',
          '}', ''].join('\n') },
      { id: 'ab', title: t('آزمون A/B با هدر'), route: '/landing', desc: t('هر بازدیدکننده را با کوکی در گروه A یا B نگه می‌دارد و گروه را با هدر X-Variant به سرور اصلی می‌گوید.'),
        code: [
          '// A/B test: put each visitor in variant A or B (50/50), remember it in a cookie',
          '// and tell the origin which variant to render with the X-Variant header.',
          'async function handleRequest(request) {',
          '  const cookie = request.headers.get(\'cookie\') || \'\';',
          '  const m = /(?:^|;\\s*)ab=(A|B)/.exec(cookie);',
          '  const variant = m ? m[1] : (Math.random() < 0.5 ? \'A\' : \'B\');',
          '',
          '  const headers = new Headers(request.headers);',
          '  headers.set(\'x-variant\', variant);',
          '  const res = await fetch(request.url, { method: request.method, headers, body: request.body });',
          '',
          '  const out = new Response(res.body, { status: res.status, headers: res.headers });',
          '  out.headers.set(\'vary\', \'cookie\');',
          '  if (!m) out.headers.append(\'set-cookie\', \'ab=\' + variant + \'; Path=/; Max-Age=2592000; SameSite=Lax\');',
          '  return out;',
          '}', ''].join('\n') },
      { id: 'json', title: t('پاسخ JSON ساده (API)'), route: '/api/hello', desc: t('بدون درخواست به سرور اصلی، مستقیماً روی نود CDN یک پاسخ JSON برمی‌گرداند.'),
        code: [
          '// A tiny JSON API answered at the edge (the origin is never asked).',
          'async function handleRequest(request) {',
          '  if (request.method !== \'GET\') {',
          '    return Response.json({ error: \'method not allowed\' }, { status: 405, headers: { allow: \'GET\' } });',
          '  }',
          '  const url = new URL(request.url);',
          '  return Response.json({',
          '    hello: url.searchParams.get(\'name\') || \'world\',',
          '    country: request.client.country || null,',
          '    time: new Date().toISOString(),',
          '  }, { headers: { \'cache-control\': \'no-store\' } });',
          '}', ''].join('\n') },
      { id: 'maintenance', title: t('صفحهٔ تعمیر و نگهداری'), route: '/', desc: t('به همه صفحهٔ «در حال به‌روزرسانی» (کد ۵۰۳) نشان می‌دهد؛ آی‌پی‌های فهرست‌شده به سرور اصلی می‌رسند.'),
        code: [
          '// Maintenance page (HTTP 503) for everyone except the listed IPs, which reach the origin.',
          'const ALLOW = [\'203.0.113.7\'];   // your office / your own IP',
          '',
          'const HTML = \'<!doctype html><html lang="' + lang + '" dir="' + dir + '"><head><meta charset="utf-8">\' +',
          '  \'<meta name="viewport" content="width=device-width, initial-scale=1"><title>\' + ' + jsStr(mTitle) + ' + \'</title>\' +',
          '  \'<style>body{font-family:system-ui,Tahoma,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;\' +',
          '  \'background:#f5f7fb;color:#1f2937;text-align:center}main{max-width:520px;padding:24px}</style></head>\' +',
          '  \'<body><main><h1>\' + ' + jsStr(mTitle) + ' + \'</h1><p>\' + ' + jsStr(mText) + ' + \'</p></main></body></html>\';',
          '',
          'async function handleRequest(request) {',
          '  if (ALLOW.includes(request.client.ip)) return null;   // pass to the origin',
          '  return new Response(HTML, {',
          '    status: 503,',
          '    headers: { \'content-type\': \'text/html; charset=utf-8\', \'retry-after\': \'600\', \'cache-control\': \'no-store\' },',
          '  });',
          '}', ''].join('\n') },
      { id: 'headers', title: t('افزودن هدرهای امنیتی'), route: '/', desc: t('صفحه را از سرور اصلی می‌گیرد و هدرهای امنیتی را به پاسخ اضافه می‌کند؛ فایل‌های حجیم و درخواست‌های غیر GET مستقیم عبور می‌کنند.'),
        code: [
          '// Add security headers to pages from the origin. Large files and non-GET requests',
          '// pass straight through (return null): a function response is limited to 5 MB.',
          'const PASS = /\\.(?:jpe?g|png|gif|webp|avif|svg|ico|mp4|webm|mp3|zip|pdf|woff2?)$/i;',
          '',
          'async function handleRequest(request) {',
          '  const url = new URL(request.url);',
          '  if (request.method !== \'GET\' || PASS.test(url.pathname)) return null;',
          '',
          '  const res = await fetch(request.url, { headers: request.headers });',
          '  const out = new Response(res.body, { status: res.status, headers: res.headers });',
          '  out.headers.set(\'strict-transport-security\', \'max-age=31536000; includeSubDomains\');',
          '  out.headers.set(\'x-content-type-options\', \'nosniff\');',
          '  out.headers.set(\'x-frame-options\', \'SAMEORIGIN\');',
          '  out.headers.set(\'referrer-policy\', \'strict-origin-when-cross-origin\');',
          '  out.headers.set(\'permissions-policy\', \'camera=(), microphone=(), geolocation=()\');',
          '  return out;',
          '}', ''].join('\n') }
    ];
  }
  var STARTER = [
    '// Runs on the CDN edge for every request under this function\'s route.',
    '// Return a Response to answer, or null to continue to your origin.',
    'async function handleRequest(request) {',
    '  return null;',
    '}', ''].join('\n');

  // ------------------------------------------------------------------ code editor (textarea + line numbers, no dependencies)

  /**
   * A monospace code editor: line-number gutter, Tab / Shift+Tab indentation (selection too), Enter keeps
   * the indentation, Ctrl+M (or Esc… not used: Esc closes the drawer) toggles "Tab moves focus" for keyboard
   * users. o: {value, label, readonly, oninput(value)}. Returns {el, ta, value()}.
   */
  function codeEditor(o) {
    var IND = '  ';
    var gutter = h('pre', { className: 'pcdn-fn-gutter', 'aria-hidden': 'true' });
    var ta = h('textarea', { className: 'pcdn-fn-code', dir: 'ltr', spellcheck: 'false', autocomplete: 'off', autocapitalize: 'off', autocorrect: 'off',
      wrap: 'off', 'aria-label': o.label, value: o.value || '' });
    if (o.readonly) { ta.readOnly = true; ta.setAttribute('data-ro-ok', '1'); }
    var pos = h('span', { className: 'pcdn-fn-pos', dir: 'ltr' });
    var size = h('span', { className: 'pcdn-fn-size' });
    var mode = h('span', { className: 'pcdn-fn-tabmode' });
    var tabMoves = false, lastLines = -1;
    function lines() {
      var n = 1, v = ta.value;
      for (var i = v.indexOf('\n'); i >= 0; i = v.indexOf('\n', i + 1)) n++;
      if (n !== lastLines) {
        lastLines = n;
        var out = [];
        for (var k = 1; k <= n; k++) out.push(k);
        gutter.textContent = out.join('\n') + '\n';
      }
      gutter.scrollTop = ta.scrollTop;
    }
    function status() {
      var v = ta.value, at = ta.selectionStart || 0, before = v.slice(0, at), ln = before.split('\n').length, col = at - before.lastIndexOf('\n');
      pos.textContent = P.fa('Ln ' + ln + ', Col ' + col);
      var b = utf8Len(v);
      size.textContent = kb(b) + t(' از ۲۵۶');
      size.className = 'pcdn-fn-size' + (b > CODE_MAX ? ' is-over' : b > CODE_MAX * 0.9 ? ' is-near' : '');
      mode.textContent = o.readonly ? t('فقط مشاهده') : tabMoves ? t('Tab: رفتن به فیلد بعدی (Ctrl+M)') : t('Tab: تورفتگی (Ctrl+M برای خروج با Tab)');
    }
    function changed() { lines(); status(); if (o.oninput) o.oninput(ta.value); }
    /** Replace [a, b) with text keeping the browser's undo history when possible. */
    function replace(a, b, text, selA, selB) {
      ta.focus();
      ta.setSelectionRange(a, b);
      var ok = false;
      try { ok = document.execCommand('insertText', false, text); } catch (e) { ok = false; }
      if (!ok || ta.value.slice(a, a + text.length) !== text) {
        ta.setRangeText(text, a, b, 'end');
        ta.dispatchEvent(new Event('input', { bubbles: true }));
      }
      if (selA !== undefined) ta.setSelectionRange(selA, selB);
    }
    function indent(outdent) {
      var v = ta.value, a = ta.selectionStart, b = ta.selectionEnd;
      var ls = v.lastIndexOf('\n', a - 1) + 1;
      if (a === b && !outdent) { replace(a, b, IND); return; }
      var le = v.indexOf('\n', b > a && v.charAt(b - 1) === '\n' ? b - 1 : b);
      if (le < 0) le = v.length;
      var block = v.slice(ls, le).split('\n'), first = 0, total = 0;
      var nb = block.map(function (l, i) {
        if (!outdent) { if (i === 0) first = IND.length; total += IND.length; return IND + l; }
        var m = /^( {1,2}|\t)/.exec(l), d = m ? m[0].length : 0;
        if (i === 0) first = -Math.min(d, a - ls);
        total -= d;
        return l.slice(d);
      }).join('\n');
      if (nb === v.slice(ls, le)) return;
      replace(ls, le, nb, a === b ? Math.max(ls, a + first) : Math.max(ls, a + first), a === b ? Math.max(ls, a + first) : b + total);
    }
    ta.addEventListener('keydown', function (e) {
      if (ta.readOnly) return;
      if ((e.ctrlKey || e.metaKey) && !e.altKey && (e.key === 'm' || e.key === 'M')) { e.preventDefault(); tabMoves = !tabMoves; status(); return; }
      if (e.key === 'Tab' && !tabMoves && !e.ctrlKey && !e.altKey && !e.metaKey) {
        e.preventDefault();
        e.stopPropagation();
        indent(e.shiftKey);
        return;
      }
      if (e.key === 'Enter' && !e.shiftKey && !e.ctrlKey && !e.altKey && !e.metaKey && !e.isComposing) {
        var v = ta.value, a = ta.selectionStart, ls = v.lastIndexOf('\n', a - 1) + 1;
        var ind = /^[ \t]*/.exec(v.slice(ls, a))[0];
        if (/[{[(]\s*$/.test(v.slice(ls, a))) ind += IND;
        e.preventDefault();
        replace(a, ta.selectionEnd, '\n' + ind);
      }
    });
    ta.addEventListener('input', changed);
    ta.addEventListener('scroll', function () { gutter.scrollTop = ta.scrollTop; });
    ['keyup', 'click', 'select'].forEach(function (ev) { ta.addEventListener(ev, status); });
    var el = h('div', { className: 'pcdn-fn-editor' + (o.readonly ? ' is-readonly' : '') },
      h('div', { className: 'pcdn-fn-editor-main', dir: 'ltr' }, gutter, ta),
      h('div', { className: 'pcdn-fn-editor-bar' }, pos, mode, size));
    lines();
    status();
    return {
      el: el, ta: ta,
      value: function () { return ta.value; },
      set: function (v) {
        if (ta.readOnly) return;
        replace(0, ta.value.length, v, 0, 0);
        ta.scrollTop = 0;
        changed();
      }
    };
  }

  // ------------------------------------------------------------------ editor drawer

  function editDrawer(d, f2, idx) {
    var items = d.items, orig = idx >= 0 ? items[idx] : null, rw = canWrite();
    var draft = orig ? clone(orig) : { id: newId(items), route: '', code: STARTER, enabled: true, timeout_ms: DEF_TIMEOUT, memory_mb: DEF_MEMORY, on_error: null };
    if (draft.on_error === undefined) draft.on_error = null;
    var others = items.filter(function (x, i) { return i !== idx; });
    var dlg = P.dialog({ title: !orig ? t('تابع جدید') : rw ? t('ویرایش تابع') : t('مشاهدهٔ تابع'),
      subtitle: orig ? '\u2066' + String(orig.route || '') + '\u2069' : t('کد JavaScript که روی نودهای CDN برای یک مسیر اجرا می‌شود.'), icon: 'code', kind: 'drawer', wide: true });
    dlg.el.classList.add('pcdn-fn-drawer');
    var err = h('div'), form = h('form', { className: 'pcdn-form', novalidate: true, onsubmit: function (e) { e.preventDefault(); ok(); } });
    var ed = null, ctx = null, codeDirty = false, routeHint = h('div', { className: 'pcdn-fn-routehint', 'aria-live': 'polite' });
    function hintRoute() {
      clear(routeHint);
      var r = String(draft.route || ''), p = r ? routeProblem(r) : '', tp = !p && r ? tunnelClash(r) : null;
      if (p && r) routeHint.appendChild(h('p', { className: 'pcdn-help pcdn-tone-danger', text: p }));
      else if (tp) routeHint.appendChild(h('p', { className: 'pcdn-help pcdn-tone-danger', text: t('این مسیر با مسیر تونل {0} هم‌پوشانی دارد (یکی پیشوند دیگری است)؛ مسیر دیگری انتخاب کنید.', tp.path) }));
      else if (r) {
        var ex = r.charAt(r.length - 1) === '/' ? r + 'x' : r + '/x';
        routeHint.appendChild(h('p', { className: 'pcdn-help' }, t('اجرا برای '), ltr(r), t(' و هر نشانی که با آن شروع شود، مثل '), ltr(ex),
          r.charAt(r.length - 1) === '/' ? null : [t(' و حتی '), ltr(r + 'x')], '.'));
      }
    }
    function handlerHint() {
      var c = String(draft.code || '');
      return /\bhandleRequest\b/.test(c) || /addEventListener\s*\(\s*['"]fetch['"]/.test(c) ? null
        : P.alertBox('warning', t('در این کد تابع handleRequest(request) یا addEventListener(\'fetch\', …) دیده نمی‌شود؛ بدون یکی از این دو، هر درخواست با خطا (رفتار «هنگام خطا») پاسخ می‌گیرد.'));
    }
    var hhBox = h('div');
    function draw() {
      clear(form);
      P.beginForm(draft);
      ed = codeEditor({ value: draft.code, label: t('کد JavaScript تابع'), readonly: !rw, oninput: function (v) {
        draft.code = v; codeDirty = true;
        clear(hhBox); append(hhBox, handlerHint());
      } });
      var tpl = rw ? h('div', { className: 'pcdn-field pcdn-fn-tpls' }, h('span', { className: 'pcdn-label', text: t('شروع از یک الگو') }),
        h('div', { className: 'pcdn-chips-row' }, templates().map(function (tp) {
          return h('button', { type: 'button', className: 'pcdn-chip-btn', 'data-write': '1', 'data-tpl': tp.id, title: tp.desc, text: tp.title, onclick: function () { useTemplate(tp); } });
        })), h('div', { className: 'pcdn-help', text: t('الگو جای کد فعلی را می‌گیرد؛ اگر مسیر خالی باشد مسیر پیشنهادی آن هم نوشته می‌شود.') })) : null;
      var idField = orig
        ? h('div', { className: 'pcdn-field' }, h('span', { className: 'pcdn-label', text: t('شناسه') }), h('div', null, ltr(String(draft.id))),
          h('div', { className: 'pcdn-help', text: t('شناسه پس از ساخت تغییر نمی‌کند (در آمار و گزارش‌ها استفاده می‌شود).') }))
        : P.input(draft, 'id', t('شناسه'), { maxlength: 32, placeholder: 'auth', cls: 'pcdn-fn-id', help: t('۱ تا ۳۲ کاراکتر: حروف کوچک انگلیسی، رقم، - و _ (برای شناختن تابع در آمار).') });
      append(form, [
        h('div', { className: 'pcdn-grid' }, idField,
          h('div', null, P.input(draft, 'route', t('مسیر تابع'), { maxlength: 256, placeholder: '/api/hello', cls: 'pcdn-fn-route', oninput: hintRoute,
            help: t('پیشوند مسیری که این تابع به آن پاسخ می‌دهد (با / شروع می‌شود). برای محدود کردن به یک پوشه، / پایانی بگذارید (مثل /api/).') }), routeHint)),
        tpl,
        P.field(t('کد JavaScript'), ed.el, { cls: 'pcdn-fn-codefield', path: 'code',
          help: t('تابع async handleRequest(request) یا addEventListener(\'fetch\', …) بنویسید؛ Response برگردانید تا پاسخ دهد، یا null تا درخواست به سرور اصلی برود. راهنمای کامل API پایین همین صفحه است.') }),
        hhBox,
        h('div', { className: 'pcdn-grid pcdn-grid-3' },
          P.input(draft, 'timeout_ms', t('سقف زمان CPU'), { type: 'number', min: TIMEOUT[0], max: TIMEOUT[1], suffix: t('میلی‌ثانیه'), suffixRtl: true, cls: 'pcdn-fn-timeout',
            help: t('زمان پردازنده در هر اجرا (۱ تا ۲۰۰؛ پیش‌فرض ۵۰). انتظار برای fetch حساب نمی‌شود.') }),
          P.input(draft, 'memory_mb', t('سقف حافظه'), { type: 'number', min: MEMORY[0], max: MEMORY[1], suffix: t('مگابایت'), suffixRtl: true, cls: 'pcdn-fn-memory',
            help: t('حافظهٔ JavaScript در هر اجرا (۸ تا ۱۲۸؛ پیش‌فرض ۳۲).') }),
          P.select(draft, 'on_error', t('هنگام خطا یا اتمام زمان'), [[null, errLabel(null, d.on_error)], ['502', errLabel('502')], ['origin', errLabel('origin')]],
            { cls: 'pcdn-fn-onerror', help: t('«خطای ۵۰۲» امن‌تر است (مثلاً برای تابع احراز هویت)؛ «ارسال به سرور اصلی» درخواست را بدون تابع ادامه می‌دهد.') })),
        P.toggle(draft, 'enabled', t('فعال'), { cls: 'pcdn-fn-enabled', help: t('تابع غیرفعال نگه داشته می‌شود ولی روی نودها اجرا نمی‌شود.') }),
        h('button', { type: 'submit', hidden: true, tabindex: '-1', 'aria-hidden': 'true' })]);
      ctx = P.endForm();
      hintRoute();
      clear(hhBox); append(hhBox, handlerHint());
      A().lockWrites(form);
    }
    function useTemplate(tp) {
      var cur = String(ed.value());
      var go = cur.trim() && cur !== STARTER && (codeDirty || orig) ? P.confirm({ title: t('جایگزینی کد با الگو'), ok: t('جایگزینی'),
        body: t('کد فعلی این تابع با الگوی «{0}» جایگزین می‌شود. ادامه می‌دهید؟', tp.title) }) : Promise.resolve(true);
      go.then(function (yes) {
        if (!yes) return;
        draft.code = tp.code;
        if (!String(draft.route || '').trim()) {
          draft.route = tp.route;
          var ri = form.querySelector('.pcdn-fn-route input');
          if (ri) ri.value = tp.route;
          hintRoute();
        }
        ed.set(tp.code);
        codeDirty = true;
        P.toast(t('الگوی «{0}» در ویرایشگر قرار گرفت؛ مقادیر نمونه را با مقادیر خودتان عوض کنید.', tp.title), 'info');
      });
    }
    function ok() {
      clear(err);
      P.clearErrors(form);
      draft.code = ed.value();
      if (typeof draft.id === 'string') draft.id = draft.id.trim();
      if (typeof draft.route === 'string') draft.route = draft.route.trim();
      var probs = itemProblems(draft, others);
      if (probs.length) {
        var rest = P.placeErrors(ctx, probs);
        if (rest.length) err.appendChild(P.alertBox('danger', h('ul', { className: 'pcdn-errlist' }, rest.map(function (x) { return h('li', { text: x.msg }); }))));
        var b = form.querySelector('[aria-invalid]') || form.querySelector('.has-error input, .has-error textarea');
        if (b) b.focus();
        return;
      }
      var nw = clone(draft);
      if (!orig || orig.code !== nw.code) { OUT_KEYS.forEach(function (k) { delete nw[k]; }); }
      dlg.close(true);
      if (orig) items[idx] = nw; else { nw._new = true; items.push(nw); }
      f2.redraw();
      P.toast(orig ? t('تغییرات تابع اعمال شد؛ برای ثبت «ذخیره» را بزنید.') : t('تابع به فهرست اضافه شد؛ برای ثبت «ذخیره» را بزنید.'), 'info');
    }
    if (rw) {
      append(dlg.foot, [P.btn(t('تأیید'), { kind: 'primary', icon: 'check', write: true, cls: 'pcdn-fn-ok', onclick: ok }),
        P.btn(t('انصراف'), { onclick: function () { dlg.close(); } })]);
    } else {
      var cl = P.btn(t('بستن'), { kind: 'primary', cls: 'pcdn-fn-close', onclick: function () { dlg.close(); } });
      cl.setAttribute('data-ro-ok', '1');
      var cp = P.btn(t('کپی کد'), { icon: 'copy', cls: 'pcdn-fn-copy', onclick: function () {
        P.copyText(ed.value()).then(function () { P.toast(t('کد کپی شد')); }, function () { P.toast(t('کپی خودکار ممکن نشد؛ متن را دستی انتخاب کنید.'), 'error'); });
      } });
      cp.setAttribute('data-ro-ok', '1');
      append(dlg.foot, [cl, cp]);
    }
    append(dlg.body, [err, form]);
    draw();
    if (orig) ed.ta.focus(); else dlg.focusFirst();
    return dlg;
  }

  // ------------------------------------------------------------------ list + settings (section form)

  function build(d, f2) {
    d.items = Array.isArray(d.items) ? d.items : [];
    if (d.on_error !== 'origin') d.on_error = '502';
    var items = d.items, max = maxFns(), full = items.length >= max, rw = canWrite();
    // settings
    var sc = P.card({ title: t('اجرای توابع'), icon: 'power', id: 'fn-settings' });
    var decoy = decoyFallback();
    append(sc.body, [
      P.toggle(d, 'enabled', t('اجرای توابع لبه روی این سایت'), { cls: 'pcdn-fn-master', onchange: f2.redraw,
        help: t('خاموش: هیچ تابعی اجرا نمی‌شود و همهٔ درخواست‌ها مستقیم به سرور اصلی می‌روند؛ توابع پاک نمی‌شوند.') }),
      P.choice(d, 'on_error', t('هنگام خطا یا اتمام زمان (پیش‌فرض همهٔ توابع)'), [
        ['502', t('پاسخ خطای ۵۰۲'), t('امن‌تر: اگر تابع (مثلاً احراز هویت) خطا بدهد، درخواست به سرور اصلی نمی‌رسد.'), 'shield'],
        ['origin', t('ارسال به سرور اصلی'), t('اگر تابع خطا بدهد، درخواست بدون آن ادامه پیدا می‌کند (برای توابع غیرحیاتی مثل افزودن هدر).'), 'server']],
        { cols: 2, onchange: f2.redraw }),
      decoy ? P.alertBox(live(d) ? 'danger' : 'warning', [h('strong', { text: t('تونل و توابع: ') }),
        t('تونل این سایت به مسیرهای ناشناخته پاسخ decoy یا 404 می‌دهد؛ در این حالت توابع اجرا نمی‌شوند و ذخیرهٔ توابع روشن پذیرفته نمی‌شود. «پاسخ پیش‌فرض» تونل را «سرور اصلی» کنید. '),
        A().goLink('tunnel', t('رفتن به تنظیمات تونل'))]) : null]);
    // list
    var add = P.btn(t('تابع جدید'), { kind: 'primary', icon: 'plus', size: 'sm', write: true, cls: 'pcdn-fn-add', disabled: full,
      title: full ? (max ? t('به سقف {0} تابع پلن رسیده‌اید', num(max)) : t('پلن شما تابعی را مجاز نمی‌داند')) : null, onclick: function () { editDrawer(d, f2, -1); } });
    var lc = P.card({ title: t('توابع'), icon: 'code', id: 'fn-list', subtitle: t('هر تابع به یک مسیر (پیشوند نشانی) وصل است و پیش از سرور اصلی روی نود CDN اجرا می‌شود.'),
      actions: [P.kit && P.kit.limitText ? P.kit.limitText(items.length, max, t('تابع')) : null, add] });
    P.reg('items', lc);
    if (!items.length) {
      lc.body.appendChild(P.empty('code', t('هنوز تابعی نساخته‌اید'),
        t('با چند خط JavaScript روی نودهای CDN پاسخ بدهید: ریدایرکت بر اساس کشور، API کوچک، صفحهٔ تعمیرات، آزمون A/B یا افزودن هدر — بدون تغییر در سرور خودتان.')));
    } else {
      var total = 0;
      var ul = h('ul', { className: 'pcdn-whs pcdn-fns' });
      items.forEach(function (it, i) {
        var on = it.enabled !== false, bytes = typeof it.code === 'string' ? utf8Len(it.code) : Number(it.code_bytes) || 0;
        total += bytes;
        var tp = tunnelClash(it.route);
        var li = h('li', { className: 'pcdn-wh pcdn-fn' + (on ? '' : ' is-off') + (it._new ? ' is-new' : ''), 'data-fn': String(it.id || i) },
          h('div', { className: 'pcdn-wh-main' },
            h('div', { className: 'pcdn-wh-urlline' },
              h('bdi', { className: 'pcdn-wh-url pcdn-fn-route-v', dir: 'ltr', text: String(it.route || '') }),
              P.badge(String(it.id || ''), 'muted'),
              on ? null : P.badge(t('غیرفعال'), 'muted'), it._new ? P.badge(t('ذخیره نشده'), 'warning') : null,
              tp ? P.badge(t('هم‌پوشانی با تونل'), 'danger', 'warn') : null),
            h('div', { className: 'pcdn-l4-meta pcdn-fn-meta' },
              h('span', { className: 'pcdn-fn-bytes', text: t('حجم کد: ') + kb(bytes) }),
              h('span', { text: t('زمان CPU: ') + num(Number(it.timeout_ms) || 0) + t(' میلی‌ثانیه') }),
              h('span', { text: t('حافظه: ') + num(Number(it.memory_mb) || 0) + t(' مگابایت') }),
              h('span', { className: 'pcdn-fn-err', text: t('هنگام خطا: ') + errLabel(it.on_error, d.on_error) }))),
          h('div', { className: 'pcdn-wh-ctl' },
            P.switchInput(on, (on ? t('غیرفعال کردن تابع ') : t('فعال کردن تابع ')) + (it.id || ''), function (v) { it.enabled = v; f2.redraw(); }, { write: true, small: true }),
            rw ? P.iconBtn('edit', t('ویرایش تابع ') + (it.id || ''), function () { editDrawer(d, f2, i); }, { cls: 'pcdn-fn-edit' })
              : P.iconBtn('eye', t('مشاهدهٔ کد تابع ') + (it.id || ''), function () { editDrawer(d, f2, i); }, { cls: 'pcdn-fn-view' }),
            P.iconBtn('trash', t('حذف تابع ') + (it.id || ''), function () {
              P.confirm({ title: t('حذف تابع'), danger: true, ok: t('حذف'), body: t('تابع «{0}» ({1}) از فهرست حذف می‌شود و پس از «ذخیره» دیگر اجرا نمی‌شود. کد آن قابل بازیابی نیست.', it.id || '', it.route || '') })
                .then(function (yes) { if (!yes) return; items.splice(i, 1); f2.redraw(); P.toast(t('تابع از فهرست حذف شد؛ برای اعمال «ذخیره» را بزنید.'), 'info'); });
            }, { write: true, cls: 'is-danger pcdn-fn-del' })));
        P.reg('items.' + i, li);
        ul.appendChild(li);
      });
      lc.body.appendChild(ul);
      lc.body.appendChild(h('p', { className: 'pcdn-help pcdn-fn-total', text: t('مجموع کد همهٔ توابع: ') + kb(total) }));
    }
    if (!rw) Array.prototype.forEach.call(lc.querySelectorAll('.pcdn-fn-view'), function (b) { b.setAttribute('data-ro-ok', '1'); });
    return [sc, lc];
  }

  // ------------------------------------------------------------------ usage (GET functions/stats)

  function kpi(ic, tone, label, value, sub, id) {
    return h('div', { className: 'pcdn-kpi', 'data-kpi': id || null },
      h('div', { className: 'pcdn-kpi-top' }, h('span', { className: 'pcdn-kpi-icon pcdn-tone-' + tone }, icon(ic)), h('span', { className: 'pcdn-kpi-label', text: label })),
      h('div', { className: 'pcdn-kpi-value' }, value), sub ? h('div', { className: 'pcdn-kpi-sub' }, sub) : null);
  }
  function statsCard() {
    var hours = P.store('fn-hours') === '168' ? 168 : 24;
    var holder = h('div', { className: 'pcdn-fn-stats' });
    var seg = h('div');
    var c = P.card({ title: t('آمار اجرا'), icon: 'chart', tone: 'violet', id: 'fn-stats', actions: seg,
      subtitle: t('اجراها، خطاها و زمان CPU همهٔ توابع این سایت (با چند دقیقه تأخیر).') });
    c.body.appendChild(holder);
    function pick(v) { hours = v; P.store('fn-hours', v === 168 ? '168' : null); load(); }
    function load() {
      clear(seg);
      seg.appendChild(P.segmented([[24, t('۲۴ ساعت')], [168, t('۷ روز')]], hours, pick, t('بازهٔ آمار توابع')));
      seg.firstChild.setAttribute('data-seg', 'fn-hours');
      clear(holder);
      holder.appendChild(P.skeleton(3));
      var want = hours;
      P.api('GET', 'functions/stats', undefined, { hours: String(hours) }).then(function (res) {
        if (want !== hours || !document.body.contains(holder)) return;
        clear(holder);
        if (!res.ok || !res.data || typeof res.data !== 'object') { holder.appendChild(P.errorBox(res, t('آمار توابع دریافت نشد'))); return; }
        draw(res.data);
      });
    }
    function draw(st) {
      var inv = Number(st.invocations) || 0, errs = Number(st.errors) || 0, tmo = Number(st.timeouts) || 0, cpu = Number(st.cpu_ms) || 0;
      var ep = Number(st.error_pct) || 0, tone = ep >= 5 ? 'danger' : ep >= 1 ? 'warning' : 'success';
      append(holder, h('div', { className: 'pcdn-kpis', 'data-fn-kpis': '1' },
        kpi('activity', 'brand', t('اجراها'), num(inv), hours === 24 ? t('در ۲۴ ساعت گذشته') : t('در ۷ روز گذشته'), 'fn-inv'),
        kpi('warn', tone, t('نرخ خطا'), inv ? P.num1(ep) + t('٪') : '—', num(errs) + t(' خطا، ') + num(tmo) + t(' مورد اتمام زمان'), 'fn-err'),
        kpi('zap', 'violet', t('زمان CPU'), P.num1(cpu / 1000) + t(' ثانیه'), inv ? t('میانگین {0} میلی‌ثانیه در هر اجرا', P.num1(cpu / inv)) : null, 'fn-cpu'),
        kpi('clock', tmo ? 'warning' : 'muted', t('اتمام زمان'), num(tmo), t('اجراهایی که از سقف CPU یا زمان گذشتند'), 'fn-tmo')));
      var series = Array.isArray(st.series) ? st.series : [];
      var size = hours <= 48 ? 1 : 6, pts = [];
      for (var i = 0; i < series.length; i += size) {
        var b = { t: series[i].t, inv: 0, err: 0 };
        for (var j = i; j < Math.min(series.length, i + size); j++) { b.inv += Number(series[j].invocations) || 0; b.err += (Number(series[j].errors) || 0) + (Number(series[j].timeouts) || 0); }
        pts.push(b);
      }
      var C = P.charts || {};
      if (!inv || !pts.length || !C.area) {
        holder.appendChild(P.empty('chart', t('در این بازه تابعی اجرا نشده است'), t('پس از روشن کردن توابع و رسیدن درخواست به مسیرهایشان، آمار اینجا نمایش داده می‌شود.')));
        return;
      }
      var labels = pts.map(function (x) { return hours <= 48 ? P.date(x.t, { hour: '2-digit', minute: '2-digit' }) : P.date(x.t, { month: 'short', day: 'numeric', hour: '2-digit' }); });
      var box = h('div', { className: 'pcdn-fn-chart' });
      holder.appendChild(box);
      C.area(box, labels, [
        { name: t('اجراها'), color: C.COLORS.requests, values: pts.map(function (x) { return x.inv; }), total: num(inv) },
        { name: t('خطا و اتمام زمان'), color: C.COLORS.s5, values: pts.map(function (x) { return x.err; }), total: num(errs + tmo) }
      ], num, t('نمودار اجراها و خطاهای توابع لبه'));
    }
    load();
    return c;
  }

  // ------------------------------------------------------------------ static panels: testing + API reference

  function codeBlock(text, caption, cls) {
    return h('figure', { className: 'pcdn-codeblock' + (cls ? ' ' + cls : '') },
      h('figcaption', null, icon('terminal'), h('span', { dir: 'ltr', text: caption }),
        P.copyBtn(text, t('کپی کد ') + caption, { text: t('کپی'), cls: 'pcdn-copy-code', done: t('کد کپی شد') })),
      h('pre', { dir: 'ltr', tabindex: '0' }, h('code', { text: text })));
  }

  function testCard(fn) {
    var c = P.collapsible({ title: t('آزمودن تابع'), icon: 'play', tone: 'muted', id: 'fn-test',
      subtitle: t('تابع فقط روی نودهای CDN اجرا می‌شود؛ این پنل اجرا نمی‌کند و فقط روش آزمودن را نشان می‌دهد.') });
    var dom = (site() && site().domain) || 'example.com';
    var first = (fn.items || []).filter(function (i) { return i.enabled !== false; })[0] || (fn.items || [])[0];
    var route = first && first.route ? first.route : '/api/hello';
    var url = 'https://' + dom + route;
    append(c.body, [
      P.alertBox('info', t('برای امنیت، کد شما هرگز در این پنل یا روی سرور صورت‌حساب اجرا نمی‌شود. آن را ذخیره کنید و نشانی واقعی را از مرورگر یا خط فرمان باز کنید.')),
      h('ol', { className: 'pcdn-ol' },
        h('li', { text: t('تابع را بسازید، «اجرای توابع لبه» را روشن کنید و «ذخیره» را بزنید؛ تا چند ثانیه روی همهٔ نودها فعال می‌شود.') }),
        h('li', { text: t('نشانی مسیر تابع را باز کنید و پاسخ (کد وضعیت، هدرها و بدنه) را ببینید:') }),
        h('li', { text: t('خروجی console در جایی ذخیره یا نمایش داده نمی‌شود؛ برای عیب‌یابی موقتاً مقدار دلخواه را در یک هدر پاسخ برگردانید (مثلاً x-debug).') }),
        h('li', { text: t('اگر تابع خطا بدهد یا از سقف CPU بگذرد، رفتار «هنگام خطا» اعمال می‌شود (خطای ۵۰۲ یا ارسال به سرور اصلی) و در کارت «آمار اجرا» شمرده می‌شود.') })),
      codeBlock('curl -i ' + url + '\ncurl -i -X POST ' + url + " -H 'content-type: application/json' -d '{\"ping\":1}'", 'curl', 'pcdn-fn-curl'),
      h('p', { className: 'pcdn-help', text: t('پیش از روشن کردن روی سایت اصلی، تابع را روی یک مسیر آزمایشی (مثل /fn-test/) امتحان کنید و بعد مسیر را عوض کنید.') })]);
    return c;
  }

  function docsCard() {
    var c = P.collapsible({ title: t('راهنمای API و محدودیت‌ها'), icon: 'book', tone: 'muted', id: 'fn-docs',
      subtitle: t('آنچه کد شما در دسترس دارد و سقف‌های هر اجرا') });
    function li(code, text) { return h('li', null, code ? [ltr(code), ' — '] : null, text); }
    var ex1 = ['async function handleRequest(request) {', '  const url = new URL(request.url);', '  if (url.searchParams.has(\'debug\')) {',
      '    return new Response(\'hello from the edge\', { headers: { \'content-type\': \'text/plain\' } });', '  }',
      '  return null;   // continue to the origin', '}'].join('\n');
    var ex2 = ['addEventListener(\'fetch\', (event) => {', '  event.passThroughOnException();   // an exception -> origin',
      '  event.respondWith(fetch(event.request));', '});'].join('\n');
    append(c.body, [
      h('h4', { className: 'pcdn-fn-h', text: t('نوشتن تابع') }),
      h('p', { text: t('یکی از دو شکل زیر را بنویسید. Response برگردانید تا همان پاسخ به بازدیدکننده برسد؛ null یا undefined برگردانید تا درخواست بدون تغییر به سرور اصلی برود (pass).') }),
      codeBlock(ex1, 'handleRequest', 'pcdn-fn-ex1'),
      codeBlock(ex2, 'addEventListener', 'pcdn-fn-ex2'),
      h('h4', { className: 'pcdn-fn-h', text: t('اشیای در دسترس') }),
      h('ul', { className: 'pcdn-ul pcdn-fn-api' },
        li('request.method, request.url, request.headers', t('درخواست بازدیدکننده؛ بدنه با await request.text()، request.json() یا request.arrayBuffer().')),
        li('request.client.ip, request.client.country', t('آی‌پی واقعی بازدیدکننده و کد دوحرفی کشور (مثل DE؛ اگر معلوم نباشد خالی).')),
        li('new Response(body, { status, headers })', t('پاسخ دلخواه؛ همچنین Response.json(data) و Response.redirect(url, 302).')),
        li('Headers, URL, URLSearchParams', t('مثل مرورگر؛ به‌همراه TextEncoder، TextDecoder، atob، btoa و setTimeout.')),
        li('fetch(url, init)', t('فقط به نشانی‌های همین سایت؛ درخواست به سرور اصلی شما می‌رود (نه کش CDN و نه تابع)، حداکثر ۸ بار در هر اجرا. دامنه‌های دیگر و اینترنت در دسترس نیستند.')),
        li('console.log()', t('خروجی دور ریخته می‌شود و جایی نمایش داده نمی‌شود.'))),
      h('h4', { className: 'pcdn-fn-h', text: t('محدودیت‌های هر اجرا') }),
      h('ul', { className: 'pcdn-ul pcdn-fn-limits' },
        li(null, t('زمان CPU: پیش‌فرض ۵۰ میلی‌ثانیه، حداکثر ۲۰۰ (برای هر تابع قابل تنظیم). کل زمان هر اجرا با انتظار fetch حداکثر ۵ ثانیه است.')),
        li(null, t('حافظه: پیش‌فرض ۳۲ مگابایت، بین ۸ و ۱۲۸ مگابایت.')),
        li(null, t('بدنهٔ درخواستی که به تابع می‌رسد حداکثر ۱ مگابایت و بدنهٔ پاسخ تابع (و هر fetch) حداکثر ۵ مگابایت است؛ بیشتر از آن، رفتار «هنگام خطا» اعمال می‌شود.')),
        li(null, t('کد هر تابع حداکثر ۲۵۶ کیلوبایت؛ تعداد توابع طبق پلن (حداکثر ۳۲).')),
        li(null, t('هر اجرا در یک محیط تازه و ایزوله است: متغیرهای سراسری بین درخواست‌ها نمی‌مانند، فایل و شبکه در دسترس نیست و import ماژول ممکن نیست.'))),
      h('h4', { className: 'pcdn-fn-h', text: t('مسیرها') }),
      h('ul', { className: 'pcdn-ul' },
        h('li', null, t('مسیر، پیشوند نشانی است: '), ltr('/api'), t(' هم '), ltr('/api/users'), t(' و هم '), ltr('/apix'), t(' را می‌گیرد؛ برای فقط یک پوشه '), ltr('/api/'), t(' بنویسید.')),
        h('li', { text: t('مسیر توابع نباید با مسیرهای تونل یکی یا پیشوند هم باشد، و وقتی تونل به مسیرهای ناشناخته decoy یا 404 می‌دهد توابع اجرا نمی‌شوند.') }),
        h('li', { text: t('هزینه: اجراها و زمان CPU در آمار این صفحه شمرده می‌شوند و ترافیک پاسخ‌ها مثل بقیهٔ ترافیک سایت از سهمیهٔ سرویس کم می‌شود.') }))]);
    return c;
  }

  // ------------------------------------------------------------------ page

  function render(Aa) {
    var wrap = h('div', { className: 'pcdn-stack pcdn-fnpage', 'data-functions': '1' }, P.skeleton(5));
    function start() {
      clear(wrap);
      wrap.appendChild(P.skeleton(5));
      // the site object has no code (SPEC §16.9): always edit what GET config/functions returns
      P.api('GET', 'config/functions').then(function (res) {
        if (S().page !== 'functions' || !document.body.contains(wrap)) return;
        clear(wrap);
        if (!res.ok || !valid(res.data)) {
          var again = P.btn(t('تلاش دوباره'), { icon: 'refresh', cls: 'pcdn-fn-retry', onclick: start });
          again.setAttribute('data-ro-ok', '1');
          append(wrap, [P.errorBox(res.ok ? { ok: false, status: 502, data: { detail: t('پاسخ نامعتبر از سرور CDN') } } : res, t('دریافت توابع ممکن نشد')), h('div', null, again)]);
          return;
        }
        Aa.setConfig('functions', res.data);
        var base = fingerprint(res.data);
        var f = Aa.sectionForm('functions', build, { serialize: serialize, validate: problems,
          savedMsg: t('توابع ذخیره شد و تا چند ثانیه روی همهٔ نودهای CDN اعمال می‌شود.'),
          onSaved: function () { base = fingerprint(site().config.functions); } });
        var save0 = f.save;
        f.save = function (button) {
          if (problems(f.draft).length) return save0(button);   // shows the problems, sends nothing
          var size = utf8Len(JSON.stringify(serialize(f.draft)));
          if (size > BODY_MAX) {
            P.toast(t('حجم کل توابع ({0}) از سقف ۹ مگابایت یک ذخیره بیشتر است؛ کد را کوچک‌تر کنید.', kb(size)), 'error');
            return Promise.resolve({ ok: false, status: 413, data: null });
          }
          // read the stored version again: someone (another window, the API) may have changed it meanwhile
          return P.busy(button, P.api('GET', 'config/functions')).then(function (cur) {
            if (!cur.ok || !cur.data || !Array.isArray(cur.data.items)) {
              P.toast(t('نسخهٔ فعلی توابع از سرور خوانده نشد؛ ذخیره انجام نشد: ') + P.errorText(cur), 'error');
              return cur;
            }
            if (fingerprint(cur.data) === base) return save0(button);
            return P.confirm({ title: t('توابع جای دیگری تغییر کرده‌اند'), danger: true, ok: t('ذخیره و جایگزینی'), cancel: t('انصراف'),
              body: t('از زمان باز شدن این صفحه، توابع این سایت جای دیگری (پنجرهٔ دیگر، کاربر دیگر یا API) تغییر کرده‌اند. با ذخیره، نسخهٔ شما جایگزین آن می‌شود؛ برای دیدن نسخهٔ تازه، تغییرات را لغو و صفحه را دوباره باز کنید.') })
              .then(function (yes) { return yes ? save0(button) : cur; });
          });
        };
        append(wrap, [f.el, statsCard(), testCard(res.data), docsCard()]);
        Aa.lockWrites(wrap);
      });
    }
    start();
    return wrap;
  }

  // ------------------------------------------------------------------ registry

  pages.functions = {
    title: t('توابع لبه'), icon: 'code', heading: t('توابع لبه (Edge Functions)'),
    desc: t('کد JavaScript خودتان را روی نودهای CDN، پیش از سرور اصلی و نزدیک به بازدیدکننده اجرا کنید: ریدایرکت، API کوچک، آزمون A/B، صفحهٔ تعمیرات و تغییر هدرها.'),
    guide: {
      what: t('هر تابع چند خط JavaScript است که برای یک مسیر سایت روی نودهای CDN در محیطی ایزوله اجرا می‌شود و می‌تواند خودش پاسخ بدهد یا درخواست را به سرور اصلی بفرستد.'),
      when: t('برای منطق کوچک و سریع که نباید منتظر سرور اصلی بماند: ریدایرکت بر اساس کشور، پاسخ API ساده، صفحهٔ تعمیرات، آزمون A/B یا افزودن هدر.'),
      rec: t('از یک الگو شروع کنید، روی مسیر آزمایشی امتحان کنید، سقف CPU را پایین نگه دارید و برای توابع حیاتی (مثل احراز هویت) «خطای ۵۰۲» را انتخاب کنید.'),
      mistakes: [t('مسیر بدون / پایانی (/api پاسخ /apix را هم می‌گیرد).'), t('انتظار نگه‌داشتن داده بین درخواست‌ها (هر اجرا محیط تازه دارد).'),
        t('fetch به دامنه‌های دیگر (فقط نشانی‌های همین سایت مجاز است).'), t('پاسخ‌های بزرگ‌تر از ۵ مگابایت از تابع (برای فایل‌ها null برگردانید).')]
    },
    upsell: t('با ارتقای پلن، می‌توانید کد JavaScript خودتان را روی نودهای CDN اجرا کنید: ریدایرکت هوشمند، API کوچک، آزمون A/B و تغییر پاسخ‌ها بدون تغییر سرور.'),
    hidden: function (s) { return !known(s); },
    lock: function (f) { return !f.edge_functions; },
    render: function (Aa) { return render(Aa); }
  };

  P.functions = {
    known: known,
    // exported for tests
    routeProblem: routeProblem, itemProblems: itemProblems, problems: problems, serialize: serialize, utf8Len: utf8Len,
    templates: templates, codeEditor: codeEditor, fingerprint: fingerprint
  };
})();
