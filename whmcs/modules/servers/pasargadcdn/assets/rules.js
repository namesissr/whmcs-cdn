/*
 * Pasargad CDN — Wave 6B (SPEC §14.2) rules & security for the client app:
 *   «قوانین تبدیل» (section `transform`), «ریدایرکت‌ها» (section `redirects`, CSV import/export),
 *   «مدیریت ربات‌ها» (section `bots`), and — used by pages.js through PCDN.sec6b at render time —
 *   the WAF «بسته‌های آماده» card (`waf.packs`), the SSL «احراز هویت مبدأ (mTLS)» card
 *   (`ssl.origin_client_auth`) and the HSTS presets (client-side, filling `ssl.hsts`).
 *
 * Everything is feature-detected like Wave 6A: a page or card only appears when the controller's
 * site payload carries its section/field, so an older controller (which rejects unknown fields
 * with 422) never receives them. Validation mirrors the controller contract; the controller still
 * has the last word and its Persian `detail` is shown next to the field or above the form.
 * Data only reaches the DOM through textContent / createElement (ui.js helpers).
 */
(function () {
  'use strict';
  var P = window.PCDN = window.PCDN || {};
  var t = P.t;  // i18n.js (SPEC §16.10)
  var pages = P.pages = P.pages || {};
  var K = P.kit;
  if (!K || !P.h) return;
  var h = P.h, append = P.append, clear = P.clear, icon = P.icon, ltr = P.ltr, clone = P.clone, num = P.num;
  var has = K.has, word = K.word;

  function A() { return P.app; }
  function site() { return P.app.S.site; }
  function domain() { return site().domain; }
  /** The controller returned this config section (feature detection for whole pages). */
  function sectionOf(s, name) { var c = s && s.config && s.config[name]; return !!c && typeof c === 'object' && !Array.isArray(c); }
  /** Plan limit from site.plan.features, or the controller default when the plan predates the key. */
  function limitOf(key, def) { var v = A().features()[key]; return typeof v === 'number' && v >= 0 ? v : def; }
  function uniq(list) { var out = []; (list || []).forEach(function (x) { if (out.indexOf(x) < 0) out.push(x); }); return out; }
  function chip(tx, cls) { return h('bdi', { className: 'pcdn-vchip' + (cls ? ' ' + cls : ''), dir: 'ltr', text: tx }); }

  // ------------------------------------------------------------------ shared validation (mirror of the controller)

  // Mirrors controller/app/sections.py (§14.2); the controller re-validates and has the last word.
  var CTRL = /[\x00-\x1f\x7f]/;                                  // control characters, CR/LF included
  var HEADER_NAME_RE = /^[A-Za-z0-9-]{1,64}$/;                    // HEADER_NAME_RE
  var HEADER_VALUE_RE = /^[\x20-\x7e]{1,1024}$/;                  // HEADER_VALUE_RE: printable ASCII, no CR/LF
  var PATH_PATTERN_RE = /^\/[A-Za-z0-9\-._~%!$&'()*+,;=:@/]*$/;   // PATH_PATTERN_RE (with * wildcards)
  var REWRITE_RE = /^\/[A-Za-z0-9\-._~%!$&'()*+,;=:@/?]*$/;       // REWRITE_RE
  var PCT_BAD_RE = /%(?![0-9A-Fa-f]{2})/;                         // PCT_BAD_RE
  var HOST_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/;
  var SOURCE_SAFE = "!&'()*+,;=:@/%", TARGET_SAFE = "!&'()*+,;=:@/?#[]%$";   // REDIRECT_SOURCE_SAFE / _TARGET_SAFE
  var REGEX_MAX_LEN = 256, REGEX_MAX_UNBOUNDED = 10;
  // TRANSFORM_RESERVED (+ prefixes): hop-by-hop / framing headers and the ones the platform relies on;
  // TRANSFORM_REMOVE_ONLY: may be removed, never set.
  var RESERVED_HEADERS = ['connection', 'keep-alive', 'transfer-encoding', 'upgrade', 'te', 'trailer', 'trailers', 'host', 'content-length',
    'x-real-ip', 'forwarded'];
  var RESERVED_PREFIXES = ['proxy-', 'x-pcdn-', 'x-forwarded-'];
  var REMOVE_ONLY = ['cookie', 'set-cookie'];
  var RESERVED_TEXT = t('Host، Content-Length، Connection، Keep-Alive، Transfer-Encoding، Upgrade، TE، Trailer(s)، X-Real-IP، Forwarded و هدرهای Proxy-*، X-Forwarded-* و X-Pcdn-*');
  var MAX_HEADER_VALUE = 1024;
  function reservedHeader(n) {
    n = String(n || '').toLowerCase();
    return RESERVED_HEADERS.indexOf(n) >= 0 || RESERVED_PREFIXES.some(function (p) { return n.indexOf(p) === 0; });
  }

  /** Compiles a (Python/PCRE-style) pattern with the browser's engine; a leading (?i) is accepted. Returns RegExp or null. */
  function compile(src) {
    var s = String(src), flags = '';
    if (s.indexOf('(?i)') === 0) { s = s.slice(4); flags = 'i'; }
    try { return new RegExp(s, flags); } catch (e) { return null; }
  }
  function groups(re) { try { return new RegExp(re.source + '|', re.flags).exec('').length - 1; } catch (e) { return 9; } }
  /** Unbounded quantifiers (*, +, {n,}) outside character classes — the controller allows at most 10. */
  function unbounded(s) {
    var n = 0, inClass = false;
    for (var i = 0; i < s.length; i++) {
      var c = s.charAt(i);
      if (c === '\\') { i++; continue; }
      if (inClass) { if (c === ']') inClass = false; continue; }
      if (c === '[') inClass = true;
      else if (c === '*' || c === '+') n++;
      else if (c === '{' && /^\{\d+,\}/.test(s.slice(i))) n++;
    }
    return n;
  }
  /** _safe_regex: required, ≤ 256, no whitespace/control characters, no (?P<…>), compiles, ≤ 10 unbounded quantifiers. */
  function regexProblem(src, what) {
    src = String(src || '');
    if (!src) return what + t(' را وارد کنید.');
    if (src.length > REGEX_MAX_LEN) return what + t(' حداکثر ') + num(REGEX_MAX_LEN) + t(' نویسه می‌تواند باشد.');
    if (CTRL.test(src) || /\s/.test(src)) return what + t(' نباید فاصله، شکست خط (CR/LF) یا نویسهٔ کنترلی داشته باشد (برای فاصله از \\s یا %20 استفاده کنید).');
    if (src.indexOf('(?P') >= 0) return t('گروه نام‌دار (?P<…>) در ') + what + t(' پشتیبانی نمی‌شود؛ از گروه معمولی (…) و $1 تا $9 استفاده کنید.');
    if (!compile(src)) return what + t(' نامعتبر است؛ پرانتزها و کروشه‌ها را بررسی کنید.');
    if (unbounded(src) > REGEX_MAX_UNBOUNDED) return what + t(' بیش از ') + num(REGEX_MAX_UNBOUNDED) + t(' کمیت‌سنج نامحدود (* یا +) دارد؛ آن را ساده کنید.');
    return null;
  }
  /** _check_refs: `$` only as $1..$9, only where allowed (regex), and not beyond the regex's groups. */
  function refsProblem(text, nGroups, allowed, what) {
    var m, r = /\$(\d?)(\d?)/g;
    while ((m = r.exec(String(text)))) {
      if (!allowed) return t('$1 تا $9 (و علامت $) فقط با نوع تطبیق «عبارت منظم» کار می‌کند.');
      if (!m[1] || m[1] === '0' || m[2]) return t('در ') + what + t(' علامت $ فقط به شکل $1 تا $9 مجاز است.');
      if (+m[1] > nGroups) return what + t(' از $') + m[1] + t(' استفاده کرده ولی عبارت منظم فقط ') + num(nGroups) + t(' گروه پرانتزی دارد.');
    }
    return null;
  }
  /** Python urllib.parse.quote(s, safe): what the controller stores for redirect sources/targets. */
  function pyQuote(s, safe) {
    return String(s).replace(/[\uD800-\uDBFF][\uDC00-\uDFFF]|[\s\S]/g, function (ch) {
      if (/^[A-Za-z0-9_.~-]$/.test(ch) || safe.indexOf(ch) >= 0) return ch;
      try { return encodeURIComponent(ch); } catch (e) { return ch; }
    });
  }

  // ------------------------------------------------------------------ transform rules

  var T_TYPES = [
    ['set_request_header', t('تنظیم هدر درخواست'), t('هدر را به درخواستی که به سرور اصلی می‌رود اضافه می‌کند (یا مقدار قبلی را جایگزین می‌کند).')],
    ['remove_request_header', t('حذف هدر درخواست'), t('هدر را پیش از رسیدن درخواست به سرور اصلی حذف می‌کند.')],
    ['set_response_header', t('تنظیم هدر پاسخ'), t('هدر را به پاسخی که بازدیدکننده می‌گیرد اضافه می‌کند (یا مقدار قبلی را جایگزین می‌کند).')],
    ['remove_response_header', t('حذف هدر پاسخ'), t('هدر را از پاسخ سرور اصلی حذف می‌کند.')],
    ['rewrite_path', t('بازنویسی مسیر'), t('مسیر درخواست پیش از ارسال به سرور اصلی تغییر می‌کند؛ آدرس در مرورگر بازدیدکننده عوض نمی‌شود.')]
  ];
  var T_FIELDS = { set_request_header: ['name', 'value'], remove_request_header: ['name'], set_response_header: ['name', 'value'],
    remove_response_header: ['name'], rewrite_path: ['regex', 'replacement'] };
  var T_TONE = { set_request_header: 'brand', remove_request_header: 'warning', set_response_header: 'brand', remove_response_header: 'warning', rewrite_path: 'violet' };
  var MAX_ACTIONS = 10;
  var POPULAR_CC = ['IR', 'DE', 'NL', 'US', 'TR', 'AE'];
  function typeInfo(tx) { for (var i = 0; i < T_TYPES.length; i++) if (T_TYPES[i][0] === tx) return T_TYPES[i]; return [tx, tx, '']; }
  function isSet(tx) { return tx === 'set_request_header' || tx === 'set_response_header'; }

  /** The rule as sent to the controller: trimmed, upper-cased lists, only the fields each action type uses. */
  function cleanTransform(r) {
    var m = r.match || {};
    var out = {
      id: r.id || P.uid('t'), enabled: r.enabled !== false,
      match: { path: String(m.path || '').trim(),
        methods: uniq((m.methods || []).map(function (x) { return String(x).trim().toUpperCase(); }).filter(Boolean)),
        countries: uniq((m.countries || []).map(function (x) { return String(x).trim().toUpperCase(); }).filter(Boolean)) },
      actions: (r.actions || []).map(function (a) {
        var tx = T_FIELDS[a.type] ? a.type : 'set_request_header', o = { type: tx };
        T_FIELDS[tx].forEach(function (k) { o[k] = typeof a[k] === 'string' ? a[k].trim() : ''; });
        return o;
      })
    };
    if (r._new) out._new = true;
    return out;
  }

  /** Client-side mirror of the controller's transform rules; returns a Persian problem or null. */
  function transformProblem(r) {
    var m = r.match || {}, p = String(m.path || '');
    if (!p) return t('مسیر را وارد کنید (برای همه مسیرها ‎/*‎ بنویسید).');
    if (p.charAt(0) !== '/') return t('مسیر باید با / شروع شود.');
    if (p.length > 512) return t('الگوی مسیر حداکثر ۵۱۲ نویسه می‌تواند باشد.');
    if (!PATH_PATTERN_RE.test(p)) return t('مسیر نویسهٔ غیرمجاز دارد؛ فاصله، کوتیشن، < > و حروف غیرلاتین را به‌صورت کدشده (%xx) بنویسید.');
    var methods = m.methods || [], countries = m.countries || [];
    for (var i = 0; i < methods.length; i++) if (K.METHODS.indexOf(methods[i]) < 0) return t('متد «') + methods[i] + t('» نامعتبر است.');
    for (i = 0; i < countries.length; i++) if (!/^[A-Z]{2}$/.test(countries[i])) return t('کد کشور «') + countries[i] + t('» نامعتبر است؛ کد دوحرفی مثل IR بنویسید.');
    var acts = r.actions || [];
    if (!acts.length) return t('دست‌کم یک اقدام لازم است.');
    if (acts.length > MAX_ACTIONS) return t('حداکثر ') + num(MAX_ACTIONS) + t(' اقدام در هر قانون مجاز است.');
    for (i = 0; i < acts.length; i++) {
      var a = acts[i], n = num(i + 1);
      if (!T_FIELDS[a.type]) return t('نوع اقدام ') + n + t(' نامعتبر است.');
      if (a.type === 'rewrite_path') {
        var src = String(a.regex || ''), rep = String(a.replacement || '');
        var rp = regexProblem(src, t('عبارت منظم اقدام ') + n);
        if (rp) return rp;
        if (!rep) return t('مسیر جدید در اقدام ') + n + t(' را وارد کنید.');
        if (rep.charAt(0) !== '/' || rep.charAt(1) === '/') return t('مسیر جدید در اقدام ') + n + t(' باید با یک / شروع شود (مثل ‎/new/$1‎).');
        if (CTRL.test(rep) || /\s/.test(rep)) return t('مسیر جدید در اقدام ') + n + t(' نباید فاصله، شکست خط (CR/LF) یا نویسهٔ کنترلی داشته باشد.');
        if (rep.length > 1024) return t('مسیر جدید در اقدام ') + n + t(' بیش از حد طولانی است (حداکثر ۱۰۲۴ نویسه).');
        if (!REWRITE_RE.test(rep)) return t('مسیر جدید در اقدام ') + n + t(' فقط نویسه‌های مجاز آدرس را می‌پذیرد (حروف غیرلاتین را به‌صورت %xx بنویسید).');
        if (PCT_BAD_RE.test(rep)) return t('کدگذاری درصدی (%XX) در مسیر جدید اقدام ') + n + t(' نامعتبر است.');
        if (rep.toLowerCase().indexOf('/__pcdn') === 0) return t('مسیرهای ‎/__pcdn‎ رزرو شده‌اند (اقدام ') + n + ').';
        var refs = refsProblem(rep, groups(compile(src)), true, t('مسیر جدید اقدام ') + n);
        if (refs) return refs;
        continue;
      }
      var name = String(a.name || '');
      if (!name) return t('نام هدر در اقدام ') + n + t(' را وارد کنید.');
      if (!HEADER_NAME_RE.test(name)) return t('نام هدر «') + name + t('» در اقدام ') + n + t(' نامعتبر است؛ فقط حروف لاتین، عدد و خط تیره (حداکثر ۶۴ نویسه).');
      if (reservedHeader(name)) return t('هدر ') + name + t(' (اقدام ') + n + t(') رزرو شده و قابل تغییر نیست. هدرهای رزرو: ') + RESERVED_TEXT + '.';
      if (isSet(a.type)) {
        var v = String(a.value || '');
        if (REMOVE_ONLY.indexOf(name.toLowerCase()) >= 0) return t('هدر ') + name + t(' (اقدام ') + n + t(') را فقط می‌توان حذف کرد، نه مقداردهی.');
        if (!v) return t('مقدار هدر در اقدام ') + n + t(' را وارد کنید (برای حذف هدر، نوع «حذف هدر» را انتخاب کنید).');
        if (CTRL.test(v)) return t('مقدار هدر در اقدام ') + n + t(' نباید شکست خط (CR/LF) یا نویسهٔ کنترلی داشته باشد.');
        if (v.length > MAX_HEADER_VALUE) return t('مقدار هدر در اقدام ') + n + t(' بیش از حد طولانی است (حداکثر ۱۰۲۴ نویسه).');
        if (!HEADER_VALUE_RE.test(v)) return t('مقدار هدر در اقدام ') + n + t(' فقط نویسه‌های چاپ‌پذیر انگلیسی (ASCII) می‌پذیرد.');
      }
    }
    return null;
  }
  function validateTransform(d) {
    var out = [], max = limitOf('max_transform_rules', 10);
    (d.rules || []).forEach(function (r, i) {
      var p = transformProblem(cleanTransform(r));
      if (p) out.push({ path: 'rules.' + i, msg: p });
    });
    if ((d.rules || []).length > max) out.push({ path: 'rules', msg: t('حداکثر ') + num(max) + t(' قانون تبدیل در پلن شما مجاز است.') });
    return out;
  }

  function tSentence(r) {
    var m = r.match || {}, out = [word(t('برای مسیر')), chip(m.path || '/*')];
    if ((m.methods || []).length) out.push(word(t('با متد')), K.chipsOf(m.methods));
    if ((m.countries || []).length) out.push(word(t('از کشور')), K.chipsOf(m.countries, { country: true }));
    out.push(word(P.arrow, 'pcdn-arrow'));
    var acts = r.actions || [];
    if (!acts.length) out.push(word(t('(بدون اقدام)'), 'pcdn-w pcdn-w-bad'));
    acts.forEach(function (a, i) {
      if (i) out.push(word(t('،'), 'pcdn-w pcdn-w-and'));
      out.push(h('span', { className: 'pcdn-act pcdn-tone-' + (T_TONE[a.type] || 'muted'), text: typeInfo(a.type)[1] }), ' ');
      if (a.type === 'rewrite_path') {
        out.push(chip(a.regex || '?'), word(P.arrow, 'pcdn-arrow'), chip(a.replacement || '?'));
      } else {
        out.push(chip(a.name || '?', 'is-key'));
        if (isSet(a.type)) out.push(word('='), a.value ? chip(a.value) : word(t('(خالی)'), 'pcdn-w pcdn-w-bad'));
      }
    });
    return out;
  }

  function countriesField(m, redraw) {
    var picks = h('div', { className: 'pcdn-chips-row pcdn-cc-picks', role: 'group', 'aria-label': t('کشورهای پرکاربرد') }, POPULAR_CC.map(function (cc) {
      var on = m.countries.indexOf(cc) >= 0;
      return h('button', { type: 'button', className: 'pcdn-chip-btn' + (on ? ' is-on' : ''), 'aria-pressed': String(on), 'data-write': '1', 'data-cc': cc,
        text: P.country(cc) + ' (' + cc + ')',
        onclick: function () {
          var at = m.countries.indexOf(cc);   // live: the tags input may have changed the list since render
          if (at >= 0) m.countries.splice(at, 1); else m.countries.push(cc);
          redraw();
        } });
    }));
    return [P.tags(m, 'countries', t('کشورها (خالی = همه کشورها)'), { upper: true, placeholder: 'IR', aria: t('کشورها'),
      help: t('کد دوحرفی کشور (ISO)؛ چند کشور را با Enter جدا کنید یا از دکمه‌های زیر انتخاب کنید.') }), picks];
  }

  function actionRow(a, list, j, redraw) {
    var info = typeInfo(a.type), header = a.type !== 'rewrite_path';
    var head = h('div', { className: 'pcdn-cond-head' },
      h('span', { className: 'pcdn-cond-no', text: num(j + 1) }),
      P.select(a, 'type', null, T_TYPES.map(function (tx) { return [tx[0], tx[1]]; }), { aria: t('نوع اقدام ') + num(j + 1), onchange: redraw }),
      P.iconBtn('up', t('انتقال اقدام ') + num(j + 1) + t(' به بالا'), function () { K.move(list, j, -1); redraw(); }, { write: true, disabled: j === 0 }),
      P.iconBtn('down', t('انتقال اقدام ') + num(j + 1) + t(' به پایین'), function () { K.move(list, j, 1); redraw(); }, { write: true, disabled: j === list.length - 1 }),
      P.iconBtn('trash', t('حذف اقدام ') + num(j + 1), function () { list.splice(j, 1); redraw(); }, { write: true, cls: 'is-danger', disabled: list.length < 2 }));
    var fields = header
      ? h('div', { className: 'pcdn-grid' },
        P.input(a, 'name', t('نام هدر'), { placeholder: a.type.indexOf('response') > 0 ? 'Access-Control-Allow-Origin' : 'X-From-CDN', maxlength: 64 }),
        isSet(a.type) ? P.input(a, 'value', t('مقدار'), { placeholder: a.type.indexOf('response') > 0 ? 'https://' + domain() : 'pasargad', maxlength: MAX_HEADER_VALUE }) : null)
      : h('div', { className: 'pcdn-grid' },
        P.input(a, 'regex', t('عبارت منظم مسیر'), { placeholder: '^/old/(.*)$', maxlength: REGEX_MAX_LEN }),
        P.input(a, 'replacement', t('مسیر جدید'), { placeholder: '/new/$1', maxlength: 1024 }));
    return h('div', { className: 'pcdn-cond pcdn-taction', 'data-action': String(j), 'data-type': a.type }, head, fields,
      h('div', { className: 'pcdn-help', text: info[2] + (header ? '' : t(' در مسیر جدید از $1 تا $9 برای گروه‌های پرانتزی عبارت منظم استفاده کنید.')) }));
  }

  function tEditor(r, done) {
    var isNew = !r;
    var x0 = r ? clone(r) : { id: P.uid('t'), enabled: true, match: { path: '/*', methods: [], countries: [] }, actions: [{ type: 'set_request_header' }] };
    x0.match = x0.match || {};
    x0.match.path = x0.match.path || '';
    x0.match.methods = Array.isArray(x0.match.methods) ? x0.match.methods : [];
    x0.match.countries = Array.isArray(x0.match.countries) ? x0.match.countries : [];
    // While editing every action carries all fields, so switching its type keeps what was typed.
    x0.actions = (x0.actions || []).map(function (a) {
      return { type: a.type, name: a.name || '', value: a.value || '', regex: a.regex || '', replacement: a.replacement || '' };
    });
    K.editDrawer(isNew ? t('قانون تبدیل جدید') : t('ویرایش قانون تبدیل'), t('روی درخواست‌هایی که با شرط‌ها منطبق‌اند، هدرها یا مسیر را تغییر دهید.'), x0, function (x, redraw) {
      var full = x.actions.length >= MAX_ACTIONS;
      return [
        h('fieldset', { className: 'pcdn-fieldset pcdn-t-match' }, h('legend', { text: t('شرط تطبیق (همه باید برقرار باشند)') }),
          P.input(x.match, 'path', t('الگوی مسیر'), { placeholder: '/api/*', maxlength: 512,
            help: h('span', null, t('با '), ltr('/'), t(' شروع کنید؛ '), ltr('*'), t(' یعنی هر چیزی. مثلاً '), ltr('/api/*'), t(' یا برای همه مسیرها '), ltr('/*'), '.') }),
          P.checks(x.match, 'methods', t('متدها (هیچ‌کدام = همه)'), K.METHODS.map(function (m) { return [m, m]; }), { ltr: true }),
          countriesField(x.match, redraw)),
        h('fieldset', { className: 'pcdn-fieldset pcdn-t-actions' }, h('legend', { text: t('اقدام‌ها (به همین ترتیب اجرا می‌شوند)') }),
          x.actions.map(function (a, j) { return actionRow(a, x.actions, j, redraw); }),
          h('div', { className: 'pcdn-row-actions' },
            P.btn(t('افزودن اقدام'), { icon: 'plus', size: 'sm', write: true, cls: 'pcdn-add-action', disabled: full,
              title: full ? t('حداکثر ') + num(MAX_ACTIONS) + t(' اقدام در هر قانون') : null,
              onclick: function () { x.actions.push({ type: 'set_request_header', name: '', value: '', regex: '', replacement: '' }); redraw(); } }),
            K.limitText(x.actions.length, MAX_ACTIONS, t('اقدام')))),
        h('p', { className: 'pcdn-help', text: t('هدرهای رزرو قابل تغییر نیستند: ') + RESERVED_TEXT + t('. نام هدر فقط حروف لاتین، عدد و خط تیره؛ مقدار بدون شکست خط.') }),
        P.toggle(x, 'enabled', t('قانون فعال باشد'))
      ];
    }, function (x) { done(cleanTransform(x)); }, function (x) { return transformProblem(cleanTransform(x)); }, function (x) { return tSentence(cleanTransform(x)); });
  }

  function tPresets(d, max) {
    var full = d.rules.length >= max ? t('به سقف قوانین تبدیل پلن رسیده‌اید') : null;
    function add(r) { r.id = P.uid('t'); r.enabled = true; r._new = true; d.rules.push(r); }
    var all = { path: '/*', methods: [], countries: [] };
    return [
      { id: 'hide', title: t('مخفی کردن هدرهای افشاگر'), icon: 'eye', desc: t('X-Powered-By و Server از پاسخ همهٔ صفحات حذف می‌شوند تا نوع و نسخهٔ نرم‌افزار سرور دیده نشود.'), disabled: full,
        apply: function () { add({ match: clone(all), actions: [{ type: 'remove_response_header', name: 'X-Powered-By' }, { type: 'remove_response_header', name: 'Server' }] }); } },
      { id: 'cors', title: t('CORS برای API'), icon: 'code', desc: t('هدر Access-Control-Allow-Origin به پاسخ مسیرهای ‎/api/*‎ اضافه می‌شود؛ دامنهٔ مجاز را ویرایش کنید.'), disabled: full,
        apply: function () { add({ match: { path: '/api/*', methods: [], countries: [] }, actions: [{ type: 'set_response_header', name: 'Access-Control-Allow-Origin', value: 'https://' + domain() }] }); } },
      { id: 'rewrite', title: t('بازنویسی مسیر قدیمی'), icon: 'swap', desc: t('درخواست‌های ‎/old/…‎ بی‌صدا از ‎/new/…‎ سرور اصلی پاسخ می‌گیرند؛ آدرس مرورگر عوض نمی‌شود.'), disabled: full,
        apply: function () { add({ match: { path: '/old/*', methods: [], countries: [] }, actions: [{ type: 'rewrite_path', regex: '^/old/(.*)$', replacement: '/new/$1' }] }); } }
    ];
  }

  function renderTransform(Aa) {
    var max = limitOf('max_transform_rules', 10);
    var f = Aa.sectionForm('transform', function (d, f2) {
      d.rules = d.rules || [];
      return [
        K.presets(t('الگوهای آماده'), t('قوانین پرکاربرد را با یک کلیک اضافه کنید؛ سپس بررسی و «ذخیره» کنید.'), tPresets(d, max), d, f2),
        K.ruleList(d, f2, {
          title: t('قوانین تبدیل'), icon: 'swap', max: max, what: t('قانون'), addLabel: t('قانون جدید'),
          subtitle: t('قوانین به ترتیب از بالا به پایین روی درخواست‌های منطبق اعمال می‌شوند.'),
          sentence: tSentence, edit: tEditor,
          empty: ['swap', t('هنوز قانون تبدیلی ندارید'), t('با قانون تبدیل می‌توانید برای مسیرها، متدها یا کشورهای خاص هدر اضافه یا حذف کنید یا مسیر درخواست را پیش از رسیدن به سرور اصلی بازنویسی کنید.')]
        })];
    }, { serialize: K.stripNew('rules'), validate: validateTransform });
    return f.el;
  }

  // ------------------------------------------------------------------ redirects

  var R_MATCH = [
    ['exact', t('دقیق'), t('فقط همین مسیر؛ مثل ‎/old-page‎.'), 'check'],
    ['prefix', t('پیشوند'), t('هر مسیری که با این مقدار شروع شود (مثل ‎/blog/‎)؛ همه به همان مقصد ثابت می‌روند.'), 'arrowLeft'],
    ['regex', t('عبارت منظم'), t('الگوی regex؛ در مقصد از $1 تا $9 استفاده کنید.'), 'code']
  ];
  var R_MATCH_WORD = { exact: t('دقیق'), prefix: t('پیشوند'), regex: 'regex' };
  var R_STATUS = [[301, t('۳۰۱ — دائمی')], [302, t('۳۰۲ — موقت')], [307, t('۳۰۷ — موقت (حفظ متد)')], [308, t('۳۰۸ — دائمی (حفظ متد)')]];
  var STATUSES = [301, 302, 307, 308];
  var MAX_SOURCE = 1024, MAX_TARGET = 2048;
  var ABS_RE = /^(https?):\/\/([^/?#]*)([\s\S]*)$/i;

  /** _url_host: lower-case, IDN → punycode (via the URL parser), keeps a valid port. */
  function normHost(hp) {
    var m = /^(.*?)(?::(\d{1,5}))?$/.exec(String(hp).trim().toLowerCase()), host = m[1];
    if (/[^\x00-\x7f]/.test(host)) { try { host = new URL('http://' + host + '/').hostname; } catch (e) { /* reported below */ } }
    return host + (m[2] !== undefined ? ':' + m[2] : '');
  }
  /** _redirect_target normalisation: scheme/host lower-cased, the rest percent-encoded like the controller. */
  function normTarget(tx) {
    if (CTRL.test(tx)) return tx;
    var m = ABS_RE.exec(tx);
    if (m) return m[1].toLowerCase() + '://' + normHost(m[2]) + pyQuote(m[3], TARGET_SAFE);
    return tx.charAt(0) === '/' && tx.charAt(1) !== '/' ? pyQuote(tx, TARGET_SAFE) : tx;
  }
  /** The rule as the controller stores it: exact/prefix sources and targets percent-encoded (spaces, Persian slugs). */
  function cleanRedirect(r) {
    var match = R_MATCH_WORD[r.match] ? r.match : 'exact', src = String(r.source || '').trim();
    if (match !== 'regex' && !CTRL.test(src) && !/[?#]/.test(src)) src = pyQuote(src, SOURCE_SAFE);
    var out = {
      id: r.id || P.uid('r'), enabled: r.enabled !== false, source: src, match: match, target: normTarget(String(r.target || '').trim()),
      status: STATUSES.indexOf(Number(r.status)) >= 0 ? Number(r.status) : 301, preserve_query: !!r.preserve_query
    };
    if (r._new) out._new = true;
    return out;
  }
  /** Client-side mirror of the controller's RedirectRule; returns a Persian problem or null. */
  function redirectProblem(r) {
    var s = r.source, tx = r.target, re = null;
    if (!s) return t('مبدأ را وارد کنید.');
    if (r.match === 'regex') {
      var rp = regexProblem(s, t('عبارت منظم مبدأ'));
      if (rp) return rp;
      re = compile(s);
    } else {
      if (CTRL.test(s)) return t('مبدأ نباید شکست خط (CR/LF) یا نویسهٔ کنترلی داشته باشد.');
      if (/[?#]/.test(s)) return t('مبدأ فقط مسیر است؛ Query String (?) و # پشتیبانی نمی‌شود.');
      if (s.charAt(0) !== '/') return t('مبدأ باید مسیری با / باشد (مثل ‎/old-page‎)؛ دامنه را ننویسید.');
      if (s.length > MAX_SOURCE) return t('مبدأ بیش از حد طولانی است (حداکثر ۱۰۲۴ نویسه).');
      if (PCT_BAD_RE.test(s)) return t('کدگذاری درصدی (%XX) در مبدأ نامعتبر است.');
    }
    if (!tx) return t('مقصد را وارد کنید.');
    if (CTRL.test(tx)) return t('مقصد نباید شکست خط (CR/LF) یا نویسهٔ کنترلی داشته باشد.');
    var m = ABS_RE.exec(tx);
    if (m) {
      var hp = /^(.*?)(?::(\d{1,5}))?$/.exec(m[2]);
      if (hp[1].indexOf('@') >= 0) return t('آدرس مقصد نباید نام کاربری/رمز (user@) داشته باشد.');
      if (!HOST_RE.test(hp[1]) || hp[1].length > 253) return t('نام میزبان مقصد نامعتبر است.');
      if (hp[2] !== undefined && !(+hp[2] >= 1 && +hp[2] <= 65535)) return t('پورت مقصد نامعتبر است.');
    } else if (tx.charAt(0) !== '/' || tx.charAt(1) === '/') {
      return t('مقصد باید مسیری با / (مثل ‎/new-page‎) یا آدرس کامل http:// یا https:// باشد.');
    }
    if (tx.length > MAX_TARGET) return t('مقصد بیش از حد طولانی است (حداکثر ۲۰۴۸ نویسه).');
    if (PCT_BAD_RE.test(tx)) return t('کدگذاری درصدی (%XX) در مقصد نامعتبر است.');
    var refs = refsProblem(tx, re ? groups(re) : 0, r.match === 'regex', t('مقصد'));
    if (refs) return refs;
    if (STATUSES.indexOf(r.status) < 0) return t('کد وضعیت باید ۳۰۱، ۳۰۲، ۳۰۷ یا ۳۰۸ باشد.');
    // loops, like the controller: a relative target that matches its own rule again
    if (tx.charAt(0) === '/') {
      var path = tx.split('?')[0].split('#')[0];
      if (r.match === 'regex' ? tx.indexOf('$') < 0 && re && re.test(path) : (r.match === 'exact' ? path === s : path.indexOf(s) === 0)) {
        return t('مقصد این ریدایرکت دوباره با همین مبدأ تطبیق می‌خورد و حلقهٔ بی‌پایان ریدایرکت می‌سازد.');
      }
    }
    return null;
  }
  function validateRedirects(d) {
    var out = [], seen = {}, max = limitOf('max_redirects', 100);
    (d.rules || []).forEach(function (r, i) {
      var c = cleanRedirect(r), p = redirectProblem(c);
      if (p) { out.push({ path: 'rules.' + i, msg: p }); return; }
      var k = c.match + ' ' + c.source;   // the controller refuses duplicates, enabled or not
      if (seen[k] !== undefined) out.push({ path: 'rules.' + i, msg: t('همین مبدأ (با همین نوع تطبیق) قبلاً در ریدایرکت ') + num(seen[k] + 1) + t(' تعریف شده است؛ هر مبدأ فقط یک بار مجاز است.') });
      else seen[k] = i;
    });
    if ((d.rules || []).length > max) out.push({ path: 'rules', msg: t('حداکثر ') + num(max) + t(' ریدایرکت در پلن شما مجاز است.') });
    return out;
  }

  function statusText(s) { for (var i = 0; i < R_STATUS.length; i++) if (R_STATUS[i][0] === Number(s)) return R_STATUS[i][1]; return String(s); }
  function rSentence(r) {
    var out = [word(t('درخواست')), chip(r.source || '?'), word('(' + (r.match === 'exact' ? t('تطبیق دقیق') : r.match === 'prefix' ? t('هر مسیر با این پیشوند') : t('عبارت منظم')) + ')'),
      word(P.arrow, 'pcdn-arrow'), h('span', { className: 'pcdn-act pcdn-tone-' + (r.status === 301 || r.status === 308 ? 'brand' : 'warning'), text: t('ریدایرکت ') + statusText(r.status) }),
      word(t(' به')), chip(r.target || '?')];
    if (r.preserve_query) out.push(word(t('با حفظ Query String')));
    return out;
  }

  function rEditor(r, done) {
    var isNew = !r;
    var x0 = r ? clone(r) : { id: P.uid('r'), enabled: true, source: '/', match: 'exact', target: '/', status: 301, preserve_query: true };
    x0.match = R_MATCH_WORD[x0.match] ? x0.match : 'exact';
    K.editDrawer(isNew ? t('ریدایرکت جدید') : t('ویرایش ریدایرکت'), t('بازدیدکننده‌ای که به مبدأ می‌آید از لبهٔ CDN به مقصد فرستاده می‌شود.'), x0, function (x, redraw) {
      var rx = x.match === 'regex';
      return [
        P.choice(x, 'match', t('نوع تطبیق'), R_MATCH, { cols: 3, onchange: redraw }),
        P.input(x, 'source', rx ? t('الگوی مبدأ (regex)') : t('مسیر مبدأ'), { placeholder: rx ? '^/blog/(.*)$' : (x.match === 'prefix' ? '/blog/' : '/old-page'), maxlength: rx ? REGEX_MAX_LEN : MAX_SOURCE,
          help: rx ? h('span', null, t('روی مسیر (بدون دامنه و Query String) اجرا می‌شود؛ '), ltr('^'), t(' و '), ltr('$'), t(' ابتدا و انتهای مسیر را مشخص می‌کنند و هر جفت پرانتز یک گروه '), ltr('$1'), t('، '), ltr('$2'), t(' و … می‌سازد.'))
            : h('span', null, t('فقط مسیر، بدون دامنه و بدون Query String؛ با '), ltr('/'), t(' شروع کنید. فاصله و حروف فارسی خودکار کدگذاری (%xx) می‌شوند.')) }),
        P.input(x, 'target', t('مقصد'), { placeholder: rx ? '/news/$1' : 'https://' + domain() + '/new-page', maxlength: MAX_TARGET,
          help: h('span', null, t('مسیری مثل '), ltr('/new-page'), t(' یا آدرس کامل '), ltr('https://example.com/page'), t('. فاصله و حروف فارسی خودکار کدگذاری (%xx) می‌شوند.')) }),
        h('div', { className: 'pcdn-grid' },
          P.select(x, 'status', t('کد وضعیت'), R_STATUS, { help: t('۳۰۱ و ۳۰۸ دائمی‌اند و مرورگرها و موتورهای جستجو آن را به خاطر می‌سپارند؛ برای آزمایش از ۳۰۲ یا ۳۰۷ استفاده کنید. ۳۰۷ و ۳۰۸ متد (مثلاً POST فرم) را حفظ می‌کنند.') })),
        P.toggle(x, 'preserve_query', t('حفظ Query String'), { help: t('اگر روشن باشد پارامترهای آدرس اصلی (مثل ‎?utm_source=…‎) به مقصد منتقل می‌شوند.') }),
        P.toggle(x, 'enabled', t('ریدایرکت فعال باشد'))
      ];
    }, function (x) { done(cleanRedirect(x)); }, function (x) { return redirectProblem(cleanRedirect(x)); }, function (x) { return rSentence(cleanRedirect(x)); });
  }

  function rPresets(d, max) {
    var full = d.rules.length >= max ? t('به سقف ریدایرکت‌های پلن رسیده‌اید') : null;
    function add(r) { r.id = P.uid('r'); r.enabled = true; r.status = 301; r.preserve_query = true; r._new = true; d.rules.push(r); }
    return [
      { id: 'page', title: t('انتقال یک صفحهٔ قدیمی'), icon: 'redirect', desc: t('ریدایرکت دائمی (۳۰۱) ‎/old-page‎ به ‎/new-page‎؛ آدرس‌ها را ویرایش کنید.'), disabled: full,
        apply: function () { add({ source: '/old-page', match: 'exact', target: '/new-page' }); } },
      { id: 'folder', title: t('انتقال یک پوشه'), icon: 'arrowLeft', desc: t('همهٔ آدرس‌های ‎/blog/…‎ با همان ادامهٔ مسیر به ‎/news/…‎ منتقل می‌شوند.'), disabled: full,
        apply: function () { add({ source: '^/blog/(.*)$', match: 'regex', target: '/news/$1' }); } },
      { id: 'domain', title: t('انتقال کل سایت به دامنهٔ جدید'), icon: 'globe', desc: t('هر آدرس با همان مسیر به دامنهٔ جدید می‌رود؛ دامنهٔ مقصد را ویرایش کنید.'), disabled: full,
        apply: function () { add({ source: '^/(.*)$', match: 'regex', target: 'https://new-domain.ir/$1' }); } }
    ];
  }

  var rState = { q: '' };
  function redirectsCard(d, f2, max) {
    var arr = d.rules, full = arr.length >= max;
    var add = P.btn(t('ریدایرکت جدید'), { kind: 'primary', icon: 'plus', size: 'sm', write: true, cls: 'pcdn-add-rule pcdn-add-redirect', disabled: full,
      title: full ? t('به سقف ') + num(max) + t(' ریدایرکت پلن رسیده‌اید') : null,
      onclick: function () { rEditor(null, function (r) { r._new = true; arr.push(r); f2.redraw(); }); } });
    var c = P.card({ title: t('ریدایرکت‌ها'), icon: 'redirect', id: 'rules', subtitle: t('قوانین از بالا به پایین بررسی می‌شوند و اولین قانون منطبق اجرا می‌شود.'),
      actions: [K.limitText(arr.length, max, t('ریدایرکت')), add] });
    if (!arr.length) {
      c.body.appendChild(P.empty('redirect', t('هنوز ریدایرکتی ندارید'), t('آدرس‌های قدیمی را بدون رسیدن درخواست به سرور اصلی به آدرس جدید بفرستید؛ یکی‌یکی بسازید، از الگوهای آماده شروع کنید یا فهرست کامل را از فایل CSV وارد کنید.')));
      return c;
    }
    var tbody = h('tbody');
    arr.forEach(function (r, i) {
      var n = num(i + 1);
      var src = h('td', { className: 'pcdn-rd-src', 'data-label': t('مبدأ') },
        h('div', { className: 'pcdn-rd-srcline' }, chip(r.source || ''), P.badge(R_MATCH_WORD[r.match] || r.match, r.match === 'regex' ? 'violet' : r.match === 'prefix' ? 'brand' : 'muted'),
          r._new ? P.badge(t('ذخیره نشده'), 'warning') : null));
      P.reg('rules.' + i, src);
      tbody.appendChild(h('tr', { className: 'pcdn-rd-row' + (r.enabled === false ? ' is-off' : '') + (r._new ? ' is-new' : ''), 'data-rule': r.id || String(i),
        'data-q': P.norm((r.source || '') + ' ' + (r.target || '')) },
        h('td', { className: 'pcdn-rd-no', text: n }),
        src,
        h('td', { className: 'pcdn-rd-target', 'data-label': t('مقصد') }, chip(r.target || '')),
        h('td', { className: 'pcdn-rd-status', 'data-label': t('کد') }, h('span', { className: 'pcdn-pill pcdn-tone-' + (r.status === 301 || r.status === 308 ? 'brand' : 'warning'), text: num(r.status) })),
        h('td', { className: 'pcdn-rd-query', 'data-label': 'Query String', text: r.preserve_query ? t('حفظ') : '—' }),
        h('td', { className: 'pcdn-rd-on' }, P.switchInput(r.enabled !== false, (r.enabled === false ? t('فعال کردن') : t('غیرفعال کردن')) + t(' ریدایرکت ') + n,
          function (v) { r.enabled = v; f2.redraw(); }, { write: true, small: true })),
        h('td', { className: 'pcdn-rd-ctl' }, h('div', { className: 'pcdn-row-btns' },
          P.iconBtn('up', t('انتقال ریدایرکت ') + n + t(' به بالا'), function () { K.move(arr, i, -1); f2.redraw(); }, { write: true, disabled: i === 0, cls: 'pcdn-rd-move' }),
          P.iconBtn('down', t('انتقال ریدایرکت ') + n + t(' به پایین'), function () { K.move(arr, i, 1); f2.redraw(); }, { write: true, disabled: i === arr.length - 1, cls: 'pcdn-rd-move' }),
          P.iconBtn('edit', t('ویرایش ریدایرکت ') + n, function () { rEditor(r, function (nr) { if (r._new) nr._new = true; arr[i] = nr; f2.redraw(); }); }, { write: true }),
          P.iconBtn('trash', t('حذف ریدایرکت ') + n, function () { arr.splice(i, 1); f2.redraw(); P.toast(t('ریدایرکت از فهرست حذف شد؛ برای اعمال «ذخیره» را بزنید.'), 'info'); }, { write: true, cls: 'is-danger' })))));
    });
    var table = h('table', { className: 'pcdn-table pcdn-rd-table' },
      h('caption', { className: 'pcdn-sr', text: t('ریدایرکت‌ها') }),
      h('thead', null, h('tr', null, ['#', t('مبدأ'), t('مقصد'), t('کد'), 'Query String', t('فعال'), t('عملیات')].map(function (tx) { return h('th', { scope: 'col', text: tx }); }))),
      tbody);
    var count = h('span', { className: 'pcdn-muted pcdn-rd-count', 'aria-live': 'polite' });
    function applyFilter() {
      var q = P.norm(rState.q.trim()), n = 0;
      Array.prototype.forEach.call(tbody.children, function (tr) {
        var ok = !q || tr.getAttribute('data-q').indexOf(q) >= 0;
        tr.hidden = !ok;
        if (ok) n++;
      });
      table.classList.toggle('is-filtering', !!q);
      count.textContent = q ? num(n) + t(' مورد از ') + num(arr.length) + t(' (جابه‌جایی هنگام جستجو غیرفعال است)') : '';
    }
    var search = arr.length > 8 ? h('div', { className: 'pcdn-toolbar pcdn-rd-toolbar' },
      h('div', { className: 'pcdn-search' }, icon('search'),
        h('input', { type: 'search', className: 'pcdn-input pcdn-rd-search', placeholder: t('جستجو در مبدأ یا مقصد…'), 'aria-label': t('جستجوی ریدایرکت‌ها'), value: rState.q, 'data-ro-ok': '1',
          oninput: function (e) { rState.q = e.target.value; applyFilter(); } })), count) : null;
    if (!search) rState.q = '';
    append(c.body, [search, h('div', { className: 'pcdn-table-wrap' }, table)]);
    applyFilter();
    return c;
  }

  // CSV import / export. Column order of the export (and of the import help) — the controller parses the import.
  var CSV_COLS = ['source', 'target', 'status', 'match', 'preserve_query', 'enabled'];
  var CSV_FIELD = { source: t('مبدأ'), target: t('مقصد'), status: t('کد وضعیت'), match: t('نوع تطبیق'), preserve_query: t('حفظ Query String'), enabled: t('فعال') };
  var MAX_CSV = 200 * 1024;   // stays under the proxy's 256 KB body limit once JSON-encoded
  function csvCell(v) { v = String(v === null || v === undefined ? '' : v); return /[",\r\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }
  function toCsv(rules) {
    return [CSV_COLS.join(',')].concat((rules || []).map(function (r) {
      return [r.source, r.target, r.status, r.match, r.preserve_query ? 'true' : 'false', r.enabled === false ? 'false' : 'true'].map(csvCell).join(',');
    })).join('\r\n') + '\r\n';
  }
  /** Data rows in pasted CSV (non-empty lines, an optional header line not counted). */
  function csvRows(text) {
    var lines = String(text || '').split(/\r?\n/).filter(function (l) { l = l.trim(); return l !== '' && l.charAt(0) !== '#'; });
    if (lines.length && /^\s*"?source"?\s*[,;]/i.test(lines[0])) lines.shift();
    return lines.length;
  }
  /**
   * Per-row errors of a 422 from POST redirects/import. The controller sends
   * detail: [{loc: ["csv", line], line, msg}] (line = 1-based CSV line, 0 = the whole file); also accepted:
   * detail string | [{row|line, field|column, msg|message|error}] | [{loc:[…, <index>, <field>], msg}] | {message, errors:[…]},
   * or a top-level errors/rows list. `row`/`line` are shown as sent; a loc index without row/line is 0-based (+1).
   */
  function csvErrors(data) {
    var d = data && typeof data === 'object' ? data : {}, rows = [];
    function add(x) {
      if (typeof x === 'string') { rows.push({ row: null, field: '', msg: x }); return; }
      if (!x || typeof x !== 'object') return;
      var loc = Array.isArray(x.loc) ? x.loc : [];
      var row = x.row !== undefined && x.row !== null ? x.row : (x.line !== undefined && x.line !== null ? x.line : null);
      if (row === null) { var nums = loc.filter(function (v) { return typeof v === 'number'; }); if (nums.length) row = nums[0] + 1; }
      var strs = loc.filter(function (v) { return typeof v === 'string' && ['body', 'csv', 'rules', 'rows'].indexOf(v) < 0; });
      rows.push({ row: row, field: String(x.field || x.column || strs[strs.length - 1] || ''), msg: String(x.msg || x.message || x.error || x.reason || x.detail || '') });
    }
    var det = d.detail;
    [d.errors, d.rows, Array.isArray(det) ? det : null, det && typeof det === 'object' && !Array.isArray(det) ? det.errors : null]
      .forEach(function (list) { if (Array.isArray(list)) list.forEach(add); });
    var summary = typeof det === 'string' ? det : (det && typeof det === 'object' && typeof det.message === 'string' ? det.message : (typeof d.message === 'string' ? d.message : ''));
    return { summary: summary, rows: rows };
  }
  function csvErrorBox(res) {
    var e = csvErrors(res.data);
    if (!e.rows.length) return P.errorBox(res, t('ورود ریدایرکت‌ها انجام نشد'));
    var shown = e.rows.slice(0, 100), withField = shown.some(function (x) { return !!x.field; });
    return h('div', { className: 'pcdn-alert pcdn-alert-danger pcdn-csv-errors', role: 'alert' }, icon('xCircle'),
      h('div', { className: 'pcdn-alert-body' },
        h('strong', { text: t('ورود ریدایرکت‌ها انجام نشد؛ ') + num(e.rows.length) + t(' خطا در CSV. ردیف‌های زیر را اصلاح کنید و دوباره وارد کنید.') }),
        e.summary ? h('div', { text: e.summary }) : null,
        h('div', { className: 'pcdn-table-wrap pcdn-csv-errtable' }, h('table', { className: 'pcdn-table' },
          h('caption', { className: 'pcdn-sr', text: t('خطاهای ردیف‌های CSV') }),
          h('thead', null, h('tr', null, (withField ? [t('ردیف'), t('ستون'), t('خطا')] : [t('ردیف'), t('خطا')]).map(function (tx) { return h('th', { scope: 'col', text: tx }); }))),
          h('tbody', null, shown.map(function (x) {
            // row 0 = an error about the whole file (e.g. too large)
            var rn = x.row === null || Number(x.row) === 0 ? '—' : (isFinite(Number(x.row)) ? num(x.row) : String(x.row));
            return h('tr', { 'data-row': x.row === null ? '' : String(x.row) }, h('td', { text: rn }),
              withField ? h('td', { text: x.field ? (CSV_FIELD[x.field] || x.field) : '—' }) : null, h('td', { text: x.msg }));
          })))),
        e.rows.length > shown.length ? h('p', { className: 'pcdn-muted', text: t('و ') + num(e.rows.length - shown.length) + t(' خطای دیگر.') }) : null));
  }

  /** Saves text as a file through a temporary object URL. */
  function download(name, text, type) {
    if (!window.Blob || !window.URL || !URL.createObjectURL) return false;
    var url = URL.createObjectURL(new Blob([text], { type: type }));
    var a = h('a', { href: url, download: name, className: 'pcdn-offscreen' });
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { if (a.parentNode) a.parentNode.removeChild(a); URL.revokeObjectURL(url); }, 4000);
    return true;
  }
  /** Reads the picked file as UTF-8 text (BOM dropped). */
  function readFile(inp, max, done, fail) {
    var file = inp.files && inp.files[0];
    if (!file) return;
    if (file.size > max) { fail(t('حجم فایل بیش از حد مجاز است (حداکثر ') + P.bytes(max) + ').'); inp.value = ''; return; }
    if (!window.FileReader) { fail(t('مرورگر شما خواندن فایل را پشتیبانی نمی‌کند؛ محتوا را در کادر بچسبانید.')); return; }
    var rd = new FileReader();
    rd.onload = function () { inp.value = ''; done(String(rd.result || '').replace(/^﻿/, '')); };
    rd.onerror = function () { inp.value = ''; fail(t('خواندن فایل ممکن نشد.')); };
    rd.readAsText(file);
  }
  function fileButton(label, accept, cls, onText, onError) {
    var inp = h('input', { type: 'file', accept: accept, className: 'pcdn-file-input', 'aria-label': label,
      onchange: function () { readFile(inp, MAX_CSV, onText, onError); } });
    return h('label', { className: 'pcdn-btn pcdn-btn-sm pcdn-file-btn' + (cls ? ' ' + cls : '') }, inp, icon('upload'), h('span', { text: label }));
  }

  function csvCard(Aa, form) {
    var c = P.collapsible({ title: t('ورود و خروج CSV'), icon: 'upload', tone: 'muted', id: 'csv',
      subtitle: t('افزودن یا جایگزینی یکجای ریدایرکت‌ها از فایل CSV و تهیهٔ نسخهٔ پشتیبان'), open: P.store('rd-csv') === '1', onOpen: function () { P.store('rd-csv', '1'); } });
    var st = { csv: '', mode: 'append' };
    var result = h('div', { className: 'pcdn-csv-result' });
    var count = h('span', { className: 'pcdn-limit pcdn-csv-count', hidden: true });
    function upd() { var n = csvRows(st.csv); count.textContent = num(n) + t(' ردیف'); count.hidden = !n; }
    var ta = h('textarea', { className: 'pcdn-input pcdn-mono pcdn-csv-input', dir: 'ltr', rows: 6, spellcheck: 'false', 'aria-label': t('محتوای CSV'),
      placeholder: 'source,target,status,match,preserve_query,enabled\n/old-page,/new-page,301,exact,true,true', oninput: function (e) { st.csv = e.target.value; upd(); } });
    var pick = fileButton(t('انتخاب فایل CSV'), '.csv,text/csv,text/plain', 'pcdn-csv-file', function (text) { st.csv = text; ta.value = text; upd(); clear(result); },
      function (msg) { clear(result); result.appendChild(P.alertBox('danger', msg)); });
    var imp = P.btn(t('ورود ریدایرکت‌ها'), { kind: 'primary', icon: 'upload', size: 'sm', write: true, cls: 'pcdn-csv-import', onclick: function () {
      clear(result);
      if (form.dirty()) { result.appendChild(P.alertBox('warning', t('فهرست ریدایرکت‌ها تغییر ذخیره‌نشده دارد؛ ابتدا آن را ذخیره یا لغو کنید و سپس CSV را وارد کنید.'))); return; }
      if (!st.csv.trim()) { result.appendChild(P.alertBox('warning', t('ابتدا محتوای CSV را بچسبانید یا فایل آن را انتخاب کنید.'))); return; }
      if (st.csv.length > MAX_CSV) { result.appendChild(P.alertBox('warning', t('محتوای CSV بیش از حد بزرگ است (حداکثر ') + P.bytes(MAX_CSV) + t(')؛ آن را در چند بخش وارد کنید.'))); return; }
      var current = (Aa.config('redirects').rules || []).length;
      var pre = st.mode === 'replace' ? P.confirm({ title: t('جایگزینی همهٔ ریدایرکت‌ها'), danger: true, ok: t('حذف و جایگزینی'),
        body: t('همهٔ ') + num(current) + t(' ریدایرکت فعلی حذف و ردیف‌های CSV جایگزین آن‌ها می‌شوند. اگر ریدایرکتی در فایل نباشد، از دست می‌رود.') }) : Promise.resolve(true);
      pre.then(function (ok) {
        if (!ok) return;
        P.busy(imp, P.api('POST', 'redirects/import', { csv: st.csv, mode: st.mode })).then(function (res) {
          if (!res.ok) { result.appendChild(res.status === 422 ? csvErrorBox(res) : P.errorBox(res, t('ورود ریدایرکت‌ها انجام نشد'))); return; }
          var d = res.data || {}, n = typeof d.imported === 'number' ? d.imported : csvRows(st.csv);
          var fresh = Array.isArray(d.rules) ? Promise.resolve({ ok: true, data: d }) : P.api('GET', 'config/redirects');
          fresh.then(function (r2) {
            if (r2.ok && r2.data && Array.isArray(r2.data.rules)) {
              Aa.setConfig('redirects', { rules: r2.data.rules });
              if (Aa.S.form === form && !form.dirty()) { form.load(); form.redraw(); }
            }
            st.csv = ''; ta.value = ''; upd();
            P.toast(num(n) + t(' ریدایرکت وارد شد.'));
            result.appendChild(P.alertBox('success', num(n) + t(' ریدایرکت ') + (st.mode === 'replace' ? t('جایگزین فهرست قبلی شد') : t('به انتهای فهرست اضافه شد')) + t(' و تا چند ثانیه روی همهٔ سرورها اعمال می‌شود.')));
          });
        });
      });
    } });
    var exp = P.btn(t('خروجی CSV'), { icon: 'download', size: 'sm', cls: 'pcdn-csv-export', onclick: function () {
      var rules = Aa.config('redirects').rules || [];
      if (!rules.length) { P.toast(t('هنوز ریدایرکت ذخیره‌شده‌ای ندارید.'), 'warn'); return; }
      if (download(domain() + '-redirects.csv', toCsv(rules), 'text/csv;charset=utf-8')) P.toast(num(rules.length) + t(' ریدایرکت در فایل CSV ذخیره شد.'));
      else P.toast(t('مرورگر شما ساخت فایل را پشتیبانی نمی‌کند.'), 'error');
    } });
    exp.setAttribute('data-ro-ok', '1');
    append(c.body, [
      h('p', { className: 'pcdn-help' }, t('هر ردیف یک ریدایرکت است با ستون‌های '), ltr(CSV_COLS.join(',')),
        t(' (مبدأ، مقصد، کد ۳۰۱/۳۰۲/۳۰۷/۳۰۸، نوع تطبیق exact/prefix/regex، حفظ Query String و فعال بودن با true/false). ردیف عنوان اختیاری است و مقدار دارای کاما را داخل "…" بگذارید. ساده‌ترین راه: «خروجی CSV» بگیرید، ویرایش کنید و دوباره وارد کنید.')),
      P.field(t('محتوای CSV'), ta, { hint: null }),
      h('div', { className: 'pcdn-row-actions' }, pick, count),
      P.choice(st, 'mode', t('روش ورود'), [
        ['append', t('افزودن به انتهای فهرست'), t('ریدایرکت‌های فعلی می‌مانند و ردیف‌های CSV پس از آن‌ها اضافه می‌شوند.'), 'plus'],
        ['replace', t('جایگزینی کامل'), t('همهٔ ریدایرکت‌های فعلی حذف و ردیف‌های CSV جایگزین می‌شوند.'), 'refresh']], { cols: 2 }),
      h('p', { className: 'pcdn-help', text: t('اگر ردیفی خطا داشته باشد، خطای هر ردیف همین‌جا نمایش داده می‌شود. خروجی فقط ریدایرکت‌های ذخیره‌شده را شامل می‌شود.') }),
      h('div', { className: 'pcdn-row-actions' }, imp, exp), result]);
    return c;
  }

  function renderRedirects(Aa) {
    var max = limitOf('max_redirects', 100);
    var f = Aa.sectionForm('redirects', function (d, f2) {
      d.rules = d.rules || [];
      return [K.presets(t('الگوهای آماده'), t('ریدایرکت‌های پرکاربرد را با یک کلیک اضافه کنید؛ سپس آدرس‌ها را ویرایش و «ذخیره» کنید.'), rPresets(d, max), d, f2),
        redirectsCard(d, f2, max)];
    }, { serialize: K.stripNew('rules'), validate: validateRedirects });
    return [f.el, csvCard(Aa, f)];
  }

  // ------------------------------------------------------------------ bot management

  var BOT_MODES = [
    ['off', t('خاموش'), t('ربات‌ها جداگانه بررسی نمی‌شوند.'), 'power'],
    ['log', t('فقط ثبت'), t('ربات‌های تأییدنشده شناسایی و در رویدادهای امنیتی ثبت می‌شوند ولی مسدود نمی‌شوند. برای شروع و بررسی.'), 'eye'],
    ['challenge', t('چالش'), t('ربات‌های تأییدنشده یک چالش JS می‌بینند؛ مرورگرهای واقعی خودکار عبور می‌کنند.'), 'shieldCheck', t('پیشنهادی')],
    ['block', t('مسدودسازی'), t('ربات‌های تأییدنشده با خطای ۴۰۳ مسدود می‌شوند.'), 'ban']
  ];
  function validateBots(d) {
    var out = [];
    if (BOT_MODES.map(function (m) { return m[0]; }).indexOf(d.mode) < 0) out.push({ path: 'mode', msg: t('حالت مدیریت ربات‌ها نامعتبر است.') });
    return out;
  }
  function renderBots(Aa) {
    var f = Aa.sectionForm('bots', function (d, f2) {
      var mode = P.card({ title: t('حالت'), icon: 'bot', id: 'mode', subtitle: t('با ربات‌های خودکاری که موتور جستجوی تأییدشده نیستند چه شود؟') });
      append(mode.body, [
        P.choice(d, 'mode', null, BOT_MODES, { cols: 2, onchange: f2.redraw }),
        d.mode === 'log' ? P.alertBox('info', [t('در حالت «فقط ثبت» چیزی مسدود نمی‌شود. چند روز '), Aa.goLink('events', t('رویدادهای امنیتی')), t(' را بررسی کنید و سپس «چالش» را انتخاب کنید.')]) : null,
        d.mode === 'block' ? P.alertBox('warning', t('ابزارهای مانیتورینگ، وب‌هوک‌های درگاه پرداخت و اپلیکیشن‌هایی که با کتابخانه‌هایی مثل curl یا python-requests درخواست می‌فرستند هم ممکن است مسدود شوند. اگر سایت API یا وب‌هوک دارد، پیش از این حالت چند روز «فقط ثبت» را امتحان کنید.')) : null]);
      var opts = P.card({ title: t('گزینه‌ها'), icon: 'sliders', id: 'options' });
      append(opts.body, [
        has(d, 'allow_verified') ? P.toggle(d, 'allow_verified', t('اجازه به ربات‌های تأییدشدهٔ موتورهای جستجو'), { cls: 'pcdn-bots-verified', onchange: f2.redraw,
          help: t('گوگل، بینگ، یاندکس و دیگر موتورهای جستجوی بزرگ فقط وقتی «تأییدشده» حساب می‌شوند که هم آی‌پی در بازه‌های منتشرشدهٔ آن‌ها باشد (روزانه به‌روز می‌شود) و هم User-Agent بخواند؛ پس ربات جعلی با User-Agent «Googlebot» عبور نمی‌کند.') }) : null,
        d.allow_verified === false && d.mode !== 'off' && d.mode !== 'log' ? P.alertBox('warning', t('موتورهای جستجو هم مثل بقیهٔ ربات‌ها چالش می‌بینند یا مسدود می‌شوند و سایت از نتایج جستجو حذف یا افت رتبه پیدا می‌کند.')) : null,
        has(d, 'block_empty_ua') ? P.toggle(d, 'block_empty_ua', t('مسدود کردن درخواست‌های بدون User-Agent'), { cls: 'pcdn-bots-emptyua',
          help: t('مرورگرهای واقعی همیشه User-Agent می‌فرستند؛ درخواستی که آن را ندارد تقریباً همیشه از اسکریپت یا ابزار اسکن است.') }) : null]);
      var how = P.card({ title: t('چطور کار می‌کند؟'), icon: 'info', tone: 'muted', id: 'how' });
      append(how.body, h('ul', { className: 'pcdn-ul' },
        h('li', { text: t('ربات‌های تأییدشده (موتورهای جستجو) با تطبیق آی‌پی منتشرشده و User-Agent شناسایی می‌شوند و اگر گزینهٔ بالا روشن باشد بدون بررسی عبور می‌کنند.') }),
        h('li', { text: t('نشانه‌های اتوماسیون تأییدنشده — User-Agent خالی یا متعلق به کتابخانه‌ها (curl، python-requests، Go-http-client و …) و نشانه‌های مرورگر بی‌سر (Headless) — طبق «حالت» بالا رفتار می‌شوند.') }),
        h('li', null, t('هر تصمیم در '), Aa.goLink('events', t('رویدادهای امنیتی')), t(' ثبت می‌شود.'))));
      return [mode, opts, how];
    }, { validate: validateBots });
    return f.el;
  }

  // ------------------------------------------------------------------ WAF managed packs (card on the WAF page)

  var WAF_PACKS = [
    ['generic', t('عمومی'), t('قوانین پایه برای همهٔ سایت‌ها: جستجوی فایل‌های حساس (‎.env، ‎.git، فایل‌های پشتیبان)، ابزارهای اسکن و الگوهای رایج سوءاستفاده.')],
    ['wordpress', t('وردپرس'), t('محافظت از wp-login.php و xmlrpc.php، شناسایی کاربران از REST API و حملات شناخته‌شده به افزونه‌ها و پوسته‌ها.')],
    ['joomla', t('جوملا'), t('حملات رایج به پنل administrator، کامپوننت‌های آسیب‌پذیر شناخته‌شده و فایل configuration.php.')],
    ['drupal', t('دروپال'), t('الگوهای Drupalgeddon، تزریق در فرم‌ها و دسترسی به فایل‌های حساس هسته.')],
    ['laravel', t('لاراول'), t('دسترسی به ‎.env، صفحهٔ دیباگ (Ignition)، پوشهٔ storage و فایل‌های لاگ.')],
    ['api', 'API', t('بدنهٔ JSON/XML نامعتبر، تزریق در پارامترهای API و متدهای غیرمعمول؛ برای سایت‌ها و اپلیکیشن‌هایی که API دارند.')]
  ];
  var PACK_IDS = WAF_PACKS.map(function (p) { return p[0]; });
  function wafPacks(d, f2, Aa) {
    if (!has(d, 'packs')) return null;
    if (!Array.isArray(d.packs)) d.packs = [];
    var c = P.card({ title: t('بسته‌های آماده'), icon: 'package', id: 'packs', subtitle: t('مجموعه‌قوانین ویژهٔ هر نرم‌افزار؛ فقط بسته‌هایی را روشن کنید که سایت شما واقعاً از آن‌ها استفاده می‌کند.') });
    var grid = h('div', { className: 'pcdn-packs', role: 'group', 'aria-label': t('بسته‌های آماده WAF') }, WAF_PACKS.map(function (p) {
      var id = P.uid('pcdn-pk-'), on = d.packs.indexOf(p[0]) >= 0;
      return h('label', { className: 'pcdn-pack' + (on ? ' is-on' : ''), 'for': id, 'data-pack': p[0] },
        h('input', { type: 'checkbox', id: id, checked: on, onchange: function (e) {
          var rest = d.packs.filter(function (x) { return x !== p[0]; });
          if (e.target.checked) rest.push(p[0]);
          d.packs.length = 0;
          Array.prototype.push.apply(d.packs, rest);
          f2.redraw();
        } }),
        h('span', { className: 'pcdn-pack-text' },
          h('span', { className: 'pcdn-pack-title' }, h('span', { text: p[1] }), h('bdi', { className: 'pcdn-pack-id', dir: 'ltr', text: p[0] })),
          h('span', { className: 'pcdn-pack-desc', text: p[2] })));
    }));
    append(c.body, [P.field(null, grid, { path: P.pathOf(d, 'packs') }),
      d.mode === 'off' && d.packs.length ? P.alertBox('info', t('WAF خاموش است؛ بسته‌ها پس از انتخاب «فقط ثبت» یا «مسدودسازی» در «حالت کار» اعمال می‌شوند.')) : null,
      h('p', { className: 'pcdn-help' }, t('هر بسته نسخه‌بندی می‌شود و شناسهٔ قوانینش ثابت است؛ «حالت کار» (فقط ثبت / مسدودسازی) و «استثناها»ی همین صفحه روی بسته‌ها هم اعمال می‌شود. شناسهٔ قانون هر مسدودسازی را در '),
        Aa.goLink('events', t('رویدادهای امنیتی')), t(' ببینید.'))]);
    return c;
  }
  function validateWaf(d) {
    if (!has(d, 'packs')) return [];
    var bad = (d.packs || []).filter(function (x) { return PACK_IDS.indexOf(x) < 0; });
    return bad.length ? [{ path: 'packs', msg: t('بستهٔ ناشناخته: ') + bad.join(t('، ')) }] : [];
  }

  // ------------------------------------------------------------------ SSL: HSTS presets + authenticated origin pulls

  var HSTS_MAX = 63072000, YEAR = 31536000;
  var HSTS_PRESETS = [
    { id: 'basic', title: t('پایه'), icon: 'lock', desc: t('max-age شش ماه، بدون زیردامنه‌ها و preload؛ شروع امن برای اغلب سایت‌ها.'),
      v: { enabled: true, max_age: 15552000, include_subdomains: false, preload: false } },
    { id: 'strict', title: t('سخت‌گیرانه'), icon: 'shieldCheck', desc: t('max-age یک سال و شامل همهٔ زیردامنه‌ها؛ فقط وقتی همهٔ زیردامنه‌ها HTTPS دارند.'),
      v: { enabled: true, max_age: YEAR, include_subdomains: true, preload: false } },
    { id: 'preload', title: t('آماده preload'), icon: 'shieldBolt', desc: t('max-age دو سال، زیردامنه‌ها و preload به‌همراه انتقال خودکار به HTTPS؛ شرایط ثبت در فهرست preload مرورگرها.'),
      v: { enabled: true, max_age: HSTS_MAX, include_subdomains: true, preload: true }, https: true }
  ];
  function sameHsts(a, v) { return Object.keys(v).every(function (k) { return a[k] === v[k]; }); }
  function hstsPresets(d, f2) {
    d.hsts = d.hsts || { enabled: false, max_age: YEAR, include_subdomains: false, preload: false };
    var row = h('div', { className: 'pcdn-presets pcdn-hsts-presets', 'data-n': '3' }, HSTS_PRESETS.map(function (p) {
      var act = sameHsts(d.hsts, p.v) && (!p.https || d.force_https === true);
      return h('button', { type: 'button', className: 'pcdn-preset' + (act ? ' is-active' : ''), 'data-hsts-preset': p.id, 'data-write': '1', 'aria-pressed': String(act),
        onclick: function () {
          var go = p.id !== 'preload' ? Promise.resolve(true) : P.confirm({ title: t('HSTS آماده preload'), danger: true, ok: t('می‌دانم، اعمال شود'), cancel: t('انصراف'),
            body: h('div', null,
              h('p', { text: t('با preload، دامنه پس از ثبت در hstspreload.org در فهرست داخلی مرورگرها (Chrome، Firefox، Safari و …) قرار می‌گیرد و مرورگرها فقط با HTTPS به این دامنه و همهٔ زیردامنه‌هایش وصل می‌شوند.') }),
              h('p', { className: 'pcdn-warn-text', text: t('برگرداندن آن بسیار دشوار است: خروج از فهرست ماه‌ها طول می‌کشد و در این مدت هر زیردامنهٔ بدون HTTPS (مثلاً پنل‌های داخلی یا سرویس‌های قدیمی) از دسترس خارج می‌شود.') }),
              h('p', { text: t('این الگو HSTS را دو ساله با زیردامنه‌ها و preload تنظیم و انتقال خودکار به HTTPS را روشن می‌کند؛ ثبت نهایی در hstspreload.org با خود شماست.') })) });
          go.then(function (ok) {
            if (!ok) return;
            Object.keys(p.v).forEach(function (k) { d.hsts[k] = p.v[k]; });
            if (p.https) d.force_https = true;
            f2.redraw();
            P.toast(t('الگوی HSTS «') + p.title + t('» اعمال شد؛ بررسی کنید و «ذخیره» را بزنید.'), 'info');
          });
        } },
        h('span', { className: 'pcdn-preset-icon' }, icon(p.icon)),
        h('span', { className: 'pcdn-preset-text' }, h('span', { className: 'pcdn-preset-title', text: p.title }), h('span', { className: 'pcdn-preset-desc', text: p.desc })),
        act ? h('span', { className: 'pcdn-preset-badge', text: t('فعلی') }) : null);
    }));
    return P.field(t('الگوهای آماده HSTS'), row, { cls: 'pcdn-hsts-field', help: t('یکی را انتخاب کنید تا تنظیمات HSTS زیر پر شود؛ سپس بررسی کنید و «ذخیره» را بزنید.') });
  }
  function validateSsl(d) {
    var out = [], hs = d.hsts || {};
    var ma = hs.max_age;
    if (typeof ma !== 'number' || Math.floor(ma) !== ma || ma < 0 || ma > HSTS_MAX) out.push({ path: 'hsts.max_age', msg: t('مدت باید بین ۰ تا ۶۳٬۰۷۲٬۰۰۰ ثانیه (۲ سال) باشد.') });
    else if (hs.preload && !(hs.include_subdomains && ma >= YEAR)) out.push({ path: 'hsts.preload', msg: t('preload نیازمند «شامل همه زیردامنه‌ها» و max-age دست‌کم یک سال (۳۱٬۵۳۶٬۰۰۰ ثانیه) است.') });
    if (has(d, 'origin_client_auth') && ['off', 'platform', 'custom'].indexOf(d.origin_client_auth) < 0) out.push({ path: 'origin_client_auth', msg: t('حالت احراز هویت مبدأ نامعتبر است.') });
    return out;
  }

  var ORIGIN_AUTH = [
    ['off', t('خاموش'), t('CDN بدون گواهی کلاینت به سرور اصلی وصل می‌شود (مثل قبل).'), 'power'],
    ['platform', t('گواهی سکو'), t('نودهای CDN با گواهی مشترک پاسارگاد CDN وصل می‌شوند؛ سرور اصلی فقط درخواست‌های دارای این گواهی را می‌پذیرد.'), 'shieldCheck', t('ساده')],
    ['custom', t('گواهی اختصاصی'), t('گواهی و کلید خودتان را بارگذاری می‌کنید؛ سرور اصلی فقط به CA خودتان اعتماد می‌کند.'), 'key']
  ];
  var NGINX_SNIPPET = '# inside: server { listen 443 ssl; ... }\nssl_client_certificate /etc/nginx/pasargadcdn-origin-pull-ca.pem;\nssl_verify_client on;';
  var APACHE_SNIPPET = '# inside: <VirtualHost *:443> ... </VirtualHost>  (mod_ssl)\nSSLCACertificateFile /etc/ssl/pasargadcdn-origin-pull-ca.pem\nSSLVerifyClient require\nSSLVerifyDepth 2';
  var NGINX_CUSTOM = '# inside: server { listen 443 ssl; ... }\n# the CA that signed YOUR client certificate (not the certificate itself)\nssl_client_certificate /etc/nginx/my-origin-pull-ca.pem;\nssl_verify_client on;';
  // In-session state per domain: uploaded client-certificate details and the not-yet-sent PEM drafts.
  var ocState = {}, ocDraft = {};

  function codeBlock(text, caption) {
    return h('figure', { className: 'pcdn-codeblock' },
      h('figcaption', null, icon('terminal'), h('span', { dir: 'ltr', text: caption }),
        P.copyBtn(text, t('کپی تنظیم ') + caption, { text: t('کپی'), cls: 'pcdn-copy-code', done: t('کپی شد') })),
      h('pre', { dir: 'ltr', tabindex: '0' }, h('code', { text: text })));
  }
  /**
   * The site's origin-pull block: `origin_client` at the top level of the site payload,
   * {mode, effective, custom: {subject, issuer, expires_at, expired} | null, ca_url} (never the key).
   */
  function ocBlock() { var s = site(), b = s && s.origin_client; return b && typeof b === 'object' && !Array.isArray(b) ? b : null; }
  /** Uploaded custom client certificate: object (details), null (none) or undefined (the controller does not say). */
  function originClient() {
    var dom = domain();
    if (Object.prototype.hasOwnProperty.call(ocState, dom)) return ocState[dom];
    var b = ocBlock();
    if (b && has(b, 'custom')) return b.custom && typeof b.custom === 'object' ? b.custom : null;
    return undefined;
  }
  /** Certificate details from a PUT/DELETE answer ({…, custom: {…}} like the site block, or the bare details). */
  function infoFrom(data) {
    var x = data && typeof data === 'object' ? data : {};
    if (has(x, 'custom')) return x.custom && typeof x.custom === 'object' ? x.custom : null;
    var out = {};
    ['subject', 'issuer', 'not_after', 'expires_at', 'fingerprint_sha256', 'fingerprint'].forEach(function (k) { if (typeof x[k] === 'string' && x[k]) out[k] = x[k]; });
    if (x.expired === true) out.expired = true;
    return out;
  }
  function infoList(info) {
    var rows = [];
    if (info.subject) rows.push([t('موضوع (Subject)'), ltr(String(info.subject))]);
    if (info.issuer) rows.push([t('صادرکننده'), ltr(String(info.issuer))]);
    if (info.not_after || info.expires_at) {
      rows.push([t('تاریخ انقضا'), h('span', null, P.date(info.not_after || info.expires_at, { dateStyle: 'long' }), info.expired ? [' ', P.badge(t('منقضی شده'), 'danger')] : null)]);
    }
    if (info.fingerprint_sha256 || info.fingerprint) rows.push([t('اثر انگشت SHA-256'), ltr(String(info.fingerprint_sha256 || info.fingerprint))]);
    return rows.length ? h('dl', { className: 'pcdn-dl pcdn-oc-info' }, rows.map(function (r) { return h('div', null, h('dt', { text: r[0] }), h('dd', null, r[1])); })) : null;
  }
  /** After an upload/removal: refresh the site; keep the user's unsaved form edits if any. */
  function afterCertChange(f2, Aa) {
    var dirty = f2.dirty();
    return Aa.reloadSite().then(function (res) {
      if (Aa.S.form !== f2) return;
      if (res.ok && !dirty) f2.load();
      f2.redraw();
    });
  }

  function platformPanel() {
    var fp = h('div', { className: 'pcdn-mtls-ca' });
    var dl = P.btn(t('دانلود گواهی CA'), { kind: 'primary', icon: 'download', size: 'sm', cls: 'pcdn-ca-download', onclick: function () {
      P.busy(dl, P.api('GET', 'origin-pull-ca')).then(function (res) {
        clear(fp);
        if (!res.ok || !res.data || typeof res.data.pem !== 'string') { fp.appendChild(P.errorBox(res, t('دریافت گواهی CA ممکن نشد'))); return; }
        var name = String(res.data.filename || '').replace(/[^A-Za-z0-9._-]/g, '') || 'pasargadcdn-origin-pull-ca.pem';
        var ok = download(name, res.data.pem, 'application/x-pem-file');
        append(fp, [
          res.data.fingerprint_sha256 ? h('p', { className: 'pcdn-help pcdn-ca-fp' }, t('اثر انگشت SHA-256 گواهی: '), ltr(String(res.data.fingerprint_sha256))) : null,
          h('details', { className: 'pcdn-details', open: !ok }, h('summary', { text: t('نمایش متن گواهی (برای کپی دستی)') }), codeBlock(res.data.pem, name))]);
        if (ok) P.toast(t('فایل گواهی CA دانلود شد.'));
      });
    } });
    return h('div', { className: 'pcdn-subpanel pcdn-mtls-platform' },
      h('ol', { className: 'pcdn-ol' },
        h('li', { text: t('«گواهی سکو» را انتخاب و «ذخیره» کنید تا نودهای CDN هنگام اتصال به سرور اصلی گواهی کلاینت ارائه کنند (تا وقتی سرور اصلی آن را نخواهد، اثری ندارد).') }),
        h('li', null, t('گواهی CA را دانلود و روی سرور اصلی ذخیره کنید (مثلاً در '), ltr('/etc/nginx/pasargadcdn-origin-pull-ca.pem'), ').'),
        h('li', { text: t('یکی از تنظیم‌های زیر را به وب‌سرور اضافه و آن را دوباره بارگذاری (reload) کنید. از این پس سرور اصلی فقط اتصال‌هایی را می‌پذیرد که از CDN بیایند.') })),
      h('div', { className: 'pcdn-row-actions' }, dl), fp,
      h('p', { className: 'pcdn-help', text: t('nginx — داخل بلوک server سایت که روی ۴۴۳ با SSL گوش می‌دهد:') }),
      codeBlock(NGINX_SNIPPET, 'nginx'),
      h('p', { className: 'pcdn-help', text: t('Apache — داخل VirtualHost پورت ۴۴۳ (ماژول mod_ssl):') }),
      codeBlock(APACHE_SNIPPET, 'Apache'),
      P.alertBox('warning', t('ترتیب مهم است: اگر وب‌سرور را پیش از ذخیرهٔ این تنظیم سخت‌گیر کنید، همهٔ درخواست‌های CDN با خطای ۴۰۰ رد می‌شوند و سایت از دسترس خارج می‌شود.')),
      P.alertBox('info', t('گواهی سکو بین همهٔ سایت‌های این CDN مشترک است؛ یعنی ثابت می‌کند اتصال از شبکهٔ CDN آمده، نه لزوماً برای سایت شما. برای اطمینان کامل «گواهی اختصاصی» را انتخاب کنید.')));
  }

  function customPanel(d, f2, Aa) {
    var dom = domain(), dr = ocDraft[dom] = ocDraft[dom] || { cert: '', key: '' };
    var info = originClient(), errs = h('div');
    function fail(msg) { clear(errs); errs.appendChild(P.alertBox('danger', msg)); }
    var up = P.btn(info ? t('جایگزینی گواهی') : t('بارگذاری گواهی'), { kind: 'primary', icon: 'upload', size: 'sm', write: true, cls: 'pcdn-oc-upload', onclick: function () {
      clear(errs);
      var cert = dr.cert.trim(), key = dr.key.trim();
      if (cert.indexOf('-----BEGIN CERTIFICATE-----') < 0) return fail(t('گواهی باید با فرمت PEM باشد و با -----BEGIN CERTIFICATE----- شروع شود.'));
      if (/PRIVATE KEY/.test(cert)) return fail(t('در کادر گواهی فقط گواهی را بگذارید؛ کلید خصوصی را در کادر خودش وارد کنید.'));
      if (!/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(key)) return fail(t('کلید خصوصی باید با فرمت PEM باشد (-----BEGIN PRIVATE KEY----- یا RSA/EC PRIVATE KEY).'));
      if (/ENCRYPTED/.test(key)) return fail(t('کلید خصوصی رمزدار پشتیبانی نمی‌شود؛ ابتدا رمز آن را بردارید (مثلاً openssl pkey -in key.pem -out key-plain.pem).'));
      P.busy(up, P.api('PUT', 'ssl/origin-client', { cert: cert, key: key })).then(function (res) {
        if (!res.ok) { errs.appendChild(P.errorBox(res, t('بارگذاری گواهی انجام نشد'))); return; }
        dr.cert = ''; dr.key = '';   // the key is never kept or shown again
        ocState[dom] = infoFrom(res.data) || {};
        var saved = (Aa.config('ssl') || {}).origin_client_auth === 'custom';
        P.toast(saved ? t('گواهی اختصاصی اتصال مبدأ جایگزین شد.') : t('گواهی بارگذاری شد؛ حالا «ذخیره» را بزنید تا «گواهی اختصاصی» اعمال شود.'));
        afterCertChange(f2, Aa);
      });
    } });
    var rm = info !== null ? P.btn(t('حذف گواهی'), { kind: 'danger-soft', icon: 'trash', size: 'sm', write: true, cls: 'pcdn-oc-remove', onclick: function () {
      P.confirm({ title: t('حذف گواهی اختصاصی اتصال مبدأ'), danger: true, ok: t('حذف گواهی'),
        body: t('گواهی و کلید بارگذاری‌شده حذف می‌شوند. اگر سرور اصلی گواهی کلاینت را الزامی کرده باشد، تا انتخاب حالت دیگر و تنظیم دوبارهٔ سرور، درخواست‌های CDN رد می‌شوند.') })
        .then(function (ok) {
          if (!ok) return;
          P.busy(rm, P.api('DELETE', 'ssl/origin-client')).then(function (res) {
            if (!res.ok) { errs.appendChild(P.errorBox(res, t('حذف گواهی انجام نشد'))); return; }
            ocState[dom] = null;
            P.toast(t('گواهی اختصاصی اتصال مبدأ حذف شد.'));
            afterCertChange(f2, Aa);
          });
        });
    } }) : null;
    function pemPick(key, label) {
      return fileButton(label, '.pem,.crt,.cer,.key,text/plain', 'pcdn-oc-file', function (text) { dr[key] = text; f2.redraw(); }, fail);
    }
    return h('div', { className: 'pcdn-subpanel pcdn-mtls-custom' },
      info ? h('div', { className: 'pcdn-oc-current' }, info.expired ? P.badge(t('گواهی بارگذاری‌شده منقضی شده است'), 'danger', 'warn')
        : P.badge(t('گواهی بارگذاری شده است'), 'success', 'checkCircle'), infoList(info),
        h('p', { className: 'pcdn-help', text: t('کلید خصوصی رمزنگاری‌شده نگهداری می‌شود و هرگز دوباره نمایش داده نمی‌شود.') }))
        : info === null ? P.alertBox('info', t('هنوز گواهی اختصاصی بارگذاری نشده است. ابتدا گواهی و کلید را بارگذاری کنید و سپس «ذخیره» را بزنید.'))
          : h('p', { className: 'pcdn-help', text: t('اگر قبلاً گواهی بارگذاری کرده‌اید، برای تعویض دوباره بارگذاری کنید؛ کلید خصوصی هرگز نمایش داده نمی‌شود.') }),
      P.textarea(dr, 'cert', t('گواهی کلاینت (PEM)'), { rows: 5, placeholder: '-----BEGIN CERTIFICATE-----' }),
      h('div', { className: 'pcdn-row-actions' }, pemPick('cert', t('انتخاب فایل گواهی'))),
      P.textarea(dr, 'key', t('کلید خصوصی (PEM)'), { rows: 5, placeholder: '-----BEGIN PRIVATE KEY-----',
        help: t('کلید فقط یک‌بار برای CDN فرستاده و رمزنگاری‌شده نگهداری می‌شود؛ پس از بارگذاری از این صفحه پاک می‌شود و هرگز دوباره نمایش داده نمی‌شود.') }),
      h('div', { className: 'pcdn-row-actions' }, pemPick('key', t('انتخاب فایل کلید'))),
      errs, h('div', { className: 'pcdn-row-actions' }, up, rm),
      h('p', { className: 'pcdn-help', text: t('در سرور اصلی، CA ای را که گواهی کلاینت شما را امضا کرده (نه خود گواهی) معرفی کنید؛ مثلاً در nginx:') }),
      codeBlock(NGINX_CUSTOM, 'nginx'));
  }

  function mtlsCard(d, f2, Aa) {
    if (!has(d, 'origin_client_auth')) return null;
    var c = P.card({ title: t('احراز هویت مبدأ (mTLS)'), icon: 'certificate', id: 'mtls',
      subtitle: t('سرور اصلی مطمئن می‌شود هر اتصال واقعاً از CDN آمده است (Authenticated Origin Pulls)؛ دسترسی مستقیم به آی‌پی سرور هم بسته می‌شود.') });
    var mode = d.origin_client_auth, b = ocBlock(), saved = (Aa.config('ssl') || {}).origin_client_auth;
    // the controller reports what the edges really do (`effective`), e.g. custom without a usable cert → off
    var folded = !!b && b.mode === mode && saved === mode && typeof b.effective === 'string' && b.effective !== b.mode;
    append(c.body, [
      P.choice(d, 'origin_client_auth', null, ORIGIN_AUTH, { cols: 3, onchange: f2.redraw }),
      folded ? h('div', { className: 'pcdn-mtls-effective' }, P.alertBox('danger', [h('strong', { text: t('هنوز اعمال نمی‌شود: ') }),
        t('نودها فعلاً ') + (b.effective === 'off' ? t('بدون گواهی کلاینت') : t('با حالت «') + b.effective + '»') + t(' به سرور اصلی وصل می‌شوند') +
        (mode === 'custom' ? t('؛ یک گواهی کلاینت معتبر و منقضی‌نشده بارگذاری کنید.') : '.')])) : null,
      mode !== 'off' && d.origin_protocol !== 'https' ? P.alertBox('warning', t('گواهی کلاینت فقط در اتصال HTTPS فرستاده می‌شود؛ در همین صفحه «اتصال CDN به سرور اصلی» را روی HTTPS بگذارید.')) : null,
      mode === 'platform' ? platformPanel() : null,
      mode === 'custom' ? customPanel(d, f2, Aa) : null]);
    return c;
  }

  // ------------------------------------------------------------------ registry + hooks for pages.js

  P.sec6b = {
    wafPacks: wafPacks, validateWaf: validateWaf, hstsPresets: hstsPresets, validateSsl: validateSsl, mtlsCard: mtlsCard,
    // exported for tests
    transformProblem: transformProblem, cleanTransform: cleanTransform, redirectProblem: redirectProblem, cleanRedirect: cleanRedirect,
    csvErrors: csvErrors, toCsv: toCsv
  };

  pages.transform = {
    title: t('قوانین تبدیل'), icon: 'swap', heading: t('قوانین تبدیل (Transform Rules)'),
    desc: t('هدرهای درخواست و پاسخ را برای مسیرها، متدها یا کشورهای خاص اضافه یا حذف کنید یا مسیر درخواست را پیش از رسیدن به سرور اصلی بازنویسی کنید.'),
    guide: {
      what: t('قانون تبدیل روی درخواست‌هایی که با مسیر، متد و کشور منطبق‌اند اجرا می‌شود و هدرهای درخواست/پاسخ را تنظیم یا حذف می‌کند یا مسیر را بی‌صدا بازنویسی می‌کند.'),
      when: t('برای افزودن هدر CORS یا امنیتی روی بخشی از سایت، فرستادن یک هدر شناسایی به سرور اصلی، حذف هدرهای افشاگر (مثل X-Powered-By) یا انتقال بی‌صدای مسیرهای قدیمی به ساختار جدید.'),
      rec: t('برای تغییر آدرسی که بازدیدکننده می‌بیند (و سئو) از «ریدایرکت‌ها» استفاده کنید؛ بازنویسی مسیر آدرس مرورگر را عوض نمی‌کند.'),
      mistakes: [t('تغییر هدرهای رزرو مثل Host یا Content-Length (مجاز نیست).'), t('عبارت منظم بدون ^ و $ که مسیرهای ناخواسته را هم بازنویسی می‌کند.'),
        t('حذف Cache-Control سرور اصلی بدون آگاهی از اثرش روی کش.')]
    },
    upsell: t('با ارتقای پلن می‌توانید هدرها و مسیر درخواست‌ها را برای بخش‌های مختلف سایت تغییر دهید.'),
    hidden: function (s) { return !sectionOf(s, 'transform'); },
    lock: function (f) { return f.max_transform_rules === 0; },
    render: renderTransform
  };
  pages.redirects = {
    title: t('ریدایرکت‌ها'), icon: 'redirect', heading: t('ریدایرکت‌ها'),
    desc: t('آدرس‌های قدیمی را مستقیم از لبهٔ CDN به آدرس جدید بفرستید؛ یکی‌یکی یا یکجا از فایل CSV.'),
    guide: {
      what: t('بازدیدکننده‌ای که مبدأ را باز می‌کند بی‌درنگ از لبهٔ CDN به مقصد فرستاده می‌شود و درخواست اصلاً به سرور شما نمی‌رسد.'),
      when: t('تغییر ساختار آدرس‌ها، انتقال صفحات یا پوشه‌های قدیمی، آدرس‌های کوتاه و انتقال کل سایت به دامنهٔ جدید.'),
      rec: t('برای انتقال دائمی ۳۰۱ (یا ۳۰۸ برای فرم‌ها و API). ابتدا با ۳۰۲ آزمایش کنید؛ مرورگرها ۳۰۱ را مدت‌ها به خاطر می‌سپارند.'),
      mistakes: [t('قانون پیشوند یا regex خیلی کلی بالای قوانین خاص (قوانین پایین‌تر اجرا نمی‌شوند).'), t('مقصدی که خودش با مبدأ منطبق است (حلقهٔ ریدایرکت).'), t('استفاده از ۳۰۱ برای انتقال موقت.')]
    },
    upsell: t('با ارتقای پلن می‌توانید آدرس‌های قدیمی را مستقیم از لبهٔ CDN ریدایرکت کنید.'),
    hidden: function (s) { return !sectionOf(s, 'redirects'); },
    lock: function (f) { return f.max_redirects === 0; },
    render: renderRedirects
  };
  pages.bots = {
    title: t('مدیریت ربات‌ها'), icon: 'bot',
    desc: t('ربات‌های خودکار (اسکرپرها، اسکنرها و ابزارهای بدون مرورگر) را شناسایی و ثبت، چالش یا مسدود کنید؛ موتورهای جستجوی تأییدشده عبور می‌کنند.'),
    guide: {
      what: t('درخواست‌های خودکار از روی User-Agent و نشانه‌های مرورگرهای بی‌سر شناسایی می‌شوند؛ موتورهای جستجو با بازه‌های IP منتشرشده و User-Agent تأیید می‌شوند.'),
      when: t('وقتی محتوای سایت اسکرپ می‌شود، ربات‌ها بار سرور را بالا می‌برند یا اسکن خودکار می‌بینید.'),
      rec: t('حالت «چالش» با «اجازه به ربات‌های تأییدشده» و «مسدود کردن درخواست‌های بدون User-Agent» روشن.'),
      mistakes: [t('خاموش کردن «اجازه به ربات‌های تأییدشده» (سئو آسیب می‌بیند).'), t('حالت «مسدودسازی» وقتی API، اپلیکیشن موبایل یا وب‌هوک‌ها با curl و کتابخانه‌های HTTP درخواست می‌فرستند.')]
    },
    hidden: function (s) { return !sectionOf(s, 'bots'); },
    render: renderBots
  };
})();
