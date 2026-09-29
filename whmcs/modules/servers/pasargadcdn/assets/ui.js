/*
 * Pasargad CDN — client-area UI kit (vanilla JS, no dependencies).
 *
 * Loaded before pages.js and app.js; everything hangs off window.PCDN.
 * Data is only ever put into the DOM with textContent / createElement /
 * setAttribute — never innerHTML. The SVG icon paths below are static,
 * hand-written strings.
 */
(function () {
  'use strict';
  var P = window.PCDN = window.PCDN || {};

  // ------------------------------------------------------------------ DOM

  function h(tag, props) {
    var el = document.createElement(tag);
    props = props || {};
    Object.keys(props).forEach(function (k) {
      var v = props[k];
      if (v === null || v === undefined || v === false) return;
      if (k === 'text') el.textContent = String(v);
      else if (k === 'className') el.className = v;
      else if (k.slice(0, 2) === 'on' && typeof v === 'function') el.addEventListener(k.slice(2), v);
      else if (k === 'value' || k === 'checked' || k === 'disabled' || k === 'selected' || k === 'indeterminate') el[k] = v;
      else el.setAttribute(k, v === true ? '' : String(v));
    });
    for (var i = 2; i < arguments.length; i++) append(el, arguments[i]);
    return el;
  }
  function append(el, c) {
    if (c === null || c === undefined || c === false) return el;
    if (Array.isArray(c)) { c.forEach(function (x) { append(el, x); }); return el; }
    el.appendChild(typeof c === 'object' ? c : document.createTextNode(String(c)));
    return el;
  }
  function clear(el) { while (el && el.firstChild) el.removeChild(el.firstChild); return el; }
  var SVGNS = 'http://www.w3.org/2000/svg';
  function s(tag, attrs, text) {
    var el = document.createElementNS(SVGNS, tag);
    Object.keys(attrs || {}).forEach(function (k) { if (attrs[k] !== null && attrs[k] !== undefined) el.setAttribute(k, String(attrs[k])); });
    if (text !== undefined) el.textContent = String(text);
    return el;
  }
  function ltr(t, cls) { return h('bdi', { className: 'pcdn-ltr' + (cls ? ' ' + cls : ''), dir: 'ltr', text: t }); }
  function code(t) { return h('code', { className: 'pcdn-code', dir: 'ltr', text: t }); }
  function clone(o) { return o === undefined ? undefined : JSON.parse(JSON.stringify(o)); }
  function uid(prefix) { return prefix + Math.random().toString(36).slice(2, 8); }

  // ------------------------------------------------------------------ icons (24×24, stroke)

  var C = 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18';
  var SHIELD = 'M12 3 5 6v5.2c0 4.3 2.9 8.1 7 9.8 4.1-1.7 7-5.5 7-9.8V6z';
  var ICONS = {
    home: 'M3.5 10.5 12 3.5l8.5 7|M5.5 9v11h4.5v-6h4v6h4.5V9',
    book: 'M5 4.5A1.5 1.5 0 0 1 6.5 3H19v15H6.5A1.5 1.5 0 0 0 5 19.5z|M5 19.5A1.5 1.5 0 0 0 6.5 21H19v-3|M9 7.5h6|M9 11h4',
    server: 'M4 4h16v6H4z|M4 14h16v6H4z|M8 7h.01|M8 17h.01|M12 7h4|M12 17h4',
    key: 'M8 11a4 4 0 1 0 0 8a4 4 0 1 0 0-8|M10.9 12.1 19 4|M15.5 7.5l2.5 2.5|M13 10l1.8 1.8',
    zap: 'M13 2.5 4.5 14h7l-1 7.5 8.5-11.5h-7z',
    sliders: 'M4 6h9|M17 6h3|M15 4v4|M4 12h3|M11 12h9|M9 10v4|M4 18h11|M19 18h1|M17 16v4',
    image: 'M4 5h16v14H4z|M4 16l5-5 4 4 2-2 5 5|M15.5 8.5h.01',
    lb: 'M9 3h6v4H9z|M12 7v3|M6 13v-3h12v3|M3 13h6v6H3z|M15 13h6v6h-6z',
    wall: 'M3 5h18v14H3z|M3 9.7h18|M3 14.3h18|M9 5v4.7|M15 5v4.7|M6 9.7v4.6|M12 9.7v4.6|M18 9.7v4.6|M9 14.3V19|M15 14.3V19',
    shield: SHIELD,
    shieldCheck: SHIELD + '|M9 12l2.2 2.2L15.5 10',
    shieldBolt: SHIELD + '|M12.8 7.5 10 12.5h3.5L11.5 16.5',
    gauge: 'M4 17a8 8 0 1 1 16 0|M12 17l3.5-4.5|M4 20h16',
    link: 'M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1|M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1',
    lock: 'M5.5 11h13v10h-13z|M8.5 11V8a3.5 3.5 0 0 1 7 0v3|M12 15v2.5',
    unlock: 'M5.5 11h13v10h-13z|M8.5 11V8a3.5 3.5 0 0 1 6.8-1.2|M12 15v2.5',
    code: 'M8 8l-4 4 4 4|M16 8l4 4-4 4|M13.5 5l-3 14',
    fileWarn: 'M6 3h8l4 4v14H6z|M14 3v4h4|M12 10v4|M12 17h.01',
    chart: 'M4 4v16h16|M8 16v-4|M12 16V8|M16 16v-6',
    activity: 'M3 12h4l2.5-6 5 12 2.5-6h4',
    check: 'M5 12.5l4.5 4.5L19 7.5',
    x: 'M6 6l12 12|M18 6 6 18',
    plus: 'M12 5v14|M5 12h14',
    edit: 'M4 20h4L19 9l-4-4L4 16z|M13.5 6.5l4 4',
    trash: 'M4 7h16|M10 11v6|M14 11v6|M6 7l1 13h10l1-13|M9 7V4h6v3',
    copy: 'M9 9h11v11H9z|M5 15H4V4h11v1',
    refresh: 'M20 11a8 8 0 0 0-14.5-4.5L4 8|M4 4v4h4|M4 13a8 8 0 0 0 14.5 4.5L20 16|M20 20v-4h-4',
    chevronDown: 'M6 9l6 6 6-6',
    chevronLeft: 'M15 6l-6 6 6 6',
    chevronRight: 'M9 6l6 6-6 6',
    up: 'M12 19V5|M6 11l6-6 6 6',
    down: 'M12 5v14|M6 13l6 6 6-6',
    arrowLeft: 'M19 12H5|M11 6l-6 6 6 6',
    arrowRight: 'M5 12h14|M13 6l6 6-6 6',
    search: 'M11 4a7 7 0 1 0 0 14a7 7 0 1 0 0-14|M20 20l-4-4',
    menu: 'M4 6h16|M4 12h16|M4 18h16',
    external: 'M14 4h6v6|M20 4l-9 9|M18 14v6H4V6h6',
    info: C + '|M12 11v5|M12 8h.01',
    warn: 'M12 3.5 2.5 20h19z|M12 10v4.5|M12 17.2h.01',
    checkCircle: C + '|M8 12.5l2.5 2.5L16 9.5',
    xCircle: C + '|M9 9l6 6|M15 9l-6 6',
    circle: C,
    clock: C + '|M12 7v5l3 2',
    upload: 'M12 15V4|M7 9l5-5 5 5|M4 15v5h16v-5',
    download: 'M12 4v11|M7 10l5 5 5-5|M4 15v5h16v-5',
    sparkles: 'M11 3l1.8 4.7 4.7 1.8-4.7 1.8L11 16l-1.8-4.7L4.5 9.5l4.7-1.8z|M18.5 14.5l.8 2 2 .8-2 .8-.8 2-.8-2-2-.8 2-.8z',
    cloud: 'M7 18.5a4.5 4.5 0 0 1-.6-9A6 6 0 0 1 17.9 10a4.3 4.3 0 0 1-.4 8.5z',
    ban: C + '|M5.7 5.7l12.6 12.6',
    mail: 'M3 6h18v12H3z|M3 7l9 6 9-6',
    tool: 'M14.5 4a5 5 0 0 0-4.6 6.9L4 16.8V20h3.2l5.9-5.9A5 5 0 0 0 20 9.5l-3 .9-2.4-2.4.9-3z',
    rocket: 'M5 15c-1.5 1.5-2 5-2 5s3.5-.5 5-2|M9 15l-3-3c1-4 5-8.5 13-9-.5 8-5 12-10 12z|M14.5 9.5h.01',
    power: 'M12 3v8|M6.3 6.8a8 8 0 1 0 11.4 0',
    terminal: 'M4 5h16v14H4z|M7.5 9.5 10 12l-2.5 2.5|M12.5 14.5h4',
    bulb: 'M9 18h6|M10 21h4|M12 3a6 6 0 0 0-3.5 10.9V16h7v-2.1A6 6 0 0 0 12 3',
    globe: C + '|M3 12h18|M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3',
    filter: 'M4 5h16l-6 7.5V19l-4 1.5v-8z',
    eye: 'M2.5 12s3.5-6.5 9.5-6.5 9.5 6.5 9.5 6.5-3.5 6.5-9.5 6.5S2.5 12 2.5 12z|M12 9.5a2.5 2.5 0 1 0 0 5a2.5 2.5 0 1 0 0-5',
    grip: 'M9 6h.01|M15 6h.01|M9 12h.01|M15 12h.01|M9 18h.01|M15 18h.01',
    wallet: 'M4 7h15a1.5 1.5 0 0 1 1.5 1.5v10A1.5 1.5 0 0 1 19 20H5a1.5 1.5 0 0 1-1.5-1.5v-12A2.5 2.5 0 0 1 6 4h11v3|M16 13.5h.01',
    star: 'M12 3.5l2.6 5.4 5.9.8-4.3 4.1 1 5.8L12 16.9l-5.2 2.7 1-5.8-4.3-4.1 5.9-.8z',
    certificate: 'M4 4h16v11H4z|M8 8h8|M8 11h5|M16 14a2.5 2.5 0 1 0 0 5a2.5 2.5 0 1 0 0-5|M14.5 18.5 14 22l2-1 2 1-.5-3.5',
    tunnel: 'M3 20V12a9 9 0 0 1 18 0v8|M7.5 20v-7.5a4.5 4.5 0 0 1 9 0V20|M2 20h20|M12 4v2',
    qr: 'M4 4h6v6H4z|M14 4h6v6h-6z|M4 14h6v6H4z|M14 14h2.5v2.5H14z|M18 18h2v2h-2z|M18 14h2|M14 19.5h2'
  };
  function icon(name, cls) {
    var svg = s('svg', { viewBox: '0 0 24 24', width: 20, height: 20, fill: 'none', stroke: 'currentColor',
      'stroke-width': 1.8, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true', focusable: 'false',
      class: 'pcdn-icon' + (cls ? ' ' + cls : '') });
    (ICONS[name] || ICONS.circle).split('|').forEach(function (d) { svg.appendChild(s('path', { d: d })); });
    return svg;
  }

  // ------------------------------------------------------------------ formatting (Persian digits for user-facing numbers)

  var nf = null, nf1 = null;
  try { nf = new Intl.NumberFormat('fa-IR'); nf1 = new Intl.NumberFormat('fa-IR', { maximumFractionDigits: 1 }); } catch (e) { /* old browser */ }
  var FA_DIGITS = '۰۱۲۳۴۵۶۷۸۹';
  function fa(str) { return String(str).replace(/[0-9]/g, function (d) { return FA_DIGITS[+d]; }); }
  function num(n) { n = Number(n) || 0; return nf ? nf.format(n) : fa(n); }
  function num1(n) { n = Number(n) || 0; return nf1 ? nf1.format(n) : fa(Math.round(n * 10) / 10); }
  function bytes(b) {
    b = Number(b) || 0;
    var u = ['B', 'KB', 'MB', 'GB', 'TB'], i = 0;
    while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
    return (i ? num1(b >= 100 ? Math.round(b) : b) : num(b)) + ' ' + u[i];
  }
  function short(n) {
    n = Number(n) || 0;
    if (n >= 1e9) return num1(n / 1e9) + ' میلیارد';
    if (n >= 1e6) return num1(n / 1e6) + ' میلیون';
    if (n >= 1e3) return num1(n / 1e3) + ' هزار';
    return num(Math.round(n));
  }
  function pct(a, b) { return b > 0 ? num(Math.round(a * 100 / b)) + '٪' : '—'; }
  function dur(sec) {
    sec = Number(sec) || 0;
    if (sec <= 0) return '۰ ثانیه';
    var parts = [], units = [[31536000, 'سال'], [2592000, 'ماه'], [86400, 'روز'], [3600, 'ساعت'], [60, 'دقیقه'], [1, 'ثانیه']];
    for (var i = 0; i < units.length && parts.length < 2; i++) {
      var q = Math.floor(sec / units[i][0]);
      if (q > 0) { parts.push(num(q) + ' ' + units[i][1]); sec -= q * units[i][0]; }
    }
    return parts.join(' و ');
  }
  function date(iso, opts) {
    if (!iso) return '—';
    var d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso);
    try { return d.toLocaleString('fa-IR', opts || { dateStyle: 'medium', timeStyle: 'short' }); } catch (e) { return d.toISOString(); }
  }
  function rel(iso) {
    var d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso || '—');
    var sec = Math.round((Date.now() - d.getTime()) / 1000);
    if (sec < 0) sec = 0;
    if (sec < 45) return 'همین الان';
    if (sec < 3600) return num(Math.max(1, Math.round(sec / 60))) + ' دقیقه پیش';
    if (sec < 86400) return num(Math.round(sec / 3600)) + ' ساعت پیش';
    if (sec < 30 * 86400) return num(Math.round(sec / 86400)) + ' روز پیش';
    return date(iso, { dateStyle: 'medium' });
  }
  /** Search normalisation: Arabic ي/ك → Persian, drop ZWNJ/diacritics, lower-case. */
  function norm(t) {
    return String(t || '').toLowerCase().replace(/ي/g, 'ی').replace(/ك/g, 'ک').replace(/[‌ً-ٟ]/g, '')
      .replace(/[۰-۹]/g, function (c) { return String(c.charCodeAt(0) - 0x06f0); });
  }

  var COUNTRIES = {
    IR: 'ایران', US: 'آمریکا', DE: 'آلمان', NL: 'هلند', GB: 'انگلستان', FR: 'فرانسه', CN: 'چین', RU: 'روسیه', TR: 'ترکیه',
    AE: 'امارات', IQ: 'عراق', AF: 'افغانستان', CA: 'کانادا', SE: 'سوئد', FI: 'فنلاند', IN: 'هند', SG: 'سنگاپور', JP: 'ژاپن',
    KR: 'کره جنوبی', UA: 'اوکراین', PL: 'لهستان', IT: 'ایتالیا', ES: 'اسپانیا', BR: 'برزیل', AM: 'ارمنستان', AZ: 'آذربایجان',
    OM: 'عمان', QA: 'قطر', SA: 'عربستان', KW: 'کویت', BH: 'بحرین', PK: 'پاکستان', VN: 'ویتنام', HK: 'هنگ‌کنگ', RO: 'رومانی',
    CH: 'سوئیس', AT: 'اتریش', BG: 'بلغارستان', CZ: 'چک', IE: 'ایرلند', AU: 'استرالیا', LT: 'لیتوانی', GE: 'گرجستان',
    TM: 'ترکمنستان', TJ: 'تاجیکستان', UZ: 'ازبکستان', KZ: 'قزاقستان', ID: 'اندونزی', MY: 'مالزی', TH: 'تایلند', EG: 'مصر',
    SY: 'سوریه', LB: 'لبنان', JO: 'اردن', BE: 'بلژیک', DK: 'دانمارک', NO: 'نروژ', CY: 'قبرس', GR: 'یونان', HU: 'مجارستان',
    MX: 'مکزیک', AR: 'آرژانتین', ZA: 'آفریقای جنوبی', NG: 'نیجریه', IL: 'اسرائیل', TW: 'تایوان', PH: 'فیلیپین', BD: 'بنگلادش'
  };
  function country(code) { code = String(code || '').toUpperCase(); return COUNTRIES[code] || code || '—'; }

  // ------------------------------------------------------------------ storage (never required)

  function store(key, val) {
    try {
      if (val === undefined) return window.localStorage.getItem('pcdn:' + key);
      if (val === null) window.localStorage.removeItem('pcdn:' + key);
      else window.localStorage.setItem('pcdn:' + key, String(val));
    } catch (e) { /* private mode / blocked */ }
    return null;
  }

  // ------------------------------------------------------------------ API

  var CFG = { api: '', csrf: '', serviceId: 0 };
  function api(method, path, body, query) {
    // The admin-mode endpoint (addonmodules.php?module=…) already has a query string.
    var url = CFG.api + (CFG.api.indexOf('?') >= 0 ? '&' : '?') + 'id=' + encodeURIComponent(CFG.serviceId) + '&path=' + encodeURIComponent(path);
    Object.keys(query || {}).forEach(function (k) { url += '&' + encodeURIComponent(k) + '=' + encodeURIComponent(query[k]); });
    var init = { method: method, credentials: 'same-origin', headers: { 'X-PCDN-CSRF': CFG.csrf, 'Accept': 'application/json' } };
    if (body !== undefined) {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    return fetch(url, init).then(function (r) {
      return r.json().catch(function () { return { detail: 'پاسخ نامعتبر از سرور (HTTP ' + r.status + ')' }; })
        .then(function (data) { return { ok: r.ok, status: r.status, data: data }; });
    }, function () {
      return { ok: false, status: 0, data: { detail: 'ارتباط با سرور برقرار نشد. اتصال اینترنت را بررسی کنید.' } };
    });
  }

  var LOC = {
    rules: 'قانون', conditions: 'شرط', pools: 'استخر', origins: 'سرور', exclusions: 'استثنا', request: 'هدر درخواست',
    response: 'هدر پاسخ', value: 'مقدار', name: 'نام', id: 'شناسه', path: 'مسیر', content: 'مقدار', ttl: 'TTL', type: 'نوع',
    priority: 'اولویت', pool: 'استخر', origin_port: 'پورت سرور اصلی', health_port: 'پورت بررسی سلامت', address: 'آدرس',
    port: 'پورت', weight: 'وزن', pattern: 'الگو', redirect: 'ریدایرکت', url: 'آدرس', edge_ttl: 'مدت کش CDN',
    browser_ttl: 'مدت کش مرورگر', requests: 'تعداد درخواست', period: 'بازه', block_seconds: 'مدت مسدودی', methods: 'متدها',
    action: 'اقدام', field: 'فیلد', op: 'عملگر', rule_id: 'شناسه قانون', health: 'بررسی سلامت', interval: 'فاصله',
    timeout: 'مهلت', expect: 'کدهای سالم', host: 'هاست', quality: 'کیفیت', max_width: 'حداکثر عرض', extensions: 'پسوندها',
    allowed_referers: 'دامنه‌های مجاز', bypass_cookies: 'کوکی‌های عبور از کش', threshold_rps: 'آستانه', clearance_ttl: 'اعتبار مجوز',
    max_age: 'max-age', hsts: 'HSTS', cert: 'گواهی', key: 'کلید خصوصی', zone: 'فایل زون', paranoia: 'سطح حساسیت', groups: 'گروه‌ها'
  };
  /** Controller errors → {summary, items:[{path, label, msg}]}. */
  function parseErrors(data, status) {
    var d = data && data.detail;
    if (Array.isArray(d)) {
      return { summary: 'اطلاعات واردشده معتبر نیست.', items: d.map(function (e) {
        var loc = Array.isArray(e.loc) ? e.loc.filter(function (x, i) { return !(i === 0 && (x === 'body' || x === 'query')); }) : [];
        var label = [];
        loc.forEach(function (x) {
          if (typeof x === 'number' && label.length) label[label.length - 1] += ' ' + num(x + 1);
          else if (typeof x !== 'number') label.push(LOC[x] || String(x));
        });
        return { path: loc.join('.'), label: label.join(' › '), msg: String(e.msg || '') };
      }) };
    }
    if (typeof d === 'string' && d) return { summary: d, items: [] };
    return { summary: status === 0 ? 'ارتباط با سرور برقرار نشد.' : 'خطای ناشناخته (HTTP ' + status + ')', items: [] };
  }
  function errorText(res) {
    var e = parseErrors(res.data, res.status);
    return e.summary + (e.items.length ? ' ' + e.items.map(function (x) { return (x.label ? x.label + ': ' : '') + x.msg; }).join('؛ ') : '');
  }
  function errorBox(res, title) {
    var e = parseErrors(res.data, res.status);
    return h('div', { className: 'pcdn-alert pcdn-alert-danger', role: 'alert' }, icon('xCircle'),
      h('div', null, title ? h('strong', { text: title }) : null, h('div', { text: e.summary }),
        e.items.length ? h('ul', { className: 'pcdn-errlist' }, e.items.map(function (x) {
          return h('li', null, x.label ? h('b', { text: x.label + ': ' }) : null, x.msg);
        })) : null));
  }

  // ------------------------------------------------------------------ layer (modals, drawers, toasts)

  var layer = null, toasts = null;
  function getLayer() {
    if (!layer) {
      layer = h('div', { id: 'pcdn-layer', className: 'pcdn pcdn-layer', dir: 'rtl', lang: 'fa' });
      toasts = h('div', { className: 'pcdn-toasts', role: 'status', 'aria-live': 'polite' });
      layer.appendChild(toasts);
      document.body.appendChild(layer);
      theme.attach(layer);
    }
    return layer;
  }

  function toast(msg, kind, action) {
    getLayer();
    kind = kind || 'success';
    var t = h('div', { className: 'pcdn-toast pcdn-toast-' + kind, role: kind === 'error' ? 'alert' : null },
      icon(kind === 'error' ? 'xCircle' : kind === 'warn' ? 'warn' : kind === 'info' ? 'info' : 'checkCircle'),
      h('div', { className: 'pcdn-toast-msg', text: msg }),
      action ? h('button', { type: 'button', className: 'pcdn-toast-act', text: action.label, onclick: function () { close(); action.fn(); } }) : null,
      h('button', { type: 'button', className: 'pcdn-toast-x', 'aria-label': 'بستن', onclick: function () { close(); } }, icon('x')));
    function close() { if (t.parentNode) t.parentNode.removeChild(t); }
    toasts.appendChild(t);
    while (toasts.children.length > 4) toasts.removeChild(toasts.firstChild);
    setTimeout(close, kind === 'error' ? 9000 : 4500);
    return t;
  }

  var FOCUSABLE = 'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';
  var openDialogs = [];

  /**
   * Accessible dialog. kind: 'modal' (centred) | 'drawer' (side panel / bottom sheet on phones) | 'sheet'.
   * Returns {el, body, foot, close()}. Focus is trapped; Esc and the backdrop close it (onClose runs).
   */
  function dialog(o) {
    getLayer();
    var prev = document.activeElement;
    var titleId = uid('pcdn-dlg-');
    var body = h('div', { className: 'pcdn-dlg-body' });
    var foot = h('div', { className: 'pcdn-dlg-foot' });
    var closeBtn = h('button', { type: 'button', className: 'pcdn-iconbtn', 'aria-label': 'بستن', onclick: function () { api2.close(); } }, icon('x'));
    var box = h('div', { className: 'pcdn-dlg pcdn-dlg-' + (o.kind || 'modal') + (o.wide ? ' is-wide' : ''), role: o.role || 'dialog', 'aria-modal': 'true', 'aria-labelledby': titleId },
      h('div', { className: 'pcdn-dlg-head' },
        o.icon ? h('span', { className: 'pcdn-dlg-icon pcdn-tone-' + (o.tone || 'brand') }, icon(o.icon)) : null,
        h('div', { className: 'pcdn-dlg-titles' }, h('h3', { id: titleId, text: o.title }), o.subtitle ? h('p', { text: o.subtitle }) : null),
        closeBtn),
      body, foot);
    var back = h('div', { className: 'pcdn-backdrop' + (o.kind === 'drawer' ? ' is-drawer' : ''), onmousedown: function (e) { if (e.target === back) api2.close(); } }, box);
    var closed = false;
    var api2 = {
      el: box, body: body, foot: foot,
      close: function (silent) {
        if (closed) return;
        closed = true;
        document.removeEventListener('keydown', onKey, true);
        openDialogs.splice(openDialogs.indexOf(api2), 1);
        if (back.parentNode) back.parentNode.removeChild(back);
        if (!openDialogs.length) document.documentElement.classList.remove('pcdn-noscroll');
        if (prev && prev.focus && document.body.contains(prev)) { try { prev.focus(); } catch (e) { /* ignore */ } }
        if (!silent && o.onClose) o.onClose();
      },
      focusFirst: function () {
        var f = box.querySelector('[autofocus]') || body.querySelector(FOCUSABLE) || foot.querySelector(FOCUSABLE) || closeBtn;
        if (f) f.focus();
      }
    };
    function onKey(e) {
      if (openDialogs[openDialogs.length - 1] !== api2) return;
      if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); api2.close(); return; }
      if (e.key !== 'Tab') return;
      var els = Array.prototype.filter.call(box.querySelectorAll(FOCUSABLE), function (x) { return x.offsetParent !== null || x === document.activeElement; });
      if (!els.length) { e.preventDefault(); return; }
      var first = els[0], last = els[els.length - 1];
      if (e.shiftKey && (document.activeElement === first || !box.contains(document.activeElement))) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && (document.activeElement === last || !box.contains(document.activeElement))) { e.preventDefault(); first.focus(); }
    }
    document.addEventListener('keydown', onKey, true);
    openDialogs.push(api2);
    layer.appendChild(back);
    document.documentElement.classList.add('pcdn-noscroll');
    return api2;
  }

  /** Confirm dialog → Promise<boolean>. */
  function confirmDlg(o) {
    return new Promise(function (resolve) {
      var done = false;
      var d = dialog({ title: o.title, icon: o.icon || (o.danger ? 'warn' : 'info'), tone: o.danger ? 'danger' : 'brand', role: 'alertdialog',
        onClose: function () { if (!done) { done = true; resolve(false); } } });
      append(d.body, typeof o.body === 'string' ? h('p', { text: o.body }) : o.body);
      var cancel = h('button', { type: 'button', className: 'pcdn-btn', text: o.cancel || 'انصراف', onclick: function () { d.close(); } });
      var ok = h('button', { type: 'button', className: 'pcdn-btn ' + (o.danger ? 'pcdn-btn-danger' : 'pcdn-btn-primary'), text: o.ok || 'تأیید',
        'data-confirm': '1', onclick: function () { done = true; d.close(true); resolve(true); } });
      append(d.foot, [ok, cancel]);
      (o.danger ? cancel : ok).focus();
    });
  }

  // ------------------------------------------------------------------ small components

  function btn(label, o) {
    o = o || {};
    return h('button', {
      type: 'button', className: 'pcdn-btn' + (o.kind ? ' pcdn-btn-' + o.kind : '') + (o.size ? ' pcdn-btn-' + o.size : '') + (o.cls ? ' ' + o.cls : ''),
      onclick: o.onclick, 'data-write': o.write ? '1' : null, disabled: o.disabled, title: o.title, 'aria-label': o.aria
    }, o.icon ? icon(o.icon) : null, label ? h('span', { text: label }) : null);
  }
  function iconBtn(name, label, onclick, o) {
    o = o || {};
    return h('button', { type: 'button', className: 'pcdn-iconbtn' + (o.cls ? ' ' + o.cls : ''), 'aria-label': label, title: label,
      onclick: onclick, 'data-write': o.write ? '1' : null, disabled: o.disabled }, icon(name));
  }
  /** Runs a promise-returning action from a button with a busy state. */
  function busy(button, promise) {
    if (button) { button.disabled = true; button.classList.add('is-busy'); button.setAttribute('aria-busy', 'true'); }
    return promise.then(function (res) {
      if (button) { button.disabled = false; button.classList.remove('is-busy'); button.removeAttribute('aria-busy'); }
      return res;
    });
  }

  function copyText(text) {
    function fallback() {
      var ta = h('textarea', { className: 'pcdn-offscreen', readonly: true, value: text });
      document.body.appendChild(ta);
      ta.select();
      var ok = false;
      try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
      document.body.removeChild(ta);
      return ok ? Promise.resolve() : Promise.reject(new Error('copy'));
    }
    if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text).catch(fallback);
    return fallback();
  }
  function copyBtn(text, label, o) {
    o = o || {};
    var b = h('button', { type: 'button', className: 'pcdn-copy' + (o.cls ? ' ' + o.cls : ''), 'aria-label': label || 'کپی', title: label || 'کپی',
      'data-copy': '1', 'data-ro-ok': '1', onclick: function (e) {
        e.stopPropagation();
        var v = typeof text === 'function' ? text() : text;
        copyText(v).then(function () {
          b.classList.add('is-done');
          setTimeout(function () { b.classList.remove('is-done'); }, 1500);
          toast(o.done || 'کپی شد', 'success');
        }, function () { toast('کپی خودکار ممکن نشد؛ متن را دستی انتخاب کنید.', 'error'); });
      } }, icon('copy'), icon('check', 'pcdn-copy-ok'), o.text ? h('span', { text: o.text }) : null);
    return b;
  }
  /** LTR value with a copy button next to it. */
  function copyable(text, o) {
    o = o || {};
    return h('span', { className: 'pcdn-copyable' + (o.block ? ' is-block' : '') }, h('code', { dir: 'ltr', text: text }), copyBtn(text, o.label || ('کپی ' + text)));
  }

  function badge(text, tone, ic) {
    return h('span', { className: 'pcdn-badge pcdn-tone-' + (tone || 'muted') }, ic ? icon(ic) : null, h('span', { text: text }));
  }
  function alertBox(tone, content, o) {
    o = o || {};
    var ic = o.icon || { success: 'checkCircle', danger: 'xCircle', warning: 'warn', info: 'info' }[tone] || 'info';
    return h('div', { className: 'pcdn-alert pcdn-alert-' + tone, role: tone === 'danger' ? 'alert' : null }, icon(ic), h('div', { className: 'pcdn-alert-body' }, content));
  }
  function card(o) {
    o = o || {};
    var body = h('div', { className: 'pcdn-card-body' });
    var head = (o.title || o.actions) ? h('header', { className: 'pcdn-card-head' },
      o.icon ? h('span', { className: 'pcdn-card-icon pcdn-tone-' + (o.tone || 'brand') }, icon(o.icon)) : null,
      h('div', { className: 'pcdn-card-titles' }, o.title ? h('h3', { text: o.title }) : null, o.subtitle ? h('p', { text: o.subtitle }) : null),
      o.actions ? h('div', { className: 'pcdn-card-actions' }, o.actions) : null) : null;
    var c = h('section', { className: 'pcdn-card' + (o.cls ? ' ' + o.cls : ''), 'data-card': o.id || null }, head, body);
    c.body = body;
    return c;
  }
  /** Collapsible card (button with aria-expanded). */
  function collapsible(o) {
    var c = card({ title: o.title, subtitle: o.subtitle, icon: o.icon, tone: o.tone, cls: 'pcdn-collapsible' + (o.cls ? ' ' + o.cls : ''), id: o.id });
    var open = !!o.open;
    var head = c.querySelector('.pcdn-card-head');
    var tgl = h('button', { type: 'button', className: 'pcdn-collapse-btn', 'aria-expanded': String(open), 'data-ro-ok': '1',
      'aria-label': (open ? 'بستن ' : 'باز کردن ') + o.title }, icon('chevronDown'));
    head.appendChild(tgl);
    function set(v) {
      open = v;
      tgl.setAttribute('aria-expanded', String(open));
      c.classList.toggle('is-open', open);
      c.body.hidden = !open;
      if (open && o.onOpen) o.onOpen();
    }
    head.addEventListener('click', function (e) { if (!e.target.closest('.pcdn-card-actions')) set(!open); });
    set(open);
    c.setOpen = set;
    return c;
  }
  function empty(ic, title, text, action) {
    return h('div', { className: 'pcdn-empty' }, h('span', { className: 'pcdn-empty-icon' }, icon(ic)), h('h4', { text: title }),
      text ? h('p', { text: text }) : null, action || null);
  }
  function skeleton(lines, cls) {
    var out = h('div', { className: 'pcdn-skel-wrap' + (cls ? ' ' + cls : ''), 'aria-busy': 'true', 'aria-label': 'در حال بارگذاری' });
    for (var i = 0; i < (lines || 3); i++) out.appendChild(h('div', { className: 'pcdn-skel', style: 'width:' + (100 - (i % 3) * 18) + '%' }));
    return out;
  }
  function meter(ratio, tone) {
    ratio = Math.max(0, Math.min(1, ratio || 0));
    return h('div', { className: 'pcdn-meter', role: 'progressbar', 'aria-valuemin': '0', 'aria-valuemax': '100', 'aria-valuenow': String(Math.round(ratio * 100)) },
      h('span', { className: tone ? 'is-' + tone : '', style: 'width:' + (ratio * 100).toFixed(1) + '%' }));
  }

  // ------------------------------------------------------------------ form controls bound to a draft object
  // A form context (P.fctx) maps draft objects to their JSON path so controller
  // validation errors ({loc: [...]}) can be shown next to the right field.

  var fctx = null;
  function beginForm(draft) {
    var paths = new WeakMap();
    (function walk(o, p) {
      if (!o || typeof o !== 'object') return;
      paths.set(o, p);
      if (Array.isArray(o)) o.forEach(function (x, i) { walk(x, p === '' ? String(i) : p + '.' + i); });
      else Object.keys(o).forEach(function (k) { walk(o[k], p === '' ? k : p + '.' + k); });
    })(draft, '');
    fctx = { paths: paths, fields: {} };
    return fctx;
  }
  function endForm() { var c = fctx; fctx = null; return c; }
  function pathOf(obj, key) {
    if (!fctx || !obj || !fctx.paths.has(obj)) return null;
    var p = fctx.paths.get(obj);
    return key === undefined ? p : (p === '' ? String(key) : p + '.' + key);
  }
  function reg(path, el) { if (fctx && path !== null && path !== undefined) fctx.fields[path] = el; return el; }
  /** Put controller errors next to registered fields; returns the ones that matched nothing. */
  function placeErrors(ctx, items) {
    var rest = [];
    items.forEach(function (it) {
      var p = it.path, el = null;
      while (p !== '' && !el) {
        el = ctx.fields[p] || null;
        if (!el) p = p.indexOf('.') >= 0 ? p.slice(0, p.lastIndexOf('.')) : '';
      }
      if (!el || !document.body.contains(el)) { rest.push(it); return; }
      el.classList.add('has-error');
      Array.prototype.forEach.call(el.querySelectorAll('input,select,textarea'), function (x) { x.setAttribute('aria-invalid', 'true'); });
      el.appendChild(h('div', { className: 'pcdn-ferr', role: 'alert' }, icon('xCircle'), h('span', { text: (p !== it.path && it.label ? it.label + ': ' : '') + it.msg })));
    });
    return rest;
  }
  function clearErrors(el) {
    Array.prototype.forEach.call(el.querySelectorAll('.pcdn-ferr'), function (x) { x.parentNode.removeChild(x); });
    Array.prototype.forEach.call(el.querySelectorAll('.has-error'), function (x) { x.classList.remove('has-error'); });
    Array.prototype.forEach.call(el.querySelectorAll('[aria-invalid]'), function (x) { x.removeAttribute('aria-invalid'); });
  }

  function field(label, control, o) {
    o = o || {};
    var id = control && control.id ? control.id : null;
    if (!id && control && /^(INPUT|SELECT|TEXTAREA)$/.test(control.tagName)) { id = uid('pcdn-f-'); control.id = id; }
    var helpId = o.help ? uid('pcdn-h-') : null;
    if (helpId && control && control.setAttribute) control.setAttribute('aria-describedby', helpId);
    var el = h('div', { className: 'pcdn-field' + (o.cls ? ' ' + o.cls : '') },
      label ? h('label', { className: 'pcdn-label', 'for': id, text: label }) : null,
      o.hint ? h('span', { className: 'pcdn-hint', text: o.hint }) : null,
      control,
      o.help ? h('div', { className: 'pcdn-help', id: helpId }, o.help) : null);
    if (o.path) reg(o.path, el);
    return el;
  }

  /** Switch row: title + help on one side, a native checkbox styled as a switch on the other. */
  function toggle(obj, key, label, o) {
    o = o || {};
    var id = uid('pcdn-t-');
    var inp = h('input', { type: 'checkbox', role: 'switch', className: 'pcdn-switch', id: id, checked: !!obj[key], disabled: o.disabled,
      onchange: function (e) { obj[key] = e.target.checked; if (o.onchange) o.onchange(e.target.checked); } });
    var el = h('div', { className: 'pcdn-toggle' + (o.cls ? ' ' + o.cls : '') },
      h('label', { 'for': id, className: 'pcdn-toggle-text' }, h('span', { className: 'pcdn-toggle-title', text: label }),
        o.help ? h('span', { className: 'pcdn-help', text: o.help }) : null),
      inp);
    reg(pathOf(obj, key), el);
    return el;
  }
  /** Bare switch (no label row). */
  function switchInput(checked, label, onchange, o) {
    o = o || {};
    return h('input', { type: 'checkbox', role: 'switch', className: 'pcdn-switch' + (o.small ? ' is-sm' : ''), checked: !!checked, 'aria-label': label,
      title: o.title || label, 'data-write': o.write ? '1' : null, disabled: o.disabled, onchange: function (e) { onchange(e.target.checked, e.target); } });
  }

  function select(obj, key, label, options, o) {
    o = o || {};
    var sel = h('select', { className: 'pcdn-input' + (o.ltr ? ' pcdn-ltr' : ''), dir: o.ltr ? 'ltr' : null, 'aria-label': label || o.aria,
      onchange: function (e) {
        var opt = options[e.target.selectedIndex];
        obj[key] = opt[0];
        if (o.onchange) o.onchange(opt[0]);
      } }, options.map(function (x) {
      return h('option', { text: x[1], selected: x[0] === obj[key] || (x[0] === null && obj[key] == null) });
    }));
    if (label === null) { reg(pathOf(obj, key), sel); return sel; }
    return field(label, sel, { help: o.help, path: pathOf(obj, key), cls: o.cls });
  }

  function input(obj, key, label, o) {
    o = o || {};
    var isNum = o.type === 'number';
    var val = obj[key];
    var isLtr = o.ltr !== false;
    var el = h('input', {
      className: 'pcdn-input' + (isLtr ? ' pcdn-ltr' : ''), dir: isLtr ? 'ltr' : null, type: isNum ? 'number' : (o.type || 'text'),
      inputmode: isNum ? 'numeric' : null, min: o.min, max: o.max, step: o.step, placeholder: o.placeholder, spellcheck: 'false',
      autocomplete: 'off', 'aria-label': label === null ? (o.aria || o.placeholder) : null, maxlength: o.maxlength,
      value: val === null || val === undefined ? '' : String(val),
      oninput: function (e) {
        var v = e.target.value.trim();
        if (isNum) obj[key] = v === '' ? (o.nullable ? null : 0) : Number(v);
        else obj[key] = v === '' && o.nullable ? null : e.target.value;
        if (o.oninput) o.oninput(obj[key]);
      }
    });
    var control = el;
    if (o.suffix || o.prefix) {
      control = h('div', { className: 'pcdn-affix' }, o.prefix ? h('span', { className: 'pcdn-affix-part', dir: 'ltr', text: o.prefix }) : null, el,
        o.suffix ? h('span', { className: 'pcdn-affix-part', dir: isLtr && !o.suffixRtl ? 'ltr' : null, text: o.suffix }) : null);
    }
    if (label === null) { reg(pathOf(obj, key), control); return control; }
    return field(label, control, { help: o.help, path: pathOf(obj, key), cls: o.cls, hint: o.hint });
  }

  /** Seconds input with a live human-readable hint and quick-pick chips. */
  function duration(obj, key, label, o) {
    o = o || {};
    var hint = h('span', { className: 'pcdn-dur-hint' });
    function upd() { hint.textContent = obj[key] === null || obj[key] === undefined ? (o.nullText || '') : (Number(obj[key]) === 0 && o.zeroText ? o.zeroText : '≈ ' + dur(obj[key])); }
    var inp = input(obj, key, null, { type: 'number', min: o.min, max: o.max, nullable: o.nullable, aria: label, suffix: 'ثانیه', suffixRtl: true,
      oninput: function () { upd(); if (o.oninput) o.oninput(obj[key]); } });
    var chips = h('div', { className: 'pcdn-chips-row' }, (o.picks || []).map(function (p) {
      return h('button', { type: 'button', className: 'pcdn-chip-btn', text: p[1], 'data-write': '1', onclick: function () {
        obj[key] = p[0];
        inp.querySelector('input').value = String(p[0]);
        upd();
        if (o.oninput) o.oninput(obj[key]);
        inp.querySelector('input').dispatchEvent(new Event('change', { bubbles: true }));
      } });
    }));
    upd();
    return field(label, h('div', { className: 'pcdn-dur' }, inp, hint, (o.picks || []).length ? chips : null), { help: o.help, path: pathOf(obj, key) });
  }

  /** Tag input for a list of strings. */
  function tags(obj, key, label, o) {
    o = o || {};
    if (!Array.isArray(obj[key])) obj[key] = [];
    var list = obj[key];
    var wrap = h('div', { className: 'pcdn-tags', dir: 'ltr' });
    var inp = h('input', { className: 'pcdn-tags-input', type: 'text', dir: 'ltr', placeholder: list.length ? '' : (o.placeholder || ''),
      'aria-label': label || o.aria, spellcheck: 'false', autocomplete: 'off',
      onkeydown: function (e) {
        if (e.key === 'Enter' || e.key === ',' || e.key === '،' || (e.key === ' ' && o.space !== false)) {
          if (inp.value.trim()) { e.preventDefault(); commit(); } else if (e.key === 'Enter') e.preventDefault();
        } else if (e.key === 'Backspace' && !inp.value && list.length) {
          list.pop(); draw(); fire();
        }
      },
      onblur: function () { if (inp.value.trim()) commit(); },
      onpaste: function () { setTimeout(function () { if (/[\s,،]/.test(inp.value)) commit(); }, 0); }
    });
    function norm2(x) {
      x = x.trim();
      if (o.upper) x = x.toUpperCase();
      if (o.lower) x = x.toLowerCase();
      return x;
    }
    function commit() {
      inp.value.split(/[\s,،]+/).map(norm2).filter(Boolean).forEach(function (x) { if (list.indexOf(x) < 0) list.push(x); });
      inp.value = '';
      draw();
      fire();
    }
    function fire() { inp.dispatchEvent(new Event('change', { bubbles: true })); if (o.onchange) o.onchange(list); }
    function draw() {
      Array.prototype.slice.call(wrap.querySelectorAll('.pcdn-tag')).forEach(function (x) { wrap.removeChild(x); });
      list.forEach(function (v, i) {
        wrap.insertBefore(h('span', { className: 'pcdn-tag' }, h('span', { text: v }),
          h('button', { type: 'button', className: 'pcdn-tag-x', 'aria-label': 'حذف ' + v, 'data-write': '1', onclick: function () { list.splice(i, 1); draw(); fire(); } }, icon('x'))), inp);
      });
      inp.placeholder = list.length ? '' : (o.placeholder || '');
    }
    wrap.appendChild(inp);
    wrap.addEventListener('click', function (e) { if (e.target === wrap) inp.focus(); });
    draw();
    if (label === null) { reg(pathOf(obj, key), wrap); return wrap; }
    return field(label, wrap, { help: o.help || 'با Enter یا کاما اضافه کنید.', path: pathOf(obj, key) });
  }

  /** Radio cards: [[value, title, description, icon?, badge?]]. */
  function choice(obj, key, label, options, o) {
    o = o || {};
    var name = uid('pcdn-r-');
    var grid = h('div', { className: 'pcdn-choices' + (o.cols ? ' cols-' + o.cols : ''), role: 'radiogroup', 'aria-label': label });
    options.forEach(function (opt) {
      var id = uid('pcdn-c-');
      var inp = h('input', { type: 'radio', name: name, id: id, className: 'pcdn-choice-input', checked: obj[key] === opt[0],
        onchange: function () { obj[key] = opt[0]; if (o.onchange) o.onchange(opt[0]); } });
      grid.appendChild(h('label', { className: 'pcdn-choice', 'for': id, 'data-value': String(opt[0]) }, inp,
        h('span', { className: 'pcdn-choice-box' },
          opt[3] ? h('span', { className: 'pcdn-choice-icon' }, icon(opt[3])) : null,
          h('span', { className: 'pcdn-choice-text' }, h('span', { className: 'pcdn-choice-title' }, opt[1], opt[4] ? h('span', { className: 'pcdn-choice-badge', text: opt[4] }) : null),
            opt[2] ? h('span', { className: 'pcdn-choice-desc', text: opt[2] }) : null),
          h('span', { className: 'pcdn-choice-dot', 'aria-hidden': 'true' }))));
    });
    if (label === null) { reg(pathOf(obj, key), grid); return grid; }
    return field(label, grid, { help: o.help, path: pathOf(obj, key) });
  }

  /** Multi-select chips over a list field: [[value, label]]. */
  function checks(obj, key, label, options, o) {
    o = o || {};
    if (!Array.isArray(obj[key])) obj[key] = [];
    var box = h('div', { className: 'pcdn-checks', role: 'group', 'aria-label': label });
    options.forEach(function (opt) {
      var id = uid('pcdn-k-');
      box.appendChild(h('label', { className: 'pcdn-check', 'for': id },
        h('input', { type: 'checkbox', id: id, checked: obj[key].indexOf(opt[0]) >= 0, onchange: function (e) {
          var arr = obj[key].filter(function (x) { return x !== opt[0]; });
          if (e.target.checked) arr.push(opt[0]);
          obj[key].length = 0;
          Array.prototype.push.apply(obj[key], arr);
          if (o.onchange) o.onchange();
        } }), h('span', { className: o.ltr ? 'pcdn-ltr' : null, dir: o.ltr ? 'ltr' : null, text: opt[1] })));
    });
    if (label === null) return box;
    return field(label, box, { help: o.help, path: pathOf(obj, key) });
  }

  function textarea(obj, key, label, o) {
    o = o || {};
    var ta = h('textarea', { className: 'pcdn-input pcdn-mono', dir: 'ltr', rows: o.rows || 4, placeholder: o.placeholder, spellcheck: 'false',
      value: obj[key] === null || obj[key] === undefined ? '' : String(obj[key]),
      oninput: function (e) { obj[key] = o.nullable && e.target.value.trim() === '' ? null : e.target.value; if (o.oninput) o.oninput(); } });
    if (label === null) return ta;
    return field(label, ta, { help: o.help, path: pathOf(obj, key) });
  }

  /** Segmented control (period switch etc.). */
  function segmented(options, value, onpick, aria) {
    return h('div', { className: 'pcdn-seg', role: 'group', 'aria-label': aria }, options.map(function (o) {
      return h('button', { type: 'button', className: 'pcdn-seg-btn' + (o[0] === value ? ' is-active' : ''), 'aria-pressed': o[0] === value ? 'true' : 'false',
        'data-value': o[0], 'data-ro-ok': '1', text: o[1], onclick: function () { onpick(o[0]); } });
    }));
  }

  // ------------------------------------------------------------------ theme: blend into the host page
  //
  // The app has no page background of its own. PCDN.theme reads the host page around #pcdn-app —
  // background (colour or gradient), text colour, primary colour and font — decides light/dark and
  // derives the neutral + brand tokens from it (set inline on the app root and the overlay layer),
  // so our cards look like the host theme's own cards. Mode: data-theme="auto|light|dark" on
  // #pcdn-app (templates/clientarea.tpl) or boot.theme; default "auto". It re-checks when the host
  // toggles a class/style/data-theme on <html>/<body>, on prefers-color-scheme changes and on load.

  var theme = (function () {
    var WHITE = [255, 255, 255, 1], BLACK = [0, 0, 0, 1], INK = [11, 18, 32, 1];
    var PERSIAN = /vazir|iran\s?sans|iransans|yekan|shabnam|sahel|samim|tanha|dana|peyda|estedad|kalameh|morabba|irancell|parastoo|nahid|gandom/i;
    var targets = [], rootEl = null, mode = 'auto', applied = {}, attr = null, last = '', timer = null, cvs = null, watching = false;

    function parse(str) {
      str = String(str || '').trim();
      if (!str || str === 'transparent' || str === 'none') return null;
      var m = str.match(/^rgba?\(\s*([\d.]+)[\s,]+([\d.]+)[\s,]+([\d.]+)(?:\s*[,/]\s*([\d.]+%?))?\s*\)$/i);
      if (m) return [+m[1], +m[2], +m[3], m[4] === undefined ? 1 : m[4].slice(-1) === '%' ? parseFloat(m[4]) / 100 : +m[4]];
      m = str.match(/^#([0-9a-f]{3,8})$/i);
      if (m) {
        var x = m[1];
        if (x.length < 6) x = x.split('').map(function (c) { return c + c; }).join('');
        return [parseInt(x.slice(0, 2), 16), parseInt(x.slice(2, 4), 16), parseInt(x.slice(4, 6), 16), x.length === 8 ? parseInt(x.slice(6, 8), 16) / 255 : 1];
      }
      try { // oklch(), color(srgb …), hsl(), names: let a canvas normalise it
        cvs = cvs || document.createElement('canvas');
        cvs.width = cvs.height = 1;
        var cx = cvs.getContext('2d');
        if (!cx) return null;
        cx.fillStyle = '#010203'; cx.fillStyle = str;
        if (cx.fillStyle === '#010203') return null;
        cx.clearRect(0, 0, 1, 1); cx.fillRect(0, 0, 1, 1);
        var d = cx.getImageData(0, 0, 1, 1).data;
        return [d[0], d[1], d[2], d[3] / 255];
      } catch (e) { return null; }
    }
    function lin(v) { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }
    function lum(c) { return 0.2126 * lin(c[0]) + 0.7152 * lin(c[1]) + 0.0722 * lin(c[2]); }
    function contrast(a, b) { var x = lum(a), y = lum(b); return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05); }
    function mix(a, b, t) { return [0, 1, 2].map(function (i) { return a[i] + (b[i] - a[i]) * t; }).concat([1]); }
    function over(top, bot) {
      var a = top[3] + bot[3] * (1 - top[3]);
      if (!a) return [0, 0, 0, 0];
      return [0, 1, 2].map(function (i) { return (top[i] * top[3] + bot[i] * bot[3] * (1 - top[3])) / a; }).concat([a]);
    }
    function hex(c) { return '#' + c.slice(0, 3).map(function (v) { var s2 = Math.max(0, Math.min(255, Math.round(v))).toString(16); return s2.length < 2 ? '0' + s2 : s2; }).join(''); }
    function rgba(c, a) { return 'rgba(' + c.slice(0, 3).map(Math.round).join(', ') + ', ' + a + ')'; }
    function chroma(c) { return Math.max(c[0], c[1], c[2]) - Math.min(c[0], c[1], c[2]); }
    /** Worst contrast of fg against a list of backgrounds. */
    function worst(fg, bgs) { return Math.min.apply(null, bgs.map(function (b) { return contrast(fg, b); })); }
    /** Move fg toward `to` until it reaches `ratio` against every bg. */
    function ensure(fg, bgs, ratio, to) {
      for (var i = 0; i < 25 && worst(fg, bgs) < ratio; i++) fg = mix(fg, to, 0.08);
      return fg;
    }

    /** Average colour of a CSS gradient (computed background-image), or null. */
    function gradient(img) {
      if (!img || img === 'none' || img.indexOf('gradient') < 0) return null;
      var list = img.match(/rgba?\([^)]*\)|#[0-9a-f]{3,8}\b|(?:color|oklch|oklab|lab|lch|hsla?)\([^)]*\)/gi) || [];
      var acc = [0, 0, 0], w = 0, n = 0;
      list.forEach(function (x) { var c = parse(x); if (c) { n++; if (c[3] > 0) { acc[0] += c[0] * c[3]; acc[1] += c[1] * c[3]; acc[2] += c[2] * c[3]; w += c[3]; } } });
      return w ? [acc[0] / w, acc[1] / w, acc[2] / w, Math.min(1, w / n)] : null;
    }
    /** Painted background of one element (gradient over colour), or null. */
    function paintOf(el) {
      var cs = window.getComputedStyle(el), c = parse(cs.backgroundColor), g = gradient(cs.backgroundImage);
      if (c && c[3] < 0.02) c = null;
      return g && c ? over(g, c) : g || c;
    }
    /** First (composited) non-transparent background from `el` upwards. */
    function hostBg(el) {
      var layers = [];
      for (; el && el.nodeType === 1; el = el.parentElement) {
        var p = paintOf(el);
        if (p) { layers.push(p); if (p[3] >= 0.98) break; }
      }
      if (!layers.length) return null;
      var res = layers[layers.length - 1][3] >= 0.98 ? layers.pop() : WHITE;
      while (layers.length) res = over(layers.pop(), res);
      return res.slice(0, 3).concat([1]);
    }
    function inApp(el) { return !!(el.closest && el.closest('#pcdn-app, #pcdn-layer')); }
    /** The host's primary colour: a real .btn-primary (what users see, incl. custom.css), the Bootstrap vars, or a hidden probe. */
    function hostBrand(host) {
      function ok(c) { return c && c[3] > 0.5 && chroma(c) >= 24 ? c.slice(0, 3).concat([1]) : null; }
      var list = document.querySelectorAll('.btn-primary'), c = null, i;
      for (i = 0; i < list.length && i < 20 && !c; i++) if (!inApp(list[i])) c = ok(paintOf(list[i]));
      if (c) return c;
      var st = [window.getComputedStyle(document.documentElement), document.body ? window.getComputedStyle(document.body) : null];
      ['--bs-primary', '--primary'].forEach(function (v) { st.forEach(function (x) { if (!c && x) c = ok(parse(x.getPropertyValue(v))); }); });
      if (c) return c;
      try {
        var probe = document.createElement('button');
        probe.type = 'button'; probe.className = 'btn btn-primary'; probe.tabIndex = -1;
        probe.setAttribute('aria-hidden', 'true');
        probe.style.cssText = 'position:absolute;visibility:hidden;pointer-events:none;left:-9999px;top:0';
        probe.textContent = 'x';
        (host || document.body).appendChild(probe);
        c = ok(paintOf(probe));
        probe.parentNode.removeChild(probe);
      } catch (e) { c = null; }
      return c;
    }
    /** A host card colour (.card / .panel outside the app) when it clearly is one. */
    function hostCard(bg, dark) {
      var list = document.querySelectorAll('.card, .panel'), i, c;
      for (i = 0; i < list.length && i < 30; i++) {
        if (inApp(list[i]) || list[i].contains(rootEl)) continue;
        c = paintOf(list[i]);
        if (!c || c[3] < 0.98) continue;
        var L = lum(c);
        if (dark ? (L < 0.2 && L >= lum(bg) && contrast(c, bg) < 1.8) : (L > 0.75 && contrast(c, bg) < 1.35)) return c.slice(0, 3).concat([1]);
        return null;
      }
      return null;
    }

    function derive(bg, fg, dark, brandC, card) {
      var v = {}, surface, s2, text;
      if (dark) {
        surface = card && lum(card) > lum(bg) + 0.002 ? card : mix(bg, WHITE, 0.055);
        text = fg && lum(fg) > 0.55 && contrast(fg, surface) >= 7 ? fg : [231, 235, 242, 1];
        s2 = mix(surface, WHITE, 0.03);
        v.elevated = mix(surface, WHITE, 0.03);
        v.hover = mix(surface, text, 0.06);
        v.fill = mix(surface, text, 0.07);
        v['fill-2'] = mix(surface, text, 0.09);
        v['row-hover'] = mix(surface, text, 0.03);
        v['seg-bg'] = mix(surface, BLACK, 0.28);
        v.border = mix(bg, text, 0.14);
        v['border-strong'] = mix(bg, text, 0.24);
        v['border-hover'] = mix(bg, text, 0.34);
        v['input-bg'] = mix(surface, BLACK, 0.14);
        v['switch-off'] = mix(surface, text, 0.3);
        v.knob = mix(text, WHITE, 0.3);
        v.track = mix(surface, text, 0.12);
        v.handle = v['border-strong'];
        v['skel-a'] = mix(surface, text, 0.07);
        v['skel-b'] = mix(surface, text, 0.12);
        v.grid = mix(surface, text, 0.09);
        v.baseline = mix(surface, text, 0.2);
        v.cross = mix(surface, text, 0.4);
        v['tip-bg'] = mix(bg, WHITE, 0.13);
        v['tip-border'] = v['border-strong'];
        v['code-bg'] = mix(bg, BLACK, 0.35);
        v['code-head'] = mix(v['code-bg'], WHITE, 0.05);
        v['code-border'] = v.border;
        v['code-line'] = mix(v['code-bg'], WHITE, 0.16);
        v['inv-bg'] = mix(bg, WHITE, 0.13);
        v['inv-bg-2'] = mix(bg, WHITE, 0.09);
        v['inv-edge'] = v['border-strong'];
      } else {
        surface = card || (lum(bg) > 0.97 ? bg : mix(bg, WHITE, 0.65));
        text = fg && lum(fg) < 0.2 && contrast(fg, surface) >= 7 ? fg : [15, 23, 42, 1];
        var base = mix(surface, bg, 0.45);
        s2 = mix(base, text, 0.018);
        v.elevated = surface;
        v.hover = mix(base, text, 0.04);
        v.fill = mix(base, text, 0.045);
        v['fill-2'] = mix(base, text, 0.06);
        v['row-hover'] = mix(surface, text, 0.015);
        v['seg-bg'] = mix(base, text, 0.09);
        v.border = mix(base, text, 0.11);
        v['border-strong'] = mix(surface, text, 0.2);
        v['border-hover'] = mix(surface, text, 0.32);
        v['input-bg'] = surface;
        v['switch-off'] = mix(surface, text, 0.27);
        v.track = mix(base, text, 0.08);
        v.handle = mix(surface, text, 0.16);
        v['skel-a'] = mix(surface, text, 0.07);
        v['skel-b'] = mix(surface, text, 0.035);
        v.grid = mix(surface, text, 0.07);
        v.baseline = mix(surface, text, 0.18);
        v.cross = mix(surface, text, 0.4);
      }
      v.surface = surface;
      v['surface-2'] = s2;
      v.text = ensure(text, [surface, s2, v.fill, v.hover], 7, dark ? WHITE : BLACK);
      v['input-disabled'] = v.fill;
      var backs = [surface, s2, v.fill, v['fill-2'], v.hover, v.elevated];
      v['text-2'] = ensure(mix(v.text, surface, 0.16), backs, 7, dark ? WHITE : BLACK);
      v.muted = ensure(mix(v.text, surface, 0.4), backs, 4.6, dark ? WHITE : BLACK);
      v.faint = ensure(mix(v.text, surface, 0.52), [surface, v['input-bg']], 3.2, dark ? WHITE : BLACK);
      v.axis = v.muted;
      if (dark) {
        v['tip-fg'] = v.text;
        v['tip-label'] = ensure(v['text-2'], [v['tip-bg']], 7, WHITE);
        v['tip-muted'] = ensure(v.muted, [v['tip-bg']], 4.6, WHITE);
      }

      // brand
      var b = brandC || [29, 95, 214, 1];
      if (dark && contrast(b, surface) < 2) b = ensure(b, [surface], 2, WHITE);
      var on = WHITE;
      if (contrast(WHITE, b) < 4.5) {
        var d0 = b, k = 0;
        while (contrast(WHITE, d0) < 4.5 && k < 4) { d0 = mix(d0, BLACK, 0.06); k++; }
        if (contrast(WHITE, d0) >= 4.5) b = d0; else on = ensure(INK, [b], 4.5, BLACK);
      }
      v.brand = b;
      v['on-brand'] = on;
      v['brand-hover'] = on === WHITE ? mix(b, BLACK, 0.14) : mix(b, WHITE, 0.16);
      v['brand-lite'] = mix(b, WHITE, 0.18);
      v['brand-deep'] = mix(b, BLACK, 0.22);
      v['brand-50'] = mix(surface, b, dark ? 0.16 : 0.08);
      v['brand-100'] = mix(surface, b, dark ? 0.32 : 0.2);
      var lb = [surface, s2, v['brand-50'], v.hover, v.elevated];
      v.link = ensure(b, lb, 4.6, dark ? WHITE : BLACK);
      v['brand-600'] = ensure(mix(v.link, dark ? WHITE : BLACK, 0.12), lb, 4.6, dark ? WHITE : BLACK);
      v['info-strong'] = ensure(mix(b, dark ? WHITE : BLACK, 0.45), [v['brand-50'], surface], 6, dark ? WHITE : BLACK);
      v['hero-end'] = mix(surface, b, dark ? 0.12 : 0.07);
      v['guide-a'] = mix(surface, b, dark ? 0.04 : 0.015);
      v['guide-b'] = mix(surface, b, dark ? 0.09 : 0.05);
      v['upgrade-end'] = mix(surface, [139, 92, 246, 1], dark ? 0.12 : 0.05);
      v.ring = '0 0 0 3px ' + rgba(dark ? v.link : b, dark ? 0.45 : 0.32);
      v['brand-glow'] = dark ? 'rgba(0, 0, 0, .35)' : rgba(b, 0.28);
      v.page = bg;
      var out = {};
      Object.keys(v).forEach(function (key) { out['--pc-' + key] = Array.isArray(v[key]) ? hex(v[key]) : v[key]; });
      return out;
    }

    function detect() {
      if (!rootEl) return;
      var host = rootEl.parentElement || document.body;
      var bg = hostBg(host), fgRaw = parse(window.getComputedStyle(host).color);
      var fg = fgRaw && fgRaw[3] > 0.3 ? fgRaw.slice(0, 3).concat([1]) : null;
      var brandC = hostBrand(host), dark, forced = mode === 'light' || mode === 'dark';
      if (forced) {
        dark = mode === 'dark';
        bg = dark ? [17, 24, 39, 1] : [243, 245, 249, 1];
        fg = null;
      } else {
        var fgL = fg ? lum(fg) : null, bgL = bg ? lum(bg) : null;
        if (fgL !== null && fgL > 0.5) dark = true;          // light text: dark theme whatever the walk found
        else if (fgL !== null && fgL < 0.1) dark = false;    // dark text: light theme
        else dark = bgL !== null && bgL < 0.18;
        if (dark && (bgL === null || bgL > 0.12)) {          // signals disagree / gradient we could not read: synthesise
          var hue = brandC || [30, 41, 90, 1];
          bg = mix([17, 24, 39, 1], hue, 0.12);
        }
        if (!dark && (bgL === null || bgL < 0.35)) bg = [248, 250, 252, 1];
      }
      var card = forced ? null : hostCard(bg, dark);
      var vars = derive(bg, fg, dark, brandC, card);
      var ff = window.getComputedStyle(host).fontFamily || '';
      if (PERSIAN.test(ff)) vars['--pc-font'] = ff + ", 'PCDN Vazirmatn', Tahoma, sans-serif";
      var key = JSON.stringify(vars) + dark + forced;
      if (key === last) return;
      last = key;
      applied = vars;
      attr = dark ? 'dark' : 'light';
      targets.forEach(paint);
      rootEl.classList.toggle('pcdn-framed', forced);
    }
    function paint(el) {
      var old = el.getAttribute('data-pcdn-vars');
      if (old) old.split(' ').forEach(function (k) { if (!(k in applied)) el.style.removeProperty(k); });
      Object.keys(applied).forEach(function (k) { el.style.setProperty(k, applied[k]); });
      el.setAttribute('data-pcdn-vars', Object.keys(applied).join(' '));
      if (attr) el.setAttribute('data-pcdn-theme', attr);
    }
    function schedule() { clearTimeout(timer); timer = setTimeout(detect, 120); }
    function hostSig() {
      return [document.documentElement, document.body].map(function (el) {
        return el ? ['class', 'style', 'data-theme', 'data-bs-theme', 'data-mode', 'data-color-scheme'].map(function (a) {
          var x = el.getAttribute(a) || '';
          return a === 'class' ? x.split(/\s+/).filter(function (c) { return c.indexOf('pcdn-') !== 0; }).join(' ') : x;
        }).join('|') : '';
      }).join('#');
    }
    function watch() {
      if (watching) return;
      watching = true;
      var sig = hostSig();
      if (window.MutationObserver) {
        var mo = new window.MutationObserver(function () { var s2 = hostSig(); if (s2 !== sig) { sig = s2; schedule(); } });
        var opts = { attributes: true, attributeFilter: ['class', 'style', 'data-theme', 'data-bs-theme', 'data-mode', 'data-color-scheme'] };
        mo.observe(document.documentElement, opts);
        if (document.body) mo.observe(document.body, opts);
      }
      if (window.matchMedia) {
        var mq = window.matchMedia('(prefers-color-scheme: dark)');
        if (mq.addEventListener) mq.addEventListener('change', schedule); else if (mq.addListener) mq.addListener(schedule);
      }
      if (document.readyState !== 'complete') window.addEventListener('load', schedule);
    }
    return {
      /** Start theming `root`; `pref` = "auto" | "light" | "dark" (data-theme on the root wins). */
      init: function (root, pref) {
        rootEl = root;
        var m = String(root.getAttribute('data-theme') || pref || 'auto').toLowerCase();
        mode = m === 'light' || m === 'dark' ? m : 'auto';
        if (targets.indexOf(root) < 0) targets.push(root);
        try { detect(); } catch (e) { root.setAttribute('data-pcdn-theme', 'light'); }
        watch();
      },
      /** Give another .pcdn element (the overlay layer) the same palette. */
      attach: function (el) { if (targets.indexOf(el) < 0) { targets.push(el); if (attr) paint(el); } },
      refresh: detect,
      current: function () { return { theme: attr, mode: mode, vars: applied }; },
      _util: { parse: parse, lum: lum, contrast: contrast, mix: mix, hex: hex }
    };
  })();

  // ------------------------------------------------------------------ export

  var K = {
    h: h, s: s, append: append, clear: clear, ltr: ltr, code: code, clone: clone, uid: uid, icon: icon, ICONS: ICONS,
    fa: fa, num: num, num1: num1, bytes: bytes, short: short, pct: pct, dur: dur, date: date, rel: rel, norm: norm, country: country,
    store: store, CFG: CFG, api: api, parseErrors: parseErrors, errorText: errorText, errorBox: errorBox,
    toast: toast, dialog: dialog, confirm: confirmDlg, btn: btn, iconBtn: iconBtn, busy: busy, copyText: copyText, copyBtn: copyBtn,
    copyable: copyable, badge: badge, alertBox: alertBox, card: card, collapsible: collapsible, empty: empty, skeleton: skeleton, meter: meter,
    beginForm: beginForm, endForm: endForm, pathOf: pathOf, reg: reg, placeErrors: placeErrors, clearErrors: clearErrors,
    field: field, toggle: toggle, switchInput: switchInput, select: select, input: input, duration: duration, tags: tags,
    choice: choice, checks: checks, textarea: textarea, segmented: segmented, getLayer: getLayer, theme: theme
  };
  Object.keys(K).forEach(function (k) { P[k] = K[k]; });
})();
