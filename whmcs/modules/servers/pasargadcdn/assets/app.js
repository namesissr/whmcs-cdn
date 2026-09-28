/*
 * Pasargad CDN — client-area app (vanilla JS, no dependencies).
 *
 * Boot data comes from <script id="pcdn-boot"> (see pasargadcdn_ClientArea);
 * every call goes through api.php, which pins the request to this service's
 * domain. Data is only ever inserted with textContent / createElement.
 */
(function () {
  'use strict';

  var root = document.getElementById('pcdn-app');
  if (!root) return;
  var boot = {};
  try { boot = JSON.parse(document.getElementById('pcdn-boot').textContent || '{}'); } catch (e) { /* shown below */ }
  var API = root.getAttribute('data-api');
  var CSRF = root.getAttribute('data-csrf');
  var WEBROOT = API.replace(/modules\/servers\/pasargadcdn\/api\.php$/, '');

  var S = {
    site: boot.site || null,
    error: boot.error || (boot.serviceId ? null : 'داده اولیه نامعتبر است'),
    active: !!boot.active,
    tab: 'overview',
    flash: null,        // {key, msg} success message shown once after a re-render
    dnssec: null,
    analytics: {},
    period: '24h',
    events: null
  };
  try { S.tab = sessionStorage.getItem('pcdn-tab-' + boot.serviceId) || 'overview'; } catch (e) { /* private mode */ }

  // ------------------------------------------------------------------ DOM helpers

  function h(tag, props) {
    var el = document.createElement(tag);
    props = props || {};
    Object.keys(props).forEach(function (k) {
      var v = props[k];
      if (v === null || v === undefined || v === false) return;
      if (k === 'text') el.textContent = String(v);
      else if (k === 'className') el.className = v;
      else if (k.slice(0, 2) === 'on') el.addEventListener(k.slice(2), v);
      else if (k === 'value' || k === 'checked' || k === 'disabled' || k === 'selected') el[k] = v;
      else el.setAttribute(k, v === true ? '' : String(v));
    });
    for (var i = 2; i < arguments.length; i++) append(el, arguments[i]);
    return el;
  }

  function append(el, c) {
    if (c === null || c === undefined || c === false) return;
    if (Array.isArray(c)) { c.forEach(function (x) { append(el, x); }); return; }
    el.appendChild(typeof c === 'object' ? c : document.createTextNode(String(c)));
  }

  var SVGNS = 'http://www.w3.org/2000/svg';
  function s(tag, attrs, text) {
    var el = document.createElementNS(SVGNS, tag);
    Object.keys(attrs || {}).forEach(function (k) { el.setAttribute(k, String(attrs[k])); });
    if (text !== undefined) el.textContent = String(text);
    return el;
  }

  function clone(o) { return JSON.parse(JSON.stringify(o)); }
  function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }
  function ltr(t, cls) { return h('span', { className: 'pcdn-ltr' + (cls ? ' ' + cls : ''), dir: 'ltr', text: t }); }

  var nf = window.Intl ? new Intl.NumberFormat('fa-IR') : null;
  function num(n) { n = Number(n) || 0; return nf ? nf.format(n) : String(n); }
  function bytes(b) {
    b = Number(b) || 0;
    var u = ['B', 'KB', 'MB', 'GB', 'TB'], i = 0;
    while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
    return (i ? b.toFixed(b < 10 ? 2 : 1) : String(b)) + ' ' + u[i];
  }
  function pct(a, b) { return b > 0 ? Math.round(a * 100 / b) + '%' : '—'; }
  function short(n) {
    n = Number(n) || 0;
    if (n >= 1e9) return (n / 1e9).toFixed(1).replace(/\.0$/, '') + 'B';
    if (n >= 1e6) return (n / 1e6).toFixed(1).replace(/\.0$/, '') + 'M';
    if (n >= 1e3) return (n / 1e3).toFixed(1).replace(/\.0$/, '') + 'K';
    return String(Math.round(n));
  }
  function date(iso, opts) {
    if (!iso) return '—';
    var d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso);
    try { return d.toLocaleString('fa-IR', opts || { dateStyle: 'medium', timeStyle: 'short' }); } catch (e) { return d.toISOString(); }
  }
  function uid(prefix) { return prefix + Math.random().toString(36).slice(2, 8); }

  // ------------------------------------------------------------------ API

  function api(method, path, body, query) {
    var url = API + '?id=' + encodeURIComponent(boot.serviceId) + '&path=' + encodeURIComponent(path);
    Object.keys(query || {}).forEach(function (k) { url += '&' + encodeURIComponent(k) + '=' + encodeURIComponent(query[k]); });
    var init = { method: method, credentials: 'same-origin', headers: { 'X-PCDN-CSRF': CSRF, 'Accept': 'application/json' } };
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

  /** Controller errors: {"detail": "..."} or FastAPI's [{"loc": [...], "msg": "..."}]. */
  function errorNode(data, status) {
    var d = data && data.detail;
    if (Array.isArray(d)) {
      return h('div', null, 'اطلاعات واردشده معتبر نیست:',
        h('ul', { className: 'pcdn-errlist' }, d.map(function (e) {
          var loc = Array.isArray(e.loc) ? e.loc.filter(function (x) { return x !== 'body'; }).join(' › ') : '';
          return h('li', null, loc ? ltr(loc, 'pcdn-muted') : null, loc ? ': ' : null, String(e.msg || ''));
        })));
    }
    if (typeof d === 'string' && d) return h('div', { text: d });
    return h('div', { text: 'خطای ناشناخته (HTTP ' + status + ')' });
  }

  /** A feedback slot placed next to a form's buttons. */
  function feedback(key) {
    var el = h('div', { className: 'pcdn-fb', role: 'status' });
    if (S.flash && S.flash.key === key) { show(el, true, S.flash.msg); S.flash = null; }
    return el;
  }
  function show(el, ok, content) {
    clear(el);
    el.className = 'pcdn-fb pcdn-alert ' + (ok ? 'pcdn-alert-success' : 'pcdn-alert-danger');
    append(el, content);
  }

  /** Runs an API call from a button: busy state + error display. */
  function run(btn, fb, promise, onOk) {
    if (btn) { btn.disabled = true; btn.classList.add('pcdn-busy'); }
    if (fb) { clear(fb); fb.className = 'pcdn-fb'; }
    return promise.then(function (res) {
      if (btn) { btn.disabled = false; btn.classList.remove('pcdn-busy'); }
      if (!res.ok) { if (fb) show(fb, false, errorNode(res.data, res.status)); return; }
      onOk(res.data);
    });
  }

  function reloadSite(flashKey, msg) {
    return api('GET', '').then(function (res) {
      if (res.ok) { S.site = res.data; S.error = null; }
      else S.error = errorNode(res.data, res.status).textContent;
      if (flashKey) S.flash = { key: flashKey, msg: msg };
      render();
    });
  }

  // ------------------------------------------------------------------ form helpers (bound to a draft object)

  function field(label, control, help) {
    return h('div', { className: 'pcdn-field' },
      h('label', null, h('span', { className: 'pcdn-label', text: label }), control),
      help ? h('small', { className: 'pcdn-help', text: help }) : null);
  }
  function check(obj, key, label, help, onchange) {
    return h('div', { className: 'pcdn-field pcdn-check' },
      h('label', null, h('input', { type: 'checkbox', checked: !!obj[key], onchange: function (e) { obj[key] = e.target.checked; if (onchange) onchange(); } }), ' ', label),
      help ? h('small', { className: 'pcdn-help', text: help }) : null);
  }
  function select(obj, key, label, options, help, onchange) {
    var sel = h('select', { className: 'pcdn-input', onchange: function (e) {
      var o = options[e.target.selectedIndex];
      obj[key] = o[0];
      if (onchange) onchange();
    } }, options.map(function (o) { return h('option', { text: o[1], selected: o[0] === obj[key] || (o[0] === null && obj[key] == null) }); }));
    return label === null ? sel : field(label, sel, help);
  }
  function input(obj, key, label, o) {
    o = o || {};
    var isNum = o.type === 'number';
    var val = obj[key];
    var el = h('input', {
      className: 'pcdn-input' + (o.ltr !== false ? ' pcdn-ltr' : ''), dir: o.ltr !== false ? 'ltr' : null,
      type: isNum ? 'number' : 'text', min: o.min, max: o.max, placeholder: o.placeholder,
      value: val === null || val === undefined ? '' : String(val),
      oninput: function (e) {
        var v = e.target.value.trim();
        if (isNum) obj[key] = v === '' ? (o.nullable ? null : 0) : Number(v);
        else obj[key] = v === '' && o.nullable ? null : e.target.value;
      }
    });
    return label === null ? el : field(label, el, o.help);
  }
  /** Textarea editing a list of strings (one per line, or comma separated). */
  function list(obj, key, label, o) {
    o = o || {};
    var ta = h('textarea', {
      className: 'pcdn-input pcdn-ltr', dir: 'ltr', rows: o.rows || 3, placeholder: o.placeholder,
      value: (obj[key] || []).join(o.comma ? ', ' : '\n'),
      oninput: function (e) {
        obj[key] = e.target.value.split(o.comma ? /[\s,]+/ : /\n+/).map(function (x) { return x.trim(); })
          .filter(Boolean).map(function (x) { return o.upper ? x.toUpperCase() : o.lower ? x.toLowerCase() : x; });
      }
    });
    return field(label, ta, o.help);
  }

  function card(title, extra) {
    var body = h('div', { className: 'pcdn-card-body' });
    var c = h('section', { className: 'pcdn-card' },
      h('header', { className: 'pcdn-card-head' }, h('h3', { text: title }), extra || null), body);
    c.body = body;
    return c;
  }
  function btn(text, cls, onclick, write) {
    return h('button', { type: 'button', className: 'pcdn-btn ' + (cls || ''), text: text, onclick: onclick, 'data-write': write ? '1' : null });
  }
  function iconBtn(text, title, onclick) {
    return h('button', { type: 'button', className: 'pcdn-btn pcdn-btn-icon', text: text, title: title, 'aria-label': title, onclick: onclick, 'data-write': '1' });
  }
  function alertBox(kind, content) { return h('div', { className: 'pcdn-alert pcdn-alert-' + kind }, content); }

  // ------------------------------------------------------------------ plan / sections

  function features() { return (S.site && S.site.plan && S.site.plan.features) || {}; }

  var DEFAULTS = {
    cache: { enabled: true, dev_mode: false, level: 'standard', edge_ttl: 86400, browser_ttl: 0, ignore_query: false, bypass_cookies: [], always_online: true },
    ssl: { force_https: false, hsts: { enabled: false, max_age: 31536000, include_subdomains: false, preload: false }, min_tls: '1.2', origin_protocol: 'http', origin_verify: false },
    waf: { mode: 'off', paranoia: 1, groups: ['sqli', 'xss', 'lfi', 'rce', 'php', 'scanner', 'protocol'], exclusions: [] },
    ddos: { mode: 'off', threshold_rps: 200, clearance_ttl: 3600 },
    firewall: { default_action: 'allow', rules: [] },
    ratelimit: { rules: [] },
    pagerules: { rules: [] },
    pools: { pools: [] },
    headers: { request: [], response: [] },
    hotlink: { enabled: false, extensions: ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'mp4'], allowed_referers: [], allow_empty: true },
    image: { enabled: false, quality: 85, max_width: 2000 },
    errorpages: { '5xx': null, '4xx': null }
  };
  function config(section) {
    var c = S.site && S.site.config && S.site.config[section];
    return clone(c || DEFAULTS[section]);
  }

  /** Standard "edit a config section" card with a save button. */
  function sectionCard(section, title, build, opts) {
    opts = opts || {};
    var draft = config(section);
    var c = card(title);
    var fields = h('div', { className: 'pcdn-form' });
    var fb = feedback(section);
    function redraw() { clear(fields); append(fields, build(draft, redraw)); lockWrites(fields); }
    redraw();
    var save = btn('ذخیره تغییرات', 'pcdn-btn-primary', function () {
      var body = opts.serialize ? opts.serialize(clone(draft)) : draft;
      run(save, fb, api('PUT', 'config/' + section, body), function (data) {
        S.site.config = S.site.config || {};
        S.site.config[section] = data;
        S.flash = { key: section, msg: 'تغییرات ذخیره شد.' };
        render();
      });
    }, true);
    append(c.body, [opts.intro ? h('p', { className: 'pcdn-muted', text: opts.intro }) : null, fields,
      h('div', { className: 'pcdn-actions' }, save), fb]);
    return c;
  }

  function limitNote(n, max, what) {
    return h('p', { className: 'pcdn-muted' }, what + ': ', ltr(num(n) + ' / ' + num(max)));
  }

  function move(arr, i, d) {
    var j = i + d;
    if (j < 0 || j >= arr.length) return;
    var t = arr[i]; arr[i] = arr[j]; arr[j] = t;
  }

  /** ↑ ↓ ✕ controls for an ordered list item. */
  function orderControls(arr, i, redraw) {
    return h('span', { className: 'pcdn-order' },
      iconBtn('↑', 'بالا', function () { move(arr, i, -1); redraw(); }),
      iconBtn('↓', 'پایین', function () { move(arr, i, 1); redraw(); }),
      iconBtn('✕', 'حذف', function () { arr.splice(i, 1); redraw(); }));
  }

  // ------------------------------------------------------------------ tabs

  var TABS = [
    { id: 'overview', title: 'نمای کلی', render: renderOverview },
    { id: 'dns', title: 'DNS', render: renderDns },
    { id: 'cache', title: 'کش', render: renderCache },
    { id: 'ssl', title: 'SSL/TLS', render: renderSsl },
    { id: 'firewall', title: 'فایروال', render: renderFirewall, feature: function (f) { return f.max_firewall_rules > 0; } },
    { id: 'waf', title: 'WAF', render: renderWaf, feature: function (f) { return !!f.waf; } },
    { id: 'ddos', title: 'حفاظت DDoS', render: renderDdos, feature: function (f) { return !!f.ddos; } },
    { id: 'ratelimit', title: 'محدودیت نرخ', render: renderRatelimit, feature: function (f) { return f.max_ratelimit_rules > 0; } },
    { id: 'pagerules', title: 'قوانین صفحه', render: renderPagerules, feature: function (f) { return f.max_page_rules > 0; } },
    { id: 'pools', title: 'توزیع بار', render: renderPools, feature: function (f) { return !!f.load_balancer && f.max_pools > 0; } },
    { id: 'headers', title: 'هدرها', render: renderHeaders },
    { id: 'hotlink', title: 'Hotlink', render: renderHotlink },
    { id: 'image', title: 'بهینه‌سازی تصویر', render: renderImage, feature: function (f) { return !!f.image_optimization; } },
    { id: 'errorpages', title: 'صفحات خطا', render: renderErrorpages },
    { id: 'analytics', title: 'آنالیتیکس', render: renderAnalytics },
    { id: 'events', title: 'رویدادهای امنیتی', render: renderEvents }
  ];

  function tabLocked(t) { return t.feature ? !t.feature(features()) : false; }

  function setTab(id) {
    S.tab = id;
    try { sessionStorage.setItem('pcdn-tab-' + boot.serviceId, id); } catch (e) { /* ignore */ }
    render();
  }

  function render() {
    clear(root);
    if (!S.site) {
      append(root, alertBox('danger', [h('div', { text: 'خطا در دریافت اطلاعات CDN: ' + (S.error || '') }),
        btn('تلاش دوباره', 'pcdn-btn-sm', function (e) { e.target.disabled = true; reloadSite(); })]));
      return;
    }
    var tab = TABS.filter(function (t) { return t.id === S.tab; })[0] || TABS[0];
    S.tab = tab.id;

    var nav = h('nav', { className: 'pcdn-tabs', role: 'tablist' }, TABS.map(function (t) {
      var locked = tabLocked(t);
      return h('button', {
        type: 'button', role: 'tab', 'aria-selected': t.id === tab.id ? 'true' : 'false',
        className: 'pcdn-tab' + (t.id === tab.id ? ' is-active' : '') + (locked ? ' is-locked' : ''),
        title: locked ? 'در پلن شما فعال نیست' : null, 'data-tab': t.id,
        onclick: function () { setTab(t.id); }
      }, t.title, locked ? h('span', { className: 'pcdn-lock', 'aria-hidden': 'true', text: ' 🔒' }) : null);
    }));
    var picker = h('select', { className: 'pcdn-input pcdn-tabpicker', 'aria-label': 'بخش', 'data-ro-ok': '1',
      onchange: function (e) { setTab(TABS[e.target.selectedIndex].id); } },
    TABS.map(function (t) { return h('option', { text: t.title + (tabLocked(t) ? ' 🔒' : ''), selected: t.id === tab.id }); }));

    var panel = h('div', { className: 'pcdn-panel', role: 'tabpanel', 'data-panel': tab.id });
    append(root, [
      h('div', { className: 'pcdn-top' }, h('strong', { className: 'pcdn-domain', dir: 'ltr', text: S.site.domain }), statusBadge(S.site.status)),
      !S.active ? alertBox('warning', 'این سرویس فعال نیست؛ اطلاعات فقط قابل مشاهده است و امکان تغییر وجود ندارد.') : null,
      nav, picker, panel
    ]);
    if (tabLocked(tab)) {
      append(panel, lockedPanel(tab.title));
    } else {
      append(panel, tab.render());
      lockWrites(panel);
    }
  }

  /** Read-only mode for services that are not Active. */
  function lockWrites(el) {
    if (S.active) return;
    Array.prototype.forEach.call(el.querySelectorAll('input,select,textarea,button[data-write]'), function (x) {
      if (!x.hasAttribute('data-ro-ok')) x.disabled = true;
    });
  }

  function lockedPanel(title) {
    return h('div', { className: 'pcdn-locked' },
      h('div', { className: 'pcdn-locked-icon', 'aria-hidden': 'true', text: '🔒' }),
      h('h3', { text: title + ' در پلن فعلی شما فعال نیست' }),
      h('p', { className: 'pcdn-muted', text: 'برای استفاده از این قابلیت، سرویس خود را به پلن بالاتر ارتقا دهید.' }),
      h('a', { className: 'pcdn-btn pcdn-btn-primary', href: WEBROOT + 'upgrade.php?type=package&id=' + encodeURIComponent(boot.serviceId), text: 'ارتقای پلن' }));
  }

  var STATUS = {
    active: ['فعال', 'success'], pending_ns: ['در انتظار تغییر NS', 'warning'],
    suspended: ['معلق', 'danger'], over_quota: ['اتمام ترافیک', 'danger']
  };
  function statusBadge(st) {
    var m = STATUS[st] || [st || '—', 'muted'];
    return h('span', { className: 'pcdn-badge pcdn-badge-' + m[1], text: m[0] });
  }

  // ------------------------------------------------------------------ overview

  function renderOverview() {
    var site = S.site, out = [];
    if (site.status === 'pending_ns') {
      var fb = feedback('ns');
      var recheck = btn('بررسی مجدد', 'pcdn-btn-sm pcdn-btn-warning', function () {
        run(recheck, fb, api('POST', 'ns-check'), function (d) {
          if (d.ok) { reloadSite('overview', 'نیم‌سرورها تأیید شدند و CDN فعال شد.'); return; }
          show(fb, false, h('div', null, 'نیم‌سرورهای دامنه هنوز تغییر نکرده‌اند. تغییر NS ممکن است تا ۲۴ ساعت زمان ببرد. فعلی: ',
            ltr((d.found || []).join(', ') || '—')));
        });
      }, true);
      out.push(alertBox('warning', [
        h('strong', { text: 'در انتظار تغییر نیم‌سرورها. ' }),
        'برای فعال شدن CDN، نیم‌سرورهای (NS) دامنه ', ltr(site.domain), ' را در پنل ثبت‌کننده دامنه به موارد زیر تغییر دهید:',
        h('ul', { className: 'pcdn-ns', dir: 'ltr' }, (site.nameservers || []).map(function (ns) { return h('li', null, h('code', { text: ns })); })),
        (site.ns_found || []).length ? h('div', null, h('small', null, 'نیم‌سرورهای فعلی: ', ltr(site.ns_found.join(', ')))) : null,
        h('small', { text: 'پیش از تغییر، رکوردهای DNS فعلی خود (ایمیل، زیردامنه‌ها و ...) را در تب DNS وارد کنید.' }),
        h('div', { className: 'pcdn-actions' }, recheck), fb
      ]));
    } else if (site.status === 'suspended') {
      out.push(alertBox('danger', 'این سرویس معلق است و بازدیدکنندگان صفحه تعلیق را می‌بینند.'));
    } else if (site.status === 'over_quota') {
      out.push(alertBox('danger', 'ترافیک ماهانه این سرویس تمام شده است. برای ادامه، سرویس را ارتقا دهید.'));
    } else {
      out.push(alertBox('success', ['CDN برای ', ltr(site.domain), ' فعال است.']));
    }
    out.push(feedback('overview'));

    var u = site.usage_month || {}, plan = site.plan || {}, limit = Number(plan.bandwidth_limit_gb) || 0;
    var used = limit > 0 ? Math.min(100, Math.round((Number(u.gb) || 0) * 100 / limit)) : 0;
    var ssl = site.ssl || {};
    out.push(h('div', { className: 'pcdn-stats' },
      stat('ترافیک این ماه', bytes(u.bytes), limit > 0 ? 'از ' + num(limit) + ' GB' : 'نامحدود',
        limit > 0 ? h('div', { className: 'pcdn-progress' }, h('div', { className: used >= 90 ? 'is-danger' : '', style: 'width:' + used + '%' })) : null),
      stat('درخواست‌ها', num(u.requests), 'این ماه'),
      stat('نرخ کش', pct(u.cache_hits || 0, u.requests || 0), 'درخواست‌های پاسخ‌داده‌شده از کش'),
      stat('SSL', sslLabel(ssl.status), ssl.expires_at ? 'انقضا: ' + date(ssl.expires_at, { dateStyle: 'medium' }) : '')));

    var f = features();
    var rows = [
      ['رکوردهای DNS', num((site.records || []).length) + ' / ' + num(plan.max_records)],
      ['SSL رایگان', plan.ssl_allowed ? '✓' : '—'],
      ['WAF', f.waf ? '✓' : '—'], ['حفاظت DDoS', f.ddos ? '✓' : '—'],
      ['توزیع بار', f.load_balancer ? num(f.max_pools) + ' استخر' : '—'],
      ['بهینه‌سازی تصویر', f.image_optimization ? '✓' : '—'], ['گواهی اختصاصی', f.custom_ssl ? '✓' : '—'],
      ['DNSSEC', f.dnssec ? '✓' : '—'],
      ['قوانین فایروال', num(f.max_firewall_rules || 0)], ['قوانین صفحه', num(f.max_page_rules || 0)],
      ['قوانین محدودیت نرخ', num(f.max_ratelimit_rules || 0)]
    ];
    var c = card('امکانات پلن');
    append(c.body, h('dl', { className: 'pcdn-dl' }, rows.map(function (r) {
      return h('div', null, h('dt', { text: r[0] }), h('dd', { text: r[1] }));
    })));
    out.push(c);
    return out;
  }

  function stat(label, value, sub, extra) {
    return h('div', { className: 'pcdn-stat' }, h('span', { className: 'pcdn-stat-label', text: label }),
      h('b', { text: value }), sub ? h('small', { text: sub }) : null, extra || null);
  }
  function sslLabel(st) {
    return { active: 'فعال', pending: 'در حال صدور', failed: 'ناموفق' }[st] || 'غیرفعال';
  }

  // ------------------------------------------------------------------ DNS

  var TYPES = ['A', 'AAAA', 'CNAME', 'ALIAS', 'TXT', 'MX', 'SRV', 'CAA', 'NS'];
  var PROXYABLE = { A: 1, AAAA: 1, CNAME: 1 };
  var dnsForm = null; // record being added / edited (draft), or null

  function recordBody(r) {
    var proxied = !!PROXYABLE[r.type] && !!r.proxied;
    var hc = !proxied && (r.type === 'A' || r.type === 'AAAA') && !!r.health_check;
    return {
      name: (r.name || '@').trim(), type: r.type, content: (r.content || '').trim(),
      ttl: Number(r.ttl) || 300,
      priority: (r.type === 'MX' || r.type === 'SRV') && r.priority !== null && r.priority !== '' ? Number(r.priority) : null,
      proxied: proxied,
      pool: proxied && r.pool ? r.pool : null,
      origin_port: proxied && !r.pool && r.origin_port ? Number(r.origin_port) : null,
      health_check: hc,
      health_port: hc && r.health_port ? Number(r.health_port) : null
    };
  }

  function reloadRecords(msg) {
    return api('GET', 'records').then(function (res) {
      if (res.ok) S.site.records = res.data;
      S.flash = { key: 'dns', msg: msg };
      render();
    });
  }

  function renderDns() {
    var site = S.site, recs = site.records || [], max = (site.plan || {}).max_records || 0, f = features();
    var pools = (config('pools').pools || []).map(function (p) { return p.name; });
    var fb = feedback('dns');
    var out = [];

    var c = card('رکوردهای DNS', btn('+ افزودن رکورد', 'pcdn-btn-primary pcdn-btn-sm', function () {
      dnsForm = { type: 'A', name: '', content: '', ttl: 300, priority: null, proxied: true, pool: null, origin_port: null, health_check: false, health_port: null };
      render();
    }, true));
    if (recs.length >= max) c.querySelector('.pcdn-card-head button').disabled = true;
    append(c.body, [
      limitNote(recs.length, max, 'تعداد رکوردها'),
      h('p', { className: 'pcdn-muted pcdn-small' },
        h('span', { className: 'pcdn-cloud is-on', text: '☁ پروکسی (CDN)' }), ': ترافیک از سرورهای CDN عبور می‌کند و IP سرور شما مخفی می‌ماند (A، AAAA، CNAME). ',
        h('span', { className: 'pcdn-cloud', text: '☁ فقط DNS' }), ': رکورد بدون تغییر پاسخ داده می‌شود.'),
      dnsForm ? recordForm(dnsForm, pools, f) : null,
      fb
    ]);

    var table = h('table', { className: 'pcdn-table' },
      h('thead', null, h('tr', null, ['نوع', 'نام', 'مقدار', 'TTL', 'CDN', ''].map(function (t) { return h('th', { text: t }); }))),
      h('tbody', null, recs.length ? recs.map(function (r) {
        var extra = [];
        if (r.pool) extra.push('pool: ' + r.pool);
        if (r.origin_port) extra.push('port: ' + r.origin_port);
        if (r.health_check) extra.push('health: ' + (r.health_port || 80));
        return h('tr', { 'data-record': r.id },
          h('td', null, h('span', { className: 'pcdn-badge pcdn-badge-muted', text: r.type })),
          h('td', { className: 'pcdn-ltr', dir: 'ltr', text: r.name }),
          h('td', { className: 'pcdn-ltr pcdn-content', dir: 'ltr' },
            h('code', { text: (r.priority !== null && r.priority !== undefined ? r.priority + ' ' : '') + r.content }),
            extra.length ? h('small', { className: 'pcdn-muted', text: ' ' + extra.join(' · ') }) : null),
          h('td', { className: 'pcdn-ltr', dir: 'ltr', text: r.ttl }),
          h('td', null, PROXYABLE[r.type]
            ? h('button', { type: 'button', className: 'pcdn-cloud-btn' + (r.proxied ? ' is-on' : ''), 'data-write': '1',
              title: r.proxied ? 'پروکسی فعال — کلیک برای خاموش کردن' : 'فقط DNS — کلیک برای فعال کردن پروکسی', text: '☁',
              'aria-pressed': r.proxied ? 'true' : 'false',
              onclick: function (e) {
                var b = recordBody(r); b.proxied = !r.proxied; b = recordBody(b);
                run(e.target, fb, api('PUT', 'records/' + r.id, b), function () { reloadRecords('وضعیت پروکسی تغییر کرد.'); });
              } })
            : h('span', { className: 'pcdn-cloud', text: '—' })),
          h('td', { className: 'pcdn-nowrap' },
            btn('ویرایش', 'pcdn-btn-sm', function () { dnsForm = clone(r); render(); }, true),
            ' ',
            btn('حذف', 'pcdn-btn-sm pcdn-btn-danger', function (e) {
              if (!window.confirm('رکورد ' + r.type + ' ' + r.name + ' حذف شود؟')) return;
              run(e.target, fb, api('DELETE', 'records/' + r.id), function () { reloadRecords('رکورد حذف شد.'); });
            }, true)));
      }) : h('tr', null, h('td', { colspan: 6, className: 'pcdn-empty', text: 'هنوز رکوردی ثبت نشده است.' }))));
    append(c.body, h('div', { className: 'pcdn-table-wrap' }, table));
    out.push(c);
    out.push(importExportCard());
    out.push(dnssecCard(f));
    return out;
  }

  function recordForm(r, pools, f) {
    var box = h('div', { className: 'pcdn-subform' });
    var fb = feedback('record-form');
    function redraw() {
      clear(box);
      var proxyable = !!PROXYABLE[r.type];
      if (!proxyable) r.proxied = false;
      var grid = h('div', { className: 'pcdn-grid' },
        select(r, 'type', 'نوع', TYPES.map(function (t) { return [t, t]; }), null, redraw),
        input(r, 'name', 'نام', { placeholder: '@ یا www' }),
        input(r, 'content', 'مقدار', { placeholder: { A: '185.1.2.3', AAAA: '2001:db8::1', CNAME: 'target.example.net', ALIAS: 'target.example.net', MX: 'mail.example.com', SRV: 'weight port target', TXT: 'v=spf1 ...', CAA: '0 issue "letsencrypt.org"' }[r.type] || '' }),
        input(r, 'ttl', 'TTL (ثانیه)', { type: 'number', min: 60 }),
        (r.type === 'MX' || r.type === 'SRV') ? input(r, 'priority', 'اولویت', { type: 'number', min: 0, nullable: true }) : null);
      append(box, [h('h4', { text: r.id ? 'ویرایش رکورد' : 'افزودن رکورد' }), grid]);
      if (r.type === 'ALIAS') append(box, h('p', { className: 'pcdn-help', text: 'ALIAS مانند CNAME است ولی روی ریشه دامنه (@) هم مجاز است و توسط DNS حل می‌شود (بدون پروکسی).' }));
      if (proxyable) {
        var g2 = h('div', { className: 'pcdn-grid' }, check(r, 'proxied', 'پروکسی از طریق CDN', null, redraw));
        if (r.proxied) {
          if (f.load_balancer && pools.length) {
            g2.appendChild(select(r, 'pool', 'استخر توزیع بار', [[null, '— بدون استخر (سرور بالا) —']].concat(pools.map(function (p) { return [p, p]; })),
              'در صورت انتخاب، ترافیک این نام به استخر فرستاده می‌شود و «مقدار» فقط پشتیبان DNS است.', redraw));
          }
          if (!r.pool) g2.appendChild(input(r, 'origin_port', 'پورت سرور اصلی', { type: 'number', min: 1, max: 65535, nullable: true, placeholder: '80 / 443', help: 'خالی = پیش‌فرض بر اساس پروتکل' }));
        } else if (r.type === 'A' || r.type === 'AAAA') {
          g2.appendChild(check(r, 'health_check', 'بررسی سلامت', 'در صورت وجود چند رکورد هم‌نام، فقط آدرس‌های سالم پاسخ داده می‌شوند.', redraw));
          if (r.health_check) g2.appendChild(input(r, 'health_port', 'پورت بررسی سلامت', { type: 'number', min: 1, max: 65535, nullable: true, placeholder: '80' }));
        }
        box.appendChild(g2);
      }
      var save = btn(r.id ? 'ذخیره رکورد' : 'افزودن', 'pcdn-btn-primary', function () {
        var p = r.id ? api('PUT', 'records/' + r.id, recordBody(r)) : api('POST', 'records', recordBody(r));
        run(save, fb, p, function () { dnsForm = null; reloadRecords(r.id ? 'رکورد ذخیره شد.' : 'رکورد اضافه شد.'); });
      }, true);
      append(box, [h('div', { className: 'pcdn-actions' }, save, btn('انصراف', '', function () { dnsForm = null; render(); })), fb]);
      lockWrites(box);
    }
    redraw();
    return box;
  }

  function importExportCard() {
    var c = card('ورود و خروج زون (BIND)');
    var st = { zone: '', replace: false };
    var fb = feedback('import');
    var out = h('textarea', { className: 'pcdn-input pcdn-ltr pcdn-mono', dir: 'ltr', rows: 6, readonly: true, 'data-ro-ok': '1', hidden: true });
    var dl = h('a', { className: 'pcdn-btn pcdn-btn-sm', hidden: true, text: 'دانلود فایل', download: S.site.domain + '.zone' });
    var exp = btn('خروجی زون', 'pcdn-btn-sm', function () {
      run(exp, fb, api('GET', 'records/export'), function (d) {
        out.value = d.zone || '';
        out.hidden = false;
        if (window.Blob && window.URL) { dl.href = URL.createObjectURL(new Blob([out.value], { type: 'text/plain' })); dl.hidden = false; }
      });
    });
    var imp = btn('ورود رکوردها', 'pcdn-btn-primary pcdn-btn-sm', function () {
      if (st.replace && !window.confirm('همه رکوردهای فعلی حذف و با فایل جایگزین شوند؟')) return;
      run(imp, fb, api('POST', 'records/import', { zone: st.zone, replace: st.replace }), function (d) {
        api('GET', 'records').then(function (res) {
          if (res.ok) S.site.records = res.data;
          var skipped = d.skipped || [];
          S.flash = { key: 'import', msg: h('div', null, num(d.imported || 0) + ' رکورد وارد شد.',
            skipped.length ? h('ul', { className: 'pcdn-errlist' }, skipped.map(function (x) {
              return h('li', null, ltr(x.line || ''), ' — ', String(x.reason || ''));
            })) : null) };
          render();
        });
      });
    }, true);
    append(c.body, [
      h('p', { className: 'pcdn-muted', text: 'محتوای فایل زون (BIND) فعلی دامنه را اینجا قرار دهید تا رکوردها وارد شوند. رکوردهای SOA و NS ریشه نادیده گرفته می‌شوند.' }),
      field('فایل زون', h('textarea', { className: 'pcdn-input pcdn-ltr pcdn-mono', dir: 'ltr', rows: 5, spellcheck: 'false',
        placeholder: 'www 300 IN A 185.1.2.3', oninput: function (e) { st.zone = e.target.value; } })),
      check(st, 'replace', 'جایگزینی کامل رکوردهای فعلی'),
      h('div', { className: 'pcdn-actions' }, imp, exp, dl), fb, out
    ]);
    return c;
  }

  function dnssecCard(f) {
    var c = card('DNSSEC');
    if (!f.dnssec) {
      append(c.body, h('p', { className: 'pcdn-muted' }, '🔒 DNSSEC در پلن شما فعال نیست.'));
      return c;
    }
    var fb = feedback('dnssec');
    var body = h('div');
    append(c.body, [body, fb]);
    function draw() {
      clear(body);
      var d = S.dnssec;
      if (!d) { append(body, h('p', { className: 'pcdn-muted', text: 'در حال دریافت…' })); return; }
      var toggle = btn(d.enabled ? 'غیرفعال کردن DNSSEC' : 'فعال‌سازی DNSSEC', d.enabled ? 'pcdn-btn-danger pcdn-btn-sm' : 'pcdn-btn-primary pcdn-btn-sm', function () {
        if (d.enabled && !window.confirm('پیش از غیرفعال کردن، رکورد DS را از ثبت‌کننده دامنه حذف کنید؛ وگرنه دامنه از دسترس خارج می‌شود. ادامه؟')) return;
        run(toggle, fb, api('POST', 'dnssec', { enabled: !d.enabled }), function (res) { S.dnssec = res; draw(); lockWrites(body); });
      }, true);
      append(body, [
        h('p', null, 'وضعیت: ', h('strong', { text: d.enabled ? 'فعال' : 'غیرفعال' })),
        d.enabled ? [
          h('p', { className: 'pcdn-muted', text: 'رکورد(های) DS زیر را در پنل ثبت‌کننده دامنه (مثلاً ایرنیک) وارد کنید:' }),
          h('div', { className: 'pcdn-codebox', dir: 'ltr' }, (d.ds || []).map(function (x) { return h('code', { text: x }); })),
          d.dnskey ? h('details', null, h('summary', { text: 'DNSKEY' }), h('div', { className: 'pcdn-codebox', dir: 'ltr' }, h('code', { text: d.dnskey }))) : null
        ] : null,
        h('div', { className: 'pcdn-actions' }, toggle)
      ]);
      lockWrites(body);
    }
    draw();
    if (!S.dnssec) {
      api('GET', 'dnssec').then(function (res) {
        if (res.ok) { S.dnssec = res.data; draw(); } else show(fb, false, errorNode(res.data, res.status));
      });
    }
    return c;
  }

  // ------------------------------------------------------------------ cache

  var TTL_HELP = 'ثانیه — مثلاً 3600 = ۱ ساعت، 86400 = ۱ روز';

  function renderCache() {
    var out = [sectionCard('cache', 'تنظیمات کش', function (d) {
      return [
        check(d, 'enabled', 'فعال‌سازی کش'),
        check(d, 'dev_mode', 'حالت توسعه', 'کش موقتاً غیرفعال می‌شود تا تغییرات سایت فوراً دیده شود.'),
        select(d, 'level', 'سطح کش', [['standard', 'استاندارد — رعایت Cache-Control سرور، کش فایل‌های ثابت'], ['aggressive', 'تهاجمی — کش همه پاسخ‌های 200/301']],
          'در حالت تهاجمی کوکی و Cache-Control سرور نادیده گرفته می‌شود؛ برای سایت‌های پویا با احتیاط استفاده کنید.'),
        h('div', { className: 'pcdn-grid' },
          input(d, 'edge_ttl', 'مدت کش در CDN', { type: 'number', min: 60, max: 31536000, help: TTL_HELP }),
          input(d, 'browser_ttl', 'مدت کش در مرورگر', { type: 'number', min: 0, help: '0 = طبق هدر سرور اصلی' })),
        check(d, 'ignore_query', 'نادیده گرفتن Query String در کلید کش'),
        list(d, 'bypass_cookies', 'کوکی‌های عبور از کش', { help: 'هر نام در یک خط؛ اگر کوکی با این پیشوند وجود داشته باشد پاسخ کش نمی‌شود.', placeholder: 'wordpress_logged_in\nPHPSESSID' }),
        check(d, 'always_online', 'همیشه آنلاین', 'در صورت خطای سرور اصلی، نسخه کش‌شده نمایش داده می‌شود.')
      ];
    })];

    var c = card('پاکسازی کش');
    var st = { urls: [] };
    var fb = feedback('purge');
    var purge = btn('پاکسازی آدرس‌ها', 'pcdn-btn-primary', function () {
      if (!st.urls.length) { show(fb, false, 'حداقل یک آدرس وارد کنید.'); return; }
      run(purge, fb, api('POST', 'purge', { urls: st.urls }), function () { show(fb, true, 'درخواست پاکسازی ثبت شد و تا چند ثانیه روی همه نودها اعمال می‌شود.'); });
    }, true);
    var all = btn('پاکسازی کامل', 'pcdn-btn-danger', function () {
      if (!window.confirm('کل کش دامنه پاک شود؟')) return;
      run(all, fb, api('POST', 'purge', { urls: [] }), function () { show(fb, true, 'پاکسازی کامل کش ثبت شد.'); });
    }, true);
    append(c.body, [
      list(st, 'urls', 'آدرس‌ها (هر آدرس در یک خط، حداکثر ۱۰۰)', { rows: 4, placeholder: 'https://' + S.site.domain + '/style.css' }),
      h('div', { className: 'pcdn-actions' }, purge, all), fb
    ]);
    out.push(c);
    return out;
  }

  // ------------------------------------------------------------------ SSL

  function renderSsl() {
    var site = S.site, ssl = site.ssl || {}, plan = site.plan || {}, f = features(), out = [];
    var c = card('وضعیت گواهی');
    var fb = feedback('ssl-status');
    var info = h('dl', { className: 'pcdn-dl' },
      h('div', null, h('dt', { text: 'وضعیت' }), h('dd', { text: sslLabel(ssl.status) })),
      h('div', null, h('dt', { text: 'نوع' }), h('dd', { text: ssl.source === 'custom' ? 'گواهی اختصاصی' : ssl.source === 'letsencrypt' ? "Let's Encrypt" : '—' })),
      h('div', null, h('dt', { text: 'انقضا' }), h('dd', { text: date(ssl.expires_at, { dateStyle: 'medium' }) })),
      (ssl.names || []).length ? h('div', null, h('dt', { text: 'نام‌ها' }), h('dd', null, ltr(ssl.names.join(', ')))) : null);
    append(c.body, info);
    if (ssl.status === 'failed' && ssl.error) append(c.body, h('pre', { className: 'pcdn-pre', dir: 'ltr', text: String(ssl.error).slice(-600) }));
    if (!plan.ssl_allowed) {
      append(c.body, h('p', { className: 'pcdn-muted', text: 'SSL رایگان در این پلن فعال نیست.' }));
    } else if (ssl.source !== 'custom') {
      append(c.body, h('p', { className: 'pcdn-muted' }, "گواهی رایگان Let's Encrypt برای ", ltr(site.domain), ' و ', ltr('*.' + site.domain), ' پس از تغییر نیم‌سرورها خودکار صادر و تمدید می‌شود.'));
      if (site.ns_verified && ssl.status !== 'pending') {
        var req = btn(ssl.status === 'active' ? 'صدور مجدد' : 'درخواست صدور', 'pcdn-btn-sm', function () {
          run(req, fb, api('POST', 'ssl'), function () { reloadSite('ssl-status', 'درخواست صدور گواهی ثبت شد.'); });
        }, true);
        append(c.body, h('div', { className: 'pcdn-actions' }, req));
      }
    }
    append(c.body, fb);
    out.push(c);

    out.push(sectionCard('ssl', 'تنظیمات HTTPS', function (d, redraw) {
      d.hsts = d.hsts || clone(DEFAULTS.ssl.hsts);
      return [
        check(d, 'force_https', 'انتقال خودکار HTTP به HTTPS', 'فقط وقتی گواهی فعال باشد اعمال می‌شود.'),
        check(d.hsts, 'enabled', 'فعال‌سازی HSTS', 'مرورگرها تا پایان مدت تعیین‌شده فقط با HTTPS به سایت وصل می‌شوند.', redraw),
        d.hsts.enabled ? h('div', { className: 'pcdn-subform' },
          input(d.hsts, 'max_age', 'max-age (ثانیه)', { type: 'number', min: 0 }),
          check(d.hsts, 'include_subdomains', 'شامل زیردامنه‌ها (includeSubDomains)'),
          check(d.hsts, 'preload', 'preload')) : null,
        select(d, 'min_tls', 'حداقل نسخه TLS', [['1.2', 'TLS 1.2'], ['1.3', 'TLS 1.3']]),
        select(d, 'origin_protocol', 'پروتکل اتصال به سرور اصلی', [['http', 'HTTP (پورت 80)'], ['https', 'HTTPS (پورت 443)']], null, redraw),
        d.origin_protocol === 'https' ? check(d, 'origin_verify', 'بررسی اعتبار گواهی سرور اصلی') : null
      ];
    }));

    var cc = card('گواهی اختصاصی');
    if (!f.custom_ssl) {
      append(cc.body, h('p', { className: 'pcdn-muted', text: '🔒 بارگذاری گواهی اختصاصی در پلن شما فعال نیست.' }));
    } else {
      var st = { cert: '', key: '' };
      var fb2 = feedback('ssl-custom');
      var up = btn('بارگذاری گواهی', 'pcdn-btn-primary', function () {
        run(up, fb2, api('PUT', 'ssl/custom', st), function () { reloadSite('ssl-custom', 'گواهی اختصاصی فعال شد.'); });
      }, true);
      var rm = ssl.source === 'custom' ? btn('حذف گواهی اختصاصی', 'pcdn-btn-danger', function () {
        if (!window.confirm("گواهی اختصاصی حذف و به Let's Encrypt بازگردانده شود؟")) return;
        run(rm, fb2, api('DELETE', 'ssl/custom'), function () { reloadSite('ssl-custom', 'گواهی اختصاصی حذف شد.'); });
      }, true) : null;
      var ta = function (key, label, ph) {
        return field(label, h('textarea', { className: 'pcdn-input pcdn-ltr pcdn-mono', dir: 'ltr', rows: 5, placeholder: ph, spellcheck: 'false',
          oninput: function (e) { st[key] = e.target.value; } }));
      };
      append(cc.body, [
        h('p', { className: 'pcdn-muted', text: 'گواهی (به همراه زنجیره میانی) و کلید خصوصی را با فرمت PEM وارد کنید. گواهی باید معتبر و شامل نام دامنه باشد.' }),
        ta('cert', 'گواهی (PEM)', '-----BEGIN CERTIFICATE-----'),
        ta('key', 'کلید خصوصی (PEM)', '-----BEGIN PRIVATE KEY-----'),
        h('div', { className: 'pcdn-actions' }, up, rm), fb2
      ]);
    }
    out.push(cc);
    return out;
  }

  // ------------------------------------------------------------------ firewall

  var FW_FIELDS = [['ip', 'IP / CIDR'], ['country', 'کشور'], ['path', 'مسیر'], ['host', 'هاست'], ['query', 'Query String'],
    ['user_agent', 'User-Agent'], ['referer', 'Referer'], ['method', 'متد'], ['header', 'هدر']];
  var LIST_OPS = [['in', 'یکی از'], ['not_in', 'هیچ‌کدام از']];
  var STR_OPS = [['eq', 'برابر'], ['ne', 'نابرابر'], ['contains', 'شامل'], ['not_contains', 'شامل نباشد'], ['starts_with', 'شروع با'],
    ['ends_with', 'پایان با'], ['regex', 'عبارت منظم'], ['in', 'یکی از'], ['not_in', 'هیچ‌کدام از']];
  var FW_ACTIONS = [['block', 'مسدود'], ['challenge', 'چالش JS'], ['captcha', 'کپچا'], ['allow', 'اجازه (عبور از WAF و محدودیت‌ها)'], ['log', 'فقط ثبت']];

  function opsFor(fieldName) { return fieldName === 'ip' || fieldName === 'country' ? LIST_OPS : STR_OPS; }
  function isList(op) { return op === 'in' || op === 'not_in'; }

  function conditionRow(cond, conds, i, redraw) {
    var ops = opsFor(cond.field);
    if (!ops.some(function (o) { return o[0] === cond.op; })) cond.op = ops[0][0];
    // Keep `value` a list for in/not_in and a string otherwise.
    if (isList(cond.op) && !Array.isArray(cond.value)) cond.value = cond.value ? [String(cond.value)] : [];
    if (!isList(cond.op) && Array.isArray(cond.value)) cond.value = cond.value.join(',');
    var val = h('input', {
      className: 'pcdn-input pcdn-ltr', dir: 'ltr',
      placeholder: cond.field === 'ip' ? '1.2.3.4, 10.0.0.0/8' : cond.field === 'country' ? 'CN, RU' : isList(cond.op) ? 'a, b' : '',
      value: Array.isArray(cond.value) ? cond.value.join(', ') : (cond.value || ''),
      oninput: function (e) {
        var v = e.target.value;
        cond.value = isList(cond.op)
          ? v.split(',').map(function (x) { x = x.trim(); return cond.field === 'country' ? x.toUpperCase() : x; }).filter(Boolean)
          : v;
      }
    });
    return h('div', { className: 'pcdn-cond' },
      select(cond, 'field', null, FW_FIELDS, null, function () { if (cond.field !== 'header') delete cond.name; redraw(); }),
      cond.field === 'header' ? input(cond, 'name', null, { placeholder: 'X-Header' }) : null,
      select(cond, 'op', null, ops, null, redraw),
      val,
      iconBtn('✕', 'حذف شرط', function () { conds.splice(i, 1); redraw(); }));
  }

  function renderFirewall() {
    var max = features().max_firewall_rules || 0;
    return sectionCard('firewall', 'قوانین فایروال', function (d, redraw) {
      d.rules = d.rules || [];
      var rules = d.rules.map(function (r, i) {
        r.conditions = r.conditions || [];
        return h('div', { className: 'pcdn-rule' + (r.enabled ? '' : ' is-disabled') },
          h('div', { className: 'pcdn-rule-head' },
            h('span', { className: 'pcdn-rule-no', text: num(i + 1) }),
            input(r, 'name', null, { ltr: false, placeholder: 'نام قانون' }),
            select(r, 'action', null, FW_ACTIONS),
            h('label', { className: 'pcdn-inline' }, h('input', { type: 'checkbox', checked: !!r.enabled, onchange: function (e) { r.enabled = e.target.checked; redraw(); } }), ' فعال'),
            orderControls(d.rules, i, redraw)),
          h('div', { className: 'pcdn-conds' },
            h('small', { className: 'pcdn-muted', text: 'اگر همه شرط‌های زیر برقرار باشد:' }),
            r.conditions.map(function (c, j) { return conditionRow(c, r.conditions, j, redraw); }),
            btn('+ شرط', 'pcdn-btn-sm', function () { r.conditions.push({ field: 'path', op: 'starts_with', value: '' }); redraw(); }, true)));
      });
      var add = btn('+ قانون جدید', 'pcdn-btn-sm', function () {
        d.rules.push({ id: uid('r'), name: '', enabled: true, action: 'block', conditions: [{ field: 'country', op: 'in', value: [] }] });
        redraw();
      }, true);
      if (d.rules.length >= max) add.disabled = true;
      return [
        h('p', { className: 'pcdn-muted', text: 'قوانین به ترتیب بررسی می‌شوند و اولین قانون منطبق اعمال می‌شود. عبارت منظم به حروف کوچک/بزرگ حساس نیست.' }),
        limitNote(d.rules.length, max, 'تعداد قوانین'),
        rules.length ? rules : h('p', { className: 'pcdn-empty', text: 'قانونی تعریف نشده است.' }),
        h('div', { className: 'pcdn-actions' }, add),
        select(d, 'default_action', 'اقدام پیش‌فرض (وقتی هیچ قانونی منطبق نباشد)', [['allow', 'اجازه'], ['block', 'مسدود']])
      ];
    });
  }

  // ------------------------------------------------------------------ WAF / DDoS / rate limit

  var WAF_GROUPS = [['sqli', 'SQL Injection'], ['xss', 'XSS'], ['lfi', 'LFI / پیمایش مسیر'], ['rce', 'اجرای فرمان (RCE)'],
    ['php', 'حملات PHP'], ['scanner', 'اسکنرها و ربات‌های مخرب'], ['protocol', 'نقض پروتکل HTTP']];

  function renderWaf() {
    return sectionCard('waf', 'فایروال برنامه وب (WAF)', function (d, redraw) {
      d.groups = d.groups || [];
      d.exclusions = d.exclusions || [];
      return [
        select(d, 'mode', 'حالت', [['off', 'خاموش'], ['detect', 'تشخیص (فقط ثبت رویداد)'], ['block', 'مسدودسازی']]),
        select(d, 'paranoia', 'سطح حساسیت', [[1, '۱ — کم (پیشنهادی)'], [2, '۲ — متوسط'], [3, '۳ — زیاد (احتمال خطای بیشتر)']]),
        h('fieldset', { className: 'pcdn-fieldset' }, h('legend', { text: 'گروه‌های قوانین' }),
          WAF_GROUPS.map(function (g) {
            return h('label', { className: 'pcdn-inline' }, h('input', { type: 'checkbox', checked: d.groups.indexOf(g[0]) >= 0, onchange: function (e) {
              d.groups = d.groups.filter(function (x) { return x !== g[0]; });
              if (e.target.checked) d.groups.push(g[0]);
            } }), ' ', g[1]);
          })),
        h('fieldset', { className: 'pcdn-fieldset' }, h('legend', { text: 'استثناها' }),
          h('small', { className: 'pcdn-help', text: 'شناسه قانون را از تب رویدادهای امنیتی بردارید. شناسه 0 یعنی همه قوانین؛ در مسیر می‌توانید از * استفاده کنید.' }),
          d.exclusions.map(function (x, i) {
            return h('div', { className: 'pcdn-row' },
              input(x, 'rule_id', null, { type: 'number', min: 0, placeholder: 'rule id' }),
              input(x, 'path', null, { placeholder: '/api/*', nullable: true }),
              iconBtn('✕', 'حذف', function () { d.exclusions.splice(i, 1); redraw(); }));
          }),
          btn('+ استثنا', 'pcdn-btn-sm', function () { d.exclusions.push({ rule_id: 0, path: '' }); redraw(); }, true))
      ];
    });
  }

  function renderDdos() {
    return sectionCard('ddos', 'حفاظت در برابر DDoS', function (d, redraw) {
      return [
        select(d, 'mode', 'حالت', [['off', 'خاموش'], ['auto', 'خودکار — چالش JS هنگام حمله'], ['js', 'چالش JS برای همه بازدیدکنندگان'], ['captcha', 'کپچا برای همه بازدیدکنندگان']],
          'در حالت خودکار، وقتی تعداد درخواست‌ها روی یک نود از آستانه بیشتر شود، بازدیدکنندگان جدید چالش JS دریافت می‌کنند.', redraw),
        h('div', { className: 'pcdn-grid' },
          d.mode === 'auto' ? input(d, 'threshold_rps', 'آستانه (درخواست در ثانیه)', { type: 'number', min: 1 }) : null,
          input(d, 'clearance_ttl', 'اعتبار مجوز عبور (ثانیه)', { type: 'number', min: 60 }))
      ];
    });
  }

  var METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];

  function renderRatelimit() {
    var max = features().max_ratelimit_rules || 0;
    return sectionCard('ratelimit', 'قوانین محدودیت نرخ', function (d, redraw) {
      d.rules = d.rules || [];
      var add = btn('+ قانون جدید', 'pcdn-btn-sm', function () {
        d.rules.push({ id: uid('rl'), enabled: true, path: '/*', methods: [], requests: 60, period: 60, action: 'block', block_seconds: 600 });
        redraw();
      }, true);
      if (d.rules.length >= max) add.disabled = true;
      return [
        h('p', { className: 'pcdn-muted', text: 'تعداد درخواست هر IP روی هر نود شمرده می‌شود. متد خالی یعنی همه متدها.' }),
        limitNote(d.rules.length, max, 'تعداد قوانین'),
        d.rules.map(function (r, i) {
          r.methods = r.methods || [];
          return h('div', { className: 'pcdn-rule' + (r.enabled ? '' : ' is-disabled') },
            h('div', { className: 'pcdn-rule-head' },
              input(r, 'id', null, { placeholder: 'id' }),
              h('label', { className: 'pcdn-inline' }, h('input', { type: 'checkbox', checked: !!r.enabled, onchange: function (e) { r.enabled = e.target.checked; redraw(); } }), ' فعال'),
              orderControls(d.rules, i, redraw)),
            h('div', { className: 'pcdn-grid' },
              input(r, 'path', 'مسیر', { placeholder: '/wp-login.php*' }),
              input(r, 'requests', 'تعداد درخواست', { type: 'number', min: 1 }),
              input(r, 'period', 'در بازه (ثانیه)', { type: 'number', min: 1 }),
              select(r, 'action', 'اقدام', [['block', 'مسدود (429)'], ['challenge', 'چالش JS'], ['captcha', 'کپچا']], null, redraw),
              r.action === 'block' ? input(r, 'block_seconds', 'مدت مسدودی (ثانیه)', { type: 'number', min: 1 }) : null),
            h('div', { className: 'pcdn-methods' }, METHODS.map(function (m) {
              return h('label', { className: 'pcdn-inline' }, h('input', { type: 'checkbox', checked: r.methods.indexOf(m) >= 0, onchange: function (e) {
                r.methods = r.methods.filter(function (x) { return x !== m; });
                if (e.target.checked) r.methods.push(m);
              } }), ' ', ltr(m));
            })));
        }),
        h('div', { className: 'pcdn-actions' }, add)
      ];
    });
  }

  // ------------------------------------------------------------------ page rules

  function renderPagerules() {
    var max = features().max_page_rules || 0;
    return sectionCard('pagerules', 'قوانین صفحه', function (d, redraw) {
      d.rules = d.rules || [];
      var add = btn('+ قانون جدید', 'pcdn-btn-sm', function () {
        d.rules.push({ id: uid('p'), enabled: true, pattern: '/', cache: null, edge_ttl: null, browser_ttl: null, ignore_query: null, waf: null, redirect: null });
        redraw();
      }, true);
      if (d.rules.length >= max) add.disabled = true;
      return [
        h('p', { className: 'pcdn-muted', text: 'الگو مسیر URL است و با / شروع می‌شود؛ * با هر رشته‌ای (حتی /) منطبق است. اولین قانون منطبق اعمال می‌شود. فیلدهای خالی یعنی «طبق تنظیمات کلی».' }),
        limitNote(d.rules.length, max, 'تعداد قوانین'),
        d.rules.map(function (r, i) {
          var redirect = !!r.redirect;
          return h('div', { className: 'pcdn-rule' + (r.enabled ? '' : ' is-disabled') },
            h('div', { className: 'pcdn-rule-head' },
              h('span', { className: 'pcdn-rule-no', text: num(i + 1) }),
              input(r, 'pattern', null, { placeholder: '/wp-admin/*' }),
              h('label', { className: 'pcdn-inline' }, h('input', { type: 'checkbox', checked: !!r.enabled, onchange: function (e) { r.enabled = e.target.checked; redraw(); } }), ' فعال'),
              orderControls(d.rules, i, redraw)),
            h('div', { className: 'pcdn-grid' },
              h('label', { className: 'pcdn-inline' }, h('input', { type: 'checkbox', checked: redirect, onchange: function (e) {
                r.redirect = e.target.checked ? { url: 'https://', code: 301 } : null; redraw();
              } }), ' ریدایرکت'),
              redirect ? [input(r.redirect, 'url', 'آدرس مقصد', { placeholder: 'https://example.com/new' }),
                select(r.redirect, 'code', 'کد', [[301, '301 دائمی'], [302, '302 موقت']])] : [
                select(r, 'cache', 'کش', [[null, 'طبق تنظیمات'], ['bypass', 'بدون کش'], ['standard', 'استاندارد'], ['everything', 'کش همه‌چیز']]),
                input(r, 'edge_ttl', 'TTL در CDN', { type: 'number', min: 0, nullable: true }),
                input(r, 'browser_ttl', 'TTL مرورگر', { type: 'number', min: 0, nullable: true }),
                select(r, 'ignore_query', 'Query String', [[null, 'طبق تنظیمات'], [true, 'نادیده گرفتن'], [false, 'در کلید کش']]),
                select(r, 'waf', 'WAF', [[null, 'طبق تنظیمات'], [false, 'غیرفعال در این مسیر']])
              ]));
        }),
        h('div', { className: 'pcdn-actions' }, add)
      ];
    });
  }

  // ------------------------------------------------------------------ pools

  function renderPools() {
    var max = features().max_pools || 0;
    return sectionCard('pools', 'استخرهای توزیع بار', function (d, redraw) {
      d.pools = d.pools || [];
      var add = btn('+ استخر جدید', 'pcdn-btn-sm', function () {
        d.pools.push({ name: 'pool' + (d.pools.length + 1), method: 'weighted', protocol: 'http',
          origins: [{ address: '', port: 80, weight: 10, backup: false }],
          health: { enabled: true, path: '/', interval: 10, timeout: 3, expect: '2xx,3xx', host: null } });
        redraw();
      }, true);
      if (d.pools.length >= max) add.disabled = true;
      return [
        h('p', { className: 'pcdn-muted', text: 'پس از ذخیره، در تب DNS برای رکورد پروکسی‌شده استخر را انتخاب کنید. سرورهای پشتیبان فقط وقتی همه سرورهای اصلی از دسترس خارج شوند استفاده می‌شوند.' }),
        limitNote(d.pools.length, max, 'تعداد استخرها'),
        d.pools.map(function (p, i) {
          p.origins = p.origins || [];
          p.health = p.health || clone({ enabled: false, path: '/', interval: 10, timeout: 3, expect: '2xx,3xx', host: null });
          return h('div', { className: 'pcdn-rule' },
            h('div', { className: 'pcdn-rule-head' },
              input(p, 'name', null, { placeholder: 'main' }),
              select(p, 'method', null, [['weighted', 'وزنی (تصادفی)'], ['ip_hash', 'چسبنده (IP hash)']]),
              select(p, 'protocol', null, [['http', 'HTTP'], ['https', 'HTTPS']]),
              iconBtn('✕', 'حذف استخر', function () { d.pools.splice(i, 1); redraw(); })),
            h('div', { className: 'pcdn-table-wrap' }, h('table', { className: 'pcdn-table pcdn-table-form' },
              h('thead', null, h('tr', null, ['آدرس', 'پورت', 'وزن', 'پشتیبان', ''].map(function (t) { return h('th', { text: t }); }))),
              h('tbody', null, p.origins.map(function (o, j) {
                return h('tr', null,
                  h('td', null, input(o, 'address', null, { placeholder: '185.1.2.3' })),
                  h('td', null, input(o, 'port', null, { type: 'number', min: 1, max: 65535 })),
                  h('td', null, input(o, 'weight', null, { type: 'number', min: 1, max: 100 })),
                  h('td', null, h('input', { type: 'checkbox', checked: !!o.backup, 'aria-label': 'پشتیبان', onchange: function (e) { o.backup = e.target.checked; } })),
                  h('td', null, iconBtn('✕', 'حذف سرور', function () { p.origins.splice(j, 1); redraw(); })));
              })))),
            btn('+ سرور', 'pcdn-btn-sm', function () { p.origins.push({ address: '', port: p.protocol === 'https' ? 443 : 80, weight: 10, backup: false }); redraw(); }, true),
            h('fieldset', { className: 'pcdn-fieldset' }, h('legend', { text: 'بررسی سلامت' }),
              check(p.health, 'enabled', 'فعال', null, redraw),
              p.health.enabled ? h('div', { className: 'pcdn-grid' },
                input(p.health, 'path', 'مسیر', { placeholder: '/' }),
                input(p.health, 'interval', 'فاصله (ثانیه)', { type: 'number', min: 5 }),
                input(p.health, 'timeout', 'مهلت (ثانیه)', { type: 'number', min: 1 }),
                input(p.health, 'expect', 'کدهای سالم', { placeholder: '2xx,3xx' }),
                input(p.health, 'host', 'هدر Host', { nullable: true, placeholder: S.site.domain })) : null));
        }),
        h('div', { className: 'pcdn-actions' }, add)
      ];
    });
  }

  // ------------------------------------------------------------------ headers / hotlink / image / error pages

  function headerList(d, key, title, allowRemove, redraw) {
    d[key] = d[key] || [];
    return h('fieldset', { className: 'pcdn-fieldset' }, h('legend', { text: title }),
      d[key].map(function (x, i) {
        var removing = allowRemove && x.value === null;
        return h('div', { className: 'pcdn-row' },
          input(x, 'name', null, { placeholder: 'X-Header' }),
          removing ? h('span', { className: 'pcdn-muted pcdn-grow', text: 'این هدر از پاسخ حذف می‌شود' }) : input(x, 'value', null, { placeholder: 'value' }),
          allowRemove ? h('label', { className: 'pcdn-inline' }, h('input', { type: 'checkbox', checked: removing, onchange: function (e) {
            x.value = e.target.checked ? null : ''; redraw();
          } }), ' حذف') : null,
          iconBtn('✕', 'حذف ردیف', function () { d[key].splice(i, 1); redraw(); }));
      }),
      d[key].length < 20 ? btn('+ هدر', 'pcdn-btn-sm', function () { d[key].push({ name: '', value: '' }); redraw(); }, true) : null);
  }

  function renderHeaders() {
    return sectionCard('headers', 'هدرهای HTTP', function (d, redraw) {
      return [
        h('p', { className: 'pcdn-muted', text: 'نام هدر فقط حروف لاتین، عدد و خط تیره. هدرهای Host، Content-Length و hop-by-hop مجاز نیستند. حداکثر ۲۰ مورد در هر بخش.' }),
        headerList(d, 'request', 'هدرهای درخواست به سرور اصلی', false, redraw),
        headerList(d, 'response', 'هدرهای پاسخ به بازدیدکننده', true, redraw)
      ];
    });
  }

  function renderHotlink() {
    return sectionCard('hotlink', 'جلوگیری از Hotlink', function (d) {
      return [
        check(d, 'enabled', 'فعال', 'استفاده از فایل‌های شما در سایت‌های دیگر مسدود می‌شود.'),
        list(d, 'extensions', 'پسوندها', { comma: true, lower: true, rows: 2, placeholder: 'jpg, png, mp4' }),
        list(d, 'allowed_referers', 'دامنه‌های مجاز', { help: 'هر دامنه در یک خط؛ * برای زیردامنه‌ها (مثلاً *.example.com).', placeholder: S.site.domain + '\n*.' + S.site.domain }),
        check(d, 'allow_empty', 'اجازه به درخواست‌های بدون Referer')
      ];
    });
  }

  function renderImage() {
    return sectionCard('image', 'بهینه‌سازی تصویر', function (d) {
      return [
        check(d, 'enabled', 'فعال'),
        h('div', { className: 'pcdn-grid' },
          input(d, 'quality', 'کیفیت (1 تا 100)', { type: 'number', min: 1, max: 100 }),
          input(d, 'max_width', 'حداکثر عرض (پیکسل)', { type: 'number', min: 1 })),
        h('p', { className: 'pcdn-help' }, 'تصاویر jpg/png/gif/webp با پارامتر ', ltr('?width=800'), ' یا ', ltr('?height=600'), ' در لبه تغییر اندازه داده و کش می‌شوند.')
      ];
    });
  }

  function renderErrorpages() {
    return sectionCard('errorpages', 'صفحات خطای سفارشی', function (d) {
      var ta = function (key, label) {
        return field(label, h('textarea', { className: 'pcdn-input pcdn-ltr pcdn-mono', dir: 'ltr', rows: 8, spellcheck: 'false',
          placeholder: '<html>…</html>', value: d[key] || '',
          oninput: function (e) { d[key] = e.target.value.trim() === '' ? null : e.target.value; } }),
        'خالی = صفحه پیش‌فرض. حداکثر ۶۴ کیلوبایت.');
      };
      return [ta('5xx', 'خطاهای سرور (5xx)'), ta('4xx', 'خطاهای کاربر (4xx)')];
    });
  }

  // ------------------------------------------------------------------ analytics

  var C = { blue: '#2a78d6', aqua: '#1baf7a', orange: '#eb6834' };
  var PERIODS = [['24h', '۲۴ ساعت'], ['7d', '۷ روز'], ['30d', '۳۰ روز']];

  function renderAnalytics() {
    var holder = h('div');
    var bar = h('div', { className: 'pcdn-seg', role: 'group', 'aria-label': 'بازه' }, PERIODS.map(function (p) {
      return h('button', { type: 'button', className: 'pcdn-seg-btn' + (S.period === p[0] ? ' is-active' : ''), 'data-period': p[0], 'aria-pressed': S.period === p[0] ? 'true' : 'false', text: p[1],
        onclick: function () { S.period = p[0]; render(); } });
    }));
    var data = S.analytics[S.period];
    if (!data) {
      append(holder, h('p', { className: 'pcdn-muted', text: 'در حال دریافت آمار…' }));
      var period = S.period;
      api('GET', 'analytics', undefined, { period: period }).then(function (res) {
        if (!res.ok) { clear(holder); append(holder, alertBox('danger', errorNode(res.data, res.status))); return; }
        S.analytics[period] = res.data;
        if (S.tab === 'analytics' && S.period === period) render();
      });
    } else {
      // Charts measure their container, so draw after the panel is in the DOM.
      setTimeout(function () { drawAnalytics(holder, data); }, 0);
    }
    return [h('div', { className: 'pcdn-toolbar' }, bar), holder];
  }

  function drawAnalytics(holder, a) {
    clear(holder);
    var t = a.totals || {}, series = a.series || [], sec = t.security || {}, st = t.status || {};
    var secTotal = Object.keys(sec).reduce(function (s2, k) { return s2 + (Number(sec[k]) || 0); }, 0);
    var hourly = a.period === '24h';
    var labels = series.map(function (p) {
      return date(p.t, hourly ? { hour: '2-digit', minute: '2-digit' } : { month: 'short', day: 'numeric' });
    });
    append(holder, h('div', { className: 'pcdn-stats' },
      stat('درخواست‌ها', num(t.requests), ''), stat('ترافیک', bytes(t.bytes), ''),
      stat('نرخ کش', pct(t.cache_hits || 0, t.requests || 0), num(t.cache_hits) + ' از کش'),
      stat('رویدادهای امنیتی', num(secTotal), '')));

    var c1 = card('درخواست‌ها');
    var c2 = card('ترافیک');
    append(holder, [c1, c2]);
    if (!series.length) {
      append(c1.body, h('p', { className: 'pcdn-empty', text: 'هنوز داده‌ای برای این بازه ثبت نشده است.' }));
      c2.parentNode.removeChild(c2);
    } else {
      lineChart(c1.body, labels, [
        { name: 'کل درخواست‌ها', color: C.blue, values: series.map(function (p) { return p.requests || 0; }) },
        { name: 'پاسخ از کش', color: C.aqua, values: series.map(function (p) { return p.cache_hits || 0; }) }
      ], num);
      barChart(c2.body, labels, series.map(function (p) { return p.bytes || 0; }), C.orange, bytes);
    }

    var grid = h('div', { className: 'pcdn-two' });
    var cs = card('کدهای وضعیت');
    append(cs.body, barList(['2xx', '3xx', '4xx', '5xx'].map(function (k) { return [k, st[k] || 0]; }), true));
    append(cs.body, h('h4', { text: 'پرتکرارترین کدها' }));
    append(cs.body, barList((a.status_codes || []).map(function (x) { return [String(x.code), x.requests]; }), true));
    var cse = card('رویدادهای امنیتی بر اساس منبع');
    var SRC = { waf: 'WAF', firewall: 'فایروال', ratelimit: 'محدودیت نرخ', challenge: 'چالش', ddos: 'DDoS', hotlink: 'Hotlink' };
    append(cse.body, barList(Object.keys(SRC).map(function (k) { return [SRC[k], sec[k] || 0]; })));
    var cc = card('کشورها');
    append(cc.body, barList((a.countries || []).map(function (x) { return [x.code, x.requests]; }), true));
    var cp = card('پربازدیدترین مسیرها');
    append(cp.body, barList((a.paths || []).map(function (x) { return [x.path, x.requests]; }), true));
    append(grid, [cs, cse, cc, cp]);
    append(holder, grid);
  }

  /** Horizontal bar list: label · bar · value. */
  function barList(rows, ltrLabels) {
    if (!rows.length) return h('p', { className: 'pcdn-empty', text: 'داده‌ای وجود ندارد.' });
    var max = Math.max.apply(null, rows.map(function (r) { return Number(r[1]) || 0; })) || 1;
    return h('ul', { className: 'pcdn-barlist' }, rows.map(function (r) {
      var w = Math.round((Number(r[1]) || 0) * 100 / max);
      return h('li', null,
        h('span', { className: 'pcdn-barlist-label' + (ltrLabels ? ' pcdn-ltr' : ''), dir: ltrLabels ? 'ltr' : null, title: r[0], text: r[0] }),
        h('span', { className: 'pcdn-barlist-track' }, h('span', { className: 'pcdn-barlist-bar', style: 'width:' + w + '%' })),
        h('span', { className: 'pcdn-barlist-val', text: num(r[1]) }));
    }));
  }

  function niceMax(v) {
    if (v <= 0) return 1;
    var p = Math.pow(10, Math.floor(Math.log10(v))), n = v / p;
    return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 2.5 ? 2.5 : n <= 5 ? 5 : 10) * p;
  }

  /** Shared frame for the time-series charts: axes, grid, hover crosshair + tooltip. */
  function chartFrame(host, labels, max, fmtAxis) {
    var wrap = h('div', { className: 'pcdn-chart', dir: 'ltr' });
    host.appendChild(wrap);
    var W = Math.max(260, wrap.clientWidth || 600), H = 220, L = 62, R = 10, T = 10, B = 26;
    var svg = s('svg', { width: W, height: H, viewBox: '0 0 ' + W + ' ' + H, role: 'img' });
    var n = labels.length, pw = W - L - R, ph = H - T - B;
    var f = {
      svg: svg, wrap: wrap, W: W, H: H, L: L, T: T, pw: pw, ph: ph, n: n,
      y: function (v) { return T + ph - (v / max) * ph; }
    };
    for (var i = 0; i <= 4; i++) {
      var v = max * i / 4, y = f.y(v);
      svg.appendChild(s('line', { x1: L, x2: W - R, y1: y, y2: y, class: 'pcdn-grid-line' }));
      svg.appendChild(s('text', { x: L - 6, y: y + 4, 'text-anchor': 'end', class: 'pcdn-axis' }, fmtAxis(v)));
    }
    var step = Math.max(1, Math.ceil(n / Math.max(2, Math.floor(pw / 70))));
    f.labelAt = function (i2, x) {
      if (i2 % step === 0) svg.appendChild(s('text', { x: x, y: H - 8, 'text-anchor': 'middle', class: 'pcdn-axis' }, labels[i2]));
    };
    wrap.appendChild(svg);
    return f;
  }

  function attachHover(f, xAt, rowsAt) {
    var tip = h('div', { className: 'pcdn-tip', hidden: true });
    var cross = s('line', { y1: f.T, y2: f.T + f.ph, class: 'pcdn-cross', visibility: 'hidden' });
    f.svg.appendChild(cross);
    f.wrap.appendChild(tip);
    function hide() { tip.hidden = true; cross.setAttribute('visibility', 'hidden'); }
    f.svg.addEventListener('pointermove', function (e) {
      var r = f.svg.getBoundingClientRect();
      var px = (e.clientX - r.left) * (f.W / r.width);
      var best = 0, bd = Infinity;
      for (var i = 0; i < f.n; i++) { var d = Math.abs(xAt(i) - px); if (d < bd) { bd = d; best = i; } }
      var x = xAt(best);
      cross.setAttribute('x1', x); cross.setAttribute('x2', x); cross.setAttribute('visibility', 'visible');
      clear(tip);
      append(tip, rowsAt(best));
      tip.hidden = false;
      var left = x * (r.width / f.W);
      tip.style.left = Math.min(Math.max(0, left + 12), r.width - tip.offsetWidth) + 'px';
      if (left + 12 + tip.offsetWidth > r.width) tip.style.left = Math.max(0, left - 12 - tip.offsetWidth) + 'px';
    });
    f.svg.addEventListener('pointerleave', hide);
  }

  function tipRow(color, label, value) {
    return h('div', { className: 'pcdn-tip-row' },
      color ? h('span', { className: 'pcdn-key', style: 'background:' + color }) : null,
      h('strong', { text: value }), ' ', h('span', { text: label }));
  }

  function lineChart(host, labels, series, fmt) {
    var max = niceMax(Math.max.apply(null, [0].concat.apply([], series.map(function (sr) { return sr.values; }))));
    var f = chartFrame(host, labels, max, short);
    var xAt = function (i) { return f.L + (f.n > 1 ? i * f.pw / (f.n - 1) : f.pw / 2); };
    for (var i = 0; i < f.n; i++) f.labelAt(i, xAt(i));
    series.forEach(function (sr) {
      var d = sr.values.map(function (v, i2) { return (i2 ? 'L' : 'M') + xAt(i2).toFixed(1) + ' ' + f.y(v).toFixed(1); }).join(' ');
      f.svg.appendChild(s('path', { d: d, fill: 'none', stroke: sr.color, 'stroke-width': 2, 'stroke-linejoin': 'round', 'stroke-linecap': 'round' }));
    });
    attachHover(f, xAt, function (i2) {
      return [h('div', { className: 'pcdn-tip-title', text: labels[i2] })].concat(series.map(function (sr) { return tipRow(sr.color, sr.name, fmt(sr.values[i2])); }));
    });
    host.appendChild(h('div', { className: 'pcdn-legend' }, series.map(function (sr) {
      return h('span', null, h('span', { className: 'pcdn-key', style: 'background:' + sr.color }), sr.name);
    })));
  }

  function barChart(host, labels, values, color, fmt) {
    var max = niceMax(Math.max.apply(null, [0].concat(values)));
    var f = chartFrame(host, labels, max, function (v) {
      var p = bytes(v).split(' '), n = parseFloat(p[0]); // compact: "38.4 MB" -> "38 MB", "2.50 GB" -> "2.5 GB"
      return (n >= 10 ? Math.round(n) : Math.round(n * 10) / 10) + ' ' + p[1];
    });
    var slot = f.pw / Math.max(1, f.n), bw = Math.max(1, slot - 2);
    var xAt = function (i) { return f.L + i * slot + slot / 2; };
    values.forEach(function (v, i) {
      f.labelAt(i, xAt(i));
      var y = f.y(v), x = f.L + i * slot + 1, bh = f.T + f.ph - y;
      if (bh <= 0) return;
      var r = Math.min(4, bw / 2, bh);
      // rounded data-end, square baseline
      f.svg.appendChild(s('path', { fill: color, d: 'M' + x + ' ' + (y + bh) + 'V' + (y + r) + 'Q' + x + ' ' + y + ' ' + (x + r) + ' ' + y +
        'H' + (x + bw - r) + 'Q' + (x + bw) + ' ' + y + ' ' + (x + bw) + ' ' + (y + r) + 'V' + (y + bh) + 'Z' }));
    });
    attachHover(f, xAt, function (i) { return [h('div', { className: 'pcdn-tip-title', text: labels[i] }), tipRow(color, 'ترافیک', fmt(values[i]))]; });
  }

  // ------------------------------------------------------------------ security events

  var SOURCES = { waf: 'WAF', firewall: 'فایروال', ratelimit: 'محدودیت نرخ', ddos: 'DDoS', hotlink: 'Hotlink' };
  var ACTIONS = { block: ['مسدود', 'danger'], challenge: ['چالش', 'warning'], captcha: ['کپچا', 'warning'], log: ['ثبت', 'muted'] };
  var eventFilter = { source: '' };

  function renderEvents() {
    var c = card('رویدادهای امنیتی (۱۰۰ مورد آخر)');
    var fb = feedback('events');
    var body = h('div');
    var refresh = btn('بروزرسانی', 'pcdn-btn-sm', function () { load(); });
    var filter = select(eventFilter, 'source', null, [['', 'همه منابع']].concat(Object.keys(SOURCES).map(function (k) { return [k, SOURCES[k]]; })), null, function () { draw(); });
    filter.setAttribute('data-ro-ok', '1');
    append(c.body, [h('div', { className: 'pcdn-toolbar' }, filter, refresh), fb, body]);
    function load() {
      run(refresh, fb, api('GET', 'events', undefined, { limit: 100 }), function (d) { S.events = Array.isArray(d) ? d : []; draw(); });
    }
    function draw() {
      clear(body);
      if (!S.events) { append(body, h('p', { className: 'pcdn-muted', text: 'در حال دریافت…' })); return; }
      var rows = S.events.filter(function (e) { return !eventFilter.source || e.source === eventFilter.source; });
      if (!rows.length) { append(body, h('p', { className: 'pcdn-empty', text: 'رویدادی ثبت نشده است.' })); return; }
      append(body, h('div', { className: 'pcdn-table-wrap' }, h('table', { className: 'pcdn-table pcdn-events' },
        h('thead', null, h('tr', null, ['زمان', 'IP', 'کشور', 'درخواست', 'اقدام', 'منبع', 'قانون'].map(function (t) { return h('th', { text: t }); }))),
        h('tbody', null, rows.map(function (e) {
          var act = ACTIONS[e.action] || [e.action, 'muted'];
          return h('tr', null,
            h('td', { className: 'pcdn-nowrap', text: date(e.t) }),
            h('td', { className: 'pcdn-ltr', dir: 'ltr', text: e.ip }),
            h('td', { className: 'pcdn-ltr', dir: 'ltr', text: e.country || '—' }),
            h('td', { className: 'pcdn-ltr pcdn-req', dir: 'ltr', title: e.user_agent || '' },
              h('code', { text: (e.method || '') + ' ' + (e.host || '') + (e.path || '') }),
              e.user_agent ? h('small', { className: 'pcdn-muted pcdn-ua', text: e.user_agent }) : null),
            h('td', null, h('span', { className: 'pcdn-badge pcdn-badge-' + act[1], text: act[0] })),
            h('td', { text: SOURCES[e.source] || e.source }),
            h('td', { className: 'pcdn-ltr', dir: 'ltr', text: e.rule || '—' }));
        })))));
    }
    draw();
    if (!S.events) load();
    return c;
  }

  // ------------------------------------------------------------------ boot

  var resizeTimer = null;
  window.addEventListener('resize', function () {
    if (S.tab !== 'analytics') return;
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(render, 200);
  });

  render();
})();
