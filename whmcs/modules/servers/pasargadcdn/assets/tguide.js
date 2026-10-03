/*
 * Pasargad CDN — wave 13 (docs/SPEC.md §22.5 / §22.11): the tunnel profile and «تنظیمات پیشنهادی برنامه‌ها» (page `tguide`).
 *
 *   GET tunnel/profile → {edge: {client_idle_s, max_connection_age_s, h2_max_streams, tcp_keepalive, connect_timeout_s},
 *                         http3: {site, nodes, nodes_h3, available},
 *                         paths: [{id, path, protocol, idle_timeout_s, read_timeout_s, send_timeout_s, origins, balance, http3,
 *                                  recommended: {keepalive_s, mux, xmux, grpc, ws_heartbeat_s}}]}
 *   One background call when the app starts on a tunnel plan (PCDN.tprofile.probe); an older controller answers 404 and every
 *   wave-13 piece of the client app (this page, per-path idle timeout, multi-origin editor, timeout checks, HTTP/3 variant)
 *   stays hidden. The profile carries no node name or address.
 *
 * Hard constraint (§22): the guide recommends STABILITY settings only — keepalive / ping intervals, mux and the choice of
 * protocol. It never recommends fragment / noise / padding options, SNI tricks or address lists.
 *
 * Exports:
 *   PCDN.tguide = {APPS, SUPPORT, support(appId, proto), keepalive(idle, clientIdle), recommend(path, edge, siteIdle),
 *                  settings(appId, path, rec, opts) → {rows: [{id, field, value, note}], json: text|null, core}, EDGE}
 *   PCDN.tprofile = {ok(), data(), path(id), probe(), load(force), invalidate()}
 * The data part is require()-able from node (unit tests); the page is registered only in the browser.
 */
(function (root) {
  'use strict';
  var P = root.PCDN = root.PCDN || {};
  var t = P.t || function (s) { var a = arguments; return String(s).replace(/\{(\d+)\}/g, function (m, i) { return a[+i + 1] === undefined ? m : String(a[+i + 1]); }); };  // i18n.js (SPEC §16.10); identity + {n} in node tests

  // ================================================================== data (pure)

  /** Edge timer contract (§22.5 EDGE_TUNNEL_TIMERS) — used only until the profile arrives / for unsaved drafts. */
  var EDGE = { client_idle_s: 600, max_connection_age_s: 21600, h2_max_streams: 512, tcp_keepalive: { idle_s: 120, interval_s: 30, count: 4 }, connect_timeout_s: 10 };

  var PROTO_LABEL = { grpc: 'gRPC', xhttp: 'XHTTP', ws: 'WebSocket', httpupgrade: 'HTTPUpgrade', h2: 'HTTP/2 (h2)' };
  var PROTOCOLS = ['grpc', 'xhttp', 'ws', 'httpupgrade', 'h2'];

  /**
   * The app ↔ protocol support table (one data object, §22.11). Checked against the current releases:
   * v2rayNG 1.9+/1.10, v2rayN 7.x, Streisand (Xray-core) carry XHTTP (incl. stream-one for the h2 path); Hiddify, NekoBox and
   * sing-box (SFA / SFI / SFM) run the sing-box core, which has no XHTTP transport — XHTTP / h2 paths are for Xray-core apps only.
   * HTTPUpgrade: Xray ≥ 1.8.9 and sing-box ≥ 1.8 (every current release of the six apps).
   */
  var APPS = [
    { id: 'v2rayng', name: 'v2rayNG', os: t('اندروید'), core: 'xray' },
    { id: 'v2rayn', name: 'v2rayN', os: t('ویندوز، لینوکس، مک'), core: 'xray' },
    { id: 'streisand', name: 'Streisand', os: t('iOS و مک'), core: 'xray' },
    { id: 'hiddify', name: 'Hiddify', os: t('اندروید، iOS، ویندوز، مک'), core: 'singbox' },
    { id: 'nekobox', name: 'NekoBox', os: t('اندروید'), core: 'singbox' },
    { id: 'singbox', name: 'sing-box', os: t('اندروید، iOS، مک (SFA / SFI / SFM)'), core: 'singbox' }
  ];
  var CORE_SUPPORT = {
    xray: { grpc: 'yes', xhttp: 'yes', ws: 'yes', httpupgrade: 'yes', h2: 'yes' },
    singbox: { grpc: 'yes', xhttp: 'no', ws: 'yes', httpupgrade: 'yes', h2: 'no' }
  };
  var SUPPORT = {};
  APPS.forEach(function (a) { SUPPORT[a.id] = CORE_SUPPORT[a.core]; });
  function appOf(id) { return APPS.filter(function (a) { return a.id === id; })[0] || null; }
  function support(appId, proto) { var s = SUPPORT[appId]; return s ? (s[proto] || 'no') : 'no'; }

  /** Recommended client keepalive / ping for an effective idle timeout (§22.5): max(10, min(60, ⌊min(idle, client_idle)/3⌋)). */
  function keepalive(idle, clientIdle) {
    var i = Number(idle) > 0 ? Number(idle) : 3600, c = Number(clientIdle) > 0 ? Number(clientIdle) : EDGE.client_idle_s;
    return Math.max(10, Math.min(60, Math.floor(Math.min(i, c) / 3)));
  }
  function isNum(v) { return typeof v === 'number' && isFinite(v); }

  /**
   * Recommended values of one path — the controller's own (profile) when it matches, else computed the same way
   * (unsaved drafts, other idle timeout). path = {protocol, idle_timeout?, idle_timeout_s?, recommended?}.
   */
  function recommend(path, edge, siteIdle) {
    edge = edge || EDGE;
    var idle = isNum(path.idle_timeout_s) ? path.idle_timeout_s : (isNum(path.idle_timeout) ? path.idle_timeout : (Number(siteIdle) || 3600));
    var k = keepalive(idle, edge.client_idle_s);
    var r = path.recommended && typeof path.recommended === 'object' ? path.recommended : null;
    var proto = path.protocol;
    if (r && isNum(r.keepalive_s) && r.keepalive_s === k) return { idle_s: idle, keepalive_s: k, mux: r.mux || 'off', xmux: r.xmux || null, grpc: r.grpc || null, ws_heartbeat_s: isNum(r.ws_heartbeat_s) ? r.ws_heartbeat_s : null };
    return {
      idle_s: idle, keepalive_s: k,
      mux: proto === 'ws' || proto === 'httpupgrade' ? 'low' : 'off',
      xmux: proto === 'xhttp' ? { max_concurrency: '16-32', c_max_reuse_times: 0, h_max_request_times: '600-900', h_max_reusable_secs: '1800-3000', h_keepalive_period_s: k } : null,
      grpc: proto === 'grpc' ? { idle_timeout_s: k, health_check_timeout_s: 20, permit_without_stream: false } : null,
      ws_heartbeat_s: proto === 'ws' ? k : null
    };
  }

  /** Xray `xhttpSettings.extra` object (camelCase, as Xray and the share-link `extra` parameter take it). */
  function xmuxExtra(x) {
    if (!x) return null;
    return { xmux: { maxConcurrency: String(x.max_concurrency), cMaxReuseTimes: Number(x.c_max_reuse_times) || 0,
      hMaxRequestTimes: String(x.h_max_request_times), hMaxReusableSecs: String(x.h_max_reusable_secs), hKeepAlivePeriod: Number(x.h_keepalive_period_s) || 0 } };
  }

  /**
   * The exact settings of one app for one path: rows {id, field (the app's own field name), value, note} and a JSON fragment
   * for apps that take a custom config. opts = {h3: bool (xhttp over HTTP/3 available), path, host}.
   */
  function settings(appId, proto, rec, opts) {
    opts = opts || {};
    var a = appOf(appId), rows = [], json = null;
    if (!a || support(appId, proto) === 'no') return { rows: rows, json: null, core: a ? a.core : null, unsupported: true };
    var k = rec.keepalive_s;
    function row(id, field, value, note) { rows.push({ id: id, field: field, value: String(value), note: note || null }); }
    if (a.core === 'xray') {
      if (rec.mux === 'low') row('mux', 'Mux', t('روشن — concurrency بین ۴ تا ۸'), t('برای WebSocket / HTTPUpgrade چند اتصال کاربر روی یک اتصال می‌نشیند و اتصال‌های پشت‌سرهم کمتر می‌شود؛ بیشتر از ۸ نگذارید.'));
      else row('mux', 'Mux', t('خاموش'), proto === 'grpc' ? t('gRPC خودش چند جریان را روی یک اتصال HTTP/2 می‌برد؛ Mux روی آن فقط تأخیر اضافه می‌کند.') : t('XHTTP اتصال‌ها را با XMUX مدیریت می‌کند؛ Mux را خاموش بگذارید.'));
      if (proto === 'grpc') {
        row('grpc_mode', 'mode', 'gun', t('در لینک اشتراک هست (mode=gun).'));
        row('grpc_idle', 'idle_timeout', String(rec.grpc ? rec.grpc.idle_timeout_s : k), t('ثانیه؛ هر چند ثانیه بی‌کاری یک ping HTTP/2 می‌فرستد تا اتصال بیکار بسته نشود.'));
        row('grpc_hc', 'health_check_timeout', String(rec.grpc ? rec.grpc.health_check_timeout_s : 20), t('ثانیه؛ اگر پاسخ ping تا این مدت نیامد اتصال دوباره ساخته می‌شود.'));
        row('grpc_pws', 'permit_without_stream', 'false', t('بدون جریان فعال ping نمی‌فرستد (مصرف کمتر باتری).'));
        json = { streamSettings: { network: 'grpc', grpcSettings: { serviceName: opts.serviceName || '…', multiMode: false,
          idle_timeout: rec.grpc ? rec.grpc.idle_timeout_s : k, health_check_timeout: rec.grpc ? rec.grpc.health_check_timeout_s : 20, permit_without_stream: false } },
          mux: { enabled: false } };
      } else if (proto === 'xhttp') {
        var ex = xmuxExtra(rec.xmux);
        row('xmux', 'XMUX (xhttp extra)', JSON.stringify(ex), t('در لینک اشتراک پنل (پارامتر extra) هست؛ در v2rayNG و v2rayN در فیلد «xhttp extra» هم می‌توانید بچسبانید.'));
        row('xhttp_mode', 'mode', 'auto', t('حالت خودکار؛ اگر شبکه‌ی کاربر ناپایدار است packet-up را امتحان کنید.'));
        if (opts.h3) row('alpn', 'alpn', 'h3', t('نسخه‌ی HTTP/3 همین مسیر (QUIC)؛ اگر شبکه‌ی کاربر UDP را محدود می‌کند همان h2 را نگه دارید.'));
        json = { streamSettings: { network: 'xhttp', xhttpSettings: { path: opts.path || '/…', mode: 'auto', extra: ex } }, mux: { enabled: false } };
      } else if (proto === 'ws') {
        row('ws_hb', 'heartbeatPeriod', String(isNum(rec.ws_heartbeat_s) ? rec.ws_heartbeat_s : k), t('ثانیه (Xray نسخه‌ی ۲۵ به بعد)؛ در رابط برنامه نیست، در کانفیگ سفارشی JSON بگذارید. در نسخه‌های قدیمی‌تر نادیده گرفته می‌شود.'));
        json = { streamSettings: { network: 'ws', wsSettings: { path: opts.path || '/…', heartbeatPeriod: isNum(rec.ws_heartbeat_s) ? rec.ws_heartbeat_s : k } }, mux: { enabled: true, concurrency: 8 } };
      } else if (proto === 'httpupgrade') {
        row('hu_note', 'keepalive', '—', t('HTTPUpgrade تنظیم ping ندارد؛ برای اتصال‌های طولانی بیکار gRPC را ترجیح دهید.'));
        json = { streamSettings: { network: 'httpupgrade', httpupgradeSettings: { path: opts.path || '/…' } }, mux: { enabled: true, concurrency: 8 } };
      } else if (proto === 'h2') {
        row('xhttp_mode', 'mode', 'stream-one', t('در لینک اشتراک هست؛ مسیر h2 همیشه stream-one است.'));
        json = { streamSettings: { network: 'xhttp', xhttpSettings: { path: opts.path || '/…', mode: 'stream-one' } }, mux: { enabled: false } };
      }
    } else {
      row('mux', 'multiplex.enabled', 'false', t('سرور Xray از multiplex هسته‌ی sing-box پشتیبانی نمی‌کند؛ روشن کردنش اتصال را خراب می‌کند. در Hiddify گزینه‌ی Mux را خاموش بگذارید.'));
      if (proto === 'grpc') {
        var gi = rec.grpc ? rec.grpc.idle_timeout_s : k, gh = rec.grpc ? rec.grpc.health_check_timeout_s : 20;
        row('grpc_idle', 'idle_timeout', gi + 's', t('هر چند ثانیه بی‌کاری یک ping HTTP/2 می‌فرستد.'));
        row('grpc_ping', 'ping_timeout', gh + 's', t('اگر پاسخ ping تا این مدت نیامد اتصال دوباره ساخته می‌شود.'));
        row('grpc_pws', 'permit_without_stream', 'false', null);
        json = { multiplex: { enabled: false }, transport: { type: 'grpc', service_name: opts.serviceName || '…', idle_timeout: gi + 's', ping_timeout: gh + 's', permit_without_stream: false } };
      } else if (proto === 'ws') {
        row('ws_hb', 'heartbeat', '—', t('sing-box برای WebSocket ping ندارد؛ heartbeatPeriod را روی ورودی Xray سرور {0} ثانیه بگذارید.', k));
        json = { multiplex: { enabled: false }, transport: { type: 'ws', path: opts.path || '/…' } };
      } else if (proto === 'httpupgrade') {
        row('hu_note', 'keepalive', '—', t('HTTPUpgrade تنظیم ping ندارد؛ برای اتصال‌های طولانی بیکار gRPC را ترجیح دهید.'));
        json = { multiplex: { enabled: false }, transport: { type: 'httpupgrade', path: opts.path || '/…' } };
      }
    }
    return { rows: rows, json: json ? JSON.stringify(json, null, 2) : null, core: a.core, unsupported: false };
  }

  P.tguide = { APPS: APPS, SUPPORT: SUPPORT, PROTOCOLS: PROTOCOLS, EDGE: EDGE, support: support, appOf: appOf, keepalive: keepalive,
    recommend: recommend, settings: settings, xmuxExtra: xmuxExtra };
  if (typeof module !== 'undefined' && module.exports) module.exports = P.tguide;
  if (!P.h) return;

  // ================================================================== profile (one GET per app load; 404 = older controller)

  var h = P.h, append = P.append, clear = P.clear, icon = P.icon, num = P.num, ltr = P.ltr;
  function A() { return P.app; }
  function S() { return P.app.S; }
  function site() { return P.app.S.site || {}; }
  function feats() { return P.app.features(); }
  function tunnelOn() { return !!feats().tunnel; }

  function tpState() { var st = S(); return st.tp || (st.tp = { ok: undefined, data: null, at: 0, loading: null }); }
  function load(force) {
    var T = tpState();
    if (!tunnelOn()) return Promise.resolve(null);
    if (!force && T.data && Date.now() - T.at < 60000) return Promise.resolve(T.data);
    if (T.loading) return T.loading;
    T.loading = P.api('GET', 'tunnel/profile').then(function (res) {
      T.loading = null;
      if (res.ok && res.data && typeof res.data === 'object' && Array.isArray(res.data.paths)) {
        T.ok = true; T.data = res.data; T.at = Date.now();
      } else if (res.status === 404) {
        T.ok = false; T.data = null;   // older controller (or no tunnel in the plan): wave-13 pieces stay hidden
      }
      return T.data;
    });
    return T.loading;
  }
  P.tprofile = {
    /** true / false, or undefined while unknown. */
    ok: function () { return P.app ? tpState().ok : undefined; },
    data: function () { return P.app ? tpState().data : null; },
    /** The profile entry of a saved path, or null. */
    path: function (id) {
      var d = P.app ? tpState().data : null;
      return d ? (d.paths || []).filter(function (p) { return p && p.id === id; })[0] || null : null;
    },
    edge: function () { var d = P.app ? tpState().data : null; return d && d.edge && typeof d.edge === 'object' ? d.edge : EDGE; },
    http3: function () { var d = P.app ? tpState().data : null; return d && d.http3 && typeof d.http3 === 'object' ? d.http3 : null; },
    probe: function () { return load(false).then(function () { return tpState().ok === true; }); },
    load: load,
    /** After the tunnel section was saved: the next read refetches. */
    invalidate: function () { if (P.app) tpState().at = 0; }
  };
  function supported() { return P.app && tpState().ok === true; }

  // ================================================================== page «تنظیمات پیشنهادی برنامه‌ها»

  function codeBlock(text, label, id) {
    return h('figure', { className: 'pcdn-codeblock', 'data-code': id || null },
      h('figcaption', null, icon('terminal'), h('span', { dir: 'auto', text: label }),
        P.copyBtn(text, t('کپی ') + label, { text: t('کپی'), cls: 'pcdn-copy-code', done: t('کپی شد') })),
      h('pre', { dir: 'ltr', tabindex: '0' }, h('code', { text: text })));
  }
  function protoBadge(p) { return h('span', { className: 'pcdn-tn-proto pcdn-tn-' + String(p || ''), text: PROTO_LABEL[p] || String(p || '—') }); }
  function secs(v) { return isNum(v) ? (v >= 120 && v % 60 === 0 ? P.dur(v) : num(v) + t(' ثانیه')) : '—'; }
  function gState() { var st = S(); return st.tg || (st.tg = { app: 'v2rayng', path: null }); }

  function renderGuide(Aa) {
    var G = gState();
    var holder = h('div', { className: 'pcdn-stack', 'data-tg-holder': '1' });
    holder.appendChild(P.skeleton(4));
    function alive() { return S().page === 'tguide' && document.body.contains(holder); }
    load(false).then(function (d) {
      if (!alive()) return;
      clear(holder);
      if (!d) {
        holder.appendChild(P.alertBox('info', t('تنظیمات پیشنهادی روی این سرور CDN در دسترس نیست.')));
        return;
      }
      draw(holder, d, Aa);
    });
    var intro = P.alertBox('info', [h('strong', { text: t('فقط تنظیمات پایداری: ') }),
      t('این صفحه فاصله‌ی keepalive / ping، Mux و انتخاب پروتکل را از روی مهلت‌های واقعی مسیرهای همین سرویس پیشنهاد می‌دهد تا اتصال‌های طولانی بی‌دلیل قطع نشوند.')], { icon: 'bulb' });
    return [intro, holder];
  }

  function draw(holder, d, Aa) {
    var G = gState();
    var edge = d.edge && typeof d.edge === 'object' ? d.edge : EDGE;
    var paths = (d.paths || []).filter(function (p) { return p && p.id && PROTO_LABEL[p.protocol]; });
    if (!paths.length) {
      holder.appendChild(P.empty('tunnel', t('هنوز مسیر تونلی ذخیره نشده است'), t('پس از ساخت و ذخیره‌ی اولین مسیر در صفحه‌ی تونل، تنظیمات پیشنهادی هر برنامه اینجا نمایش داده می‌شود.'),
        Aa.goLink('tunnel', t('ساخت مسیر در صفحه تونل'))));
      holder.appendChild(supportCard());
      return;
    }
    if (!paths.some(function (p) { return p.id === G.path; })) G.path = paths[0].id;
    if (!appOf(G.app)) G.app = APPS[0].id;
    var appSeg = P.segmented(APPS.map(function (a) { return [a.id, a.name]; }), G.app, function (v) { G.app = v; redraw(); }, t('برنامه‌ی کلاینت'));
    appSeg.setAttribute('data-seg', 'tg-app');
    appSeg.classList.add('pcdn-tg-appseg');
    var pathSel = P.select(G, 'path', t('مسیر تونل'), paths.map(function (p) { return [p.id, (PROTO_LABEL[p.protocol] || p.protocol) + ' — ' + p.path]; }),
      { ltr: true, onchange: function () { redraw(); } });
    pathSel.classList.add('pcdn-tg-pathsel');
    var body = h('div', { className: 'pcdn-stack', 'aria-live': 'polite' });
    var pick = P.card({ title: t('برنامه و مسیر'), icon: 'sliders', id: 'tg-pick' });
    append(pick.body, [h('div', { className: 'pcdn-field' }, h('span', { className: 'pcdn-label', text: t('برنامه‌ی کاربر') }), appSeg), pathSel,
      P.alertBox('info', t('برای پایداری gRPC یا XHTTP را ترجیح دهید؛ WebSocket روی شبکه‌های ناپایدار زودتر قطع می‌شود.'), { icon: 'zap' })]);
    append(holder, [pick, body, supportCard()]);
    function redraw() {
      Array.prototype.forEach.call(appSeg.querySelectorAll('.pcdn-seg-btn'), function (b) {
        var on = b.getAttribute('data-value') === G.app;
        b.classList.toggle('is-active', on); b.setAttribute('aria-pressed', on ? 'true' : 'false');
      });
      clear(body);
      var p = paths.filter(function (x) { return x.id === G.path; })[0] || paths[0];
      append(body, [appCard(p, edge, d), edgeCard(p, edge)]);
    }
    redraw();
  }

  function appCard(p, edge, d) {
    var G = gState(), a = appOf(G.app) || APPS[0];
    var rec = recommend(p, edge);
    var h3 = !!(p.http3 && d.http3 && d.http3.available);
    var c = P.card({ title: a.name + ' — ' + (PROTO_LABEL[p.protocol] || p.protocol), icon: 'tool', id: 'tg-app',
      subtitle: a.os + t(' — هسته ') + (a.core === 'xray' ? 'Xray-core' : 'sing-box') });
    c.setAttribute('data-tg-app', a.id);
    c.setAttribute('data-tg-path', p.id);
    var sup = support(a.id, p.protocol);
    if (sup === 'no') {
      append(c.body, P.alertBox('danger', [h('strong', { text: t('{0} پروتکل {1} را ندارد.', a.name, PROTO_LABEL[p.protocol] || p.protocol) + ' ' }),
        p.protocol === 'xhttp' || p.protocol === 'h2' ? t('XHTTP فقط در برنامه‌های با هسته‌ی Xray (v2rayNG، v2rayN، Streisand) کار می‌کند؛ برای کاربران این برنامه یک مسیر gRPC بسازید.')
          : t('برای کاربران این برنامه یک مسیر gRPC یا WebSocket بسازید.')], { icon: 'xCircle' }));
      c.body.lastChild.setAttribute('data-tg-unsupported', '1');
      return c;
    }
    var s = settings(a.id, p.protocol, rec, { h3: h3, path: p.path, serviceName: String(p.path || '').replace(/^\/+/, '') });
    var tbody = h('tbody');
    s.rows.forEach(function (r) {
      tbody.appendChild(h('tr', { 'data-tg-row': r.id },
        h('td', { 'data-label': t('فیلد در برنامه') }, h('bdi', { dir: 'ltr', className: 'pcdn-mono', text: r.field })),
        h('td', { 'data-label': t('مقدار') }, (/[؀-ۿ]/.test(r.value) ? h('span', { className: 'pcdn-tg-val is-text', text: r.value }) : h('bdi', { dir: 'ltr', className: 'pcdn-tg-val', text: r.value }))),
        h('td', { 'data-label': t('توضیح'), className: 'pcdn-muted pcdn-small', text: r.note || '' })));
    });
    append(c.body, [
      h('div', { className: 'pcdn-table-wrap' }, h('table', { className: 'pcdn-table pcdn-rtable pcdn-tg-table' },
        h('caption', { className: 'pcdn-sr', text: t('تنظیمات پیشنهادی {0}', a.name) }),
        h('thead', null, h('tr', null, [t('فیلد در برنامه'), t('مقدار'), t('توضیح')].map(function (x) { return h('th', { scope: 'col', text: x }); }))),
        tbody)),
      p.protocol === 'xhttp' ? (h3 ? P.alertBox('success', t('همه‌ی نودهای این سرویس HTTP/3 دارند؛ در «پیکربندی آماده» نسخه‌ی HTTP/3 این مسیر (alpn=h3) را هم می‌گیرید.'), { icon: 'zap' })
        : P.alertBox('info', t('همه‌ی نودهای این سرویس هنوز HTTP/3 ندارند؛ از همان نسخه‌ی h2 استفاده کنید.'))) : null,
      s.json ? codeBlock(s.json, a.core === 'xray' ? t('بخش کانفیگ Xray (کلاینت)') : t('بخش outbound در sing-box'), 'tg-json') : null,
      h('p', { className: 'pcdn-muted pcdn-small', text: a.core === 'xray'
        ? t('لینک اشتراک «پیکربندی آماده» همین مقدارها را تا جایی که قالب لینک اجازه می‌دهد دارد؛ بقیه را در تنظیمات برنامه یا کانفیگ سفارشی بگذارید.')
        : t('این مقدارها را در outbound همین مسیر بگذارید؛ «پیکربندی آماده» خروجی sing-box را با همین مقدارها می‌سازد.') })]);
    c.body.firstChild.setAttribute('data-tg-rows', String(s.rows.length));
    return c;
  }

  function edgeCard(p, edge) {
    var rec = recommend(p, edge);
    var tk = edge.tcp_keepalive && typeof edge.tcp_keepalive === 'object' ? edge.tcp_keepalive : EDGE.tcp_keepalive;
    var c = P.card({ title: t('مهلت‌های لبه برای این مسیر'), icon: 'clock', tone: 'muted', id: 'tg-edge',
      subtitle: t('keepalive برنامه باید کوتاه‌تر از مهلت بیکاری باشد تا اتصال بیکار پیش از ping بسته نشود.') });
    function row(k, label, value) { return h('div', { 'data-tg-edge': k }, h('dt', { text: label }), h('dd', { text: value })); }
    append(c.body, h('dl', { className: 'pcdn-dl pcdn-dl-cols' },
      row('idle', t('مهلت بیکاری مسیر'), secs(rec.idle_s)),
      row('keepalive', t('keepalive پیشنهادی'), secs(rec.keepalive_s)),
      row('client_idle', t('مهلت بیکاری اتصال کاربر به لبه'), secs(edge.client_idle_s)),
      row('age', t('حداکثر عمر یک اتصال'), secs(edge.max_connection_age_s)),
      row('connect', t('مهلت اتصال لبه به سرور شما'), secs(edge.connect_timeout_s)),
      row('streams', t('حداکثر جریان همزمان روی یک اتصال HTTP/2'), num(edge.h2_max_streams || EDGE.h2_max_streams)),
      row('tcp', t('TCP keepalive لبه (idle / فاصله / تعداد)'), num(tk.idle_s) + ' / ' + num(tk.interval_s) + ' / ' + num(tk.count))));
    append(c.body, h('p', { className: 'pcdn-muted pcdn-small', text: t('پس از «حداکثر عمر یک اتصال» برنامه خودکار اتصال تازه می‌سازد؛ این قطع کوتاه عادی است.') }));
    return c;
  }

  function supportCard() {
    var c = P.collapsible({ title: t('پشتیبانی برنامه‌ها از پروتکل‌ها'), icon: 'checkCircle', tone: 'muted', id: 'tg-support' });
    var M = { yes: ['success', t('دارد')], no: ['muted', t('ندارد')] };
    var tbody = h('tbody');
    APPS.forEach(function (a) {
      tbody.appendChild(h('tr', { 'data-tg-support': a.id }, h('th', { scope: 'row' }, h('bdi', { dir: 'ltr', text: a.name }), h('span', { className: 'pcdn-muted pcdn-small', text: ' (' + (a.core === 'xray' ? 'Xray' : 'sing-box') + ')' })),
        PROTOCOLS.map(function (pr) {
          var v = support(a.id, pr), m = M[v] || M.no;
          return h('td', { 'data-label': PROTO_LABEL[pr], 'data-proto': pr, 'data-v': v }, P.badge(m[1], m[0]));
        })));
    });
    append(c.body, [h('div', { className: 'pcdn-table-wrap' }, h('table', { className: 'pcdn-table pcdn-rtable pcdn-tg-support' },
      h('caption', { className: 'pcdn-sr', text: t('پشتیبانی برنامه‌ها از پروتکل‌ها') }),
      h('thead', null, h('tr', null, [h('th', { scope: 'col', text: t('برنامه') })].concat(PROTOCOLS.map(function (pr) { return h('th', { scope: 'col', text: PROTO_LABEL[pr] }); })))),
      tbody)),
      h('p', { className: 'pcdn-muted pcdn-small', text: t('XHTTP و مسیر h2 فقط در برنامه‌های با هسته‌ی Xray کار می‌کنند؛ نسخه‌ی برنامه را به‌روز نگه دارید.') })]);
    return c;
  }

  P.pages = P.pages || {};
  P.pages.tguide = {
    title: t('تنظیمات پیشنهادی برنامه‌ها'), icon: 'bulb', heading: t('تنظیمات پیشنهادی برنامه‌ها'),
    desc: t('برای هر برنامه‌ی کاربر (v2rayNG، v2rayN، Streisand، Hiddify، NekoBox، sing-box) و هر مسیر تونل، مقدار دقیق Mux، keepalive و ping را با نام فیلد همان برنامه ببینید.'),
    hidden: function () { return !supported() || !tunnelOn(); },
    render: renderGuide
  };
})(typeof window !== 'undefined' ? window : this);
