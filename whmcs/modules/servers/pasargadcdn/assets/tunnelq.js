/*
 * Pasargad CDN — Wave 7 (docs/SPEC.md §15) tunnel diagnostics for the client app:
 *   - «کیفیت تونل»        (tquality)  GET tunnel/quality?hours=24|168|720 + GET tunnel/health
 *                                       + wave 13 (§22.12) «چرا اتصال من قطع شد؟»: GET tunnel/drops?hours=… (hidden on 404)
 *   - «مصرف تونل»          (tusage)    GET tunnel/usage?days=30
 *   - «بررسی کانفیگ سرور»  (tconfig)   browser-only checker (tcheck.js): no network call, nothing stored
 *   - «تست سرعت»           (speedtest) latency / download / upload against the customer's OWN domain
 *                                       (https://<site>/__pcdn/speed/*, §15.6) — never a node address
 *
 * Feature detection: one background GET tunnel/health when the app starts (P.w7.probe). The
 * controller-backed pages appear only when it answers (an older controller 404s → they stay hidden
 * and are never called again). The config checker needs no endpoint and is shown on tunnel plans.
 * Data only reaches the DOM through textContent / createElement (ui.js helpers) — never innerHTML.
 */
(function () {
  'use strict';
  var P = window.PCDN = window.PCDN || {};
  var t = P.t;  // i18n.js (SPEC §16.10)
  var pages = P.pages = P.pages || {};
  if (!P.h) return;
  var h = P.h, s = P.s, append = P.append, clear = P.clear, icon = P.icon, ltr = P.ltr, num = P.num;

  function A() { return P.app; }
  function S() { return P.app.S; }
  function site() { return P.app.S.site || {}; }
  function feats() { return P.app.features(); }
  function onLeave(fn) { if (A().onLeave) A().onLeave(fn); }
  function tunnelOn() { return !!feats().tunnel; }

  var NO_DATA = t('داده‌ای نیست');
  var nf1 = null, nf2 = null;
  try {
    nf1 = new Intl.NumberFormat(P.locale, { maximumFractionDigits: 1 });
    nf2 = new Intl.NumberFormat(P.locale, { maximumFractionDigits: 2 });
  } catch (e) { /* old browser: plain digits */ }
  function isNum(v) { return typeof v === 'number' && isFinite(v); }
  function f1(v) { return nf1 ? nf1.format(Math.round(v * 10) / 10) : P.fa(Math.round(v * 10) / 10); }
  function f2(v) { return nf2 ? nf2.format(Math.round(v * 100) / 100) : P.fa(Math.round(v * 100) / 100); }
  function pct(v) { return isNum(v) ? f1(v) + t('٪') : NO_DATA; }
  function ms(v) { return isNum(v) ? num(Math.round(v)) + t(' میلی‌ثانیه') : NO_DATA; }

  var PROTO = { grpc: 'gRPC', xhttp: 'XHTTP', ws: 'WebSocket', httpupgrade: 'HTTPUpgrade', h2: 'HTTP/2 (h2)' };
  function protoBadge(p) { return h('span', { className: 'pcdn-tn-proto pcdn-tn-' + String(p || ''), text: PROTO[p] || String(p || '—') }); }

  // ================================================================== feature detection (§15.3/§15.4)

  function w7State() { var st = S(); return st.w7 || (st.w7 = { ok: undefined, health: null, healthAt: 0, probing: null }); }
  function fetchHealth() {
    var W = w7State();
    return P.api('GET', 'tunnel/health').then(function (res) {
      if (res.ok && res.data && typeof res.data === 'object' && typeof res.data.state === 'string') {
        W.ok = true;
        W.health = res.data;
        W.healthAt = Date.now();
      } else if (res.status === 404) {
        W.ok = false;   // older controller: the Wave 7 pages stay hidden
      }
      return res;
    });
  }
  P.w7 = {
    /** true / false, or undefined while unknown. */
    ok: function () { return P.app ? w7State().ok : undefined; },
    /** One background call per app load; resolves to a boolean. */
    probe: function () {
      var W = w7State();
      if (typeof W.ok === 'boolean') return Promise.resolve(W.ok);
      if (!W.probing) W.probing = fetchHealth().then(function () { W.probing = null; return W.ok === true; });
      return W.probing;
    }
  };
  function supported() { return P.app && w7State().ok === true; }

  // ================================================================== small pieces

  function kpi(ic, tone, label, value, sub, id) {
    return h('div', { className: 'pcdn-kpi', 'data-kpi': id || null },
      h('div', { className: 'pcdn-kpi-top' }, h('span', { className: 'pcdn-kpi-icon pcdn-tone-' + tone }, icon(ic)), h('span', { className: 'pcdn-kpi-label', text: label })),
      h('div', { className: 'pcdn-kpi-value' }, value), sub ? h('div', { className: 'pcdn-kpi-sub' }, sub) : null);
  }
  function refreshBtn(label, fn) {
    var b = P.btn('', { icon: 'refresh', aria: label, title: label, cls: 'pcdn-btn-iconic', onclick: function () { fn(b); } });
    b.setAttribute('data-ro-ok', '1');
    return b;
  }
  function successTone(v) { return !isNum(v) ? 'muted' : v >= 98 ? 'success' : v >= 90 ? 'warning' : 'danger'; }
  function bytesOf(v) {
    if (isNum(v)) return v;
    if (v && typeof v === 'object') return (Number(v.bytes) || 0) + (Number(v.bytes_up) || 0) + (Number(v.bytes_down) || 0);
    return Number(v) || 0;
  }

  /** Stacked daily bars (inline SVG, same look as reports.js charts). series: [{name, color, values}] */
  function stackedBars(host, labels, series, aria, fmt) {
    fmt = fmt || P.bytes;
    var totals = labels.map(function (_, i) { return series.reduce(function (tx, sr) { return tx + (sr.values[i] || 0); }, 0); });
    var maxV = Math.max.apply(null, [1].concat(totals));
    var p10 = Math.pow(10, Math.floor(Math.log(maxV) / Math.LN10)), nn = maxV / p10;
    var max = (nn <= 1 ? 1 : nn <= 2 ? 2 : nn <= 2.5 ? 2.5 : nn <= 5 ? 5 : 10) * p10;
    var wrap = h('div', { className: 'pcdn-chart', dir: 'ltr' });
    host.appendChild(wrap);
    var W = Math.max(260, Math.floor(wrap.clientWidth || 600)), narrow = W < 480, H = narrow ? 200 : 240;
    var L = narrow ? 52 : 64, R = 12, T = 14, B = 28, pw = W - L - R, ph = H - T - B;
    var svg = s('svg', { width: W, height: H, viewBox: '0 0 ' + W + ' ' + H, role: 'img', 'aria-label': aria, focusable: 'false' });
    function y(v) { return T + ph - (v / max) * ph; }
    for (var i = 0; i <= 4; i++) {
      var yy = y(max * i / 4);
      svg.appendChild(s('line', { x1: L, x2: W - R, y1: yy, y2: yy, class: i ? 'pcdn-gridline' : 'pcdn-baseline' }));
      svg.appendChild(s('text', { x: L - 8, y: yy + 4, 'text-anchor': 'end', class: 'pcdn-axis' }, i ? (fmt === P.bytes ? P.bytes(max * i / 4).replace(/\s*[٫.]0+ /, ' ') : fmt(max * i / 4)) : t('۰')));
    }
    var n = labels.length, slot = pw / Math.max(1, n), bw = Math.max(2, Math.min(26, slot * 0.66));
    var step = Math.max(1, Math.ceil(n / Math.max(2, Math.floor(pw / (narrow ? 64 : 80)))));
    labels.forEach(function (lb, i2) {
      var x = L + i2 * slot + slot / 2;
      if (i2 % step === 0) svg.appendChild(s('text', { x: x, y: H - 8, 'text-anchor': 'middle', class: 'pcdn-axis' }, lb));
      var base = 0;
      var g = s('g', { class: 'pcdn-stack-col' });
      series.forEach(function (sr) {
        var v = sr.values[i2] || 0;
        if (v <= 0) return;
        var y1 = y(base + v), y0 = y(base);
        g.appendChild(s('rect', { x: x - bw / 2, y: y1, width: bw, height: Math.max(0.5, y0 - y1), class: 'pcdn-bar', style: 'fill:' + sr.color }));
        base += v;
      });
      g.appendChild(s('title', {}, lb + ' — ' + series.filter(function (sr) { return sr.values[i2] > 0; })
        .map(function (sr) { return sr.name + ': ' + fmt(sr.values[i2]); }).join(t('، ')) + (totals[i2] ? '' : fmt === P.bytes ? t(' بدون ترافیک') : '')));
      svg.appendChild(g);
    });
    wrap.appendChild(svg);
    host.appendChild(h('div', { className: 'pcdn-legend' }, series.map(function (sr) {
      var tot = sr.values.reduce(function (tx, v) { return tx + (v || 0); }, 0);
      return h('span', { className: 'pcdn-legend-item' }, h('span', { className: 'pcdn-key', style: 'background:' + sr.color }), h('span', { text: sr.name }), h('strong', { text: fmt(tot) }));
    })));
  }

  // ================================================================== «کیفیت تونل» (§15.3 quality + §15.4 health)

  var PERIODS = [['24', t('۲۴ ساعت')], ['168', t('۷ روز')], ['720', t('۳۰ روز')]];
  var ISSUE = {
    origin_refused: [t('اتصال به سرور شما رد شد'), t('سرور شما روی پورت مسیر اتصال را رد می‌کند؛ سرویس Xray/sing-box و پورت را بررسی کنید.')],
    origin_timeout: [t('مهلت اتصال به سرور شما تمام شد'), t('سرور شما دیر جواب می‌دهد یا فایروال آن اتصال نودهای CDN را بی‌پاسخ می‌گذارد؛ فایروال، بار سرور و مسیر شبکه‌ی آن را بررسی کنید.')],
    origin_error: [t('پاسخ نامعتبر از سرور شما'), t('سرور شما اتصال را پذیرفت ولی پاسخ تونل نداد (مثلاً ۴۰۴ یا ۴۰۰)؛ مسیر، پروتکل و TLS ورودی سرور را با «بررسی کانفیگ سرور» مقایسه کنید.')],
    limit: [t('سقف تعداد اتصال پر شد'), t('به سقف اتصال همزمان رسیده‌اید؛ «حداکثر اتصال هر IP» را بیشتر کنید یا پلن با اتصال بیشتر بگیرید.')],
    country: [t('کاربر خارج از کشورهای مجاز'), t('کاربرانی از کشوری خارج از «کشورهای مجاز» وصل شده‌اند؛ اگر لازم است فهرست کشورها را تغییر دهید.')],
    protocol: [t('کلاینت با پروتکل اشتباه وصل شد'), t('کلاینت با پروتکلی غیر از پروتکل مسیر وصل می‌شود؛ لینک اشتراک را دوباره از «پیکربندی آماده» بگیرید.')],
    edge: [t('خطای موقت نود CDN'), t('خطای موقت در نودهای CDN؛ اگر ادامه داشت با پشتیبانی تماس بگیرید.')]
  };
  var ERR_KEYS = ['origin_refused', 'origin_timeout', 'origin_error', 'limit', 'country', 'protocol', 'edge'];

  function qState() { var st = S(); return st.tq || (st.tq = { hours: '24', data: {}, at: {}, drops: {}, dropsAt: {}, dropsOk: undefined }); }

  function healthBadge(W) {
    var hd = W.health || {}, st = hd.state;
    var M = { up: ['success', 'checkCircle', t('سرور پشت تونل در دسترس است'), t('نودهای CDN در چند دقیقه‌ی گذشته به سرور شما وصل شده‌اند.')],
      down: ['danger', 'xCircle', t('سرور پشت تونل پاسخ نمی‌دهد'), t('بیشتر تلاش‌های نودهای CDN برای اتصال به سرور شما ناموفق بوده است. سرویس Xray/sing-box، پورت و فایروال سرور را بررسی کنید.')],
      unknown: ['muted', 'clock', t('وضعیت سرور هنوز مشخص نیست'), t('در چند دقیقه‌ی گذشته اتصال تونلی کافی برای قضاوت ثبت نشده است.')] };
    var m = M[st] || M.unknown;
    var since = hd.since ? h('span', { className: 'pcdn-muted pcdn-small' }, (st === 'down' ? t('قطع از ') : st === 'up' ? t('وصل از ') : t('از ')) , h('time', { dateTime: String(hd.since), title: P.date(hd.since), text: P.rel(hd.since) })) : null;
    var check = hd.last_check ? h('span', { className: 'pcdn-muted pcdn-small' }, t('آخرین بررسی: '), h('time', { dateTime: String(hd.last_check), text: P.rel(hd.last_check) })) : null;
    return h('div', { className: 'pcdn-tq-health pcdn-tone-' + m[0], role: 'status', 'data-origin-health': st || 'unknown' },
      h('span', { className: 'pcdn-tq-health-icon' }, icon(m[1])),
      h('div', { className: 'pcdn-tq-health-text' }, h('strong', { text: m[2] }), h('span', { text: m[3] }),
        h('span', { className: 'pcdn-tq-health-meta' }, since, check),
        st === 'down' ? h('span', { className: 'pcdn-tq-health-links' }, A().goLink('tunnel', t('تست اتصال در صفحه تونل')), A().goLink('tconfig', t('بررسی کانفیگ سرور'))) : null));
  }

  function renderQuality(Aa) {
    var Q = qState(), W = w7State();
    var hours = Q.hours;
    var holder = h('div', { className: 'pcdn-stack', 'data-tq-holder': hours });
    var healthSlot = h('div', { className: 'pcdn-tq-health-slot' }, W.health ? healthBadge(W) : P.skeleton(1));
    var seg = P.segmented(PERIODS, hours, function (v) { Q.hours = v; Aa.renderMain(); }, t('بازه کیفیت تونل'));
    seg.setAttribute('data-seg', 'tq-hours');
    var refresh = refreshBtn(t('بروزرسانی کیفیت تونل'), function (b) { load(b, true); });
    var bar = h('div', { className: 'pcdn-toolbar pcdn-toolbar-end' }, seg, refresh);
    function alive() { return S().page === 'tquality' && Q.hours === hours && document.body.contains(holder); }
    function load(b, force) {
      if (force || !W.health || Date.now() - W.healthAt > 60000) {
        fetchHealth().then(function () { if (alive() && W.health) { clear(healthSlot); healthSlot.appendChild(healthBadge(W)); } });
      }
      if (!force && Q.data[hours] && Date.now() - (Q.at[hours] || 0) < 60000) { setTimeout(function () { if (alive()) draw(holder, Q.data[hours], Number(hours)); }, 0); return; }
      if (!Q.data[hours]) { clear(holder); holder.appendChild(skeletons()); }
      P.busy(b || null, P.api('GET', 'tunnel/quality', undefined, { hours: hours })).then(function (res) {
        if (!alive()) return;
        if (!res.ok) {
          clear(holder);
          if (res.status === 404) { W.ok = false; holder.appendChild(P.alertBox('info', t('گزارش کیفیت تونل روی این سرور CDN در دسترس نیست.'))); return; }
          holder.appendChild(P.errorBox(res, t('دریافت گزارش کیفیت تونل ممکن نشد')));
          return;
        }
        Q.data[hours] = res.data || {};
        Q.at[hours] = Date.now();
        draw(holder, Q.data[hours], Number(hours));
      });
    }
    var dropsSlot = h('div', { className: 'pcdn-tq-drops-slot', 'data-drops-slot': '1' });
    function loadDrops(force) {
      if (Q.dropsOk === false) return;   // older controller: section hidden
      if (!force && Q.drops[hours] && Date.now() - (Q.dropsAt[hours] || 0) < 60000) { setTimeout(function () { if (alive()) drawDrops(dropsSlot, Q.drops[hours], Number(hours)); }, 0); return; }
      P.api('GET', 'tunnel/drops', undefined, { hours: hours }).then(function (res) {
        if (!alive()) return;
        clear(dropsSlot);
        if (!res.ok) {
          if (res.status === 404) { Q.dropsOk = false; return; }
          dropsSlot.appendChild(P.errorBox(res, t('دریافت گزارش دلیل قطع اتصال ممکن نشد')));
          return;
        }
        Q.dropsOk = true;
        Q.drops[hours] = res.data || {};
        Q.dropsAt[hours] = Date.now();
        drawDrops(dropsSlot, Q.drops[hours], Number(hours));
      });
    }
    var load0 = load;
    load = function (b, force) { load0(b, force); loadDrops(force); };
    load(null, false);
    S().redrawCharts = function () {
      if (Q.data[hours] && alive()) draw(holder, Q.data[hours], Number(hours));
      if (Q.drops[hours] && alive()) drawDrops(dropsSlot, Q.drops[hours], Number(hours));
    };
    return [bar, healthSlot, holder, dropsSlot];
  }
  function skeletons() {
    return h('div', { className: 'pcdn-stack' }, h('div', { className: 'pcdn-kpis' }, [1, 2, 3, 4].map(function () { return h('div', { className: 'pcdn-kpi' }, P.skeleton(3)); })),
      h('div', { className: 'pcdn-card' }, h('div', { className: 'pcdn-card-body' }, h('div', { className: 'pcdn-skel pcdn-skel-chart' }))));
  }

  function draw(holder, d, hours) {
    clear(holder);
    var paths = Array.isArray(d.paths) ? d.paths.filter(function (p) { return p && typeof p === 'object'; }) : [];
    var edges = Array.isArray(d.edges) ? d.edges.filter(function (e) { return e && typeof e === 'object'; }) : [];
    var series = Array.isArray(d.series) ? d.series : [];
    var sessions = 0, errors = 0, abnormal = 0, cSum = 0, cN = 0;
    paths.forEach(function (p) {
      var n = Number(p.sessions) || 0;
      sessions += n;
      errors += Number(p.error_total) || 0;
      if (isNum(p.abnormal_pct)) abnormal += p.abnormal_pct * n / 100;
      if (isNum(p.connect_ms_avg) && n) { cSum += p.connect_ms_avg * n; cN += n; }
    });
    var succ = sessions + errors > 0 ? 100 * sessions / (sessions + errors) : null;
    holder.appendChild(h('div', { className: 'pcdn-kpis', 'data-tq-kpis': '1' },
      kpi('link', 'brand', t('نشست‌های موفق'), num(sessions), t('اتصال‌هایی که به سرور شما رسیدند'), 'tq-sessions'),
      kpi('checkCircle', successTone(succ), t('نرخ موفقیت'), pct(succ), num(errors) + t(' اتصال ناموفق'), 'tq-success'),
      kpi('warn', 'warning', t('قطع غیرعادی'), sessions ? pct(abnormal * 100 / sessions) : NO_DATA, t('نشست‌هایی که ناگهان قطع شدند'), 'tq-abnormal'),
      kpi('clock', 'violet', t('زمان اتصال به سرور'), cN ? ms(cSum / cN) : NO_DATA, t('میانگین زمان وصل شدن نود به سرور شما'), 'tq-connect')));
    if (!paths.length) {
      holder.appendChild(P.card({ title: t('مسیرها'), icon: 'link', id: 'tq-paths' }));
      holder.lastChild.body.appendChild(P.empty('activity', t('در این بازه داده‌ای ثبت نشده است'),
        t('وقتی کاربران از مسیرهای تونل استفاده کنند، کیفیت هر مسیر با چند دقیقه تأخیر اینجا نمایش داده می‌شود.')));
      return;
    }
    // per-path cards
    var pc = P.card({ title: t('کیفیت هر مسیر'), icon: 'link', id: 'tq-paths', subtitle: t('نرخ موفقیت = نشست‌های موفق ÷ (نشست‌های موفق + اتصال‌های ناموفق).') });
    var grid = h('div', { className: 'pcdn-tq-grid' });
    paths.slice().sort(function (a, b) { return (a.removed ? 1 : 0) - (b.removed ? 1 : 0) || (Number(b.sessions) || 0) - (Number(a.sessions) || 0); })
      .forEach(function (p) { grid.appendChild(pathCard(p)); });
    pc.body.appendChild(grid);
    holder.appendChild(pc);
    // hourly chart
    var C = P.charts || {};
    var cc = P.card({ title: t('روند نشست‌ها و خطاها'), icon: 'chart', tone: 'violet', id: 'tq-chart',
      subtitle: hours <= 48 ? t('ساعتی') : hours <= 168 ? t('هر ۴ ساعت') : t('روزانه') });
    holder.appendChild(cc);
    var size = hours <= 48 ? 1 : hours <= 168 ? 4 : 24;
    var pts = [];
    for (var i = 0; i < series.length; i += size) {
      var b = { t: series[i].t, sessions: 0, errors: 0, abnormal: 0 };
      for (var j = i; j < Math.min(series.length, i + size); j++) {
        b.sessions += Number(series[j].sessions) || 0; b.errors += Number(series[j].errors) || 0; b.abnormal += Number(series[j].abnormal) || 0;
      }
      pts.push(b);
    }
    var any = pts.some(function (x) { return x.sessions || x.errors || x.abnormal; });
    if (!pts.length || !any || !C.area) cc.body.appendChild(P.empty('chart', t('در این بازه نشستی ثبت نشده است'), null));
    else {
      var labels = pts.map(function (x) { return size >= 24 ? P.date(x.t, { month: 'short', day: 'numeric' }) : P.date(x.t, hours <= 48 ? { hour: '2-digit', minute: '2-digit' } : { day: 'numeric', hour: '2-digit' }); });
      C.area(cc.body, labels, [
        { name: t('نشست‌های موفق'), color: C.COLORS.requests, values: pts.map(function (x) { return x.sessions; }), total: num(sessions) },
        { name: t('اتصال‌های ناموفق'), color: C.COLORS.s5, values: pts.map(function (x) { return x.errors; }), total: num(errors) },
        { name: t('قطع غیرعادی'), color: C.COLORS.s4, values: pts.map(function (x) { return x.abnormal; }) }
      ], num, t('نمودار نشست‌ها، خطاها و قطع‌های غیرعادی تونل'));
    }
    // per-edge table (node names only — never addresses)
    if (edges.length) {
      var ec = P.card({ title: t('کیفیت به تفکیک نود'), icon: 'server', tone: 'muted', id: 'tq-edges',
        subtitle: t('اگر فقط یک نود مشکل دارد، معمولاً مسیر شبکه‌ی آن نود تا سرور شما کند است و سیستم خودش ترافیک را به نودهای سالم می‌برد.') });
      var tbody = h('tbody');
      edges.forEach(function (e) {
        var tone = isNum(e.abnormal_pct) && e.abnormal_pct >= 10 ? 'is-bad' : '';
        tbody.appendChild(h('tr', { className: tone, 'data-edge': String(e.name || '') },
          h('td', { 'data-label': t('نود') }, h('bdi', { dir: 'ltr', text: String(e.name || '—') })),
          h('td', { 'data-label': t('نشست‌ها'), className: 'pcdn-num', text: num(e.sessions || 0) }),
          h('td', { 'data-label': t('قطع غیرعادی'), className: 'pcdn-num', text: pct(e.abnormal_pct) }),
          h('td', { 'data-label': t('زمان اتصال'), className: 'pcdn-num', text: ms(e.connect_ms_avg) }),
          h('td', { 'data-label': t('اتصال ناموفق'), className: 'pcdn-num', text: num(e.error_total || 0) })));
      });
      ec.body.appendChild(h('div', { className: 'pcdn-table-wrap' }, h('table', { className: 'pcdn-table pcdn-rtable pcdn-tq-edges' },
        h('caption', { className: 'pcdn-sr', text: t('کیفیت تونل به تفکیک نود') }),
        h('thead', null, h('tr', null, [t('نود'), t('نشست‌ها'), t('قطع غیرعادی'), t('زمان اتصال'), t('اتصال ناموفق')].map(function (tx) { return h('th', { scope: 'col', text: tx }); }))),
        tbody)));
      holder.appendChild(ec);
    }
  }

  function pathCard(p) {
    var tone = successTone(p.success_pct);
    var errs = p.errors && typeof p.errors === 'object' ? p.errors : {};
    var chips = ERR_KEYS.filter(function (k) { return Number(errs[k]) > 0; }).map(function (k) {
      return h('span', { className: 'pcdn-tq-chip', 'data-err': k }, h('span', { text: ISSUE[k][0] }), h('strong', { text: num(errs[k]) }));
    });
    var top = p.top_issue && ISSUE[p.top_issue] ? p.top_issue : null;
    // The controller's advice is Persian: on an English page the known issues use our own text (SPEC §16.10).
    var advice = P.isEn && top && ISSUE[top] ? ISSUE[top][1]
      : typeof p.advice === 'string' && p.advice ? P.ctlText(p.advice) : top ? ISSUE[top][1] : null;
    var avg = Number(p.avg_session_s);
    return h('article', { className: 'pcdn-tq-path' + (p.removed ? ' is-removed' : ''), 'data-tq-path': String(p.id || '') },
      h('header', { className: 'pcdn-tq-path-head' }, protoBadge(p.protocol),
        h('bdi', { className: 'pcdn-vchip pcdn-tn-pathval', dir: 'ltr', text: String(p.path || p.id || '—') }),
        p.removed ? P.badge(t('حذف‌شده از تنظیمات'), 'muted') : null),
      h('div', { className: 'pcdn-tq-big pcdn-tone-' + tone },
        h('span', { className: 'pcdn-tq-big-val', text: pct(p.success_pct) }), h('span', { className: 'pcdn-tq-big-lbl', text: t('نرخ موفقیت') })),
      isNum(p.success_pct) ? P.meter(p.success_pct / 100, tone === 'muted' ? null : tone) : null,
      h('dl', { className: 'pcdn-dl pcdn-tq-dl' },
        h('div', null, h('dt', { text: t('نشست‌ها') }), h('dd', { text: num(p.sessions || 0) })),
        h('div', null, h('dt', { text: t('قطع غیرعادی') }), h('dd', { text: pct(p.abnormal_pct) })),
        h('div', null, h('dt', { text: t('زمان اتصال به سرور') }), h('dd', { text: ms(p.connect_ms_avg) })),
        h('div', null, h('dt', { text: t('میانگین طول نشست') }), h('dd', { text: avg > 0 ? P.dur(Math.round(avg)) : NO_DATA })),
        // §22.7: share of connects that reused a kept-alive connection to your server (approximation; null without data)
        p.reuse_pct !== undefined ? h('div', { 'data-tq-reuse': isNum(p.reuse_pct) ? String(p.reuse_pct) : '' }, h('dt', { text: t('استفاده‌ی دوباره از اتصال به سرور') }),
          h('dd', { text: pct(p.reuse_pct) })) : null),
      chips.length ? h('div', { className: 'pcdn-tq-chips' }, chips) : null,
      top ? P.alertBox(tone === 'success' ? 'info' : 'warning', [h('strong', { text: t('مشکل اصلی: ') + ISSUE[top][0] + '. ' }), advice || ''], { icon: 'bulb' })
        : (isNum(p.success_pct) ? h('p', { className: 'pcdn-muted pcdn-small', text: t('مشکل قابل توجهی دیده نشد.') }) : null));
  }

  // ================================================================== «چرا اتصال من قطع شد؟» (§22.12)
  //
  // Why accepted tunnel sessions ended, per reason / hour / path, plus rejected reconnects, the plan state and planned node
  // maintenance — never a node name or address (the controller sends none: `maintenance` rows carry only time + kind).

  var END_KEYS = ['normal', 'idle_timeout', 'origin', 'node_reload', 'node_drain', 'other'];
  var END = {
    normal: [t('عادی (برنامه یا سرور شما بست)'), t('برنامه‌ی شما یا سرور شما اتصال را بست (عادی).'), 'var(--pc-c-2xx)'],
    idle_timeout: [t('مهلت بیکاری'), t('اتصال مدتی بی‌استفاده ماند و پس از مهلت بیکاری بسته شد؛ keepalive برنامه را طبق «تنظیمات پیشنهادی» کم کنید یا مهلت بیکاری مسیر را بیشتر کنید.'), 'var(--pc-c-4xx)'],
    origin: [t('قطع از سمت سرور شما'), t('سرور شما (Xray/sing-box) اتصال را قطع کرد یا ری‌استارت شد؛ لاگ سرور را بررسی کنید.'), 'var(--pc-c-5xx)'],
    node_reload: [t('اعمال تنظیمات روی نود'), t('یک نود هنگام اعمال تنظیمات جدید، اتصال‌های بسیار طولانی را پس از مهلت مجاز بست؛ برنامه خودکار دوباره وصل می‌شود.'), 'var(--pc-c-req)'],
    node_drain: [t('تخلیه‌ی نود برای به‌روزرسانی'), t('نود برای به‌روزرسانی برنامه‌ریزی‌شده تخلیه شد؛ اتصال‌های جدید به نودهای دیگر رفتند.'), 'var(--pc-c-bytes)'],
    other: [t('خطای لبه'), t('خطای داخلی لبه؛ اگر تکرار شد با پشتیبانی تماس بگیرید.'), 'var(--pc-faint)']
  };

  function drawDrops(slot, d, hours) {
    clear(slot);
    var c = P.card({ title: t('چرا اتصال من قطع شد؟'), icon: 'warn', tone: 'warning', id: 'tq-drops',
      subtitle: t('دلیل پایان نشست‌های تونل در همین بازه، به زبان ساده.') });
    slot.appendChild(c);
    if (!d || d.has_data === false) {
      c.body.appendChild(P.alertBox('info', t('گزارش دلیل قطع پس از به‌روزرسانی نودها در دسترس است.')));
      c.body.lastChild.setAttribute('data-drops-nodata', '1');
      planNotes(c.body, d || {});
      return;
    }
    var reasons = d.reasons && typeof d.reasons === 'object' ? d.reasons : {};
    var total = isNum(d.total) ? d.total : END_KEYS.reduce(function (a, k) { return a + (Number(reasons[k]) || 0); }, 0);
    var top = d.top && END[d.top] ? d.top : null;
    planNotes(c.body, d);
    if (top) {
      c.body.appendChild(P.alertBox(top === 'other' || top === 'origin' ? 'warning' : 'info',
        [h('strong', { text: t('بیشترین دلیل قطع (غیر از عادی): ') + END[top][0] + '. ' }), END[top][1]], { icon: 'bulb' }));
      c.body.lastChild.setAttribute('data-drops-top', top);
    } else if (total > 0) {
      c.body.appendChild(h('p', { className: 'pcdn-muted pcdn-small', 'data-drops-top': '', text: t('بیشتر نشست‌ها عادی بسته شده‌اند؛ دلیل غیرعادی قابل توجهی دیده نشد.') }));
    }
    if (!total) {
      c.body.appendChild(P.empty('activity', t('در این بازه نشستی پایان نیافته است'), null));
      rejectedNotes(c.body, d);
      return;
    }
    // reasons: bars with count, share and the plain-language explanation
    var keys = END_KEYS.slice().sort(function (a, b) { return (Number(reasons[b]) || 0) - (Number(reasons[a]) || 0); });
    var max = Math.max(1, Number(reasons[keys[0]]) || 0);
    c.body.appendChild(h('ul', { className: 'pcdn-barlist pcdn-tq-reasons', 'data-drops-reasons': '1' }, keys.map(function (k) {
      var v = Number(reasons[k]) || 0;
      return h('li', { 'data-reason': k, className: v ? '' : 'is-zero' },
        h('div', { className: 'pcdn-barlist-row' },
          h('span', { className: 'pcdn-barlist-label' }, h('span', { className: 'pcdn-key', style: 'background:' + END[k][2] }), h('span', { text: END[k][0] })),
          h('span', { className: 'pcdn-barlist-val' }, h('strong', { text: num(v) }), h('span', { className: 'pcdn-muted', text: P.pct(v, total) }))),
        h('span', { className: 'pcdn-barlist-track' }, h('span', { className: 'pcdn-barlist-bar', style: 'width:' + (v ? Math.max(1, Math.round(v * 100 / max)) : 0) + '%;background:' + END[k][2] })),
        v && k !== 'normal' ? h('p', { className: 'pcdn-muted pcdn-small pcdn-tq-reason-why', text: END[k][1] }) : null);
    })));
    // hourly stacked series (4-hourly for 7 days, daily for 30)
    var series = Array.isArray(d.series) ? d.series.filter(function (x) { return x && typeof x === 'object'; }) : [];
    var size = hours <= 48 ? 1 : hours <= 168 ? 4 : 24, pts = [];
    for (var i = 0; i < series.length; i += size) {
      var b = { t: series[i].t };
      END_KEYS.forEach(function (k) { b[k] = 0; });
      for (var j = i; j < Math.min(series.length, i + size); j++) END_KEYS.forEach(function (k) { b[k] += Number(series[j][k]) || 0; });
      pts.push(b);
    }
    if (pts.some(function (x) { return END_KEYS.some(function (k) { return x[k] > 0; }); })) {
      var ch = h('div', { className: 'pcdn-tq-drops-chart', 'data-drops-chart': '1' });
      c.body.appendChild(h('h4', { className: 'pcdn-tq-sub', text: t('روند قطع‌ها') }));
      c.body.appendChild(ch);
      stackedBars(ch, pts.map(function (x) { return size >= 24 ? P.date(x.t, { month: 'short', day: 'numeric' }) : P.date(x.t, hours <= 48 ? { hour: '2-digit', minute: '2-digit' } : { day: 'numeric', hour: '2-digit' }); }),
        END_KEYS.map(function (k) { return { name: END[k][0], color: END[k][2], values: pts.map(function (x) { return x[k]; }) }; }),
        t('نمودار دلیل پایان نشست‌های تونل'), function (v) { return num(Math.round(v)); });
    }
    // per path: total + top reason
    var paths = Array.isArray(d.paths) ? d.paths.filter(function (p) { return p && typeof p === 'object'; }) : [];
    if (paths.length) {
      var names = pathNames();
      var tbody = h('tbody');
      paths.forEach(function (p) {
        var tp = p.top && END[p.top] ? p.top : null;
        tbody.appendChild(h('tr', { 'data-drops-path': String(p.id || '') },
          h('td', { 'data-label': t('مسیر') }, h('bdi', { dir: 'ltr', className: 'pcdn-tn-pathval', text: names[p.id] || String(p.id || '—') })),
          h('td', { 'data-label': t('نشست‌های پایان‌یافته'), className: 'pcdn-num', text: num(p.total || 0) }),
          h('td', { 'data-label': t('دلیل اصلی') }, tp ? P.badge(END[tp][0], tp === 'other' || tp === 'origin' ? 'danger' : 'warning') : h('span', { className: 'pcdn-muted', text: t('عادی') }))));
      });
      c.body.appendChild(h('h4', { className: 'pcdn-tq-sub', text: t('به تفکیک مسیر') }));
      c.body.appendChild(h('div', { className: 'pcdn-table-wrap' }, h('table', { className: 'pcdn-table pcdn-rtable pcdn-tq-droppaths' },
        h('caption', { className: 'pcdn-sr', text: t('دلیل قطع به تفکیک مسیر') }),
        h('thead', null, h('tr', null, [t('مسیر'), t('نشست‌های پایان‌یافته'), t('دلیل اصلی')].map(function (x) { return h('th', { scope: 'col', text: x }); }))),
        tbody)));
    }
    rejectedNotes(c.body, d);
    // planned maintenance (time + kind only)
    var mt = Array.isArray(d.maintenance) ? d.maintenance.filter(function (m) { return m && m.t; }) : [];
    if (mt.length) {
      c.body.appendChild(h('h4', { className: 'pcdn-tq-sub', text: t('نگهداری برنامه‌ریزی‌شده‌ی نودها در این بازه') }));
      c.body.appendChild(h('ul', { className: 'pcdn-ul pcdn-tq-maint', 'data-drops-maint': String(mt.length) }, mt.slice(0, 20).map(function (m) {
        return h('li', null, h('time', { dateTime: String(m.t), text: P.date(m.t, { dateStyle: 'medium', timeStyle: 'short' }) }), ' — ',
          h('span', { text: m.kind === 'upgrade' ? t('به‌روزرسانی یک نود (اتصال‌ها پیش از آن به نودهای دیگر منتقل شدند)') : t('تخلیه‌ی یک نود برای نگهداری') }));
      })));
    }
  }
  function planNotes(body, d) {
    var pl = d.plan && typeof d.plan === 'object' ? d.plan : {};
    if (pl.over_quota_since) {
      body.appendChild(P.alertBox('danger', [h('strong', { text: t('ترافیک ماهانه‌ی سرویس تمام شده است.') + ' ' }),
        t('از {0} اتصال‌های تازه پذیرفته نمی‌شوند؛ ترافیک افزوده بخرید یا پلن را ارتقا دهید.', P.date(pl.over_quota_since, { dateStyle: 'medium', timeStyle: 'short' }))]));
      body.lastChild.setAttribute('data-drops-plan', 'over_quota');
    } else if (pl.suspended) {
      body.appendChild(P.alertBox('danger', t('سرویس معلق است و اتصال تونلی پذیرفته نمی‌شود.')));
      body.lastChild.setAttribute('data-drops-plan', 'suspended');
    }
  }
  function rejectedNotes(body, d) {
    var r = d.rejected && typeof d.rejected === 'object' ? d.rejected : {};
    var items = [];
    if (Number(r.limit) > 0) items.push(['limit', num(r.limit) + ' — ' + t('تلاش‌های اتصال دوباره به سقف اتصال پلن یا سهم منصفانه‌ی نود خورد.')]);
    if (Number(r.origin_refused) > 0) items.push(['origin_refused', num(r.origin_refused) + ' — ' + t('سرور شما اتصال دوباره را رد کرد.')]);
    if (Number(r.origin_timeout) > 0) items.push(['origin_timeout', num(r.origin_timeout) + ' — ' + t('سرور شما به اتصال دوباره در زمان مناسب پاسخ نداد.')]);
    if (!items.length) return;
    body.appendChild(h('div', { className: 'pcdn-tq-rejected', 'data-drops-rejected': '1' }, h('h4', { className: 'pcdn-tq-sub', text: t('تلاش‌های اتصال دوباره که پذیرفته نشدند') }),
      h('ul', { className: 'pcdn-ul' }, items.map(function (x) { return h('li', { 'data-rejected': x[0], text: x[1] }); }))));
  }

  // ================================================================== «مصرف تونل» (§15.3 usage)

  var COLORS = ['var(--pc-c-req)', 'var(--pc-c-bytes)', 'var(--pc-c-hit)', 'var(--pc-c-4xx)', 'var(--pc-c-2xx)', 'var(--pc-c-5xx)'];
  function uState() { var st = S(); return st.tu || (st.tu = { by: 'protocol', data: null, at: 0 }); }

  function renderUsage(Aa) {
    var U = uState();
    var holder = h('div', { className: 'pcdn-stack', 'data-tu-holder': '1' });
    var refresh = refreshBtn(t('بروزرسانی مصرف تونل'), function (b) { load(b, true); });
    function alive() { return S().page === 'tusage' && document.body.contains(holder); }
    function load(b, force) {
      if (!force && U.data && Date.now() - U.at < 60000) { setTimeout(function () { if (alive()) drawUsage(holder, U.data, Aa); }, 0); return; }
      if (!U.data) { clear(holder); holder.appendChild(skeletons()); }
      P.busy(b || null, P.api('GET', 'tunnel/usage', undefined, { days: '30' })).then(function (res) {
        if (!alive()) return;
        if (!res.ok) {
          clear(holder);
          if (res.status === 404) { w7State().ok = false; holder.appendChild(P.alertBox('info', t('گزارش مصرف تونل روی این سرور CDN در دسترس نیست.'))); return; }
          holder.appendChild(P.errorBox(res, t('دریافت مصرف تونل ممکن نشد')));
          return;
        }
        U.data = res.data || {};
        U.at = Date.now();
        drawUsage(holder, U.data, Aa);
      });
    }
    load(null, false);
    S().redrawCharts = function () { if (U.data && alive()) drawUsage(holder, U.data, Aa); };
    return [h('div', { className: 'pcdn-toolbar pcdn-toolbar-end' }, refresh), holder];
  }

  function drawUsage(holder, d, Aa) {
    clear(holder);
    var U = uState();
    var days = Array.isArray(d.days) ? d.days.filter(function (x) { return x && typeof x === 'object'; }) : [];
    var m = d.month && typeof d.month === 'object' ? d.month : {};
    var used = Number(m.used_bytes) || 0, limit = isNum(m.limit_bytes) && m.limit_bytes > 0 ? m.limit_bytes : null;
    var fc = isNum(m.forecast_bytes) ? m.forecast_bytes : null;
    // month card
    var mc = P.card({ title: t('این ماه'), icon: 'activity', id: 'tu-month', tone: 'brand',
      subtitle: t('ترافیک تونل جزو ترافیک ماهانه سرویس حساب می‌شود.') });
    var ratio = limit ? used / limit : 0;
    append(mc.body, [
      h('dl', { className: 'pcdn-dl' },
        h('div', { 'data-tu': 'used' }, h('dt', { text: t('مصرف تونل این ماه') }), h('dd', { text: P.bytes(used) })),
        h('div', { 'data-tu': 'limit' }, h('dt', { text: t('سقف ترافیک سرویس') }), h('dd', { text: limit ? P.bytes(limit) : t('بدون سقف') })),
        h('div', { 'data-tu': 'forecast' }, h('dt', { text: t('پیش‌بینی مصرف تا پایان ماه') }), h('dd', { text: fc !== null ? P.bytes(fc) : NO_DATA })),
        limit ? h('div', { 'data-tu': 'exhaust' }, h('dt', { text: t('تاریخ احتمالی اتمام ترافیک') }),
          h('dd', { text: m.forecast_exhaust_date ? P.date(m.forecast_exhaust_date, { dateStyle: 'medium' }) : t('پیش از پایان ماه تمام نمی‌شود') })) : null),
      limit ? h('div', { className: 'pcdn-usage-bar' }, P.meter(Math.min(1, ratio), ratio >= 1 ? 'danger' : ratio >= 0.85 ? 'warning' : 'brand'),
        h('div', { className: 'pcdn-usage-bar-legend' }, h('span', { text: P.pct(used, limit) + t(' مصرف‌شده') }), h('span', { text: P.bytes(used) + t(' از ') + P.bytes(limit) }))) : null,
      m.forecast_exhaust_date && limit ? P.alertBox('warning', [h('strong', { text: t('با این روند، ترافیک حدود ') + P.date(m.forecast_exhaust_date, { dateStyle: 'medium' }) + t(' تمام می‌شود. ') }),
        t('برای جلوگیری از قطعی، '), Aa.wallet ? t('اعتبار کیف پول را شارژ کنید یا ') : '', t('بسته‌ی ترافیک افزوده بخرید یا پلن را ارتقا دهید.')], { icon: 'activity' })
        : fc !== null && limit ? h('p', { className: 'pcdn-usage-forecast' }, icon('activity'), h('span', { text: t(' با این روند، ترافیک این ماه کافی است.') })) : null
    ]);
    holder.appendChild(mc);
    // totals
    var up = 0, down = 0, sess = 0;
    days.forEach(function (x) { up += Number(x.bytes_up) || 0; down += Number(x.bytes_down) || 0; sess += Number(x.sessions) || 0; });
    holder.appendChild(h('div', { className: 'pcdn-kpis', 'data-tu-kpis': '1' },
      kpi('upload', 'warning', t('آپلود (۳۰ روز)'), P.bytes(up), t('از کاربران به سرور شما'), 'tu-up'),
      kpi('download', 'success', t('دانلود (۳۰ روز)'), P.bytes(down), t('از سرور شما به کاربران'), 'tu-down'),
      kpi('link', 'brand', t('نشست‌ها (۳۰ روز)'), num(sess), null, 'tu-sessions'),
      kpi('chart', 'violet', t('میانگین روزانه'), P.bytes(days.length ? (up + down) / days.length : 0), null, 'tu-avg')));
    // daily chart by protocol / path
    var seg = P.segmented([['protocol', t('بر اساس پروتکل')], ['path', t('بر اساس مسیر')]], U.by, function (v) { U.by = v; drawUsage(holder, d, Aa); }, t('تفکیک نمودار'));
    seg.setAttribute('data-seg', 'tu-by');
    var cc = P.card({ title: t('مصرف روزانه'), icon: 'chart', tone: 'violet', id: 'tu-daily', actions: seg });
    holder.appendChild(cc);
    var key = U.by === 'path' ? 'by_path' : 'by_protocol';
    var totals = {};
    days.forEach(function (x) { var o = x[key] && typeof x[key] === 'object' ? x[key] : {}; Object.keys(o).forEach(function (k) { totals[k] = (totals[k] || 0) + bytesOf(o[k]); }); });
    var keys = Object.keys(totals).filter(function (k) { return totals[k] > 0; }).sort(function (a, b) { return totals[b] - totals[a]; });
    var top = keys.slice(0, 5), rest = keys.slice(5);
    var names = pathNames();
    var series = top.map(function (k, i) {
      return { name: U.by === 'path' ? (names[k] || k) : (PROTO[k] || k), color: COLORS[i % COLORS.length],
        values: days.map(function (x) { var o = x[key] || {}; return bytesOf(o[k]); }) };
    });
    if (rest.length) series.push({ name: t('سایر'), color: 'var(--pc-faint)', values: days.map(function (x) { var o = x[key] || {}; return rest.reduce(function (tx, k) { return tx + bytesOf(o[k]); }, 0); }) });
    if (!series.length) {
      var tot = days.map(function (x) { return (Number(x.bytes_up) || 0) + (Number(x.bytes_down) || 0); });
      if (tot.some(function (v) { return v > 0; })) series = [{ name: t('ترافیک تونل'), color: COLORS[1], values: tot }];
    }
    if (!days.length || !series.length) {
      cc.body.appendChild(P.empty('chart', t('هنوز ترافیک تونلی ثبت نشده است'), t('پس از اتصال اولین کاربر، مصرف روزانه با چند دقیقه تأخیر اینجا نمایش داده می‌شود.')));
      return;
    }
    stackedBars(cc.body, days.map(function (x) { return P.date(String(x.date) + 'T12:00:00Z', { month: 'short', day: 'numeric' }); }), series,
      t('نمودار مصرف روزانه تونل ') + (U.by === 'path' ? t('به تفکیک مسیر') : t('به تفکیک پروتکل')));
  }
  /** path id → path text from the saved tunnel section (for the «بر اساس مسیر» legend). */
  function pathNames() {
    var out = {}, c = site().config && site().config.tunnel;
    ((c && c.paths) || []).forEach(function (p) { if (p && p.id) out[p.id] = String(p.path || p.id); });
    return out;
  }

  // ================================================================== «بررسی کانفیگ سرور» (§15.7, browser only)

  var MAX_CFG = 524288;
  /** The site's saved tunnel paths with the port(s) and TLS the CDN uses to reach the origin. */
  function checkCtx() {
    var c = site().config && site().config.tunnel;
    var list = (c && Array.isArray(c.paths)) ? c.paths : [];
    var hosts = P.tunnelHosts ? P.tunnelHosts() : [];
    return { domain: site().domain, paths: list.filter(function (p) { return p && p.path; }).map(function (p) {
      var ports = [], tls = false;
      var cands = p.origin || p.pool || (Array.isArray(p.origins) && p.origins.length) ? [null] : (hosts.length ? hosts : [null]);
      var many = Array.isArray(p.origins) && p.origins.length > 0;
      cands.forEach(function (hn) {
        var l = P.tunnelListen ? P.tunnelListen(p, hn) : { port: p.origin ? Number(p.origin.port) || (p.origin.tls ? 443 : 80) : 80, tls: !!(p.origin && p.origin.tls) };
        // §22.4: every origin of a multi-origin path is a valid listen port
        (many && P.tunnelPorts ? P.tunnelPorts(p, hn) : [l.port]).forEach(function (v) { if (ports.indexOf(v) < 0) ports.push(v); });
        tls = l.tls;
      });
      var out = { id: String(p.id || ''), path: String(p.path), protocol: String(p.protocol || ''), ports: ports, tls: tls,
        mode: many ? 'multi' : p.pool ? 'pool' : p.origin ? 'custom' : 'site' };
      // §22.5: edge idle timeout + recommended keepalive of the saved path (wave-13 controllers only; read from the cached profile — no request)
      var pp = P.tprofile && P.tprofile.ok() === true ? P.tprofile.path(out.id) : null;
      if (pp && isNum(pp.idle_timeout_s)) {
        out.idle_timeout_s = pp.idle_timeout_s;
        out.keepalive_s = pp.recommended && isNum(pp.recommended.keepalive_s) ? pp.recommended.keepalive_s : (P.tguide ? P.tguide.keepalive(pp.idle_timeout_s, P.tprofile.edge().client_idle_s) : null);
      }
      return out;
    }) };
  }

  function renderConfigCheck(Aa) {
    var C = P.tunnelCheck;
    var ctx = checkCtx();
    var out = [];
    out.push(P.alertBox('info', [h('strong', { text: t('حریم خصوصی: ') }), t('کانفیگ فقط در همین مرورگر بررسی می‌شود؛ به هیچ سروری فرستاده نمی‌شود و جایی ذخیره نمی‌شود. با بستن یا ترک این صفحه پاک می‌شود. شناسه‌ها و کلیدهای خصوصی هیچ‌جا کامل نمایش داده نمی‌شوند.')], { icon: 'lock' }));
    var c = P.card({ title: t('کانفیگ سرور'), icon: 'fileText', id: 'tc-input', subtitle: t('محتوای config.json سرور Xray یا sing-box را بچسبانید (کامل یا فقط بخش inbounds).') });
    var ta = h('textarea', { className: 'pcdn-input pcdn-mono pcdn-tc-input', dir: 'ltr', rows: 12, spellcheck: 'false', autocomplete: 'off', autocapitalize: 'off',
      'data-ro-ok': '1', 'aria-label': t('کانفیگ JSON سرور'), placeholder: '{\n  "inbounds": [ … ]\n}', maxlength: MAX_CFG, 'data-lpignore': 'true', 'data-1p-ignore': 'true' });
    var result = h('div', { className: 'pcdn-tc-result', 'aria-live': 'polite' });
    var go = P.btn(t('بررسی کانفیگ'), { kind: 'primary', icon: 'shieldCheck', cls: 'pcdn-tc-run', onclick: function () { runCheck(); } });
    go.setAttribute('data-ro-ok', '1');
    var wipe = P.btn(t('پاک کردن'), { icon: 'trash', cls: 'pcdn-tc-clear', onclick: function () { ta.value = ''; clear(result); ta.focus(); } });
    wipe.setAttribute('data-ro-ok', '1');
    function runCheck() {
      clear(result);
      if (!C) { result.appendChild(P.alertBox('danger', t('بررسی‌کننده بارگذاری نشد؛ صفحه را دوباره باز کنید.'))); return; }
      var text = ta.value;
      if (text.length > MAX_CFG) { result.appendChild(P.alertBox('danger', t('کانفیگ بیش از حد بزرگ است.'))); return; }
      ctx = checkCtx();   // wave 13: the profile (edge idle timeouts) may have arrived after the page was drawn — cached, no request
      var r = C.run(text, ctx);
      result.appendChild(resultView(r, ctx));
      var first = result.querySelector('.pcdn-tc-summary');
      if (first && first.scrollIntoView) first.scrollIntoView({ block: 'nearest', behavior: Aa.reduced && Aa.reduced() ? 'auto' : 'smooth' });
    }
    ta.addEventListener('keydown', function (e) { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); runCheck(); } });
    append(c.body, [ta, h('div', { className: 'pcdn-row-actions' }, go, wipe, h('span', { className: 'pcdn-muted pcdn-small', text: t('Ctrl+Enter هم بررسی می‌کند.') }))]);
    out.push(c);
    out.push(result);
    // reference: what the site expects
    var ref = P.collapsible({ title: t('مسیرهای تونل این سایت (مبنای مقایسه)'), icon: 'link', tone: 'muted', id: 'tc-paths', open: !ctx.paths.length });
    if (!ctx.paths.length) ref.body.appendChild(P.alertBox('warning', [t('هنوز مسیر تونلی ذخیره نشده است. '), Aa.goLink('tunnel', t('ساخت مسیر در صفحه تونل'))]));
    else {
      var tbody = h('tbody');
      var withIdle = ctx.paths.some(function (p) { return isNum(p.idle_timeout_s); });
      ctx.paths.forEach(function (p) {
        tbody.appendChild(h('tr', { 'data-tc-path': p.id },
          h('td', { 'data-label': t('مسیر') }, h('bdi', { dir: 'ltr', className: 'pcdn-tn-pathval', text: p.path })),
          h('td', { 'data-label': t('پروتکل') }, protoBadge(p.protocol)),
          h('td', { 'data-label': t('پورت مورد انتظار') }, h('bdi', { dir: 'ltr', text: p.ports.join(' / ') })),
          h('td', { 'data-label': t('TLS روی سرور') }, h('span', { text: p.tls ? t('بله (security: tls)') : t('خیر (security: none)') })),
          withIdle ? h('td', { 'data-label': t('مهلت بیکاری لبه / keepalive') }, h('span', { text: isNum(p.idle_timeout_s) ? P.dur(p.idle_timeout_s) + ' / ' + num(p.keepalive_s) + t(' ثانیه') : '—' })) : null));
      });
      ref.body.appendChild(h('div', { className: 'pcdn-table-wrap' }, h('table', { className: 'pcdn-table pcdn-rtable' },
        h('caption', { className: 'pcdn-sr', text: t('مسیرهای تونل سایت') }),
        h('thead', null, h('tr', null, [t('مسیر'), t('پروتکل'), t('پورت مورد انتظار'), t('TLS روی سرور')].concat(withIdle ? [t('مهلت بیکاری لبه / keepalive')] : [])
          .map(function (tx) { return h('th', { scope: 'col', text: tx }); }))),
        tbody)));
    }
    out.push(ref);
    // the text lives only in this textarea: drop it when the page is left
    onLeave(function () { ta.value = ''; });
    return out;
  }

  var LEVEL = { error: ['danger', 'xCircle', t('خطا')], warning: ['warning', 'warn', t('هشدار')], ok: ['success', 'checkCircle', t('درست')], info: ['info', 'info', t('نکته')] };
  function resultView(r, ctx) {
    var sum = r.summary || {};
    var head = h('div', { className: 'pcdn-tc-summary pcdn-alert pcdn-alert-' + (r.ok ? (sum.warning ? 'warning' : 'success') : 'danger'), role: 'status', 'data-tc-ok': r.ok ? '1' : '0' },
      icon(r.ok ? 'checkCircle' : 'xCircle'),
      h('div', { className: 'pcdn-alert-body' },
        h('strong', { text: r.ok ? (sum.warning ? t('کانفیگ قابل استفاده است ولی چند نکته دارد.') : t('کانفیگ با تنظیمات تونل سایت هماهنگ است.')) : t('کانفیگ مشکل دارد و احتمالاً وصل نمی‌شود.') }),
        h('div', { className: 'pcdn-tc-counts' },
          r.kind ? P.badge(r.kind === 'singbox' ? 'sing-box' : 'Xray', 'muted') : null,
          P.badge(num(sum.error || 0) + t(' خطا'), sum.error ? 'danger' : 'muted'),
          P.badge(num(sum.warning || 0) + t(' هشدار'), sum.warning ? 'warning' : 'muted'),
          P.badge(num(sum.ok || 0) + t(' مورد درست'), sum.ok ? 'success' : 'muted'))));
    var list = h('ul', { className: 'pcdn-tc-findings' }, (r.findings || []).map(function (f) {
      var L = LEVEL[f.level] || LEVEL.info;
      return h('li', { className: 'pcdn-tc-finding is-' + f.level, 'data-level': f.level, 'data-code': f.code },
        h('span', { className: 'pcdn-tc-ficon pcdn-tone-' + L[0], title: L[2] }, icon(L[1]), h('span', { className: 'pcdn-sr', text: L[2] + ': ' })),
        h('div', { className: 'pcdn-tc-ftext' }, h('span', { className: 'pcdn-tc-ftitle', text: f.title }),
          f.fix ? h('span', { className: 'pcdn-tc-ffix' }, h('b', { text: t('راه‌حل: ') }), f.fix) : null));
    }));
    return h('div', { className: 'pcdn-card pcdn-tc-card', 'data-card': 'tc-result' }, h('div', { className: 'pcdn-card-body' }, head, list,
      r.ok && ctx.paths.length ? h('p', { className: 'pcdn-muted pcdn-small', text: t('پس از اعمال کانفیگ، Xray / sing-box را ری‌استارت و در صفحه تونل «تست اتصال» را بزنید.') }) : null));
  }

  // ================================================================== «تست سرعت» (§15.6 — the customer's own domain only)

  var PINGS = 10;
  var DOWN_SIZES = [1048576, 10485760];   // 1 MB warm-up/slow links, then 10 MB (edge maximum)
  var UP_SIZES = [1048576, 8388608];
  function spState() { var st = S(); return st.sp || (st.sp = { result: null }); }

  /** Base URL of the customer's own domain (whatever node DNS gives) and why a test may be impossible. */
  function speedTarget() {
    var st = site(), ssl = st.ssl || {};
    var pageHttps = window.location.protocol === 'https:';
    var https = ssl.status === 'active';
    if (st.status !== 'active') return { base: null, why: 'pending' };
    if (!https && pageHttps) return { base: null, why: 'mixed' };
    return { base: (https ? 'https://' : 'http://') + st.domain, why: null };
  }

  function now() { return window.performance && performance.now ? performance.now() : Date.now(); }
  function rid() { return Math.random().toString(36).slice(2) + Date.now().toString(36); }

  function randomBlob(n) {
    var chunk = new Uint8Array(Math.min(n, 65536));
    try { window.crypto.getRandomValues(chunk); } catch (e) { for (var i = 0; i < chunk.length; i++) chunk[i] = (i * 131 + 7) & 255; }
    var parts = [], left = n;
    while (left > 0) { var k = Math.min(left, chunk.length); parts.push(k === chunk.length ? chunk : chunk.subarray(0, k)); left -= k; }
    // text/plain keeps the POST a CORS "simple request" (no preflight)
    return new Blob(parts, { type: 'text/plain' });
  }

  function runSpeed(base, ui, signal) {
    var res = { ping: [], ping_ms: null, jitter_ms: null, down_mbps: null, up_mbps: null, node: null, cors: true, error: null };
    var opts = { mode: 'cors', cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' };
    /** fetch with a per-request time limit (a stuck connection never hangs the page) chained to the page's abort signal. */
    function f(path, extra, ms) {
      var ac = window.AbortController ? new AbortController() : null, timedOut = false, timer = null;
      if (ac) {
        if (signal) { if (signal.aborted) ac.abort(); else signal.addEventListener('abort', function () { ac.abort(); }); }
        timer = setTimeout(function () { timedOut = true; ac.abort(); }, ms || 15000);
      }
      return fetch(base + path + (path.indexOf('?') >= 0 ? '&' : '?') + '_=' + rid(), Object.assign({}, opts, extra || {}, ac ? { signal: ac.signal } : {}))
        .then(function (r) { if (timer) clearTimeout(timer); return r; }, function (e) {
          if (timer) clearTimeout(timer);
          if (timedOut) { var tx = new Error('timeout'); tx.code = 'timeout'; throw tx; }
          throw e;
        });
    }
    function check(r) {
      if (r.status === 429) { var e = new Error('rate'); e.code = 'rate'; throw e; }
      if (!r.ok) { var e2 = new Error('http'); e2.code = 'http'; e2.status = r.status; throw e2; }
      if (!res.node) { var nd = r.headers.get('X-Pcdn-Node'); if (nd && /^[A-Za-z0-9._-]{1,64}$/.test(nd)) res.node = nd; }
      return r;
    }
    function pingOnce() { var t0 = now(); return f('/__pcdn/speed/ping').then(check).then(function () { return now() - t0; }); }
    function pings(i) {
      if (i > PINGS) return Promise.resolve();
      return pingOnce().then(function (d) {
        if (i > 0) { res.ping.push(d); ui.progress('ping', i / PINGS, d); }   // i = 0 is the warm-up (DNS + TLS)
        return pings(i + 1);
      });
    }
    function download(sizes) {
      var best = null;
      function one(k) {
        if (k >= sizes.length) return Promise.resolve();
        var n = sizes[k], t0 = now(), got = 0;
        return f('/__pcdn/speed/down?bytes=' + n, null, 60000).then(check).then(function (r) {
          if (r.body && r.body.getReader) {
            var rd = r.body.getReader();
            var pump = function () {
              return rd.read().then(function (x) {
                if (x.done) return;
                got += x.value.length;
                ui.progress('down', got / n, got * 8 / Math.max(1, now() - t0) / 1000);
                return pump();
              });
            };
            return pump();
          }
          return r.arrayBuffer().then(function (b) { got = b.byteLength; });
        }).then(function () {
          var sec = Math.max(0.001, (now() - t0) / 1000), mbps = got * 8 / sec / 1e6;
          best = best === null ? mbps : Math.max(best, mbps);
          res.down_mbps = best;
          if (sec > 4 && k === 0) return;          // slow link: the small file is enough
          return one(k + 1);
        });
      }
      return one(0);
    }
    function upload(sizes) {
      var best = null;
      function one(k) {
        if (k >= sizes.length) return Promise.resolve();
        var n = sizes[k], body = randomBlob(n), t0 = now();
        ui.progress('up', 0.05, null);
        return f('/__pcdn/speed/up', { method: 'POST', body: body }, 60000).then(check).then(function () {
          var sec = Math.max(0.001, (now() - t0) / 1000), mbps = n * 8 / sec / 1e6;
          best = best === null ? mbps : Math.max(best, mbps);
          res.up_mbps = best;
          ui.progress('up', (k + 1) / sizes.length, mbps);
          if (sec > 4 && k === 0) return;
          return one(k + 1);
        });
      }
      return one(0);
    }
    function stats() {
      if (!res.ping.length) return;
      var a = res.ping.slice().sort(function (x, y) { return x - y; });
      res.ping_ms = a[Math.floor(a.length / 2)];
      var j = 0;
      for (var i = 1; i < res.ping.length; i++) j += Math.abs(res.ping[i] - res.ping[i - 1]);
      res.jitter_ms = res.ping.length > 1 ? j / (res.ping.length - 1) : 0;
    }
    return pings(0).then(stats).then(function () { return download(DOWN_SIZES); }).then(function () { return upload(UP_SIZES); })
      .then(function () { return res; }, function (e) {
        stats();
        if (e && e.name === 'AbortError') { res.error = 'abort'; return res; }
        if (e && e.code) { res.error = e.code; res.status = e.status; return res; }
        // TypeError: blocked by CORS, DNS / TLS failure or offline. Tell CORS apart with an opaque (no-cors) ping.
        if (res.ping.length) { res.error = 'network'; return res; }
        var t0 = now();
        return f('/__pcdn/speed/ping', { mode: 'no-cors' }, 10000).then(function () {
          res.cors = false;
          res.error = 'cors';
          res.ping_ms = now() - t0;   // rough: one opaque round trip
          return res;
        }, function () { res.error = 'network'; return res; });
      });
  }

  function verdict(r) {
    var out = [];
    if (isNum(r.ping_ms)) {
      var p = r.ping_ms;
      out.push(p < 60 ? t('تأخیر (پینگ) عالی است؛ برای بازی آنلاین و تماس تصویری مناسب است.') : p < 120 ? t('تأخیر خوب است؛ وب‌گردی و تماس صوتی/تصویری روان است.')
        : p < 250 ? t('تأخیر متوسط است؛ وب‌گردی خوب است ولی بازی آنلاین ممکن است کمی کند باشد.') : t('تأخیر زیاد است؛ معمولاً به‌خاطر اینترنت شما یا شلوغی شبکه در این لحظه است. چند دقیقه بعد دوباره امتحان کنید.'));
    }
    if (isNum(r.jitter_ms) && r.jitter_ms > 30) out.push(t('نوسان پینگ زیاد است (') + f1(r.jitter_ms) + t(' میلی‌ثانیه)؛ اتصال اینترنت شما ناپایدار است (مثلاً Wi-Fi ضعیف).'));
    if (isNum(r.down_mbps)) {
      var d = r.down_mbps;
      out.push(d >= 50 ? t('سرعت دانلود عالی است؛ ویدیوی 4K هم روان پخش می‌شود.') : d >= 20 ? t('سرعت دانلود خوب است؛ ویدیوی Full HD روان پخش می‌شود.')
        : d >= 5 ? t('سرعت دانلود متوسط است؛ برای وب‌گردی و ویدیوی معمولی کافی است.') : t('سرعت دانلود کم است؛ معمولاً سقف سرعت اینترنت شما یا شلوغی شبکه است.'));
    }
    if (isNum(r.up_mbps)) out.push(r.up_mbps >= 10 ? t('سرعت آپلود برای تماس تصویری و ارسال فایل خوب است.') : t('سرعت آپلود محدود است؛ ارسال فایل‌های بزرگ کندتر است (در اینترنت خانگی طبیعی است).'));
    return out;
  }

  function gauge(id, ic, label, unit) {
    var val = h('span', { className: 'pcdn-sp-val', text: '—' });
    var bar = h('span', { className: 'pcdn-sp-bar', style: 'width:0%' });
    var el = h('div', { className: 'pcdn-sp-gauge', 'data-sp': id },
      h('div', { className: 'pcdn-sp-top' }, icon(ic), h('span', { className: 'pcdn-sp-label', text: label })),
      h('div', { className: 'pcdn-sp-num' }, val, h('span', { className: 'pcdn-sp-unit', text: unit })),
      h('span', { className: 'pcdn-sp-track' }, bar));
    return { el: el, set: function (v, frac) { val.textContent = v; if (frac !== undefined) bar.style.width = Math.max(0, Math.min(100, frac * 100)).toFixed(0) + '%'; } };
  }

  function renderSpeed(Aa) {
    var SP = spState(), tg = speedTarget();
    var out = [];
    var c = P.card({ title: t('تست سرعت تا CDN'), icon: 'gauge', id: 'sp-card',
      subtitle: t('از مرورگر شما تا دامنه‌ی خودتان، از طریق همان نودی که DNS به شما می‌دهد. نشانی هیچ نودی نمایش داده یا انتخاب نمی‌شود.') });
    var gP = gauge('ping', 'clock', t('تأخیر (پینگ)'), t('میلی‌ثانیه')), gD = gauge('down', 'download', t('دانلود'), t('مگابیت بر ثانیه')), gU = gauge('up', 'upload', t('آپلود'), t('مگابیت بر ثانیه'));
    var status = h('p', { className: 'pcdn-muted pcdn-sp-status', 'aria-live': 'polite' });
    var verdictBox = h('div', { className: 'pcdn-sp-verdict' });
    var ctrl = null;
    var start = P.btn(SP.result ? t('تست دوباره') : t('شروع تست'), { kind: 'primary', icon: 'gauge', cls: 'pcdn-sp-start', disabled: !tg.base, onclick: function () {
      if (ctrl) return;
      clear(verdictBox);
      [gP, gD, gU].forEach(function (g) { g.set('—', 0); });
      ctrl = window.AbortController ? new AbortController() : null;
      start.disabled = true;
      start.classList.add('is-busy');
      status.textContent = t('در حال اندازه‌گیری تأخیر…');
      runSpeed(tg.base, { progress: function (kind, frac, v) {
        if (kind === 'ping') { gP.set(num(Math.round(v)), frac); status.textContent = t('در حال اندازه‌گیری تأخیر… (') + num(Math.round(frac * PINGS)) + t(' از ') + num(PINGS) + ')'; }
        if (kind === 'down') { if (v !== null) gD.set(f1(v), frac); status.textContent = t('در حال اندازه‌گیری سرعت دانلود…'); }
        if (kind === 'up') { if (v !== null) gU.set(f1(v), frac); status.textContent = t('در حال اندازه‌گیری سرعت آپلود…'); }
      } }, ctrl ? ctrl.signal : undefined).then(function (r) {
        ctrl = null;
        if (!document.body.contains(start)) return;
        start.disabled = false;
        start.classList.remove('is-busy');
        start.querySelector('span').textContent = t('تست دوباره');
        SP.result = r;   // in-memory only for this page view (never stored)
        paint(r);
      });
    } });
    start.setAttribute('data-ro-ok', '1');
    function paint(r) {
      gP.set(isNum(r.ping_ms) ? num(Math.round(r.ping_ms)) : '—', isNum(r.ping_ms) ? 1 : 0);
      gD.set(isNum(r.down_mbps) ? f1(r.down_mbps) : '—', isNum(r.down_mbps) ? 1 : 0);
      gU.set(isNum(r.up_mbps) ? f1(r.up_mbps) : '—', isNum(r.up_mbps) ? 1 : 0);
      clear(verdictBox);
      status.textContent = r.error ? '' : t('تست کامل شد.');
      if (r.error === 'cors') {
        verdictBox.appendChild(P.alertBox('warning', [h('strong', { text: t('مرورگر اجازه‌ی اندازه‌گیری کامل را نداد. ') }),
          t('دامنه در دسترس است') + (isNum(r.ping_ms) ? t(' (یک رفت‌وبرگشت حدود ') + num(Math.round(r.ping_ms)) + t(' میلی‌ثانیه)') : '') +
          t(' ولی سرور CDN هنوز اجازه‌ی تست سرعت از صفحه‌ی ناحیه کاربری را نمی‌دهد. چند دقیقه بعد دوباره امتحان کنید؛ اگر ادامه داشت به پشتیبانی اطلاع دهید.')], { icon: 'warn' }));
        return;
      }
      if (r.error === 'rate') { verdictBox.appendChild(P.alertBox('warning', t('تعداد تست‌ها در یک دقیقه زیاد شد؛ یک دقیقه صبر کنید و دوباره امتحان کنید.'))); }
      else if (r.error === 'timeout') verdictBox.appendChild(P.alertBox('danger', t('پاسخی از دامنه‌ی شما در زمان مناسب نرسید. اینترنت خود را بررسی کنید و چند دقیقه بعد دوباره امتحان کنید.')));
      else if (r.error === 'network') verdictBox.appendChild(P.alertBox('danger', t('اتصال به دامنه‌ی شما برقرار نشد. اینترنت خود را بررسی کنید؛ اگر سایت در مرورگر هم باز نمی‌شود، وضعیت سرویس را در «نمای کلی» ببینید.')));
      else if (r.error === 'http') verdictBox.appendChild(P.alertBox('danger', t('سرور CDN به تست پاسخ نداد (HTTP ') + num(r.status || 0) + t('). کمی بعد دوباره امتحان کنید.')));
      else if (r.error === 'abort') return;
      var lines = verdict(r);
      if (lines.length) {
        verdictBox.appendChild(h('div', { className: 'pcdn-card pcdn-sp-result', 'data-card': 'sp-result' }, h('div', { className: 'pcdn-card-body' },
          h('h4', { text: t('نتیجه به زبان ساده') }),
          h('ul', { className: 'pcdn-ul' }, lines.map(function (x) { return h('li', { text: x }); })),
          h('p', { className: 'pcdn-muted pcdn-small', text: t('این تست سرعت مسیر «شما ← CDN» است. سرعت تونل علاوه بر این به مسیر نود تا سرور شما و پهنای باند آن سرور هم بستگی دارد؛ برای آن «کیفیت تونل» را ببینید.') }),
          r.node ? h('p', { className: 'pcdn-muted pcdn-small' }, t('شناسه‌ی نود پاسخ‌دهنده (برای پشتیبانی): '), ltr(r.node)) : null)));
      }
    }
    var notes = [];
    if (tg.why === 'pending') notes.push(P.alertBox('info', t('تست سرعت پس از فعال شدن سایت روی CDN (تأیید نیم‌سرورها) در دسترس است.')));
    if (tg.why === 'mixed') notes.push(P.alertBox('warning', t('گواهی SSL سایت هنوز فعال نیست و این صفحه روی HTTPS است؛ مرورگر اجازه‌ی تست روی HTTP را نمی‌دهد. پس از صدور گواهی دوباره امتحان کنید.')));
    append(c.body, [notes, h('div', { className: 'pcdn-sp-gauges' }, gP.el, gD.el, gU.el),
      h('div', { className: 'pcdn-row-actions' }, start, status), verdictBox,
      h('p', { className: 'pcdn-muted pcdn-small' }, t('مقصد تست: '), ltr(tg.base ? tg.base + '/__pcdn/speed/' : site().domain || ''),
        t(' — حدود ') + num(25) + t(' مگابایت ترافیک مصرف می‌شود که مثل ترافیک عادی سایت حساب می‌شود.'))]);
    out.push(c);
    var how = P.card({ title: t('چطور نتیجه را بخوانم؟'), icon: 'bulb', tone: 'muted', id: 'sp-how' });
    append(how.body, h('ul', { className: 'pcdn-ul' },
      h('li', { text: t('تأخیر (پینگ): زمان رفت و برگشت یک درخواست کوچک. هر چه کمتر بهتر؛ زیر ۱۰۰ میلی‌ثانیه خوب است.') }),
      h('li', { text: t('دانلود و آپلود: سرعت دریافت و ارسال داده بین شما و CDN. معمولاً سقف آن را سرعت اینترنت خود شما تعیین می‌کند.') }),
      h('li', { text: t('برای مقایسه‌ی منصفانه، تست را چند بار و در ساعت‌های مختلف تکرار کنید؛ Wi-Fi ضعیف و دانلودهای هم‌زمان نتیجه را پایین می‌آورند.') })));
    out.push(how);
    if (SP.result) setTimeout(function () { if (document.body.contains(start)) paint(SP.result); }, 0);
    onLeave(function () { if (ctrl) { try { ctrl.abort(); } catch (e) { /* ignore */ } ctrl = null; } });
    return out;
  }

  // ================================================================== registry

  pages.tquality = {
    title: t('کیفیت تونل'), icon: 'activity', heading: t('کیفیت تونل'),
    desc: t('نرخ موفقیت، قطع‌های غیرعادی و زمان اتصال هر مسیر تونل، همراه با مشکل اصلی و راه‌حل پیشنهادی.'),
    guide: {
      what: t('برای هر مسیر تونل نشان می‌دهد چند درصد اتصال‌ها به سرور شما رسیده‌اند، چند نشست ناگهان قطع شده‌اند و نودها با چه سرعتی به سرور شما وصل می‌شوند.'),
      when: t('وقتی کاربران از قطعی یا کندی شکایت می‌کنند، یا بعد از تغییر کانفیگ سرور.'),
      rec: t('نرخ موفقیت بالای ۹۸٪ و قطع غیرعادی زیر ۲٪ یعنی مسیر سالم است.'),
      mistakes: [t('تغییر پورت یا مسیر روی سرور بدون به‌روزرسانی مسیر در صفحه تونل.'), t('بستن آی‌پی‌های CDN در فایروال سرور.')],
      tut: 'tunnel'
    },
    hidden: function () { return !supported() || !tunnelOn(); },
    render: renderQuality
  };
  pages.tusage = {
    title: t('مصرف تونل'), icon: 'chart', heading: t('مصرف تونل'),
    desc: t('مصرف روزانه‌ی تونل به تفکیک پروتکل و مسیر، مصرف این ماه و پیش‌بینی تاریخ اتمام ترافیک.'),
    hidden: function () { return !supported() || !tunnelOn(); },
    render: renderUsage
  };
  pages.tconfig = {
    title: t('بررسی کانفیگ سرور'), icon: 'fileText', heading: t('بررسی کانفیگ سرور'),
    desc: t('کانفیگ Xray یا sing-box سرور خود را بچسبانید تا با مسیرهای تونل این سایت مقایسه و اشکال‌های رایج پیدا شود — فقط در مرورگر شما.'),
    hidden: function () { return !tunnelOn(); },
    render: renderConfigCheck
  };
  pages.speedtest = {
    title: t('تست سرعت'), icon: 'gauge', heading: t('تست سرعت'),
    desc: t('تأخیر، سرعت دانلود و آپلود از دستگاه شما تا دامنه‌ی شما روی CDN، با توضیح ساده‌ی نتیجه.'),
    hidden: function () { return !supported(); },
    render: renderSpeed
  };
  P.tunnelq = { checkCtx: checkCtx, verdict: verdict, speedTarget: speedTarget };
})();
