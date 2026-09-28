/*
 * Pasargad CDN — reports: inline-SVG charts, analytics and security events.
 * Registers into window.PCDN.pages; app.js provides the shell (PCDN.app) at render time.
 */
(function () {
  'use strict';
  var P = window.PCDN = window.PCDN || {};
  var pages = P.pages = P.pages || {};
  var h = P.h, s = P.s, append = P.append, clear = P.clear, icon = P.icon, ltr = P.ltr, num = P.num;
  function A() { return P.app; }

  // Series colours are theme tokens (app.css), applied through style attributes so they follow light/dark.
  var COLORS = { requests: 'var(--pc-c-req)', hits: 'var(--pc-c-hit)', bytes: 'var(--pc-c-bytes)', s2: 'var(--pc-c-2xx)', s3: 'var(--pc-c-3xx)',
    s4: 'var(--pc-c-4xx)', s5: 'var(--pc-c-5xx)' };

  // ------------------------------------------------------------------ charts

  function niceMax(v) {
    if (v <= 0) return 1;
    var p = Math.pow(10, Math.floor(Math.log(v) / Math.LN10)), n = v / p;
    return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 2.5 ? 2.5 : n <= 5 ? 5 : 10) * p;
  }

  /** Small area sparkline (width follows the container). */
  function sparkline(values) {
    var W = 200, H = 48, max = Math.max.apply(null, [1].concat(values)), n = values.length;
    var pts = values.map(function (v, i) { return [n > 1 ? i * W / (n - 1) : W / 2, H - 3 - (v / max) * (H - 8)]; });
    var line = pts.map(function (p, i) { return (i ? 'L' : 'M') + p[0].toFixed(1) + ' ' + p[1].toFixed(1); }).join(' ');
    var gid = P.uid('pcdn-sg-');
    var svg = s('svg', { viewBox: '0 0 ' + W + ' ' + H, preserveAspectRatio: 'none', class: 'pcdn-spark', role: 'img', 'aria-label': 'روند درخواست‌ها در ۲۴ ساعت گذشته', focusable: 'false' });
    var grad = s('linearGradient', { id: gid, x1: 0, y1: 0, x2: 0, y2: 1 });
    grad.appendChild(s('stop', { offset: '0', style: 'stop-color:' + COLORS.requests + ';stop-opacity:.28' }));
    grad.appendChild(s('stop', { offset: '1', style: 'stop-color:' + COLORS.requests + ';stop-opacity:0' }));
    var defs = s('defs'); defs.appendChild(grad); svg.appendChild(defs);
    if (n) {
      svg.appendChild(s('path', { d: line + ' L' + W + ' ' + H + ' L0 ' + H + ' Z', style: 'fill:url(#' + gid + ');stroke:none' }));
      svg.appendChild(s('path', { d: line, style: 'fill:none;stroke:' + COLORS.requests, 'stroke-width': 2, 'vector-effect': 'non-scaling-stroke', 'stroke-linejoin': 'round' }));
    }
    return h('div', { className: 'pcdn-spark-wrap' }, svg);
  }
  P.sparkline = sparkline;

  function frame(host, labels, max, fmtAxis, aria) {
    var wrap = h('div', { className: 'pcdn-chart', dir: 'ltr' });
    host.appendChild(wrap);
    var W = Math.max(260, Math.floor(wrap.clientWidth || 600)), narrow = W < 480, H = narrow ? 200 : 240;
    var L = narrow ? 52 : 64, R = 12, T = 14, B = 28;
    var svg = s('svg', { width: W, height: H, viewBox: '0 0 ' + W + ' ' + H, role: 'img', 'aria-label': aria, focusable: 'false' });
    var f = { svg: svg, wrap: wrap, W: W, H: H, L: L, T: T, pw: W - L - R, ph: H - T - B, n: labels.length };
    f.y = function (v) { return T + f.ph - (v / max) * f.ph; };
    for (var i = 0; i <= 4; i++) {
      var y = f.y(max * i / 4);
      svg.appendChild(s('line', { x1: L, x2: W - R, y1: y, y2: y, class: i ? 'pcdn-gridline' : 'pcdn-baseline' }));
      svg.appendChild(s('text', { x: L - 8, y: y + 4, 'text-anchor': 'end', class: 'pcdn-axis' }, fmtAxis(max * i / 4)));
    }
    var step = Math.max(1, Math.ceil(f.n / Math.max(2, Math.floor(f.pw / (narrow ? 64 : 80)))));
    f.label = function (i2, x) {
      if (i2 % step === 0) svg.appendChild(s('text', { x: x, y: H - 8, 'text-anchor': 'middle', class: 'pcdn-axis' }, labels[i2]));
    };
    wrap.appendChild(svg);
    return f;
  }

  function hover(f, xAt, rowsAt, dotsAt) {
    var tip = h('div', { className: 'pcdn-tip', hidden: true, dir: 'rtl' });
    var cross = s('line', { y1: f.T, y2: f.T + f.ph, class: 'pcdn-cross', visibility: 'hidden' });
    var dots = s('g', { visibility: 'hidden' });
    f.svg.appendChild(cross);
    f.svg.appendChild(dots);
    f.wrap.appendChild(tip);
    function hide() { tip.hidden = true; cross.setAttribute('visibility', 'hidden'); dots.setAttribute('visibility', 'hidden'); }
    function at(clientX) {
      var r = f.svg.getBoundingClientRect();
      var px = (clientX - r.left) * (f.W / r.width), best = 0, bd = Infinity;
      for (var i = 0; i < f.n; i++) { var dd = Math.abs(xAt(i) - px); if (dd < bd) { bd = dd; best = i; } }
      var x = xAt(best);
      cross.setAttribute('x1', x); cross.setAttribute('x2', x); cross.setAttribute('visibility', 'visible');
      while (dots.firstChild) dots.removeChild(dots.firstChild);
      (dotsAt ? dotsAt(best) : []).forEach(function (d) { dots.appendChild(s('circle', { cx: x, cy: d[0], r: 4, style: 'fill:var(--pc-surface);stroke:' + d[1], 'stroke-width': 2 })); });
      dots.setAttribute('visibility', 'visible');
      clear(tip);
      append(tip, rowsAt(best));
      tip.hidden = false;
      var left = x * (r.width / f.W), tw = tip.offsetWidth;
      tip.style.left = (left + 14 + tw > r.width ? Math.max(0, left - 14 - tw) : left + 14) + 'px';
    }
    f.svg.addEventListener('pointermove', function (e) { at(e.clientX); });
    f.svg.addEventListener('pointerdown', function (e) { at(e.clientX); });
    f.svg.addEventListener('pointerleave', hide);
  }
  function tipRow(color, label, value) {
    return h('div', { className: 'pcdn-tip-row' }, color ? h('span', { className: 'pcdn-key', style: 'background:' + color }) : null,
      h('span', { className: 'pcdn-tip-label', text: label }), h('strong', { text: value }));
  }
  function legend(items) {
    return h('div', { className: 'pcdn-legend' }, items.map(function (it) {
      return h('span', { className: 'pcdn-legend-item' }, h('span', { className: 'pcdn-key', style: 'background:' + it[0] }), h('span', { text: it[1] }), it[2] ? h('strong', { text: it[2] }) : null);
    }));
  }

  function areaChart(host, labels, series, fmt, aria) {
    var max = niceMax(Math.max.apply(null, [0].concat.apply([], series.map(function (x) { return x.values; }))));
    var f = frame(host, labels, max, P.short, aria);
    var xAt = function (i) { return f.L + (f.n > 1 ? i * f.pw / (f.n - 1) : f.pw / 2); };
    for (var i = 0; i < f.n; i++) f.label(i, xAt(i));
    var defs = s('defs');
    f.svg.insertBefore(defs, f.svg.firstChild);
    series.forEach(function (sr) {
      var gid = P.uid('pcdn-g-');
      var g = s('linearGradient', { id: gid, x1: 0, y1: 0, x2: 0, y2: 1 });
      g.appendChild(s('stop', { offset: '0', style: 'stop-color:' + sr.color + ';stop-opacity:.22' }));
      g.appendChild(s('stop', { offset: '1', style: 'stop-color:' + sr.color + ';stop-opacity:.02' }));
      defs.appendChild(g);
      var d = sr.values.map(function (v, i2) { return (i2 ? 'L' : 'M') + xAt(i2).toFixed(1) + ' ' + f.y(v).toFixed(1); }).join(' ');
      f.svg.appendChild(s('path', { d: d + ' L' + xAt(f.n - 1).toFixed(1) + ' ' + (f.T + f.ph) + ' L' + xAt(0).toFixed(1) + ' ' + (f.T + f.ph) + ' Z', style: 'fill:url(#' + gid + ');stroke:none' }));
      f.svg.appendChild(s('path', { d: d, style: 'fill:none;stroke:' + sr.color, 'stroke-width': 2.2, 'stroke-linejoin': 'round', 'stroke-linecap': 'round' }));
    });
    hover(f, xAt, function (i2) {
      return [h('div', { className: 'pcdn-tip-title', text: labels[i2] })].concat(series.map(function (sr) { return tipRow(sr.color, sr.name, fmt(sr.values[i2])); }));
    }, function (i2) { return series.map(function (sr) { return [f.y(sr.values[i2]), sr.color]; }); });
    host.appendChild(legend(series.map(function (sr) { return [sr.color, sr.name, sr.total]; })));
  }

  function barChart(host, labels, values, color, fmt, aria, name) {
    var max = niceMax(Math.max.apply(null, [0].concat(values)));
    var f = frame(host, labels, max, function (v) { return v ? P.bytes(v).replace(/\s*[٫.]0+ /, ' ') : '۰'; }, aria);
    var slot = f.pw / Math.max(1, f.n), bw = Math.max(2, Math.min(28, slot * 0.66));
    var xAt = function (i) { return f.L + i * slot + slot / 2; };
    values.forEach(function (v, i) {
      f.label(i, xAt(i));
      var y = f.y(v), x = xAt(i) - bw / 2, bh = f.T + f.ph - y;
      if (bh <= 0) return;
      var r = Math.min(4, bw / 2, bh);
      f.svg.appendChild(s('path', { style: 'fill:' + color + ';stroke:none', class: 'pcdn-bar', d: 'M' + x + ' ' + (y + bh) + 'V' + (y + r) + 'Q' + x + ' ' + y + ' ' + (x + r) + ' ' + y +
        'H' + (x + bw - r) + 'Q' + (x + bw) + ' ' + y + ' ' + (x + bw) + ' ' + (y + r) + 'V' + (y + bh) + 'Z' }));
    });
    hover(f, xAt, function (i) { return [h('div', { className: 'pcdn-tip-title', text: labels[i] }), tipRow(color, name, fmt(values[i]))]; });
  }

  /** Donut with centre total + legend (label, value, share). parts: [{label, value, color}] */
  function donut(parts, centerLabel) {
    var total = parts.reduce(function (t, p) { return t + (Number(p.value) || 0); }, 0);
    var R = 52, C = 2 * Math.PI * R, off = 0;
    var svg = s('svg', { viewBox: '0 0 140 140', class: 'pcdn-donut', role: 'img', focusable: 'false',
      'aria-label': parts.map(function (p) { return p.label + ': ' + P.pct(p.value, total); }).join('، ') });
    svg.appendChild(s('circle', { cx: 70, cy: 70, r: R, style: 'fill:none;stroke:var(--pc-track)', 'stroke-width': 18 }));
    parts.forEach(function (p) {
      var v = Number(p.value) || 0;
      if (!total || !v) return;
      var len = Math.max(0.5, C * v / total - (parts.length > 1 ? 1.5 : 0));
      svg.appendChild(s('circle', { cx: 70, cy: 70, r: R, style: 'fill:none;stroke:' + p.color, 'stroke-width': 18, 'stroke-dasharray': len + ' ' + (C - len),
        'stroke-dashoffset': -off, transform: 'rotate(-90 70 70)' }));
      off += C * v / total;
    });
    svg.appendChild(s('text', { x: 70, y: 68, 'text-anchor': 'middle', class: 'pcdn-donut-num' }, P.short(total)));
    svg.appendChild(s('text', { x: 70, y: 88, 'text-anchor': 'middle', class: 'pcdn-donut-lbl' }, centerLabel || ''));
    return h('div', { className: 'pcdn-donut-wrap' }, svg,
      h('ul', { className: 'pcdn-donut-legend' }, parts.map(function (p) {
        return h('li', null, h('span', { className: 'pcdn-key', style: 'background:' + p.color }), h('span', { className: 'pcdn-dl-label', text: p.label }),
          h('strong', { text: P.pct(p.value, total) }), h('span', { className: 'pcdn-muted', text: num(p.value) }));
      })));
  }

  /** Horizontal bar list: [[label, value, sublabel?]]. */
  function barList(rows, o) {
    o = o || {};
    if (!rows.length) return P.empty('chart', 'داده‌ای وجود ندارد', null);
    var max = Math.max.apply(null, rows.map(function (r) { return Number(r[1]) || 0; })) || 1;
    var sum = rows.reduce(function (t, r) { return t + (Number(r[1]) || 0); }, 0);
    var total = Math.max(o.total || 0, sum);
    return h('ul', { className: 'pcdn-barlist' }, rows.map(function (r) {
      return h('li', null,
        h('div', { className: 'pcdn-barlist-row' },
          h('span', { className: 'pcdn-barlist-label' + (o.ltr ? ' is-ltr' : ''), dir: o.ltr ? 'ltr' : null, title: r[0] }, r[2] ? h('span', { className: 'pcdn-barlist-sub', dir: 'ltr', text: r[2] }) : null, h('span', { text: r[0] })),
          h('span', { className: 'pcdn-barlist-val' }, h('strong', { text: num(r[1]) }), h('span', { className: 'pcdn-muted', text: P.pct(r[1], total) }))),
        h('span', { className: 'pcdn-barlist-track' }, h('span', { className: 'pcdn-barlist-bar', style: 'width:' + Math.max(1, Math.round((Number(r[1]) || 0) * 100 / max)) + '%' + (o.color ? ';background:' + o.color : '') })));
    }));
  }

  // ------------------------------------------------------------------ analytics

  var PERIODS = [['24h', '۲۴ ساعت'], ['7d', '۷ روز'], ['30d', '۳۰ روز']];
  var SEC_SRC = { waf: 'WAF', firewall: 'فایروال', ratelimit: 'محدودیت نرخ', challenge: 'چالش', ddos: 'DDoS', hotlink: 'Hotlink' };

  function renderAnalytics(Aa) {
    var S = Aa.S;
    var holder = h('div', { className: 'pcdn-stack' });
    var seg = P.segmented(PERIODS, S.period, function (v) { S.period = v; Aa.renderMain(); }, 'بازه زمانی');
    var refresh = P.btn('', { icon: 'refresh', aria: 'بروزرسانی آمار', title: 'بروزرسانی آمار', cls: 'pcdn-btn-iconic', onclick: function () {
      delete S.analytics[S.period];
      Aa.renderMain();
    } });
    refresh.setAttribute('data-ro-ok', '1');
    var bar = h('div', { className: 'pcdn-toolbar pcdn-toolbar-end' }, seg, refresh);
    var period = S.period;
    if (S.analytics[period]) setTimeout(function () { draw(holder, S.analytics[period]); }, 0);
    else {
      append(holder, [h('div', { className: 'pcdn-kpis' }, [1, 2, 3, 4].map(function () { return h('div', { className: 'pcdn-kpi' }, P.skeleton(3)); })),
        h('div', { className: 'pcdn-card' }, h('div', { className: 'pcdn-card-body' }, h('div', { className: 'pcdn-skel pcdn-skel-chart' })))]);
      Aa.ensureAnalytics(period).then(function (res) {
        if (S.page !== 'analytics' || S.period !== period || !document.body.contains(holder)) return;
        if (!res.ok) {
          clear(holder);
          holder.appendChild(P.errorBox(res, 'دریافت آمار ممکن نشد'));
          holder.appendChild(P.btn('تلاش دوباره', { icon: 'refresh', onclick: function () { Aa.renderMain(); } }));
          return;
        }
        draw(holder, res.data);
      });
    }
    S.redrawCharts = function () { if (S.analytics[S.period]) draw(holder, S.analytics[S.period]); };
    return [bar, holder];
  }

  function draw(holder, a) {
    clear(holder);
    var t = a.totals || {}, series = a.series || [], sec = t.security || {}, st = t.status || {};
    var hourly = a.period === '24h';
    var labels = series.map(function (p) { return P.date(p.t, hourly ? { hour: '2-digit', minute: '2-digit' } : { month: 'short', day: 'numeric' }); });
    var reqs = Number(t.requests) || 0, hits = Number(t.cache_hits) || 0, secT = A().secTotal(a);
    function kpi(ic, tone, label, value, sub) {
      return h('div', { className: 'pcdn-kpi' }, h('div', { className: 'pcdn-kpi-top' }, h('span', { className: 'pcdn-kpi-icon pcdn-tone-' + tone }, icon(ic)), h('span', { className: 'pcdn-kpi-label', text: label })),
        h('div', { className: 'pcdn-kpi-value', text: value }), sub ? h('div', { className: 'pcdn-kpi-sub', text: sub }) : null);
    }
    append(holder, h('div', { className: 'pcdn-kpis' },
      kpi('chart', 'brand', 'درخواست‌ها', P.short(reqs), num(reqs) + ' درخواست'),
      kpi('activity', 'violet', 'ترافیک', P.bytes(t.bytes), 'حجم ارسال‌شده به بازدیدکنندگان'),
      kpi('zap', 'success', 'نرخ کش', P.pct(hits, reqs), P.short(hits) + ' پاسخ از کش'),
      kpi('shieldCheck', 'danger', 'رویدادهای امنیتی', num(secT), 'درخواست متوقف یا ثبت‌شده')));

    var e5 = Number(st['5xx']) || 0;
    if (reqs >= 100 && e5 / reqs >= 0.02) {
      holder.appendChild(P.alertBox('warning', [h('strong', { text: 'سهم خطاهای 5xx بالاست (' + P.pct(e5, reqs) + '). ' }), 'سرور اصلی احتمالاً در دسترس نیست یا آی‌پی‌های CDN را مسدود کرده است. ', A().tutLink('troubleshoot', 'عیب‌یابی ۵۰۲ / ۵۰۴')]));
    }

    var c1 = P.card({ title: 'درخواست‌ها و کش', icon: 'chart', id: 'requests' });
    var c2 = P.card({ title: 'ترافیک', icon: 'activity', tone: 'violet', id: 'bytes' });
    append(holder, [c1, c2]);
    if (!series.length) {
      c1.body.appendChild(P.empty('chart', 'هنوز داده‌ای برای این بازه ثبت نشده است', 'پس از تغییر نیم‌سرورها و عبور ترافیک از CDN، آمار اینجا نمایش داده می‌شود.'));
      c2.parentNode.removeChild(c2);
    } else {
      areaChart(c1.body, labels, [
        { name: 'کل درخواست‌ها', color: COLORS.requests, values: series.map(function (p) { return Number(p.requests) || 0; }), total: P.short(reqs) },
        { name: 'پاسخ از کش', color: COLORS.hits, values: series.map(function (p) { return Number(p.cache_hits) || 0; }), total: P.short(hits) }
      ], num, 'نمودار درخواست‌ها و پاسخ‌های کش‌شده');
      barChart(c2.body, labels, series.map(function (p) { return Number(p.bytes) || 0; }), COLORS.bytes, P.bytes, 'نمودار ترافیک', 'ترافیک');
    }

    var cs = P.card({ title: 'کدهای وضعیت', icon: 'checkCircle', tone: 'success', id: 'status' });
    append(cs.body, [donut([
      { label: 'موفق (2xx)', value: st['2xx'] || 0, color: COLORS.s2 }, { label: 'ریدایرکت (3xx)', value: st['3xx'] || 0, color: COLORS.s3 },
      { label: 'خطای کاربر (4xx)', value: st['4xx'] || 0, color: COLORS.s4 }, { label: 'خطای سرور (5xx)', value: st['5xx'] || 0, color: COLORS.s5 }], 'درخواست'),
    (a.status_codes || []).length ? h('div', { className: 'pcdn-codes' }, (a.status_codes || []).map(function (x) {
      var c = String(x.code), tone = c[0] === '2' ? 'success' : c[0] === '3' ? 'brand' : c[0] === '4' ? 'warning' : 'danger';
      return h('span', { className: 'pcdn-code-chip pcdn-tone-' + tone }, h('b', { dir: 'ltr', text: c }), h('span', { text: P.short(x.requests) }));
    })) : null]);
    var cse = P.card({ title: 'رویدادها بر اساس منبع', icon: 'shield', tone: 'danger', id: 'security', actions: A().goLink('events', 'مشاهده رویدادها') });
    cse.body.appendChild(secT ? barList(Object.keys(SEC_SRC).map(function (k) { return [SEC_SRC[k], sec[k] || 0]; }).filter(function (r) { return r[1] > 0; }).sort(function (x, y) { return y[1] - x[1]; }), { color: COLORS.s5 })
      : P.empty('shieldCheck', 'رویداد امنیتی ثبت نشده', 'در این بازه درخواستی مسدود یا ثبت نشده است.'));
    var cc = P.card({ title: 'کشورها', icon: 'globe', id: 'countries' });
    cc.body.appendChild(barList((a.countries || []).slice(0, 10).map(function (x) { return [P.country(x.code), x.requests, String(x.code || '').toUpperCase()]; }), { total: reqs }));
    var cp = P.card({ title: 'پربازدیدترین مسیرها', icon: 'sliders', id: 'paths' });
    cp.body.appendChild(barList((a.paths || []).slice(0, 10).map(function (x) { return [String(x.path), x.requests]; }), { ltr: true, total: reqs }));
    append(holder, h('div', { className: 'pcdn-grid-2' }, cs, cse, cc, cp));
  }

  // ------------------------------------------------------------------ security events

  var SOURCES = [['', 'همه'], ['waf', 'WAF'], ['firewall', 'فایروال'], ['ratelimit', 'محدودیت نرخ'], ['ddos', 'DDoS'], ['hotlink', 'Hotlink']];
  var ACTIONS = { block: ['مسدود', 'danger'], challenge: ['چالش', 'warning'], captcha: ['کپچا', 'warning'], log: ['ثبت', 'muted'] };
  var BLOCK_RULE_ID = 'blocked-ips';

  function renderEvents(Aa) {
    var S = Aa.S;
    var body = h('div', { className: 'pcdn-events' });
    var refresh = P.btn('بروزرسانی', { icon: 'refresh', size: 'sm', cls: 'pcdn-ev-refresh', onclick: function () { load(); } });
    refresh.setAttribute('data-ro-ok', '1');
    var srcChips = h('div', { className: 'pcdn-filter-chips', role: 'group', 'aria-label': 'فیلتر منبع' });
    var actSel = h('select', { className: 'pcdn-input pcdn-input-sm', 'aria-label': 'فیلتر اقدام', 'data-ro-ok': '1', onchange: function (e) { S.ev.action = e.target.value; draw(); } },
      [['', 'همه اقدام‌ها'], ['block', 'مسدود'], ['challenge', 'چالش'], ['captcha', 'کپچا'], ['log', 'فقط ثبت']].map(function (o) {
        return h('option', { value: o[0], text: o[1], selected: S.ev.action === o[0] });
      }));
    function drawChips() {
      clear(srcChips);
      SOURCES.forEach(function (o) {
        var n = (S.events || []).filter(function (e) { return !o[0] || e.source === o[0]; }).length;
        srcChips.appendChild(h('button', { type: 'button', className: 'pcdn-fchip' + (S.ev.source === o[0] ? ' is-active' : ''), 'aria-pressed': String(S.ev.source === o[0]), 'data-source': o[0] || 'all', 'data-ro-ok': '1',
          onclick: function () { S.ev.source = o[0]; drawChips(); draw(); } }, h('span', { text: o[1] }), S.events ? h('span', { className: 'pcdn-fchip-n', text: num(n) }) : null));
      });
    }
    var c = P.card({ title: 'آخرین رویدادها', icon: 'activity', id: 'events', subtitle: '۱۰۰ رویداد آخر؛ جدیدترین در بالا', actions: refresh });
    append(c.body, [h('div', { className: 'pcdn-toolbar' }, srcChips, actSel), body]);
    function load() {
      clear(body);
      body.appendChild(P.skeleton(5));
      P.busy(refresh, P.api('GET', 'events', undefined, { limit: 100 })).then(function (res) {
        if (S.page !== 'events') return;
        if (!res.ok) { clear(body); body.appendChild(P.errorBox(res, 'دریافت رویدادها ممکن نشد')); return; }
        S.events = Array.isArray(res.data) ? res.data : [];
        drawChips();
        draw();
      });
    }
    function draw() {
      clear(body);
      if (!S.events) { body.appendChild(P.skeleton(5)); return; }
      var rows = S.events.filter(function (e) { return (!S.ev.source || e.source === S.ev.source) && (!S.ev.action || e.action === S.ev.action); });
      if (!S.events.length) { body.appendChild(P.empty('shieldCheck', 'رویدادی ثبت نشده است', 'وقتی WAF، فایروال یا سایر بخش‌های امنیتی درخواستی را مسدود یا ثبت کنند، اینجا می‌بینید.')); return; }
      if (!rows.length) { body.appendChild(P.empty('filter', 'رویدادی با این فیلتر وجود ندارد', null, P.btn('نمایش همه', { onclick: function () { S.ev.source = ''; S.ev.action = ''; actSel.value = ''; drawChips(); draw(); } }))); return; }
      var tbody = h('tbody');
      var cards = h('ul', { className: 'pcdn-evcards pcdn-only-narrow' });
      rows.forEach(function (e) { tbody.appendChild(eventRow(e)); cards.appendChild(eventCard(e)); });
      append(body, [h('div', { className: 'pcdn-table-wrap pcdn-only-wide' }, h('table', { className: 'pcdn-table pcdn-ev-table' },
        h('caption', { className: 'pcdn-sr', text: 'رویدادهای امنیتی' }),
        h('colgroup', null, h('col', { style: 'width:104px' }), h('col', { style: 'width:150px' }), h('col'), h('col', { style: 'width:128px' }), h('col', { style: 'width:128px' })),
        h('thead', null, h('tr', null, ['زمان', 'آی‌پی', 'درخواست', 'اقدام', ''].map(function (t) { return h('th', { scope: 'col', text: t }); }))), tbody)), cards]);
      Aa.lockWrites(body);
    }
    drawChips();
    if (S.events) draw(); else load();
    return c;
  }

  function evTime(e) { return h('time', { dateTime: e.t, title: P.date(e.t), className: 'pcdn-ev-time', text: P.rel(e.t) }); }
  function evIp(e) {
    return h('div', { className: 'pcdn-ev-ip' }, h('span', { className: 'pcdn-copyable' }, h('code', { dir: 'ltr', text: e.ip || '—' }), e.ip ? P.copyBtn(e.ip, 'کپی آی‌پی ' + e.ip) : null),
      e.country ? h('span', { className: 'pcdn-ev-cc', title: P.country(e.country) }, h('b', { dir: 'ltr', text: String(e.country).toUpperCase() }), ' ', P.country(e.country)) : null);
  }
  function evReq(e) {
    return h('div', { className: 'pcdn-ev-req' },
      h('div', { className: 'pcdn-ev-line', dir: 'ltr' }, h('span', { className: 'pcdn-method', text: e.method || '' }), h('code', { text: (e.host || '') + (e.path || ''), title: (e.host || '') + (e.path || '') })),
      e.user_agent ? h('div', { className: 'pcdn-ev-ua', dir: 'ltr', title: e.user_agent, text: e.user_agent }) : null);
  }
  function evAction(e) {
    var act = ACTIONS[e.action] || [e.action || '—', 'muted'];
    var src = (SOURCES.filter(function (x) { return x[0] === e.source; })[0] || [0, e.source || '—'])[1];
    return h('div', { className: 'pcdn-ev-act' }, P.badge(act[0], act[1]), h('span', { className: 'pcdn-muted' }, src, e.rule ? [' · ', ltr('#' + e.rule)] : null));
  }
  function blockBtn(e) {
    var f = A().features();
    if (!e.ip || !(f.max_firewall_rules > 0)) return null;
    var b = P.btn('مسدود کردن', { icon: 'ban', size: 'sm', kind: 'danger-soft', write: true, cls: 'pcdn-block-ip', aria: 'مسدود کردن آی‌پی ' + e.ip, onclick: function () { blockIp(e.ip, b); } });
    return b;
  }
  function eventRow(e) {
    return h('tr', { 'data-ip': e.ip }, h('td', null, evTime(e)), h('td', null, evIp(e)), h('td', null, evReq(e)), h('td', null, evAction(e)), h('td', null, blockBtn(e)));
  }
  function eventCard(e) {
    return h('li', { className: 'pcdn-evcard', 'data-ip': e.ip },
      h('div', { className: 'pcdn-evcard-head' }, evAction(e), evTime(e)),
      evIp(e), evReq(e), h('div', { className: 'pcdn-evcard-foot' }, blockBtn(e)));
  }

  function blockIp(ip, button) {
    var Aa = A(), max = Aa.features().max_firewall_rules || 0;
    var fw = Aa.config('firewall');
    fw.rules = fw.rules || [];
    var cidr = /\//.test(ip) ? ip : ip + (ip.indexOf(':') >= 0 ? '/128' : '/32');
    var rule = fw.rules.filter(function (r) { return r.id === BLOCK_RULE_ID; })[0];
    var vals = rule && rule.conditions && rule.conditions[0] && Array.isArray(rule.conditions[0].value) ? rule.conditions[0].value : null;
    if (vals && (vals.indexOf(ip) >= 0 || vals.indexOf(cidr) >= 0)) { P.toast('آی‌پی ' + ip + ' قبلاً در فایروال مسدود شده است.', 'info'); return; }
    if (!rule && fw.rules.length >= max) {
      P.toast('به سقف ' + num(max) + ' قانون فایروال پلن رسیده‌اید؛ یک قانون را حذف کنید یا پلن را ارتقا دهید.', 'error', { label: 'فایروال', fn: function () { Aa.go('firewall'); } });
      return;
    }
    P.confirm({ title: 'مسدود کردن آی‌پی', ok: 'مسدود شود', danger: true,
      body: h('div', null, h('p', null, 'همه درخواست‌های ', ltr(ip), ' در همه سرورهای CDN مسدود می‌شوند.'),
        h('p', { className: 'pcdn-muted', text: rule ? 'آی‌پی به قانون «آی‌پی‌های مسدودشده» در فایروال اضافه می‌شود.' : 'قانون «آی‌پی‌های مسدودشده» در ابتدای فهرست فایروال ساخته می‌شود (' + num(fw.rules.length + 1) + ' از ' + num(max) + ' قانون).' }),
        h('p', { className: 'pcdn-muted', text: 'برای رفع مسدودی، آی‌پی را از همان قانون در بخش فایروال حذف کنید.' })) })
      .then(function (ok) {
        if (!ok) return;
        if (rule) {
          rule.conditions[0].value = (vals || []).concat([cidr]);
          rule.enabled = true;
        } else {
          fw.rules.unshift({ id: BLOCK_RULE_ID, name: 'آی‌پی‌های مسدودشده', enabled: true, action: 'block', conditions: [{ field: 'ip', op: 'in', value: [cidr] }] });
        }
        P.busy(button, Aa.putSection('firewall', fw)).then(function (res) {
          if (!res.ok) { P.toast(P.errorText(res), 'error'); return; }
          P.toast('آی‌پی ' + ip + ' مسدود شد.', 'success', { label: 'مشاهده در فایروال', fn: function () { Aa.go('firewall'); } });
        });
      });
  }

  // ------------------------------------------------------------------ registry

  pages.analytics = {
    title: 'آنالیتیکس', icon: 'chart',
    desc: 'حجم ترافیک، درخواست‌ها، کارایی کش، کشورها و خطاها را در بازه‌های مختلف ببینید.',
    guide: { what: 'آمار همه درخواست‌هایی که از سرورهای CDN عبور کرده‌اند (با کمی تأخیر به‌روز می‌شود).',
      when: 'برای بررسی رشد بازدید، کارایی کش و پیدا کردن خطاها.', rec: 'نرخ کش بالای ۶۰٪ برای سایت‌های معمولی خوب است؛ سهم 5xx باید نزدیک صفر باشد.',
      mistakes: ['نتیجه‌گیری از چند ساعت اول پس از تغییر نیم‌سرورها (هنوز همه ترافیک منتقل نشده).'], tut: 'cache' },
    render: renderAnalytics,
    onResize: function (Aa) { if (Aa.S.redrawCharts) Aa.S.redrawCharts(); }
  };
  pages.events = {
    title: 'رویدادهای امنیتی', icon: 'activity',
    desc: 'درخواست‌هایی که WAF، فایروال، محدودیت نرخ یا حفاظت DDoS مسدود یا ثبت کرده‌اند.',
    guide: { what: 'هر رویداد نشان می‌دهد چه درخواستی، از چه آی‌پی و کشوری، توسط کدام قانون متوقف شده است.',
      when: 'وقتی کاربری خطای ۴۰۳ یا ۴۲۹ گزارش می‌دهد، یا هنگام حمله برای پیدا کردن منبع آن.',
      rec: 'برای مسدودسازی اشتباه WAF، شناسه قانون را بردارید و در WAF استثنا بسازید.',
      mistakes: ['مسدود کردن آی‌پی‌های مشترک (مثل آی‌پی اپراتورهای موبایل) که کاربران زیادی پشت آن هستند.'], tut: 'waf' },
    render: renderEvents
  };
})();
