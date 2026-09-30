/*
 * Pasargad CDN — client app: live usage view (SPEC §10.3).
 *
 * Registers PCDN.pages.usage — current-month used / included / remaining with a
 * live-updating bar (polls the usage endpoint), today's usage, and a client-side
 * forecast line. Also exports PCDN.usageForecast(series, used, included) so the
 * overview can show the same "با این روند …" line. Uses only existing endpoints.
 */
(function () {
  'use strict';
  var P = window.PCDN = window.PCDN || {};
  if (!P.h) return;
  var h = P.h, append = P.append, clear = P.clear, icon = P.icon, num = P.num, api = P.api;
  var pages = P.pages = P.pages || {};
  function A() { return P.app; }
  var GB = 1073741824;
  var POLL_MS = 8000; // live refresh of the current-month bar

  /**
   * Days until the included traffic runs out at the recent daily rate.
   * series: array of {bytes} (or numbers) daily points. Returns {days, rate} in
   * GB, or null when it cannot be estimated (no rate, already over, unlimited).
   */
  function usageForecast(series, usedGb, includedGb) {
    if (!includedGb || includedGb <= 0) return null;
    var remaining = includedGb - usedGb;
    if (remaining <= 0) return null;
    var vals = (series || []).map(function (p) {
      var b = typeof p === 'number' ? p : (p && p.bytes);
      return (Number(b) || 0) / GB;
    }).filter(function (v) { return v >= 0; });
    if (!vals.length) return null;
    var recent = vals.slice(-7);
    var rate = recent.reduce(function (t, v) { return t + v; }, 0) / recent.length; // GB/day
    if (rate <= 0) return null;
    return { days: Math.max(1, Math.ceil(remaining / rate)), rate: rate };
  }
  P.usageForecast = usageForecast;

  /** Persian forecast sentence for a series, or null. */
  function forecastLine(series, usedGb, includedGb) {
    var f = usageForecast(series, usedGb, includedGb);
    if (!f) return null;
    return 'با این روند، ترافیک شما حدود ' + num(f.days) + ' روز دیگر تمام می‌شود.';
  }
  P.usageForecastLine = forecastLine;

  function limits(Aa) {
    var s = Aa.S.site || {}, plan = s.plan || {};
    var w = Aa.wallet, b = Aa.billing;
    var cap = Number(plan.bandwidth_limit_gb) || 0;
    var included = w ? Number(w.cap_gb) : b ? Number(b.included_gb) : cap;
    return { included: included, planGb: w ? Number(w.plan_gb) : included, unlimited: !(included > 0) };
  }

  function render(Aa) {
    Aa = Aa || A();
    var s = Aa.S.site || {}, lim = limits(Aa);
    var usedGb = (Number((s.usage_month || {}).bytes) || 0) / GB;

    var card = P.card({ title: 'مصرف ماهانه', icon: 'activity', id: 'usage-live', tone: 'brand',
      actions: h('span', { className: 'pcdn-live', 'data-live': '1' }, h('span', { className: 'pcdn-live-dot', 'aria-hidden': 'true' }), h('span', { text: 'زنده' })) });

    var usedEl = h('strong', { 'data-usage': 'used' });
    var remainEl = h('span', { 'data-usage': 'remaining' });
    var bar = h('div', { 'data-usage-bar': '1', className: 'pcdn-usage-bar' });
    var dl = h('dl', { className: 'pcdn-dl' },
      h('div', null, h('dt', { text: 'مصرف این ماه' }), h('dd', null, usedEl)),
      h('div', null, h('dt', { text: lim.unlimited ? 'ترافیک' : 'ترافیک ماهانه' }),
        h('dd', { text: lim.unlimited ? 'نامحدود' : num(lim.included) + ' گیگابایت' + (Aa.wallet && Number(Aa.wallet.bought_gb) > 0 ? ' (' + num(Aa.wallet.plan_gb) + ' پلن + ' + num(Aa.wallet.bought_gb) + ' خریداری‌شده)' : '') })),
      lim.unlimited ? null : h('div', null, h('dt', { text: 'باقی‌مانده' }), h('dd', null, remainEl)));

    var todayEl = h('dd', { 'data-usage': 'today', text: '—' });
    var todayDl = h('dl', { className: 'pcdn-dl' }, h('div', null, h('dt', { text: 'مصرف امروز (۲۴ ساعت گذشته)' }), todayEl));

    var forecastEl = h('p', { className: 'pcdn-usage-forecast', 'data-usage': 'forecast' });

    append(card.body, [dl, lim.unlimited ? null : bar, todayDl, forecastEl]);

    var ctx = { Aa: Aa, lim: lim, usedGb: usedGb, usedEl: usedEl, remainEl: remainEl, bar: bar,
      todayEl: todayEl, forecastEl: forecastEl, card: card, timer: null };
    paintCurrent(ctx);
    loadSeries(ctx);
    startPolling(ctx);
    return card;
  }

  function paintCurrent(ctx) {
    var lim = ctx.lim, used = ctx.usedGb;
    ctx.usedEl.textContent = P.bytes(used * GB);
    if (!lim.unlimited) {
      var remaining = Math.max(0, lim.included - used);
      ctx.remainEl.textContent = num(Math.round(remaining * 10) / 10) + ' گیگابایت';
      var ratio = lim.included > 0 ? used / lim.included : 0;
      var tone = ratio >= 1 ? 'danger' : ratio >= 0.85 ? 'warning' : 'brand';
      clear(ctx.bar);
      ctx.bar.appendChild(P.meter(Math.min(ratio, 1), tone));
      ctx.bar.appendChild(h('div', { className: 'pcdn-usage-bar-legend' },
        h('span', { text: P.pct(used, lim.included) + ' مصرف‌شده' }),
        h('span', { text: num(Math.round(used * 10) / 10) + ' از ' + num(lim.included) + ' گیگابایت' })));
    }
  }

  function loadSeries(ctx) {
    // 24h (today) + 7d (daily rate for the forecast). ensureAnalytics caches per period.
    ctx.Aa.ensureAnalytics('24h').then(function (res) {
      if (!alive(ctx) || !res.ok) return;
      var series = (res.data && res.data.series) || [];
      var todayBytes = series.reduce(function (t, p) { return t + (Number(p.bytes) || 0); }, 0);
      ctx.todayEl.textContent = P.bytes(todayBytes);
    });
    ctx.Aa.ensureAnalytics('7d').then(function (res) {
      if (!alive(ctx)) return;
      var series = (res.ok && res.data && res.data.series) || [];
      var line = forecastLine(series, ctx.usedGb, ctx.lim.included);
      clear(ctx.forecastEl);
      if (line) {
        ctx.forecastEl.appendChild(icon('activity'));
        ctx.forecastEl.appendChild(h('span', { text: ' ' + line }));
      } else if (!ctx.lim.unlimited && ctx.usedGb >= ctx.lim.included) {
        ctx.forecastEl.appendChild(h('span', { className: 'pcdn-text-danger', text: 'ترافیک این ماه به سقف رسیده است.' }));
      } else {
        ctx.forecastEl.appendChild(h('span', { className: 'pcdn-muted', text: 'برای پیش‌بینی، به داده مصرف چند روز اخیر نیاز است.' }));
      }
    });
  }

  function startPolling(ctx) {
    if (ctx.lim.unlimited) return;
    ctx.timer = setInterval(function () {
      if (!alive(ctx)) { clearInterval(ctx.timer); ctx.timer = null; return; }
      api('GET', 'usage').then(function (res) {
        if (!alive(ctx) || !res.ok) return;
        var m = res.data && res.data.month;
        if (m && m.bytes != null) {
          ctx.usedGb = (Number(m.bytes) || 0) / GB;
          if (ctx.Aa.S.site && ctx.Aa.S.site.usage_month) ctx.Aa.S.site.usage_month.bytes = Number(m.bytes) || 0;
          paintCurrent(ctx);
        }
      });
    }, POLL_MS);
  }

  function alive(ctx) {
    return ctx.Aa.S.page === 'usage' && document.body.contains(ctx.card);
  }

  pages.usage = {
    title: 'مصرف زنده', icon: 'activity',
    desc: 'مصرف ترافیک این ماه به‌صورت زنده، مصرف امروز و پیش‌بینی زمان اتمام ترافیک.',
    render: function (Aa) { return render(Aa); }
  };
})();
