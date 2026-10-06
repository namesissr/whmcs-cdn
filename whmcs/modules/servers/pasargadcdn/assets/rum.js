/*
 * Pasargad CDN — client app: «تجربهٔ کاربران واقعی» / "Real user monitoring" (SPEC §23.7, wave 14).
 *
 * Registers PCDN.pages.rum — only when the plan has `rum` and the controller returns the `rum` section; a 404 from GET rum
 * (plan without rum, older controller) hides the page again. Shown to the site owner as a performance report only.
 *   - settings (section `rum`): on/off, sample rate, automatic / manual tag (manual shows the <script> tag and the CSP lines),
 *     excluded paths, single-page-app mode;
 *   - KPI cards LCP / INP / CLS / TTFB / FCP (p75, good / needs improvement / poor with the published web-vitals thresholds),
 *     hourly p75 chart, breakdowns by country, internet provider («اپراتور اینترنت»), region, device and page, and «اثر CDN»
 *     (cache HIT vs MISS);
 *   - privacy note «بدون کوکی و بدون ذخیرهٔ IP».
 * All data reaches the DOM through textContent / createElement only.
 */
(function () {
  'use strict';
  var P = window.PCDN = window.PCDN || {};
  var t = P.t;
  if (!P.h) return;
  var h = P.h, append = P.append, clear = P.clear, icon = P.icon, num = P.num, api = P.api;
  var pages = P.pages = P.pages || {};
  function A() { return P.app; }

  var R = { gone: false, hours: 24, by: 'country' };
  var METRICS = [
    ['lcp', 'LCP', t('بزرگ‌ترین محتوای قابل مشاهده'), 'ms'],
    ['inp', 'INP', t('پاسخ به تعامل کاربر'), 'ms'],
    ['cls', 'CLS', t('جابه‌جایی ناگهانی صفحه'), 'cls'],
    ['ttfb', 'TTFB', t('زمان رسیدن اولین بایت'), 'ms'],
    ['fcp', 'FCP', t('اولین نمایش محتوا'), 'ms']
  ];
  var DEF_TH = { lcp: [2500, 4000], inp: [200, 500], cls: [0.1, 0.25], ttfb: [800, 1800], fcp: [1800, 3000] };
  var BY = [['country', t('کشور')], ['isp', t('اپراتور اینترنت')], ['region', t('استان / منطقه')], ['device', t('دستگاه')], ['path', t('صفحه')]];
  var DEVICE = { m: t('موبایل'), t: t('تبلت'), d: t('رایانه') };

  function fmt(v, kind) {
    if (v === null || v === undefined || isNaN(Number(v))) return '—';
    if (kind === 'cls') return P.fa((Math.round(Number(v) * 1000) / 1000).toFixed(Number(v) >= 1 ? 2 : 3).replace(/0+$/, '').replace(/\.$/, ''));
    var n = Number(v);
    return n >= 1000 ? t('{0} ثانیه', P.num1(n / 1000)) : t('{0} میلی‌ثانیه', num(Math.round(n)));
  }
  function grade(v, th) {
    if (v === null || v === undefined || !th) return ['muted', t('بدون داده')];
    return v <= th[0] ? ['success', t('خوب')] : v <= th[1] ? ['warning', t('نیاز به بهبود')] : ['danger', t('ضعیف')];
  }
  function sectionOf(s) { return s && s.config && s.config.rum && typeof s.config.rum === 'object' ? s.config.rum : null; }

  // ------------------------------------------------------------------ settings form

  function settings(Aa) {
    // The section keys are sample_rate / exclude_paths (SPEC §23.7); a controller that answers with the edge names sample / exclude
    // gets those back (the form edits whichever the controller returned).
    var f = Aa.sectionForm('rum', function (d, f2) {
      var SR = has(d, 'sample') && !has(d, 'sample_rate') ? 'sample' : 'sample_rate', EX = has(d, 'exclude') && !has(d, 'exclude_paths') ? 'exclude' : 'exclude_paths';
      if (typeof d.enabled !== 'boolean') d.enabled = false;
      if (!(Number(d[SR]) > 0)) d[SR] = 0.1;
      if (d.inject !== 'manual') d.inject = 'auto';
      if (!Array.isArray(d[EX])) d[EX] = [];
      d.spa = !!d.spa;
      var c = P.card({ title: t('تنظیمات پایش'), icon: 'sliders', id: 'rum-settings',
        subtitle: t('یک اسکریپت کوچک از همان دامنهٔ سایت زمان بارگذاری صفحه را در مرورگر بازدیدکنندگان می‌سنجد.') });
      var pct = { v: Math.round(Number(d[SR]) * 100) };
      append(c.body, [
        P.toggle(d, 'enabled', t('پایش کاربران واقعی روشن باشد'), { cls: 'pcdn-rum-on', onchange: f2.redraw,
          help: t('بدون کوکی، بدون ذخیرهٔ آی‌پی و بدون هیچ شناسه‌ای؛ فقط زمان‌ها، نوع دستگاه و مسیر صفحه (بدون پارامترها).') }),
        h('div', { className: 'pcdn-grid' },
          P.input(pct, 'v', t('درصد بازدیدهای نمونه‌برداری‌شده'), { type: 'number', min: 1, max: 100, suffix: '%', cls: 'pcdn-rum-rate',
            oninput: function (v) { d[SR] = Math.max(0.01, Math.min(1, (Number(v) || 0) / 100)); },
            help: t('۱ تا ۱۰۰٪ (پیش‌فرض ۱۰٪). برای سایت‌های پربازدید درصد کمتر کافی است.') })),
        P.choice(d, 'inject', t('افزودن اسکریپت'), [
          ['auto', t('خودکار'), t('CDN تگ اسکریپت را به صفحه‌های HTML اضافه می‌کند. برای این کار صفحه‌ها بدون فشرده‌سازی از سرور شما گرفته می‌شوند (کمی پهنای باند بیشتر بین CDN و سرور شما). سایت‌هایی با CSP سخت‌گیرانه (nonce) باید حالت دستی را انتخاب کنند.'), 'sparkles'],
          ['manual', t('دستی'), t('خودتان تگ زیر را به قالب سایت اضافه می‌کنید؛ پاسخ‌ها دست‌نخورده می‌مانند.'), 'code']], { cols: 2, onchange: f2.redraw }),
        d.inject === 'manual' ? manualSnippet(d, d[SR]) : null,
        P.tags(d, EX, t('مسیرهای بدون پایش'), { placeholder: '/admin', space: true, help: t('پیشوند مسیرهایی که اسکریپت در آن‌ها اجرا نشود (حداکثر ۲۰)، مثل /admin.') }),
        P.toggle(d, 'spa', t('برنامهٔ تک‌صفحه‌ای (SPA)'), { onchange: f2.redraw, help: t('برای سایت‌هایی که بدون بارگذاری دوبارهٔ صفحه مسیر عوض می‌کنند؛ هر جابه‌جایی جداگانه سنجیده می‌شود.') })]);
      return [c];
    }, { savedMsg: t('تنظیمات پایش ذخیره شد و تا چند ثانیه روی همهٔ نودها اعمال می‌شود.') });
    return f.el;
  }
  function has(o, k) { return Object.prototype.hasOwnProperty.call(o, k); }
  function manualSnippet(d, sample) {
    var rate = Math.round(Math.max(0.01, Math.min(1, Number(sample) || 0.1)) * 100) / 100;
    var tag = '<script src="/__pcdn/rum.js" data-s="' + rate + '"' + (d.spa ? ' data-spa="1"' : '') + ' defer></script>';
    var csp = "script-src 'self'; connect-src 'self'";
    return h('div', { className: 'pcdn-rum-manual', 'data-rum-manual': '1' },
      P.field(t('این تگ را پیش از </head> قالب سایت قرار دهید'), h('div', { className: 'pcdn-key-plain' }, h('code', { className: 'pcdn-key-value', dir: 'ltr', text: tag }), P.copyBtn(tag, t('کپی تگ'), { text: t('کپی') }))),
      P.field(t('اگر سیاست امنیت محتوا (CSP) دارید، این‌ها کافی است'), h('div', { className: 'pcdn-key-plain' }, h('code', { className: 'pcdn-key-value', dir: 'ltr', text: csp }), P.copyBtn(csp, t('کپی'), { text: t('کپی') }))),
      h('p', { className: 'pcdn-muted pcdn-small', text: t('اگر از nonce در CSP استفاده می‌کنید، همان nonce را به این تگ بدهید. اسکریپت و ارسال داده هر دو از دامنهٔ خود سایت هستند.') }));
  }

  // ------------------------------------------------------------------ report

  function report(holder) {
    clear(holder);
    holder.appendChild(P.skeleton(5));
    api('GET', 'rum', null, { hours: String(R.hours), by: R.by }).then(function (res) {
      clear(holder);
      if (res.status === 404) {
        // plan without rum / older controller: the page disappears (§23.16)
        R.gone = true;
        if (A().refreshNav) A().refreshNav();
        holder.appendChild(P.empty('chart', t('پایش کاربران واقعی در پلن این سرویس فعال نیست'), null));
        return;
      }
      if (!res.ok) { holder.appendChild(P.errorBox(res, t('دریافت گزارش ممکن نشد'))); return; }
      draw(holder, res.data || {});
    });
  }

  function draw(holder, d) {
    var th = d.thresholds && typeof d.thresholds === 'object' ? d.thresholds : DEF_TH;
    var m = d.metrics && typeof d.metrics === 'object' ? d.metrics : {};
    var bar = h('div', { className: 'pcdn-toolbar pcdn-rum-bar' },
      P.segmented([[24, t('۲۴ ساعت')], [168, t('۷ روز')], [720, t('۳۰ روز')]], R.hours, function (v) { R.hours = v; report(holder); }, t('بازه')),
      h('span', { className: 'pcdn-muted pcdn-small', 'data-rum-n': String(d.n || 0), text: t('{0} بازدید سنجیده شد', num(d.n || 0)) }));
    holder.appendChild(bar);
    if (!d.has_data) {
      holder.appendChild(P.empty('chart', d.enabled ? t('هنوز داده‌ای نرسیده است') : t('پایش خاموش است'),
        d.enabled ? t('چند دقیقه پس از روشن کردن، اولین داده‌ها اینجا نمایش داده می‌شوند. اگر داده‌ای نمی‌رسد، شاید نودها هنوز به نسخهٔ جدید به‌روزرسانی نشده‌اند (پس از به‌روزرسانی نودها).')
          : t('برای دیدن تجربهٔ واقعی بازدیدکنندگان، پایش را در تنظیمات بالا روشن و ذخیره کنید.')));
      return;
    }
    holder.appendChild(h('div', { className: 'pcdn-kpis pcdn-rum-kpis' }, METRICS.map(function (x) {
      var v = m[x[0]] || {};
      var g = grade(v.p75, th[x[0]] || DEF_TH[x[0]]);
      return h('div', { className: 'pcdn-kpi pcdn-rum-kpi is-' + g[0], 'data-rum-metric': x[0], 'data-grade': g[0] },
        h('div', { className: 'pcdn-kpi-head' }, h('span', { className: 'pcdn-kpi-label' }, h('b', { text: x[1] }), ' ', h('span', { className: 'pcdn-muted', text: x[2] }))),
        h('div', { className: 'pcdn-kpi-value', text: fmt(v.p75, x[3]) }),
        h('div', { className: 'pcdn-kpi-sub' }, P.badge(g[1], g[0]), v.good_pct != null ? h('span', { className: 'pcdn-muted pcdn-small', text: ' ' + t('{0}٪ خوب', P.num1(v.good_pct)) }) : null),
        v.good_pct != null ? h('div', { className: 'pcdn-rum-dist', 'aria-hidden': 'true' },
          h('span', { className: 'is-good', style: 'width:' + Math.max(0, Math.min(100, Number(v.good_pct))) + '%' }),
          h('span', { className: 'is-ni', style: 'width:' + Math.max(0, Math.min(100, 100 - Number(v.good_pct) - Number(v.poor_pct || 0))) + '%' }),
          h('span', { className: 'is-poor', style: 'width:' + Math.max(0, Math.min(100, Number(v.poor_pct || 0))) + '%' })) : null);
    })));
    holder.appendChild(h('p', { className: 'pcdn-muted pcdn-small', text: t('مقدارها صدک ۷۵ام هستند (۷۵٪ بازدیدها بهتر یا برابر). مرزهای خوب / ضعیف همان معیارهای رایج Web Vitals است.') }));
    // series
    var series = Array.isArray(d.series) ? d.series : [];
    var C = P.charts || {};
    var cc = P.card({ title: t('روند ساعتی (صدک ۷۵)'), icon: 'chart', tone: 'violet', id: 'rum-series' });
    if (series.length && C.area) {
      var labels = series.map(function (x) { return P.date(x.t, R.hours <= 24 ? { hour: '2-digit', minute: '2-digit' } : { month: 'short', day: 'numeric', hour: '2-digit' }); });
      C.area(cc.body, labels, [
        { name: 'LCP', color: C.COLORS.requests, values: series.map(function (x) { return Number(x.lcp_p75) || 0; }) },
        { name: 'TTFB', color: C.COLORS.hits, values: series.map(function (x) { return Number(x.ttfb_p75) || 0; }) },
        { name: 'INP', color: C.COLORS.s4, values: series.map(function (x) { return Number(x.inp_p75) || 0; }) }
      ], function (v) { return fmt(v, 'ms'); }, t('نمودار ساعتی LCP، TTFB و INP'));
    } else cc.body.appendChild(P.empty('chart', t('داده‌ای برای نمودار نیست'), null));
    holder.appendChild(cc);
    // CDN impact
    if (d.cdn_impact && typeof d.cdn_impact === 'object') holder.appendChild(impact(d.cdn_impact));
    // breakdown
    var bc = P.card({ title: t('به تفکیک'), icon: 'filter', id: 'rum-by' });
    bc.body.appendChild(P.segmented(BY.map(function (x) { return [x[0], x[1]]; }), R.by, function (v) { R.by = v; report(holder); }, t('تفکیک بر اساس')));
    var rows = Array.isArray(d.by) ? d.by.filter(function (x) { return x && typeof x === 'object'; }) : [];
    if (!rows.length) bc.body.appendChild(P.empty('filter', t('داده‌ای برای این تفکیک نیست'), null));
    else {
      var tb = h('tbody', null, rows.slice(0, 50).map(function (x) {
        var p = x.p75 || {};
        return h('tr', { 'data-rum-key': String(x.key || '') },
          h('td', { 'data-label': BY.filter(function (b) { return b[0] === R.by; })[0][1] }, keyLabel(x)),
          h('td', { 'data-label': t('بازدید'), className: 'pcdn-num', text: num(x.n || 0) }),
          h('td', { 'data-label': 'LCP', className: 'pcdn-num ' + toneCls(p.lcp, th.lcp), text: fmt(p.lcp, 'ms') }),
          h('td', { 'data-label': 'INP', className: 'pcdn-num ' + toneCls(p.inp, th.inp), text: fmt(p.inp, 'ms') }),
          h('td', { 'data-label': 'CLS', className: 'pcdn-num ' + toneCls(p.cls, th.cls), text: fmt(p.cls, 'cls') }),
          h('td', { 'data-label': 'TTFB', className: 'pcdn-num ' + toneCls(p.ttfb, th.ttfb), text: fmt(p.ttfb, 'ms') }));
      }));
      bc.body.appendChild(h('div', { className: 'pcdn-table-wrap' }, h('table', { className: 'pcdn-table pcdn-rtable pcdn-rum-table' },
        h('thead', null, h('tr', null, [BY.filter(function (b) { return b[0] === R.by; })[0][1], t('بازدید'), 'LCP', 'INP', 'CLS', 'TTFB'].map(function (x) { return h('th', { scope: 'col', text: x }); }))), tb)));
    }
    holder.appendChild(bc);
    holder.appendChild(P.alertBox('info', [h('strong', { text: t('بدون کوکی و بدون ذخیرهٔ IP. ') }),
      t('آی‌پی بازدیدکننده فقط برای تشخیص کشور و اپراتور در لحظه خوانده و دور ریخته می‌شود؛ مسیرها بدون پارامتر ثبت می‌شوند. این گزارش فقط برای شماست.')], { icon: 'lock' }));
  }
  function toneCls(v, th) { var g = grade(v, th || null); return g[0] === 'muted' ? '' : 'pcdn-rum-' + g[0]; }
  function keyLabel(x) {
    var k = String(x.key || '');
    if (R.by === 'device') return h('span', { text: DEVICE[k] || k });
    if (R.by === 'path') return h('bdi', { dir: 'ltr', className: 'pcdn-ltr', text: k });
    if (k === 'other') return h('span', { text: t('سایر') });
    var label = P.isEn ? (x.label_en || x.label) : (x.label || x.label_en);
    if (R.by === 'country' && /^[A-Z]{2}$/.test(k)) label = P.country(k) !== k ? P.country(k) : (label || k);
    if (!label || (P.isEn && /[؀-ۿ]/.test(label))) label = k;
    return h('span', { text: String(label) });
  }
  function impact(ci) {
    var c = P.card({ title: t('اثر CDN'), icon: 'zap', tone: 'success', id: 'rum-impact', subtitle: t('مقایسهٔ صفحه‌هایی که از کش CDN آمدند با صفحه‌هایی که از سرور شما گرفته شدند.') });
    var hit = ci.hit || {}, miss = ci.miss || {};
    append(c.body, [h('div', { className: 'pcdn-rum-impact' },
      h('div', { className: 'pcdn-rum-side is-hit' }, h('strong', { text: t('از کش (HIT)') }), h('span', { className: 'pcdn-muted pcdn-small', text: t('{0} بازدید', num(hit.n || 0)) }),
        h('div', { text: 'TTFB ' + fmt(hit.ttfb_p75, 'ms') }), h('div', { text: 'LCP ' + fmt(hit.lcp_p75, 'ms') })),
      h('div', { className: 'pcdn-rum-side is-miss' }, h('strong', { text: t('از سرور شما (MISS)') }), h('span', { className: 'pcdn-muted pcdn-small', text: t('{0} بازدید', num(miss.n || 0)) }),
        h('div', { text: 'TTFB ' + fmt(miss.ttfb_p75, 'ms') }), h('div', { text: 'LCP ' + fmt(miss.lcp_p75, 'ms') }))),
      h('p', { 'data-rum-gain': String(ci.ttfb_gain_pct || 0), text: t('با کش، زمان اولین بایت {0}٪ و LCP {1}٪ سریع‌تر است؛ {2}٪ بازدیدها از کش پاسخ گرفتند.',
        P.num1(ci.ttfb_gain_pct || 0), P.num1(ci.lcp_gain_pct || 0), P.num1(ci.hit_ratio_pct || 0)) })]);
    return c;
  }

  function render(Aa) {
    var holder = h('div', { className: 'pcdn-stack', 'data-rum-report': '1' });
    report(holder);
    return [settings(Aa), holder];
  }

  pages.rum = {
    title: t('تجربهٔ کاربران واقعی'), icon: 'gauge', heading: t('تجربهٔ کاربران واقعی (RUM)'),
    desc: t('سرعت واقعی سایت در مرورگر بازدیدکنندگان: LCP، INP، CLS، TTFB و FCP به تفکیک کشور، اپراتور اینترنت، دستگاه و صفحه.'),
    hidden: function (s) {
      var f = (s && s.plan && s.plan.features) || {};
      return R.gone || f.rum !== true || !sectionOf(s);
    },
    render: function (Aa) { return render(Aa); }
  };
})();
