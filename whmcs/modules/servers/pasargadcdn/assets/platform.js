/*
 * Pasargad CDN — Wave 6D (SPEC §14.3) analytics & platform for the client app:
 *   - live analytics: the «زنده» mode of the analytics page (GET analytics/live?minutes=…),
 *     auto-refreshed every 30 s, paused while the tab is hidden, stopped when leaving the page;
 *   - «ارسال لاگ» (section `logs`, GET logs/status, POST logs/test);
 *   - «وب‌هوک‌ها» (section `webhooks`, POST webhooks/{id}/test|rotate, GET webhooks/deliveries)
 *     with the one-time signing-secret dialog and a signature-verification guide;
 *   - «گزارش SLA» (GET sla?month=YYYY-MM) with CSV export (UTF-8 BOM) and a print view.
 *
 * Feature detection like Waves 6A/6B: the pages appear only when the controller's site payload
 * carries the 6D sections (`config.logs` / `config.webhooks`); the live mode also hides itself
 * when the endpoint answers 404 — so an older controller keeps working and never gets the calls.
 * Signing secrets live only in the dialog that shows them (never in app state or localStorage).
 * Data only reaches the DOM through textContent / createElement (ui.js helpers) — never innerHTML.
 */
(function () {
  'use strict';
  var P = window.PCDN = window.PCDN || {};
  var t = P.t;  // i18n.js (SPEC §16.10)
  var pages = P.pages = P.pages || {};
  if (!P.h) return;
  var h = P.h, append = P.append, clear = P.clear, icon = P.icon, ltr = P.ltr, num = P.num;

  function A() { return P.app; }
  function site() { return P.app.S.site; }
  function domain() { return site().domain; }
  function has(o, k) { return !!o && typeof o === 'object' && Object.prototype.hasOwnProperty.call(o, k); }
  /** The controller returned this config section. */
  function sectionOf(s, name) { var c = s && s.config && s.config[name]; return !!c && typeof c === 'object' && !Array.isArray(c); }
  /** A Wave 6D controller (it always returns its new sections with defaults). */
  function is6d(s) { return sectionOf(s, 'logs') || sectionOf(s, 'webhooks'); }
  /** Plan feature from site.plan.features, or the controller default when the plan predates the key. */
  function feat(key, def) { var v = A().features()[key]; return v === undefined || v === null ? def : v; }
  function onLeave(fn) { if (A().onLeave) A().onLeave(fn); }

  var NO_DATA = t('داده‌ای نیست');
  var nf3 = null, nf1 = null, mf = null, jf = null;
  try {
    nf3 = new Intl.NumberFormat(P.locale, { minimumFractionDigits: 3, maximumFractionDigits: 3 });
    nf1 = new Intl.NumberFormat(P.locale, { maximumFractionDigits: 1 });
    mf = new Intl.DateTimeFormat(P.isEn ? 'en-US' : 'fa-IR-u-ca-gregory', { year: 'numeric', month: 'long', timeZone: 'UTC' });
    jf = new Intl.DateTimeFormat('fa-IR-u-nu-latn', { year: 'numeric', month: '2-digit', day: '2-digit', timeZone: 'UTC' });
  } catch (e) { /* old browser: plain digits below */ }
  function isNum(v) { return typeof v === 'number' && isFinite(v); }
  /** Percentage with 3 decimals in Persian digits (SPEC §14.3.4), or «داده‌ای نیست». */
  function pct3(v) { return isNum(v) ? (nf3 ? nf3.format(v) : P.fa(v.toFixed(3))) + t('٪') : NO_DATA; }
  function pct1(v) { return isNum(v) ? (nf1 ? nf1.format(Math.round(v * 10) / 10) : P.fa(Math.round(v * 10) / 10)) + t('٪') : NO_DATA; }

  function kpi(ic, tone, label, value, sub, id) {
    return h('div', { className: 'pcdn-kpi', 'data-kpi': id || null },
      h('div', { className: 'pcdn-kpi-top' }, h('span', { className: 'pcdn-kpi-icon pcdn-tone-' + tone }, icon(ic)), h('span', { className: 'pcdn-kpi-label', text: label })),
      h('div', { className: 'pcdn-kpi-value' }, value), sub ? h('div', { className: 'pcdn-kpi-sub' }, sub) : null);
  }
  function codeBlock(text, caption) {
    return h('figure', { className: 'pcdn-codeblock' },
      h('figcaption', null, icon('terminal'), h('span', { dir: 'ltr', text: caption }),
        P.copyBtn(text, t('کپی کد ') + caption, { text: t('کپی'), cls: 'pcdn-copy-code', done: t('کد کپی شد') })),
      h('pre', { dir: 'ltr', tabindex: '0' }, h('code', { text: text })));
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
  function refreshBtn(label, fn, cls) {
    var b = P.btn(label, { icon: 'refresh', size: 'sm', cls: cls, onclick: function () { fn(b); } });
    b.setAttribute('data-ro-ok', '1');
    return b;
  }
  /** Relative time that also reads right for the future (a delivery's next attempt). */
  function relTime(iso) {
    var tx = new Date(iso).getTime();
    if (isNaN(tx)) return String(iso);
    var sec = Math.round((tx - Date.now()) / 1000);
    if (sec <= 45) return P.rel(iso);
    if (sec < 3600) return num(Math.max(1, Math.round(sec / 60))) + t(' دقیقهٔ دیگر');
    if (sec < 86400) return num(Math.round(sec / 3600)) + t(' ساعت دیگر');
    return P.date(iso, { dateStyle: 'medium' });
  }
  function timeCell(iso, empty) {
    return iso ? h('time', { dateTime: String(iso), title: P.date(iso), text: relTime(iso) }) : h('span', { className: 'pcdn-muted', text: empty || '—' });
  }

  // ================================================================== live analytics (§14.3.1)

  var LIVE_MINUTES = [['15', t('۱۵ دقیقه')], ['60', t('۱ ساعت')], ['360', t('۶ ساعت')], ['1440', t('۲۴ ساعت')]];
  var LIVE_MS = 30000;

  function liveState(Aa) {
    var S = Aa.S;
    return S.live || (S.live = { ok: undefined, minutes: 60, data: {}, at: {} });
  }
  /** true / false, or undefined while unknown (older controller without the 6D sections, not probed yet). */
  function liveSupported(Aa) {
    var L = liveState(Aa);
    if (typeof L.ok === 'boolean') return L.ok;
    return is6d(Aa.S.site) ? true : undefined;
  }
  function fetchLive(Aa, minutes) {
    var L = liveState(Aa);
    return P.api('GET', 'analytics/live', undefined, { minutes: minutes }).then(function (res) {
      if (res.ok && res.data && Array.isArray(res.data.series)) {
        L.ok = true;
        L.data[minutes] = res.data;
        L.at[minutes] = Date.now();
      } else if (res.status === 404) {
        L.ok = false;   // older controller: the live mode disappears
      }
      return res;
    });
  }
  /** One background call to learn whether this controller serves live analytics. Resolves to a boolean. */
  function probe(Aa) {
    var L = liveState(Aa);
    if (!L.probing) L.probing = fetchLive(Aa, 15).then(function () { L.probing = null; return L.ok === true; });
    return L.probing;
  }
  function modeSwitch(Aa) {
    var seg = P.segmented([['range', t('گزارش دوره‌ای')], ['live', t('زنده')]], Aa.S.amode === 'live' ? 'live' : 'range', function (v) {
      Aa.S.amode = v;
      Aa.renderMain();
    }, t('نوع گزارش'));
    seg.classList.add('pcdn-amode');
    seg.setAttribute('data-seg', 'amode');
    return seg;
  }

  /** Sums consecutive minute points into buckets of `size` minutes (≤ ~96 points on screen). */
  function bucketize(series, size) {
    if (size <= 1) return series;
    var out = [];
    for (var i = 0; i < series.length; i += size) {
      var b = { t: series[i].t, requests: 0, bytes: 0, cache_hits: 0 };
      for (var j = i; j < Math.min(series.length, i + size); j++) {
        b.requests += Number(series[j].requests) || 0;
        b.bytes += Number(series[j].bytes) || 0;
        b.cache_hits += Number(series[j].cache_hits) || 0;
      }
      out.push(b);
    }
    return out;
  }
  function bucketOf(minutes) { return minutes <= 60 ? 1 : minutes <= 360 ? 5 : 15; }

  function renderLive(Aa) {
    var S = Aa.S, L = liveState(Aa), minutes = L.minutes;
    var holder = h('div', { className: 'pcdn-stack', 'data-live-holder': String(minutes) });
    var stamp = h('span', { className: 'pcdn-muted pcdn-live-stamp', 'aria-live': 'polite' });
    var errBox = h('div', { className: 'pcdn-live-err' });
    var seg = P.segmented(LIVE_MINUTES, String(minutes), function (v) { L.minutes = Number(v); Aa.renderMain(); }, t('بازه نمایش زنده'));
    seg.setAttribute('data-seg', 'live-minutes');
    var refresh = P.btn('', { icon: 'refresh', aria: t('بروزرسانی آمار زنده'), title: t('بروزرسانی آمار زنده'), cls: 'pcdn-btn-iconic pcdn-live-refresh', onclick: function () { load(true); } });
    refresh.setAttribute('data-ro-ok', '1');
    var bar = h('div', { className: 'pcdn-toolbar pcdn-toolbar-end pcdn-live-bar' },
      h('div', { className: 'pcdn-toolbar' }, modeSwitch(Aa), seg),
      h('div', { className: 'pcdn-toolbar' },
        h('span', { className: 'pcdn-live', 'data-live': '1' }, h('span', { className: 'pcdn-live-dot', 'aria-hidden': 'true' }), h('span', { text: t('زنده') })),
        stamp, refresh));
    var timer = null, busy = false;
    function alive() { return S.page === 'analytics' && S.amode === 'live' && L.minutes === minutes && document.body.contains(holder); }
    function stop() { if (timer) { clearInterval(timer); timer = null; } document.removeEventListener('visibilitychange', onVis); }
    function stale() { return !L.at[minutes] || Date.now() - L.at[minutes] >= LIVE_MS - 500; }
    function paintStamp() {
      if (!L.at[minutes]) return;
      stamp.textContent = t('به‌روزرسانی: ') + P.date(new Date(L.at[minutes]).toISOString(), { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }
    function load(manual) {
      if (busy) return Promise.resolve(null);
      busy = true;
      return P.busy(manual ? refresh : null, fetchLive(Aa, minutes)).then(function (res) {
        busy = false;
        if (!alive()) { stop(); return res; }
        clear(errBox);
        if (!res.ok) {
          if (res.status === 404) {   // older controller after all: back to the period report
            stop();
            S.amode = 'range';
            Aa.renderMain();
            P.toast(t('آمار زنده روی این سرور CDN در دسترس نیست.'), 'info');
            return res;
          }
          errBox.appendChild(P.errorBox(res, t('دریافت آمار زنده ممکن نشد')));
          if (!L.data[minutes]) { clear(holder); holder.appendChild(errBox); }
          return res;
        }
        drawLive(holder, res.data, minutes);
        holder.insertBefore(errBox, holder.firstChild);
        paintStamp();
        return res;
      });
    }
    function onVis() {
      if (!alive()) { stop(); return; }
      if (!document.hidden && stale()) load(false);   // catch up right away when the tab comes back
    }
    if (L.data[minutes]) {
      setTimeout(function () {
        if (!alive()) return;
        drawLive(holder, L.data[minutes], minutes);
        holder.insertBefore(errBox, holder.firstChild);
        paintStamp();
        if (stale()) load(false);
      }, 0);
    } else {
      append(holder, [h('div', { className: 'pcdn-kpis' }, [1, 2, 3, 4].map(function () { return h('div', { className: 'pcdn-kpi' }, P.skeleton(3)); })),
        h('div', { className: 'pcdn-card' }, h('div', { className: 'pcdn-card-body' }, h('div', { className: 'pcdn-skel pcdn-skel-chart' })))]);
      load(false);
    }
    // Auto-refresh every 30 s; skipped while the document is hidden; stopped when the page is left.
    timer = setInterval(function () {
      if (!alive()) { stop(); return; }
      if (document.hidden) return;
      load(false);
    }, LIVE_MS);
    document.addEventListener('visibilitychange', onVis);
    onLeave(stop);
    S.redrawCharts = function () { if (L.data[minutes] && alive()) { drawLive(holder, L.data[minutes], minutes); holder.insertBefore(errBox, holder.firstChild); } };
    return [bar, holder];
  }

  function drawLive(holder, a, minutes) {
    clear(holder);
    var C = P.charts || {};
    var tx = a.totals || {}, st = tx.status || {}, raw = Array.isArray(a.series) ? a.series : [];
    var reqs = Number(tx.requests) || 0, bytes = Number(tx.bytes) || 0, hits = Number(tx.cache_hits) || 0;
    var e5 = Number(st['5xx']) || 0;
    var hr = isNum(tx.hit_ratio) ? tx.hit_ratio * 100 : null;
    var span = LIVE_MINUTES.filter(function (x) { return Number(x[0]) === minutes; })[0];
    var spanText = span ? span[1] : num(minutes) + t(' دقیقه');
    var mbps = minutes > 0 ? bytes * 8 / (minutes * 60) / 1e6 : 0;
    append(holder, h('div', { className: 'pcdn-kpis', 'data-live-kpis': '1' },
      kpi('chart', 'brand', t('درخواست‌ها'), P.short(reqs), num(reqs) + t(' درخواست در ') + spanText + t(' گذشته'), 'live-requests'),
      kpi('activity', 'violet', t('پهنای باند'), P.bytes(bytes), t('میانگین ') + (nf1 ? nf1.format(Math.round(mbps * 10) / 10) : P.fa(Math.round(mbps * 10) / 10)) + t(' مگابیت بر ثانیه'), 'live-bytes'),
      kpi('zap', 'success', t('نرخ کش'), hr === null ? NO_DATA : pct1(hr), hr === null ? t('هنوز درخواستی ثبت نشده') : P.short(hits) + t(' پاسخ از کش'), 'live-hit'),
      kpi('warn', 'danger', t('سهم خطای 5xx'), reqs ? pct1(e5 * 100 / reqs) : NO_DATA, num(e5) + t(' پاسخ 5xx'), 'live-5xx')));
    if (reqs >= 100 && e5 / reqs >= 0.02) {
      holder.appendChild(P.alertBox('warning', [h('strong', { text: t('سهم خطاهای 5xx در ') + spanText + t(' گذشته بالاست (') + pct1(e5 * 100 / reqs) + '). ' }),
        t('سرور اصلی احتمالاً در دسترس نیست یا آی‌پی‌های CDN را مسدود کرده است. '), A().tutLink('troubleshoot', t('عیب‌یابی ۵۰۲ / ۵۰۴'))]));
    }
    var size = bucketOf(minutes), series = bucketize(raw, size);
    var per = size === 1 ? t('هر دقیقه') : t('هر ') + num(size) + t(' دقیقه');
    var c1 = P.card({ title: t('درخواست‌ها (') + per + ')', icon: 'chart', id: 'live-requests', subtitle: t('دقیقهٔ جاری ممکن است هنوز کامل نشده باشد.') });
    var c2 = P.card({ title: t('پهنای باند (') + per + ')', icon: 'activity', tone: 'violet', id: 'live-bytes' });
    append(holder, [c1, c2]);
    if (!reqs || !series.length || !C.area) {
      c1.body.appendChild(P.empty('chart', t('در این بازه درخواستی ثبت نشده است'), t('آمار زنده هر دقیقه از سرورهای CDN می‌رسد؛ کمی بعد دوباره نگاه کنید.')));
      c2.parentNode.removeChild(c2);
    } else {
      var labels = series.map(function (p) { return P.date(p.t, { hour: '2-digit', minute: '2-digit' }); });
      C.area(c1.body, labels, [
        { name: t('کل درخواست‌ها'), color: C.COLORS.requests, values: series.map(function (p) { return Number(p.requests) || 0; }), total: P.short(reqs) },
        { name: t('پاسخ از کش'), color: C.COLORS.hits, values: series.map(function (p) { return Number(p.cache_hits) || 0; }), total: P.short(hits) }
      ], num, t('نمودار زندهٔ درخواست‌ها و پاسخ‌های کش‌شده'));
      C.bar(c2.body, labels, series.map(function (p) { return Number(p.bytes) || 0; }), C.COLORS.bytes, P.bytes, t('نمودار زندهٔ پهنای باند'), t('ترافیک'));
    }
    var list = C.barList || function () { return null; };
    var cp = P.card({ title: t('پربازدیدترین مسیرها'), icon: 'sliders', id: 'live-paths' });
    cp.body.appendChild(list((a.top_paths || []).slice(0, 10).filter(Array.isArray).map(function (x) { return [String(x[0]), Number(x[1]) || 0]; }), { ltr: true, total: reqs }));
    var cc = P.card({ title: t('کشورها'), icon: 'globe', id: 'live-countries' });
    cc.body.appendChild(list((a.top_countries || []).slice(0, 10).filter(Array.isArray).map(function (x) { return [P.country(x[0]), Number(x[1]) || 0, String(x[0] || '').toUpperCase()]; }), { total: reqs }));
    append(holder, h('div', { className: 'pcdn-grid-2' }, cp, cc));
  }

  P.live = { supported: liveSupported, probe: probe, modeSwitch: modeSwitch, render: renderLive, bucketize: bucketize };

  // ================================================================== log export (§14.3.2)

  var S3_ENDPOINT_RE = /^https:\/\/(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*)(:\d{1,5})?(\/[^\s?#]*)?$/;
  // mirrors controller/app/sections.py (Logs): S3_BUCKET_RE, LOG_PREFIX_RE, S3_REGION_RE, S3_KEY_RE
  var BUCKET_RE = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;
  var PREFIX_RE = /^[A-Za-z0-9/_.-]*$/;
  var REGION_RE = /^[A-Za-z0-9_-]{1,64}$/;
  var KEY_RE = /^[\x21-\x7e]*$/;
  var CTRL = /[\x00-\x1f\x7f]/;
  var SAMPLE_PICKS = [[1, t('۱٪')], [10, t('۱۰٪')], [50, t('۵۰٪')], [100, t('۱۰۰٪')]];

  /** The section as sent: every key the controller returned except the read-only `secret_key_set`; the secret only when typed. */
  function logsSerialize(d) {
    var out = {};
    Object.keys(d).forEach(function (k) {
      if (k === 'secret_key_set' || k === 'secret_key') return;
      out[k] = typeof d[k] === 'string' ? d[k].trim() : d[k];
    });
    if (typeof d.secret_key === 'string' && d.secret_key.trim() !== '') out.secret_key = d.secret_key.trim();
    if (isNum(out.sample_rate)) out.sample_rate = Math.round(out.sample_rate * 100) / 100;
    return out;
  }
  function logsProblems(d) {
    var out = [], ep = String(d.s3_endpoint || '').trim(), bucket = String(d.bucket || '').trim(), prefix = String(d.prefix || '').trim();
    var ak = String(d.access_key || '').trim(), sk = String(d.secret_key || '').trim(), region = String(d.region || '').trim();
    function bad(path, msg) { out.push({ path: path, msg: msg }); }
    if (ep) {
      if (ep.length > 512) bad('s3_endpoint', t('نشانی سرویس حداکثر ۵۱۲ نویسه می‌تواند باشد.'));
      else if (!/^https:\/\//i.test(ep)) bad('s3_endpoint', t('نشانی سرویس باید با https:// شروع شود (اتصال رمزنگاری‌شده الزامی است).'));
      else if (!S3_ENDPOINT_RE.test(ep) || /@/.test(ep)) bad('s3_endpoint', t('نشانی سرویس معتبر نیست؛ مثل https://s3.example.com بنویسید (بدون نام کاربری، ? یا #).'));
    }
    if (region && !REGION_RE.test(region)) bad('region', t('ناحیه (region) فقط حروف انگلیسی، عدد، - و _ (حداکثر ۶۴ نویسه) است؛ مثلاً us-east-1.'));
    if (bucket && (!BUCKET_RE.test(bucket) || bucket.indexOf('..') >= 0 || /\.-|-\./.test(bucket) || /^\d+\.\d+\.\d+\.\d+$/.test(bucket))) {
      bad('bucket', t('نام باکت طبق قواعد S3: ۳ تا ۶۳ نویسه، فقط حروف کوچک لاتین، عدد، نقطه و خط تیره، با حرف یا عدد شروع و تمام شود (و شبیه آی‌پی نباشد).'));
    }
    if (prefix.length > 128) bad('prefix', t('پیشوند حداکثر ۱۲۸ نویسه می‌تواند باشد.'));
    else if (!PREFIX_RE.test(prefix) || prefix.indexOf('..') >= 0) bad('prefix', t('پیشوند فقط حروف لاتین، عدد و نویسه‌های / _ . - را می‌پذیرد و نباید .. داشته باشد.'));
    if (ak.length > 128) bad('access_key', t('کلید دسترسی حداکثر ۱۲۸ نویسه می‌تواند باشد.'));
    else if (!KEY_RE.test(ak)) bad('access_key', t('کلید دسترسی فقط نویسه‌های چاپ‌پذیر انگلیسی و بدون فاصله است.'));
    if (sk.length > 256) bad('secret_key', t('کلید مخفی حداکثر ۲۵۶ نویسه می‌تواند باشد.'));
    else if (!KEY_RE.test(sk)) bad('secret_key', t('کلید مخفی فقط نویسه‌های چاپ‌پذیر انگلیسی و بدون فاصله است.'));
    if (has(d, 'sample_rate') && !(isNum(d.sample_rate) && d.sample_rate >= 0.01 && d.sample_rate <= 1)) bad('sample_rate', t('نرخ نمونه‌برداری باید بین ۱٪ و ۱۰۰٪ باشد.'));
    if (d.enabled) {
      if (!ep) bad('s3_endpoint', t('برای روشن کردن ارسال لاگ، نشانی سرویس S3 را وارد کنید.'));
      if (!bucket) bad('bucket', t('برای روشن کردن ارسال لاگ، نام باکت را وارد کنید.'));
      if (!ak) bad('access_key', t('برای روشن کردن ارسال لاگ، کلید دسترسی (Access Key) را وارد کنید.'));
      if (!sk && !d.secret_key_set) bad('secret_key', t('برای روشن کردن ارسال لاگ، کلید مخفی (Secret Key) را وارد کنید.'));
    }
    return out;
  }
  function objectExample(d) {
    var pre = String(d.prefix || '').trim();
    return pre + domain() + '/YYYY/MM/DD/HH-xxxxxxxx.jsonl.gz';
  }

  function sampleControl(d, f) {
    var pctVal = Math.max(1, Math.min(100, Math.round((isNum(d.sample_rate) ? d.sample_rate : 1) * 100)));
    var out = h('output', { className: 'pcdn-range-val', 'aria-live': 'polite' });
    function paint(v) { out.textContent = num(v) + t('٪ درخواست‌ها'); }
    var rng = h('input', { type: 'range', className: 'pcdn-range', min: '1', max: '100', step: '1', value: String(pctVal), 'aria-label': t('نرخ نمونه‌برداری (درصد)'),
      oninput: function (e) { var v = Number(e.target.value) || 1; d.sample_rate = v / 100; paint(v); } });
    paint(pctVal);
    var picks = h('div', { className: 'pcdn-chips-row' }, SAMPLE_PICKS.map(function (p) {
      return h('button', { type: 'button', className: 'pcdn-chip-btn', text: p[1], 'data-write': '1', 'data-sample': String(p[0]), onclick: function () {
        d.sample_rate = p[0] / 100;
        rng.value = String(p[0]);
        paint(p[0]);
        rng.dispatchEvent(new Event('change', { bubbles: true }));
      } });
    }));
    return P.field(t('نرخ نمونه‌برداری'), h('div', { className: 'pcdn-range-wrap' }, h('div', { className: 'pcdn-range-row' }, rng, out), picks),
      { path: 'sample_rate', help: t('فقط این درصد از درخواست‌ها ارسال می‌شود؛ برای سایت‌های پربازدید، نمونه‌برداری حجم و هزینهٔ ذخیره‌سازی را کم می‌کند. ۱۰۰٪ یعنی همهٔ درخواست‌ها.') });
  }

  function renderLogs(Aa) {
    var f = Aa.sectionForm('logs', function (d, f2) {
      var secretSet = !!d.secret_key_set;
      var sec = P.input(d, 'secret_key', t('کلید مخفی (Secret Key)'), { type: 'password', maxlength: 256,
        placeholder: secretSet ? t('ذخیره شده — برای تغییر مقدار جدید وارد کنید') : t('کلید مخفی سرویس S3'),
        help: secretSet ? t('کلید فعلی رمزنگاری‌شده نگهداری می‌شود و هرگز نمایش داده نمی‌شود؛ خالی بگذارید تا همان بماند.')
          : t('فقط یک‌بار فرستاده و رمزنگاری‌شده نگهداری می‌شود؛ پس از ذخیره دیگر نمایش داده نمی‌شود.') });
      var si = sec.querySelector('input');
      if (si) { si.setAttribute('autocomplete', 'new-password'); si.setAttribute('data-secret-input', '1'); }
      if (secretSet) {
        var lab = sec.querySelector('.pcdn-label');
        if (lab) append(lab, [' ', P.badge(t('ذخیره شده'), 'success', 'check')]);
      }
      var dest = P.card({ title: t('مقصد (فضای ذخیره‌سازی سازگار با S3)'), icon: 'server', id: 'logs-dest',
        subtitle: t('هر ساعت یک فایل فشرده (gzip، هر خط یک رکورد JSON) در باکت شما بارگذاری می‌شود.') });
      append(dest.body, [
        h('div', { className: 'pcdn-grid' },
          P.input(d, 's3_endpoint', t('نشانی سرویس (Endpoint)'), { placeholder: 'https://s3.example.com', maxlength: 512,
            help: t('نشانی HTTPS سرویس ذخیره‌سازی (AWS S3، آروان، MinIO و …). باید به آی‌پی عمومی برسد.') }),
          P.input(d, 'region', t('ناحیه (Region)'), { placeholder: 'us-east-1', maxlength: 64, help: t('اگر سرویس شما ناحیه ندارد، همان us-east-1 را بگذارید.') })),
        h('div', { className: 'pcdn-grid' },
          P.input(d, 'bucket', t('نام باکت (Bucket)'), { placeholder: 'my-cdn-logs', maxlength: 63 }),
          P.input(d, 'prefix', t('پیشوند مسیر فایل‌ها (اختیاری)'), { placeholder: 'cdn-logs/', maxlength: 128,
            help: h('span', null, t('نمونهٔ مسیر فایل: '), ltr(objectExample(d), 'pcdn-logs-example')) })),
        h('div', { className: 'pcdn-grid' },
          P.input(d, 'access_key', t('کلید دسترسی (Access Key)'), { maxlength: 128, placeholder: 'AKIA…' }),
          sec),
        P.alertBox('info', t('برای امنیت بیشتر یک کلید جداگانه بسازید که فقط اجازهٔ «نوشتن» (PutObject) در همین باکت/پیشوند را داشته باشد.'))]);
      dest.body.addEventListener('input', function () {
        var ex = dest.body.querySelector('.pcdn-logs-example');   // live example path under the prefix field
        if (ex) ex.textContent = objectExample(d);
      });
      var opts = P.card({ title: t('حریم خصوصی و نمونه‌برداری'), icon: 'shieldCheck', tone: 'success', id: 'logs-privacy' });
      append(opts.body, [
        has(d, 'anonymize_ip') ? P.toggle(d, 'anonymize_ip', t('ناشناس‌سازی آی‌پی بازدیدکنندگان (پیشنهادی)'), { onchange: f2.redraw,
          help: t('پیش از ارسال، بخش آخر آی‌پی حذف می‌شود (IPv4: هشت بیت آخر صفر می‌شود، مثلاً 5.160.12.0؛ IPv6: فقط ۴۸ بیت اول می‌ماند). آمار کشور و رفتار کلی حفظ می‌شود ولی بازدیدکنندهٔ مشخصی قابل شناسایی نیست.') }) : null,
        has(d, 'anonymize_ip') && !d.anonymize_ip ? P.alertBox('warning', t('آی‌پی کامل بازدیدکنندگان دادهٔ شخصی است. اگر خاموشش می‌کنید، طبق قوانین حریم خصوصی و سیاست سایت خودتان با آن رفتار کنید و دسترسی به باکت را محدود نگه دارید.')) : null,
        has(d, 'sample_rate') ? sampleControl(d, f2) : null]);
      var main = P.card({ title: t('ارسال لاگ دسترسی'), icon: 'upload', id: 'logs-enable', tone: d.enabled ? 'success' : 'muted' });
      append(main.body, [
        P.toggle(d, 'enabled', t('ارسال لاگ‌های دسترسی این سایت به باکت من'), { onchange: f2.redraw,
          help: t('سرورهای CDN رکورد درخواست‌ها را جمع می‌کنند و هر ساعت در باکت شما بارگذاری می‌شود. برای روشن کردن، نشانی، باکت و هر دو کلید لازم است.') })]);
      return [main, dest, opts];
    }, { serialize: logsSerialize, validate: logsProblems, savedMsg: t('تنظیمات ارسال لاگ ذخیره شد.'),
      onSaved: function () {
        // the secret never stays in the app: the stored section keeps only secret_key_set
        var c = Aa.S.site && Aa.S.site.config && Aa.S.site.config.logs;
        if (c && typeof c.secret_key === 'string' && c.secret_key !== '') { c.secret_key = ''; c.secret_key_set = true; }
        if (Aa.S.form === f) { f.load(); f.redraw(); }
        if (status.reload) status.reload();
      } });
    var status = statusCard(Aa, f);
    return [f.el, status, formatCard()];
  }

  function statusCard(Aa, f) {
    var body = h('div', { 'data-logs-status': '1' }, P.skeleton(3));
    var result = h('div', { className: 'pcdn-logs-test', 'aria-live': 'polite' });
    var reload = refreshBtn(t('بروزرسانی'), function (b) { load(b); }, 'pcdn-logs-refresh');
    var test = P.btn(t('آزمایش اتصال'), { icon: 'send', size: 'sm', kind: 'primary', write: true, cls: 'pcdn-logs-testbtn', onclick: function () {
      clear(result);
      if (Aa.S.form === f && f.dirty()) {
        result.appendChild(P.alertBox('warning', t('آزمایش با تنظیمات ذخیره‌شده انجام می‌شود؛ ابتدا تغییرات را ذخیره کنید.')));
        return;
      }
      P.busy(test, P.api('POST', 'logs/test')).then(function (res) {
        clear(result);
        if (!res.ok) { result.appendChild(P.errorBox(res, t('آزمایش اتصال انجام نشد'))); return; }
        var d = res.data || {};
        if (d.ok) {
          result.appendChild(P.alertBox('success', [h('strong', { text: t('اتصال برقرار است. ') }), t('فایل آزمایشی '),
            ltr(String((Aa.config('logs') || {}).prefix || '') + domain() + '/.pcdn-test'), t(' در باکت نوشته شد.')]));
        } else {
          result.appendChild(P.alertBox('danger', [h('strong', { text: t('اتصال ناموفق بود: ') }), ltr(String(d.error || t('خطای نامشخص')))]));
        }
        load(null);
      });
    } });
    var c = P.card({ title: t('وضعیت ارسال'), icon: 'activity', id: 'logs-status', actions: [reload] });
    append(c.body, [body, h('div', { className: 'pcdn-row-actions' }, test), result]);
    function load(b) {
      var pr = P.api('GET', 'logs/status');
      return P.busy(b, pr).then(function (res) {
        if (!document.body.contains(c)) return;
        clear(body);
        if (!res.ok) { body.appendChild(P.errorBox(res, t('دریافت وضعیت ارسال لاگ ممکن نشد'))); return; }
        var s = res.data || {};
        var rows = [
          [t('وضعیت'), s.enabled ? P.badge(t('فعال'), 'success', 'checkCircle') : P.badge(t('خاموش'), 'muted'), 'enabled'],
          [t('آخرین بارگذاری'), timeCell(s.last_upload_at, t('هنوز فایلی بارگذاری نشده')), 'last_upload'],
          [t('آخرین فایل'), s.last_object ? h('span', { className: 'pcdn-copyable' }, h('code', { dir: 'ltr', text: String(s.last_object) }), P.copyBtn(String(s.last_object), t('کپی نام فایل'))) : h('span', { className: 'pcdn-muted', text: '—' }), 'last_object'],
          [t('رکوردهای در صف'), h('span', { text: num(s.pending_records || 0) }), 'pending'],
          [t('رکوردهای کنارگذاشته'), h('span', { className: Number(s.dropped_records) > 0 ? 'pcdn-text-danger' : null, text: num(s.dropped_records || 0) }), 'dropped']
        ];
        body.appendChild(h('dl', { className: 'pcdn-dl' }, rows.map(function (r) { return h('div', { 'data-ls': r[2] }, h('dt', { text: r[0] }), h('dd', null, r[1])); })));
        if (Number(s.dropped_records) > 0) {
          body.appendChild(h('p', { className: 'pcdn-help', text: t('رکوردهای کنارگذاشته به‌خاطر سقف ساعتی هر سایت یا خطای طولانی بارگذاری (بیش از ۷۲ ساعت) ارسال نشده‌اند.') }));
        }
        if (s.last_error) {
          body.appendChild(P.alertBox('danger', [h('strong', { text: t('آخرین خطا') + (s.last_error_at ? ' (' + P.rel(s.last_error_at) + ')' : '') + ': ' }), ltr(String(s.last_error)),
            h('div', { className: 'pcdn-help', text: t('بارگذاری‌های ناموفق هر ۱۰ دقیقه دوباره امتحان می‌شوند؛ نشانی، باکت و کلیدها را بررسی کنید.') })]));
        }
        Aa.lockWrites(c);
      });
    }
    c.reload = function () { return load(null); };
    load(null);
    return c;
  }

  function formatCard() {
    var c = P.collapsible({ title: t('قالب فایل‌ها و رکوردها'), icon: 'fileText', tone: 'muted', id: 'logs-format',
      subtitle: t('هر خط فایل یک درخواست است (JSON Lines، فشرده با gzip)') });
    var sample = JSON.stringify({ host: domain(), t: '2026-10-01T10:15:02Z', ip: '5.160.12.0', method: 'GET', scheme: 'https', path: '/products/12',
      status: 200, bytes: 5120, rt: 0.012, cache: 'HIT', country: 'IR', ua: 'Mozilla/5.0 …', referer: 'https://www.google.com/', proto: 'HTTP/2.0' });
    append(c.body, [
      h('ul', { className: 'pcdn-ul' },
        h('li', null, t('مسیر هر فایل: '), ltr('{prefix}' + domain() + '/YYYY/MM/DD/HH-xxxxxxxx.jsonl.gz'), t(' (ساعت به وقت UTC؛ هر ساعتِ کامل یک فایل).')),
        h('li', { text: t('Query String از مسیر و Referer حذف می‌شود؛ User-Agent حداکثر ۵۱۲ نویسه نگه داشته می‌شود.') }),
        h('li', { text: t('بارگذاری ناموفق نگه داشته و هر ۱۰ دقیقه دوباره امتحان می‌شود؛ داده‌ای که ۷۲ ساعت بارگذاری نشود کنار گذاشته می‌شود.') }),
        h('li', { text: t('برای هر سایت سقف ساعتی رکورد وجود دارد؛ رکوردهای بیش از سقف شمرده و کنار گذاشته می‌شوند.') })),
      codeBlock(sample, 'JSON Lines')]);
    return c;
  }

  // ================================================================== webhooks (§14.3.3)

  var EVENTS = [
    ['purge.completed', t('پاکسازی کش انجام شد')],
    ['ssl.issued', t('گواهی SSL صادر شد')],
    ['ssl.failed', t('صدور گواهی SSL ناموفق بود')],
    ['quota.warning', t('هشدار مصرف ترافیک (۸۰٪)')],
    ['quota.exceeded', t('اتمام ترافیک ماهانه')],
    ['site.suspended', t('تعلیق سایت')],
    ['site.unsuspended', t('رفع تعلیق سایت')],
    ['attack.detected', t('تشخیص حمله')]
  ];
  var EVENT_IDS = EVENTS.map(function (e) { return e[0]; });
  var DELIVERY = { pending: [t('در انتظار'), 'warning'], ok: [t('تحویل شد'), 'success'], failed: [t('ناموفق'), 'danger'] };
  var WH_MAX = 50;   // controller hard cap (sections.WEBHOOKS_MAX); the plan's max_webhooks (default 10) applies below it
  function eventLabel(e) {
    if (e === 'ping') return t('آزمایشی (ping)');
    for (var i = 0; i < EVENTS.length; i++) if (EVENTS[i][0] === e) return EVENTS[i][1];
    return String(e || '—');
  }
  function hooksOf(Aa) { var c = Aa.config('webhooks') || {}; return Array.isArray(c.items) ? c.items : []; }
  function hookMax() { var m = feat('max_webhooks', 10); return typeof m === 'number' && m >= 0 ? Math.min(m, WH_MAX) : 10; }
  /** A hook as sent to the controller: only the writable fields (never secret_set). */
  function cleanHook(x) {
    var o = { url: String(x.url || '').trim(), events: EVENT_IDS.filter(function (e) { return (x.events || []).indexOf(e) >= 0; }),
      enabled: x.enabled !== false, description: String(x.description || '').trim() };
    if (x.id) o.id = x.id;
    return o;
  }
  function hookProblems(x) {
    var out = [], u = String(x.url || '').trim();
    function bad(path, msg) { out.push({ path: path, msg: msg }); }
    if (!u) bad('url', t('نشانی وب‌هوک را وارد کنید.'));
    else if (u.length > 512) bad('url', t('نشانی حداکثر ۵۱۲ نویسه می‌تواند باشد.'));
    else if (!/^https:\/\//i.test(u)) bad('url', t('نشانی باید با https:// شروع شود؛ وب‌هوک‌ها فقط روی اتصال رمزنگاری‌شده فرستاده می‌شوند.'));
    else if (!/^https:\/\/[^\s/?#@]+(\/[^\s#]*)?$/i.test(u) || CTRL.test(u)) bad('url', t('نشانی معتبر نیست؛ مثل https://example.com/pcdn-webhook بنویسید (بدون فاصله، نام کاربری یا #).'));
    else {
      var host = u.replace(/^https:\/\//i, '').split(/[/?]/)[0].replace(/:\d+$/, '').toLowerCase();
      if (/^(localhost|.*\.localhost|.*\.local|.*\.internal)$/.test(host) || /^(127\.|10\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host) || host.charAt(0) === '[') {
        bad('url', t('نشانی باید یک میزبان عمومی در اینترنت باشد (نه localhost یا آی‌پی داخلی).'));
      }
    }
    if (!(x.events || []).length) bad('events', t('دست‌کم یک رویداد را انتخاب کنید.'));
    var desc = String(x.description || '').trim();
    if (desc.length > 100) bad('description', t('توضیح حداکثر ۱۰۰ نویسه می‌تواند باشد.'));
    else if (CTRL.test(desc)) bad('description', t('توضیح نباید نویسهٔ کنترلی (مثل شکست خط) داشته باشد.'));
    return out;
  }

  /** PUT the whole list; the stored section never keeps `new_secrets`. Resolves to {res, secrets}. */
  function saveHooks(Aa, items, button) {
    var cur = Aa.config('webhooks') || {}, body = {};
    Object.keys(cur).forEach(function (k) { if (k !== 'items' && k !== 'new_secrets') body[k] = cur[k]; });
    body.items = items.map(cleanHook);
    return P.busy(button, P.api('PUT', 'config/webhooks', body)).then(function (res) {
      var secrets = null;
      if (res.ok) {
        var d = res.data && typeof res.data === 'object' && !Array.isArray(res.data) ? res.data : null;
        if (d && d.new_secrets && typeof d.new_secrets === 'object') secrets = d.new_secrets;
        var stored = {};
        if (d && Array.isArray(d.items)) Object.keys(d).forEach(function (k) { if (k !== 'new_secrets') stored[k] = d[k]; });
        else stored = body;
        Aa.setConfig('webhooks', stored);
      }
      return { res: res, secrets: secrets };
    });
  }

  /** The one-time secret dialog. list: [{id, url, secret}]. Nothing is kept once it is closed. */
  function secretDialog(list, rotated) {
    var d = P.dialog({ title: rotated ? t('کلید امضای جدید') : (list.length > 1 ? t('کلیدهای امضای وب‌هوک‌ها') : t('کلید امضای وب‌هوک')), icon: 'key', tone: 'warning', wide: true });
    d.el.classList.add('pcdn-wh-secret-dlg');
    append(d.body, [
      P.alertBox('warning', [h('strong', { text: t('این کلید فقط همین یک بار نمایش داده می‌شود. ') }),
        t('همین حالا آن را کپی کنید و در تنظیمات سرور خود (مثلاً متغیر محیطی PCDN_WEBHOOK_SECRET) ذخیره کنید؛ اگر گم شود باید «تعویض کلید امضا» بزنید.')], { icon: 'warn' }),
      rotated ? P.alertBox('info', t('کلید قبلی باطل شد؛ از این پس همهٔ ارسال‌ها با کلید جدید امضا می‌شوند.')) : null,
      list.map(function (x) {
        return h('div', { className: 'pcdn-wh-secret', 'data-secret-for': String(x.id || '') },
          x.url ? h('div', { className: 'pcdn-help' }, t('وب‌هوک: '), ltr(String(x.url))) : null,
          h('div', { className: 'pcdn-key-plain' }, h('code', { className: 'pcdn-key-value', dir: 'ltr', text: String(x.secret) }),
            P.copyBtn(String(x.secret), t('کپی کلید امضا'), { text: t('کپی'), done: t('کلید امضا کپی شد') })));
      })]);
    var done = P.btn(t('کلید را ذخیره کردم'), { kind: 'primary', icon: 'check', cls: 'pcdn-wh-secret-ok', onclick: function () { d.close(); } });
    done.setAttribute('data-ro-ok', '1');
    d.foot.appendChild(done);
    d.focusFirst();
    return d;
  }
  function secretsList(secrets, items) {
    return Object.keys(secrets || {}).map(function (id) {
      var it = (items || []).filter(function (x) { return x.id === id; })[0];
      return { id: id, url: it ? it.url : '', secret: secrets[id] };
    }).filter(function (x) { return typeof x.secret === 'string' && x.secret; });
  }

  function hookDrawer(Aa, idx, done) {
    var items = hooksOf(Aa), orig = idx >= 0 ? items[idx] : null;
    var draft = orig ? cleanHook(orig) : { url: '', events: ['ssl.failed', 'quota.warning', 'quota.exceeded', 'site.suspended', 'attack.detected'], enabled: true, description: '' };
    var d = P.dialog({ title: orig ? t('ویرایش وب‌هوک') : t('وب‌هوک جدید'), subtitle: orig ? String(orig.url || '') : t('رویدادهای این سایت به نشانی شما فرستاده می‌شود.'), icon: 'webhook', kind: 'drawer', wide: true });
    d.el.classList.add('pcdn-wh-drawer');
    var err = h('div'), form = h('form', { className: 'pcdn-form', novalidate: true, onsubmit: function (e) { e.preventDefault(); submit(); } });
    var ctx = null;
    function draw() {
      clear(form);
      P.beginForm(draft);
      var evBox = P.checks(draft, 'events', null, EVENTS.map(function (e) { return [e[0], e[1]]; }));
      Array.prototype.forEach.call(evBox.querySelectorAll('.pcdn-check'), function (lab, i) { lab.setAttribute('data-event', EVENTS[i][0]); });
      var all = h('button', { type: 'button', className: 'pcdn-chip-btn', 'data-write': '1', text: t('انتخاب همه'), onclick: function () { draft.events = EVENT_IDS.slice(); draw(); } });
      var none = h('button', { type: 'button', className: 'pcdn-chip-btn', 'data-write': '1', text: t('هیچ‌کدام'), onclick: function () { draft.events = []; draw(); } });
      append(form, [
        P.input(draft, 'url', t('نشانی (فقط HTTPS)'), { placeholder: 'https://example.com/pcdn-webhook', maxlength: 512,
          help: t('درخواست POST با بدنهٔ JSON و امضای X-Pcdn-Signature به این نشانی فرستاده می‌شود. ریدایرکت دنبال نمی‌شود و پاسخ باید ظرف ۱۰ ثانیه 2xx باشد.') }),
        P.field(t('رویدادها'), h('div', { className: 'pcdn-wh-evpick' }, evBox, h('div', { className: 'pcdn-chips-row' }, all, none)), { path: 'events' }),
        P.input(draft, 'description', t('توضیح (اختیاری)'), { ltr: false, maxlength: 100, placeholder: t('مثلاً «اعلان به اسلک تیم فنی»') }),
        P.toggle(draft, 'enabled', t('فعال'), { help: t('وب‌هوک غیرفعال نگه داشته می‌شود ولی چیزی برایش فرستاده نمی‌شود.') }),
        orig ? null : P.alertBox('info', t('پس از ذخیره، کلید امضای این وب‌هوک فقط یک بار نمایش داده می‌شود؛ آماده باشید آن را کپی کنید.')),
        h('button', { type: 'submit', hidden: true, tabindex: '-1', 'aria-hidden': 'true' })]);
      ctx = P.endForm();
      Aa.lockWrites(form);
    }
    var save = P.btn(orig ? t('ذخیره وب‌هوک') : t('افزودن وب‌هوک'), { kind: 'primary', icon: 'check', write: true, cls: 'pcdn-wh-save', onclick: submit });
    append(d.foot, [save, P.btn(t('انصراف'), { onclick: function () { d.close(); } })]);
    append(d.body, [err, form]);
    function show(itemsErr, summary, status) {
      var rest = P.placeErrors(ctx, itemsErr);
      if (rest.length || !itemsErr.length) {
        err.appendChild(P.errorBox({ status: status, data: { detail: rest.length ? rest.map(function (x) { return { loc: x.path.split('.'), msg: x.msg }; }) : summary } }, t('ذخیره انجام نشد')));
      }
      var bad = form.querySelector('[aria-invalid]');
      if (bad) bad.focus();
    }
    function submit() {
      clear(err);
      P.clearErrors(form);
      var probs = hookProblems(draft);
      if (probs.length) { show(probs, '', 422); return; }
      var next = hooksOf(Aa).map(cleanHook), pos = idx >= 0 ? idx : next.length;
      if (idx >= 0) next[idx] = cleanHook(draft); else next.push(cleanHook(draft));
      saveHooks(Aa, next, save).then(function (r) {
        if (!r.res.ok) {
          var e = P.parseErrors(r.res.data, r.res.status);
          // controller locs are items.<n>.<field>: the fields of the edited hook go next to its inputs
          var mine = [], other = [];
          e.items.forEach(function (x) {
            var m = /^items\.(\d+)(?:\.(.+))?$/.exec(x.path);
            if (m && Number(m[1]) === pos && m[2]) mine.push({ path: m[2].split('.')[0], label: x.label, msg: x.msg });
            else other.push(x);
          });
          show(mine.concat(other), e.summary, r.res.status);
          return;
        }
        d.close(true);
        P.toast(orig ? t('وب‌هوک ذخیره شد.') : t('وب‌هوک اضافه شد.'));
        done(r);
      });
    }
    draw();
    d.focusFirst();
    return d;
  }

  function renderWebhooks(Aa) {
    var wrap = h('div', { className: 'pcdn-stack', 'data-webhooks': '1' });
    var listCard = P.card({ title: t('وب‌هوک‌ها'), icon: 'webhook', id: 'webhooks' });
    var delCard = deliveriesCard(Aa);
    var testRes = {};   // id → last test result (this page view only)
    function afterSave(r) {
      var list = secretsList(r.secrets, hooksOf(Aa));
      drawList();
      if (list.length) secretDialog(list, false);
    }
    function drawList() {
      var items = hooksOf(Aa), max = hookMax(), full = items.length >= max;
      var head = listCard.querySelector('.pcdn-card-head');
      var acts = head.querySelector('.pcdn-card-actions');
      if (!acts) { acts = h('div', { className: 'pcdn-card-actions' }); head.appendChild(acts); }
      clear(acts);
      var add = P.btn(t('وب‌هوک جدید'), { kind: 'primary', icon: 'plus', size: 'sm', write: true, cls: 'pcdn-wh-add', disabled: full,
        title: full ? t('به سقف ') + num(max) + t(' وب‌هوک پلن رسیده‌اید') : null, onclick: function () { hookDrawer(Aa, -1, afterSave); } });
      append(acts, [P.kit && P.kit.limitText ? P.kit.limitText(items.length, max, t('وب‌هوک')) : null, add]);
      clear(listCard.body);
      if (!items.length) {
        listCard.body.appendChild(P.empty('webhook', t('هنوز وب‌هوکی ندارید'), t('با وب‌هوک، رویدادهای مهم سایت (پاکسازی کش، صدور یا خطای SSL، هشدار و اتمام ترافیک، تعلیق، حمله) بی‌درنگ به سرور، اسلک یا سیستم پایش شما فرستاده می‌شود.')));
        Aa.lockWrites(listCard);
        return;
      }
      var ul = h('ul', { className: 'pcdn-whs' });
      items.forEach(function (x, i) { ul.appendChild(hookRow(x, i)); });
      listCard.body.appendChild(ul);
      Aa.lockWrites(listCard);
    }
    function hookRow(x, i) {
      var on = x.enabled !== false;
      var sw = P.switchInput(on, (on ? t('غیرفعال کردن') : t('فعال کردن')) + t(' وب‌هوک ') + (x.url || ''), function (v, el) {
        el.disabled = true;
        var next = hooksOf(Aa).map(cleanHook);
        next[i].enabled = v;
        saveHooks(Aa, next, null).then(function (r) {
          if (!r.res.ok) { el.checked = !v; el.disabled = false; P.toast(P.errorText(r.res), 'error'); return; }
          P.toast(v ? t('وب‌هوک فعال شد.') : t('وب‌هوک غیرفعال شد.'));
          afterSave(r);
        });
      }, { write: true });
      var tr = testRes[x.id];
      var test = P.btn(t('ارسال آزمایشی'), { icon: 'send', size: 'sm', write: true, cls: 'pcdn-wh-test', disabled: !x.id, onclick: function () {
        P.busy(test, P.api('POST', 'webhooks/' + x.id + '/test')).then(function (res) {
          if (!res.ok) { P.toast(P.errorText(res), 'error'); return; }
          var d = res.data || {};
          testRes[x.id] = d;
          P.toast(d.ok ? t('رویداد آزمایشی تحویل شد') + (d.status_code ? ' (HTTP ' + d.status_code + ')' : '') + '.' : t('ارسال آزمایشی ناموفق بود.'), d.ok ? 'success' : 'error');
          drawList();
          delCard.reload();
        });
      } });
      var rotate = P.btn(t('تعویض کلید امضا'), { icon: 'key', size: 'sm', write: true, cls: 'pcdn-wh-rotate', disabled: !x.id, onclick: function () {
        P.confirm({ title: t('تعویض کلید امضا'), danger: true, ok: t('تعویض کلید'),
          body: h('div', null, h('p', null, t('کلید امضای '), ltr(String(x.url || '')), t(' بلافاصله عوض می‌شود و کلید فعلی دیگر معتبر نیست.')),
            h('p', { className: 'pcdn-muted', text: t('تا کلید جدید را در سرور خود جایگزین نکنید، بررسی امضای ارسال‌های بعدی در سرور شما ناموفق خواهد بود.') })) })
          .then(function (ok) {
            if (!ok) return;
            P.busy(rotate, P.api('POST', 'webhooks/' + x.id + '/rotate')).then(function (res) {
              if (!res.ok) { P.toast(P.errorText(res), 'error'); return; }
              var d = res.data || {};
              if (typeof d.secret === 'string' && d.secret) secretDialog([{ id: d.id || x.id, url: x.url, secret: d.secret }], true);
              else P.toast(t('کلید امضا عوض شد.'));
            });
          });
      } });
      var edit = P.iconBtn('edit', t('ویرایش وب‌هوک ') + (x.url || ''), function () { hookDrawer(Aa, i, afterSave); }, { write: true, cls: 'pcdn-wh-edit' });
      var del = P.iconBtn('trash', t('حذف وب‌هوک ') + (x.url || ''), function () {
        P.confirm({ title: t('حذف وب‌هوک'), danger: true, ok: t('حذف وب‌هوک'), body: h('div', null, h('p', null, t('وب‌هوک '), ltr(String(x.url || '')), t(' و کلید امضای آن حذف می‌شود و دیگر رویدادی برایش فرستاده نمی‌شود.'))) })
          .then(function (ok) {
            if (!ok) return;
            var next = hooksOf(Aa).map(cleanHook);
            next.splice(i, 1);
            saveHooks(Aa, next, null).then(function (r) {
              if (!r.res.ok) { P.toast(P.errorText(r.res), 'error'); return; }
              P.toast(t('وب‌هوک حذف شد.'));
              afterSave(r);
            });
          });
      }, { write: true, cls: 'is-danger pcdn-wh-del' });
      return h('li', { className: 'pcdn-wh' + (on ? '' : ' is-off'), 'data-hook': String(x.id || i) },
        h('div', { className: 'pcdn-wh-main' },
          h('div', { className: 'pcdn-wh-urlline' }, h('bdi', { className: 'pcdn-wh-url', dir: 'ltr', text: String(x.url || '') }),
            on ? null : P.badge(t('غیرفعال'), 'muted'), x.secret_set === false ? P.badge(t('بدون کلید امضا'), 'warning') : null),
          x.description ? h('div', { className: 'pcdn-wh-desc', text: String(x.description) }) : null,
          h('div', { className: 'pcdn-wh-events' }, (x.events || []).map(function (e) { return h('span', { className: 'pcdn-wh-ev', title: e, 'data-ev': e, text: eventLabel(e) }); })),
          tr ? h('div', { className: 'pcdn-wh-testres' }, tr.ok ? P.badge(t('آزمایش موفق') + (tr.status_code ? ' — HTTP ' + tr.status_code : ''), 'success', 'checkCircle')
            : P.badge(t('آزمایش ناموفق') + (tr.status_code ? ' — HTTP ' + tr.status_code : ''), 'danger', 'xCircle'),
            !tr.ok && tr.error ? h('span', { className: 'pcdn-muted', dir: 'auto', text: String(tr.error) }) : null) : null),
        h('div', { className: 'pcdn-wh-ctl' }, sw, test, rotate, edit, del));
    }
    drawList();
    append(wrap, [listCard, delCard, guideCard()]);
    return wrap;
  }

  function deliveriesCard(Aa) {
    var body = h('div', { 'data-deliveries': '1' }, P.skeleton(4));
    var refresh = refreshBtn(t('بروزرسانی'), function (b) { load(b); }, 'pcdn-wh-del-refresh');
    var c = P.card({ title: t('ارسال‌های اخیر'), icon: 'activity', id: 'deliveries', subtitle: t('۵۰ ارسال آخر در ۷ روز گذشته؛ جدیدترین در بالا'), actions: refresh });
    c.body.appendChild(body);
    function hookUrl(id) { var x = hooksOf(Aa).filter(function (k) { return k.id === id; })[0]; return x ? x.url : id; }
    function load(b) {
      return P.busy(b, P.api('GET', 'webhooks/deliveries', undefined, { limit: 50 })).then(function (res) {
        if (!document.body.contains(c)) return;
        clear(body);
        if (!res.ok) { body.appendChild(P.errorBox(res, t('دریافت ارسال‌ها ممکن نشد'))); return; }
        var rows = Array.isArray(res.data) ? res.data : (res.data && Array.isArray(res.data.items) ? res.data.items : []);
        if (!rows.length) { body.appendChild(P.empty('send', t('هنوز رویدادی ارسال نشده است'), t('پس از اولین رویداد یا «ارسال آزمایشی»، نتیجهٔ هر ارسال (کد پاسخ، تعداد تلاش و خطا) اینجا دیده می‌شود.'))); return; }
        var tbody = h('tbody');
        rows.forEach(function (r) {
          var st = DELIVERY[r.status] || [String(r.status || '—'), 'muted'];
          var when = r.status === 'ok' ? timeCell(r.delivered_at) : r.status === 'pending' && r.next_attempt_at ? h('span', null, t('تلاش بعدی: '), timeCell(r.next_attempt_at)) : h('span', { className: 'pcdn-muted', text: '—' });
          tbody.appendChild(h('tr', { 'data-delivery': String(r.id || ''), 'data-status': String(r.status || '') },
            h('td', { 'data-label': t('زمان'), className: 'pcdn-nowrap' }, timeCell(r.created_at)),
            h('td', { 'data-label': t('رویداد') }, h('span', { text: eventLabel(r.event) }), ' ', h('span', { className: 'pcdn-muted pcdn-wh-evid', dir: 'ltr', text: String(r.event || '') })),
            h('td', { 'data-label': t('وب‌هوک'), className: 'pcdn-dl-hook' }, h('bdi', { dir: 'ltr', text: String(hookUrl(r.hook_id) || '—') })),
            h('td', { 'data-label': t('وضعیت'), className: 'pcdn-nowrap' }, P.badge(st[0], st[1])),
            h('td', { 'data-label': t('تلاش'), className: 'pcdn-nowrap', text: num(r.attempts || 0) }),
            h('td', { 'data-label': t('کد پاسخ'), className: 'pcdn-nowrap' }, r.last_code ? h('bdi', { dir: 'ltr', text: String(r.last_code) }) : h('span', { className: 'pcdn-muted', text: '—' })),
            h('td', { 'data-label': t('خطا'), className: 'pcdn-dl-err' }, r.last_error ? h('span', { dir: 'auto', title: String(r.last_error), text: String(r.last_error) }) : h('span', { className: 'pcdn-muted', text: '—' })),
            h('td', { 'data-label': t('تحویل / تلاش بعدی') }, when)));
        });
        body.appendChild(h('div', { className: 'pcdn-table-wrap' }, h('table', { className: 'pcdn-table pcdn-rtable pcdn-deliveries' },
          h('caption', { className: 'pcdn-sr', text: t('ارسال‌های اخیر وب‌هوک') }),
          h('thead', null, h('tr', null, [t('زمان'), t('رویداد'), t('وب‌هوک'), t('وضعیت'), t('تلاش'), t('کد پاسخ'), t('خطا'), t('تحویل / تلاش بعدی')].map(function (tx) { return h('th', { scope: 'col', text: tx }); }))),
          tbody)));
        body.appendChild(h('p', { className: 'pcdn-help', text: t('ارسال ناموفق پس از ۱ دقیقه، ۵ دقیقه، ۳۰ دقیقه، ۲ ساعت، ۶ ساعت و سپس هر ۶ ساعت تا ۲۴ ساعت دوباره امتحان می‌شود.') }));
      });
    }
    c.reload = function () { return load(null); };
    load(null);
    return c;
  }

  var SIG_PHP = [
    '<?php',
    '// Pasargad CDN webhook receiver — verify X-Pcdn-Signature before trusting the body',
    "$secret = getenv('PCDN_WEBHOOK_SECRET');            // whsec_...",
    "$body = file_get_contents('php://input');            // the RAW body",
    "$ts = $_SERVER['HTTP_X_PCDN_TIMESTAMP'] ?? '';",
    "$sig = $_SERVER['HTTP_X_PCDN_SIGNATURE'] ?? '';",
    "$expected = 'sha256=' . hash_hmac('sha256', $ts . '.' . $body, $secret);",
    '',
    'if (!ctype_digit($ts) || abs(time() - (int) $ts) > 300   // 5-minute tolerance',
    '    || !hash_equals($expected, $sig)) {                  // constant-time compare',
    '    http_response_code(401);',
    '    exit;',
    '}',
    '$event = json_decode($body, true);   // {id, type, created_at, site, data}',
    '// de-duplicate on $event[\'id\'] (or X-Pcdn-Delivery): retries resend the same event',
    'http_response_code(204);'
  ].join('\n');
  var SIG_NODE = [
    "// Node.js (Express) — keep the raw body for the signature check",
    "const crypto = require('crypto');",
    "const express = require('express');",
    'const app = express();',
    '',
    "app.post('/pcdn-webhook', express.raw({ type: 'application/json' }), (req, res) => {",
    '  const secret = process.env.PCDN_WEBHOOK_SECRET;            // whsec_...',
    "  const ts = req.get('X-Pcdn-Timestamp') || '';",
    "  const sig = req.get('X-Pcdn-Signature') || '';",
    "  const expected = 'sha256=' + crypto.createHmac('sha256', secret)",
    "    .update(ts + '.').update(req.body).digest('hex');",
    '  const fresh = /^\\d+$/.test(ts) && Math.abs(Date.now() / 1000 - Number(ts)) <= 300;  // 5 minutes',
    '  const a = Buffer.from(sig), b = Buffer.from(expected);',
    '  if (!fresh || a.length !== b.length || !crypto.timingSafeEqual(a, b)) {   // constant-time',
    '    return res.sendStatus(401);',
    '  }',
    "  const event = JSON.parse(req.body.toString('utf8'));   // {id, type, created_at, site, data}",
    '  // de-duplicate on event.id (or X-Pcdn-Delivery): retries resend the same event',
    '  res.sendStatus(204);',
    '});',
    'app.listen(3000);'
  ].join('\n');
  var SIG_PY = [
    '# Python (Flask) — verify against the raw request body',
    'import hashlib, hmac, os, time',
    'from flask import Flask, abort, request',
    '',
    'app = Flask(__name__)',
    'SECRET = os.environ["PCDN_WEBHOOK_SECRET"].encode()   # whsec_...',
    '',
    '@app.post("/pcdn-webhook")',
    'def pcdn_webhook():',
    '    ts = request.headers.get("X-Pcdn-Timestamp", "")',
    '    sig = request.headers.get("X-Pcdn-Signature", "")',
    '    body = request.get_data()                       # raw bytes, before JSON parsing',
    '    expected = "sha256=" + hmac.new(SECRET, ts.encode() + b"." + body, hashlib.sha256).hexdigest()',
    '    if not ts.isdigit() or abs(time.time() - int(ts)) > 300 \\',
    '            or not hmac.compare_digest(expected, sig):   # 5 minutes, constant-time',
    '        abort(401)',
    '    event = request.get_json()                      # {id, type, created_at, site, data}',
    '    # de-duplicate on event["id"] (or X-Pcdn-Delivery): retries resend the same event',
    '    return "", 204'
  ].join('\n');
  var SIG_LANGS = [['php', 'PHP', SIG_PHP], ['node', 'Node.js', SIG_NODE], ['python', 'Python', SIG_PY]];
  /** `data` of each event as the controller sends it (controller/app/webhooks.py emitters). */
  var EVENT_DATA = [
    ['purge.completed', '{purge_id, urls, prefixes, everything}'],
    ['ssl.issued', '{renewal, names, expires_at}'],
    ['ssl.failed', '{renewal, error}'],
    ['quota.warning / quota.exceeded', '{used_bytes, limit_bytes, percent, month}'],
    ['site.suspended / site.unsuspended', '{status}'],
    ['attack.detected', '{events_5m, threshold, window_start, by_source}'],
    ['ping', '{hook_id}']
  ];
  function samplePayload() {
    return JSON.stringify({ id: 'evt_3f9c2a71be04d2c8', type: 'ssl.issued', created_at: '2026-10-01T10:15:02Z', site: domain(),
      data: { renewal: false, names: [domain(), '*.' + domain()], expires_at: '2026-12-30T10:15:00Z' } }, null, 2);
  }

  function guideCard() {
    var c = P.collapsible({ title: t('راهنمای بررسی امضا'), icon: 'shieldCheck', tone: 'success', id: 'wh-guide',
      subtitle: t('مطمئن شوید هر درخواست واقعاً از CDN آمده و در مسیر تغییر نکرده است') });
    var lang = 'php';
    var slot = h('div', { className: 'pcdn-wh-code' });
    function drawCode() {
      clear(slot);
      var x = SIG_LANGS.filter(function (l) { return l[0] === lang; })[0];
      slot.appendChild(codeBlock(x[2], x[1]));
    }
    var seg = P.segmented(SIG_LANGS.map(function (l) { return [l[0], l[1]]; }), lang, function (v) {
      lang = v;
      Array.prototype.forEach.call(seg.children, function (b) { var on = b.getAttribute('data-value') === v; b.classList.toggle('is-active', on); b.setAttribute('aria-pressed', on ? 'true' : 'false'); });
      drawCode();
    }, t('زبان نمونه کد'));
    seg.setAttribute('data-seg', 'sig-lang');
    drawCode();
    append(c.body, [
      h('p', { text: t('هر ارسال یک درخواست POST با بدنهٔ JSON است ({id, type, created_at, site, data}) و این هدرها را دارد:') }),
      h('ul', { className: 'pcdn-ul pcdn-wh-headers' },
        h('li', null, ltr('X-Pcdn-Event'), t(' — نوع رویداد (مثل '), ltr('ssl.issued'), ')'),
        h('li', null, ltr('X-Pcdn-Delivery'), t(' — شناسهٔ این ارسال (برای جلوگیری از پردازش تکراری)')),
        h('li', null, ltr('X-Pcdn-Timestamp'), t(' — زمان ارسال به ثانیهٔ یونیکس')),
        h('li', null, ltr('X-Pcdn-Signature'), ' — ', ltr('sha256=HMAC-SHA256(secret, timestamp + "." + body)'), t(' به‌صورت hex'))),
      h('ol', { className: 'pcdn-ol' },
        h('li', { text: t('بدنهٔ خام درخواست را همان‌طور که رسیده بخوانید (پیش از هر تبدیل JSON).') }),
        h('li', { text: t('رشتهٔ «timestamp + نقطه + بدنهٔ خام» را با کلید امضا (whsec_…) با HMAC-SHA256 امضا کنید و پیشوند sha256= بگذارید.') }),
        h('li', { text: t('حاصل را با هدر X-Pcdn-Signature با مقایسهٔ زمان‌ثابت (hash_equals / timingSafeEqual / compare_digest) مقایسه کنید.') }),
        h('li', { text: t('درخواستی را که timestamp آن بیش از ۵ دقیقه با ساعت سرور شما فاصله دارد رد کنید (جلوگیری از بازپخش).') }),
        h('li', { text: t('سریع (کمتر از ۱۰ ثانیه) با کد 2xx پاسخ دهید و کار سنگین را در پس‌زمینه انجام دهید؛ در غیر این صورت ارسال دوباره تکرار می‌شود.') })),
      h('p', { className: 'pcdn-help', text: t('نمونهٔ بدنهٔ یک رویداد (هدر X-Pcdn-Event: ssl.issued):') }),
      codeBlock(samplePayload(), 'JSON'),
      h('ul', { className: 'pcdn-ul pcdn-wh-data' }, EVENT_DATA.map(function (e) {
        return h('li', null, ltr(e[0]), ' — ', h('code', { className: 'pcdn-code', dir: 'ltr', text: 'data: ' + e[1] }));
      })),
      h('div', { className: 'pcdn-toolbar' }, seg), slot,
      P.alertBox('info', t('ساعت سرور خود را با NTP همگام نگه دارید؛ اختلاف ساعت بیش از ۵ دقیقه باعث رد شدن همهٔ ارسال‌ها می‌شود.'))]);
    return c;
  }

  // ================================================================== SLA report (§14.3.4)

  function ymOf(d) { return d.getUTCFullYear() + '-' + ('0' + (d.getUTCMonth() + 1)).slice(-2); }
  /** Current UTC month and the previous 12, newest first. */
  function slaMonths() {
    var now = new Date(), out = [];
    for (var i = 0; i <= 12; i++) out.push(ymOf(new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - i, 1))));
    return out;
  }
  function monthLabel(ym) {
    var p = String(ym).split('-');
    try { if (mf) return mf.format(new Date(Date.UTC(+p[0], +p[1] - 1, 15))); } catch (e) { /* below */ }
    return P.fa(ym);
  }
  function lastDay(ym) { var p = ym.split('-'); return new Date(Date.UTC(+p[0], +p[1], 0)).toISOString().slice(0, 10); }
  function dayLabel(iso) { return P.date(String(iso).slice(0, 10) + 'T12:00:00Z', { dateStyle: 'medium', timeZone: 'UTC' }); }
  function jalaliLatin(iso) {
    try { if (jf) return jf.format(new Date(String(iso).slice(0, 10) + 'T12:00:00Z')); } catch (e) { /* below */ }
    return '';
  }
  /** Availability of a day = the lower of the two non-null percentages (same rule as the month). */
  function availOf(x) {
    var v = [x.request_success_pct, x.edge_uptime_pct].filter(isNum);
    return v.length ? Math.min.apply(null, v) : null;
  }
  function fix3(v) { return isNum(v) ? v.toFixed(3) : ''; }
  function csvCell(v) { v = String(v === null || v === undefined ? '' : v); return /[",\r\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }
  var SLA_CSV_HEAD = [t('تاریخ (میلادی)'), t('تاریخ (شمسی)'), t('درخواست‌ها'), t('خطاهای سکو'), t('موفقیت درخواست‌ها (٪)'), t('آپتایم لبه (٪)'), t('دسترس‌پذیری (٪)')];
  /** CSV with a UTF-8 BOM (Excel then shows Persian correctly); ASCII digits, empty cells for missing data. */
  function slaCsv(d) {
    var rows = [SLA_CSV_HEAD];
    (Array.isArray(d.days) ? d.days : []).forEach(function (x) {
      rows.push([String(x.date || ''), jalaliLatin(x.date), isNum(x.requests) ? x.requests : '', isNum(x.platform_errors) ? x.platform_errors : '',
        fix3(x.request_success_pct), fix3(x.edge_uptime_pct), fix3(availOf(x))]);
    });
    rows.push([t('کل ماه ') + String(d.month || ''), '', isNum(d.requests) ? d.requests : '', isNum(d.platform_errors) ? d.platform_errors : '',
      fix3(d.request_success_pct), fix3(d.edge_uptime_pct), fix3(d.availability_pct)]);
    rows.push([]);
    rows.push([t('دامنه'), String(d.domain || domain())]);
    rows.push([t('ماه (UTC)'), String(d.month || '')]);
    rows.push([t('هدف SLA (٪)'), fix3(d.target_pct)]);
    rows.push([t('وضعیت'), d.met === true ? t('برآورده شد') : d.met === false ? t('برآورده نشد') : t('بدون داده')]);
    return '﻿' + rows.map(function (r) { return r.map(csvCell).join(','); }).join('\r\n') + '\r\n';
  }

  /**
   * Print just this panel: every sibling along the panel's ancestor chain (WHMCS header, sidebar,
   * our own navigation, page head, banners) gets .pcdn-print-hide and the chain .pcdn-print-chain;
   * both only matter under @media print (app.css), so nothing changes on screen.
   */
  function printPanel(panel) {
    var marked = [];
    function mark(el, cls) { el.classList.add(cls); marked.push([el, cls]); }
    function cleanup() {
      marked.forEach(function (m) { m[0].classList.remove(m[1]); });
      marked = [];
      document.documentElement.classList.remove('pcdn-printing');
      window.removeEventListener('afterprint', cleanup);
    }
    for (var n = panel; n && n.parentNode && n !== document.body; n = n.parentNode) {
      mark(n, 'pcdn-print-chain');
      Array.prototype.forEach.call(n.parentNode.children, function (sib) {
        if (sib !== n && sib.nodeType === 1) mark(sib, 'pcdn-print-hide');
      });
    }
    document.documentElement.classList.add('pcdn-printing');
    window.addEventListener('afterprint', cleanup);
    try { window.print(); } catch (e) { cleanup(); }
  }

  function renderSla(Aa, panel) {
    var S = Aa.S, st = S.sla || (S.sla = { month: slaMonths()[0], data: {} });
    if (slaMonths().indexOf(st.month) < 0) st.month = slaMonths()[0];
    var holder = h('div', { className: 'pcdn-stack pcdn-sla' });
    var sel = h('select', { className: 'pcdn-input pcdn-sla-month', 'aria-label': t('ماه گزارش'), 'data-ro-ok': '1',
      onchange: function (e) { st.month = e.target.value; Aa.renderMain(); } },
      slaMonths().map(function (m, i) { return h('option', { value: m, selected: m === st.month, text: monthLabel(m) + (i === 0 ? t(' (ماه جاری)') : '') }); }));
    var csv = P.btn(t('خروجی CSV'), { icon: 'download', size: 'sm', cls: 'pcdn-sla-csv', disabled: true, onclick: function () {
      var d = st.data[st.month];
      if (!d) return;
      if (download('sla-' + domain() + '-' + st.month + '.csv', slaCsv(d), 'text/csv;charset=utf-8')) P.toast(t('فایل CSV گزارش SLA ذخیره شد.'));
    } });
    var print = P.btn(t('نسخه‌ی چاپی'), { icon: 'printer', size: 'sm', cls: 'pcdn-sla-print', disabled: true, onclick: function () { printPanel(panel || holder); } });
    var reload = refreshBtn('', function () { delete st.data[st.month]; Aa.renderMain(); }, 'pcdn-btn-iconic pcdn-sla-reload');
    reload.setAttribute('aria-label', t('بروزرسانی گزارش'));
    reload.setAttribute('title', t('بروزرسانی گزارش'));
    var bar = h('div', { className: 'pcdn-toolbar pcdn-toolbar-end pcdn-no-print' },
      P.field(null, sel, { cls: 'pcdn-sla-pick' }), h('div', { className: 'pcdn-row-actions' }, csv, print, reload));
    var month = st.month;
    function ready(d) {
      csv.disabled = false;
      print.disabled = false;
      csv.setAttribute('data-ro-ok', '1');
      print.setAttribute('data-ro-ok', '1');
      drawSla(holder, d, month);
    }
    if (st.data[month]) setTimeout(function () { ready(st.data[month]); }, 0);
    else {
      append(holder, [h('div', { className: 'pcdn-kpis' }, [1, 2, 3, 4].map(function () { return h('div', { className: 'pcdn-kpi' }, P.skeleton(3)); })), P.skeleton(6)]);
      P.api('GET', 'sla', undefined, { month: month }).then(function (res) {
        if (S.page !== 'sla' || st.month !== month || !document.body.contains(holder)) return;
        clear(holder);
        if (res.status === 404) {
          holder.appendChild(P.empty('chart', t('گزارش SLA روی این سرور CDN در دسترس نیست'), t('سرور CDN هنوز به نسخه‌ای که گزارش دسترس‌پذیری ماهانه دارد به‌روز نشده است.')));
          return;
        }
        if (!res.ok || !res.data || typeof res.data !== 'object') {
          holder.appendChild(P.errorBox(res, t('دریافت گزارش SLA ممکن نشد')));
          holder.appendChild(P.btn(t('تلاش دوباره'), { icon: 'refresh', onclick: function () { Aa.renderMain(); } }));
          return;
        }
        st.data[month] = res.data;
        ready(res.data);
      });
    }
    return [bar, holder];
  }

  function drawSla(holder, d, month) {
    clear(holder);
    var target = isNum(d.target_pct) ? d.target_pct : null, av = isNum(d.availability_pct) ? d.availability_pct : null;
    var metBadge = d.met === true ? P.badge(t('هدف برآورده شد'), 'success', 'checkCircle') : d.met === false ? P.badge(t('هدف برآورده نشد'), 'danger', 'xCircle') : P.badge(NO_DATA, 'muted');
    var range = dayLabel(month + '-01') + t(' تا ') + dayLabel(lastDay(month));
    append(holder, [
      h('div', { className: 'pcdn-print-only pcdn-print-head' },
        h('h1', { text: t('گزارش دسترس‌پذیری (SLA)') }),
        h('p', null, h('strong', { text: t('دامنه: ') }), ltr(String(d.domain || domain()))),
        h('p', null, h('strong', { text: t('ماه: ') }), monthLabel(month) + ' (' + range + t('، به وقت UTC)')),
        h('p', { className: 'pcdn-muted', text: t('تهیه‌شده در ') + P.date(new Date().toISOString()) })),
      h('div', { className: 'pcdn-sla-hero pcdn-card', 'data-sla-met': d.met === true ? 'yes' : d.met === false ? 'no' : 'none' },
        h('div', { className: 'pcdn-sla-main' },
          h('span', { className: 'pcdn-sla-label', text: t('دسترس‌پذیری ') + monthLabel(month) }),
          h('strong', { className: 'pcdn-sla-value' + (d.met === false ? ' pcdn-text-danger' : ''), 'data-sla': 'availability', text: pct3(av) }),
          h('span', { className: 'pcdn-muted pcdn-sla-range', text: range + ' (UTC)' })),
        h('div', { className: 'pcdn-sla-target' },
          h('span', { className: 'pcdn-sla-label', text: t('هدف SLA پلن') }),
          h('strong', { 'data-sla': 'target', text: pct3(target) }),
          metBadge)),
      h('div', { className: 'pcdn-kpis pcdn-sla-kpis' },
        kpi('checkCircle', 'success', t('موفقیت درخواست‌ها'), h('span', { 'data-sla': 'success', text: pct3(d.request_success_pct) }), t('بدون احتساب خطاهای سرور اصلی شما'), 'sla-success'),
        kpi('server', 'brand', t('آپتایم نودهای لبه'), h('span', { 'data-sla': 'uptime', text: pct3(d.edge_uptime_pct) }), t('میانگین پایش نودهای گروه سایت'), 'sla-uptime'),
        kpi('chart', 'violet', t('درخواست‌ها'), h('span', { 'data-sla': 'requests', text: isNum(d.requests) ? num(d.requests) : NO_DATA }), isNum(d.requests) ? P.short(d.requests) + t(' درخواست') : null, 'sla-requests'),
        kpi('warn', 'danger', t('خطاهای سکو'), h('span', { 'data-sla': 'errors', text: isNum(d.platform_errors) ? num(d.platform_errors) : NO_DATA }), t('خطای 5xx تولیدشده توسط خود CDN'), 'sla-errors'))]);
    var c = P.card({ title: t('روزبه‌روز'), icon: 'calendar', id: 'sla-days' });
    var days = Array.isArray(d.days) ? d.days : [];
    if (!days.length) c.body.appendChild(P.empty('calendar', t('برای این ماه داده‌ای ثبت نشده است'), t('گزارش از روزی که سایت ترافیک داشته یا نودها پایش شده‌اند ساخته می‌شود.')));
    else {
      var tbody = h('tbody');
      days.forEach(function (x) {
        var a = availOf(x), low = isNum(a) && target !== null && a < target;
        function cell(v, label) { return h('td', { 'data-label': label, className: isNum(v) ? 'pcdn-num' : 'pcdn-muted', text: isNum(v) ? pct3(v) : NO_DATA }); }
        tbody.appendChild(h('tr', { className: low ? 'is-bad' : null, 'data-day': String(x.date || '') },
          h('td', { 'data-label': t('تاریخ') }, h('span', { text: dayLabel(x.date) }), ' ', h('span', { className: 'pcdn-muted pcdn-sla-greg', dir: 'ltr', text: String(x.date || '') })),
          h('td', { 'data-label': t('درخواست‌ها'), className: 'pcdn-num', text: isNum(x.requests) ? num(x.requests) : NO_DATA }),
          h('td', { 'data-label': t('خطاهای سکو'), className: 'pcdn-num', text: isNum(x.platform_errors) ? num(x.platform_errors) : NO_DATA }),
          cell(x.request_success_pct, t('موفقیت درخواست‌ها')), cell(x.edge_uptime_pct, t('آپتایم لبه')), cell(a, t('دسترس‌پذیری'))));
      });
      c.body.appendChild(h('div', { className: 'pcdn-table-wrap' }, h('table', { className: 'pcdn-table pcdn-rtable pcdn-sla-table' },
        h('caption', { className: 'pcdn-sr', text: t('دسترس‌پذیری روزانه') }),
        h('thead', null, h('tr', null, [t('تاریخ'), t('درخواست‌ها'), t('خطاهای سکو'), t('موفقیت درخواست‌ها'), t('آپتایم لبه'), t('دسترس‌پذیری')].map(function (tx) { return h('th', { scope: 'col', text: tx }); }))),
        tbody)));
    }
    holder.appendChild(c);
    holder.appendChild(h('div', { className: 'pcdn-card pcdn-sla-how' }, h('div', { className: 'pcdn-card-body' },
      h('h4', { text: t('نحوهٔ محاسبه') }),
      h('ul', { className: 'pcdn-ul' },
        h('li', { text: t('موفقیت درخواست‌ها = ۱۰۰ × (۱ − خطاهای سکو ÷ کل درخواست‌ها). خطای سکو یعنی پاسخ 5xx که خود CDN ساخته است؛ خطاهای سرور اصلی شما و درخواست‌هایی که فایروال، WAF یا محدودیت نرخ مسدود کرده‌اند حساب نمی‌شوند.') }),
        h('li', { text: t('آپتایم لبه = میانگین نتیجهٔ پایش نودهای گروهی که به سایت شما سرویس می‌دهند.') }),
        h('li', { text: t('دسترس‌پذیری = کمترِ این دو مقدار (هر کدام که داده داشته باشد). ماهی که هیچ داده‌ای ندارد «داده‌ای نیست» نشان داده می‌شود.') }),
        h('li', { text: t('ماه‌ها به وقت UTC (ماه میلادی) حساب می‌شوند.') })))));
  }

  // ================================================================== registry

  pages.logs = {
    title: t('ارسال لاگ'), icon: 'fileText', heading: t('ارسال لاگ دسترسی'),
    desc: t('لاگ درخواست‌های این سایت را هر ساعت به باکت S3 (یا سرویس سازگار) خودتان بفرستید تا برای تحلیل، نگهداری یا SIEM در اختیار داشته باشید.'),
    guide: {
      what: t('سرورهای CDN رکورد هر درخواست (زمان، آی‌پی، مسیر، کد پاسخ، حجم، وضعیت کش، کشور و …) را جمع و هر ساعت به‌صورت فایل فشرده در باکت شما بارگذاری می‌کنند.'),
      when: t('وقتی به لاگ کامل دسترسی برای تحلیل ترافیک، بررسی امنیتی یا نگهداری طبق مقررات نیاز دارید.'),
      rec: t('ناشناس‌سازی آی‌پی روشن، نمونه‌برداری ۱۰۰٪ برای سایت‌های کوچک و کمتر برای سایت‌های پربازدید، و یک کلید S3 که فقط اجازهٔ نوشتن در همین باکت را دارد.'),
      mistakes: [t('کلیدی با دسترسی کامل به همهٔ باکت‌ها.'), t('نشانی سرویس با http:// (فقط HTTPS پذیرفته می‌شود).'), t('خاموش کردن ناشناس‌سازی بدون نیاز واقعی به آی‌پی کامل.')]
    },
    upsell: t('با ارتقای پلن می‌توانید لاگ دسترسی سایت را به فضای ذخیره‌سازی خودتان بفرستید.'),
    hidden: function (s) { return !sectionOf(s, 'logs'); },
    lock: function (f) { return f.log_export === false; },
    render: function (Aa) { return renderLogs(Aa); }
  };
  pages.webhooks = {
    title: t('وب‌هوک‌ها'), icon: 'webhook',
    desc: t('رویدادهای مهم سایت (پاکسازی کش، SSL، هشدار و اتمام ترافیک، تعلیق، حمله) را بی‌درنگ با درخواست امضاشده به سرور یا ابزار خودتان بفرستید.'),
    guide: {
      what: t('وب‌هوک یک درخواست HTTPS با بدنهٔ JSON است که هنگام رخ دادن رویداد به نشانی شما فرستاده می‌شود و با کلید مخصوص همان وب‌هوک امضا شده است.'),
      when: t('برای اعلان در اسلک/تلگرام از راه سرور واسط، ثبت در سیستم پایش، یا خودکارسازی (مثلاً پاکسازی کش برنامه پس از پاکسازی CDN).'),
      rec: t('همیشه امضا و timestamp را بررسی کنید، سریع پاسخ 2xx بدهید و رویدادها را بر اساس id یکتا پردازش کنید.'),
      mistakes: [t('نادیده گرفتن بررسی امضا (هر کسی می‌تواند به نشانی شما درخواست بفرستد).'), t('پاسخ کند یا ریدایرکت (ارسال ناموفق حساب می‌شود و تکرار می‌شود).'), t('ذخیره نکردن کلید امضا هنگام نمایش (فقط یک بار نشان داده می‌شود).')]
    },
    upsell: t('با ارتقای پلن می‌توانید رویدادهای سایت را با وب‌هوک به سیستم‌های خودتان بفرستید.'),
    hidden: function (s) { return !sectionOf(s, 'webhooks'); },
    lock: function (f) { return f.max_webhooks === 0; },
    render: function (Aa) { return renderWebhooks(Aa); }
  };
  pages.sla = {
    title: t('گزارش SLA'), icon: 'calendar', heading: t('گزارش دسترس‌پذیری (SLA)'),
    desc: t('دسترس‌پذیری ماهانهٔ سایت روی CDN در مقایسه با هدف SLA پلن، به‌همراه جزئیات روزانه، خروجی CSV و نسخهٔ چاپی.'),
    hidden: function (s) { return !is6d(s); },
    render: function (Aa, body) { return renderSla(Aa, body); }
  };

  // exported for tests
  P.sec6d = { logsSerialize: logsSerialize, logsProblems: logsProblems, hookProblems: hookProblems, cleanHook: cleanHook, slaCsv: slaCsv,
    slaMonths: slaMonths, availOf: availOf, bucketize: bucketize, pct3: pct3 };
})();
