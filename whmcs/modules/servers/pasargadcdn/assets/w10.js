/*
 * Pasargad CDN — Wave 10 client-app pages (docs/SPEC.md §18, docs/WHMCS.md «موج ۱۰»):
 *   - «اتاق انتظار» (section `waiting_room`, plan feature waiting_room): settings form validated like the
 *     controller (sections.WaitingRoom) + live stats from GET waiting-room (refreshed every 30 s);
 *   - «دسترسی محافظت‌شده» (section `access`, plan feature access): apps editor (paths, method, e-mails /
 *     @domain, IPs, session hours) in a drawer, «کلید جدید» (POST access/rotate {} with confirm) and the
 *     sign-in log (GET access/log);
 *   - «صورت‌حساب مصرف»: month picker → PDF / CSV download through the proxy (GET statement?month&format&lang;
 *     api.php streams the file) + the month's summary (format=json); a reseller picks one of its sub-sites;
 *   - «گزارش تغییرات»: the site's audit entries (GET audit?from&to&format=json) + CSV download;
 *   - the global error reporter (SPEC §18.4): window.onerror / unhandledrejection of THIS app's scripts only,
 *     posted to api.php?action=client-error (no query strings, no origins, ≤ 10 per page load).
 *
 * Feature detection like Waves 6–9: the two section pages appear only when the controller's site payload
 * carries the section (a wave-10 controller); the statement / audit pages appear with them and hide
 * themselves when their endpoint answers 404. A plan without the feature sees the page locked (upsell).
 * Read-only team members and inactive services can view everything and download files, never write.
 * Data reaches the DOM only via textContent / createElement.
 */
(function () {
  'use strict';
  var P = window.PCDN = window.PCDN || {};
  var t = P.t;  // i18n.js (SPEC §16.10)
  var pages = P.pages = P.pages || {};

  // ================================================================== §18.4 error reporter (installed first)

  var ERR = { sent: 0, max: 10, seen: {} };
  // the controller's page names (pcdn_client_errors_total{page}) for this app's page ids
  var PAGE_IDS = { waitingroom: 'waiting_room', monthly: 'statement', changes: 'audit' };
  /** Only errors raised by this app's own scripts are reported (never the host theme's, never other sites'). */
  var OWN = /\/modules\/servers\/pasargadcdn\/assets\//;
  function pathOnly(u) {
    u = String(u || '');
    try { return new URL(u, window.location.href).pathname; } catch (e) { return u.replace(/^[a-z][a-z0-9+.-]*:\/\/[^/]*/i, '').replace(/[?#].*$/, ''); }
  }
  /** Stack without origins, query strings or fragments; ≤ 4000 characters. */
  function cleanStack(s) {
    return String(s || '').replace(/[a-z][a-z0-9+.-]*:\/\/[^/\s)]*/gi, '').replace(/[?#][^\s):]*/g, '').slice(0, 4000);
  }
  function report(message, source, line, col, stack) {
    var own = OWN.test(String(source || '')) || OWN.test(String(stack || ''));
    if (!own || ERR.sent >= ERR.max || !P.CFG || !P.CFG.api || !P.CFG.csrf || typeof window.fetch !== 'function') return;
    var msg = String(message || '').replace(/[a-z][a-z0-9+.-]*:\/\/[^/\s)]*/gi, '').replace(/[?#][^\s):]*/g, '').slice(0, 500);
    var key = msg + '|' + pathOnly(source) + '|' + (line || 0);
    if (ERR.seen[key]) return;
    ERR.seen[key] = true;
    ERR.sent++;
    var page = P.app && P.app.S && typeof P.app.S.page === 'string' ? P.app.S.page : 'boot';
    page = PAGE_IDS[page] || page;
    var body = { message: msg, source: pathOnly(source), line: Number(line) || 0, col: Number(col) || 0, stack: cleanStack(stack),
      page: /^[a-z0-9_-]{1,40}$/.test(page) ? page : 'unknown', ua: String(navigator.userAgent || '').slice(0, 300) };
    var url = P.CFG.api + (P.CFG.api.indexOf('?') >= 0 ? '&' : '?') + 'action=client-error&id=' + encodeURIComponent(P.CFG.serviceId || '')
      + (P.CFG.rsid ? '&rsid=' + encodeURIComponent(P.CFG.rsid) : '');
    try {
      window.fetch(url, { method: 'POST', credentials: 'same-origin', keepalive: true,
        headers: { 'Content-Type': 'application/json', 'X-PCDN-CSRF': P.CFG.csrf, 'X-PCDN-Lang': P.lang || 'fa' },
        body: JSON.stringify(body) }).catch(function () { /* reporting never fails the app */ });
    } catch (e) { /* ignore */ }
  }
  if (!P.errorReporter && window.addEventListener) {
    window.addEventListener('error', function (e) {
      if (!e || e.target !== window && e.target && e.target.nodeType === 1) return;   // resource load errors: not ours to report
      var er = e.error;
      report(e.message || (er && er.message), e.filename, e.lineno, e.colno, er && er.stack);
    });
    window.addEventListener('unhandledrejection', function (e) {
      var r = e && e.reason;
      var st = r && r.stack ? String(r.stack) : '';
      var src = (/(\S+\/modules\/servers\/pasargadcdn\/assets\/[^\s):]+)/.exec(st) || [])[1] || '';
      report(r && r.message ? r.message : String(r), src, 0, 0, st);
    });
    P.errorReporter = { report: report, cleanStack: cleanStack, pathOnly: pathOnly, state: ERR };
  }

  if (!P.h) return;
  var h = P.h, append = P.append, clear = P.clear, icon = P.icon, ltr = P.ltr, num = P.num, clone = P.clone;

  function A() { return P.app; }
  function S() { return P.app.S; }
  function site() { return P.app.S.site; }
  function canWrite() { return !!S().active && !A().readonly; }
  function isObj(o) { return !!o && typeof o === 'object' && !Array.isArray(o); }
  function has(o, k) { return isObj(o) && Object.prototype.hasOwnProperty.call(o, k); }
  function sectionOf(s, name) { var c = s && s.config && s.config[name]; return isObj(c); }
  /** A wave-10 controller: its site payload carries the new sections. */
  function wave10(s) { return sectionOf(s, 'waiting_room') || sectionOf(s, 'access'); }

  // ------------------------------------------------------------------ the controller contract in one place (ClientApi::W10_*)

  var EP = { wr: 'waiting-room', alog: 'access/log', rotate: 'access/rotate', statement: 'statement', audit: 'audit' };
  // Limits of controller/app/sections.py (WaitingRoom, AccessApp, Access) — validated here, in api.php and on the controller.
  var WR = { paths: 20, active: [1, 1000000], minutes: [1, 120], text: 500, bpaths: 20, bips: 50, defActive: 1000, defMinutes: 10 };
  var AC = { apps: 20, paths: 20, emails: 200, ips: 100, hours: [1, 720], defHours: 24, name: 100 };
  var APP_ID = /^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$/;
  var EMAIL = /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
  var EMAIL_DOMAIN = /^@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
  var PREFIX_CHARS = /^\/[A-Za-z0-9\-._~%!$&'()+,;=:@/]*$/;
  var absent = {};   // page id → true once its endpoint answered 404 (older controller)

  /** Path prefix as sections._prefixes accepts it. */
  function prefixOk(p) {
    p = String(p || '');
    return p.length <= 256 && PREFIX_CHARS.test(p) && !(p === '/__pcdn' || p.indexOf('/__pcdn/') === 0 || p.indexOf('/__pcdn_') === 0);
  }
  function ipv4(v) {
    var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(v);
    return !!m && m.slice(1).every(function (x) { return Number(x) <= 255 && (x === '0' || x.charAt(0) !== '0'); });
  }
  /** IP or network, no wider than /8 (IPv4) or /16 (IPv6) — sections._cidrs_list. */
  function cidrOk(v) {
    v = String(v || '').trim();
    var m = /^([^/]+)(?:\/(\d{1,3}))?$/.exec(v);
    if (!m) return false;
    var base = P.w8 && P.w8.cidr ? P.w8.cidr(m[1]) : (ipv4(m[1]) || /^[0-9a-f:.]+$/i.test(m[1]) && m[1].indexOf(':') >= 0);
    if (!base) return false;
    if (m[2] === undefined) return true;
    var n = Number(m[2]);
    return ipv4(m[1]) ? n >= 8 && n <= 32 : n >= 16 && n <= 128;
  }
  function emailOk(e) { e = String(e || '').toLowerCase(); return e.length <= 254 && (EMAIL.test(e) || EMAIL_DOMAIN.test(e)); }
  function overlap(a, b) { return a.indexOf(b) === 0 || b.indexOf(a) === 0; }
  function intIn(v, r) { return typeof v === 'number' && Math.floor(v) === v && v >= r[0] && v <= r[1]; }
  function ctl(s) { return /[\x00-\x08\x0B-\x1F\x7F]/.test(String(s || '')); }

  // ================================================================== §18.1 «اتاق انتظار»

  function wrDefaults(d) {
    if (!Array.isArray(d.paths) || !d.paths.length) d.paths = Array.isArray(d.paths) ? d.paths : ['/'];
    if (typeof d.max_active !== 'number') d.max_active = WR.defActive;
    if (typeof d.session_minutes !== 'number') d.session_minutes = WR.defMinutes;
    if (d.mode !== 'queue' && d.mode !== 'off') d.mode = 'queue';
    if (!isObj(d.queue_page)) d.queue_page = {};
    ['title_fa', 'title_en', 'message_fa', 'message_en'].forEach(function (k) { if (typeof d.queue_page[k] !== 'string') d.queue_page[k] = ''; });
    if (!isObj(d.bypass)) d.bypass = {};
    if (typeof d.bypass.verified_bots !== 'boolean') d.bypass.verified_bots = true;
    if (!Array.isArray(d.bypass.paths)) d.bypass.paths = [];
    if (!Array.isArray(d.bypass.ips)) d.bypass.ips = [];
    return d;
  }
  /** Exactly the contract's keys (ClientApi::waitingRoomProblems refuses anything else). */
  function wrSerialize(d) {
    d = wrDefaults(clone(d) || {});
    return { enabled: !!d.enabled, mode: d.mode, paths: d.paths.slice(), max_active: d.max_active, session_minutes: d.session_minutes,
      queue_page: { title_fa: d.queue_page.title_fa, title_en: d.queue_page.title_en, message_fa: d.queue_page.message_fa, message_en: d.queue_page.message_en },
      bypass: { verified_bots: !!d.bypass.verified_bots, paths: d.bypass.paths.slice(), ips: d.bypass.ips.slice() } };
  }
  function listProblems(out, list, path, max, ok, msg, min) {
    if (list.length > max) out.push({ path: path, msg: t('حداکثر {0} مورد مجاز است.', num(max)) });
    if (min && list.length < min) out.push({ path: path, msg: t('دست‌کم یک مسیر لازم است.') });
    list.forEach(function (x, i) { if (!ok(x)) out.push({ path: path + '.' + i, msg: msg + ' (' + String(x).slice(0, 60) + ')' }); });
  }
  var PREFIX_MSG = t('پیشوند مسیر باید با / شروع شود، بدون * و ? باشد؛ مسیرهای /__pcdn/ رزرو شده‌اند.');
  var CIDR_MSG = t('آدرس IP یا شبکهٔ نامعتبر (شبکه حداکثر /8 برای IPv4 و /16 برای IPv6).');
  function wrProblems(d0) {
    var d = wrDefaults(clone(d0) || {}), out = [];
    listProblems(out, d.paths, 'paths', WR.paths, prefixOk, PREFIX_MSG, 1);
    if (!intIn(d.max_active, WR.active)) out.push({ path: 'max_active', msg: t('عددی بین ۱ تا ۱٬۰۰۰٬۰۰۰ وارد کنید.') });
    if (!intIn(d.session_minutes, WR.minutes)) out.push({ path: 'session_minutes', msg: t('عددی بین ۱ تا ۱۲۰ دقیقه وارد کنید.') });
    ['title_fa', 'title_en', 'message_fa', 'message_en'].forEach(function (k) {
      var v = d.queue_page[k];
      if (v.length > WR.text || ctl(v.replace(/[\n\t]/g, ''))) out.push({ path: 'queue_page.' + k, msg: t('حداکثر ۵۰۰ نویسه و بدون نویسهٔ کنترلی.') });
    });
    listProblems(out, d.bypass.paths, 'bypass.paths', WR.bpaths, prefixOk, PREFIX_MSG);
    listProblems(out, d.bypass.ips, 'bypass.ips', WR.bips, cidrOk, CIDR_MSG);
    return out;
  }

  function textArea(obj, key, label, o) {
    o = o || {};
    var ta = h('textarea', { className: 'pcdn-input pcdn-w10-text', dir: o.dir || 'auto', rows: o.rows || 2, maxlength: String(WR.text),
      placeholder: o.placeholder || '', value: obj[key] || '', oninput: function (e) { obj[key] = e.target.value; } });
    return P.field(label, ta, { help: o.help, path: P.pathOf(obj, key) });
  }

  function kpi(ic, tone, label, value, sub, id) {
    return h('div', { className: 'pcdn-kpi', 'data-kpi': id || null },
      h('div', { className: 'pcdn-kpi-top' }, h('span', { className: 'pcdn-kpi-icon pcdn-tone-' + tone }, icon(ic)), h('span', { className: 'pcdn-kpi-label', text: label })),
      h('div', { className: 'pcdn-kpi-value', text: value }), sub ? h('div', { className: 'pcdn-kpi-sub', text: sub }) : null);
  }

  /** Live stats of GET waiting-room: {enabled, active_estimate, queued_estimate, last_hour: {...}, hourly: [...]}. */
  function wrStatsCard() {
    var c = P.card({ title: t('وضعیت زنده'), icon: 'activity', id: 'wr-stats', subtitle: t('برآورد بازدیدکنندگان فعال و در صف روی همهٔ نودها؛ هر ۳۰ ثانیه به‌روز می‌شود.'),
      actions: P.btn(t('به‌روزرسانی'), { icon: 'refresh', size: 'sm', cls: 'pcdn-wr-refresh', onclick: function () { load(true); } }) });
    c.setAttribute('data-state', 'loading');
    var timer = null;
    function n(v) { return typeof v === 'number' && isFinite(v) ? v : 0; }
    function load(quiet) {
      if (!quiet) { clear(c.body); c.body.appendChild(P.skeleton(2)); }
      return P.api('GET', EP.wr, undefined, { hours: 24 }).then(function (res) {
        if (!document.body.contains(c) && quiet) return;
        clear(c.body);
        if (res.status === 404) { c.setAttribute('data-state', 'absent'); c.hidden = true; return; }
        if (!res.ok || !isObj(res.data)) {
          c.setAttribute('data-state', 'error');
          c.body.appendChild(P.errorBox(res, t('آمار اتاق انتظار دریافت نشد')));
          return;
        }
        var d = res.data, lh = isObj(d.last_hour) ? d.last_hour : {};
        c.setAttribute('data-state', d.enabled ? 'on' : 'off');
        append(c.body, [
          d.enabled ? null : P.alertBox('info', t('اتاق انتظار خاموش است؛ پس از روشن کردن و ذخیره، آمار اینجا نمایش داده می‌شود.')),
          h('div', { className: 'pcdn-kpis' },
            kpi('eye', 'brand', t('بازدیدکنندهٔ فعال'), num(n(d.active_estimate)), t('برآورد لحظه‌ای'), 'active'),
            kpi('clock', n(d.queued_estimate) > 0 ? 'warning' : 'muted', t('در صف'), num(n(d.queued_estimate)), t('برآورد لحظه‌ای'), 'queued'),
            kpi('check', 'success', t('ورود در ساعت گذشته'), num(n(lh.admitted)), t('اوج فعال: {0}', num(n(lh.peak_active))), 'admitted'),
            kpi('gauge', 'violet', t('بیشترین انتظار'), n(lh.max_wait_s) > 0 ? P.dur(n(lh.max_wait_s)) : t('بدون انتظار'), t('{0} نفر به صف رفتند', num(n(lh.queued))), 'wait')),
          typeof d.serving_edges === 'number' ? h('p', { className: 'pcdn-help pcdn-wr-edges', text: t('{0} نود این سایت را سرو می‌کنند؛ سهم هر نود: {1} بازدیدکنندهٔ فعال ({2} نود گزارش داده‌اند).',
            num(n(d.serving_edges)), num(n(d.node_max)), num(n(d.edges_reporting))) }) : null,
          hourlyBars(Array.isArray(d.hourly) ? d.hourly : [])]);
      });
    }
    function hourlyBars(rows) {
      rows = rows.filter(isObj).slice(-24);
      if (!rows.length) return null;
      var max = Math.max.apply(null, rows.map(function (r) { return Math.max(n(r.peak_active), n(r.queued)); }).concat([1]));
      return h('div', { className: 'pcdn-w10-bars-wrap' },
        h('div', { className: 'pcdn-w10-bars-title', text: t('۲۴ ساعت گذشته: اوج فعال و صف') }),
        h('div', { className: 'pcdn-w10-bars', role: 'img', 'aria-label': t('نمودار ساعتی اوج بازدیدکنندگان فعال و صف') }, rows.map(function (r) {
          var tip = P.date(r.t || r.hour, { hour: '2-digit', minute: '2-digit' }) + ' — ' + t('فعال: {0}، صف: {1}', num(n(r.peak_active)), num(n(r.queued)));
          return h('span', { className: 'pcdn-w10-bar', title: tip },
            h('span', { className: 'pcdn-w10-bar-a', style: 'height:' + Math.round(n(r.peak_active) * 100 / max) + '%' }),
            h('span', { className: 'pcdn-w10-bar-q', style: 'height:' + Math.round(n(r.queued) * 100 / max) + '%' }));
        })),
        h('div', { className: 'pcdn-w10-legend' }, h('span', { className: 'is-a', text: t('فعال') }), h('span', { className: 'is-q', text: t('صف') })));
    }
    load();
    timer = setInterval(function () { if (document.body.contains(c) && !document.hidden) load(true); }, 30000);
    A().onLeave(function () { clearInterval(timer); });
    return c;
  }

  function renderWaitingRoom(Aa) {
    var f = Aa.sectionForm('waiting_room', function (d, f2) {
      wrDefaults(d);
      var main = P.card({ title: t('اتاق انتظار'), icon: 'clock', id: 'wr-main',
        subtitle: t('وقتی تعداد بازدیدکنندگان هم‌زمان از ظرفیت بیشتر شود، بقیه در یک صف منصفانه منتظر می‌مانند تا سایت از دسترس خارج نشود.') });
      append(main.body, [
        P.toggle(d, 'enabled', t('اتاق انتظار روشن باشد'), { cls: 'pcdn-wr-on', onchange: f2.redraw,
          help: t('صف فقط وقتی تشکیل می‌شود که تعداد بازدیدکنندگان فعال از سقف زیر بیشتر شود؛ در حالت عادی کسی منتظر نمی‌ماند.') }),
        P.choice(d, 'mode', t('حالت'), [['queue', t('صف'), t('بازدیدکنندگان اضافه به ترتیب ورود در صف می‌مانند.'), 'clock'],
          ['off', t('موقتاً غیرفعال'), t('تنظیمات حفظ می‌شود ولی کسی به صف نمی‌رود.'), 'power']], { cols: 2 }),
        h('div', { className: 'pcdn-grid' },
          P.input(d, 'max_active', t('سقف بازدیدکنندهٔ فعال (کل سایت)'), { type: 'number', min: WR.active[0], max: WR.active[1], cls: 'pcdn-wr-max',
            help: t('تعداد بازدیدکنندگانی که هم‌زمان وارد سایت می‌شوند؛ بین همهٔ نودهای سالم تقسیم می‌شود.') }),
          P.input(d, 'session_minutes', t('مدت نشست بی‌کار'), { type: 'number', min: WR.minutes[0], max: WR.minutes[1], suffix: t('دقیقه'), suffixRtl: true, cls: 'pcdn-wr-min',
            help: t('بازدیدکننده‌ای که این مدت درخواستی نفرستد، جایش را به نفر بعدی صف می‌دهد (۱ تا ۱۲۰؛ پیش‌فرض ۱۰).') })),
        P.tags(d, 'paths', t('مسیرهای تحت پوشش'), { placeholder: '/checkout', space: true,
          help: t('پیشوند مسیرهایی که صف دارند (حداکثر ۲۰)؛ / یعنی کل سایت. مسیرهای تونل و /__pcdn/ هیچ‌وقت صف ندارند.') })]);
      var page = P.card({ title: t('صفحهٔ صف'), icon: 'fileText', tone: 'muted', id: 'wr-page',
        subtitle: t('متن ساده (بدون HTML) تا ۵۰۰ نویسه؛ خالی = متن پیش‌فرض. زبان صفحه از تنظیم مرورگر بازدیدکننده انتخاب می‌شود.') });
      append(page.body, h('div', { className: 'pcdn-grid' },
        textArea(d.queue_page, 'title_fa', t('عنوان (فارسی)'), { dir: 'rtl', rows: 1, placeholder: t('در صف ورود هستید') }),
        textArea(d.queue_page, 'title_en', t('عنوان (انگلیسی)'), { dir: 'ltr', rows: 1, placeholder: 'You are in the queue' }),
        textArea(d.queue_page, 'message_fa', t('پیام (فارسی)'), { dir: 'rtl', rows: 3 }),
        textArea(d.queue_page, 'message_en', t('پیام (انگلیسی)'), { dir: 'ltr', rows: 3 })));
      var by = P.collapsible({ title: t('استثناها'), icon: 'filter', tone: 'muted', id: 'wr-bypass', open: d.bypass.paths.length > 0 || d.bypass.ips.length > 0,
        subtitle: t('درخواست‌هایی که هیچ‌وقت به صف نمی‌روند.') });
      append(by.body, [
        P.toggle(d.bypass, 'verified_bots', t('ربات‌های تأییدشدهٔ موتورهای جست‌وجو'), { help: t('گوگل، بینگ و ربات‌های تأییدشدهٔ دیگر بدون صف عبور می‌کنند تا رتبهٔ سایت آسیب نبیند.') }),
        P.tags(d.bypass, 'paths', t('مسیرهای بدون صف'), { placeholder: '/api/', space: true, help: t('مثلاً /api/ یا /webhook (حداکثر ۲۰).') }),
        P.tags(d.bypass, 'ips', t('آی‌پی‌های بدون صف'), { placeholder: '198.51.100.0/24', help: t('آی‌پی یا شبکهٔ CIDR دفتر یا سرورهای خودتان (حداکثر ۵۰).') })]);
      return [main, page, by];
    }, { serialize: wrSerialize, validate: wrProblems, savedMsg: t('تنظیمات اتاق انتظار ذخیره شد و تا چند ثانیه روی همهٔ نودها اعمال می‌شود.') });
    return [wrStatsCard(), f.el];
  }

  // ================================================================== §18.2 «دسترسی محافظت‌شده»

  var METHODS = [['otp', t('کد یک‌بارمصرف ایمیلی'), t('کاربر ایمیلش را وارد می‌کند و کدی ۶ رقمی دریافت می‌کند؛ فقط ایمیل‌ها یا دامنه‌های فهرست.'), 'mail'],
    ['ip', t('فقط آی‌پی'), t('فقط از آی‌پی‌ها یا شبکه‌های فهرست باز می‌شود؛ بقیه هیچ صفحهٔ ورودی نمی‌بینند.'), 'globe'],
    ['otp_or_ip', t('آی‌پی یا کد ایمیلی'), t('از آی‌پی‌های فهرست بدون ورود باز می‌شود و از جای دیگر با کد ایمیلی.'), 'shieldCheck']];
  function methodLabel(m) { var x = METHODS.filter(function (r) { return r[0] === m; })[0]; return x ? x[1] : String(m || '—'); }

  function accSerialize(d) {
    d = clone(d) || {};
    return { enabled: !!d.enabled, apps: (Array.isArray(d.apps) ? d.apps : []).map(function (a) {
      return { id: String(a.id || ''), name: String(a.name || ''), paths: (a.paths || []).slice(), methods: a.methods || 'otp',
        emails: (a.emails || []).map(function (e) { return String(e).trim().toLowerCase(); }), ips: (a.ips || []).slice(),
        session_hours: typeof a.session_hours === 'number' ? a.session_hours : AC.defHours };
    }) };
  }
  /** Problems of one app (path prefix 'apps.i.' for the page; '' inside the drawer) — sections.AccessApp. */
  function appProblems(a, others, base) {
    var out = [];
    base = base || '';
    if (!APP_ID.test(String(a.id || ''))) out.push({ path: base + 'id', msg: t('شناسه: حروف کوچک انگلیسی، عدد و - (حداکثر ۳۲ نویسه، بدون - در ابتدا و انتها).') });
    else if (others.some(function (o) { return o.id === a.id; })) out.push({ path: base + 'id', msg: t('این شناسه را برنامهٔ دیگری دارد.') });
    var nm = String(a.name || '');
    if (!nm.trim() || nm.length > AC.name || /\n/.test(nm) || ctl(nm)) out.push({ path: base + 'name', msg: t('نام لازم است (حداکثر ۱۰۰ نویسه، یک خط).') });
    var paths = a.paths || [];
    listProblems(out, paths, base + 'paths', AC.paths, prefixOk, PREFIX_MSG, 1);
    paths.forEach(function (p, i) {
      others.forEach(function (o) {
        (o.paths || []).forEach(function (q) {
          if (prefixOk(p) && prefixOk(q) && overlap(p, q)) out.push({ path: base + 'paths.' + i, msg: t('مسیر {0} با مسیر {1} از برنامهٔ «{2}» هم‌پوشانی دارد.', p, q, o.name || o.id) });
        });
      });
    });
    listProblems(out, a.emails || [], base + 'emails', AC.emails, emailOk, t('ایمیل یا @دامنهٔ نامعتبر (مثل a@b.com یا @company.com).'));
    listProblems(out, a.ips || [], base + 'ips', AC.ips, cidrOk, CIDR_MSG);
    if (!intIn(a.session_hours, AC.hours)) out.push({ path: base + 'session_hours', msg: t('عددی بین ۱ تا ۷۲۰ ساعت وارد کنید.') });
    var m = a.methods || 'otp';
    if (m === 'otp' && !(a.emails || []).length) out.push({ path: base + 'emails', msg: t('برای کد ایمیلی دست‌کم یک ایمیل یا @دامنه لازم است.') });
    if (m === 'ip' && !(a.ips || []).length) out.push({ path: base + 'ips', msg: t('برای روش آی‌پی دست‌کم یک آی‌پی یا شبکه لازم است.') });
    if (m === 'otp_or_ip' && !(a.emails || []).length && !(a.ips || []).length) out.push({ path: base + 'emails', msg: t('دست‌کم یک ایمیل یا یک آی‌پی لازم است.') });
    return out;
  }
  function accProblems(d0) {
    var d = accSerialize(d0), out = [];
    if (d.apps.length > AC.apps) out.push({ path: 'apps', msg: t('حداکثر {0} مورد مجاز است.', num(AC.apps)) });
    d.apps.forEach(function (a, i) { out = out.concat(appProblems(a, d.apps.slice(0, i), 'apps.' + i + '.')); });
    return out;
  }
  function slug(name, apps) {
    var base = String(name || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 24) || 'app';
    var id = base, i = 2;
    while (apps.some(function (a) { return a.id === id; })) id = base + '-' + i++;
    return id;
  }

  function appDrawer(d, f, idx) {
    var apps = d.apps, orig = idx >= 0 ? apps[idx] : null;
    var draft = orig ? clone(orig) : { id: '', name: '', paths: apps.length ? [] : ['/admin'], methods: 'otp', emails: [], ips: [], session_hours: AC.defHours };
    ['paths', 'emails', 'ips'].forEach(function (k) { if (!Array.isArray(draft[k])) draft[k] = []; });
    var autoId = !orig;
    var dlg = P.dialog({ title: orig ? t('ویرایش برنامهٔ محافظت‌شده') : t('برنامهٔ محافظت‌شدهٔ جدید'), subtitle: orig ? String(orig.name || orig.id) : t('مسیرهایی که فقط افراد مجاز می‌بینند.'),
      icon: 'lock', kind: 'drawer', wide: true });
    dlg.el.classList.add('pcdn-acc-drawer');
    var err = h('div'), form = h('form', { className: 'pcdn-form', novalidate: true, onsubmit: function (e) { e.preventDefault(); ok(); } });
    var ctx = null;
    function draw() {
      clear(form);
      P.beginForm(draft);
      append(form, [
        h('div', { className: 'pcdn-grid' },
          P.input(draft, 'name', t('نام'), { ltr: false, maxlength: AC.name, placeholder: t('پنل مدیریت'), cls: 'pcdn-acc-name',
            oninput: function (v) { if (autoId) { draft.id = slug(v, apps.filter(function (x) { return x !== orig; })); var el = form.querySelector('.pcdn-acc-id input'); if (el) el.value = draft.id; } } }),
          P.input(draft, 'id', t('شناسه'), { maxlength: 32, placeholder: 'admin', cls: 'pcdn-acc-id', oninput: function () { autoId = false; },
            help: t('در نشانی ورود و نام کوکی می‌آید؛ حروف کوچک انگلیسی، عدد و -.') })),
        P.tags(draft, 'paths', t('مسیرها'), { placeholder: '/wp-admin', space: true,
          help: t('پیشوند مسیرهای محافظت‌شده (حداکثر ۲۰)؛ مسیرهای دو برنامه نباید روی هم بیفتند.') }),
        P.choice(draft, 'methods', t('روش ورود'), METHODS, { cols: 3, onchange: draw }),
        draft.methods !== 'ip' ? P.tags(draft, 'emails', t('ایمیل‌ها یا دامنه‌های مجاز'), { placeholder: 'ali@company.com @company.com', lower: true,
          help: t('ایمیل کامل یا @دامنه برای همهٔ ایمیل‌های آن دامنه (حداکثر ۲۰۰). به ایمیل خارج از فهرست کدی فرستاده نمی‌شود، ولی پیام صفحه یکسان است.') }) : null,
        draft.methods !== 'otp' ? P.tags(draft, 'ips', t('آی‌پی‌ها یا شبکه‌های مجاز'), { placeholder: '198.51.100.0/24',
          help: t('آی‌پی یا شبکهٔ CIDR (حداکثر ۱۰۰).') }) : null,
        P.input(draft, 'session_hours', t('اعتبار ورود'), { type: 'number', min: AC.hours[0], max: AC.hours[1], suffix: t('ساعت'), suffixRtl: true,
          help: t('پس از این مدت کاربر دوباره کد می‌گیرد (۱ تا ۷۲۰ ساعت؛ پیش‌فرض ۲۴).') }),
        h('button', { type: 'submit', hidden: true, tabindex: '-1', 'aria-hidden': 'true' })]);
      ctx = P.endForm();
      A().lockWrites(form);
    }
    function ok() {
      clear(err);
      P.clearErrors(form);
      // validated and stored as a copy: the tag inputs keep editing draft's own arrays
      var cand = clone(draft);
      if (cand.methods === 'ip') cand.emails = [];
      if (cand.methods === 'otp') cand.ips = [];
      cand.emails = cand.emails.map(function (e) { return String(e).trim().toLowerCase(); });
      var probs = appProblems(cand, apps.filter(function (x, i) { return i !== idx; }), '');
      if (probs.length) {
        var rest = P.placeErrors(ctx, probs);
        if (rest.length) err.appendChild(P.alertBox('danger', h('ul', { className: 'pcdn-errlist' }, rest.map(function (x) { return h('li', { text: x.msg }); }))));
        var b = form.querySelector('[aria-invalid]');
        if (b) b.focus();
        return;
      }
      dlg.close(true);
      if (orig) apps[idx] = cand; else apps.push(cand);
      f.redraw();
      P.toast(orig ? t('تغییرات برنامه اعمال شد؛ برای ثبت «ذخیره» را بزنید.') : t('برنامه به فهرست اضافه شد؛ برای ثبت «ذخیره» را بزنید.'), 'info');
    }
    append(dlg.foot, [P.btn(t('تأیید'), { kind: 'primary', icon: 'check', write: true, cls: 'pcdn-acc-ok', onclick: ok }), P.btn(t('انصراف'), { onclick: function () { dlg.close(); } })]);
    append(dlg.body, [err, form]);
    draw();
    dlg.focusFirst();
    return dlg;
  }

  function rotateCard() {
    var c = P.card({ title: t('کلید ورود'), icon: 'key', tone: 'muted', id: 'acc-rotate',
      subtitle: t('کلید مخفی سایت که کدها و کوکی‌های ورود با آن امضا می‌شوند؛ هیچ‌وقت نمایش داده نمی‌شود.') });
    var b = P.btn(t('ساخت کلید جدید'), { icon: 'refresh', write: true, cls: 'pcdn-acc-rotate', onclick: function () {
      P.confirm({ title: t('ساخت کلید جدید'), danger: true, ok: t('ساخت کلید جدید و خروج همه'), cancel: t('انصراف'),
        body: t('با کلید جدید همهٔ کاربرانی که الان وارد شده‌اند خارج می‌شوند و کدهای ارسال‌شده باطل می‌شوند. اگر احتمال می‌دهید کوکی یا کدی لو رفته این کار را انجام دهید.') })
        .then(function (yes) {
          if (!yes) return;
          P.busy(b, P.api('POST', EP.rotate, {})).then(function (res) {
            if (!res.ok) { P.toast(P.errorText(res), 'error'); return; }
            P.toast(t('کلید جدید ساخته شد؛ همهٔ کاربران باید دوباره وارد شوند.'), 'success');
          });
        });
    } });
    append(c.body, [h('p', { className: 'pcdn-help', text: t('پس از چند ثانیه روی همهٔ نودها اعمال می‌شود.') }), h('div', { className: 'pcdn-w10-tools' }, b)]);
    return c;
  }

  /** GET access/log → [{t, app, email_hash, ok}] (or {events: [...]}), newest first. */
  function logCard() {
    var c = P.card({ title: t('گزارش ورودها'), icon: 'activity', id: 'acc-log', subtitle: t('آخرین ورودهای موفق و ناموفق (ایمیل‌ها به‌صورت درهم‌شده نگه داشته می‌شوند).'),
      actions: P.btn(t('به‌روزرسانی'), { icon: 'refresh', size: 'sm', cls: 'pcdn-acc-log-refresh', onclick: function () { load(); } }) });
    function load() {
      clear(c.body);
      c.body.appendChild(P.skeleton(3));
      return P.api('GET', EP.alog, undefined, { limit: 200 }).then(function (res) {
        clear(c.body);
        if (res.status === 404) { c.hidden = true; return; }
        if (!res.ok) { c.body.appendChild(P.errorBox(res, t('گزارش ورودها دریافت نشد'))); return; }
        var rows = Array.isArray(res.data) ? res.data : (isObj(res.data) && Array.isArray(res.data.events) ? res.data.events : []);
        rows = rows.filter(isObj).sort(function (a, b) { return String(b.t || '').localeCompare(String(a.t || '')); }).slice(0, 200);
        if (!rows.length) { c.body.appendChild(P.empty('lock', t('هنوز ورودی ثبت نشده است'), t('پس از اولین ورود یا تلاش ناموفق، اینجا نمایش داده می‌شود.'))); return; }
        var ok = rows.filter(function (r) { return r.ok; }).length;
        var d24 = isObj(res.data) && isObj(res.data.last_24h) ? res.data.last_24h : null;
        append(c.body, [d24 ? h('div', { className: 'pcdn-kpis pcdn-acc-24h' },
            kpi('check', 'success', t('ورود موفق (۲۴ ساعت)'), num(Number(d24.ok) || 0), null, 'ok'),
            kpi('x', 'danger', t('تلاش ناموفق (۲۴ ساعت)'), num(Number(d24.fail) || 0), null, 'fail'),
            kpi('mail', 'brand', t('کد ارسال‌شده (۲۴ ساعت)'), num(Number(d24.otp) || 0), null, 'otp')) : null,
          h('p', { className: 'pcdn-help', text: t('{0} ورود موفق و {1} تلاش ناموفق در فهرست.', num(ok), num(rows.length - ok)) }),
          h('div', { className: 'pcdn-table-wrap' }, h('table', { className: 'pcdn-table pcdn-acc-log' },
            h('thead', null, h('tr', null, h('th', { text: t('زمان') }), h('th', { text: t('برنامه') }), h('th', { text: t('ایمیل (درهم)') }), h('th', { text: t('نتیجه') }))),
            h('tbody', null, rows.map(function (r) {
              return h('tr', { 'data-ok': r.ok ? '1' : '0' }, h('td', { text: P.date(r.t) }), h('td', null, ltr(String(r.app || '—'))),
                h('td', null, ltr(String(r.email_hash || '—').slice(0, 16))),
                h('td', null, r.ok ? P.badge(t('موفق'), 'success', 'check') : P.badge(t('ناموفق'), 'danger', 'x')));
            }))))]);
      });
    }
    load();
    return c;
  }

  function renderAccess(Aa) {
    var dom = site().domain;
    var f = Aa.sectionForm('access', function (d, f2) {
      d.apps = Array.isArray(d.apps) ? d.apps : [];
      var apps = d.apps, full = apps.length >= AC.apps;
      var add = P.btn(t('برنامهٔ جدید'), { kind: 'primary', icon: 'plus', size: 'sm', write: true, cls: 'pcdn-acc-add', disabled: full,
        onclick: function () { appDrawer(d, f2, -1); } });
      var main = P.card({ title: t('دسترسی محافظت‌شده'), icon: 'lock', id: 'acc-main',
        subtitle: t('بخشی از سایت (مثل پنل مدیریت) را پشت ورود ایمیلی یا فهرست آی‌پی قرار دهید؛ بدون تغییر در کد سایت.'),
        actions: [P.kit && P.kit.limitText ? P.kit.limitText(apps.length, AC.apps, t('برنامه')) : null, add] });
      main.body.appendChild(P.toggle(d, 'enabled', t('دسترسی محافظت‌شده روشن باشد'), { cls: 'pcdn-acc-on', onchange: f2.redraw,
        help: t('خاموش = همهٔ مسیرها مثل قبل برای همه باز است (برنامه‌ها حفظ می‌شوند).') }));
      if (!apps.length) {
        main.body.appendChild(P.empty('lock', t('هنوز برنامه‌ای نساخته‌اید'), t('برای هر بخش محافظت‌شده یک برنامه بسازید: مسیرها، روش ورود و افراد مجاز.')));
      } else {
        var ul = h('ul', { className: 'pcdn-whs pcdn-acc-apps' });
        apps.forEach(function (a, i) {
          var li = h('li', { className: 'pcdn-wh pcdn-acc-app', 'data-app': String(a.id || i) },
            h('div', { className: 'pcdn-wh-main' },
              h('div', { className: 'pcdn-wh-urlline' }, h('strong', { text: String(a.name || a.id) }), P.badge(methodLabel(a.methods), 'brand'), ltr(String(a.id || ''))),
              h('div', { className: 'pcdn-l4-meta' },
                h('span', null, t('مسیرها: '), ltr((a.paths || []).join('  '))),
                (a.emails || []).length ? h('span', { text: t('{0} ایمیل/دامنه', num(a.emails.length)) }) : null,
                (a.ips || []).length ? h('span', { text: t('{0} آی‌پی/شبکه', num(a.ips.length)) }) : null,
                h('span', { text: t('اعتبار ورود: {0} ساعت', num(a.session_hours || AC.defHours)) })),
              a.id ? h('div', { className: 'pcdn-acc-login' }, h('span', { className: 'pcdn-muted', text: t('نشانی ورود: ') }),
                P.copyable('https://' + dom + '/__pcdn/access/login?app=' + a.id, { label: t('کپی نشانی ورود') })) : null),
            h('div', { className: 'pcdn-wh-ctl' },
              P.iconBtn('edit', t('ویرایش برنامهٔ ') + String(a.name || a.id), function () { appDrawer(d, f2, i); }, { write: true, cls: 'pcdn-acc-edit' }),
              P.iconBtn('trash', t('حذف برنامهٔ ') + String(a.name || a.id), function () {
                apps.splice(i, 1); f2.redraw(); P.toast(t('برنامه از فهرست حذف شد؛ برای اعمال «ذخیره» را بزنید.'), 'info');
              }, { write: true, cls: 'is-danger pcdn-acc-del' })));
          P.reg('apps.' + i, li);
          ul.appendChild(li);
        });
        main.body.appendChild(ul);
      }
      var how = P.collapsible({ title: t('نحوهٔ کار'), icon: 'book', tone: 'muted', id: 'acc-how' });
      append(how.body, h('ul', { className: 'pcdn-ul' },
        h('li', { text: t('بازدیدکنندهٔ واردنشده به صفحهٔ ورود همین دامنه هدایت می‌شود، ایمیلش را می‌دهد و کد ۶ رقمی (معتبر ۵ دقیقه) دریافت می‌کند.') }),
        h('li', null, t('سرور شما ایمیل کاربر واردشده را در هدر '), ltr('X-PCDN-Access-Email'), t(' دریافت می‌کند؛ این هدر از درخواست‌های کاربران همیشه حذف می‌شود.')),
        h('li', null, t('خروج: '), ltr('https://' + dom + '/__pcdn/access/logout')),
        h('li', { text: t('مسیرهای /__pcdn/ هیچ‌وقت محافظت نمی‌شوند؛ ارسال کد برای هر آی‌پی محدود است و پیام صفحه برای ایمیل مجاز و غیرمجاز یکسان است.') })));
      return [main, how];
    }, { serialize: accSerialize, validate: accProblems, savedMsg: t('تنظیمات دسترسی ذخیره شد و تا چند ثانیه روی همهٔ نودها اعمال می‌شود.') });
    return [f.el, rotateCard(), logCard()];
  }

  // ================================================================== §18.3 downloads (statement / audit)

  /**
   * GET a file through api.php (CSRF header, so no plain link) and hand it to the browser as a download.
   * JSON answers are errors ({detail}); the filename comes from Content-Disposition.
   */
  function download(path, query, rsid) {
    var CFG = P.CFG;
    var url = CFG.api + (CFG.api.indexOf('?') >= 0 ? '&' : '?') + 'id=' + encodeURIComponent(CFG.serviceId) + '&path=' + encodeURIComponent(path);
    var rs = rsid === undefined ? CFG.rsid : rsid;
    if (rs) url += '&rsid=' + encodeURIComponent(rs);
    Object.keys(query || {}).forEach(function (k) { url += '&' + encodeURIComponent(k) + '=' + encodeURIComponent(query[k]); });
    return fetch(url, { method: 'GET', credentials: 'same-origin', headers: { 'X-PCDN-CSRF': CFG.csrf, 'X-PCDN-Lang': P.lang || 'fa', 'Accept': 'application/pdf, text/csv, application/json' } })
      .then(function (r) {
        var ct = String(r.headers.get('Content-Type') || '');
        if (!r.ok || ct.indexOf('application/json') === 0) {
          return r.json().catch(function () { return { detail: t('پاسخ نامعتبر از سرور (HTTP ') + r.status + ')' }; })
            .then(function (data) { return { ok: false, status: r.status, data: data }; });
        }
        var cd = String(r.headers.get('Content-Disposition') || '');
        var name = (/filename="?([^";]+)"?/.exec(cd) || [])[1] || 'pasargadcdn-download';
        return r.blob().then(function (b) {
          var href = URL.createObjectURL(b);
          var a = h('a', { href: href, download: name, hidden: true, 'data-download': name });
          document.body.appendChild(a);
          a.click();
          setTimeout(function () { URL.revokeObjectURL(href); if (a.parentNode) a.parentNode.removeChild(a); }, 1500);
          return { ok: true, status: r.status, name: name, size: b.size };
        });
      }, function () {
        return { ok: false, status: 0, data: { detail: t('ارتباط با سرور برقرار نشد. اتصال اینترنت را بررسی کنید.') } };
      });
  }
  /** Marks a page as missing on this controller (404) and takes it out of the navigation. */
  function gone(id, holder) {
    absent[id] = true;
    clear(holder);
    holder.appendChild(P.empty('info', t('این بخش روی سرور CDN شما هنوز فعال نیست'), t('پس از به‌روزرسانی سرور CDN در دسترس قرار می‌گیرد.')));
    if (A().refreshNav) A().refreshNav();
  }

  // ------------------------------------------------------------------ «صورت‌حساب مصرف»

  function ym(d) { return d.getUTCFullYear() + '-' + (d.getUTCMonth() < 9 ? '0' : '') + (d.getUTCMonth() + 1); }
  function months(n) {
    var out = [], d = new Date();
    d = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1));
    for (var i = 0; i < n; i++) { out.push(ym(d)); d = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() - 1, 1)); }
    return out;
  }
  function monthName(m) {
    var p = m.split('-');
    try {
      return new Intl.DateTimeFormat((P.locale || 'fa-IR') + '-u-ca-gregory', { year: 'numeric', month: 'long', timeZone: 'UTC' })
        .format(new Date(Date.UTC(Number(p[0]), Number(p[1]) - 1, 15)));
    } catch (e) { return m; }
  }
  // GET statement?format=json (controller statement.py): [id, dotted path in the answer, label, unit]
  var SUM = [['traffic', 'totals.gb', t('ترافیک'), 'GB'], ['requests', 'totals.requests', t('درخواست‌ها'), ''],
    ['cache', 'totals.cache_hit_ratio', t('نرخ برخورد کش'), '%'], ['tunnel', 'tunnel_gb', t('ترافیک تونل'), 'GB'],
    ['storage', 'storage.gb_month', t('فضای ذخیره‌سازی'), t('گیگابایت-ماه')], ['functions', 'functions_invocations', t('اجرای توابع لبه'), ''],
    ['l4', 'l4_gb', t('ترافیک TCP/UDP'), 'GB'], ['security', 'security_total', t('رویدادهای امنیتی'), ''],
    ['quota', 'quota.limit_gb', t('سهمیهٔ پلن'), 'GB'], ['overage', 'quota.overage_gb', t('ترافیک اضافه'), 'GB'], ['blocks', 'quota.blocks', t('بسته‌های اضافه'), '']];
  function pick(o, path) {
    return path.split('.').reduce(function (x, k) { return isObj(x) && has(x, k) ? x[k] : undefined; }, o);
  }
  function sumValue(v, unit) {
    if (typeof v !== 'number' || !isFinite(v)) return null;
    if (unit === '%') return num(Math.round((v <= 1 ? v * 100 : v) * 10) / 10) + t('٪');
    return (unit === 'GB' ? P.num1(v) : num(v)) + (unit && unit !== '%' ? ' ' + unit : '');
  }
  /** Summary of GET statement?format=json — the contract's known fields only, the rest ignored. */
  function summary(d) {
    var tiles = SUM.map(function (k) {
      var v = sumValue(pick(d, k[1]), k[3]);
      if (k[0] === 'quota' && pick(d, k[1]) === 0) v = t('نامحدود');
      return v === null ? null : h('div', { className: 'pcdn-w10-sum', 'data-sum': k[0] }, h('dt', { text: k[2] }), h('dd', null, ltr(v)));
    }).filter(Boolean);
    var plan = isObj(d.plan) ? d.plan.name : null;
    return [
      d.month_to_date || d.partial ? P.alertBox('info', t('ماه جاری است؛ ارقام تا امروز حساب شده‌اند.')) : null,
      typeof plan === 'string' && plan ? h('p', { className: 'pcdn-help' }, t('پلن: '), h('strong', { text: plan })) : null,
      tiles.length ? h('dl', { className: 'pcdn-w10-sums' }, tiles) : P.empty('fileText', t('خلاصه‌ای برای این ماه نیست'), t('فایل PDF یا CSV را دریافت کنید.'))];
  }

  function renderStatement(Aa, holder) {
    var st = { month: months(1)[0], rsid: undefined, sites: null };
    var c = P.card({ title: t('صورت‌حساب ماهانهٔ مصرف'), icon: 'fileText', id: 'w10-statement',
      subtitle: t('ترافیک روزانه، درخواست‌ها، نرخ کش، تونل، فضای ذخیره‌سازی، توابع لبه، TCP/UDP، رویدادهای امنیتی و سهمیهٔ پلن — بدون آی‌پی بازدیدکنندگان.') });
    var monthSel = h('select', { className: 'pcdn-input pcdn-w10-month', 'aria-label': t('ماه'), 'data-ro-ok': '1',
      onchange: function (e) { st.month = e.target.value; preview(); } },
      months(12).map(function (m, i) { return h('option', { value: m, text: monthName(m) + ' (' + m + ')' + (i === 0 ? t(' — تا امروز') : '') }); }));
    var siteBox = h('div', { className: 'pcdn-w10-site', hidden: true });
    var msg = h('div', { className: 'pcdn-w10-msg', 'aria-live': 'polite' });
    var prev = h('div', { className: 'pcdn-w10-preview' });
    function dl(fmt, button) {
      clear(msg);
      return P.busy(button, download(EP.statement, { month: st.month, format: fmt, lang: P.isEn ? 'en' : 'fa' }, st.rsid)).then(function (res) {
        if (res.ok) { P.toast(t('فایل {0} دریافت شد.', res.name), 'success'); return; }
        if (res.status === 404 && !(res.data && typeof res.data.detail === 'string' && /[؀-ۿ]/.test(res.data.detail))) { gone('monthly', holder); return; }
        msg.appendChild(P.errorBox(res, t('دریافت صورت‌حساب انجام نشد')));
      });
    }
    function preview() {
      clear(prev);
      prev.appendChild(P.skeleton(2));
      var q = { month: st.month, format: 'json', lang: P.isEn ? 'en' : 'fa' };
      if (st.rsid) q.rsid = st.rsid;
      return P.api('GET', EP.statement, undefined, q).then(function (res) {
        clear(prev);
        if (res.status === 404 && !st.rsid) { gone('monthly', holder); return; }
        if (!res.ok || !isObj(res.data)) { prev.appendChild(P.errorBox(res, t('خلاصهٔ این ماه دریافت نشد'))); return; }
        append(prev, summary(res.data));
      });
    }
    var pdf = P.btn(t('دریافت PDF'), { kind: 'primary', icon: 'download', cls: 'pcdn-w10-pdf', onclick: function (e) { dl('pdf', e.currentTarget); } });
    var csv = P.btn(t('دریافت CSV'), { icon: 'download', cls: 'pcdn-w10-csv', onclick: function (e) { dl('csv', e.currentTarget); } });
    append(c.body, [h('div', { className: 'pcdn-w10-tools' }, P.field(t('ماه'), monthSel), siteBox, h('div', { className: 'pcdn-w10-actions' }, pdf, csv)), msg, prev]);
    // §10.5 reseller: one statement per sub-site (the reseller's own service is the first choice)
    if (Aa.reseller && !Aa.inSubSite()) {
      P.api('GET', '', undefined, { rop: 'list' }).then(function (res) {
        var list = res.ok && isObj(res.data) && Array.isArray(res.data.sites) ? res.data.sites : [];
        if (!list.length) return;
        siteBox.hidden = false;
        var sel = h('select', { className: 'pcdn-input pcdn-w10-subsite', 'data-ro-ok': '1', 'aria-label': t('سایت'),
          onchange: function (e) { st.rsid = e.target.value ? Number(e.target.value) : undefined; preview(); } },
          [h('option', { value: '', text: t('سرویس خودم ({0})', site().domain) })].concat(list.map(function (s) {
            return h('option', { value: String(s.id), text: String(s.domain) + (s.label ? ' — ' + String(s.label) : '') });
          })));
        siteBox.appendChild(P.field(t('سایت'), sel));
      });
    }
    preview();
    return [c];
  }

  // ------------------------------------------------------------------ «گزارش تغییرات»

  var RANGES = [['7', t('۷ روز')], ['30', t('۳۰ روز')], ['90', t('۹۰ روز')]];
  var ACTOR_KINDS = { admin: [t('پشتیبانی'), 'brand'], capi: [t('API مشتری'), 'violet'], customer: [t('شما'), 'success'], client: [t('شما'), 'success'], system: [t('سیستم'), 'muted'] };
  function dayIso(daysAgo) { var d = new Date(Date.now() - daysAgo * 86400000); return d.toISOString().slice(0, 10); }
  function auditDetail(v) {
    if (v === null || v === undefined || v === '') return '—';
    if (!isObj(v)) return String(v).slice(0, 200);
    return Object.keys(v).slice(0, 8).map(function (k) {
      var x = v[k];
      return k + ': ' + (typeof x === 'object' ? JSON.stringify(x) : String(x)).slice(0, 80);
    }).join(' · ');
  }
  /** SPEC §20.3: a member of a shared domain did it — detail.on_behalf_of = share:<client id>:<role>. */
  function behalf(d) {
    var v = isObj(d) && typeof d.on_behalf_of === 'string' ? d.on_behalf_of : '';
    var m = /^share:(\d{1,10}):(viewer|dns|editor)$/.exec(v);
    if (!m) return null;
    var roles = { viewer: t('مشاهده‌گر'), dns: t('مدیر DNS'), editor: t('ویرایشگر') };
    return h('div', { className: 'pcdn-w10-behalf', 'data-on-behalf': v }, P.badge(t('عضو اشتراکی #{0} — {1}', m[1], roles[m[2]]), 'violet'));
  }
  function renderAudit(Aa, holder) {
    var st = { days: '30' };
    var c = P.card({ title: t('گزارش تغییرات'), icon: 'activity', id: 'w10-audit',
      subtitle: t('هر تغییری که در تنظیمات این سایت داده شده: چه زمانی، چه چیزی و توسط چه کسی (شما، کلید API یا پشتیبانی).') });
    var list = h('div', { className: 'pcdn-w10-audit-list' });
    var msg = h('div', { className: 'pcdn-w10-msg', 'aria-live': 'polite' });
    function q(fmt) { return { from: dayIso(Number(st.days)), to: dayIso(-1), format: fmt }; }
    function load() {
      clear(list);
      list.appendChild(P.skeleton(4));
      return P.api('GET', EP.audit, undefined, q('json')).then(function (res) {
        clear(list);
        if (res.status === 404) { gone('changes', holder); return; }
        if (!res.ok) { list.appendChild(P.errorBox(res, t('گزارش تغییرات دریافت نشد'))); return; }
        var rows = Array.isArray(res.data) ? res.data : (isObj(res.data) && Array.isArray(res.data.entries) ? res.data.entries : (isObj(res.data) && Array.isArray(res.data.items) ? res.data.items : []));
        rows = rows.filter(isObj).sort(function (a, b) { return String(b.at || b.t || '').localeCompare(String(a.at || a.t || '')); });
        if (!rows.length) { list.appendChild(P.empty('activity', t('در این بازه تغییری ثبت نشده است'), t('بازهٔ طولانی‌تری انتخاب کنید.'))); return; }
        var cut = isObj(res.data) && res.data.truncated;
        append(list, [cut ? P.alertBox('warning', t('فقط ۱۰٬۰۰۰ مورد آخر نمایش داده می‌شود؛ بازهٔ کوتاه‌تری انتخاب کنید یا CSV را دریافت کنید.')) : null,
          h('p', { className: 'pcdn-help', text: t('{0} مورد', num(rows.length)) }),
          h('div', { className: 'pcdn-table-wrap' }, h('table', { className: 'pcdn-table pcdn-w10-audit' },
            h('thead', null, h('tr', null, h('th', { text: t('زمان') }), h('th', { text: t('تغییر') }), h('th', { text: t('توسط') }), h('th', { text: t('جزئیات') }))),
            h('tbody', null, rows.slice(0, 500).map(function (r) {
              var kind = String(r.actor_kind || String(r.actor || '').split(':')[0] || '');
              var k = ACTOR_KINDS[kind] || [kind || '—', 'muted'];
              return h('tr', null, h('td', { className: 'pcdn-nowrap', text: P.date(r.at || r.t) }),
                h('td', null, ltr(String(r.action || '—')), r.target ? h('div', { className: 'pcdn-muted' }, ltr(String(r.target).slice(0, 80))) : null),
                h('td', null, P.badge(k[0], k[1]), r.actor ? ' ' : null, r.actor ? ltr(String(r.actor).slice(0, 40)) : null, behalf(r.detail)),
                h('td', { className: 'pcdn-w10-detail' }, ltr(auditDetail(r.detail))));
            }))))]);
      });
    }
    var csv = P.btn(t('دریافت CSV'), { icon: 'download', cls: 'pcdn-w10-audit-csv', onclick: function (e) {
      clear(msg);
      P.busy(e.currentTarget, download(EP.audit, q('csv'))).then(function (res) {
        if (res.ok) { P.toast(t('فایل {0} دریافت شد.', res.name), 'success'); return; }
        msg.appendChild(P.errorBox(res, t('دریافت فایل انجام نشد')));
      });
    } });
    append(c.body, [h('div', { className: 'pcdn-w10-tools' },
      P.segmented(RANGES, st.days, function (v) { st.days = v; Array.prototype.forEach.call(c.querySelectorAll('.pcdn-seg-btn'), function (b) {
        var on = b.getAttribute('data-value') === v; b.classList.toggle('is-active', on); b.setAttribute('aria-pressed', on ? 'true' : 'false'); }); load(); }, t('بازهٔ زمانی')),
      h('div', { className: 'pcdn-w10-actions' }, csv)), msg, list]);
    load();
    return [c];
  }

  // ================================================================== registry

  pages.waitingroom = {
    title: t('اتاق انتظار'), icon: 'clock', heading: t('اتاق انتظار'),
    desc: t('در اوج ترافیک (حراج، ثبت‌نام، اعلام نتایج) بازدیدکنندگان اضافه را در صف نگه دارید تا سایت برای همه کار کند.'),
    guide: {
      what: t('هر نود تعداد بازدیدکنندگان فعال را می‌شمارد؛ تا سقف، همه وارد می‌شوند و بقیه صفحهٔ صف را با جایگاه تقریبی می‌بینند و به ترتیب وارد می‌شوند.'),
      when: t('وقتی انتظار هجوم ناگهانی بازدیدکننده دارید و سرور شما ظرفیت محدودی دارد.'),
      rec: t('سقف را کمی کمتر از ظرفیت واقعی سرور بگذارید و فقط مسیرهای سنگین (مثل /checkout) را پوشش دهید.'),
      mistakes: [t('سقف خیلی پایین (صف در ترافیک عادی هم تشکیل می‌شود).'), t('پوشش دادن مسیرهای API یا وب‌هوک (برنامه‌ها صفحهٔ صف را نمی‌فهمند؛ آن‌ها را در استثناها بگذارید).')]
    },
    upsell: t('با ارتقای پلن، در اوج ترافیک بازدیدکنندگان در صف منصفانه منتظر می‌مانند و سایت از دسترس خارج نمی‌شود.'),
    hidden: function (s) { return !sectionOf(s, 'waiting_room'); },
    lock: function (f) { return f.waiting_room !== true; },
    render: function (Aa) { return renderWaitingRoom(Aa); }
  };
  pages.access = {
    title: t('دسترسی محافظت‌شده'), icon: 'lock', heading: t('دسترسی محافظت‌شده'),
    desc: t('پنل مدیریت، نسخهٔ آزمایشی یا هر مسیر دیگر را فقط برای ایمیل‌ها یا آی‌پی‌های مشخص باز کنید.'),
    guide: {
      what: t('CDN پیش از رسیدن درخواست به سرور شما ورود را بررسی می‌کند: کد یک‌بارمصرف ایمیلی، فهرست آی‌پی یا هر دو.'),
      when: t('برای پنل مدیریت (wp-admin و …)، محیط تست و ابزارهای داخلی که نباید عمومی باشند.'),
      rec: t('برای تیم‌ها از @دامنهٔ شرکت استفاده کنید و اعتبار ورود را کوتاه (مثلاً ۸ ساعت) بگذارید.'),
      mistakes: [t('هم‌پوشانی مسیر دو برنامه (ذخیره نمی‌شود).'), t('محافظت از مسیری که برنامه‌های موبایل یا API از آن استفاده می‌کنند.')]
    },
    upsell: t('با ارتقای پلن، بخش‌هایی از سایت را پشت ورود ایمیلی یا فهرست آی‌پی قرار دهید.'),
    hidden: function (s) { return !sectionOf(s, 'access'); },
    lock: function (f) { return f.access !== true; },
    render: function (Aa) { return renderAccess(Aa); }
  };
  pages.monthly = {
    title: t('صورت‌حساب مصرف'), icon: 'fileText', heading: t('صورت‌حساب ماهانهٔ مصرف'),
    desc: t('گزارش رسمی مصرف هر ماه به‌صورت PDF یا CSV، برای حسابداری یا ارائه به مشتری.'),
    hidden: function (s) { return !wave10(s) || !!absent.monthly; },
    render: function (Aa, holder) { return renderStatement(Aa, holder); }
  };
  pages.changes = {
    title: t('گزارش تغییرات'), icon: 'activity', heading: t('گزارش تغییرات'),
    desc: t('تاریخچهٔ تغییرات تنظیمات این سایت، با امکان دریافت CSV.'),
    hidden: function (s) { return !wave10(s) || !!absent.changes; },
    render: function (Aa, holder) { return renderAudit(Aa, holder); }
  };

  P.w10 = {
    EP: EP, wrSerialize: wrSerialize, wrProblems: wrProblems, accSerialize: accSerialize, accProblems: accProblems,
    appProblems: appProblems, prefixOk: prefixOk, cidrOk: cidrOk, emailOk: emailOk, download: download, months: months, absent: absent
  };
})();
