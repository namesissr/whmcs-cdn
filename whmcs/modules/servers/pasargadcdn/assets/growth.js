/*
 * Pasargad CDN — client app: growth features (docs/WHMCS.md «رشد»).
 *
 *  - free trial: a slim banner on every page (days left / ended) and an overview card with the paid plans
 *    and their WHMCS upgrade links (boot.trial, lib/Trial.php);
 *  - onboarding store: the first-run guide's manual progress (done / skipped / dismissed) kept per service
 *    in WHMCS through api.php local ops (lop=onboarding), with an in-browser fallback when WHMCS cannot
 *    store it (admin embed, reseller sub-site, read-only member, older addon) — the guide itself is the
 *    overview's «راه‌اندازی CDN» card in app.js;
 *  - «گزارش ایمیلی» page: the weekly / monthly e-mail report opt-in (lop=report); the WHMCS cron sends it.
 *
 * Everything is WHMCS-side: no controller endpoint is involved, so it works the same on older controllers.
 */
(function () {
  'use strict';
  var P = window.PCDN = window.PCDN || {};
  var t = P.t;  // i18n.js (SPEC §16.10)
  if (!P.h) return;
  var h = P.h, append = P.append, clear = P.clear, icon = P.icon, num = P.num, api = P.api;
  var pages = P.pages = P.pages || {};
  var G = { trial: null, persist: false, onboarding: { done: [], skipped: [], dismissed: false }, report: { freq: 'off', last: null }, admin: false, readonly: false, sid: '0' };

  function A() { return P.app; }
  function inSub() { var a = A(); return !!(a && a.inSubSite && a.inSubSite()); }
  /** Server-side persistence applies to the service itself only (not the admin embed / a reseller sub-site / read-only members). */
  function serverSide() { return G.persist && !G.admin && !G.readonly && !inSub(); }
  function localKey() { return 'onb-' + G.sid + (inSub() ? '-rs' + (P.CFG.rsid || '') : ''); }

  function init(boot, o) {
    o = o || {};
    G.admin = !!o.admin;
    G.readonly = !!o.readonly;
    G.sid = String(boot.serviceId || '0');
    G.trial = !G.admin && boot.trial && typeof boot.trial === 'object' ? boot.trial : null;
    var g = boot.growth && typeof boot.growth === 'object' ? boot.growth : {};
    G.persist = !!g.persist;
    G.reports = !!g.reports;
    if (g.onboarding && typeof g.onboarding === 'object') G.onboarding = clean(g.onboarding);
    if (g.report && typeof g.report === 'object') G.report = { freq: /^(weekly|monthly)$/.test(g.report.freq) ? g.report.freq : 'off', last: g.report.last || null };
  }
  function clean(o) {
    return { done: Array.isArray(o.done) ? o.done.slice() : [], skipped: Array.isArray(o.skipped) ? o.skipped.slice() : [], dismissed: !!o.dismissed };
  }

  // ------------------------------------------------------------------ onboarding store

  function onboarding() {
    if (serverSide()) return G.onboarding;
    var raw = P.store(localKey());
    var o = null;
    try { o = raw ? JSON.parse(raw) : null; } catch (e) { o = null; }
    o = clean(o && typeof o === 'object' ? o : {});
    // the guide's older in-browser «انجام دادم» mark (before progress moved to WHMCS)
    if (P.store('realip-' + G.sid) === '1' && o.done.indexOf('realip') < 0) o.done.push('realip');
    return o;
  }
  /** Applies a change and persists it (WHMCS when possible, else this browser). Resolves to the new state. */
  function saveOnboarding(patch) {
    var cur = clean(onboarding());
    Object.keys(patch).forEach(function (k) { cur[k] = patch[k]; });
    if (!serverSide()) {
      P.store(localKey(), JSON.stringify(cur));
      if (!inSub()) P.store('realip-' + G.sid, cur.done.indexOf('realip') >= 0 ? '1' : null);
      return Promise.resolve({ ok: true, state: cur });
    }
    return api('POST', '', cur, { lop: 'onboarding' }).then(function (res) {
      if (res.ok && res.data && res.data.onboarding) { G.onboarding = clean(res.data.onboarding); return { ok: true, state: G.onboarding }; }
      return { ok: false, res: res };
    });
  }
  function has(list, id) { return onboarding()[list].indexOf(id) >= 0; }
  function toggle(list, id, on) {
    var cur = onboarding()[list].filter(function (x) { return x !== id; });
    if (on) cur.push(id);
    var patch = {};
    patch[list] = cur;
    return saveOnboarding(patch);
  }

  // ------------------------------------------------------------------ free trial

  function trialActive() { return !!G.trial && !inSub(); }

  function trialBanner() {
    if (!trialActive()) return null;
    var tr = G.trial, a = A(), ended = !!tr.ended;
    var text = ended ? t('دوره آزمایشی رایگان شما تمام شده است.')
      : tr.days_left <= 1 ? t('دوره آزمایشی رایگان شما امروز یا فردا تمام می‌شود.') : t('دوره آزمایشی رایگان: {0} روز باقی مانده است.', num(tr.days_left));
    var sub = ended ? (tr.end === 'pause' ? t('تنظیمات شما محفوظ است؛ با ارتقا به یک پلن کامل، سایت ظرف چند ثانیه دوباره از CDN سرویس می‌گیرد.')
      : t('برای ادامه استفاده از CDN یکی از پلن‌های کامل را انتخاب کنید.'))
      : t('برای ادامه بدون وقفه و با همه تنظیمات فعلی، پیش از پایان دوره ارتقا دهید.');
    return h('div', { className: 'pcdn-alert pcdn-alert-' + (ended ? 'danger' : tr.days_left <= 2 ? 'warning' : 'info') + ' pcdn-trial-banner', role: 'note', 'data-trial': ended ? 'ended' : 'active' },
      icon(ended ? 'clock' : 'sparkles'),
      h('div', { className: 'pcdn-alert-body' }, h('strong', { text: text }), ' ', h('span', { text: sub }),
        h('div', { className: 'pcdn-banner-actions' },
          h('a', { className: 'pcdn-btn pcdn-btn-primary pcdn-btn-sm pcdn-trial-upgrade', href: a ? a.upgradeUrl : '#', 'data-ro-ok': '1' }, icon('sparkles'), h('span', { text: t('ارتقا به پلن کامل') })),
          a && a.S.page !== 'overview' ? h('a', { className: 'pcdn-link', href: '#pcdn=overview', 'data-ro-ok': '1', onclick: function (e) { e.preventDefault(); a.go('overview'); } }, h('span', { text: t('مقایسه پلن‌ها') })) : null)));
  }

  var CYCLE = function (c) {
    return { monthly: t('ماهانه'), quarterly: t('سه‌ماهه'), semiannually: t('شش‌ماهه'), annually: t('سالانه') }[c] || '';
  };
  function money(v, unit) {
    v = Number(v) || 0;
    return (v >= 100 ? num(Math.round(v)) : num(Math.round(v * 100) / 100)) + (unit ? ' ' + unit : '');
  }

  function trialCard() {
    if (!trialActive()) return null;
    var tr = G.trial, a = A(), base = (a && a.webRoot) || '';
    var total = Math.max(1, Number(tr.days) || 1), left = Math.max(0, Number(tr.days_left) || 0);
    var c = P.card({ title: tr.ended ? t('دوره آزمایشی تمام شد') : t('دوره آزمایشی رایگان'), icon: 'sparkles', tone: tr.ended ? 'danger' : 'brand', id: 'trial',
      subtitle: tr.ended ? t('سایت در حال حاضر از CDN سرویس نمی‌گیرد.') : t('{0} روز از {1} روز باقی مانده — پایان: {2}', num(left), num(total), P.date(tr.ends_at, { dateStyle: 'medium' })) });
    if (!tr.ended) c.body.appendChild(P.meter(left / total, left <= 2 ? 'warning' : 'brand'));
    c.body.appendChild(h('p', { className: 'pcdn-muted', text: t('در دوره آزمایشی {0} گیگابایت ترافیک دارید و حالت تونل فعال نیست. با ارتقا، سرویس همین‌جا و با همه تنظیمات فعلی ادامه پیدا می‌کند.', num(tr.gb)) }));
    var paid = Array.isArray(tr.paid) ? tr.paid : [];
    if (paid.length) {
      append(c.body, h('div', { className: 'pcdn-trial-plans' }, paid.map(function (p) {
        return h('div', { className: 'pcdn-trial-plan', 'data-plan': String(p.pid) },
          h('strong', { className: 'pcdn-trial-plan-name', text: p.name }),
          h('span', { className: 'pcdn-muted', text: Number(p.gb) > 0 ? t('{0} گیگابایت ترافیک ماهانه', num(p.gb)) : t('ترافیک نامحدود') }),
          p.price != null ? h('span', { className: 'pcdn-trial-price', text: (Number(p.price) > 0 ? money(p.price, p.currency) : t('رایگان')) + (p.cycle ? ' / ' + CYCLE(p.cycle) : '') }) : null,
          h('a', { className: 'pcdn-btn pcdn-btn-primary pcdn-btn-sm', href: base + p.url, 'data-ro-ok': '1' }, icon('sparkles'), h('span', { text: t('ارتقا به این پلن') })));
      })));
    }
    c.body.appendChild(h('div', { className: 'pcdn-row-actions' },
      h('a', { className: 'pcdn-link', href: a ? a.upgradeUrl : '#', 'data-ro-ok': '1' }, h('span', { text: t('همه گزینه‌های ارتقا در ناحیه کاربری') }), icon('external'))));
    return c;
  }

  // ------------------------------------------------------------------ «گزارش ایمیلی» page

  var FREQS = function () {
    return [['off', t('خاموش')], ['weekly', t('هفتگی')], ['monthly', t('ماهانه')]];
  };

  function renderReports() {
    var a = A(), draft = { freq: G.report.freq };
    var c = P.card({ title: t('گزارش ایمیلی دوره‌ای'), icon: 'mail', id: 'email-report',
      subtitle: t('خلاصه عملکرد سایت را به‌صورت خودکار به ایمیل حساب WHMCS خود دریافت کنید.') });
    var choice = h('div', { className: 'pcdn-choice-row', role: 'radiogroup', 'aria-label': t('دفعات ارسال') });
    var save = P.btn(t('ذخیره'), { kind: 'primary', icon: 'check', write: true, cls: 'pcdn-report-save', onclick: function () {
      P.busy(save, api('POST', '', { freq: draft.freq }, { lop: 'report' })).then(function (res) {
        if (!res.ok) { P.toast(P.errorText(res), 'error'); return; }
        G.report = res.data.report || { freq: draft.freq, last: G.report.last };
        P.toast(G.report.freq === 'off' ? t('گزارش ایمیلی خاموش شد.') : G.report.freq === 'weekly' ? t('گزارش هفتگی فعال شد؛ اولین گزارش پس از پایان این هفته ارسال می‌شود.')
          : t('گزارش ماهانه فعال شد؛ اولین گزارش پس از پایان این ماه ارسال می‌شود.'));
        if (a) a.renderMain();
      });
    } });
    function draw() {
      clear(choice);
      FREQS().forEach(function (f) {
        var id = 'pcdn-rf-' + f[0];
        var inp = h('input', { type: 'radio', name: 'pcdn-report-freq', id: id, value: f[0], checked: draft.freq === f[0], 'data-freq': f[0],
          onchange: function () { draft.freq = f[0]; save.hidden = draft.freq === G.report.freq; } });
        choice.appendChild(h('label', { className: 'pcdn-radio-pill', 'for': id }, inp, h('span', { text: f[1] })));
      });
      save.hidden = draft.freq === G.report.freq;
    }
    draw();
    var status = G.report.freq === 'off' ? P.badge(t('خاموش'), 'muted') : P.badge(G.report.freq === 'weekly' ? t('هفتگی — فعال') : t('ماهانه — فعال'), 'success');
    append(c.body, [
      h('div', { className: 'pcdn-report-status' }, h('span', { text: t('وضعیت: ') }), status,
        G.report.last ? h('span', { className: 'pcdn-muted pcdn-small', 'data-report-last': '1', text: t(' · آخرین گزارش: {0}', P.date(String(G.report.last.at).replace(' ', 'T') + 'Z', { dateStyle: 'medium' })) }) : null),
      choice,
      h('div', { className: 'pcdn-row-actions' }, save),
      h('p', { className: 'pcdn-hint', text: t('گزارش هفتگی پس از پایان هر هفته (دوشنبه) و گزارش ماهانه در روز اول ماه بعد، به زبانی که در حساب WHMCS انتخاب کرده‌اید ارسال می‌شود.') })]);
    var inc = P.card({ title: t('محتوای گزارش'), icon: 'fileText', id: 'email-report-contents' });
    var items = [t('تعداد درخواست‌ها و ترافیک دوره'), t('نرخ کش (درصد پاسخ مستقیم از CDN)'), t('کشورها و مسیرهای پربازدید'),
      t('تهدیدهای متوقف‌شده به تفکیک WAF، فایروال، محدودیت نرخ و …'), t('دسترس‌پذیری ماه (SLA) در صورت پشتیبانی سرور CDN'), t('مصرف تونل، اگر حالت تونل در پلن شما فعال باشد')];
    append(inc.body, h('ul', { className: 'pcdn-list' }, items.map(function (x) { return h('li', { text: x }); })));
    return [c, inc];
  }

  pages.emailreports = {
    title: t('گزارش ایمیلی'), icon: 'mail',
    desc: t('گزارش خودکار هفتگی یا ماهانه عملکرد سایت در ایمیل شما.'),
    hidden: function () { return !G.persist || !G.reports || G.admin || inSub(); },
    render: function () { return renderReports(); }
  };

  P.growth = {
    init: init, onboarding: onboarding, saveOnboarding: saveOnboarding, has: has, toggle: toggle,
    trialBanner: trialBanner, trialCard: trialCard, persisted: serverSide
  };
})();
