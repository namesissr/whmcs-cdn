/*
 * Pasargad CDN — client-area app shell (vanilla JS, no dependencies).
 *
 * Script order (see pasargadcdn_assets()): ui.js → pages.js → rules.js → reports.js → … → functions.js →
 * tutorials.js → tunnel.js → … → app.js. Boot data comes from <script id="pcdn-boot"> (see
 * pasargadcdn_ClientArea); every call goes through api.php, which pins the
 * request to this service's domain. Data only reaches the DOM through
 * textContent / createElement.
 */
(function () {
  'use strict';
  var P = window.PCDN;
  var t = P.t;  // i18n.js (SPEC §16.10)
  var root = document.getElementById('pcdn-app');
  if (!root || !P || !P.h) return;
  var h = P.h, append = P.append, clear = P.clear, icon = P.icon, ltr = P.ltr, clone = P.clone, num = P.num, api = P.api;

  var boot = {};
  try { boot = JSON.parse(document.getElementById('pcdn-boot').textContent || '{}'); } catch (e) { /* shown below */ }
  // Blend into the host theme (light/dark, surfaces, brand colour, font) before anything renders.
  if (P.theme) P.theme.init(root, boot.theme);
  P.CFG.api = root.getAttribute('data-api') || '';
  P.CFG.csrf = root.getAttribute('data-csrf') || '';
  P.CFG.serviceId = boot.serviceId || 0;
  var WEBROOT = P.CFG.api.replace(/modules\/servers\/pasargadcdn\/api\.php$/, '');
  // Admin mode (addon «مدیریت کامل»): boot.admin carries WHMCS admin links; plan changes happen on the admin service page.
  var ADMIN = boot.admin && typeof boot.admin === 'object' ? boot.admin : null;
  // SPEC §20.3: a member of a shared domain (addon route «دامنه‌های اشتراکی»): {id, role, owner}. No owner billing in the boot;
  // upgrade / add-funds links are never shown; controls the role cannot use are locked and some pages hidden.
  var SHARE = boot.share && typeof boot.share === 'object' && !ADMIN ? boot.share : null;
  var UPGRADE_URL = SHARE ? '#pcdn-no-upgrade' : ADMIN ? String(ADMIN.serviceUrl || '#') : WEBROOT + 'upgrade.php?type=package&id=' + encodeURIComponent(boot.serviceId || '');
  var SID = String(boot.serviceId || '0');
  // Overage billing: included traffic (WHMCS soft limit) vs the controller hard cap.
  var BILL = boot.billing && Number(boot.billing.included_gb) > 0 ? boot.billing : null;
  // Prepaid wallet: cap = plan + blocks bought this month from the client's credit balance.
  var WALLET = boot.wallet && typeof boot.wallet === 'object' && Number(boot.wallet.plan_gb) > 0 ? boot.wallet : null;
  // §10.2 smart-usage: forecast / upgrade suggestion markers the prepaid engine set this month.
  var SUGGEST = boot.suggest && typeof boot.suggest === 'object' && (boot.suggest.forecast || boot.suggest.upgrade) ? boot.suggest : null;
  // §10.4 statement: this service's traffic top-ups (current + previous months) for the «صورت‌حساب و مصرف» page.
  var STATEMENT = boot.statement && typeof boot.statement === 'object' ? boot.statement : null;
  // §10.5 reseller: this account provisions/manages CDN sub-sites for its own end-customers.
  var RESELLER = boot.reseller && boot.reseller.enabled && !ADMIN ? boot.reseller : null;
  var RSITE = null;                  // active reseller sub-site context {id, domain, label} or null
  var OWN_SITE = boot.site || null;  // the reseller's own service site, to return to after managing a sub-site
  var OWN_ACTIVE = !!boot.active;
  var ADDFUNDS_URL = SHARE ? '#pcdn-no-upgrade' : ADMIN ? String(ADMIN.clientUrl || '#') : WEBROOT + 'clientarea.php?action=addfunds';
  // §14.3.7 team access: a WHMCS user without the manage-products permission gets a read-only app
  // (api.php refuses their writes with 403 regardless; this only keeps the UI honest).
  var READONLY = !!boot.readonly && !ADMIN;
  /** SPEC §20.1: pages a role may change (null = every page); everything else is view-only for the member. */
  var SHARE_WRITE = { viewer: [], dns: ['dns', 'secondary'], editor: null };
  /** Pages a member never sees: customer API keys, sharing management, the customer transfer (§19.3), the owner's e-mail reports / reseller panel / top-up statement. */
  var SHARE_HIDE = ['apikeys', 'sharing', 'xfer', 'emailreports', 'reseller', 'statement'];
  function shareLocked(id) {
    if (!SHARE) return false;
    var w = SHARE_WRITE.hasOwnProperty(SHARE.role) ? SHARE_WRITE[SHARE.role] : [];
    return w !== null && w.indexOf(id) < 0;
  }
  /** Read-only right now: a read-only team member, or a member whose role cannot change the current page. */
  function roNow() { return READONLY || shareLocked(S.page); }
  // SPEC §19.2: the domain was just transferred to this account — one-time notice until dismissed (local op `transfer`).
  var TRANSFER = boot.transfer && typeof boot.transfer === 'object' && !ADMIN ? boot.transfer : null;
  function money(v) {
    v = Number(v) || 0;
    return (v >= 100 ? num(Math.round(v)) : num(Math.round(v * 100) / 100)) + (WALLET && WALLET.currency ? ' ' + WALLET.currency : '');
  }
  function addFundsBtn(kind) {
    return h('a', { className: 'pcdn-btn pcdn-btn-' + (kind || 'primary') + ' pcdn-addfunds', href: ADDFUNDS_URL, 'data-ro-ok': '1' },
      icon('wallet'), h('span', { text: ADMIN ? t('افزودن اعتبار (پروفایل مشتری)') : t('شارژ کیف پول') }));
  }

  var S = {
    site: boot.site || null,
    error: boot.error || (boot.serviceId ? null : t('داده اولیه نامعتبر است')),
    active: !!boot.active,
    page: 'overview', sub: '',
    form: null,           // active config-section form (dirty tracking / save bar)
    analytics: {}, period: '24h', events: null, dnssec: null,
    dns: { q: '', type: '' }, ev: { source: '', action: '' }, help: { q: '', cat: '' },
    showSetup: false
  };

  // ------------------------------------------------------------------ navigation model

  function features() { return (S.site && S.site.plan && S.site.plan.features) || {}; }
  var NAV = [
    { title: t('شروع'), items: ['overview', 'help'] },
    // Wave 8 (SPEC §16.7): «DNS ثانویه» once the controller returns config.dns_secondary (w8.js).
    { title: 'DNS', items: ['dns', 'dnssec', 'secondary'] },
    // Wave 7 (SPEC §15.7): quality / usage / speed test appear once the controller answers tunnel/health
    // (tunnelq.js P.w7.probe); the browser-only config checker needs no endpoint.
    // Wave 13 (SPEC §22.11): «تنظیمات پیشنهادی برنامه‌ها» once the controller answers tunnel/profile (tguide.js P.tprofile.probe).
    { title: t('تونل'), items: ['tunnel', 'tquality', 'tusage', 'tconfig', 'tguide', 'speedtest'] },
    { title: t('عملکرد'), items: ['cache', 'pagerules', 'image', 'video', 'pools'] },
    // Wave 8 (SPEC §16.4 / §16.5): TCP/UDP apps and video delivery, shown only when the controller returns `l4` / `video`.
    { title: 'TCP/UDP', items: ['tcpudp'] },
    // SPEC §16.8: «فضای ذخیره‌سازی» once the controller's plan features carry storage_gb (storage.js).
    { title: t('ذخیره‌سازی'), items: ['storage'] },
    // Wave 6B (SPEC §14.2): shown only when the controller returns the section (see available()).
    { title: t('قوانین'), items: ['redirects', 'transform'] },
    // SPEC §16.9: «توابع لبه» once the controller's plan features carry edge_functions (functions.js).
    { title: t('توسعه'), items: ['functions'] },
    // Wave 10 (SPEC §18.1/§18.2): «دسترسی محافظت‌شده» / «اتاق انتظار» once the controller returns the sections (w10.js).
    { title: t('امنیت'), items: ['firewall', 'waf', 'bots', 'ddos', 'ratelimit', 'hotlink', 'access', 'waitingroom'] },
    { title: t('SSL و هدرها'), items: ['ssl', 'headers', 'errorpages'] },
    // Wave 6D (SPEC §14.3): SLA report with the reports; webhooks + log export next to the API keys.
    // Wave 10 (SPEC §18.3): monthly PDF/CSV statement and the site's change log (w10.js).
    // Wave 14 (SPEC §23.7 / §23.4): «تجربهٔ کاربران واقعی» (rum.js, plan feature rum) and «تاریخچهٔ تنظیمات» (history.js, once the
    // controller answers config/history).
    { title: t('گزارش‌ها'), items: ['analytics', 'rum', 'events', 'sla', 'usage', 'statement', 'monthly', 'changes', 'history', 'emailreports'] },
    // Wave 14 (SPEC §23.5): «هشدارها» (alerts.js, account-level; owner only)
    { title: t('یکپارچه‌سازی و API'), items: ['alerts', 'webhooks', 'logs', 'apikeys', 'sharing', 'xfer'] }
  ];
  if (RESELLER) NAV.unshift({ title: t('نمایندگی'), items: ['reseller'] });
  var pages = P.pages = P.pages || {};
  function page(id) { return available(id) ? pages[id] : pages.overview; }
  function locked(id) { var p = pages[id]; return !!(p && p.lock && p.lock(features())); }
  /** A registered page this controller supports (feature-detected pages declare hidden(site)). */
  function available(id) { var p = pages[id]; return !!p && !(SHARE && SHARE_HIDE.indexOf(id) >= 0) && !(p.hidden && p.hidden(S.site)); }

  function readHash() {
    var m = /^#pcdn=([a-z]+)(?:\/([a-z0-9_-]+))?$/.exec(window.location.hash || '');
    return m && available(m[1]) ? { page: m[1], sub: m[2] || '' } : null;
  }
  /** A deep link to a registered page that is still hidden (feature probe pending), else null. */
  function pendingHash() {
    var m = /^#pcdn=([a-z]+)(?:\/([a-z0-9_-]+))?$/.exec(window.location.hash || '');
    return m && pages[m[1]] && !available(m[1]) ? { page: m[1], sub: m[2] || '' } : null;
  }
  /** Rebuilds the side navigation in place (after a feature probe changed which pages are available). */
  function refreshNav() {
    var nav = root.querySelector('.pcdn-side .pcdn-nav');
    if (!nav || !S.site) return;
    clear(nav);
    append(nav, navTree());
  }
  function writeHash(replace) {
    var hs = '#pcdn=' + S.page + (S.sub ? '/' + S.sub : '');
    if (window.location.hash === hs) return;
    try {
      if (replace) window.history.replaceState(null, '', hs);
      else window.history.pushState(null, '', hs);
    } catch (e) { window.location.hash = hs; }
  }

  /** Navigate to a page (asks first when the current form has unsaved changes). */
  function go(id, sub, o) {
    o = o || {};
    return guard().then(function (ok) {
      if (!ok) { if (o.fromHistory) writeHash(true); return false; }
      S.page = available(id) ? id : 'overview';
      S.sub = sub || '';
      if (!o.fromHistory) writeHash(false);
      renderAll();
      var top = root.getBoundingClientRect().top;
      if (top < 0 && !o.keepScroll) window.scrollTo(0, window.pageYOffset + top - 12);
      var hd = root.querySelector('.pcdn-page-title');
      if (hd && o.focus !== false && !o.fromBoot) { hd.setAttribute('tabindex', '-1'); hd.focus({ preventScroll: true }); }
      return true;
    });
  }
  function guard() {
    if (!S.form || !S.form.dirty()) return Promise.resolve(true);
    return P.confirm({
      title: t('تغییرات ذخیره نشده‌اند'), danger: true, ok: t('خروج بدون ذخیره'), cancel: t('ماندن و ذخیره'),
      body: t('در این بخش تغییراتی داده‌اید که هنوز ذخیره نشده است. اگر خارج شوید این تغییرات از بین می‌رود.')
    }).then(function (ok) { if (ok) S.form = null; return ok; });
  }
  window.addEventListener('popstate', function () {
    var r = readHash() || { page: 'overview', sub: '' };
    if (r.page === S.page && r.sub === S.sub) return;
    go(r.page, r.sub, { fromHistory: true });
  });
  window.addEventListener('beforeunload', function (e) {
    if (S.form && S.form.dirty()) { e.preventDefault(); e.returnValue = ''; return ''; }
  });

  // ------------------------------------------------------------------ helpers shared with pages.js / reports.js

  var DEFAULTS = {
    // Wave 6A fields (SPEC §14.1): the pages render their controls only when the section returned by
    // the controller carries the key, so an older controller (which rejects unknown fields) never gets them.
    cache: { enabled: true, dev_mode: false, level: 'standard', edge_ttl: 86400, browser_ttl: 0, ignore_query: false, bypass_cookies: [], always_online: true,
      stale_while_revalidate: true, stale_if_error: 86400, shield: false, key_device: false, key_cookies: [], key_query_allow: [] },
    ssl: { force_https: false, hsts: { enabled: false, max_age: 31536000, include_subdomains: false, preload: false }, min_tls: '1.2', origin_protocol: 'http', origin_verify: false, http3: true },
    waf: { mode: 'off', paranoia: 1, groups: ['sqli', 'xss', 'lfi', 'rce', 'php', 'scanner', 'protocol'], exclusions: [] },
    ddos: { mode: 'off', threshold_rps: 200, clearance_ttl: 3600 },
    firewall: { default_action: 'allow', rules: [] },
    ratelimit: { rules: [] },
    pagerules: { rules: [] },
    pools: { pools: [] },
    headers: { request: [], response: [] },
    hotlink: { enabled: false, extensions: ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'mp4'], allowed_referers: [], allow_empty: true },
    image: { enabled: false, quality: 85, max_width: 2000, auto_webp: false },
    errorpages: { '5xx': null, '4xx': null },
    tunnel: { enabled: false, paths: [], idle_timeout: 3600, per_connection_mbps: 0, max_connections_per_ip: 0, allowed_countries: [], fallback: 'origin' },
    // Wave 6B (SPEC §14.2) — their pages are hidden unless the controller returns the section.
    transform: { rules: [] },
    redirects: { rules: [] },
    bots: { mode: 'off', allow_verified: true, block_empty_ua: true }
  };
  function config(section) {
    var c = S.site && S.site.config && S.site.config[section];
    return clone(c || DEFAULTS[section]);
  }
  function setConfig(section, data) {
    S.site.config = S.site.config || {};
    S.site.config[section] = data;
  }
  function edgeIps() { return (S.site && Array.isArray(S.site.edge_ips)) ? S.site.edge_ips.filter(function (x) { return typeof x === 'string'; }) : []; }

  /** Read-only mode for services that are not Active, and for read-only team members (§14.3.7). */
  var WRITE_SEL = 'input,select,textarea,button[data-write]', TEAM_SEL = WRITE_SEL + ',button[data-team-write]';
  function lockWrites(el) {
    if ((S.active && !roNow()) || !el) return;
    var sel = roNow() ? TEAM_SEL : WRITE_SEL;
    if (el.matches && el.matches(sel) && !el.hasAttribute('data-ro-ok')) el.disabled = true;
    Array.prototype.forEach.call(el.querySelectorAll(sel), function (x) {
      if (!x.hasAttribute('data-ro-ok')) x.disabled = true;
    });
  }
  // Read-only team member: also lock write controls that pages add later (async lists, dialogs, drawers).
  if ((READONLY || SHARE) && window.MutationObserver) {
    var roObs = new window.MutationObserver(function (muts) {
      muts.forEach(function (m) { Array.prototype.forEach.call(m.addedNodes, function (n) { if (n.nodeType === 1) lockWrites(n); }); });
    });
    roObs.observe(root, { childList: true, subtree: true });
    if (P.getLayer) roObs.observe(P.getLayer(), { childList: true, subtree: true });
  }
  if (READONLY) root.classList.add('pcdn-ro');
  if (SHARE) root.classList.add('pcdn-shared', 'pcdn-share-' + String(SHARE.role).replace(/[^a-z]/g, ''));
  // Growth (growth.js): free-trial CTA, onboarding progress kept in WHMCS, e-mail report opt-in.
  var GROWTH = P.growth || null;
  if (GROWTH) GROWTH.init(boot, { admin: !!ADMIN || !!SHARE, readonly: READONLY || !!SHARE });

  function reloadSite() {
    return api('GET', '').then(function (res) {
      if (res.ok) { S.site = res.data; S.error = null; }
      return res;
    });
  }
  function reloadRecords() {
    return api('GET', 'records').then(function (res) {
      if (res.ok && Array.isArray(res.data)) S.site.records = res.data;
      return res;
    });
  }
  /** PUT a whole config section outside of a form (quick toggles, "block this IP"). */
  function putSection(section, body) {
    return api('PUT', 'config/' + section, body).then(function (res) {
      if (res.ok) setConfig(section, res.data && typeof res.data === 'object' && !Array.isArray(res.data) && !res.data.ok ? res.data : body);
      return res;
    });
  }

  function tutLink(id, label) {
    return h('a', { className: 'pcdn-link', href: '#pcdn=help/' + id, 'data-ro-ok': '1', onclick: function (e) { e.preventDefault(); go('help', id); } },
      icon('book'), h('span', { text: label || t('آموزش کامل') }));
  }
  function goLink(id, label, ic) {
    return h('a', { className: 'pcdn-link', href: '#pcdn=' + id, 'data-ro-ok': '1', onclick: function (e) { e.preventDefault(); go(id); } },
      h('span', { text: label }), icon(ic || 'arrowLeft'));
  }

  // ------------------------------------------------------------------ config-section forms (dirty tracking + sticky save bar)

  /**
   * build(draft, form) → nodes. Returns form {el, draft, redraw(), dirty(), save(), reset()}.
   * The page puts form.el into its output; the save bar appears once the draft differs from the stored section.
   * o.validate(draft) → [{path, label, msg}] runs before the PUT (client-side mirror of controller rules);
   * any problem is shown next to its field (or in the form summary) and nothing is sent.
   */
  function sectionForm(section, build, o) {
    o = o || {};
    var ser = o.serialize || function (x) { return x; };
    var f = { section: section, el: h('div', { className: 'pcdn-form', 'data-form': section }), summary: h('div', { className: 'pcdn-form-errors' }) };
    function snap(d) { return JSON.stringify(ser(clone(d))); }
    function failed(items, summary, status) {
      var rest = P.placeErrors(f.ctx, items);
      if (rest.length || !items.length) {
        append(f.summary, P.errorBox({ ok: false, status: status, data: { detail: rest.length ? rest.map(function (x) { return { loc: ['body'].concat(x.path.split('.')), msg: x.msg }; }) : summary } }, t('ذخیره انجام نشد')));
      }
      P.toast(t('ذخیره انجام نشد؛ خطاها را بررسی کنید.'), 'error');
      var first = f.el.querySelector('.has-error, .pcdn-form-errors .pcdn-alert');
      if (first && first.scrollIntoView) first.scrollIntoView({ block: 'center', behavior: reduced() ? 'auto' : 'smooth' });
    }
    f.load = function () { f.draft = config(section); f.original = snap(f.draft); };
    f.redraw = function () {
      var y = window.pageYOffset;
      clear(f.el);
      P.beginForm(f.draft);
      append(f.el, [f.summary, build(f.draft, f)]);
      f.ctx = P.endForm();
      lockWrites(f.el);
      updateSaveBar();
      if (Math.abs(window.pageYOffset - y) > 2) window.scrollTo(0, y);
    };
    f.dirty = function () { return S.active && !roNow() && snap(f.draft) !== f.original; };
    f.reset = function () { clear(f.summary); f.load(); f.redraw(); };
    f.save = function (button) {
      clear(f.summary);
      P.clearErrors(f.el);
      var bad = o.validate ? (o.validate(f.draft) || []) : [];
      if (bad.length) {
        failed(bad, '', 422);
        return Promise.resolve({ ok: false, status: 422, data: { detail: bad.map(function (x) { return { loc: ['body'].concat(x.path.split('.')), msg: x.msg }; }) } });
      }
      return P.busy(button, api('PUT', 'config/' + section, ser(clone(f.draft)))).then(function (res) {
        if (!res.ok) {
          var e = P.parseErrors(res.data, res.status);
          failed(e.items, e.summary, res.status);
          return res;
        }
        setConfig(section, res.data && typeof res.data === 'object' && !Array.isArray(res.data) ? res.data : ser(clone(f.draft)));
        f.load();
        f.redraw();
        P.toast(o.savedMsg || t('تغییرات ذخیره شد و تا چند ثانیه روی همه سرورها اعمال می‌شود.'));
        if (o.onSaved) o.onSaved();
        return res;
      });
    };
    f.load();
    S.form = f;
    f.redraw();
    return f;
  }
  function reduced() { return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches; }

  var saveBar = null;
  function updateSaveBar() {
    if (!saveBar) return;
    var dirty = !!(S.form && S.form.dirty());
    saveBar.hidden = !dirty;
    root.classList.toggle('has-savebar', dirty);
  }
  function buildSaveBar() {
    var save = P.btn(t('ذخیره'), { kind: 'primary', icon: 'check', write: true, cls: 'pcdn-save-btn', onclick: function () { if (S.form) S.form.save(save); } });
    var cancel = P.btn(t('لغو تغییرات'), { cls: 'pcdn-cancel-btn', onclick: function () { if (S.form) S.form.reset(); } });
    saveBar = h('div', { className: 'pcdn-savebar', role: 'region', 'aria-label': t('ذخیره تغییرات'), hidden: true },
      h('div', { className: 'pcdn-savebar-msg' }, icon('info'), h('span', { text: t('تغییرات ذخیره نشده دارید.') })),
      h('div', { className: 'pcdn-savebar-actions' }, cancel, save));
    return saveBar;
  }
  root.addEventListener('input', function () { updateSaveBar(); });
  root.addEventListener('change', function () { updateSaveBar(); });

  // ------------------------------------------------------------------ shell

  var STATUS = {
    active: [t('فعال'), 'success'], pending_ns: [t('در انتظار تغییر NS'), 'warning'],
    suspended: [t('معلق'), 'danger'], over_quota: [t('اتمام ترافیک'), 'danger']
  };
  function statusPill(st) {
    var m = STATUS[st] || [st || '—', 'muted'];
    return h('span', { className: 'pcdn-pill pcdn-tone-' + m[1] }, h('span', { className: 'pcdn-dot' }), h('span', { text: m[0] }));
  }

  function navItem(id, onPick) {
    var p = page(id), lk = locked(id), cur = S.page === id;
    var extra = null;
    if (id === 'overview' && setupProgress().done < setupProgress().total) extra = h('span', { className: 'pcdn-nav-dot', title: t('راه‌اندازی کامل نشده') });
    if (id === 'dns') extra = h('span', { className: 'pcdn-nav-count', text: num((S.site.records || []).length) });
    return h('a', {
      href: '#pcdn=' + id, className: 'pcdn-nav-item' + (cur ? ' is-active' : '') + (lk ? ' is-locked' : ''), 'data-nav': id,
      'aria-current': cur ? 'page' : null, 'data-ro-ok': '1',
      onclick: function (e) { e.preventDefault(); if (onPick) onPick(); go(id); }
    }, icon(p.icon), h('span', { className: 'pcdn-nav-label', text: p.title }),
    lk ? h('span', { className: 'pcdn-nav-lock', title: t('در پلن شما فعال نیست') }, icon('lock'), h('span', { className: 'pcdn-sr', text: t('(قفل)') })) : extra);
  }
  function navTree(onPick) {
    return NAV.map(function (g) {
      var items = g.items.filter(available);
      return items.length ? h('div', { className: 'pcdn-nav-group' }, h('div', { className: 'pcdn-nav-title', text: g.title }),
        items.map(function (id) { return navItem(id, onPick); })) : null;
    });
  }

  /**
   * Language switch (SPEC §16.10): the app follows the WHMCS client language; this lets one viewer
   * override it (remembered in this browser). Not offered in the admin addon's embed (always Persian).
   */
  function langSwitch() {
    if (!P.i18n || P.i18n.admin) return null;
    var to = P.isEn ? 'fa' : 'en';
    // The target language is named in its own script (فارسی) on the English page.
    var label = t('تغییر زبان به {0}', P.isEn ? 'فارسی (Persian)' : t('انگلیسی'));
    return h('button', { type: 'button', className: 'pcdn-lang-btn', 'data-lang-switch': to, 'data-ro-ok': '1',
      title: label, 'aria-label': label,
      onclick: function () { if (!P.i18n.set(to)) P.toast(t('مرورگر اجازهٔ ذخیرهٔ انتخاب زبان را نمی‌دهد.'), 'error'); } },
      icon('globe'), h('span', { text: to.toUpperCase() }));
  }

  function openMenu() {
    var d = P.dialog({ title: t('بخش‌های CDN'), kind: 'sheet', subtitle: S.site.domain });
    d.el.classList.add('pcdn-menu-sheet');
    append(d.body, h('nav', { className: 'pcdn-nav', 'aria-label': t('بخش‌ها') }, navTree(function () { d.close(true); })));
    var ls = langSwitch();
    if (ls) d.foot.appendChild(ls);
    var cur = d.body.querySelector('.is-active');
    if (cur) cur.focus(); else d.focusFirst();
  }

  var mainEl = null;
  function renderAll() {
    leavePage();
    S.form = null;
    clear(root);
    if (!S.site) { renderFatal(); return; }
    var p = page(S.page);
    var side = h('aside', { className: 'pcdn-side' },
      h('div', { className: 'pcdn-side-head' },
        brandHead(),
        h('div', { className: 'pcdn-side-domain' }, ltr(S.site.domain, 'pcdn-domain'), statusPill(S.site.status))),
      h('nav', { className: 'pcdn-nav', 'aria-label': t('بخش‌های CDN') }, navTree()));
    var mbar = h('div', { className: 'pcdn-mbar' },
      h('button', { type: 'button', className: 'pcdn-mbar-btn', 'aria-label': t('باز کردن منوی بخش‌ها'), 'aria-haspopup': 'dialog', 'data-ro-ok': '1', onclick: openMenu },
        icon('menu'), h('span', { className: 'pcdn-mbar-title' }, icon(p.icon), h('span', { text: p.title })), icon('chevronDown', 'pcdn-mbar-caret')),
      h('div', { className: 'pcdn-mbar-meta' }, ltr(S.site.domain, 'pcdn-domain'), statusPill(S.site.status)));
    mainEl = h('main', { className: 'pcdn-main', 'data-page': S.page });
    append(root, h('div', { className: 'pcdn-shell' }, side, h('div', { className: 'pcdn-col' }, mbar, mainEl)));
    renderMain();
    measure();
  }

  /**
   * App header brand. While a reseller manages one of its sub-sites, the reseller's own white-label name /
   * logo (boot.reseller.brand, set in the reseller panel) replaces «پاسارگاد CDN». The logo is a validated
   * raster data: URI (never SVG) and is only ever set as an <img> src.
   */
  function brandHead() {
    var b = RSITE && RESELLER && RESELLER.brand && typeof RESELLER.brand === 'object' ? RESELLER.brand : null;
    var logo = b && typeof b.logo === 'string' && /^data:image\/(png|jpeg|webp|gif);base64,/.test(b.logo) ? b.logo : null;
    return h('div', { className: 'pcdn-brand' + (b ? ' is-white-label' : ''), 'data-white-label': b ? '1' : null },
      logo ? h('img', { className: 'pcdn-brand-logo', src: logo, alt: '' }) : h('span', { className: 'pcdn-brand-mark' }, icon('cloud')),
      h('span', { className: 'pcdn-brand-name', text: b && b.name ? b.name : t('پاسارگاد CDN') }), langSwitch());
  }
  function refreshBrand() {
    var el = root.querySelector('.pcdn-side .pcdn-brand');
    if (el && el.parentNode) el.parentNode.replaceChild(brandHead(), el);
  }

  function pageHead(p, id) {
    var guideBody = p.guide ? guidePanel(p.guide) : null;
    var tgl = null;
    if (guideBody) {
      var open = P.store('guide-' + id) === '1';
      guideBody.hidden = !open;
      tgl = h('button', { type: 'button', className: 'pcdn-btn pcdn-btn-ghost pcdn-guide-btn', 'aria-expanded': String(open), 'data-ro-ok': '1',
        onclick: function () {
          open = !open;
          guideBody.hidden = !open;
          tgl.setAttribute('aria-expanded', String(open));
          P.store('guide-' + id, open ? '1' : null);
        } }, icon('bulb'), h('span', { text: t('راهنما') }), icon('chevronDown', 'pcdn-caret'));
    }
    return [h('div', { className: 'pcdn-page-head' },
      h('span', { className: 'pcdn-page-icon' }, icon(p.icon)),
      h('div', { className: 'pcdn-page-titles' }, h('h2', { className: 'pcdn-page-title', text: p.heading || p.title }), p.desc ? h('p', { className: 'pcdn-page-desc', text: p.desc }) : null),
      h('div', { className: 'pcdn-page-actions' }, tgl, p.actions && !locked(id) ? p.actions(A) : null)), guideBody];
  }
  function guidePanel(g) {
    function sec(ic, title, content) {
      return content ? h('div', { className: 'pcdn-guide-sec' }, h('h4', null, icon(ic), h('span', { text: title })), content) : null;
    }
    return h('div', { className: 'pcdn-guide', role: 'note' },
      h('div', { className: 'pcdn-guide-grid' },
        sec('info', t('این چیست؟'), g.what ? h('p', { text: g.what }) : null),
        sec('clock', t('چه زمانی؟'), g.when ? h('p', { text: g.when }) : null),
        sec('star', t('مقدار پیشنهادی'), g.rec ? h('p', { text: g.rec }) : null),
        sec('warn', t('اشتباهات رایج'), g.mistakes ? h('ul', null, g.mistakes.map(function (m) { return h('li', { text: m }); })) : null)),
      g.tut ? h('div', { className: 'pcdn-guide-foot' }, tutLink(g.tut, t('مطالعه آموزش کامل'))) : null);
  }

  /** Cleanup callbacks of the page being left (timers of the live analytics etc.). */
  var leaving = [];
  function onLeave(fn) { if (typeof fn === 'function') leaving.push(fn); }
  function leavePage() {
    var fns = leaving;
    leaving = [];
    fns.forEach(function (fn) { try { fn(); } catch (e) { /* a page's cleanup never blocks navigation */ } });
  }

  function readonlyBanner() {
    return h('div', { className: 'pcdn-alert pcdn-alert-info pcdn-ro-banner', role: 'note', 'data-readonly': '1' }, icon('lock'),
      h('div', { className: 'pcdn-alert-body' }, h('strong', { text: t('دسترسی فقط‌خواندنی — ') }),
        t('برای تغییر تنظیمات از مالک حساب بخواهید دسترسی مدیریت محصولات را بدهد.')));
  }

  function renderMain() {
    leavePage();
    clear(mainEl);
    S.form = null;
    var id = S.page, p = page(id);
    var banner = null, adminBar = ADMIN ? adminBanner() : (RSITE ? resellerSubBanner() : null);
    var roBar = SHARE ? shareBanner(id) : READONLY ? readonlyBanner() : null;
    root.classList.toggle('pcdn-ro', roNow());
    var xferBar = TRANSFER && !RSITE ? transferBanner() : null;
    if (!S.active) banner = P.alertBox('warning', [h('strong', { text: t('این سرویس فعال نیست. ') }), t('اطلاعات فقط قابل مشاهده است و امکان تغییر تنظیمات وجود ندارد.')], { icon: 'lock' });
    else if (S.site.status === 'suspended') banner = P.alertBox('danger', t('این سرویس در CDN معلق است و بازدیدکنندگان صفحه تعلیق را می‌بینند.'));
    else if (S.site.status === 'over_quota' && WALLET) banner = P.alertBox('danger', [
      h('strong', { text: t('سرویس قطع است: ترافیک این ماه تمام شده ') + (WALLET.limit_reached ? t('و سقف خرید خودکار این ماه پر شده است. ') : t('و اعتبار کیف پول برای خرید بسته بعدی کافی نیست. ')) }),
      WALLET.limit_reached ? t('برای ادامه تا پایان ماه، پلن را ارتقا دهید یا با پشتیبانی تماس بگیرید. ')
        : (WALLET.needed != null ? t('با شارژ دست‌کم ') + money(WALLET.needed) + t(' یک بسته ') + num(WALLET.block_gb) + t(' گیگابایتی خودکار خریده می‌شود و سایت ظرف چند ثانیه دوباره وصل می‌شود. ') : ''),
      h('div', { className: 'pcdn-banner-actions' }, WALLET.limit_reached ? h('a', { href: UPGRADE_URL, className: 'pcdn-btn pcdn-btn-primary', 'data-ro-ok': '1', text: t('ارتقای پلن') }) : addFundsBtn())], { icon: 'ban' });
    else if (S.site.status === 'over_quota') banner = P.alertBox('danger', [h('strong', { text: t('ترافیک ماهانه تمام شده است. ') }), t('برای ادامه سرویس‌دهی، پلن را ارتقا دهید. '),
      h('a', { href: UPGRADE_URL, className: 'pcdn-link', text: t('ارتقای پلن') })]);
    var trialBar = GROWTH && id !== 'overview' ? GROWTH.trialBanner() : null;
    append(mainEl, [adminBar, roBar, xferBar, banner, trialBar, pageHead(p, id)]);
    var body = h('div', { className: 'pcdn-page', 'data-panel': id });
    mainEl.appendChild(body);
    if (locked(id)) append(body, upgradePanel(p));
    else append(body, p.render(A, body));
    mainEl.appendChild(buildSaveBar());
    lockWrites(mainEl);
    updateSaveBar();
  }

  /** SPEC §20.3: role badge of a shared domain + what this role may do on the current page. */
  function shareBanner(id) {
    var labels = { viewer: t('مشاهده‌گر'), dns: t('مدیر DNS'), editor: t('ویرایشگر') };
    return h('div', { className: 'pcdn-admin-bar pcdn-share-bar', role: 'note', 'data-share-role': String(SHARE.role) },
      h('span', { className: 'pcdn-admin-badge' }, icon('link'), h('span', { text: t('دامنهٔ اشتراکی — نقش: ') + (labels[SHARE.role] || SHARE.role) })),
      h('span', { className: 'pcdn-admin-text', text: (SHARE.owner ? t('مالک: ') + String(SHARE.owner) + '. ' : '') +
        (shareLocked(id) ? t('در این صفحه فقط مشاهده ممکن است.') : t('تغییرات شما با نام شما در گزارش تغییرات مالک ثبت می‌شود.')) }),
      SHARE.back ? h('span', { className: 'pcdn-admin-links' }, h('a', { className: 'pcdn-link', href: String(SHARE.back), 'data-ro-ok': '1', text: t('دامنه‌های اشتراکی') })) : null);
  }

  /** SPEC §19.2: shown to the new owner after a domain transfer, on every page, until «متوجه شدم». */
  function transferBanner() {
    var links = [['apikeys', t('کلید API')], ['webhooks', t('وب‌هوک‌ها')], ['logs', t('ارسال لاگ')]].filter(function (x) { return available(x[0]); })
      .map(function (x) {
        return h('a', { className: 'pcdn-btn pcdn-btn-secondary pcdn-btn-sm', href: '#pcdn=' + x[0], 'data-ro-ok': '1',
          onclick: function (e) { e.preventDefault(); go(x[0]); } }, h('span', { text: x[1] }));
      });
    var dismiss = READONLY ? null : h('button', { type: 'button', className: 'pcdn-btn pcdn-btn-ghost pcdn-btn-sm pcdn-xfer-dismiss', 'data-ro-ok': '1',
      onclick: function () {
        dismiss.disabled = true;
        api('POST', '', {}, { lop: 'transfer' }).then(function (res) {
          if (!res.ok) { dismiss.disabled = false; P.toast((res.data && typeof res.data.detail === 'string' && res.data.detail) || t('ذخیره ممکن نشد؛ دوباره تلاش کنید.'), 'error'); return; }
          TRANSFER = null;
          var bar = mainEl.querySelector('[data-transfer]');
          if (bar && bar.parentNode) bar.parentNode.removeChild(bar);
        });
      } }, h('span', { text: t('متوجه شدم') }));
    return h('div', { className: 'pcdn-alert pcdn-alert-info pcdn-xfer-banner', role: 'note', 'data-transfer': '1' }, icon('info'),
      h('div', { className: 'pcdn-alert-body' },
        h('strong', { text: t('این دامنه به حساب شما منتقل شد — کلید API، وب‌هوک‌ها و ارسال لاگ را دوباره تنظیم کنید') }),
        h('p', { text: t('کلیدهای API مالک قبلی باطل شده‌اند و وب‌هوک‌ها و ارسال لاگ تا تنظیم دوباره با کلیدها و آدرس‌های خودتان متوقف هستند. بقیه تنظیمات، رکوردهای DNS، SSL و آمار سایت بدون تغییر منتقل شده‌اند.') }),
        h('div', { className: 'pcdn-banner-actions' }, links.concat([dismiss]))));
  }

  function adminBanner() {
    var links = [];
    if (ADMIN.serviceUrl) links.push(h('a', { className: 'pcdn-link', href: String(ADMIN.serviceUrl), 'data-ro-ok': '1', text: t('صفحه سرویس در WHMCS') }));
    if (ADMIN.clientUrl) links.push(h('a', { className: 'pcdn-link', href: String(ADMIN.clientUrl), 'data-ro-ok': '1', text: t('پروفایل مشتری') }));
    if (ADMIN.backUrl) links.push(h('a', { className: 'pcdn-link', href: String(ADMIN.backUrl), 'data-ro-ok': '1',
      text: ADMIN.operator ? t('بازگشت به دامنه‌های اپراتور') : t('بازگشت به فهرست سایت‌ها') }));
    // SPEC §19.1: an operator (platform-owned) site — no WHMCS service, no client, never billed
    if (ADMIN.operator) {
      return h('div', { className: 'pcdn-admin-bar', role: 'note', 'data-admin-mode': '1', 'data-operator': '1' },
        h('span', { className: 'pcdn-admin-badge' }, icon('shieldCheck'), h('span', { text: t('حالت مدیر — دامنهٔ اپراتور') })),
        h('span', { className: 'pcdn-admin-text', text: t('سایت اپراتور ') + (S.site && S.site.domain ? S.site.domain : '') +
          (ADMIN.note ? ' — ' + String(ADMIN.note) : '') + t('. بدون سرویس WHMCS و بدون صورت‌حساب؛ تغییرات شما با نام مدیر در گزارش فعالیت WHMCS ثبت می‌شود.') }),
        h('span', { className: 'pcdn-admin-links' }, links));
    }
    return h('div', { className: 'pcdn-admin-bar', role: 'note', 'data-admin-mode': '1' },
      h('span', { className: 'pcdn-admin-badge' }, icon('shieldCheck'), h('span', { text: t('حالت مدیر') })),
      h('span', { className: 'pcdn-admin-text', text: t('سرویس #') + SID + (ADMIN.client ? ' — ' + ADMIN.client : '') +
        (ADMIN.status && ADMIN.status !== 'Active' ? t(' (وضعیت WHMCS: ') + ADMIN.status + ')' : '') + t('. تغییرات شما در گزارش فعالیت WHMCS ثبت می‌شود.') }),
      h('span', { className: 'pcdn-admin-links' }, links));
  }

  // ------------------------------------------------------------------ §10.5 reseller sub-site context

  /** Banner shown while the reseller manages one of their sub-sites, with a way back to the panel. */
  function resellerSubBanner() {
    return h('div', { className: 'pcdn-admin-bar', role: 'note', 'data-reseller-mode': '1' },
      h('span', { className: 'pcdn-admin-badge' }, icon('shieldCheck'), h('span', { text: t('مدیریت زیرسایت نمایندگی') })),
      h('span', { className: 'pcdn-admin-text', text: t('زیرسایت ') + (RSITE && RSITE.domain ? RSITE.domain : '') + (RSITE && RSITE.label ? ' — ' + RSITE.label : '') + t('. این سایت متعلق به مشتری نهایی شماست.') }),
      h('span', { className: 'pcdn-admin-links' },
        h('a', { className: 'pcdn-link', href: '#pcdn=reseller', 'data-ro-ok': '1', onclick: function (e) { e.preventDefault(); exitSubSite(); } }, icon('arrowLeft'), h('span', { text: t('بازگشت به نمایندگی') }))));
  }

  /** Enter a reseller sub-site: point the whole app at it (api calls carry its id). */
  function openSubSite(rsid, meta) {
    P.CFG.rsid = rsid;
    return api('GET', '').then(function (res) {
      if (res.ok && res.data && res.data.domain) {
        S.site = res.data;
        S.error = null;
        S.active = res.data.status !== 'suspended';
        RSITE = { id: rsid, domain: res.data.domain, label: (meta && meta.label) || '' };
        go('overview', '', { keepScroll: true });
      } else {
        P.CFG.rsid = 0;
        if (P.toast) P.toast((res.data && res.data.detail) || t('بارگذاری زیرسایت ناموفق بود.'), 'error');
      }
      return res;
    });
  }

  /** Leave the sub-site and return to the reseller panel (own service context). */
  function exitSubSite() {
    P.CFG.rsid = 0;
    RSITE = null;
    S.site = OWN_SITE;
    S.active = OWN_ACTIVE;
    S.error = OWN_SITE ? null : t('داده اولیه نامعتبر است');
    go('reseller', '', { keepScroll: true });
  }

  function upgradePanel(p) {
    return h('div', { className: 'pcdn-card pcdn-upgrade' },
      h('span', { className: 'pcdn-upgrade-icon' }, icon('lock')),
      h('h3', { text: p.title + t(' در پلن فعلی شما فعال نیست') }),
      h('p', { text: p.upsell || p.desc || '' }),
      p.guide && p.guide.what ? h('p', { className: 'pcdn-muted', text: p.guide.what }) : null,
      p.upsellMore ? p.upsellMore() : null,
      h('div', { className: 'pcdn-row-actions' },
        h('a', { className: 'pcdn-btn pcdn-btn-primary', href: UPGRADE_URL, 'data-ro-ok': '1' }, icon('sparkles'), h('span', { text: t('ارتقای پلن') })),
        p.guide && p.guide.tut ? tutLink(p.guide.tut, t('بیشتر بدانید')) : null));
  }

  function renderFatal() {
    var retry = P.btn(t('تلاش دوباره'), { kind: 'primary', icon: 'refresh', onclick: function () {
      P.busy(retry, reloadSite()).then(function (res) {
        if (res.ok) { renderAll(); P.toast(t('اتصال برقرار شد.')); } else { S.error = P.errorText(res); renderAll(); }
      });
    } });
    append(root, h('div', { className: 'pcdn-fatal pcdn-card' },
      h('span', { className: 'pcdn-empty-icon pcdn-tone-danger' }, icon('warn')),
      h('h3', { text: t('دریافت اطلاعات CDN ممکن نشد') }),
      h('p', { text: S.error ? P.ctlText(S.error) : t('خطای ناشناخته') }),
      h('p', { className: 'pcdn-muted', text: t('ممکن است سرور CDN موقتاً در دسترس نباشد. چند لحظه بعد دوباره تلاش کنید؛ اگر مشکل ادامه داشت با پشتیبانی تماس بگیرید.') }),
      retry));
  }

  // Width classes (the module may sit in a narrow WHMCS column, so measure the container, not the viewport).
  var lastW = { root: 0, main: 0 };
  function measure() {
    var w = root.clientWidth || root.getBoundingClientRect().width;
    root.classList.toggle('pc-sm', w < 820);
    root.classList.toggle('pc-md', w >= 820 && w < 1000);
    var mw = mainEl ? mainEl.clientWidth : w;
    root.classList.toggle('pc-narrow', mw < 660);
    var changed = Math.abs(mw - lastW.main) > 40;
    lastW = { root: w, main: mw };
    return changed;
  }
  var rT = null;
  function onResize() {
    clearTimeout(rT);
    rT = setTimeout(function () {
      if (measure() && page(S.page).onResize) page(S.page).onResize(A);
    }, 150);
  }
  if (window.ResizeObserver) new window.ResizeObserver(onResize).observe(root);
  else window.addEventListener('resize', onResize);

  // ------------------------------------------------------------------ overview

  function setupSteps() {
    var site = S.site, f = features(), recs = site.records || [], cfg = site.config || {};
    var ssl = site.ssl || {}, plan = site.plan || {};
    var steps = [
      { id: 'records', title: t('رکوردهای DNS را وارد کنید'), done: recs.some(function (r) { return r.proxied; }) },
      { id: 'ns', title: t('نیم‌سرورها را تغییر دهید'), done: !!site.ns_verified }
    ];
    if (plan.ssl_allowed || f.custom_ssl) steps.push({ id: 'ssl', title: t('SSL صادر شد'), done: ssl.status === 'active' });
    if (f.waf || f.ddos) {
      steps.push({ id: 'security', title: t('امنیت را فعال کنید'), done: (!!f.waf && (cfg.waf || {}).mode && cfg.waf.mode !== 'off') || (!!f.ddos && (cfg.ddos || {}).mode && cfg.ddos.mode !== 'off') });
    }
    if (f.tunnel) {
      var tn = cfg.tunnel || {};
      steps.push({ id: 'tunnel', title: t('تونل (VPN) را راه‌اندازی کنید'), done: !!tn.enabled && Array.isArray(tn.paths) && tn.paths.length > 0 });
    }
    steps.push({ id: 'realip', title: t('آی‌پی واقعی بازدیدکننده را روی سرور تنظیم کنید'), done: onb().done.indexOf('realip') >= 0 });
    // optional steps the client chose to skip count as handled (and can be brought back)
    var sk = onb().skipped;
    steps.forEach(function (x) { x.skipped = !x.done && SKIPPABLE.indexOf(x.id) >= 0 && sk.indexOf(x.id) >= 0; });
    return steps;
  }
  var SKIPPABLE = ['security', 'tunnel', 'realip'];
  /** Onboarding progress: WHMCS-side per service (growth.js), else this browser. */
  function onb() {
    if (GROWTH) return GROWTH.onboarding();
    return { done: P.store('realip-' + SID) === '1' ? ['realip'] : [], skipped: [], dismissed: false };
  }
  function saveOnb(patch) {
    if (!GROWTH) { if (patch.done) P.store('realip-' + SID, patch.done.indexOf('realip') >= 0 ? '1' : null); return Promise.resolve({ ok: true }); }
    return GROWTH.saveOnboarding(patch).then(function (r) { if (!r.ok) P.toast(P.errorText(r.res), 'error'); return r; });
  }
  function onbToggle(list, id, on) {
    var cur = onb()[list].filter(function (x) { return x !== id; });
    if (on) cur.push(id);
    var patch = {};
    patch[list] = cur;
    return saveOnb(patch);
  }
  function setupProgress() {
    var st = setupSteps();
    return { total: st.length, done: st.filter(function (x) { return x.done || x.skipped; }).length, steps: st };
  }

  /**
   * Live NS check of the first-run guide: while the NS step is current on the overview, the site is re-read
   * every 30 s (at most 20 times; reads only, so read-only members get it too) — the controller checks the
   * delegation by itself; when it flips to verified the guide moves on without a reload.
   */
  var nsPoll = { timer: null, n: 0, last: null };
  function startNsPoll(slot) {
    if (nsPoll.timer || nsPoll.n >= 20 || !S.site || S.site.ns_verified) return;
    nsPoll.timer = setTimeout(function tick() {
      nsPoll.timer = null;
      if (S.page !== 'overview' || !document.body.contains(slot)) return;
      nsPoll.n++;
      api('GET', '').then(function (res) {
        nsPoll.last = new Date();
        if (res.ok && res.data && res.data.ns_verified) {
          S.site = res.data;
          renderAll();
          P.toast(t('نیم‌سرورها تأیید شدند و CDN برای دامنه فعال شد.'));
          return;
        }
        if (res.ok && res.data) S.site.ns_found = res.data.ns_found || S.site.ns_found;
        if (document.body.contains(slot)) {
          slot.textContent = t('بررسی خودکار فعال است · آخرین بررسی: {0}', P.date(nsPoll.last.toISOString(), { timeStyle: 'short' }));
          startNsPoll(slot);
        }
      });
    }, Number(window.PCDN_NS_POLL_MS) > 0 ? Number(window.PCDN_NS_POLL_MS) : 30000);  // test hook: e2e shortens the interval
    onLeave(function () { if (nsPoll.timer) { clearTimeout(nsPoll.timer); nsPoll.timer = null; } });
  }

  function stepBody(st) {
    var site = S.site, f = features(), out = [], acts = [];
    if (st.id === 'records') {
      var recs = site.records || [], px = recs.filter(function (r) { return r.proxied; }).length;
      out.push(h('p', { text: t('پیش از تغییر نیم‌سرورها، همه رکوردهای فعلی دامنه (سایت، ایمیل و زیردامنه‌ها) را اینجا وارد کنید و رکوردهای وب‌سایت (مثل @ و www) را «پروکسی» کنید تا ترافیک از CDN عبور کند.') }));
      out.push(h('p', { className: 'pcdn-muted', text: num(recs.length) + t(' رکورد ثبت شده · ') + num(px) + t(' رکورد پروکسی') }));
      acts.push(P.btn(t('مدیریت رکوردها'), { kind: st.done ? '' : 'primary', icon: 'server', onclick: function () { go('dns'); } }));
      acts.push(P.btn(t('ورود از فایل زون'), { icon: 'upload', cls: 'pcdn-onb-import', onclick: function () {
        go('dns').then(function (ok) {
          var z = ok && root.querySelector('[data-card="zone"]');
          if (z && z.setOpen) { z.setOpen(true); if (z.scrollIntoView) z.scrollIntoView({ block: 'start', behavior: reduced() ? 'auto' : 'smooth' }); }
        });
      } }));
      // Wave 14 (SPEC §23.6): move records + settings from ArvanCloud straight from the onboarding guide
      if (P.importer && P.importer.available()) acts.push(P.importer.button('arvan'));
      acts.push(tutLink('quickstart', t('آموزش شروع سریع')));
    } else if (st.id === 'ns') {
      out.push(h('p', { text: t('در پنل ثبت‌کننده دامنه (برای دامنه‌های ‎.ir سایت nic.ir) نیم‌سرورهای دامنه را دقیقاً به موارد زیر تغییر دهید و نیم‌سرورهای قبلی را حذف کنید:') }));
      out.push(h('div', { className: 'pcdn-ns-list' }, (site.nameservers || []).map(function (ns, i) {
        return h('div', { className: 'pcdn-ns-row' }, h('span', { className: 'pcdn-ns-label', text: t('نیم‌سرور ') + num(i + 1) }), P.copyable(ns, { label: t('کپی ') + ns }));
      })));
      if (!st.done && (site.ns_found || []).length) {
        out.push(h('p', { className: 'pcdn-muted' }, t('نیم‌سرورهای فعلی دامنه: '), ltr((site.ns_found || []).join(t('، ')))));
      }
      if (!st.done) {
        out.push(h('p', { className: 'pcdn-muted', text: t('اعمال تغییر نیم‌سرور معمولاً چند دقیقه تا ۲۴ ساعت (گاهی تا ۴۸ ساعت) طول می‌کشد. سیستم خودکار بررسی می‌کند؛ برای بررسی فوری دکمه زیر را بزنید.') }));
        var chk = P.btn(t('بررسی مجدد'), { kind: 'primary', icon: 'refresh', write: true, cls: 'pcdn-nscheck', onclick: function () {
          P.busy(chk, api('POST', 'ns-check')).then(function (res) {
            if (!res.ok) { P.toast(P.errorText(res), 'error'); return; }
            if (res.data && res.data.ok) {
              reloadSite().then(function () { renderAll(); P.toast(t('نیم‌سرورها تأیید شدند و CDN برای دامنه فعال شد.')); });
            } else {
              S.site.ns_found = (res.data && res.data.found) || S.site.ns_found;
              renderMain();
              P.toast(t('نیم‌سرورها هنوز تغییر نکرده‌اند. اگر تازه تغییر داده‌اید، کمی بعد دوباره بررسی کنید.'), 'warn');
            }
          });
        } });
        acts.push(chk);
        var live = h('p', { className: 'pcdn-muted pcdn-small pcdn-ns-live', 'data-ns-live': '1', text: t('بررسی خودکار فعال است؛ هر ۳۰ ثانیه وضعیت نیم‌سرورها دوباره خوانده می‌شود.') });
        out.push(live);
        startNsPoll(live);
      }
      acts.push(tutLink('quickstart', t('آموزش تغییر نیم‌سرور (ایرنیک و سایر)')));
    } else if (st.id === 'ssl') {
      var ssl = site.ssl || {};
      if (st.done) out.push(h('p', { text: t('گواهی SSL فعال است') + (ssl.expires_at ? t(' و تا ') + P.date(ssl.expires_at, { dateStyle: 'medium' }) + t(' اعتبار دارد (تمدید خودکار).') : '.') }));
      else if (!site.ns_verified) out.push(h('p', { text: t('پس از تأیید نیم‌سرورها، گواهی رایگان برای دامنه و همه زیردامنه‌ها خودکار صادر می‌شود. کاری لازم نیست.') }));
      else if (ssl.status === 'pending') out.push(h('p', { text: t('گواهی در حال صدور است؛ معمولاً کمتر از چند دقیقه طول می‌کشد.') }));
      else if (ssl.status === 'failed') out.push(P.alertBox('danger', [t('صدور گواهی ناموفق بود. '), tutLink('https', t('راهنمای HTTPS'))]));
      else out.push(h('p', { text: t('گواهی هنوز صادر نشده است.') }));
      acts.push(P.btn(t('وضعیت SSL'), { icon: 'lock', onclick: function () { go('ssl'); } }));
    } else if (st.id === 'security') {
      out.push(h('p', { text: t('با یک کلیک، WAF (فایروال برنامه وب) در سطح پیشنهادی و حفاظت DDoS در حالت خودکار روشن می‌شود. بعداً می‌توانید جزئیات را تغییر دهید.') }));
      if (!st.done) {
        var sec = P.btn(t('فعال‌سازی امنیت پیشنهادی'), { kind: 'primary', icon: 'shieldCheck', write: true, onclick: function () {
          var jobs = [];
          if (f.waf) { var w = config('waf'); w.mode = 'block'; w.paranoia = 1; w.groups = ['sqli', 'xss', 'lfi', 'rce', 'php', 'scanner', 'protocol']; jobs.push(putSection('waf', w)); }
          if (f.ddos) { var d = config('ddos'); if (d.mode === 'off') d.mode = 'auto'; jobs.push(putSection('ddos', d)); }
          P.busy(sec, Promise.all(jobs)).then(function (rs) {
            var bad = rs.filter(function (r) { return !r.ok; });
            if (bad.length) P.toast(P.errorText(bad[0]), 'error');
            else P.toast(t('WAF و حفاظت DDoS فعال شد.'));
            renderAll();
          });
        } });
        acts.push(sec);
      }
      if (f.waf) acts.push(P.btn(t('تنظیمات WAF'), { icon: 'shield', onclick: function () { go('waf'); } }));
      acts.push(tutLink('waf', t('درباره WAF')));
    } else if (st.id === 'tunnel') {
      out.push(h('p', { text: t('پلن شما حالت تونل دارد: سرور Xray / V2Ray خود را با gRPC، XHTTP یا WebSocket پشت CDN قرار دهید. یک مسیر مخفی بسازید، تونل را روشن کنید و پیکربندی آماده سرور و کلاینت را کپی کنید.') }));
      acts.push(P.btn(t('تنظیم تونل'), { kind: st.done ? '' : 'primary', icon: 'tunnel', onclick: function () { go('tunnel'); } }));
      acts.push(tutLink('tunnel', t('آموزش راه‌اندازی VPN')));
    } else if (st.id === 'realip') {
      out.push(h('p', { text: t('پشت CDN، سرور شما آی‌پی سرورهای CDN را می‌بیند. با چند خط تنظیم (nginx، Apache، وردپرس و ...) آی‌پی واقعی بازدیدکنندگان در لاگ‌ها و افزونه‌های امنیتی ثبت می‌شود.') }));
      acts.push(P.btn(t('مشاهده آموزش'), { kind: st.done ? '' : 'primary', icon: 'book', onclick: function () { go('help', 'realip'); } }));
      var mark = P.btn(st.done ? t('برگرداندن به انجام‌نشده') : t('انجام دادم'), { icon: st.done ? 'refresh' : 'check', cls: 'pcdn-realip-done', onclick: function () {
        P.busy(mark, onbToggle('done', 'realip', !st.done)).then(function () { renderAll(); });
      } });
      mark.setAttribute('data-ro-ok', '1');
      acts.push(mark);
    }
    if (SKIPPABLE.indexOf(st.id) >= 0 && !st.done) {
      var skip = P.btn(st.skipped ? t('برگرداندن این مرحله') : t('فعلاً رد شود'), { kind: 'ghost', icon: st.skipped ? 'refresh' : 'x', cls: 'pcdn-step-skip', onclick: function () {
        P.busy(skip, onbToggle('skipped', st.id, !st.skipped)).then(function () { renderMain(); });
      } });
      skip.setAttribute('data-ro-ok', '1');
      acts.push(skip);
    }
    return [out, h('div', { className: 'pcdn-row-actions' }, acts)];
  }

  /** The guide was dismissed: a one-line strip that brings it back. */
  function checklistStrip(pr) {
    var show = P.btn(t('نمایش راهنمای راه‌اندازی'), { size: 'sm', icon: 'rocket', cls: 'pcdn-onb-restore', onclick: function () {
      P.busy(show, saveOnb({ dismissed: false })).then(function () { renderMain(); });
    } });
    show.setAttribute('data-ro-ok', '1');
    return h('div', { className: 'pcdn-onb-strip', 'data-card': 'setup', 'data-dismissed': '1' }, icon('rocket'),
      h('span', { text: t('راه‌اندازی: {0} از {1} مرحله انجام شده', num(pr.done), num(pr.total)) }), show);
  }

  function checklist() {
    var pr = setupProgress(), complete = pr.done === pr.total;
    if (!complete && onb().dismissed) return checklistStrip(pr);
    var hide = complete ? null : P.btn(t('بستن راهنما'), { kind: 'ghost', size: 'sm', icon: 'x', cls: 'pcdn-onb-dismiss', onclick: function () {
      P.busy(hide, saveOnb({ dismissed: true })).then(function () { renderMain(); });
    } });
    if (hide) hide.setAttribute('data-ro-ok', '1');
    var c = P.card({ title: complete ? t('راه‌اندازی کامل شد') : t('راه‌اندازی CDN'), icon: complete ? 'checkCircle' : 'rocket', tone: complete ? 'success' : 'brand',
      subtitle: complete ? t('همه مراحل انجام شده است. سایت شما از طریق CDN سرویس می‌گیرد.') : t('این مراحل را به ترتیب انجام دهید تا سایت شما کاملاً از CDN استفاده کند.'),
      cls: 'pcdn-setup' + (complete ? ' is-complete' : ''), id: 'setup',
      actions: complete ? h('button', { type: 'button', className: 'pcdn-btn pcdn-btn-ghost pcdn-btn-sm', 'aria-expanded': String(S.showSetup), 'data-ro-ok': '1',
        onclick: function () { S.showSetup = !S.showSetup; renderMain(); } }, h('span', { text: S.showSetup ? t('پنهان کردن مراحل') : t('نمایش مراحل') }), icon('chevronDown')) : hide });
    append(c.body, h('div', { className: 'pcdn-progress' },
      h('div', { className: 'pcdn-progress-text' }, h('strong', { text: num(pr.done) + t(' از ') + num(pr.total) }), h('span', { text: t(' مرحله انجام شده') })),
      P.meter(pr.done / pr.total, complete ? 'success' : 'brand')));
    if (complete && !S.showSetup) { c.body.classList.add('is-compact'); return c; }
    var current = null;
    pr.steps.forEach(function (st) { if (!current && !st.done && !st.skipped) current = st.id; });
    var list = h('ol', { className: 'pcdn-steps' });
    pr.steps.forEach(function (st, i) {
      var open = st.id === current;
      var bodyId = 'pcdn-step-' + st.id;
      var body = h('div', { className: 'pcdn-step-body', id: bodyId, hidden: !open }, stepBody(st));
      var head = h('button', { type: 'button', className: 'pcdn-step-head', 'aria-expanded': String(open), 'aria-controls': bodyId, 'data-ro-ok': '1',
        onclick: function () {
          var o2 = body.hidden;
          body.hidden = !o2;
          head.setAttribute('aria-expanded', String(o2));
          li.classList.toggle('is-open', o2);
        } },
        h('span', { className: 'pcdn-step-mark' }, st.done ? icon('check') : h('span', { text: num(i + 1) })),
        h('span', { className: 'pcdn-step-title', text: st.title }),
        h('span', { className: 'pcdn-step-state', text: st.done ? t('انجام شد') : st.skipped ? t('رد شد') : st.id === current ? t('مرحله فعلی') : '' }),
        icon('chevronDown', 'pcdn-caret'));
      var li = h('li', { className: 'pcdn-step' + (st.done ? ' is-done' : '') + (st.skipped ? ' is-skipped' : '') + (open ? ' is-open is-current' : ''), 'data-step': st.id }, head, body);
      list.appendChild(li);
    });
    c.body.appendChild(list);
    return c;
  }

  function kpi(ic, tone, label, value, sub, extra, o) {
    o = o || {};
    return h('div', { className: 'pcdn-kpi', 'data-kpi': o.id || null },
      h('div', { className: 'pcdn-kpi-top' }, h('span', { className: 'pcdn-kpi-icon pcdn-tone-' + tone }, icon(ic)), h('span', { className: 'pcdn-kpi-label', text: label })),
      h('div', { className: 'pcdn-kpi-value' }, value),
      sub ? h('div', { className: 'pcdn-kpi-sub' }, sub) : null, extra || null);
  }

  function ensureAnalytics(period) {
    if (S.analytics[period]) return Promise.resolve({ ok: true, data: S.analytics[period] });
    if (S['aload' + period]) return S['aload' + period];
    var pr = api('GET', 'analytics', undefined, { period: period }).then(function (res) {
      S['aload' + period] = null;
      if (res.ok) S.analytics[period] = res.data;
      return res;
    });
    S['aload' + period] = pr;
    return pr;
  }
  P.ensureAnalytics = ensureAnalytics;

  function secTotal(a) {
    var sec = (a && a.totals && a.totals.security) || {};
    return Object.keys(sec).reduce(function (tx, k) { return tx + (Number(sec[k]) || 0); }, 0);
  }

  function modeLabel(kind, mode) {
    var M = {
      waf: { off: [t('خاموش'), 'muted'], detect: [t('فقط ثبت'), 'warning'], block: [t('مسدودسازی'), 'success'] },
      ddos: { off: [t('خاموش'), 'muted'], auto: [t('خودکار'), 'success'], js: [t('زیر حمله (چالش JS)'), 'warning'], captcha: [t('کپچا برای همه'), 'warning'] },
      bots: { off: [t('خاموش'), 'muted'], log: [t('فقط ثبت'), 'warning'], challenge: [t('چالش'), 'success'], block: [t('مسدودسازی'), 'success'] }
    };
    return (M[kind] || {})[mode] || [mode || '—', 'muted'];
  }

  // High-level service-health signal for the client. Derived ONLY from the
  // customer's own site status / over-quota / SSL — no per-edge internals or
  // IPs are exposed here (the client app has no safe per-site edge signal).
  function serviceHealth() {
    var s = S.site, ssl = s.ssl || {}, st = s.status;
    if (st === 'active') {
      if (ssl.status === 'failed') return { key: 'degraded', tone: 'warning', icon: 'clock', label: t('اختلال موقت؛ در حال ترمیم'), note: t('صدور گواهی SSL ناموفق بود؛ سایت روی HTTP در دسترس است و سیستم به‌طور خودکار دوباره تلاش می‌کند.') };
      return { key: 'healthy', tone: 'success', icon: 'checkCircle', label: t('سرویس فعال و سالم'), note: t('دامنه شما از طریق شبکه CDN سرویس می‌گیرد.') };
    }
    if (st === 'over_quota') return { key: 'degraded', tone: 'warning', icon: 'clock', label: t('اختلال موقت؛ در حال ترمیم'), note: t('ترافیک این ماه به سقف رسیده است؛ پس از شارژ کیف پول یا تمدید، سرویس خودکار وصل می‌شود.') };
    if (st === 'suspended') return { key: 'suspended', tone: 'danger', icon: 'ban', label: t('سرویس معلق است'), note: t('برای فعال‌سازی مجدد با پشتیبانی در تماس باشید.') };
    if (st === 'pending_ns') return { key: 'pending', tone: 'muted', icon: 'clock', label: t('در حال راه‌اندازی'), note: t('پس از تغییر نیم‌سرورها، سرویس فعال می‌شود.') };
    return { key: 'unknown', tone: 'muted', icon: 'clock', label: t('در حال بررسی وضعیت'), note: '' };
  }

  function serviceStatus() {
    var hh = serviceHealth();
    return h('div', { className: 'pcdn-svc-status pcdn-tone-' + hh.tone, 'data-svc-health': hh.key, role: 'status' },
      h('span', { className: 'pcdn-svc-dot', 'aria-hidden': 'true' }),
      icon(hh.icon),
      h('div', { className: 'pcdn-svc-text' },
        h('span', { className: 'pcdn-svc-label', text: hh.label }),
        hh.note ? h('span', { className: 'pcdn-svc-note', text: hh.note }) : null));
  }

  // §10.2 dismissible forecast / upgrade suggestion banner (markers set by the prepaid engine).
  function suggestBanner() {
    if (!SUGGEST) return null;
    var key = 'suggest-' + SID + '-' + (SUGGEST.month || '');
    if (P.store(key) === '1') return null;
    var lines = [];
    if (SUGGEST.forecast) lines.push(h('p', { text: t('طبق روند مصرف، پیش‌بینی می‌شود ترافیک این ماه زودتر از پایان ماه تمام شود. برای جلوگیری از قطعی، اعتبار کیف پول را شارژ کنید یا پلن بزرگ‌تری بگیرید.') }));
    if (SUGGEST.upgrade) lines.push(h('p', { text: t('مصرف شما به‌طور مداوم از ترافیک پلن فراتر رفته است. یک پلن بزرگ‌تر معمولاً ارزان‌تر از خرید بسته‌های ترافیک اضافه تمام می‌شود.') }));
    var dismiss = h('button', { type: 'button', className: 'pcdn-btn pcdn-btn-ghost pcdn-btn-sm pcdn-suggest-dismiss', 'aria-label': t('بستن پیشنهاد'), 'data-ro-ok': '1',
      onclick: function () { P.store(key, '1'); var b = document.querySelector('[data-suggest]'); if (b && b.parentNode) b.parentNode.removeChild(b); } }, icon('x'), h('span', { text: t('بستن') }));
    return h('div', { className: 'pcdn-alert pcdn-alert-warning pcdn-suggest', role: 'note', 'data-suggest': SUGGEST.upgrade ? 'upgrade' : 'forecast' },
      icon('sparkles'),
      h('div', { className: 'pcdn-alert-body' },
        h('strong', { text: SUGGEST.upgrade ? t('پیشنهاد ارتقای پلن') : t('پیش‌بینی اتمام ترافیک') }),
        lines,
        h('div', { className: 'pcdn-banner-actions' },
          h('a', { className: 'pcdn-btn pcdn-btn-primary pcdn-btn-sm pcdn-suggest-upgrade', href: UPGRADE_URL, 'data-ro-ok': '1' }, icon('sparkles'), h('span', { text: t('مشاهده پلن‌ها') })),
          goLink('usage', t('مصرف زنده')),
          dismiss)));
  }

  function renderOverview() {
    var site = S.site, f = features(), plan = site.plan || {}, u = site.usage_month || {}, ssl = site.ssl || {}, cfg = site.config || {};
    var out = [];

    // hero
    var spark = h('div', { className: 'pcdn-hero-spark' }, P.skeleton(2));
    var hero = h('section', { className: 'pcdn-card pcdn-hero' },
      h('div', { className: 'pcdn-hero-main' },
        h('div', { className: 'pcdn-hero-title' }, h('span', { className: 'pcdn-hero-icon' }, icon('globe')),
          h('div', null, h('h3', null, ltr(site.domain, 'pcdn-domain')), statusPill(site.status))),
        h('ul', { className: 'pcdn-hero-facts' },
          h('li', { className: site.ns_verified ? 'is-ok' : 'is-warn' }, icon(site.ns_verified ? 'checkCircle' : 'clock'),
            h('span', { text: site.ns_verified ? t('نیم‌سرورها متصل‌اند') : t('در انتظار تغییر نیم‌سرورها') })),
          h('li', { className: ssl.status === 'active' ? 'is-ok' : ssl.status === 'failed' ? 'is-bad' : 'is-warn' }, icon(ssl.status === 'active' ? 'lock' : 'unlock'),
            h('span', { text: ssl.status === 'active' ? t('SSL فعال') + (ssl.expires_at ? t(' تا ') + P.date(ssl.expires_at, { dateStyle: 'medium' }) : '') : ssl.status === 'pending' ? t('SSL در حال صدور') : ssl.status === 'failed' ? t('صدور SSL ناموفق') : t('SSL هنوز صادر نشده') })),
          h('li', { className: 'is-ok' }, icon('server'), h('span', { text: num((site.records || []).length) + t(' رکورد DNS') }))),
        serviceStatus(),
        h('a', { className: 'pcdn-link', href: 'https://' + site.domain + '/', target: '_blank', rel: 'noopener noreferrer', 'data-ro-ok': '1' },
          h('span', { text: t('باز کردن سایت') }), icon('external'))),
      spark);
    out.push(hero);
    var trial = GROWTH ? GROWTH.trialCard() : null;
    if (trial) out.push(trial);

    var hint = h('div', { className: 'pcdn-hint-slot' });
    var sug = suggestBanner();
    if (sug) hint.appendChild(sug);
    out.push(hint);

    var pr = setupProgress();
    out.push(checklist());

    // KPIs
    var cap = Number(plan.bandwidth_limit_gb) || 0, usedGb = (Number(u.bytes) || 0) / 1073741824;
    var limit = WALLET ? Number(WALLET.cap_gb) : BILL ? Number(BILL.included_gb) : cap;
    var ratio = limit > 0 ? usedGb / limit : 0;
    var trafficSub = limit > 0 ? t('از ') + num(limit) + t(' گیگابایت (') + P.pct(usedGb, limit) + ')' : t('بدون محدودیت ترافیک');
    if (WALLET && Number(WALLET.bought_gb) > 0) trafficSub = t('از ') + num(limit) + t(' گیگابایت (') + num(WALLET.plan_gb) + t(' پلن + ') + num(WALLET.bought_gb) + t(' خریداری‌شده)');
    if (BILL && usedGb > limit) trafficSub = num(Math.ceil((usedGb - limit) * 10) / 10) + t(' گیگابایت بیش از ترافیک پلن (با هزینه ترافیک اضافه)');
    var threatVal = h('span', null, P.skeleton(1, 'is-inline'));
    var reqs = Number(u.requests) || 0, hits = Number(u.cache_hits) || 0;
    out.push(h('div', { className: 'pcdn-kpis' },
      kpi('activity', 'brand', t('ترافیک این ماه'), P.bytes(u.bytes), trafficSub,
        limit > 0 ? P.meter(Math.min(ratio, 1), WALLET ? (S.site.status === 'over_quota' ? 'danger' : Number(WALLET.more_gb) > 0 ? 'brand' : ratio >= 0.9 ? 'warning' : 'brand')
          : BILL ? (ratio >= 1 ? 'warning' : 'brand') : ratio >= 0.95 ? 'danger' : ratio >= 0.8 ? 'warning' : 'brand') : null, { id: 'traffic' }),
      kpi('chart', 'violet', t('درخواست‌های این ماه'), num(reqs), t('حدود ') + P.short(reqs) + t(' درخواست'), null, { id: 'requests' }),
      kpi('zap', 'success', t('نرخ کش'), P.pct(hits, reqs), t('پاسخ مستقیم از سرورهای CDN'), reqs ? P.meter(hits / reqs, 'success') : null, { id: 'cache' }),
      kpi('shieldCheck', 'danger', t('تهدیدهای متوقف‌شده'), threatVal, t('در ۲۴ ساعت گذشته'), goLink('events', t('مشاهده رویدادها')), { id: 'threats' })));

    if (WALLET) out.push(walletCard(usedGb));

    // quick actions + security summary
    out.push(h('div', { className: 'pcdn-grid-2' }, quickActions(), h('div', { className: 'pcdn-stack' }, securitySummary(), planSummary())));
    // Wave 14 (SPEC §23.8): «ارسال گزارش عیب‌یابی به پشتیبانی» (diag.js; shown once the wave-14 probe answered)
    if (P.diag && P.diag.card) out.push(P.diag.card());

    ensureAnalytics('24h').then(function (res) {
      if (S.page !== 'overview' || !document.body.contains(spark)) return;
      clear(spark);
      clear(threatVal);
      if (!res.ok) { spark.appendChild(h('p', { className: 'pcdn-muted', text: t('آمار ۲۴ ساعت گذشته در دسترس نیست.') })); threatVal.textContent = '—'; return; }
      var a = res.data, series = a.series || [], tx = a.totals || {};
      threatVal.textContent = num(secTotal(a));
      append(spark, [h('div', { className: 'pcdn-spark-head' }, h('span', { text: t('درخواست‌ها در ۲۴ ساعت گذشته') }), h('strong', { text: P.short(tx.requests) })),
        series.length ? P.sparkline(series.map(function (p) { return Number(p.requests) || 0; })) : h('p', { className: 'pcdn-muted', text: t('هنوز داده‌ای ثبت نشده است.') }),
        goLink('analytics', t('آنالیتیکس کامل'))]);
      var st = tx.status || {}, total = Number(tx.requests) || 0, e5 = Number(st['5xx']) || 0;
      if (total >= 100 && e5 / total >= 0.02) {
        hint.appendChild(P.alertBox('warning', [h('strong', { text: t('خطاهای سرور (5xx) بالاست: ') }),
          P.pct(e5, total) + t(' از درخواست‌های ۲۴ ساعت گذشته با خطای ۵۰۲/۵۰۴ و مشابه پاسخ گرفته‌اند. معمولاً یعنی سرور اصلی در دسترس نیست، پورت یا پروتکل اشتباه است یا فایروال سرور آی‌پی‌های CDN را مسدود کرده. '),
          tutLink('troubleshoot', t('راهنمای عیب‌یابی ۵۰۲ / ۵۰۴'))], { icon: 'warn' }));
      }
    });
    // §10.3 forecast line on the overview: computed client-side from the daily series.
    if (limit > 0 && P.usageForecastLine) {
      ensureAnalytics('7d').then(function (res) {
        if (S.page !== 'overview' || !res.ok) return;
        var line = P.usageForecastLine((res.data && res.data.series) || [], usedGb, limit);
        var kpi = root.querySelector('[data-kpi="traffic"]');
        if (line && kpi && !kpi.querySelector('[data-forecast]')) {
          kpi.appendChild(h('div', { className: 'pcdn-kpi-forecast', 'data-forecast': '1' }, icon('activity'), h('span', { text: line })));
        }
      });
    }
    return out;
  }

  function quickActions() {
    var site = S.site, f = features(), ssl = site.ssl || {};
    var c = P.card({ title: t('اقدامات سریع'), icon: 'zap', id: 'quick' });
    function row(ic, tone, title, desc, control, o) {
      o = o || {};
      return h('div', { className: 'pcdn-qa' + (o.cls ? ' ' + o.cls : ''), 'data-qa': o.id || null },
        h('span', { className: 'pcdn-qa-icon pcdn-tone-' + tone }, icon(ic)),
        h('div', { className: 'pcdn-qa-text' }, h('span', { className: 'pcdn-qa-title', id: o.id ? 'pcdn-qa-' + o.id : null, text: title }), h('span', { className: 'pcdn-qa-desc', text: desc })),
        h('div', { className: 'pcdn-qa-ctl' }, control));
    }
    function sw(checked, labelId, fn) {
      var x = P.switchInput(checked, '', function (v, el) { el.disabled = true; fn(v, el); }, { write: true });
      x.removeAttribute('aria-label');
      x.setAttribute('aria-labelledby', labelId);
      return x;
    }
    function done(el, res, okMsg, prev) {
      el.disabled = false;
      if (!res.ok) { el.checked = prev; P.toast(P.errorText(res), 'error'); return; }
      P.toast(okMsg);
      renderMain();
    }
    var purge = P.btn(t('پاکسازی'), { icon: 'refresh', write: true, cls: 'pcdn-purge-all', onclick: function () {
      P.confirm({ title: t('پاکسازی کامل کش'), ok: t('پاکسازی کامل'), danger: true,
        body: t('همه فایل‌های کش‌شده این دامنه روی همه سرورهای CDN حذف می‌شوند. تا کش دوباره پر شود، سرور اصلی شما بار بیشتری دریافت می‌کند. ادامه می‌دهید؟') })
        .then(function (ok) {
          if (!ok) return;
          P.busy(purge, api('POST', 'purge', { urls: [] })).then(function (res) {
            P.toast(res.ok ? t('پاکسازی کامل کش ثبت شد و تا چند ثانیه روی همه سرورها اعمال می‌شود.') : P.errorText(res), res.ok ? 'success' : 'error');
          });
        });
    } });
    var cache = config('cache');
    var rows = [
      row('refresh', 'brand', t('پاکسازی کامل کش'), t('بعد از به‌روزرسانی سایت، نسخه‌های قدیمی را از کش حذف کنید.'), purge, { id: 'purge' }),
      row('tool', 'violet', t('حالت توسعه'), cache.dev_mode ? t('روشن است: کش موقتاً خاموش است. بعد از پایان کار خاموشش کنید.') : t('کش را موقتاً خاموش می‌کند تا تغییرات سایت فوراً دیده شوند.'),
        sw(cache.dev_mode, 'pcdn-qa-dev', function (v, el) {
          var body = config('cache'); body.dev_mode = v;
          putSection('cache', body).then(function (res) { done(el, res, v ? t('حالت توسعه روشن شد؛ کش موقتاً غیرفعال است.') : t('حالت توسعه خاموش شد.'), !v); });
        }), { id: 'dev', cls: cache.dev_mode ? 'is-on' : '' })
    ];
    if (f.ddos) {
      var dd = config('ddos'), attack = dd.mode === 'js';
      rows.push(row('shieldBolt', 'danger', t('حالت زیر حمله'), attack ? t('روشن است: همه بازدیدکنندگان یک چالش کوتاه می‌بینند.') : t('در زمان حمله روشن کنید؛ همه بازدیدکنندگان پیش از ورود یک چالش کوتاه JS می‌بینند.'),
        sw(attack, 'pcdn-qa-attack', function (v, el) {
          var body = config('ddos');
          if (v) { P.store('prevddos-' + SID, body.mode === 'js' ? 'off' : body.mode); body.mode = 'js'; }
          else { var prev = P.store('prevddos-' + SID); body.mode = prev && prev !== 'js' && /^(off|auto|captcha)$/.test(prev) ? prev : 'off'; P.store('prevddos-' + SID, null); }
          putSection('ddos', body).then(function (res) {
            done(el, res, v ? t('حالت زیر حمله روشن شد. پس از پایان حمله خاموشش کنید.') : t('حالت زیر حمله خاموش شد (حالت قبلی: ') + modeLabel('ddos', body.mode)[0] + ').', !v);
          });
        }), { id: 'attack', cls: attack ? 'is-on is-alert' : '' }));
    } else {
      rows.push(row('shieldBolt', 'muted', t('حالت زیر حمله'), t('حفاظت DDoS در پلن شما فعال نیست.'), h('a', { href: UPGRADE_URL, className: 'pcdn-link', 'data-ro-ok': '1' }, icon('lock'), h('span', { text: t('ارتقا') })), { id: 'attack' }));
    }
    var sslc = config('ssl'), certOk = ssl.status === 'active';
    rows.push(row('lock', 'success', t('HTTPS اجباری'), certOk ? t('همه بازدیدهای HTTP به HTTPS منتقل می‌شوند.') : t('پس از فعال شدن گواهی SSL در دسترس است.'),
      certOk ? sw(sslc.force_https, 'pcdn-qa-https', function (v, el) {
        var body = config('ssl'); body.force_https = v;
        putSection('ssl', body).then(function (res) { done(el, res, v ? t('HTTPS اجباری روشن شد.') : t('HTTPS اجباری خاموش شد.'), !v); });
      }) : P.badge(t('بدون گواهی'), 'muted'), { id: 'https', cls: certOk && sslc.force_https ? 'is-on' : '' }));
    append(c.body, h('div', { className: 'pcdn-qas' }, rows));
    return c;
  }

  function securitySummary() {
    var f = features(), cfg = S.site.config || {};
    var c = P.card({ title: t('وضعیت امنیت'), icon: 'shield', id: 'security' });
    function chip(id, label, value, tone) {
      return h('a', { href: '#pcdn=' + id, className: 'pcdn-schip', 'data-ro-ok': '1', onclick: function (e) { e.preventDefault(); go(id); } },
        h('span', { className: 'pcdn-schip-label', text: label }), h('span', { className: 'pcdn-pill pcdn-tone-' + tone }, h('span', { className: 'pcdn-dot' }), h('span', { text: value })));
    }
    var fw = (cfg.firewall || {}).rules || [], rl = (cfg.ratelimit || {}).rules || [], ssl = cfg.ssl || {};
    var w = modeLabel('waf', (cfg.waf || {}).mode || 'off'), d = modeLabel('ddos', (cfg.ddos || {}).mode || 'off');
    append(c.body, h('div', { className: 'pcdn-schips' },
      f.waf ? chip('waf', 'WAF', w[0], w[1]) : chip('waf', 'WAF', t('در پلن نیست'), 'muted'),
      f.ddos ? chip('ddos', t('حفاظت DDoS'), d[0], d[1]) : chip('ddos', t('حفاظت DDoS'), t('در پلن نیست'), 'muted'),
      cfg.bots && typeof cfg.bots === 'object' ? (function (b) { return chip('bots', t('مدیریت ربات‌ها'), b[0], b[1]); })(modeLabel('bots', cfg.bots.mode || 'off')) : null,
      chip('firewall', t('قوانین فایروال'), fw.length ? num(fw.filter(function (r) { return r.enabled; }).length) + t(' قانون فعال') : t('بدون قانون'), fw.length ? 'success' : 'muted'),
      chip('ratelimit', t('محدودیت نرخ'), rl.length ? num(rl.length) + t(' قانون') : t('بدون قانون'), rl.length ? 'success' : 'muted'),
      chip('ssl', t('HTTPS اجباری'), ssl.force_https ? t('روشن') : t('خاموش'), ssl.force_https ? 'success' : 'muted'),
      chip('ssl', 'HSTS', ssl.hsts && ssl.hsts.enabled ? t('روشن') : t('خاموش'), ssl.hsts && ssl.hsts.enabled ? 'success' : 'muted')));
    return c;
  }

  function walletCard(usedGb) {
    var w = WALLET, cut = S.site.status === 'over_quota';
    var c = P.card({ title: t('کیف پول و ترافیک'), icon: 'wallet', id: 'wallet', tone: cut ? 'danger' : 'brand', actions: addFundsBtn(cut ? 'primary' : 'ghost') });
    var proj;
    if (w.limit_reached) proj = P.alertBox('warning', t('سقف خرید خودکار ترافیک این ماه پر شده است؛ پس از اتمام ترافیک فعلی، سرویس تا ماه بعد قطع می‌شود مگر اینکه پلن را ارتقا دهید.'));
    else if (w.block_price == null) proj = P.alertBox('info', t('خرید ترافیک اضافه برای این سرویس هنوز قیمت‌گذاری نشده است. با پشتیبانی تماس بگیرید.'));
    else if (Number(w.more_gb) > 0) proj = P.alertBox('success', t('با اعتبار فعلی، پس از اتمام ترافیک تا حدود ') + num(w.more_gb) + t(' گیگابایت دیگر ادامه می‌یابد (تا حدود ') + num(Number(w.cap_gb) + Number(w.more_gb)) + t(' گیگابایت در این ماه).'));
    else proj = P.alertBox(cut ? 'danger' : 'warning', (cut ? t('سرویس قطع است. ') : t('با اعتبار فعلی، پس از اتمام ') + num(w.cap_gb) + t(' گیگابایت سرویس قطع می‌شود. ')) +
      t('برای خرید بسته بعدی دست‌کم ') + money(w.needed) + t(' شارژ کنید.'));
    append(c.body, [
      h('dl', { className: 'pcdn-dl' },
        h('div', { 'data-w': 'credit' }, h('dt', { text: t('اعتبار کیف پول') }), h('dd', { className: Number(w.credit) > 0 ? '' : 'pcdn-text-danger', text: money(w.credit) })),
        h('div', null, h('dt', { text: t('ترافیک پلن') }), h('dd', { text: num(w.plan_gb) + t(' گیگابایت') })),
        h('div', { 'data-w': 'bought' }, h('dt', { text: t('خریداری‌شده این ماه') }), h('dd', { text: num(Math.max(0, Number(w.bought_gb) - (Number(w.addon_gb) || 0))) + t(' گیگابایت') })),
        // §15.7 «بسته‌ی ترافیک افزوده» add-ons paid this month (part of the cap, not of the wallet blocks)
        Number(w.addon_gb) > 0 ? h('div', { 'data-w': 'addon' }, h('dt', { text: t('بسته‌ی ترافیک افزوده') }), h('dd', { text: num(w.addon_gb) + t(' گیگابایت') })) : null,
        h('div', null, h('dt', { text: t('مصرف / سقف فعلی') }), h('dd', { text: P.num1(usedGb) + t(' از ') + num(w.cap_gb) + t(' گیگابایت') })),
        h('div', null, h('dt', { text: t('بسته ترافیک') }), h('dd', { text: num(w.block_gb) + t(' گیگابایت') + (w.block_price != null ? ' — ' + money(w.block_price) : '') }))),
      h('div', { 'data-w': 'projection' }, proj),
      h('p', { className: 'pcdn-muted pcdn-small', text: t('پس از اتمام ترافیک پلن، بسته‌ها خودکار از اعتبار کیف پول خریده می‌شوند و فاکتورشان با همان اعتبار پرداخت می‌شود. اگر اعتبار کافی نباشد سرویس قطع و پس از شارژ کیف پول ظرف چند ثانیه دوباره وصل می‌شود. ترافیک پلن ابتدای هر ماه از نو شروع می‌شود.') })
    ]);
    return c;
  }

  function planSummary() {
    var plan = S.site.plan || {}, f = features();
    var c = P.card({ title: t('پلن شما'), icon: 'star', id: 'plan', actions: h('a', { className: 'pcdn-btn pcdn-btn-sm pcdn-btn-ghost', href: UPGRADE_URL, 'data-ro-ok': '1' }, icon('sparkles'), h('span', { text: t('ارتقا') })) });
    function feat(on, label) { return h('span', { className: 'pcdn-feat' + (on ? ' is-on' : '') }, icon(on ? 'check' : 'lock'), h('span', { text: label })); }
    append(c.body, [
      h('dl', { className: 'pcdn-dl' },
        h('div', null, h('dt', { text: t('ترافیک ماهانه') }), h('dd', { text: WALLET ? num(WALLET.plan_gb) + t(' گیگابایت + بسته‌های پیش‌پرداخت') : BILL ? num(BILL.included_gb) + t(' گیگابایت') : plan.bandwidth_limit_gb ? num(plan.bandwidth_limit_gb) + t(' گیگابایت') : t('نامحدود') })),
        BILL ? h('div', { 'data-billing': '1' }, h('dt', { text: t('ترافیک اضافه') }), h('dd', { text: (Number(BILL.price_per_gb) > 0 ? t('هر گیگابایت ') + num(BILL.price_per_gb) + (BILL.currency ? ' ' + BILL.currency : '') : t('طبق تعرفه')) +
          (plan.bandwidth_limit_gb ? t(' — حداکثر تا ') + num(plan.bandwidth_limit_gb) + t(' گیگابایت') : '') })) : null,
        h('div', null, h('dt', { text: t('رکوردهای DNS') }), h('dd', { text: num((S.site.records || []).length) + t(' از ') + num(plan.max_records) })),
        h('div', null, h('dt', { text: t('قوانین فایروال / صفحه / نرخ') }), h('dd', { text: num(f.max_firewall_rules || 0) + ' / ' + num(f.max_page_rules || 0) + ' / ' + num(f.max_ratelimit_rules || 0) }))),
      h('div', { className: 'pcdn-feats' },
        feat(plan.ssl_allowed, t('SSL رایگان')), feat(f.waf, 'WAF'), feat(f.ddos, 'DDoS'), feat(f.load_balancer && f.max_pools > 0, t('توزیع بار')),
        feat(f.image_optimization, t('بهینه‌سازی تصویر')), feat(f.custom_ssl, t('گواهی اختصاصی')), feat(f.dnssec, 'DNSSEC'), feat(f.tunnel, t('تونل / VPN')))
    ]);
    return c;
  }

  // ------------------------------------------------------------------ DNS

  var TYPES = ['A', 'AAAA', 'CNAME', 'ALIAS', 'MX', 'TXT', 'SRV', 'CAA', 'NS'];
  var PROXYABLE = { A: 1, AAAA: 1, CNAME: 1 };
  var TYPE_INFO = {
    A: [t('آدرس IPv4'), '185.1.2.3', t('نام را به آی‌پی نسخه ۴ سرور وصل می‌کند.')],
    AAAA: [t('آدرس IPv6'), '2001:db8::1', t('نام را به آی‌پی نسخه ۶ سرور وصل می‌کند.')],
    CNAME: [t('نام مقصد'), 'target.example.net', t('این نام، نام مستعار نام دیگری است (روی @ مجاز نیست).')],
    ALIAS: [t('نام مقصد'), 'target.example.net', t('مثل CNAME ولی روی ریشه دامنه (@) هم مجاز است؛ بدون پروکسی.')],
    MX: [t('سرور ایمیل'), 'mail.example.com', t('مشخص می‌کند ایمیل‌های دامنه به کدام سرور تحویل شوند.')],
    TXT: [t('متن'), 'v=spf1 include:example.com ~all', t('برای SPF، DKIM، DMARC و تأیید مالکیت دامنه در سرویس‌ها.')],
    SRV: [t('وزن، پورت و مقصد'), '10 5060 sip.example.com', t('آدرس سرویس‌های خاص (مثل SIP یا XMPP).')],
    CAA: [t('مقدار CAA'), '0 issue "letsencrypt.org"', t('مشخص می‌کند کدام مراکز صدور گواهی مجازند.')],
    NS: [t('نیم‌سرور'), 'ns1.other-dns.com', t('واگذاری یک زیردامنه به نیم‌سرور دیگر.')]
  };
  var MAILISH = /^(mail|smtp|imap|pop|pop3|webmail|autodiscover|autoconfig|mx|cpanel|whm|ftp|ssh|direct)(\d*)$/i;
  var TTLS = [[60, t('۱ دقیقه')], [300, t('۵ دقیقه (پیشنهادی)')], [1800, t('۳۰ دقیقه')], [3600, t('۱ ساعت')], [14400, t('۴ ساعت')], [86400, t('۱ روز')]];

  function recordBody(r) {
    var proxied = !!PROXYABLE[r.type] && !!r.proxied;
    var hc = !proxied && (r.type === 'A' || r.type === 'AAAA') && !!r.health_check;
    var b = {
      name: String(r.name || '@').trim() || '@', type: r.type, content: String(r.content || '').trim(),
      ttl: Number(r.ttl) || 300,
      priority: (r.type === 'MX' || r.type === 'SRV') && r.priority !== null && r.priority !== undefined && r.priority !== '' ? Number(r.priority) : null,
      proxied: proxied,
      pool: proxied && r.pool ? r.pool : null,
      origin_port: proxied && !r.pool && r.origin_port ? Number(r.origin_port) : null,
      health_check: hc,
      health_port: hc && r.health_port ? Number(r.health_port) : null
    };
    // SPEC §16.8: a proxied record served from one of the site's storage buckets (`storage`, sent only when set).
    if (P.storage) b = P.storage.recordBodyExtra(r, b);
    // Wave 8 (SPEC §16.7): weight + health check (type/path) on non-proxied A/AAAA/CNAME — only for a controller that knows them.
    return P.w8 ? P.w8.recordBodyExtra(r, b) : b;
  }
  function fqdn(name) { return !name || name === '@' ? S.site.domain : name + '.' + S.site.domain; }
  function typeBadge(tx) { return h('span', { className: 'pcdn-type pcdn-type-' + String(tx).toLowerCase(), text: tx }); }
  function ttlText(tx) {
    for (var i = 0; i < TTLS.length; i++) if (TTLS[i][0] === Number(tx)) return TTLS[i][1].replace(t(' (پیشنهادی)'), '');
    return P.dur(tx);
  }

  function renderDns() {
    var site = S.site, recs = site.records || [], max = (site.plan || {}).max_records || 0;
    var out = [];
    // Wave 8 (SPEC §16.7): the zone is transferred from the customer's own primary — these records are not served.
    if (P.w8 && P.w8.secondaryMode()) {
      out.push(P.alertBox('warning', [h('strong', { text: t('DNS اصلی این دامنه جای دیگری است. ') }),
        t('زون با انتقال (AXFR) از سرور DNS شما کپی می‌شود و رکوردهای این صفحه پاسخ داده نمی‌شوند. '), goLink('secondary', t('تنظیمات DNS ثانویه'))], { icon: 'swap' }));
    }
    var proxiedCount = recs.filter(function (r) { return r.proxied; }).length;
    var mailProxied = recs.filter(function (r) { return r.proxied && MAILISH.test(String(r.name || '').split('.')[0]); });
    if (recs.length && !proxiedCount) {
      out.push(P.alertBox('info', [t('هیچ رکوردی پروکسی نشده است؛ تا وقتی پروکسی رکوردهای وب‌سایت (مثل @ و www) را روشن نکنید، ترافیک از CDN عبور نمی‌کند و کش و امنیت اعمال نمی‌شود.')]));
    }
    if (mailProxied.length) {
      out.push(P.alertBox('warning', [h('strong', { text: t('رکورد ایمیل پروکسی شده است: ') }), ltr(mailProxied.map(function (r) { return fqdn(r.name); }).join(t('، '))),
        t(' — CDN فقط ترافیک وب را عبور می‌دهد؛ برای کار کردن ایمیل (SMTP/IMAP) و FTP، پروکسی این رکوردها را خاموش کنید. '), tutLink('troubleshoot', t('بیشتر بدانید'))]));
    }

    var c = P.card({ title: t('رکوردها'), icon: 'server', id: 'records',
      subtitle: num(recs.length) + t(' از ') + num(max) + t(' رکورد مجاز پلن') });
    var search = h('div', { className: 'pcdn-search' }, icon('search'),
      h('input', { type: 'search', className: 'pcdn-input', placeholder: t('جستجو در نام یا مقدار…'), 'aria-label': t('جستجوی رکوردها'), value: S.dns.q, 'data-ro-ok': '1',
        oninput: function (e) { S.dns.q = e.target.value; drawList(); } }));
    var typesPresent = TYPES.filter(function (tx) { return recs.some(function (r) { return r.type === tx; }); });
    var chips = h('div', { className: 'pcdn-filter-chips', role: 'group', 'aria-label': t('فیلتر نوع رکورد') });
    function drawChips() {
      clear(chips);
      [''].concat(typesPresent).forEach(function (tx) {
        var n = tx ? recs.filter(function (r) { return r.type === tx; }).length : recs.length;
        chips.appendChild(h('button', { type: 'button', className: 'pcdn-fchip' + (S.dns.type === tx ? ' is-active' : ''), 'aria-pressed': String(S.dns.type === tx), 'data-type': tx || 'all', 'data-ro-ok': '1',
          onclick: function () { S.dns.type = tx; drawChips(); drawList(); } }, h('span', { text: tx || t('همه') }), h('span', { className: 'pcdn-fchip-n', text: num(n) })));
      });
    }
    drawChips();
    append(c.body, [h('div', { className: 'pcdn-toolbar' }, search, chips),
      h('div', { className: 'pcdn-legend-line' },
        h('span', { className: 'pcdn-legend-pair' }, h('span', { className: 'pcdn-proxy-demo is-on' }, icon('cloud')), h('span', null, h('b', { text: t('پروکسی: ') }), t('ترافیک از CDN عبور می‌کند و آی‌پی سرور مخفی می‌ماند.'))),
        h('span', { className: 'pcdn-legend-pair' }, h('span', { className: 'pcdn-proxy-demo' }, icon('cloud')), h('span', null, h('b', { text: t('فقط DNS: ') }), t('فقط نام به آدرس ترجمه می‌شود (برای ایمیل و FTP).'))))]);
    var list = h('div', { className: 'pcdn-records' });
    c.body.appendChild(list);

    function drawList() {
      clear(list);
      var q = P.norm(S.dns.q.trim());
      var rows = (S.site.records || []).filter(function (r) {
        if (S.dns.type && r.type !== S.dns.type) return false;
        if (!q) return true;
        return P.norm(r.name + ' ' + fqdn(r.name) + ' ' + r.content + ' ' + r.type).indexOf(q) >= 0;
      });
      if (!(S.site.records || []).length) {
        list.appendChild(P.empty('server', t('هنوز رکوردی ثبت نشده است'), t('رکوردهای فعلی دامنه را وارد کنید یا فایل زون را از بخش «ورود و خروج زون» بارگذاری کنید.'),
          P.btn(t('افزودن اولین رکورد'), { kind: 'primary', icon: 'plus', write: true, onclick: function () { recordModal(null); } })));
        lockWrites(list);
        return;
      }
      if (!rows.length) {
        list.appendChild(P.empty('search', t('رکوردی با این مشخصات پیدا نشد'), t('عبارت جستجو یا فیلتر نوع را تغییر دهید.'),
          P.btn(t('پاک کردن فیلترها'), { onclick: function () { S.dns.q = ''; S.dns.type = ''; search.querySelector('input').value = ''; drawChips(); drawList(); } })));
        return;
      }
      var tbody = h('tbody');
      var cards = h('ul', { className: 'pcdn-rcards pcdn-only-narrow', 'aria-label': t('رکوردها') });
      rows.forEach(function (r) {
        tbody.appendChild(recordRow(r));
        cards.appendChild(recordCard(r));
      });
      append(list, [h('div', { className: 'pcdn-table-wrap pcdn-only-wide' }, h('table', { className: 'pcdn-table pcdn-dns-table' },
        h('caption', { className: 'pcdn-sr', text: t('رکوردهای DNS') }),
        h('colgroup', null, h('col', { style: 'width:80px' }), h('col', { style: 'width:20%' }), h('col'), h('col', { style: 'width:84px' }), h('col', { style: 'width:128px' }), h('col', { style: 'width:88px' })),
        h('thead', null, h('tr', null, [t('نوع'), t('نام'), t('مقدار'), 'TTL', t('پروکسی CDN'), t('عملیات')].map(function (tx) { return h('th', { scope: 'col', text: tx }); }))),
        tbody)), cards]);
      lockWrites(list);
    }
    S.drawRecords = function () { drawList(); };
    drawList();
    out.push(c);
    // Wave 14 (SPEC §23.6): «انتقال از ابر آروان» / «انتقال از Cloudflare» (importer.js)
    if (P.importer && P.importer.card) out.push(P.importer.card());
    out.push(importExportCard());
    return out;
  }

  function extras(r) {
    var x = [];
    if (r.priority !== null && r.priority !== undefined && (r.type === 'MX' || r.type === 'SRV')) x.push([t('اولویت'), String(r.priority)]);
    if (r.pool) x.push([t('استخر'), r.pool]);
    if (r.storage && r.proxied) x.push([t('باکت'), String(r.storage)]);
    if (r.origin_port) x.push([t('پورت'), String(r.origin_port)]);
    if (r.health_check) x.push([t('بررسی سلامت'), (r.health_protocol && r.health_protocol !== 'tcp' ? r.health_protocol.toUpperCase() + ' ' : '') + String(r.health_port || (r.health_protocol === 'https' ? 443 : 80))]);
    if (P.w8) x = x.concat(P.w8.recordExtras(r));
    var hb = P.w8 ? P.w8.recordHealthBadge(r) : null;
    return x.length || hb ? h('span', { className: 'pcdn-rextras' }, x.map(function (e) { return h('span', { className: 'pcdn-mini' }, e[0] + ': ', ltr(e[1])); }), hb) : null;
  }
  function proxyCell(r) {
    if (!PROXYABLE[r.type]) return h('span', { className: 'pcdn-proxy-na', text: t('فقط DNS') });
    var sw = P.switchInput(r.proxied, t('پروکسی CDN برای ') + fqdn(r.name) + ' (' + r.type + ')', function (v, el) {
      el.disabled = true;
      var b = recordBody(r); b.proxied = v; b = recordBody(b);
      api('PUT', 'records/' + r.id, b).then(function (res) {
        el.disabled = false;
        if (!res.ok) { el.checked = !v; P.toast(P.errorText(res), 'error'); return; }
        var upd = res.data && res.data.id ? res.data : null;
        S.site.records = (S.site.records || []).map(function (x) { return x.id === r.id ? (upd || Object.assign({}, x, b)) : x; });
        P.toast(v ? t('پروکسی ') + fqdn(r.name) + t(' روشن شد؛ ترافیک از CDN عبور می‌کند.') : t('پروکسی ') + fqdn(r.name) + t(' خاموش شد.'));
        if (S.drawRecords) S.drawRecords();
        var n = root.querySelector('[data-nav="dns"] .pcdn-nav-count');
        if (n) n.textContent = num(S.site.records.length);
      });
    }, { write: true });
    return h('label', { className: 'pcdn-proxy' + (r.proxied ? ' is-on' : '') }, sw, h('span', { className: 'pcdn-proxy-text', text: r.proxied ? t('پروکسی') : t('فقط DNS') }));
  }
  function rowActions(r) {
    return h('div', { className: 'pcdn-row-btns' },
      P.iconBtn('edit', t('ویرایش رکورد ') + r.type + ' ' + fqdn(r.name), function () { recordModal(r); }, { write: true }),
      P.iconBtn('trash', t('حذف رکورد ') + r.type + ' ' + fqdn(r.name), function () { deleteRecord(r); }, { write: true, cls: 'is-danger' }));
  }
  function nameNode(r) {
    return h('span', { className: 'pcdn-rname', dir: 'ltr', title: fqdn(r.name) },
      h('span', { className: 'pcdn-rname-main', text: r.name || '@' }), r.name && r.name !== '@' ? h('span', { className: 'pcdn-rname-zone', text: '.' + S.site.domain }) : null);
  }
  /** Record value; long values (DKIM etc.) are clamped to two lines with a toggle. */
  function valueNode(r) {
    var v = String(r.content || ''), long = v.length > 90;
    var c = h('code', { dir: 'ltr', text: v, className: long ? 'is-long' : null, title: long ? v : null });
    var more = long ? h('button', { type: 'button', className: 'pcdn-more', 'aria-expanded': 'false', 'data-ro-ok': '1', text: t('بیشتر'),
      onclick: function () { var o = !c.classList.contains('is-open'); c.classList.toggle('is-open', o); more.textContent = o ? t('کمتر') : t('بیشتر'); more.setAttribute('aria-expanded', String(o)); } }) : null;
    return h('div', { className: 'pcdn-rvalue' }, long ? h('div', { className: 'pcdn-rvalue-text' }, c, more) : c, P.copyBtn(v, t('کپی مقدار')));
  }
  function recordRow(r) {
    return h('tr', { 'data-record': r.id },
      h('td', null, typeBadge(r.type)),
      h('td', null, nameNode(r)),
      h('td', null, valueNode(r), extras(r)),
      h('td', { className: 'pcdn-muted', text: ttlText(r.ttl) }),
      h('td', null, proxyCell(r)),
      h('td', null, rowActions(r)));
  }
  function recordCard(r) {
    return h('li', { className: 'pcdn-rcard', 'data-record': r.id },
      h('div', { className: 'pcdn-rcard-head' }, typeBadge(r.type), nameNode(r), rowActions(r)),
      valueNode(r),
      extras(r),
      h('div', { className: 'pcdn-rcard-foot' }, h('span', { className: 'pcdn-muted' }, 'TTL: ' + ttlText(r.ttl)), proxyCell(r)));
  }

  function deleteRecord(r) {
    P.confirm({ title: t('حذف رکورد'), danger: true, ok: t('حذف رکورد'),
      body: h('div', null, h('p', { text: t('این رکورد برای همیشه حذف می‌شود:') }),
        h('p', { className: 'pcdn-confirm-rec' }, typeBadge(r.type), ' ', ltr(fqdn(r.name)), ' → ', ltr(r.content)),
        r.type === 'MX' || MAILISH.test(r.name) ? h('p', { className: 'pcdn-warn-text', text: t('این رکورد به ایمیل مربوط است؛ با حذف آن ممکن است دریافت ایمیل قطع شود.') }) : null) })
      .then(function (ok) {
        if (!ok) return;
        api('DELETE', 'records/' + r.id).then(function (res) {
          if (!res.ok) { P.toast(P.errorText(res), 'error'); return; }
          reloadRecords().then(function () { P.toast(t('رکورد حذف شد.')); renderMain(); });
        });
      });
  }

  /** Record dialog: orig = the record to edit, or null for a new one (preset = initial values, e.g. the storage page's «مبدأ CDN»). */
  function recordModal(orig, preset) {
    var f = features();
    var pools = (config('pools').pools || []).map(function (p) { return p.name; });
    var r = orig ? clone(orig) : Object.assign({ type: 'A', name: '', content: '', ttl: 300, priority: null, proxied: true, pool: null, origin_port: null, health_check: false, health_port: null }, preset || {});
    var d = P.dialog({ title: orig ? t('ویرایش رکورد') : t('افزودن رکورد'), icon: orig ? 'edit' : 'plus', subtitle: orig ? fqdn(orig.name) : S.site.domain, kind: 'modal', wide: true });
    d.el.classList.add('pcdn-record-modal');
    var errBox = h('div');
    var form = h('form', { className: 'pcdn-form', novalidate: true, onsubmit: function (e) { e.preventDefault(); submit(); } });
    var ctx = null;
    append(d.body, [errBox, form]);
    function draw() {
      clear(form);
      if (!PROXYABLE[r.type]) r.proxied = false;
      var info = TYPE_INFO[r.type];
      P.beginForm(r);
      var typeGroup = h('div', { className: 'pcdn-type-pick', role: 'radiogroup', 'aria-label': t('نوع رکورد') }, TYPES.map(function (tx) {
        var id = P.uid('pcdn-tp-');
        return h('label', { className: 'pcdn-type-opt', 'for': id }, h('input', { type: 'radio', name: 'pcdn-rtype', id: id, value: tx, checked: r.type === tx,
          onchange: function () { r.type = tx; draw(); var x = form.querySelector('input[value="' + tx + '"]'); if (x) x.focus(); } }), h('span', { text: tx }));
      }));
      var nameIn = P.input(r, 'name', t('نام'), { placeholder: '@', suffix: '.' + S.site.domain, maxlength: 253,
        help: h('span', null, h('b', { text: '@' }), t(' یعنی خود دامنه ('), ltr(S.site.domain), t('). برای زیردامنه فقط بخش اول را بنویسید، مثلاً '), ltr('www'), '.') });
      var content = r.type === 'TXT'
        ? P.textarea(r, 'content', info[0], { rows: 3, placeholder: info[1] })
        : P.input(r, 'content', info[0], { placeholder: info[1] });
      var ttlOpts = TTLS.slice();
      if (!TTLS.some(function (x) { return x[0] === Number(r.ttl); })) ttlOpts.push([Number(r.ttl), P.dur(r.ttl)]);
      var grid = h('div', { className: 'pcdn-grid' }, nameIn,
        (r.type === 'MX' || r.type === 'SRV') ? P.input(r, 'priority', t('اولویت'), { type: 'number', min: 0, max: 65535, nullable: true, placeholder: '10', help: t('عدد کمتر = اولویت بالاتر') }) : null,
        P.select(r, 'ttl', t('TTL (مدت نگهداری در کش DNS)'), ttlOpts, { help: t('اگر قصد تغییر آدرس دارید، مدتی قبل آن را کم کنید.') }));
      append(form, [P.field(t('نوع رکورد'), typeGroup, { help: info[2], path: 'type' }), grid, content]);
      if (PROXYABLE[r.type]) {
        var px = h('div', { className: 'pcdn-subpanel' }, P.toggle(r, 'proxied', t('پروکسی از طریق CDN'), {
          help: t('روشن: ترافیک وب از CDN عبور می‌کند، آی‌پی سرور مخفی می‌ماند و کش و امنیت اعمال می‌شود. برای ایمیل، FTP و SSH خاموش بگذارید.'), onchange: draw }));
        if (r.proxied && MAILISH.test(String(r.name || '').split('.')[0])) px.appendChild(P.alertBox('warning', t('به نظر می‌رسد این رکورد برای ایمیل یا دسترسی مستقیم است. رکوردهای ایمیل نباید پروکسی شوند؛ وگرنه ایمیل کار نمی‌کند.')));
        if (r.proxied) {
          // SPEC §16.8: origin = the record's value (your server) or one of the site's storage buckets
          var stf = P.storage ? P.storage.recordFields(r, draw) : null;
          if (stf) px.appendChild(stf);
          var g2 = h('div', { className: 'pcdn-grid' });
          if (r.storage) { /* bucket origin: no pool, no origin port */ } else if (f.load_balancer && pools.length) {
            g2.appendChild(P.select(r, 'pool', t('استخر توزیع بار'), [[null, t('— بدون استخر —')]].concat(pools.map(function (p) { return [p, p]; })),
              { help: t('در صورت انتخاب، ترافیک به سرورهای استخر فرستاده می‌شود و «مقدار» فقط پشتیبان است.'), onchange: draw, ltr: false }));
          }
          if (!r.pool && !r.storage) g2.appendChild(P.input(r, 'origin_port', t('پورت سرور اصلی'), { type: 'number', min: 1, max: 65535, nullable: true, placeholder: '80 / 443', help: t('خالی بگذارید تا بر اساس پروتکل (۸۰ یا ۴۴۳) انتخاب شود.') }));
          px.appendChild(g2);
        } else if (P.w8 && P.w8.recordsV2()) {
          px.appendChild(P.w8.recordFields(r, draw));
        } else if (r.type === 'A' || r.type === 'AAAA') {
          px.appendChild(P.toggle(r, 'health_check', t('بررسی سلامت'), { help: t('اگر چند رکورد هم‌نام دارید، فقط آدرس‌هایی که پورتشان پاسخ می‌دهد در DNS برگردانده می‌شوند.'), onchange: draw }));
          if (r.health_check) px.appendChild(P.input(r, 'health_port', t('پورت بررسی سلامت'), { type: 'number', min: 1, max: 65535, nullable: true, placeholder: '80' }));
        }
        form.appendChild(px);
      } else if (r.type === 'ALIAS' || r.type === 'MX' || r.type === 'TXT') {
        form.appendChild(h('p', { className: 'pcdn-help' }, icon('info'), t(' رکوردهای ') + r.type + t(' پروکسی نمی‌شوند و همان‌طور که وارد می‌کنید پاسخ داده می‌شوند.')));
      }
      form.appendChild(h('button', { type: 'submit', hidden: true, tabindex: '-1', 'aria-hidden': 'true' }));
      ctx = P.endForm();
      lockWrites(form);
    }
    var save = P.btn(orig ? t('ذخیره رکورد') : t('افزودن رکورد'), { kind: 'primary', icon: 'check', write: true, cls: 'pcdn-rec-save', onclick: submit });
    append(d.foot, [save, P.btn(t('انصراف'), { onclick: function () { d.close(); } })]);
    function submit() {
      clear(errBox);
      P.clearErrors(form);
      var probs = P.w8 ? P.w8.recordProblems(recordBody(r), r) : [];
      if (probs.length) {
        var rest0 = P.placeErrors(ctx, probs);
        if (rest0.length) errBox.appendChild(P.alertBox('danger', h('ul', { className: 'pcdn-errlist' }, rest0.map(function (x) { return h('li', { text: x.msg }); }))));
        var bad0 = form.querySelector('[aria-invalid]');
        if (bad0) bad0.focus();
        return;
      }
      var body = recordBody(r);
      var p = orig ? api('PUT', 'records/' + orig.id, body) : api('POST', 'records', body);
      P.busy(save, p).then(function (res) {
        if (!res.ok) {
          var e = P.parseErrors(res.data, res.status);
          var rest = P.placeErrors(ctx, e.items);
          if (rest.length || !e.items.length) errBox.appendChild(P.errorBox({ status: res.status, data: { detail: rest.length ? rest.map(function (x) { return { loc: x.path.split('.'), msg: x.msg }; }) : e.summary } }));
          var bad = form.querySelector('[aria-invalid] , .has-error input');
          if (bad) bad.focus();
          return;
        }
        d.close(true);
        reloadRecords().then(function () { P.toast(orig ? t('رکورد ذخیره شد.') : t('رکورد اضافه شد.')); renderMain(); });
      });
    }
    draw();
    lockWrites(d.el);
    var first = form.querySelector('input[type=radio]:checked');
    if (orig) { var ci = form.querySelector('input:not([type=radio]), textarea'); if (ci) ci.focus(); } else if (first) first.focus();
  }

  function importExportCard() {
    var c = P.collapsible({ title: t('ورود و خروج زون (BIND)'), icon: 'upload', tone: 'muted', subtitle: t('انتقال یکجای رکوردها از سرویس DNS قبلی یا تهیه نسخه پشتیبان'), id: 'zone' });
    var st = { zone: '', replace: false };
    var outTa = h('textarea', { className: 'pcdn-input pcdn-mono', dir: 'ltr', rows: 6, readonly: true, 'data-ro-ok': '1', hidden: true, 'aria-label': t('خروجی زون') });
    var dl = h('a', { className: 'pcdn-btn pcdn-btn-sm', hidden: true, download: S.site.domain + '.zone', 'data-ro-ok': '1' }, icon('download'), h('span', { text: t('دانلود فایل') }));
    var result = h('div');
    var exp = P.btn(t('خروجی زون'), { icon: 'download', size: 'sm', cls: 'pcdn-export', onclick: function () {
      exp.setAttribute('data-ro-ok', '1');
      P.busy(exp, api('GET', 'records/export')).then(function (res) {
        if (!res.ok) { P.toast(P.errorText(res), 'error'); return; }
        outTa.value = (res.data && res.data.zone) || '';
        outTa.hidden = false;
        if (window.Blob && window.URL && URL.createObjectURL) { dl.href = URL.createObjectURL(new Blob([outTa.value], { type: 'text/plain' })); dl.hidden = false; }
      });
    } });
    exp.setAttribute('data-ro-ok', '1');
    var imp = P.btn(t('ورود رکوردها'), { kind: 'primary', icon: 'upload', size: 'sm', write: true, cls: 'pcdn-import', onclick: function () {
      clear(result);
      if (!st.zone.trim()) { result.appendChild(P.alertBox('warning', t('ابتدا محتوای فایل زون را وارد کنید.'))); return; }
      var pre = st.replace ? P.confirm({ title: t('جایگزینی همه رکوردها'), danger: true, ok: t('حذف و جایگزینی'),
        body: t('همه ') + num((S.site.records || []).length) + t(' رکورد فعلی حذف و رکوردهای فایل زون جایگزین آن‌ها می‌شوند. اگر رکوردی (مثلاً ایمیل) در فایل نباشد، از دست می‌رود.') }) : Promise.resolve(true);
      pre.then(function (ok) {
        if (!ok) return;
        P.busy(imp, api('POST', 'records/import', { zone: st.zone, replace: st.replace })).then(function (res) {
          if (!res.ok) { result.appendChild(P.errorBox(res, t('ورود رکوردها انجام نشد'))); return; }
          var d = res.data || {}, skipped = d.skipped || [];
          reloadRecords().then(function () {
            if (S.drawRecords) S.drawRecords();
            P.toast(num(d.imported || 0) + t(' رکورد وارد شد.'));
            result.appendChild(P.alertBox(skipped.length ? 'warning' : 'success', [h('strong', { text: num(d.imported || 0) + t(' رکورد وارد شد.') }),
              skipped.length ? [h('div', { text: num(skipped.length) + t(' خط وارد نشد:') }), h('ul', { className: 'pcdn-errlist' }, skipped.map(function (x) {
                return h('li', null, ltr(x.line || ''), ' — ', String(x.reason || ''));
              }))] : null]));
          });
        });
      });
    } });
    append(c.body, [
      h('p', { className: 'pcdn-muted', text: t('در سرویس DNS قبلی گزینه Export یا «دریافت فایل زون» را بزنید و محتوای آن را اینجا قرار دهید. رکوردهای SOA و NS ریشه نادیده گرفته می‌شوند. بعد از ورود، پروکسی رکوردهای وب را بررسی کنید.') }),
      P.field(t('محتوای فایل زون'), h('textarea', { className: 'pcdn-input pcdn-mono', dir: 'ltr', rows: 5, spellcheck: 'false', placeholder: 'www 300 IN A 185.1.2.3', 'aria-label': t('محتوای فایل زون'),
        oninput: function (e) { st.zone = e.target.value; } })),
      P.toggle(st, 'replace', t('جایگزینی کامل رکوردهای فعلی'), { help: t('اگر خاموش باشد، رکوردهای فایل به رکوردهای فعلی اضافه می‌شوند.') }),
      h('div', { className: 'pcdn-row-actions' }, imp, exp, dl), result, outTa
    ]);
    return c;
  }

  // ------------------------------------------------------------------ DNSSEC

  function renderDnssec() {
    var holder = h('div', { className: 'pcdn-stack' }, P.card({ title: 'DNSSEC', icon: 'key' }));
    holder.firstChild.body.appendChild(P.skeleton(3));
    function draw() {
      clear(holder);
      var d = S.dnssec;
      var c = P.card({ title: t('وضعیت DNSSEC'), icon: 'key', tone: d.enabled ? 'success' : 'muted', id: 'dnssec',
        actions: h('span', { className: 'pcdn-pill pcdn-tone-' + (d.enabled ? 'success' : 'muted') }, h('span', { className: 'pcdn-dot' }), h('span', { text: d.enabled ? t('فعال') : t('غیرفعال') })) });
      var toggleBtn = P.btn(d.enabled ? t('غیرفعال کردن DNSSEC') : t('فعال‌سازی DNSSEC'), { kind: d.enabled ? 'danger-soft' : 'primary', icon: d.enabled ? 'power' : 'key', write: true, cls: 'pcdn-dnssec-toggle',
        onclick: function () {
          var pre = d.enabled ? P.confirm({ title: t('غیرفعال کردن DNSSEC'), danger: true, ok: t('بله، غیرفعال شود'),
            body: h('div', null, h('p', { text: t('پیش از غیرفعال کردن، رکورد DS را از پنل ثبت‌کننده دامنه (مثلاً ایرنیک) حذف کنید و حداقل ۲۴ ساعت صبر کنید.') }),
              h('p', { className: 'pcdn-warn-text', text: t('اگر DS در ثبت‌کننده باقی بماند و DNSSEC اینجا خاموش شود، دامنه برای بسیاری از کاربران از دسترس خارج می‌شود.') })) }) : Promise.resolve(true);
          pre.then(function (ok) {
            if (!ok) return;
            P.busy(toggleBtn, api('POST', 'dnssec', { enabled: !d.enabled })).then(function (res) {
              if (!res.ok) { P.toast(P.errorText(res), 'error'); return; }
              S.dnssec = res.data;
              P.toast(res.data.enabled ? t('DNSSEC فعال شد؛ حالا رکورد DS را در ثبت‌کننده دامنه وارد کنید.') : t('DNSSEC غیرفعال شد.'));
              draw();
            });
          });
        } });
      if (!d.enabled) {
        append(c.body, [h('p', { text: t('DNSSEC پاسخ‌های DNS دامنه را امضا می‌کند تا کسی نتواند آن‌ها را در مسیر جعل کند. فعال‌سازی دو مرحله دارد: اینجا روشنش می‌کنید، سپس رکورد DS را در ثبت‌کننده دامنه ثبت می‌کنید.') }),
          h('div', { className: 'pcdn-row-actions' }, toggleBtn)]);
        holder.appendChild(c);
      } else {
        append(c.body, [h('p', { text: t('DNSSEC روشن است. اگر هنوز رکورد DS را در ثبت‌کننده ثبت نکرده‌اید، از مقادیر زیر استفاده کنید.') }),
          h('div', { className: 'pcdn-ds-list' }, (d.ds || []).map(function (ds) {
            var p = String(ds).trim().split(/\s+/);
            return h('div', { className: 'pcdn-ds' },
              h('div', { className: 'pcdn-ds-full' }, h('span', { className: 'pcdn-label', text: t('رکورد DS کامل') }), P.copyable(ds, { label: t('کپی رکورد DS'), block: true })),
              p.length >= 4 ? h('dl', { className: 'pcdn-ds-parts' }, [['Key Tag', p[0]], ['Algorithm', p[1]], ['Digest Type', p[2]], ['Digest', p.slice(3).join('')]].map(function (x) {
                return h('div', null, h('dt', { dir: 'ltr', text: x[0] }), h('dd', null, P.copyable(x[1], { label: t('کپی ') + x[0] })));
              })) : null);
          })),
          d.dnskey ? P.field(t('DNSKEY (برخی ثبت‌کننده‌ها به جای DS این را می‌خواهند)'), P.copyable(d.dnskey, { label: t('کپی DNSKEY'), block: true })) : null,
          h('div', { className: 'pcdn-row-actions' }, toggleBtn)]);
        holder.appendChild(c);
        var how = P.card({ title: t('ثبت DS در ثبت‌کننده دامنه'), icon: 'book', tone: 'muted' });
        append(how.body, [
          h('h4', { text: t('دامنه‌های ‎.ir (ایرنیک)') }),
          h('ol', { className: 'pcdn-ol' },
            h('li', { text: t('وارد nic.ir شوید و با شناسه ایرنیک خود وارد حساب شوید.') }),
            h('li', { text: t('از «مدیریت دامنه» دامنه را انتخاب کنید و بخش DNSSEC / رکورد DS را باز کنید.') }),
            h('li', { text: t('مقادیر Key Tag، Algorithm، Digest Type و Digest بالا را وارد و ثبت کنید.') })),
          h('p', { className: 'pcdn-muted', text: t('اگر این گزینه را در پنل نمی‌بینید، از طریق پشتیبانی ایرنیک درخواست ثبت DS بدهید.') }),
          h('h4', { text: t('سایر ثبت‌کننده‌ها') }),
          h('p', { text: t('در پنل دامنه به دنبال DNSSEC یا DS Records بگردید و همان چهار مقدار را وارد کنید. ثبت DS معمولاً تا ۲۴ ساعت طول می‌کشد.') })]);
        holder.appendChild(how);
      }
      lockWrites(holder);
    }
    if (S.dnssec) setTimeout(draw, 0);
    else api('GET', 'dnssec').then(function (res) {
      if (S.page !== 'dnssec') return;
      if (!res.ok) { clear(holder); holder.appendChild(P.errorBox(res, t('دریافت وضعیت DNSSEC ممکن نشد'))); return; }
      S.dnssec = res.data;
      draw();
    });
    return holder;
  }

  // ------------------------------------------------------------------ help & tutorials

  var TUT_ICONS = { 'شروع': 'rocket', 'سرور اصلی': 'server', 'SSL و HTTPS': 'lock', 'کش و عملکرد': 'zap', 'امنیت': 'shield', 'عیب‌یابی': 'tool' };
  // Tutorial categories stay Persian ids (tutorials.js `cat`); this is their label in the page language.
  var TUT_CATS = { 'شروع': t('شروع'), 'سرور اصلی': t('سرور اصلی'), 'SSL و HTTPS': t('SSL و HTTPS'), 'کش و عملکرد': t('کش و عملکرد'),
    'امنیت': t('امنیت'), 'عیب‌یابی': t('عیب‌یابی'), 'تونل / VPN': t('تونل / VPN') };
  function catLabel(c) { return TUT_CATS[c] || c; }
  var tutCache = null;
  function tutorials() {
    if (!tutCache) {
      var fn = window.PCDN_TUTORIALS;
      tutCache = typeof fn === 'function' ? fn({ domain: S.site.domain, ips: edgeIps(), ns: S.site.nameservers || [], num: P.num }) : [];
      tutCache.forEach(function (tx) {
        var txt = [tx.title, tx.summary, tx.keywords, catLabel(tx.cat)];
        (tx.blocks || []).forEach(function (b) { txt.push(Array.isArray(b[1]) ? b[1].join(' ') : b[1], b[2] || ''); });
        tx._q = P.norm(txt.join(' '));
      });
    }
    return tutCache;
  }

  function renderHelp() {
    if (S.sub) {
      var tx = tutorials().filter(function (x) { return x.id === S.sub; })[0];
      if (tx) return renderTutorial(tx);
    }
    var all = tutorials();
    var cats = [];
    all.forEach(function (tx) { if (cats.indexOf(tx.cat) < 0) cats.push(tx.cat); });
    var list = h('div', { className: 'pcdn-tuts' });
    var chips = h('div', { className: 'pcdn-filter-chips', role: 'group', 'aria-label': t('دسته‌بندی آموزش‌ها') });
    var status = h('p', { className: 'pcdn-sr', 'aria-live': 'polite' });
    function drawChips() {
      clear(chips);
      [''].concat(cats).forEach(function (c) {
        chips.appendChild(h('button', { type: 'button', className: 'pcdn-fchip' + (S.help.cat === c ? ' is-active' : ''), 'aria-pressed': String(S.help.cat === c), 'data-ro-ok': '1', text: c ? catLabel(c) : t('همه'),
          onclick: function () { S.help.cat = c; drawChips(); draw(); } }));
      });
    }
    function draw() {
      clear(list);
      var words = P.norm(S.help.q).split(/\s+/).filter(Boolean);
      var rows = all.filter(function (tx) {
        if (S.help.cat && tx.cat !== S.help.cat) return false;
        return words.every(function (w) { return tx._q.indexOf(w) >= 0; });
      });
      status.textContent = num(rows.length) + t(' آموزش');
      if (!rows.length) {
        list.appendChild(P.empty('search', t('آموزشی پیدا نشد'), t('عبارت دیگری را جستجو کنید؛ مثلاً «۵۰۲»، «ایمیل»، «وردپرس» یا «نیم‌سرور».')));
        return;
      }
      rows.forEach(function (tx) {
        list.appendChild(h('a', { href: '#pcdn=help/' + tx.id, className: 'pcdn-tut-card', 'data-tut': tx.id, 'data-ro-ok': '1', onclick: function (e) { e.preventDefault(); go('help', tx.id); } },
          h('span', { className: 'pcdn-tut-icon' }, icon(TUT_ICONS[tx.cat] || 'book')),
          h('span', { className: 'pcdn-tut-text' }, h('span', { className: 'pcdn-tut-cat', text: catLabel(tx.cat) }), h('span', { className: 'pcdn-tut-title', text: tx.title }), h('span', { className: 'pcdn-tut-sum', text: tx.summary })),
          icon('chevronLeft', 'pcdn-tut-go')));
      });
    }
    var search = h('div', { className: 'pcdn-search pcdn-search-lg' }, icon('search'),
      h('input', { type: 'search', className: 'pcdn-input', placeholder: t('جستجو در آموزش‌ها… (مثلاً ۵۰۲، ایمیل، وردپرس، nginx)'), 'aria-label': t('جستجو در آموزش‌ها'), value: S.help.q, 'data-ro-ok': '1',
        oninput: function (e) { S.help.q = e.target.value; draw(); } }));
    drawChips();
    draw();
    return [h('div', { className: 'pcdn-help-top' }, search, chips, status), list];
  }

  function renderTutorial(tx) {
    var art = h('article', { className: 'pcdn-card pcdn-article', 'data-tutorial': tx.id });
    var back = h('a', { href: '#pcdn=help', className: 'pcdn-back', 'data-ro-ok': '1', onclick: function (e) { e.preventDefault(); go('help'); } }, icon('arrowRight'), h('span', { text: t('همه آموزش‌ها') }));
    append(art, [h('header', { className: 'pcdn-article-head' }, h('span', { className: 'pcdn-tut-cat', text: catLabel(tx.cat) }), h('h3', { text: tx.title }), h('p', { className: 'pcdn-muted', text: tx.summary }))]);
    var body = h('div', { className: 'pcdn-article-body' });
    (tx.blocks || []).forEach(function (b) {
      var k = b[0];
      if (k === 'p') body.appendChild(h('p', { text: b[1] }));
      else if (k === 'h') body.appendChild(h('h4', { text: b[1] }));
      else if (k === 'steps') body.appendChild(h('ol', { className: 'pcdn-ol pcdn-steps-ol' }, b[1].map(function (x) { return h('li', { text: x }); })));
      else if (k === 'list') body.appendChild(h('ul', { className: 'pcdn-ul' }, b[1].map(function (x) { return h('li', { text: x }); })));
      else if (k === 'code') {
        body.appendChild(h('figure', { className: 'pcdn-codeblock' },
          h('figcaption', null, icon('terminal'), h('span', { dir: 'ltr', text: b[2] || '' }), P.copyBtn(b[1], t('کپی کد') + (b[2] ? ' ' + b[2] : ''), { text: t('کپی'), cls: 'pcdn-copy-code', done: t('کد کپی شد') })),
          h('pre', { dir: 'ltr', tabindex: '0' }, h('code', { text: b[1] }))));
      } else if (k === 'note') {
        var tone = b[2] === 'danger' ? 'danger' : b[2] === 'warn' ? 'warning' : 'info';
        body.appendChild(P.alertBox(tone, b[1]));
      } else if (k === 'go') {
        body.appendChild(h('div', { className: 'pcdn-article-go' }, P.btn(b[2], { icon: pages[b[1]] ? pages[b[1]].icon : 'arrowLeft', onclick: function () { go(b[1]); } })));
      } else if (k === 'tut') {
        body.appendChild(h('div', { className: 'pcdn-article-go' }, tutLink(b[1], b[2])));
      }
    });
    art.appendChild(body);
    var related = tutorials().filter(function (x) { return x.id !== tx.id && x.cat === tx.cat; });
    return [back, art, related.length ? h('div', { className: 'pcdn-related' }, h('h4', { text: t('آموزش‌های مرتبط') }), related.map(function (x) { return tutLink(x.id, x.title); })) : null];
  }

  // ------------------------------------------------------------------ page registry (core pages; the rest live in pages.js / reports.js)

  pages.overview = {
    title: t('نمای کلی'), icon: 'home', heading: t('نمای کلی'),
    desc: t('وضعیت سرویس، مراحل راه‌اندازی، مصرف و اقدامات سریع در یک نگاه.'),
    render: renderOverview
  };
  pages.help = {
    title: t('راهنما و آموزش'), icon: 'book',
    desc: t('آموزش‌های قدم‌به‌قدم برای راه‌اندازی، امنیت، کش و رفع خطاهای رایج — بدون نیاز به دانش فنی زیاد.'),
    render: renderHelp
  };
  pages.dns = {
    title: t('رکوردها'), icon: 'server', heading: t('رکوردهای DNS'),
    desc: t('رکوردهای DNS مشخص می‌کنند هر نام (سایت، ایمیل، زیردامنه) به کدام سرور برود. رکوردهای وب را پروکسی کنید تا از CDN عبور کنند.'),
    guide: {
      what: t('هر رکورد یک نام (مثل www) را به یک مقصد (آی‌پی یا نام دیگر) وصل می‌کند. رکورد «پروکسی‌شده» ترافیک را از CDN عبور می‌دهد.'),
      when: t('پیش از تغییر نیم‌سرورها همه رکوردهای فعلی را وارد کنید؛ بعد از آن هر زمان سرور یا سرویس جدیدی اضافه کردید.'),
      rec: t('A یا CNAME مربوط به @ و www: پروکسی روشن. MX، mail، ftp و رکوردهای TXT: فقط DNS. TTL: ۵ دقیقه.'),
      mistakes: [t('پروکسی کردن رکورد mail یا ftp (ایمیل و FTP قطع می‌شود).'), t('فراموش کردن رکوردهای MX و SPF هنگام انتقال.'), t('تغییر نیم‌سرورها پیش از وارد کردن کامل رکوردها.')],
      tut: 'quickstart'
    },
    actions: function () {
      var max = (S.site.plan || {}).max_records || 0, full = (S.site.records || []).length >= max;
      return P.btn(t('افزودن رکورد'), { kind: 'primary', icon: 'plus', write: true, cls: 'pcdn-add-record', disabled: full, title: full ? t('سقف تعداد رکوردهای پلن پر شده است') : null, onclick: function () { recordModal(null); } });
    },
    render: renderDns
  };
  pages.dnssec = {
    title: 'DNSSEC', icon: 'key',
    desc: t('امضای دیجیتال پاسخ‌های DNS برای جلوگیری از جعل؛ پس از فعال‌سازی باید رکورد DS را در ثبت‌کننده دامنه وارد کنید.'),
    guide: {
      what: t('DNSSEC با امضای دیجیتال تضمین می‌کند پاسخ DNS دامنه شما در مسیر تغییر داده نشده است.'),
      when: t('بعد از اینکه نیم‌سرورها تأیید شدند و سایت پایدار کار می‌کند.'),
      rec: t('برای اغلب سایت‌ها اختیاری است؛ اگر فعال می‌کنید، DS را دقیق و کامل در ثبت‌کننده وارد کنید.'),
      mistakes: [t('خاموش کردن DNSSEC در اینجا بدون حذف DS از ثبت‌کننده (دامنه از دسترس خارج می‌شود).'), t('تغییر نیم‌سرورها به سرویس دیگر در حالی که DS قدیمی هنوز ثبت است.')]
    },
    upsell: t('با ارتقای پلن، پاسخ‌های DNS دامنه شما امضای دیجیتال می‌گیرند.'),
    lock: function (f) { return !f.dnssec; },
    render: renderDnssec
  };

  // §10.5 reseller panel — registered only for reseller accounts; the page body lives in reseller.js.
  if (RESELLER) {
    pages.reseller = {
      title: t('نمایندگی'), icon: 'globe', heading: t('پنل نمایندگی'),
      desc: t('سایت‌های CDN مشتریان نهایی شما: ساخت سایت، گزارش مصرف و هزینه عمده، و مدیریت کامل هر سایت.'),
      render: function (App, body) {
        return P.reseller ? P.reseller.render(App, body) : h('div', { className: 'pcdn-alert pcdn-alert-danger', text: t('بخش نمایندگی بارگذاری نشد.') });
      }
    };
  }

  // ------------------------------------------------------------------ public API for pages.js / reports.js

  var A = P.app = {
    S: S, go: go, features: features, config: config, setConfig: setConfig, putSection: putSection, sectionForm: sectionForm,
    lockWrites: lockWrites, tutLink: tutLink, goLink: goLink, edgeIps: edgeIps, reloadSite: reloadSite, renderMain: renderMain,
    upgradeUrl: UPGRADE_URL, modeLabel: modeLabel, ensureAnalytics: ensureAnalytics, secTotal: secTotal, serviceId: SID,
    reduced: reduced, updateSaveBar: updateSaveBar, wallet: WALLET, billing: BILL,
    statement: STATEMENT, money: money, webRoot: WEBROOT, addFundsUrl: ADDFUNDS_URL,
    reseller: RESELLER, openSubSite: openSubSite, exitSubSite: exitSubSite, inSubSite: function () { return !!RSITE; },
    onLeave: onLeave, share: SHARE, sharing: SHARE || ADMIN ? null : (boot.sharing || null),
    xfer: SHARE || ADMIN || READONLY ? null : (boot.xfer || null), refreshNav: refreshNav, recordModal: recordModal, refreshBrand: refreshBrand,
    // Wave 14 (SPEC §23): account-level pages (alerts) and the diagnostics / import dialogs are the account's own — never in the admin
    // view, a shared domain or a reseller's sub-site
    admin: !!ADMIN, readonlyTeam: READONLY, reloadRecords: reloadRecords
  };

  // §14.3.7 / §20.1: modules ask A().readonly when they render — read-only team member or a role that cannot change this page
  Object.defineProperty(A, 'readonly', { enumerable: true, get: function () { return roNow(); } });

  // ------------------------------------------------------------------ boot

  var r0 = readHash(), later = r0 ? null : pendingHash();
  if (r0) { S.page = r0.page; S.sub = r0.sub; }
  renderAll();
  // Wave 7 (SPEC §15): one background GET tunnel/health decides whether the tunnel quality / usage /
  // speed-test pages exist on this controller (an older one 404s and they stay hidden).
  function probed(ok) {
    if (!ok) return;
    refreshNav();
    var w = later && available(later.page) ? later : null;
    if (w && S.page === 'overview' && /^#pcdn=/.test(window.location.hash || '')) go(w.page, w.sub, { fromHistory: true, fromBoot: true });
    // a page already open (e.g. «تونل») redraws once with the wave-13 pieces it feature-detects
    if (S.page === 'tunnel' && P.tprofile && P.tprofile.ok() === true && !(S.form && S.form.dirty()) && !document.querySelector('.pcdn-dlg')) renderMain();
  }
  if (S.site && P.w7 && P.w7.probe) P.w7.probe().then(probed);
  // Wave 13 (SPEC §22.11): one background GET tunnel/profile on tunnel plans — an older controller 404s and the guide page,
  // per-path idle timeout, multi-origin editor, timeout checks and the HTTP/3 variant stay hidden.
  if (S.site && P.tprofile && P.tprofile.probe && features().tunnel) P.tprofile.probe().then(probed);
  // Wave 14 (SPEC §23): one background GET config/history?limit=1 (settings history; also tells the diagnostics / import pieces that
  // the controller is new enough) and, for the account itself, one GET of its alerts — an older controller 404s and they stay hidden.
  var p14 = [];
  if (S.site && P.alerts && P.alerts.probe && !ADMIN && !SHARE) p14.push(P.alerts.probe());
  if (S.site && P.w17 && P.w17.probe) p14.push(P.w17.probe());
  if (p14.length) Promise.all(p14).then(function (r) { if (P.w17 && P.w17.settle) P.w17.settle(); probed(r.indexOf(true) >= 0); });
})();
