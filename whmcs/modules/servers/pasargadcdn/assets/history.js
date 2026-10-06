/*
 * Pasargad CDN — client app: «تاریخچهٔ تنظیمات» / "Settings history" (SPEC §23.4, wave 14).
 *
 * Registers PCDN.pages.history and PCDN.w17 (the wave-14 feature probe: one background GET config/history?limit=1 when the app
 * starts; an older controller — or CONFIG_HISTORY_ENABLED=false — answers 404 and the page stays hidden).
 *   - timeline of versions: who («شما»، «همکار: نام»، «پشتیبانی»، «کلید API: نام»، «سیستم»), when, how (source) and which sections;
 *   - «مشاهدهٔ تغییرات»: the ops of one version (diff from the version before it) or the difference with the current settings,
 *     redacted values shown as «[پنهان]» (the controller redacts; nothing secret ever reaches the browser);
 *   - «بازگردانی این نسخه…»: section checkboxes + a dry-run preview of what would be applied / dropped (plan gates, limits) and the
 *     warnings, then confirm. Viewers and DNS managers of a shared domain and read-only team users see history and diffs only
 *     (write buttons locked; api.php refuses the POST anyway).
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

  // ------------------------------------------------------------------ wave-14 probe (shared by alerts / import / diagnostics)
  var W = { ok: undefined, first: null, loading: null, settled: false };
  function probe() {
    if (W.ok !== undefined) return Promise.resolve(W.ok);
    if (W.loading) return W.loading;
    W.loading = api('GET', 'config/history', null, { limit: 1 }).then(function (res) {
      W.loading = null;
      if (res.ok && res.data && Array.isArray(res.data.versions)) { W.ok = true; W.first = res.data; }
      else if (res.status === 404) W.ok = false;
      return W.ok === true;
    });
    return W.loading;
  }
  var waiters = [];
  P.w17 = {
    /** true / false, or undefined while unknown */
    ok: function () { return W.ok; },
    probe: function () { return probe(); },
    /** app.js: every wave-14 probe answered (history + alerts) — the waiting slots (diagnostics, import) fill now */
    settle: function () { W.settled = true; waiters.splice(0).forEach(function (fn) { fn(P.w17.wave()); }); },
    /** fn(ok) once the wave-14 probes answered (immediately when they already did) */
    ready: function (fn) { if (W.settled) fn(P.w17.wave()); else waiters.push(fn); },
    /** a wave-14 controller: settings history or account alerts answered */
    wave: function () { return W.ok === true || !!(P.alerts && P.alerts.ok && P.alerts.ok() === true); }
  };

  // ------------------------------------------------------------------ labels

  var SECTION = {
    cache: t('کش'), ssl: t('SSL و HTTPS'), waf: t('فایروال برنامه وب (WAF)'), ddos: t('محافظت DDoS'), firewall: t('فایروال'),
    ratelimit: t('محدودیت نرخ'), pagerules: t('قوانین صفحه'), pools: t('توزیع بار'), headers: t('هدرها'), hotlink: t('جلوگیری از هات‌لینک'),
    image: t('بهینه‌سازی تصویر'), errorpages: t('صفحات خطا'), tunnel: t('تونل'), transform: t('قوانین تبدیل'), redirects: t('ریدایرکت‌ها'),
    bots: t('مدیریت ربات‌ها'), logs: t('ارسال لاگ'), webhooks: t('وب‌هوک‌ها'), l4: t('برنامه‌های TCP/UDP'), video: t('ویدیو'),
    dns_secondary: t('DNS ثانویه'), functions: t('توابع لبه'), waiting_room: t('اتاق انتظار'), access: t('دسترسی محافظت‌شده'),
    rum: t('پایش کاربران واقعی')
  };
  function secLabel(s) { return SECTION[s] || String(s || ''); }
  P.sectionLabel = secLabel;
  var SOURCE = {
    api: t('پنل'), capi: t('API مشتری'), admin: t('پشتیبانی'), restore: t('بازگردانی'), import: t('انتقال از سرویس دیگر'),
    waf_learning: t('یادگیری WAF'), transfer: t('انتقال دامنه'), system: t('سیستم')
  };
  var SYSTEM = { waf_learning: t('یادگیری WAF'), transfer: t('انتقال دامنه'), import: t('انتقال از سرویس دیگر') };
  function actorText(a) {
    a = a && typeof a === 'object' ? a : {};
    var k = String(a.kind || 'system');
    if (a.self) return t('شما');
    if (k === 'client') return t('مالک سرویس');
    if (k === 'collaborator') return a.name ? t('همکار: {0}', String(a.name)) : t('همکار') + (a.id ? ' #' + P.fa(String(a.id)) : '');
    if (k === 'support') return t('پشتیبانی');
    if (k === 'api_key') return a.label ? t('کلید API: {0}', String(a.label)) : t('کلید API');
    return a.label && SYSTEM[a.label] ? t('سیستم') + ' (' + SYSTEM[a.label] + ')' : t('سیستم');
  }
  function actorIcon(a) {
    var k = a && a.kind;
    return k === 'collaborator' ? 'link' : k === 'support' ? 'tool' : k === 'api_key' ? 'key' : k === 'client' ? 'home' : 'refresh';
  }
  var OPS = { add: [t('افزوده'), 'success'], remove: [t('حذف'), 'danger'], replace: [t('تغییر'), 'brand'] };

  // ------------------------------------------------------------------ page

  function st() { var S = A().S; return S.hist || (S.hist = { versions: null, current: null, retention: null, more: false, loading: false }); }

  function render() {
    var wrap = h('div', { className: 'pcdn-stack', 'data-history': '1' });
    var list = P.card({ title: t('نسخه‌های تنظیمات'), icon: 'clock', id: 'history-list',
      subtitle: t('هر تغییر تنظیمات (از پنل، API، پشتیبانی، بازگردانی یا سیستم) یک نسخه می‌سازد.') });
    var body = h('div', { 'data-history-body': '1' }, P.skeleton(4));
    list.body.appendChild(body);
    append(wrap, [list, P.alertBox('info', t('رکوردهای DNS، کلیدها و رمزها در این تاریخچه نیستند؛ مقدارهای محرمانه در مقایسه‌ها «[پنهان]» نمایش داده می‌شوند. بازگردانی هر بخش دوباره با پلن فعلی بررسی می‌شود.'))]);
    load(body, false);
    return wrap;
  }

  function load(body, more) {
    var s = st();
    var q = { limit: 25 };
    if (more && s.versions && s.versions.length) q.before = s.versions[s.versions.length - 1].version;
    if (!more) { clear(body); body.appendChild(P.skeleton(4)); }
    return api('GET', 'config/history', null, q).then(function (res) {
      if (!res.ok) {
        if (!more) clear(body);
        if (res.status === 404 && !more) { body.appendChild(P.empty('clock', t('تاریخچهٔ تنظیمات روی این سرور فعال نیست'), null)); return; }
        body.appendChild(P.errorBox(res, t('دریافت تاریخچه ممکن نشد')));
        return;
      }
      var d = res.data || {}, rows = Array.isArray(d.versions) ? d.versions.filter(function (v) { return v && typeof v === 'object'; }) : [];
      s.versions = more ? (s.versions || []).concat(rows) : rows;
      s.current = d.current != null ? d.current : (s.versions[0] ? s.versions[0].version : null);
      s.retention = d.retention || s.retention;
      s.more = rows.length >= 25;
      draw(body);
    });
  }

  function draw(body) {
    var s = st();
    clear(body);
    if (!s.versions.length) {
      body.appendChild(P.empty('clock', t('هنوز تغییری ثبت نشده است'), t('از این پس هر تغییر تنظیمات اینجا با زمان و انجام‌دهنده ثبت می‌شود و قابل بازگردانی است.')));
      return;
    }
    var ol = h('ol', { className: 'pcdn-hist' });
    s.versions.forEach(function (v, i) { ol.appendChild(item(v, s.versions[i + 1] || null, body)); });
    body.appendChild(ol);
    var r = s.retention || {};
    var foot = h('div', { className: 'pcdn-hist-foot' },
      r.max_versions ? h('p', { className: 'pcdn-muted pcdn-small', text: t('حداکثر {0} نسخهٔ آخر و تا {1} روز نگه داشته می‌شود.', num(r.max_versions), num(r.days || 0)) }) : null,
      s.more ? P.btn(t('نسخه‌های قدیمی‌تر'), { size: 'sm', icon: 'chevronDown', cls: 'pcdn-hist-more', onclick: function (e) {
        P.busy(e.currentTarget, load(body, true));
      } }) : null);
    body.appendChild(foot);
  }

  function item(v, prev, body) {
    var s = st();
    var cur = v.version === s.current;
    var secs = Array.isArray(v.sections) ? v.sections : [];
    var who = h('span', { className: 'pcdn-hist-who' }, icon(actorIcon(v.actor)), h('span', { text: actorText(v.actor) }));
    var meta = h('div', { className: 'pcdn-hist-meta' }, who,
      h('span', { className: 'pcdn-muted', title: P.date(v.at), text: P.rel(v.at) }),
      v.source ? P.badge(SOURCE[v.source] || String(v.source), v.source === 'restore' ? 'violet' : v.source === 'import' ? 'brand' : 'muted') : null,
      cur ? P.badge(t('تنظیمات فعلی'), 'success') : null);
    var chips = h('div', { className: 'pcdn-hist-secs' }, secs.map(function (x) { return h('span', { className: 'pcdn-chip', 'data-section': String(x), text: secLabel(x) }); }));
    var acts = [P.btn(t('مشاهدهٔ تغییرات'), { size: 'sm', icon: 'eye', cls: 'pcdn-hist-diff', onclick: function () { diffDialog(v, prev); } })];
    acts[0].setAttribute('data-ro-ok', '1');
    if (!cur) {
      acts.push(P.btn(t('بازگردانی این نسخه…'), { size: 'sm', icon: 'refresh', write: true, cls: 'pcdn-hist-restore', disabled: v.restorable === false,
        title: v.restorable === false ? t('این نسخه قابل بازگردانی نیست') : null, onclick: function () { restoreDialog(v, body); } }));
    }
    return h('li', { className: 'pcdn-hist-item' + (cur ? ' is-current' : ''), 'data-version': String(v.version) },
      h('div', { className: 'pcdn-hist-dot', 'aria-hidden': 'true' }),
      h('div', { className: 'pcdn-hist-main' },
        h('div', { className: 'pcdn-hist-title' }, h('strong', { text: t('نسخهٔ {0}', num(v.version)) }),
          v.restored_from != null ? h('span', { className: 'pcdn-muted pcdn-small', text: t('بازگردانی از نسخهٔ {0}', num(v.restored_from)) }) : null),
        meta, chips, h('div', { className: 'pcdn-row-actions' }, acts)));
  }

  // ------------------------------------------------------------------ diff

  function shortVal(x) {
    if (x === '[redacted]') return t('[پنهان]');
    if (x === undefined) return '—';
    var s;
    try { s = typeof x === 'string' ? x : JSON.stringify(x); } catch (e) { s = String(x); }
    s = String(s).replace(/"\[redacted\]"/g, '"' + t('[پنهان]') + '"');
    return s.length > 400 ? s.slice(0, 399) + '…' : s;
  }
  function opRow(o) {
    var kind = OPS[o.op] || [String(o.op || ''), 'muted'];
    var hasOld = o.op !== 'add', hasNew = o.op !== 'remove';
    var redacted = !!o.redacted;
    return h('li', { className: 'pcdn-diff-op', 'data-op': String(o.op || '') },
      h('div', { className: 'pcdn-diff-head' }, P.badge(kind[0], kind[1]), h('code', { className: 'pcdn-diff-path', dir: 'ltr', text: String(o.path || '/') }),
        redacted ? P.badge(t('مقدار محرمانه'), 'warning', 'lock') : null),
      h('div', { className: 'pcdn-diff-vals' },
        hasOld ? h('div', { className: 'pcdn-diff-old' }, h('span', { className: 'pcdn-diff-lbl', text: t('قبل') }), h('code', { dir: 'ltr', text: redacted ? t('[پنهان]') : shortVal(o.old) })) : null,
        hasNew ? h('div', { className: 'pcdn-diff-new' }, h('span', { className: 'pcdn-diff-lbl', text: t('بعد') }), h('code', { dir: 'ltr', text: redacted ? t('[پنهان]') : shortVal(o.new) })) : null));
  }
  function drawDiff(holder, d) {
    clear(holder);
    var secs = d && d.sections && typeof d.sections === 'object' ? d.sections : {};
    var names = Object.keys(secs).filter(function (k) { return Array.isArray(secs[k]) && secs[k].length; });
    if (!names.length) { holder.appendChild(P.empty('checkCircle', t('تفاوتی وجود ندارد'), null)); return; }
    names.forEach(function (k) {
      var c = h('section', { className: 'pcdn-diff-sec', 'data-diff-section': k },
        h('h4', null, h('span', { text: secLabel(k) }), h('span', { className: 'pcdn-muted pcdn-small', text: t('{0} تغییر', num(secs[k].length)) })),
        h('ul', { className: 'pcdn-diff-ops' }, secs[k].slice(0, 300).map(opRow)));
      holder.appendChild(c);
    });
    if (d.redacted) holder.appendChild(h('p', { className: 'pcdn-muted pcdn-small', text: t('مقدارهای محرمانه (کلیدها، رمزها، هدرهای احراز هویت) نمایش داده نمی‌شوند.') }));
  }
  function diffDialog(v, prev) {
    var d = P.dialog({ title: t('تغییرات نسخهٔ {0}', num(v.version)), icon: 'eye', kind: 'drawer', wide: true, subtitle: P.date(v.at) });
    d.el.classList.add('pcdn-diff-dlg');
    var mode = prev ? 'own' : 'current';
    var holder = h('div', { className: 'pcdn-diff', 'data-diff': '1' });
    var segHost = h('div');
    function seg() {
      clear(segHost);
      var opts = [];
      if (prev) opts.push(['own', t('تغییرات همین نسخه')]);
      if (v.version !== st().current) opts.push(['current', t('تفاوت با تنظیمات فعلی')]);
      if (opts.length > 1) segHost.appendChild(P.segmented(opts, mode, function (m) { mode = m; seg(); fetch(); }, t('نوع مقایسه')));
    }
    function fetch() {
      clear(holder);
      holder.appendChild(P.skeleton(4));
      var req = mode === 'own' ? api('GET', 'config/history/' + prev.version + '/diff', null, { against: String(v.version) })
        : api('GET', 'config/history/' + v.version + '/diff', null, { against: 'current' });
      req.then(function (res) {
        if (!res.ok) { clear(holder); holder.appendChild(P.errorBox(res, t('مقایسه ممکن نشد'))); return; }
        drawDiff(holder, res.data);
        if (mode === 'current') holder.insertBefore(h('p', { className: 'pcdn-muted pcdn-small', text: t('«قبل» = نسخهٔ {0}، «بعد» = تنظیمات فعلی.', num(v.version)) }), holder.firstChild);
      });
    }
    if (!prev && v.version === st().current) {
      append(d.body, P.alertBox('info', t('این اولین نسخهٔ ثبت‌شده است؛ نسخهٔ قبلی برای مقایسه وجود ندارد.')));
    } else {
      append(d.body, [segHost, holder]);
      seg();
      fetch();
    }
    d.foot.appendChild(P.btn(t('بستن'), { onclick: function () { d.close(); } }));
    d.focusFirst();
  }

  // ------------------------------------------------------------------ restore

  var DROP = {
    feature_missing: function () { return t('این بخش به قابلیتی نیاز دارد که در پلن فعلی نیست'); },
    limit: function (x) { return t('فقط {0} مورد اول نگه داشته می‌شود و {1} مورد به‌دلیل سقف پلن حذف می‌شود', num(x.kept || 0), num(x.removed || 0)); },
    invalid: function (x) { return t('با تنظیمات فعلی معتبر نیست') + (x.detail ? ': ' + P.ctlText(String(x.detail)) : ''); },
    not_restorable: function () { return t('این بخش از این نسخه قابل بازگردانی نیست'); }
  };
  function dropText(x) { return (DROP[x.reason] || function () { return P.ctlText(String(x.reason || '')); })(x); }

  function restoreDialog(v, listBody) {
    var d = P.dialog({ title: t('بازگردانی نسخهٔ {0}', num(v.version)), icon: 'refresh', wide: true, subtitle: P.date(v.at) });
    d.el.classList.add('pcdn-restore-dlg');
    var pick = {};   // section → checked
    var checks = h('div', { className: 'pcdn-restore-secs', 'data-restore-secs': '1' });
    var preview = h('div', { className: 'pcdn-restore-preview', 'data-restore-preview': '1' }, P.skeleton(3));
    var confirmBtn = P.btn(t('بازگردانی'), { kind: 'primary', icon: 'refresh', write: true, cls: 'pcdn-restore-go', disabled: true, onclick: function () { go(); } });
    var again = P.btn(t('پیش‌نمایش دوباره'), { size: 'sm', icon: 'eye', cls: 'pcdn-restore-preview-btn', onclick: function () { dry(selected()); } });
    again.setAttribute('data-ro-ok', '1');
    append(d.body, [h('p', { className: 'pcdn-muted', text: t('بخش‌هایی که با تنظیمات فعلی فرق دارند به حالت این نسخه برمی‌گردند. پیش از اعمال، نتیجه با پلن فعلی بررسی و نمایش داده می‌شود.') }),
      checks, h('div', { className: 'pcdn-row-actions' }, again), preview]);
    append(d.foot, [confirmBtn, P.btn(t('انصراف'), { onclick: function () { d.close(); } })]);
    var known = null;
    function selected() { return Object.keys(pick).filter(function (k) { return pick[k]; }); }
    function drawChecks(r) {
      if (known) return;
      known = (r.applied || []).concat((r.dropped || []).map(function (x) { return x.section; }).filter(function (s) { return (r.applied || []).indexOf(s) < 0; }));
      clear(checks);
      if (!known.length) return;
      checks.appendChild(h('div', { className: 'pcdn-label', text: t('بخش‌ها') }));
      known.forEach(function (s) {
        pick[s] = (r.applied || []).indexOf(s) >= 0;
        var id = P.uid('pcdn-rs-');
        checks.appendChild(h('label', { className: 'pcdn-check', 'for': id, 'data-section': s },
          h('input', { type: 'checkbox', id: id, checked: pick[s], onchange: function (e) { pick[s] = e.target.checked; confirmBtn.disabled = true; } }),
          h('span', { text: secLabel(s) })));
      });
    }
    function drawPreview(r) {
      clear(preview);
      var out = [];
      if ((r.applied || []).length) out.push(P.alertBox('success', [h('strong', { text: t('بازگردانده می‌شود: ') }), (r.applied || []).map(secLabel).join(t('، '))]));
      if ((r.unchanged || []).length) out.push(h('p', { className: 'pcdn-muted pcdn-small', text: t('بدون تغییر (همین حالا هم یکسان است): ') + r.unchanged.map(secLabel).join(t('، ')) }));
      if ((r.dropped || []).length) {
        out.push(P.alertBox('warning', [h('strong', { text: t('بازگردانده نمی‌شود یا تغییر می‌کند:') }),
          h('ul', { className: 'pcdn-errlist' }, r.dropped.map(function (x) {
            return h('li', { 'data-dropped': String(x.section || '') }, h('b', { text: secLabel(x.section) + ': ' }), dropText(x));
          }))]));
      }
      if ((r.warnings || []).length) {
        out.push(P.alertBox('info', h('ul', { className: 'pcdn-errlist' }, r.warnings.map(function (w) { return h('li', { text: P.ctlText(String(w)) }); }))));
      }
      if (!(r.applied || []).length) out.push(P.alertBox('info', t('با این انتخاب چیزی تغییر نمی‌کند.')));
      append(preview, out);
      confirmBtn.disabled = !(r.applied || []).length;
    }
    function dry(secs) {
      clear(preview);
      preview.appendChild(P.skeleton(3));
      confirmBtn.disabled = true;
      return P.busy(again, api('POST', 'config/history/' + v.version + '/restore', { sections: secs && secs.length ? secs : null, dry_run: true })).then(function (res) {
        if (!res.ok) { clear(preview); preview.appendChild(P.errorBox(res, t('پیش‌نمایش ممکن نشد'))); return; }
        drawChecks(res.data || {});
        drawPreview(res.data || {});
      });
    }
    function go() {
      var secs = selected();
      if (!secs.length) { P.toast(t('دست‌کم یک بخش را انتخاب کنید.'), 'error'); return; }
      P.busy(confirmBtn, api('POST', 'config/history/' + v.version + '/restore', { sections: secs, dry_run: false })).then(function (res) {
        if (!res.ok) { clear(preview); preview.appendChild(P.errorBox(res, t('بازگردانی انجام نشد'))); return; }
        var r = res.data || {};
        d.close(true);
        P.toast(r.version != null ? t('نسخهٔ {0} بازگردانده شد (نسخهٔ جدید {1}).', num(v.version), num(r.version)) : t('نسخهٔ {0} بازگردانده شد.', num(v.version)));
        A().reloadSite().then(function () { if (A().S.page === 'history') A().renderMain(); });
      });
    }
    dry(null);
    d.focusFirst();
  }

  pages.history = {
    title: t('تاریخچهٔ تنظیمات'), icon: 'clock', heading: t('تاریخچهٔ تنظیمات'),
    desc: t('هر تغییر تنظیمات سایت با زمان و انجام‌دهنده؛ مقایسهٔ نسخه‌ها و بازگردانی با یک کلیک.'),
    hidden: function () { return W.ok !== true; },
    render: function () { st().versions = null; return render(); }
  };
})();
