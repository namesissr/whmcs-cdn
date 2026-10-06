/*
 * Pasargad CDN — client app: «انتقال از ابر آروان» / «انتقال از Cloudflare» (SPEC §23.6, wave 14).
 *
 * PCDN.importer = {available(), card(), button(provider), open(provider)} — a three-step wizard on the DNS page and in the
 * onboarding guide (records step), offered once the wave-14 probe answered (PCDN.w17):
 *   1. paste the provider API key (password field; «کلید فقط برای همین انتقال استفاده می‌شود و ذخیره نمی‌شود») — it is sent
 *      once with POST import/preview and cleared from the form at once; api.php passes it to the controller without logging it;
 *   2. the dry-run mapping report: records with status badges, sections «قابل انتقال / بخشی / غیرقابل انتقال» with notes, and
 *      everything that cannot be moved;
 *   3. choose records (subset), replace or add, sections → POST import/apply → result. Closing the wizard without applying
 *      forgets the session (DELETE import/<session>).
 * Read-only team users and viewers / DNS managers of a shared domain cannot start it (write buttons, editor role server side).
 * All data reaches the DOM through textContent / createElement only.
 */
(function () {
  'use strict';
  var P = window.PCDN = window.PCDN || {};
  var t = P.t;
  if (!P.h) return;
  var h = P.h, append = P.append, clear = P.clear, icon = P.icon, num = P.num, api = P.api;
  function A() { return P.app; }

  var PROV = {
    arvan: { name: t('ابر آروان'), title: t('انتقال از ابر آروان'), keyLabel: t('کلید API آروان'), placeholder: 'Apikey xxxxxxxx-xxxx-…',
      help: t('در پنل آروان از «پروفایل ← کلیدهای API» یک کلید با دسترسی فقط‌خواندنی بسازید و همین‌جا بچسبانید.'),
      link: 'https://panel.arvancloud.ir/profile/api-keys', linkText: t('ساخت کلید فقط‌خواندنی در پنل آروان') },
    cloudflare: { name: 'Cloudflare', title: t('انتقال از Cloudflare'), keyLabel: t('توکن API کلادفلر'), placeholder: 'xxxxxxxxxxxxxxxxxxxxxxxx',
      help: t('در Cloudflare یک API Token با دسترسی خواندن Zone و DNS بسازید (Zone.Zone Read و Zone.DNS Read).'),
      link: 'https://dash.cloudflare.com/profile/api-tokens', linkText: t('ساخت توکن فقط‌خواندنی در Cloudflare') }
  };
  var RSTATUS = {
    ok: [t('قابل انتقال'), 'success'], duplicate: [t('تکراری'), 'muted'], conflict: [t('تداخل'), 'warning'],
    unsupported: [t('پشتیبانی نمی‌شود'), 'muted'], limit: [t('بیش از سقف پلن'), 'danger'], invalid: [t('نامعتبر'), 'danger']
  };
  var SSTATUS = { maps: [t('قابل انتقال'), 'success'], partial: [t('بخشی'), 'warning'], none: [t('غیرقابل انتقال'), 'muted'] };
  var SECTIONS = ['cache', 'ssl', 'firewall', 'redirects', 'ddos', 'ratelimit'];
  function secLabel(s) { return P.sectionLabel ? P.sectionLabel(s) : s; }

  function available() {
    var a = A();
    return !!a && !a.admin && !(a.inSubSite && a.inSubSite()) && !!(P.w17 && P.w17.wave && P.w17.wave());
  }

  function button(provider, o) {
    o = o || {};
    var p = PROV[provider] || PROV.arvan;
    return P.btn(p.title, { size: o.size || 'sm', icon: 'swap', write: true, kind: o.kind, cls: 'pcdn-import-open', onclick: function () { open(provider); } });
  }

  /** DNS page card; filled once the wave-14 probe answered (empty element otherwise). */
  function card() {
    var slot = h('div', { 'data-import-slot': '1' });
    function fill(ok) {
      clear(slot);
      if (!ok && !available()) return;
      if (!available()) return;
      var c = P.card({ title: t('انتقال از سرویس دیگر'), icon: 'swap', id: 'import', tone: 'brand',
        subtitle: t('رکوردها و تنظیمات اصلی را با یک کلید فقط‌خواندنی از ابر آروان یا Cloudflare بیاورید؛ پیش از اعمال، گزارش کامل را می‌بینید.') });
      append(c.body, h('div', { className: 'pcdn-row-actions' }, button('arvan', { kind: 'primary' }), button('cloudflare')));
      slot.appendChild(c);
      if (A().lockWrites) A().lockWrites(slot);
    }
    if (P.w17 && P.w17.ready) P.w17.ready(fill); else fill(false);
    return slot;
  }

  function open(provider) {
    var p = PROV[provider] || PROV.arvan;
    var d = P.dialog({ title: p.title, icon: 'swap', kind: 'drawer', wide: true, subtitle: A().S.site.domain,
      onClose: function () { forget(); } });
    d.el.classList.add('pcdn-import-dlg');
    d.el.setAttribute('data-import-provider', provider);
    var st = { session: null, report: null, step: 1, applied: false };
    function forget() {
      if (st.session && !st.applied) api('DELETE', 'import/' + st.session);
      st.session = null;
    }
    var steps = h('ol', { className: 'pcdn-wiz-steps' }, [t('کلید'), t('پیش‌نمایش'), t('اعمال')].map(function (x, i) {
      return h('li', { 'data-step': String(i + 1), text: x });
    }));
    var body = h('div', { className: 'pcdn-import-body' });
    append(d.body, [steps, body]);
    function mark(n) {
      st.step = n;
      Array.prototype.forEach.call(steps.children, function (li, i) { li.classList.toggle('is-on', i + 1 === n); li.classList.toggle('is-done', i + 1 < n); });
      clear(d.foot);
    }

    // -------- step 1: key
    function step1(err) {
      mark(1);
      clear(body);
      var m = { key: '', zone: A().S.site.domain };
      var keyInput = h('input', { type: 'password', className: 'pcdn-input pcdn-ltr', dir: 'ltr', autocomplete: 'off', spellcheck: 'false', maxlength: 512,
        placeholder: p.placeholder, 'aria-label': p.keyLabel, 'data-import-key': '1', oninput: function (e) { m.key = e.target.value; } });
      append(body, [
        P.alertBox('info', [h('strong', { text: t('کلید فقط برای همین انتقال استفاده می‌شود و ذخیره نمی‌شود. ') }),
          t('فقط اطلاعات خوانده‌شده (رکوردها و تنظیمات) تا ۳۰ دقیقه برای پیش‌نمایش رمزنگاری‌شده نگه داشته می‌شود و با اعمال یا بستن این پنجره پاک می‌شود.')], { icon: 'lock' }),
        P.field(p.keyLabel, keyInput, { help: p.help }),
        h('a', { className: 'pcdn-link', href: p.link, target: '_blank', rel: 'noopener noreferrer', 'data-ro-ok': '1' }, h('span', { text: p.linkText }), icon('external')),
        P.input(m, 'zone', t('دامنه در سرویس قبلی'), { maxlength: 253, help: t('معمولاً همین دامنه است.') }),
        err || null]);
      var next = P.btn(t('دریافت و پیش‌نمایش'), { kind: 'primary', icon: 'eye', write: true, cls: 'pcdn-import-preview', onclick: function () {
        var key = String(m.key || '').trim();
        if (!key) { P.toast(t('کلید API را وارد کنید.'), 'error'); return; }
        var zone = String(m.zone || '').trim().toLowerCase();
        // the key leaves the page once and is forgotten right away
        m.key = ''; keyInput.value = '';
        var req = { provider: provider, api_key: key };
        key = '';
        if (zone) req.zone = zone;
        P.busy(next, api('POST', 'import/preview', req)).then(function (res) {
          req.api_key = '';
          if (!res.ok) { step1(previewError(res)); return; }
          st.session = res.data && res.data.session_id;
          st.report = (res.data && res.data.report) || {};
          step2();
        });
      } });
      append(d.foot, [next, P.btn(t('انصراف'), { onclick: function () { d.close(); } })]);
      if (A().lockWrites) A().lockWrites(d.el);
      keyInput.focus();
    }
    function previewError(res) {
      var det = res.data && res.data.detail;
      var msg = det === 'provider_auth' ? t('کلید پذیرفته نشد؛ درستی و دسترسی‌های آن را بررسی کنید.')
        : det === 'provider_zone_not_found' ? t('این دامنه در حساب سرویس قبلی پیدا نشد.')
        : det === 'provider_unreachable' ? t('سرویس قبلی پاسخ نداد؛ کمی بعد دوباره تلاش کنید.')
        : res.status === 429 ? t('تعداد پیش‌نمایش‌ها در این ساعت به سقف رسیده است.')
        : res.status === 404 ? t('انتقال از سرویس دیگر روی این سرور فعال نیست.')
        : det === 'invalid request' ? t('کلید یا دامنه معتبر نیست؛ دوباره بررسی کنید.')
        : P.errorText(res);
      return P.alertBox('danger', msg);
    }

    // -------- step 2: report + choices
    var pick = { names: {}, sections: {}, replace: false };
    function step2() {
      mark(2);
      clear(body);
      var r = st.report || {}, rec = r.records || {}, items = Array.isArray(rec.items) ? rec.items.filter(function (x) { return x && typeof x === 'object'; }) : [];
      var secs = r.sections && typeof r.sections === 'object' ? r.sections : {};
      var unm = Array.isArray(r.unmapped) ? r.unmapped : [];
      pick.names = {};
      items.forEach(function (x) { if (x.status === 'ok') pick.names[x.name + '|' + x.type + '|' + x.content] = true; });
      // records
      var rc = P.card({ title: t('رکوردهای DNS'), icon: 'server', id: 'import-records',
        subtitle: t('{0} رکورد پیدا شد؛ {1} رکورد قابل انتقال است.', num(rec.total || items.length), num(rec.importable != null ? rec.importable : items.filter(function (x) { return x.status === 'ok'; }).length)) });
      if (items.length) {
        var tb = h('tbody', null, items.slice(0, 2000).map(function (x) {
          var k = x.name + '|' + x.type + '|' + x.content, s = RSTATUS[x.status] || [String(x.status || ''), 'muted'];
          var id = P.uid('pcdn-ir-');
          return h('tr', { 'data-import-record': k, 'data-status': String(x.status || '') },
            h('td', null, x.status === 'ok' ? h('input', { type: 'checkbox', id: id, checked: true, 'aria-label': t('انتقال این رکورد'),
              onchange: function (e) { pick.names[k] = e.target.checked; } }) : null),
            h('td', { 'data-label': t('نام') }, h('bdi', { dir: 'ltr', text: String(x.name || '@') })),
            h('td', { 'data-label': t('نوع'), text: String(x.type || '') }),
            h('td', { 'data-label': t('مقدار') }, h('bdi', { dir: 'ltr', className: 'pcdn-import-content', text: String(x.content || '') })),
            h('td', { 'data-label': t('پروکسی') }, x.proxied ? icon('cloud') : h('span', { className: 'pcdn-muted', text: '—' })),
            h('td', { 'data-label': t('وضعیت') }, P.badge(s[0], s[1]), x.reason ? h('div', { className: 'pcdn-muted pcdn-small', text: P.ctlText(String(x.reason)) }) : null));
        }));
        rc.body.appendChild(h('div', { className: 'pcdn-table-wrap pcdn-import-records' }, h('table', { className: 'pcdn-table pcdn-rtable' },
          h('thead', null, h('tr', null, ['', t('نام'), t('نوع'), t('مقدار'), t('پروکسی'), t('وضعیت')].map(function (x) { return h('th', { scope: 'col', text: x }); }))), tb)));
      } else rc.body.appendChild(P.empty('server', t('رکوردی پیدا نشد'), null));
      rc.body.appendChild(P.toggle(pick, 'replace', t('جایگزینی کامل رکوردهای فعلی'), { cls: 'pcdn-import-replace',
        help: t('اگر خاموش باشد، رکوردهای انتخاب‌شده به رکوردهای فعلی اضافه می‌شوند و تکراری‌ها نادیده گرفته می‌شوند.') }));
      // sections
      var sc = P.card({ title: t('تنظیمات'), icon: 'sliders', id: 'import-sections' });
      var any = false;
      pick.sections = {};
      Object.keys(secs).forEach(function (k) {
        var x = secs[k] || {}, s = SSTATUS[x.status] || SSTATUS.none;
        var can = x.status !== 'none' && SECTIONS.indexOf(k) >= 0;
        if (can) { pick.sections[k] = true; any = true; }
        var id = P.uid('pcdn-is-');
        sc.body.appendChild(h('div', { className: 'pcdn-import-sec', 'data-import-section': k, 'data-status': String(x.status || 'none') },
          h('div', { className: 'pcdn-import-sec-head' },
            can ? h('input', { type: 'checkbox', id: id, checked: true, onchange: function (e) { pick.sections[k] = e.target.checked; } }) : null,
            h('label', { 'for': can ? id : null, text: secLabel(k) }), P.badge(s[0], s[1])),
          (x.notes || []).length ? h('ul', { className: 'pcdn-muted pcdn-small' }, x.notes.map(function (n) { return h('li', { text: P.ctlText(String(n)) }); })) : null));
      });
      if (!Object.keys(secs).length) sc.body.appendChild(P.empty('sliders', t('تنظیمی برای انتقال پیدا نشد'), null));
      // unmapped
      var uc = unm.length ? P.collapsible({ title: t('غیرقابل انتقال ({0})', num(unm.length)), icon: 'warn', tone: 'muted', id: 'import-unmapped' }) : null;
      if (uc) uc.body.appendChild(h('ul', { className: 'pcdn-import-unmapped' }, unm.map(function (x) {
        return h('li', null, h('strong', { text: P.ctlText(String((x && x.what) || '')) }), x && x.reason ? h('span', { className: 'pcdn-muted', text: ' — ' + P.ctlText(String(x.reason)) }) : null);
      })));
      append(body, [P.alertBox('info', t('این فقط پیش‌نمایش است؛ تا «اعمال» را نزنید چیزی تغییر نمی‌کند. گواهی‌های SSL هیچ‌وقت منتقل نمی‌شوند؛ گواهی رایگان خودکار صادر می‌شود.')),
        rc, sc, uc]);
      var apply = P.btn(t('اعمال انتقال'), { kind: 'primary', icon: 'check', write: true, cls: 'pcdn-import-apply', onclick: function () { doApply(apply); } });
      append(d.foot, [apply, P.btn(t('بازگشت'), { onclick: function () { forget(); step1(); } }), P.btn(t('انصراف'), { onclick: function () { d.close(); } })]);
      if (!any && !items.some(function (x) { return x.status === 'ok'; })) apply.disabled = true;
      if (A().lockWrites) A().lockWrites(d.el);
    }

    function doApply(btn) {
      var all = Object.keys(pick.names), names = all.filter(function (k) { return pick.names[k]; });
      var nameList = [];
      names.forEach(function (k) { var n = k.split('|')[0]; if (nameList.indexOf(n) < 0) nameList.push(n); });
      var every = names.length === all.length;
      var secs = Object.keys(pick.sections).filter(function (k) { return pick.sections[k]; });
      if (!nameList.length && !secs.length) { P.toast(t('چیزی برای انتقال انتخاب نشده است.'), 'error'); return; }
      var go = pick.replace ? P.confirm({ title: t('جایگزینی همه رکوردها'), danger: true, ok: t('حذف و جایگزینی'),
        body: t('همه {0} رکورد فعلی حذف و رکوردهای انتخاب‌شده جایگزین آن‌ها می‌شوند.', num((A().S.site.records || []).length)) }) : Promise.resolve(true);
      go.then(function (ok) {
        if (!ok) return;
        P.busy(btn, api('POST', 'import/apply', { session_id: st.session, records: nameList.length > 0, replace_records: !!pick.replace,
          record_names: every ? null : nameList, sections: secs })).then(function (res) {
          if (!res.ok) {
            if (res.status === 404 || res.status === 410) { st.session = null; step1(P.alertBox('danger', t('نشست انتقال منقضی شده است؛ دوباره پیش‌نمایش بگیرید.'))); return; }
            body.insertBefore(P.errorBox(res, t('انتقال انجام نشد')), body.firstChild);
            return;
          }
          st.applied = true;
          st.session = null;
          step3(res.data || {});
        });
      });
    }

    // -------- step 3: result
    function step3(r) {
      mark(3);
      clear(body);
      var rec = r.records || {}, sec = r.sections || {};
      var out = [P.alertBox('success', [h('strong', { text: t('انتقال انجام شد. ') }), t('{0} رکورد وارد شد.', num(rec.imported || 0))])];
      if ((sec.applied || []).length) out.push(h('p', { 'data-import-applied': (sec.applied || []).join(','), text: t('تنظیمات اعمال‌شده: ') + sec.applied.map(secLabel).join(t('، ')) }));
      if ((rec.skipped || []).length) out.push(P.alertBox('warning', [h('strong', { text: t('{0} رکورد وارد نشد:', num(rec.skipped.length)) }),
        h('ul', { className: 'pcdn-errlist' }, rec.skipped.slice(0, 100).map(function (x) { return h('li', null, h('bdi', { dir: 'ltr', text: String(x.name || x.line || '') }), ' — ', P.ctlText(String(x.reason || ''))); }))]));
      if ((sec.warnings || []).length) out.push(P.alertBox('info', h('ul', { className: 'pcdn-errlist' }, sec.warnings.map(function (w) { return h('li', { text: P.ctlText(String(w)) }); }))));
      if ((sec.dropped || []).length) out.push(P.alertBox('warning', [h('strong', { text: t('تنظیماتی که اعمال نشد:') }),
        h('ul', { className: 'pcdn-errlist' }, sec.dropped.map(function (x) { return h('li', { text: secLabel(x.section) + ' — ' + P.ctlText(String(x.reason || '')) }); }))]));
      if (r.dns_error) out.push(P.alertBox('danger', t('رکوردها ذخیره شد ولی به‌روزرسانی DNS با خطا روبه‌رو شد؛ سیستم دوباره تلاش می‌کند.')));
      if (r.config_version != null) out.push(h('p', { className: 'pcdn-muted pcdn-small', text: t('این تغییر در «تاریخچهٔ تنظیمات» به‌عنوان نسخهٔ {0} ثبت شد و قابل بازگردانی است.', num(r.config_version)) }));
      out.push(h('p', { className: 'pcdn-muted', text: t('پروکسی رکوردهای وب (مثل @ و www) را بررسی کنید و سپس نیم‌سرورها را تغییر دهید.') }));
      append(body, out);
      d.foot.appendChild(P.btn(t('بستن'), { kind: 'primary', onclick: function () { d.close(); } }));
      A().reloadSite().then(function () { if (A().S.page === 'dns' || A().S.page === 'overview') A().renderMain(); });
    }
    step1();
  }

  P.importer = { available: available, card: card, button: button, open: open };
})();
