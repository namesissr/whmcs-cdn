/*
 * Pasargad CDN — client app: «نمایندگی» reseller panel (SPEC §10.5).
 *
 * Shown only to reseller accounts (boot.reseller.enabled). Lets a reseller
 * provision and manage CDN sub-sites for their OWN end-customers, see a
 * rolled-up usage & cost report across all sub-sites, and open any one of them
 * in the full site-management UI (App.openSubSite → the whole app re-points at
 * that sub-site; api calls then carry its id so the server resolves the domain
 * from the reseller's own row — never from client input).
 *
 * Every call goes through api.php reseller ops (rop) or the reseller-site proxy
 * (rsid); CSRF + tenant ownership are enforced server-side.
 */
(function () {
  'use strict';
  var P = window.PCDN = window.PCDN || {};
  var t = P.t;  // i18n.js (SPEC §16.10)
  if (!P.h) return;
  var h = P.h, append = P.append, clear = P.clear, icon = P.icon, num = P.num, num1 = P.num1, api = P.api;

  /** Marks a reseller write button so a read-only team member (§14.3.7) gets it disabled; api.php refuses the op anyway. */
  function team(b) { b.setAttribute('data-team-write', '1'); return b; }

  function money(v, unit) {
    v = Number(v) || 0;
    var s = v >= 100 ? num(Math.round(v)) : num(Math.round(v * 100) / 100);
    return s + (unit ? ' ' + unit : '');
  }

  // ------------------------------------------------------------------ data

  function loadReport() {
    return api('GET', '', undefined, { rop: 'report' }).then(function (res) {
      return res.ok ? res.data : { _error: (res.data && res.data.detail) || t('دریافت گزارش ناموفق بود.') };
    });
  }

  // ------------------------------------------------------------------ cards

  function summaryCard(App, rep) {
    var unit = rep.currency || '';
    var c = P.card({ title: t('خلاصه نمایندگی'), icon: 'wallet', id: 'reseller-summary', tone: 'brand',
      subtitle: rep.month || '' });
    var rate = Number(rep.rate) || 0;
    append(c.body, h('dl', { className: 'pcdn-dl' },
      h('div', null, h('dt', { text: t('تعداد زیرسایت') }), h('dd', { text: num((rep.sites || []).length) + (App.reseller && App.reseller.max_sites ? ' / ' + num(App.reseller.max_sites) : '') })),
      h('div', null, h('dt', { text: t('مصرف این ماه') }), h('dd', { text: num1(Number(rep.total_gb) || 0) + t(' گیگابایت') })),
      h('div', null, h('dt', { text: t('قیمت هر گیگابایت (عمده)') }), h('dd', { text: rate > 0 ? money(rate, unit) : '—' })),
      h('div', null, h('dt', { text: t('هزینه تخمینی این ماه') }), h('dd', { text: money(rep.total_cost, unit) })),
      h('div', null, h('dt', { text: t('اعتبار کیف پول') }), h('dd', { text: money(rep.credit, unit) }))));
    if (rep._error) c.body.appendChild(h('p', { className: 'pcdn-muted pcdn-small', text: t('مصرف لحظه‌ای در دسترس نیست: ') + rep._error }));
    else if (rep.error) c.body.appendChild(h('p', { className: 'pcdn-muted pcdn-small', text: t('مصرف لحظه‌ای بخشی از سایت‌ها در دسترس نیست.') }));
    c.body.appendChild(h('p', { className: 'pcdn-muted pcdn-small',
      text: t('هزینه از مصرف مجموع زیرسایت‌ها × قیمت عمده محاسبه می‌شود و از کیف پول شما به‌صورت خودکار تأمین می‌گردد. با اتمام اعتبار، زیرسایت‌ها موقتاً قطع و پس از شارژ دوباره وصل می‌شوند.') }));
    return c;
  }

  function createCard(App, rep, refresh) {
    var max = (App.reseller && App.reseller.max_sites) || 0;
    var full = max > 0 && (rep.sites || []).length >= max;
    var c = P.card({ title: t('ساخت زیرسایت جدید'), icon: 'plus', id: 'reseller-create' });
    if (full) {
      c.body.appendChild(P.alertBox('warning', t('به سقف تعداد زیرسایت‌های مجاز (') + num(max) + t(') رسیده‌اید. برای افزایش سقف با پشتیبانی تماس بگیرید.')));
      return c;
    }
    var domain = h('input', { className: 'pcdn-input', dir: 'ltr', placeholder: 'example.com', 'data-ro-ok': '1', 'aria-label': t('دامنه') });
    var origin = h('input', { className: 'pcdn-input', dir: 'ltr', placeholder: '185.10.20.30', 'data-ro-ok': '1', 'aria-label': t('آی‌پی سرور اصلی') });
    var label = h('input', { className: 'pcdn-input', placeholder: t('نام مشتری نهایی'), 'data-ro-ok': '1', maxlength: 120, 'aria-label': t('نام مشتری نهایی') });
    var msg = h('div', { className: 'pcdn-form-errors' });
    function row(lbl, help, ctl) {
      return h('div', { className: 'pcdn-field' }, h('label', { className: 'pcdn-label', text: lbl }), ctl,
        help ? h('p', { className: 'pcdn-hint', text: help }) : null);
    }
    var submit = P.btn(t('ساخت سایت'), { kind: 'primary', icon: 'plus', onclick: function () {
      clear(msg);
      var body = { domain: (domain.value || '').trim(), origin_ip: (origin.value || '').trim(), label: (label.value || '').trim() };
      if (!body.domain || !body.origin_ip || !body.label) {
        msg.appendChild(P.alertBox('danger', t('دامنه، آی‌پی سرور اصلی و نام مشتری نهایی الزامی است.')));
        return;
      }
      P.busy(submit, api('POST', '', body, { rop: 'create' })).then(function (res) {
        if (res.ok) {
          P.toast(t('زیرسایت ') + body.domain + t(' ساخته شد.'), 'success');
          domain.value = origin.value = label.value = '';
          refresh();
        } else {
          msg.appendChild(P.alertBox('danger', (res.data && res.data.detail) || t('ساخت زیرسایت ناموفق بود.')));
        }
      });
    } });
    append(c.body, [
      row(t('دامنه'), t('دامنه سایت مشتری نهایی، بدون http و www.'), domain),
      row(t('آی‌پی سرور اصلی (Origin)'), t('آدرس IPv4 عمومی سروری که محتوای سایت روی آن است.'), origin),
      row(t('نام مشتری نهایی'), t('برای شناسایی این سایت در گزارش‌ها؛ فقط شما آن را می‌بینید.'), label),
      msg,
      h('div', { className: 'pcdn-row-actions' }, team(submit))
    ]);
    return c;
  }

  // ------------------------------------------------------------------ growth: limits, white-label, bulk, CSV

  function limitsCard(App, rep) {
    var L = rep.limits;
    if (!L || typeof L !== 'object') return null;
    var unit = rep.currency || '';
    var c = P.card({ title: t('سقف‌ها و محدودیت‌ها'), icon: 'gauge', id: 'reseller-limits' });
    var max = Number(L.max_sites) || 0, used = Number(L.sites) || 0;
    function row(k, dt, dd) { return h('div', { 'data-limit': k }, h('dt', { text: dt }), h('dd', { text: dd })); }
    append(c.body, [
      h('dl', { className: 'pcdn-dl' },
        row('sites', t('زیرسایت‌ها'), max > 0 ? t('{0} از {1}', num(used), num(max)) : t('{0} (بدون سقف جداگانه)', num(used))),
        row('held', t('متوقف‌شده توسط شما'), num(L.held || 0)),
        row('rate', t('قیمت هر گیگابایت (عمده)'), Number(rep.rate) > 0 ? money(rep.rate, unit) : '—'),
        row('block', t('بسته خرید خودکار ترافیک'), t('{0} گیگابایت', num(L.block_gb || 0))),
        row('blocks', t('خرید خودکار این ماه'), Number(L.max_blocks) > 0 ? t('{0} از {1} بسته', num(L.blocks_month || 0), num(L.max_blocks)) : t('{0} بسته', num(L.blocks_month || 0))),
        row('plan', t('امکانات هر زیرسایت'), [L.site_plan && L.site_plan.ssl ? 'SSL' : null, L.site_plan && L.site_plan.waf ? 'WAF' : null, L.site_plan && L.site_plan.ddos ? 'DDoS' : null].filter(Boolean).join(' · ') || '—')),
      max > 0 ? P.meter(used / max, used >= max ? 'danger' : used / max >= 0.8 ? 'warning' : 'brand') : null]);
    return c;
  }

  var LOGO_TYPES = /^image\/(png|jpeg|webp|gif)$/;
  function brandCard(App, refreshHeader) {
    var cur = (App.reseller && App.reseller.brand) || { name: '', logo: null };
    var st = { name: cur.name || '', logo: cur.logo || null, changedLogo: false };
    var c = P.card({ title: t('برند شما (وایت‌لیبل)'), icon: 'star', id: 'reseller-brand',
      subtitle: t('هنگام مدیریت زیرسایت‌ها، نام و لوگوی شما به‌جای نام پاسارگاد در سربرگ پنل نمایش داده می‌شود.') });
    var preview = h('div', { className: 'pcdn-brand-preview', 'data-brand-preview': '1' });
    function drawPreview() {
      clear(preview);
      if (st.logo) preview.appendChild(h('img', { src: st.logo, alt: '', className: 'pcdn-brand-logo' }));
      preview.appendChild(h('span', { text: st.name || t('پاسارگاد CDN') }));
    }
    var name = h('input', { className: 'pcdn-input', maxlength: 60, value: st.name, 'aria-label': t('نام برند'), placeholder: t('مثلاً هاست نمونه'),
      oninput: function () { st.name = name.value; drawPreview(); } });
    var msg = h('div', { className: 'pcdn-form-errors' });
    var file = h('input', { type: 'file', accept: 'image/png,image/jpeg,image/webp,image/gif', className: 'pcdn-input', 'aria-label': t('لوگو'),
      onchange: function () {
        clear(msg);
        var f = file.files && file.files[0];
        if (!f) return;
        if (!LOGO_TYPES.test(f.type) || f.size > 65536) {
          msg.appendChild(P.alertBox('danger', t('لوگو باید تصویر PNG، JPEG، WebP یا GIF و حداکثر ۶۴ کیلوبایت باشد.')));
          file.value = '';
          return;
        }
        var rd = new window.FileReader();
        rd.onload = function () { st.logo = String(rd.result || ''); st.changedLogo = true; drawPreview(); };
        rd.readAsDataURL(f);
      } });
    var clearLogo = P.btn(t('حذف لوگو'), { size: 'sm', icon: 'trash', onclick: function () { st.logo = null; st.changedLogo = true; file.value = ''; drawPreview(); } });
    var save = P.btn(t('ذخیره برند'), { kind: 'primary', icon: 'check', onclick: function () {
      clear(msg);
      var body = { name: (st.name || '').trim() };
      if (st.changedLogo) body.logo = st.logo || '';
      P.busy(save, api('POST', '', body, { rop: 'brand' })).then(function (res) {
        if (!res.ok) { msg.appendChild(P.alertBox('danger', (res.data && res.data.detail) || t('ذخیره برند ممکن نشد.'))); return; }
        var b = res.data && res.data.brand;
        if (App.reseller) App.reseller.brand = b && (b.name || b.logo) ? b : null;
        st.changedLogo = false;
        P.toast(t('برند ذخیره شد.'), 'success');
        if (refreshHeader) refreshHeader();
      });
    } });
    drawPreview();
    append(c.body, [
      h('div', { className: 'pcdn-field' }, h('label', { className: 'pcdn-label', text: t('نام برند') }), name),
      h('div', { className: 'pcdn-field' }, h('label', { className: 'pcdn-label', text: t('لوگو') }), file,
        h('p', { className: 'pcdn-hint', text: t('PNG، JPEG، WebP یا GIF تا ۶۴ کیلوبایت؛ بهتر است مربعی و دست‌کم ۶۴ پیکسل باشد.') })),
      h('div', { className: 'pcdn-field' }, h('span', { className: 'pcdn-label', text: t('پیش‌نمایش سربرگ') }), preview),
      msg, h('div', { className: 'pcdn-row-actions' }, team(save), team(clearLogo))]);
    return c;
  }

  /** Saves the CSV the server built (formula-safe) through a Blob download. */
  function exportCsv(btn) {
    P.busy(btn, api('GET', '', undefined, { rop: 'export' })).then(function (res) {
      if (!res.ok || !res.data || typeof res.data.csv !== 'string') { P.toast((res.data && res.data.detail) || t('دریافت خروجی ناموفق بود.'), 'error'); return; }
      if (!(window.Blob && window.URL && URL.createObjectURL)) { P.toast(t('مرورگر شما دانلود فایل را پشتیبانی نمی‌کند.'), 'error'); return; }
      var a = h('a', { href: URL.createObjectURL(new Blob([res.data.csv], { type: 'text/csv;charset=utf-8' })), download: res.data.filename || 'reseller-usage.csv', hidden: true, 'data-csv-link': '1' });
      document.body.appendChild(a);
      a.click();
      setTimeout(function () { if (a.parentNode) a.parentNode.removeChild(a); }, 1000);
      P.toast(t('خروجی CSV مصرف {0} زیرسایت آماده شد.', num(res.data.rows || 0)), 'success');
    });
  }

  function sitesCard(App, rep, refresh) {
    var unit = rep.currency || '';
    var csv = P.btn(t('خروجی CSV'), { size: 'sm', icon: 'download', cls: 'pcdn-reseller-csv', onclick: function () { exportCsv(csv); } });
    csv.setAttribute('data-ro-ok', '1');
    var c = P.card({ title: t('زیرسایت‌ها (') + num((rep.sites || []).length) + ')', icon: 'globe', id: 'reseller-sites',
      actions: (rep.sites || []).length ? csv : null });
    if (!(rep.sites || []).length) {
      c.body.appendChild(P.empty('globe', t('هنوز زیرسایتی نساخته‌اید'),
        t('با فرم بالا اولین سایت CDN مشتری نهایی خود را بسازید؛ سپس می‌توانید DNS، کش، امنیت و SSL آن را مدیریت کنید.')));
      return c;
    }
    var tbody = h('tbody');
    var picked = {};
    var bar = h('div', { className: 'pcdn-bulk-bar', 'data-bulk': '1' });
    var countEl = h('span', { className: 'pcdn-muted' });
    function ids() { return Object.keys(picked).filter(function (k) { return picked[k]; }).map(Number); }
    function bulk(action, b) {
      var list = ids();
      if (!list.length) { P.toast(t('ابتدا زیرسایت‌ها را انتخاب کنید.'), 'error'); return; }
      P.confirm({ title: action === 'suspend' ? t('توقف موقت زیرسایت‌ها') : t('ادامه کار زیرسایت‌ها'), danger: action === 'suspend',
        ok: action === 'suspend' ? t('توقف موقت') : t('ادامه کار'), cancel: t('انصراف'),
        body: action === 'suspend' ? t('{0} زیرسایت موقتاً از CDN خارج می‌شوند و بازدیدکنندگان صفحه تعلیق را می‌بینند. تنظیمات آن‌ها حفظ می‌شود.', num(list.length))
          : t('{0} زیرسایت دوباره از CDN سرویس می‌گیرند (مگر اینکه به‌دلیل اتمام اعتبار قطع باشند).', num(list.length)) }).then(function (ok) {
        if (!ok) return;
        P.busy(b, api('POST', '', { ids: list, action: action }, { rop: 'bulk' })).then(function (res) {
          if (!res.ok) { P.toast((res.data && res.data.detail) || t('عملیات ناموفق بود.'), 'error'); return; }
          var d = res.data || {}, done = (d.done || []).length, skipped = (d.skipped || []).length;
          P.toast(t('{0} زیرسایت انجام شد', num(done)) + (skipped ? t('، {0} مورد بدون تغییر', num(skipped)) : '') + '.', done ? 'success' : 'warn');
          refresh();
        });
      });
    }
    var pause = P.btn(t('توقف موقت'), { size: 'sm', kind: 'danger', icon: 'ban', cls: 'pcdn-bulk-suspend', onclick: function () { bulk('suspend', pause); } });
    var resume = P.btn(t('ادامه کار'), { size: 'sm', icon: 'play', cls: 'pcdn-bulk-unsuspend', onclick: function () { bulk('unsuspend', resume); } });
    function upd() {
      var n = ids().length;
      countEl.textContent = n ? t('{0} مورد انتخاب شده', num(n)) : t('برای عملیات گروهی، زیرسایت‌ها را انتخاب کنید.');
      pause.disabled = resume.disabled = !n || !!App.readonly;
    }
    append(bar, [countEl, team(pause), team(resume)]);
    var all = h('input', { type: 'checkbox', className: 'pcdn-bulk-all', 'aria-label': t('انتخاب همه'), 'data-ro-ok': '1', onchange: function () {
      rep.sites.forEach(function (s) { picked[s.id] = all.checked; });
      Array.prototype.forEach.call(tbody.querySelectorAll('.pcdn-bulk-one'), function (x) { x.checked = all.checked; });
      upd();
    } });
    rep.sites.forEach(function (s) {
      var one = h('input', { type: 'checkbox', className: 'pcdn-bulk-one', 'aria-label': t('انتخاب ') + s.domain, 'data-ro-ok': '1',
        onchange: function () { picked[s.id] = one.checked; upd(); } });
      var manage = P.btn(t('مدیریت'), { size: 'sm', icon: 'sliders', onclick: function () { App.openSubSite(s.id, { label: s.label }); } });
      var del = P.btn(t('حذف'), { size: 'sm', kind: 'danger', icon: 'trash', onclick: function () {
        P.confirm({ title: t('حذف زیرسایت'), danger: true, ok: t('حذف'), cancel: t('انصراف'),
          body: t('زیرسایت «') + s.domain + t('» برای همیشه از CDN حذف می‌شود و محتوای آن دیگر از CDN عبور نمی‌کند. ادامه می‌دهید؟') }).then(function (ok) {
          if (!ok) return;
          api('POST', '', { id: s.id }, { rop: 'delete' }).then(function (res) {
            if (res.ok) { P.toast(t('زیرسایت حذف شد.'), 'success'); refresh(); }
            else P.toast((res.data && res.data.detail) || t('حذف ناموفق بود.'), 'error');
          });
        });
      } });
      tbody.appendChild(h('tr', { 'data-rsite': String(s.id) },
        h('td', null, one),
        h('td', { className: 'pcdn-nowrap' }, h('span', { dir: 'ltr', text: s.domain }), s.suspended ? h('div', null, P.badge(t('قطع (اعتبار)'), 'danger')) : null,
          s.held ? h('div', null, P.badge(t('متوقف (توسط شما)'), 'warning')) : null),
        h('td', { text: s.label || '—' }),
        h('td', { className: 'pcdn-num', text: num1(Number(s.gb) || 0) }),
        h('td', { className: 'pcdn-num', text: money(s.cost, unit) }),
        h('td', null, h('div', { className: 'pcdn-row-actions' }, manage, team(del)))));
    });
    append(c.body, h('div', { className: 'pcdn-table-wrap' }, h('table', { className: 'pcdn-table' },
      h('caption', { className: 'pcdn-sr', text: t('فهرست زیرسایت‌های نمایندگی') }),
      h('thead', null, h('tr', null, h('th', { scope: 'col' }, all), [t('دامنه'), t('مشتری نهایی'), t('مصرف ماه (GB)'), t('هزینه'), t('عملیات')].map(function (x) { return h('th', { scope: 'col', text: x }); }))),
      tbody)));
    c.body.insertBefore(bar, c.body.firstChild);
    upd();
    return c;
  }

  // ------------------------------------------------------------------ render

  function render(App, body) {
    App = App || P.app;
    var wrap = h('div', { className: 'pcdn-reseller' });
    var loading = h('div', null, P.skeleton ? P.skeleton(4) : h('p', { className: 'pcdn-muted', text: t('در حال بارگذاری…') }));
    wrap.appendChild(loading);
    function refresh() {
      loadReport().then(function (rep) {
        clear(wrap);
        if (rep._error) { wrap.appendChild(P.alertBox('danger', rep._error)); return; }
        append(wrap, [summaryCard(App, rep), limitsCard(App, rep), createCard(App, rep, refresh), sitesCard(App, rep, refresh), brandCard(App, App.refreshBrand)]);
      });
    }
    refresh();
    return wrap;
  }

  P.reseller = { render: render };
})();
