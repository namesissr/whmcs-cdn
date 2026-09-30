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
  if (!P.h) return;
  var h = P.h, append = P.append, clear = P.clear, icon = P.icon, num = P.num, num1 = P.num1, api = P.api;

  function money(v, unit) {
    v = Number(v) || 0;
    var s = v >= 100 ? num(Math.round(v)) : num(Math.round(v * 100) / 100);
    return s + (unit ? ' ' + unit : '');
  }

  // ------------------------------------------------------------------ data

  function loadReport() {
    return api('GET', '', null, { rop: 'report' }).then(function (res) {
      return res.ok ? res.data : { _error: (res.data && res.data.detail) || 'دریافت گزارش ناموفق بود.' };
    });
  }

  // ------------------------------------------------------------------ cards

  function summaryCard(App, rep) {
    var unit = rep.currency || '';
    var c = P.card({ title: 'خلاصه نمایندگی', icon: 'wallet', id: 'reseller-summary', tone: 'brand',
      subtitle: rep.month || '' });
    var rate = Number(rep.rate) || 0;
    append(c.body, h('dl', { className: 'pcdn-dl' },
      h('div', null, h('dt', { text: 'تعداد زیرسایت' }), h('dd', { text: num((rep.sites || []).length) + (App.reseller && App.reseller.max_sites ? ' / ' + num(App.reseller.max_sites) : '') })),
      h('div', null, h('dt', { text: 'مصرف این ماه' }), h('dd', { text: num1(Number(rep.total_gb) || 0) + ' گیگابایت' })),
      h('div', null, h('dt', { text: 'قیمت هر گیگابایت (عمده)' }), h('dd', { text: rate > 0 ? money(rate, unit) : '—' })),
      h('div', null, h('dt', { text: 'هزینه تخمینی این ماه' }), h('dd', { text: money(rep.total_cost, unit) })),
      h('div', null, h('dt', { text: 'اعتبار کیف پول' }), h('dd', { text: money(rep.credit, unit) }))));
    if (rep._error) c.body.appendChild(h('p', { className: 'pcdn-muted pcdn-small', text: 'مصرف لحظه‌ای در دسترس نیست: ' + rep._error }));
    else if (rep.error) c.body.appendChild(h('p', { className: 'pcdn-muted pcdn-small', text: 'مصرف لحظه‌ای بخشی از سایت‌ها در دسترس نیست.' }));
    c.body.appendChild(h('p', { className: 'pcdn-muted pcdn-small',
      text: 'هزینه از مصرف مجموع زیرسایت‌ها × قیمت عمده محاسبه می‌شود و از کیف پول شما به‌صورت خودکار تأمین می‌گردد. با اتمام اعتبار، زیرسایت‌ها موقتاً قطع و پس از شارژ دوباره وصل می‌شوند.' }));
    return c;
  }

  function createCard(App, rep, refresh) {
    var max = (App.reseller && App.reseller.max_sites) || 0;
    var full = max > 0 && (rep.sites || []).length >= max;
    var c = P.card({ title: 'ساخت زیرسایت جدید', icon: 'plus', id: 'reseller-create' });
    if (full) {
      c.body.appendChild(P.alertBox('warning', 'به سقف تعداد زیرسایت‌های مجاز (' + num(max) + ') رسیده‌اید. برای افزایش سقف با پشتیبانی تماس بگیرید.'));
      return c;
    }
    var domain = h('input', { className: 'pcdn-input', dir: 'ltr', placeholder: 'example.com', 'data-ro-ok': '1', 'aria-label': 'دامنه' });
    var origin = h('input', { className: 'pcdn-input', dir: 'ltr', placeholder: '185.10.20.30', 'data-ro-ok': '1', 'aria-label': 'آی‌پی سرور اصلی' });
    var label = h('input', { className: 'pcdn-input', placeholder: 'نام مشتری نهایی', 'data-ro-ok': '1', maxlength: 120, 'aria-label': 'نام مشتری نهایی' });
    var msg = h('div', { className: 'pcdn-form-errors' });
    function row(lbl, help, ctl) {
      return h('div', { className: 'pcdn-field' }, h('label', { className: 'pcdn-label', text: lbl }), ctl,
        help ? h('p', { className: 'pcdn-hint', text: help }) : null);
    }
    var submit = P.btn('ساخت سایت', { kind: 'primary', icon: 'plus', onclick: function () {
      clear(msg);
      var body = { domain: (domain.value || '').trim(), origin_ip: (origin.value || '').trim(), label: (label.value || '').trim() };
      if (!body.domain || !body.origin_ip || !body.label) {
        msg.appendChild(P.alertBox('danger', 'دامنه، آی‌پی سرور اصلی و نام مشتری نهایی الزامی است.'));
        return;
      }
      P.busy(submit, api('POST', '', body, { rop: 'create' })).then(function (res) {
        if (res.ok) {
          P.toast('زیرسایت ' + body.domain + ' ساخته شد.', 'success');
          domain.value = origin.value = label.value = '';
          refresh();
        } else {
          msg.appendChild(P.alertBox('danger', (res.data && res.data.detail) || 'ساخت زیرسایت ناموفق بود.'));
        }
      });
    } });
    append(c.body, [
      row('دامنه', 'دامنه سایت مشتری نهایی، بدون http و www.', domain),
      row('آی‌پی سرور اصلی (Origin)', 'آدرس IPv4 عمومی سروری که محتوای سایت روی آن است.', origin),
      row('نام مشتری نهایی', 'برای شناسایی این سایت در گزارش‌ها؛ فقط شما آن را می‌بینید.', label),
      msg,
      h('div', { className: 'pcdn-row-actions' }, submit)
    ]);
    return c;
  }

  function sitesCard(App, rep, refresh) {
    var unit = rep.currency || '';
    var c = P.card({ title: 'زیرسایت‌ها (' + num((rep.sites || []).length) + ')', icon: 'globe', id: 'reseller-sites' });
    if (!(rep.sites || []).length) {
      c.body.appendChild(P.empty('globe', 'هنوز زیرسایتی نساخته‌اید',
        'با فرم بالا اولین سایت CDN مشتری نهایی خود را بسازید؛ سپس می‌توانید DNS، کش، امنیت و SSL آن را مدیریت کنید.'));
      return c;
    }
    var tbody = h('tbody');
    rep.sites.forEach(function (s) {
      var manage = P.btn('مدیریت', { size: 'sm', icon: 'sliders', onclick: function () { App.openSubSite(s.id, { label: s.label }); } });
      var del = P.btn('حذف', { size: 'sm', kind: 'danger', icon: 'trash', onclick: function () {
        P.confirm({ title: 'حذف زیرسایت', danger: true, ok: 'حذف', cancel: 'انصراف',
          body: 'زیرسایت «' + s.domain + '» برای همیشه از CDN حذف می‌شود و محتوای آن دیگر از CDN عبور نمی‌کند. ادامه می‌دهید؟' }).then(function (ok) {
          if (!ok) return;
          api('POST', '', { id: s.id }, { rop: 'delete' }).then(function (res) {
            if (res.ok) { P.toast('زیرسایت حذف شد.', 'success'); refresh(); }
            else P.toast((res.data && res.data.detail) || 'حذف ناموفق بود.', 'error');
          });
        });
      } });
      tbody.appendChild(h('tr', { 'data-rsite': String(s.id) },
        h('td', { className: 'pcdn-nowrap' }, h('span', { dir: 'ltr', text: s.domain }), s.suspended ? h('div', null, P.badge('قطع (اعتبار)', 'danger')) : null),
        h('td', { text: s.label || '—' }),
        h('td', { className: 'pcdn-num', text: num1(Number(s.gb) || 0) }),
        h('td', { className: 'pcdn-num', text: money(s.cost, unit) }),
        h('td', null, h('div', { className: 'pcdn-row-actions' }, manage, del))));
    });
    append(c.body, h('div', { className: 'pcdn-table-wrap' }, h('table', { className: 'pcdn-table' },
      h('caption', { className: 'pcdn-sr', text: 'فهرست زیرسایت‌های نمایندگی' }),
      h('thead', null, h('tr', null, ['دامنه', 'مشتری نهایی', 'مصرف ماه (GB)', 'هزینه', 'عملیات'].map(function (x) { return h('th', { scope: 'col', text: x }); }))),
      tbody)));
    return c;
  }

  // ------------------------------------------------------------------ render

  function render(App, body) {
    App = App || P.app;
    var wrap = h('div', { className: 'pcdn-reseller' });
    var loading = h('div', null, P.skeleton ? P.skeleton(4) : h('p', { className: 'pcdn-muted', text: 'در حال بارگذاری…' }));
    wrap.appendChild(loading);
    function refresh() {
      loadReport().then(function (rep) {
        clear(wrap);
        if (rep._error) { wrap.appendChild(P.alertBox('danger', rep._error)); return; }
        append(wrap, [summaryCard(App, rep), createCard(App, rep, refresh), sitesCard(App, rep, refresh)]);
      });
    }
    refresh();
    return wrap;
  }

  P.reseller = { render: render };
})();
