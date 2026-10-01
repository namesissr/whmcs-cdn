/*
 * Pasargad CDN — client app: «صورت‌حساب و مصرف» statement (SPEC §10.4).
 *
 * Read-only. Combines this service's traffic top-ups (current + previous months,
 * from boot.statement) with the current month's live usage (site + wallet) into a
 * running summary (included / bought / used / remaining / spent) and a per-month
 * top-up history that links to WHMCS's own invoice pages. Uses only existing data;
 * no new endpoint and no change to billing.
 */
(function () {
  'use strict';
  var P = window.PCDN = window.PCDN || {};
  var t = P.t;  // i18n.js (SPEC §16.10)
  if (!P.h) return;
  var h = P.h, append = P.append, num = P.num, num1 = P.num1;
  var pages = P.pages = P.pages || {};
  function A() { return P.app; }
  var GB = 1073741824;

  var STATUS = { paid: [t('پرداخت‌شده'), 'success'], pending: [t('در حال پرداخت'), 'warning'], failed: [t('ناموفق / لغو'), 'muted'] };

  function money(Aa, v) {
    v = Number(v) || 0;
    var s = v >= 100 ? num(Math.round(v)) : num(Math.round(v * 100) / 100);
    var unit = (Aa.statement && Aa.statement.currency) || '';
    return s + (unit ? ' ' + unit : '');
  }

  function find(st, m) { return ((st && st.months) || []).filter(function (x) { return x.month === m; })[0] || null; }
  function drow(dt, dd, key) { return h('div', key ? { 'data-s': key } : null, h('dt', { text: dt }), h('dd', { text: dd })); }

  function summaryCard(Aa) {
    var st = Aa.statement, s = Aa.S.site || {}, w = Aa.wallet, b = Aa.billing;
    var usedGb = (Number((s.usage_month || {}).bytes) || 0) / GB;
    var plan = st && st.plan_gb != null ? Number(st.plan_gb) : (w ? Number(w.plan_gb) : b ? Number(b.included_gb) : 0);
    var cm = st ? find(st, st.current_month) : null;
    var boughtGb = w ? Number(w.bought_gb) : (cm ? Number(cm.bought_gb) : 0);
    var included = plan + boughtGb;                 // this month's effective allowance
    var remaining = included > 0 ? Math.max(0, included - usedGb) : null;
    var spent = cm ? Number(cm.spent) : (st ? Number(st.total_spent) : 0);

    var c = P.card({ title: t('خلاصه این ماه'), icon: 'wallet', id: 'statement-summary', tone: 'brand',
      subtitle: st && st.months && st.months[0] ? st.months[0].label : '' });
    append(c.body, [
      h('dl', { className: 'pcdn-dl' },
        drow(t('ترافیک پلن (این ماه)'), num(plan) + t(' گیگابایت'), 'plan'),
        drow(t('ترافیک خریداری‌شده'), num(boughtGb) + t(' گیگابایت'), 'bought'),
        // §15.7: add-on traffic bought as «بسته‌ی ترافیک افزوده» (included in the line above when prepaid)
        st && Number(st.addon_gb) > 0 ? drow(t('از آن، بسته‌ی ترافیک افزوده'), num(st.addon_gb) + t(' گیگابایت'), 'addon') : null,
        drow(t('مجموع ترافیک قابل‌استفاده'), included > 0 ? num(included) + t(' گیگابایت') : t('نامحدود'), 'included'),
        drow(t('مصرف‌شده این ماه'), num1(usedGb) + t(' گیگابایت'), 'used'),
        remaining != null ? drow(t('باقی‌مانده'), num1(remaining) + t(' گیگابایت'), 'remaining') : null,
        drow(t('هزینه خرید ترافیک این ماه'), money(Aa, spent), 'spent'))
    ]);
    if (included > 0) {
      var ratio = usedGb / included;
      var bar = h('div', { className: 'pcdn-usage-bar' });
      bar.appendChild(P.meter(Math.min(ratio, 1), ratio >= 1 ? 'danger' : ratio >= 0.85 ? 'warning' : 'brand'));
      c.body.appendChild(bar);
    }
    c.body.appendChild(h('p', { className: 'pcdn-muted pcdn-small',
      text: t('این صفحه فقط برای مشاهده است. پرداخت و مشاهده فاکتورها در ناحیه کاربری پاسارگاد میزبان انجام می‌شود.') }));
    return c;
  }

  function monthTable(Aa, m) {
    var st = Aa.statement, base = Aa.webRoot || '';
    var tbody = h('tbody');
    m.topups.forEach(function (tx) {
      var stt = STATUS[tx.status] || [tx.status, 'muted'];
      var inv = tx.invoice_id
        ? h('a', { href: base + ((st && st.invoice_url) || 'viewinvoice.php?id=') + tx.invoice_id, target: '_top' }, h('span', { dir: 'ltr', text: '#' + num(tx.invoice_id) }))
        : h('span', { className: 'pcdn-muted', text: '—' });
      tbody.appendChild(h('tr', { 'data-topup': '1' },
        h('td', { className: 'pcdn-nowrap', text: P.date(tx.ts, { dateStyle: 'medium' }) }),
        h('td', { className: 'pcdn-num' }, h('span', { text: num(tx.gb) + t(' گیگابایت') }),
          tx.kind === 'addon' ? h('span', { className: 'pcdn-stmt-kind', 'data-kind': 'addon', text: t(' بسته‌ی ترافیک افزوده') }) : null),
        h('td', { className: 'pcdn-num', text: money(Aa, tx.amount) }),
        h('td', null, inv),
        h('td', null, P.badge(stt[0], stt[1]))));
    });
    return h('div', { className: 'pcdn-table-wrap' }, h('table', { className: 'pcdn-table pcdn-statement-table' },
      h('caption', { className: 'pcdn-sr', text: t('خریدهای ترافیک ') + m.label }),
      h('thead', null, h('tr', null, [t('تاریخ'), t('حجم'), t('مبلغ'), t('فاکتور'), t('وضعیت')].map(function (x) { return h('th', { scope: 'col', text: x }); }))),
      tbody));
  }

  function monthCard(Aa, m) {
    var c = P.card({ title: m.label, icon: 'wallet', id: 'statement-' + m.month,
      subtitle: num(m.bought_gb) + t(' گیگابایت خریداری‌شده · ') + money(Aa, m.spent) });
    c.body.appendChild(monthTable(Aa, m));
    return c;
  }

  function render(Aa) {
    Aa = Aa || A();
    var out = [summaryCard(Aa)];
    var st = Aa.statement;
    var withTopups = ((st && st.months) || []).filter(function (m) { return m.topups && m.topups.length; });
    if (!withTopups.length) {
      var c = P.card({ title: t('خریدهای ترافیک'), icon: 'wallet', id: 'statement-topups' });
      c.body.appendChild(P.empty('wallet', t('در ماه‌های اخیر ترافیکی از کیف پول خریده نشده است'),
        t('وقتی مصرف سرویس به سقف نزدیک شود و اعتبار کیف پول کافی باشد، بسته‌های ترافیک خودکار خریده و اینجا فهرست می‌شوند.')));
      out.push(c);
    } else {
      withTopups.forEach(function (m) { out.push(monthCard(Aa, m)); });
    }
    return out;
  }

  pages.statement = {
    title: t('صورت‌حساب و مصرف'), icon: 'wallet',
    desc: t('خلاصه مصرف و هزینه ترافیک این ماه، و فهرست خریدهای ترافیک کیف پول در ماه‌های اخیر با لینک فاکتورهای WHMCS.'),
    render: render
  };
})();
