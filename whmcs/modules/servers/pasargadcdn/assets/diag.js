/*
 * Pasargad CDN — client app: «ارسال گزارش عیب‌یابی به پشتیبانی» (SPEC §23.8, wave 14).
 *
 * PCDN.diag = {button(o), card(), open()} — on the overview and the tunnel quality page, once the wave-14 probe answered. The
 * dialog (1) asks api.php's local op `diag` for the report; the server keeps it in the PHP session for 30 minutes so what is sent
 * is exactly what is shown here, (2) shows a readable preview plus the full message, an optional note (≤ 2000 characters) and the
 * choice «تیکت جدید» (the support department) or «افزودن به تیکت باز» (the customer's own open tickets), (3) sends only after the
 * customer confirms. The report holds no secrets, node names or node addresses (city labels only). Hidden in the admin view, a
 * shared domain and a reseller's sub-site; read-only team users can preview but not send.
 * All data reaches the DOM through textContent / createElement only.
 */
(function () {
  'use strict';
  var P = window.PCDN = window.PCDN || {};
  var t = P.t;
  if (!P.h) return;
  var h = P.h, append = P.append, clear = P.clear, icon = P.icon, num = P.num, api = P.api;
  function A() { return P.app; }
  var MAX = 2000;

  function available() {
    var a = A();
    return !!a && !a.admin && !a.share && !(a.inSubSite && a.inSubSite()) && !!(P.w17 && P.w17.wave && P.w17.wave());
  }
  function button(o) {
    o = o || {};
    var b = P.btn(t('ارسال گزارش عیب‌یابی به پشتیبانی'), { size: o.size || 'sm', icon: 'tool', kind: o.kind, cls: 'pcdn-diag-open', onclick: function () { open(); } });
    b.setAttribute('data-ro-ok', '1');
    return b;
  }
  /** A slot that becomes a small card once the wave-14 probe answered. */
  function slot(kind) {
    var el = h('div', { 'data-diag-slot': kind || 'card' });
    function fill() {
      clear(el);
      if (!available()) return;
      if (kind === 'button') { el.appendChild(button()); return; }
      var c = P.card({ title: t('مشکلی دارید؟'), icon: 'tool', id: 'diag', tone: 'muted',
        subtitle: t('یک گزارش وضعیت کامل از سایت (DNS، SSL، تنظیمات، خطاهای اخیر) بسازید و پس از بازبینی برای پشتیبانی بفرستید.') });
      c.body.appendChild(h('div', { className: 'pcdn-row-actions' }, button({ kind: 'primary' })));
      el.appendChild(c);
    }
    if (P.w17 && P.w17.ready) P.w17.ready(fill); else fill();
    return el;
  }

  function line(label, value) {
    return h('div', { className: 'pcdn-diag-row' }, h('dt', { text: label }), h('dd', null, value));
  }
  function yes(b) { return b ? t('بله') : t('خیر'); }
  function summary(r) {
    var dl = h('dl', { className: 'pcdn-diag-sum' });
    var site = r.site || {}, dns = r.dns || {}, ssl = r.ssl || {}, rec = r.recent || {}, u = r.usage || {};
    append(dl, [
      line(t('دامنه'), h('bdi', { dir: 'ltr', text: String(site.domain || '') })),
      line(t('وضعیت سرویس'), String(site.status || '—')),
      line(t('نیم‌سرورها تأیید شده'), yes(dns.ns_verified)),
      line(t('رکوردها (پروکسی)'), num(dns.records || 0) + ' (' + num(dns.proxied || 0) + ')'),
      line('SSL', String(ssl.status || '—') + (ssl.days_left != null ? ' — ' + t('{0} روز مانده', num(ssl.days_left)) : '')),
      line(t('رویدادهای امنیتی ۲۴ ساعت'), num(rec.security_events_24h || 0)),
      line(t('خطاهای سرور اصلی ۲۴ ساعت'), num(rec.origin_errors_24h || 0)),
      line(t('مصرف این ماه'), u.pct != null ? P.num1(u.pct) + t('٪') : '—')]);
    if (r.tunnel && typeof r.tunnel === 'object') {
      var tn = r.tunnel;
      dl.appendChild(line(t('تونل'), t('{0} نشست، {1}٪ قطع غیرعادی', num(tn.sessions_24h || 0), P.num1(tn.abnormal_pct || 0))));
      (Array.isArray(tn.nodes) ? tn.nodes : []).slice(0, 10).forEach(function (n) {
        // §23.12: city labels only («نود تهران ۱» / "Tehran node 1")
        var label = P.isEn ? (n.label_en || n.label) : (n.label || n.label_en);
        if (P.isEn && /[؀-ۿ]/.test(String(label || ''))) label = t('نود');
        dl.appendChild(line(String(label || t('نود')), t('{0} نشست، {1}٪ قطع غیرعادی', num(n.sessions || 0), P.num1(n.abnormal_pct || 0))));
      });
    }
    return dl;
  }

  function open() {
    var d = P.dialog({ title: t('گزارش عیب‌یابی برای پشتیبانی'), icon: 'tool', kind: 'drawer', wide: true, subtitle: A().S.site.domain });
    d.el.classList.add('pcdn-diag-dlg');
    var body = h('div', { className: 'pcdn-diag-body' }, P.skeleton(5));
    d.body.appendChild(body);
    var close = P.btn(t('بستن'), { onclick: function () { d.close(); } });
    d.foot.appendChild(close);
    api('GET', '', null, { lop: 'diag' }).then(function (res) {
      clear(body);
      if (!res.ok || !res.data || !res.data.report) { body.appendChild(P.errorBox(res, t('ساخت گزارش ممکن نشد'))); return; }
      draw(res.data);
    });
    function draw(x) {
      var r = x.report, m = { note: '', mode: 'new', ticket: null };
      var tickets = Array.isArray(x.tickets) ? x.tickets : [];
      var dept = x.department || null;
      var warn = (Array.isArray(r.warnings) ? r.warnings : []).slice(0, 10);
      var full = P.collapsible({ title: t('متن کامل پیامی که فرستاده می‌شود'), icon: 'fileText', tone: 'muted', id: 'diag-full' });
      full.body.appendChild(h('pre', { className: 'pcdn-diag-md', dir: 'auto', 'data-diag-md': '1', text: String(x.markdown || '') }));
      var count = h('span', { className: 'pcdn-muted pcdn-small', text: t('{0} از {1} نویسه', num(0), num(MAX)) });
      var note = h('textarea', { className: 'pcdn-input', rows: 4, maxlength: MAX, dir: 'auto', 'data-diag-note': '1', placeholder: t('مثلاً: از ساعت ۱۰ صبح صفحهٔ پرداخت برای بعضی کاربران باز نمی‌شود.'),
        'aria-label': t('توضیح شما (اختیاری)'), oninput: function (e) { m.note = e.target.value.slice(0, MAX); count.textContent = t('{0} از {1} نویسه', num(m.note.length), num(MAX)); } });
      var tSel = tickets.length ? P.select(m, 'ticket', null, tickets.map(function (k) { return [k.id, '#' + String(k.tid || k.id) + ' — ' + String(k.subject || '')]; }), { aria: t('تیکت باز') }) : null;
      if (tickets.length) m.ticket = tickets[0].id;
      var modes = P.choice(m, 'mode', t('ارسال به'), [
        ['new', t('تیکت جدید'), dept ? t('در بخش «{0}» با عنوان «{1}»', String(dept.name || ''), String(x.subject || '')) : t('بخش پشتیبانی'), 'plus'],
        ['reply', t('افزودن به تیکت باز'), tickets.length ? t('{0} تیکت باز دارید', num(tickets.length)) : t('تیکت بازی ندارید'), 'mail']], { cols: 2, onchange: function (v) {
          if (tSel) tSel.hidden = v !== 'reply';
        } });
      if (!tickets.length) { var rr = modes.querySelector('[data-value="reply"] input'); if (rr) rr.disabled = true; }
      if (tSel) tSel.hidden = true;
      append(body, [
        P.alertBox('info', t('پیش از ارسال، گزارش را بازبینی کنید. این گزارش هیچ رمز، کلید یا نشانی سرور شما را ندارد و فقط همین متن و توضیح شما فرستاده می‌شود.')),
        h('div', { className: 'pcdn-diag-id' }, h('span', { className: 'pcdn-muted pcdn-small', text: t('شناسهٔ گزارش') }), h('code', { dir: 'ltr', 'data-report-id': String(r.report_id || ''), text: String(r.report_id || '') })),
        summary(r),
        warn.length ? P.alertBox('warning', h('ul', { className: 'pcdn-errlist' }, warn.map(function (w) { return h('li', { text: P.ctlText(String(w)) }); }))) : null,
        full,
        P.field(t('توضیح شما (اختیاری)'), h('div', null, note, count)),
        modes, tSel]);
      var send = P.btn(t('ارسال به پشتیبانی'), { kind: 'primary', icon: 'send', write: true, cls: 'pcdn-diag-send', onclick: function () {
        var payload = { report_id: r.report_id, note: m.note || '', mode: m.mode };
        if (m.mode === 'reply') payload.ticket_id = Number(m.ticket);
        P.busy(send, api('POST', '', payload, { lop: 'diag' })).then(function (res) {
          if (!res.ok) { body.insertBefore(P.errorBox(res, t('ارسال انجام نشد')), body.firstChild); return; }
          var tk = (res.data && res.data.ticket) || {};
          clear(body);
          clear(d.foot);
          append(body, [P.alertBox('success', [h('strong', { text: res.data.mode === 'reply' ? t('گزارش به تیکت #{0} افزوده شد.', String(tk.tid || tk.id || '')) : t('تیکت #{0} ثبت شد.', String(tk.tid || tk.id || '')) }),
            t(' پاسخ پشتیبانی در بخش تیکت‌ها و ایمیل شما می‌آید.')]),
            h('a', { className: 'pcdn-link', href: A().webRoot + 'supporttickets.php', 'data-ro-ok': '1', text: t('مشاهدهٔ تیکت‌ها') })]);
          d.foot.appendChild(P.btn(t('بستن'), { kind: 'primary', onclick: function () { d.close(); } }));
        });
      } });
      clear(d.foot);
      append(d.foot, [send, P.btn(t('انصراف'), { onclick: function () { d.close(); } })]);
      if (A().lockWrites) A().lockWrites(d.el);
    }
    d.focusFirst();
  }

  P.diag = { available: available, button: button, card: function () { return slot('card'); }, inline: function () { return slot('button'); }, open: open };
})();
