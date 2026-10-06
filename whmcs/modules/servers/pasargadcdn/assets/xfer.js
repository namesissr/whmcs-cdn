/*
 * Pasargad CDN — client app: «انتقال دامنه» (SPEC §19.3), the owner page of a customer-initiated transfer.
 *
 * Registers PCDN.pages.xfer (owner and owner-side team members with manage rights only — boot.xfer; never in a shared,
 * reseller-sub-site or admin context, never for a service that is not Active). The owner names the recipient's account
 * e-mail, may add a short plain-text message, previews what moves (service, cycle, next due date, recurring amount,
 * unpaid invoices of this service, all settings) and what is revoked (controller dry run), ticks the confirmation and
 * sends the request; the recipient accepts it in their own client area. One open request per service, cancellable until
 * accepted. Everything goes through api.php's local op `xfer` (ownership, CSRF and limits checked server-side).
 * All data reaches the DOM through textContent / createElement only.
 */
(function () {
  'use strict';
  var P = window.PCDN = window.PCDN || {};
  var t = P.t;
  if (!P.h) return;
  var h = P.h, append = P.append, clear = P.clear, api = P.api;
  var pages = P.pages = P.pages || {};
  var MAX = 300;
  var TONE = { pending: 'warning', awaiting: 'brand', done: 'success', declined: 'muted', cancelled: 'muted', expired: 'muted', rejected: 'danger', failed: 'danger' };

  function money(v, cur) {
    v = Number(v) || 0;
    return P.num(Math.round(v * 100) / 100) + (cur ? ' ' + cur : '');
  }

  function render() {
    var wrap = h('div', { className: 'pcdn-stack', 'data-panel-body': 'xfer' });
    var body = h('div', { 'data-xfer': 'body' }, P.skeleton(3));
    append(wrap, [body]);
    load(body);
    return wrap;
  }

  function load(body) {
    api('GET', '', null, { lop: 'xfer' }).then(function (res) {
      if (!res.ok) { clear(body); body.appendChild(P.alertBox('danger', P.errorText(res))); return; }
      draw(body, res.data || {});
    });
  }

  function draw(body, d) {
    clear(body);
    // what moves first (live numbers), then the request form / the open request
    body.appendChild(summaryCard(d.summary || {}));
    if (d.request) body.appendChild(openCard(body, d.request));
    else body.appendChild(formCard(body, d));
    if (Array.isArray(d.recent) && d.recent.length) body.appendChild(recentCard(d.recent));
    body.appendChild(P.alertBox('info', t('گیرنده باید با همین ایمیل در پاسارگاد میزبان حساب کاربری داشته باشد. پس از پذیرش او، سرویس با همان دوره، سررسید و صورت‌حساب‌های پرداخت‌نشدهٔ همین سرویس به حساب فرد موردنظر شما منتقل می‌شود؛ اعتبار حساب و صورت‌حساب‌های پرداخت‌شده نزد شما می‌ماند.')));
  }

  /** What moves — the same facts the recipient sees on the accept page and in the e-mail. */
  function summaryCard(s) {
    var c = P.card({ title: t('آنچه منتقل می‌شود'), icon: 'book', id: 'xfer-summary' });
    var unpaid = s.unpaid || { count: 0, total: 0 };
    var rows = [
      [t('سرویس'), '#' + P.num(s.service_id || 0) + (s.product ? ' — ' + s.product : '')],
      [t('دامنه'), s.domain || '', true],
      [t('دورهٔ پرداخت'), s.cycle || '—'],
      [t('سررسید بعدی'), s.nextdue || '—', true],
      [t('مبلغ تمدید'), money(s.amount, s.currency)],
      [t('صورت‌حساب‌های پرداخت‌نشدهٔ همین سرویس'), P.num(unpaid.count || 0) + (unpaid.count ? ' — ' + money(unpaid.total, s.currency) : '')],
      [t('اشتراک‌های فعال دامنه (لغو می‌شوند)'), P.num(s.shares || 0)]
    ];
    append(c.body, [h('dl', { className: 'pcdn-dl', 'data-xfer-summary': '1' }, rows.map(function (r) {
      return h('div', null, h('dt', { text: r[0] }), h('dd', r[2] ? { dir: 'ltr', text: r[1] } : { text: r[1] }));
    })), h('p', { className: 'pcdn-muted pcdn-small', text: t('همهٔ تنظیمات، رکوردهای DNS، SSL، قوانین و آمار سایت هم منتقل می‌شوند.') })]);
    return c;
  }

  /** What the controller revokes / rotates (preview = dry run). */
  function revokeList(r) {
    r = r || {};
    var items = [
      t('کلیدهای API مشتری باطل می‌شوند') + (r.revoked_keys ? ' (' + P.num(r.revoked_keys) + ')' : ''),
      t('رمز وب‌هوک‌ها و ارسال لاگ عوض و یکپارچه‌سازی‌ها متوقف می‌شوند') + (r.paused ? ' (' + P.num(r.paused) + ')' : ''),
      t('نشست‌های «دسترسی محافظت‌شده» باطل می‌شوند'),
      t('کلیدهای ذخیره‌سازی عوض می‌شوند') + (r.storage ? ' (' + P.num(r.storage) + ')' : ''),
      t('اشتراک‌های دامنه با حساب‌های دیگر لغو می‌شوند')
    ];
    if (r.tsig) items.push(t('کلیدهای TSIG انتقال ناحیه عوض می‌شوند ({0})', P.num(r.tsig)));
    return h('ul', { className: 'pcdn-xfer-revoke', 'data-xfer-revoke': '1' }, items.map(function (x) { return h('li', { text: x }); }));
  }

  function formCard(body, d) {
    var c = P.card({ title: t('انتقال این دامنه به حساب دیگر'), icon: 'send', id: 'xfer-form', tone: 'brand' });
    var model = { email: '', message: '' };
    var preview = h('div', { 'data-xfer': 'preview' });
    var email = P.input(model, 'email', t('ایمیل اصلی حساب گیرنده'), { maxlength: 191, placeholder: 'name@example.com', type: 'email',
      oninput: function () { clear(preview); } });
    var count = h('span', { className: 'pcdn-muted pcdn-small', 'data-xfer-count': '1', text: '0 / ' + P.num(MAX) });
    var ta = h('textarea', { className: 'pcdn-input pcdn-xfer-msg', dir: 'auto', rows: 3, maxlength: MAX, 'aria-label': t('پیام برای گیرنده (اختیاری)'),
      placeholder: t('پیام کوتاه برای گیرنده (اختیاری، حداکثر ۳۰۰ نویسه)'), 'data-xfer-message': '1',
      oninput: function (e) { model.message = e.target.value; count.textContent = P.num(e.target.value.length) + ' / ' + P.num(MAX); } });
    var msgField = P.field(t('پیام برای گیرنده (اختیاری)'), h('div', null, ta, count));
    var check = P.btn(t('بررسی و پیش‌نمایش'), { kind: 'primary', icon: 'search', write: true, cls: 'pcdn-xfer-preview', onclick: function () {
      var e = String(model.email || '').trim();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)) { P.toast(t('یک ایمیل معتبر وارد کنید.'), 'error'); return; }
      P.busy(check, api('POST', '', { action: 'preview', email: e }, { lop: 'xfer' })).then(function (res) {
        clear(preview);
        if (!res.ok) { preview.appendChild(P.alertBox('danger', P.errorText(res))); return; }
        preview.appendChild(confirmBox(body, model, e, res.data || {}, d));
      });
    } });
    append(c.body, [h('p', { className: 'pcdn-muted', text: t('مالکیت کامل این سرویس — با صورت‌حساب‌ها و تمدید بعدی — به حساب فرد موردنظر شما منتقل می‌شود. گیرنده باید درخواست را بپذیرد؛ تا آن زمان می‌توانید آن را لغو کنید.') }),
      email, msgField, h('div', { className: 'pcdn-row-actions' }, check), preview]);
    return c;
  }

  function confirmBox(body, model, email, p, d) {
    var box = h('div', { className: 'pcdn-stack', 'data-xfer-confirm': '1' });
    var agreed = { v: false };
    var send = P.btn(t('ارسال درخواست انتقال'), { kind: 'danger', icon: 'send', write: true, cls: 'pcdn-xfer-send', onclick: function () {
      if (!agreed.v) { P.toast(t('برای ارسال درخواست، تأیید را علامت بزنید.'), 'error'); return; }
      if (String(model.message || '').length > MAX) { P.toast(t('پیام حداکثر ۳۰۰ نویسهٔ متن ساده باشد.'), 'error'); return; }
      P.busy(send, api('POST', '', { action: 'create', email: email, message: String(model.message || ''), confirm: true }, { lop: 'xfer' })).then(function (res) {
        if (!res.ok) { P.toast(P.errorText(res), 'error'); return; }
        P.toast((res.data && res.data.mailed) ? t('درخواست انتقال ساخته و برای گیرنده ایمیل شد.') : t('درخواست انتقال ساخته شد؛ در صفحهٔ اصلی ناحیهٔ کاربری گیرنده نمایش داده می‌شود.'), 'success');
        draw(body, res.data || {});
      });
    } });
    send.disabled = true;
    var id = 'pcdn-xfer-ok-' + Math.random().toString(36).slice(2, 8);
    var cb = h('input', { type: 'checkbox', id: id, 'data-xfer-agree': '1', onchange: function (e) { agreed.v = e.target.checked; send.disabled = !e.target.checked; } });
    append(box, [
      P.alertBox('warning', [h('strong', { text: t('گیرنده: ') }), h('span', { text: p.recipient || '—' }), ' ', h('span', { dir: 'ltr', className: 'pcdn-ltr', text: '<' + email + '>' })]),
      h('div', null, h('h4', { className: 'pcdn-xfer-h', text: t('آنچه باطل یا عوض می‌شود') }), revokeList(p.revoke)),
      d && d.approval ? P.alertBox('info', t('پس از پذیرش گیرنده، انتقال با تأیید مدیر انجام می‌شود.')) : null,
      h('label', { 'for': id, className: 'pcdn-xfer-agree' }, cb, h('span', { text: t('می‌دانم که مالکیت این سرویس و صورت‌حساب‌های پرداخت‌نشدهٔ آن با پذیرش گیرنده برای همیشه به حساب او منتقل می‌شود و دسترسی من به این دامنه قطع می‌شود.') })),
      h('div', { className: 'pcdn-row-actions' }, send)
    ]);
    return box;
  }

  function openCard(body, r) {
    var c = P.card({ title: t('درخواست انتقال باز'), icon: 'clock', id: 'xfer-open', tone: 'warning' });
    var cancel = P.btn(t('لغو درخواست'), { icon: 'x', kind: 'ghost', write: true, cls: 'pcdn-xfer-cancel', onclick: function () {
      P.confirm({ title: t('لغو درخواست انتقال'), danger: true, ok: t('لغو درخواست'), body: t('پیوند پذیرش گیرنده بلافاصله باطل می‌شود.') }).then(function (ok) {
        if (!ok) return;
        P.busy(cancel, api('POST', '', { action: 'cancel', id: r.id }, { lop: 'xfer' })).then(function (res) {
          if (!res.ok) { P.toast(P.errorText(res), 'error'); return; }
          P.toast(t('درخواست انتقال لغو شد.'), 'success');
          draw(body, res.data || {});
        });
      });
    } });
    append(c.body, [h('div', { 'data-xfer-request': String(r.id), 'data-xfer-status': r.status },
      h('p', null, h('strong', { text: t('گیرنده: ') }), h('span', { text: r.recipient || '—' }), ' ', h('span', { dir: 'ltr', className: 'pcdn-ltr', text: '<' + r.email + '>' })),
      h('p', null, P.badge(r.status_label || r.status, TONE[r.status] || 'muted'),
        r.status === 'pending' && r.expires_at ? h('span', { className: 'pcdn-muted pcdn-small', text: ' ' + t('اعتبار تا {0}', P.date(r.expires_at, { dateStyle: 'medium' })) }) : null),
      r.message ? h('blockquote', { className: 'pcdn-xfer-quote', dir: 'auto', text: r.message }) : null,
      r.status === 'pending' ? h('div', { className: 'pcdn-row-actions' }, cancel)
        : P.alertBox('info', t('گیرنده درخواست را پذیرفته است؛ انتقال پس از تأیید مدیر انجام می‌شود.')))]);
    return c;
  }

  function recentCard(rows) {
    var c = P.card({ title: t('درخواست‌های اخیر'), icon: 'clock', id: 'xfer-recent' });
    var tbl = h('table', { className: 'pcdn-table pcdn-xfer-table' },
      h('thead', null, h('tr', null, h('th', { text: t('گیرنده') }), h('th', { text: t('وضعیت') }), h('th', { text: t('زمان') }))),
      h('tbody', null, rows.map(function (r) {
        return h('tr', { 'data-xfer-row': String(r.id), 'data-xfer-status': r.status },
          h('td', null, h('span', { dir: 'ltr', className: 'pcdn-ltr', text: r.email })),
          h('td', null, P.badge(r.status_label || r.status, TONE[r.status] || 'muted')),
          h('td', { className: 'pcdn-small', text: P.date(r.created_at, { dateStyle: 'medium' }) }));
      })));
    append(c.body, h('div', { className: 'pcdn-table-wrap' }, tbl));
    return c;
  }

  pages.xfer = {
    title: t('انتقال دامنه'), icon: 'send',
    desc: t('انتقال مالکیت این سرویس و دامنه به حساب فرد موردنظر شما، با پذیرش گیرنده.'),
    hidden: function () { var a = P.app; return !a || !a.xfer || (a.inSubSite && a.inSubSite()); },
    render: function () { return render(); }
  };
})();
