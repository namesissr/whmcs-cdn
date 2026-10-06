/*
 * Pasargad CDN — client app: «اشتراک دامنه» (SPEC §20.2), the owner page.
 *
 * Registers PCDN.pages.sharing (owner and owner-side team members with manage rights only — boot.sharing; never in a
 * shared, reseller-sub-site or admin context). Invites another WHMCS account by e-mail + role (viewer | dns | editor),
 * lists members and pending invites, changes a role or revokes — all through api.php's local op `shares`, which checks
 * ownership server-side. When the invitee has no WHMCS account yet, the one-time invite link is shown here to forward.
 * All data reaches the DOM through textContent / createElement only.
 */
(function () {
  'use strict';
  var P = window.PCDN = window.PCDN || {};
  var t = P.t;
  if (!P.h) return;
  var h = P.h, append = P.append, clear = P.clear, api = P.api;
  var pages = P.pages = P.pages || {};
  var ROLES = [
    ['viewer', t('مشاهده‌گر'), t('همهٔ صفحه‌ها، آمار و گزارش‌ها را می‌بیند؛ چیزی را تغییر نمی‌دهد.')],
    ['dns', t('مدیر DNS'), t('مشاهده + رکوردهای DNS و DNS ثانویه.')],
    ['editor', t('ویرایشگر'), t('همهٔ تنظیمات سایت؛ بدون صورت‌حساب، ارتقا، کلید API، انتقال و مدیریت اشتراک.')]
  ];
  function roleLabel(r) { for (var i = 0; i < ROLES.length; i++) if (ROLES[i][0] === r) return ROLES[i][1]; return r; }
  P.shareRoleLabel = roleLabel;

  function render() {
    var wrap = h('div', { className: 'pcdn-stack', 'data-panel-body': 'sharing' });
    var listCard = P.card({ title: t('اعضا و دعوت‌ها'), icon: 'link', id: 'sharing-list' });
    var listBody = h('div', { 'data-shares': 'list' }, P.skeleton(3));
    append(listCard.body, listBody);
    var reveal = h('div', { 'data-shares': 'reveal' });
    append(wrap, [inviteCard(reveal, function (d) { draw(listBody, d); }), reveal, listCard,
      P.alertBox('info', t('اعضا از ناحیهٔ کاربری خودشان در «دامنه‌های اشتراکی» فقط همین دامنه را مدیریت می‌کنند. صورت‌حساب، کیف پول و مالکیت سرویس نزد شما می‌ماند و هر تغییر اعضا با نام آن‌ها در «گزارش تغییرات» ثبت می‌شود.'))]);
    load(listBody);
    return wrap;
  }

  function load(listBody) {
    api('GET', '', null, { lop: 'shares' }).then(function (res) {
      if (!res.ok) { clear(listBody); listBody.appendChild(P.alertBox('danger', P.errorText(res))); return; }
      draw(listBody, res.data);
    });
  }

  function draw(listBody, d) {
    clear(listBody);
    var rows = (d && Array.isArray(d.members)) ? d.members : [];
    if (!rows.length) {
      listBody.appendChild(P.empty('link', t('هنوز این دامنه را با کسی به اشتراک نگذاشته‌اید'), t('با فرم بالا یک حساب دیگر را برای مدیریت این دامنه دعوت کنید.')));
      return;
    }
    var tbl = h('table', { className: 'pcdn-table pcdn-shares-table' },
      h('thead', null, h('tr', null, h('th', { text: t('ایمیل') }), h('th', { text: t('نقش') }), h('th', { text: t('وضعیت') }), h('th', { className: 'pcdn-th-actions', text: '' }))),
      h('tbody', null, rows.map(function (m) { return row(m, listBody); })));
    listBody.appendChild(h('div', { className: 'pcdn-table-wrap' }, tbl));
    if (d.max_members) listBody.appendChild(h('p', { className: 'pcdn-muted pcdn-small', text: t('حداکثر {0} عضو و دعوت در انتظار برای هر دامنه.', P.num(d.max_members)) }));
  }

  function row(m, listBody) {
    var model = { role: m.role };
    var sel = P.select(model, 'role', null, ROLES.map(function (r) { return [r[0], r[1]]; }), { aria: t('نقش'), onchange: function (v) {
      P.busy(sel, api('POST', '', { action: 'role', id: m.id, role: v }, { lop: 'shares' })).then(function (res) {
        if (!res.ok) { P.toast(P.errorText(res), 'error'); return; }
        P.toast(t('نقش تغییر کرد؛ از همین حالا اعمال می‌شود.'), 'success');
        draw(listBody, res.data);
      });
    } });
    var revoke = P.btn(m.status === 'pending' ? t('لغو دعوت') : t('حذف عضو'), { icon: 'trash', size: 'sm', kind: 'ghost', write: true, cls: 'pcdn-share-revoke', onclick: function () {
      P.confirm({ title: t('حذف دسترسی'), danger: true, ok: t('حذف'),
        body: t('دسترسی {0} به این دامنه بلافاصله قطع می‌شود.', m.email) }).then(function (ok) {
        if (!ok) return;
        P.busy(revoke, api('POST', '', { action: 'revoke', id: m.id }, { lop: 'shares' })).then(function (res) {
          if (!res.ok) { P.toast(P.errorText(res), 'error'); return; }
          P.toast(t('دسترسی حذف شد.'), 'success');
          draw(listBody, res.data);
        });
      });
    } });
    var who = h('div', null, h('span', { className: 'pcdn-ltr', dir: 'ltr', text: m.email }), m.name ? h('div', { className: 'pcdn-muted pcdn-small', text: m.name }) : null);
    var st = m.status === 'pending'
      ? P.badge(t('در انتظار پذیرش') + (m.expires_at ? ' — ' + t('تا') + ' ' + P.date(m.expires_at, { dateStyle: 'medium' }) : ''), 'warning')
      : P.badge(t('عضو'), 'success');
    return h('tr', { className: 'pcdn-share-row', 'data-share-id': String(m.id), 'data-share-status': m.status },
      h('td', null, who), h('td', null, sel), h('td', null, st), h('td', { className: 'pcdn-td-actions' }, revoke));
  }

  function inviteCard(reveal, onDone) {
    var c = P.card({ title: t('دعوت عضو جدید'), icon: 'mail', id: 'sharing-invite', tone: 'brand' });
    var model = { email: '', role: 'viewer' };
    var email = P.input(model, 'email', t('ایمیل حساب کاربری شخص'), { maxlength: 191, placeholder: 'name@example.com', type: 'email' });
    var roleSel = P.select(model, 'role', t('نقش'), ROLES.map(function (r) { return [r[0], r[1] + ' — ' + r[2]]; }));
    var send = P.btn(t('ارسال دعوت'), { kind: 'primary', icon: 'send', write: true, cls: 'pcdn-share-invite', onclick: function () {
      var e = String(model.email || '').trim();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)) { P.toast(t('یک ایمیل معتبر وارد کنید.'), 'error'); return; }
      P.busy(send, api('POST', '', { action: 'invite', email: e, role: model.role }, { lop: 'shares' })).then(function (res) {
        if (!res.ok) { P.toast(P.errorText(res), 'error'); return; }
        clear(reveal);
        var d = res.data || {};
        if (d.link) {
          reveal.appendChild(h('div', { 'data-share-link': '1' }, P.alertBox('warning', [
            h('strong', { text: t('این ایمیل هنوز حساب کاربری ندارد. ') }),
            t('پیوند زیر را برای او بفرستید؛ پس از ثبت‌نام با همین ایمیل می‌تواند دعوت را بپذیرد. این پیوند فقط همین یک بار نمایش داده می‌شود و ۷ روز اعتبار دارد.')]),
            h('div', { className: 'pcdn-key-plain' }, h('code', { className: 'pcdn-key-value', dir: 'ltr', text: d.link }),
              P.copyBtn(d.link, t('کپی پیوند'), { text: t('کپی'), done: t('کپی شد') }))));
        }
        model.email = '';
        var inp = email.querySelector('input'); if (inp) inp.value = '';
        P.toast(d.link ? t('دعوت ساخته شد.') : (d.mailed ? t('دعوت ساخته و ایمیل شد.') : t('دعوت ساخته شد؛ در صفحهٔ اصلی ناحیهٔ کاربری او نمایش داده می‌شود.')), 'success');
        onDone(d);
      });
    } });
    append(c.body, [h('p', { className: 'pcdn-muted', text: t('این دامنه را با حساب کاربری شخص دیگری به اشتراک بگذارید تا آن را از ناحیهٔ کاربری خودش مدیریت کند. صورت‌حساب و مالکیت تغییر نمی‌کند.') }),
      email, roleSel, h('div', { className: 'pcdn-row-actions' }, send)]);
    return c;
  }

  pages.sharing = {
    title: t('اشتراک دامنه'), icon: 'link',
    desc: t('دسترسی حساب‌های دیگر به مدیریت این دامنه با نقش مشاهده‌گر، مدیر DNS یا ویرایشگر.'),
    hidden: function () { var a = P.app; return !a || !a.sharing || (a.inSubSite && a.inSubSite()); },
    render: function () { return render(); }
  };
})();
