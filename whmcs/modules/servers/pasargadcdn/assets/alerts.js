/*
 * Pasargad CDN — client app: «هشدارها» / "Alerts" (SPEC §23.5, wave 14). Account-level: the same subscriptions and channels on
 * every CDN service of the account.
 *
 * Registers PCDN.pages.alerts and PCDN.alerts (probe: one background GET of the account's alerts when the app starts — only for
 * the account itself: never in the admin view, a shared domain or a reseller's sub-site; an older controller answers 404 and the
 * page stays hidden). Calls go through api.php's account op (`acct=<sub-path>`): the controller path is
 * /api/v1/accounts/{the logged-in client}/alerts/… — the client id is the session's, never sent by the browser.
 *   - channel cards: e-mail (always), SMS (number + 6-digit code), Bale / Telegram («اتصال» opens the bot's deep link with a one-time
 *     code and polls until it is linked); channels the operator did not configure are hidden, channels outside the plan show
 *     «در پلن شما فعال نیست» with the upgrade link; per target «ارسال پیام آزمایشی» and «حذف» (opt-out);
 *   - subscription editor: all services / this service, events with descriptions, channels, language, quiet hours «از … تا …» +
 *     «هشدارهای بحرانی در ساعات سکوت هم ارسال شوند», on/off; saved as a full replace (PUT subscriptions).
 * Messages never contain node names or addresses (the controller's templates). All data reaches the DOM through textContent.
 */
(function () {
  'use strict';
  var P = window.PCDN = window.PCDN || {};
  var t = P.t;
  if (!P.h) return;
  var h = P.h, append = P.append, clear = P.clear, icon = P.icon, num = P.num, api = P.api;
  var pages = P.pages = P.pages || {};
  function A() { return P.app; }

  function call(method, sub, body) { return api(method, '', body === undefined ? null : body, { acct: sub || '' }); }

  var S = { ok: undefined, data: null, loading: null };
  function load(force) {
    if (!force && S.data) return Promise.resolve({ ok: true, data: S.data });
    if (S.loading) return S.loading;
    S.loading = call('GET', '').then(function (res) {
      S.loading = null;
      if (res.ok && res.data && typeof res.data === 'object' && res.data.channels) { S.ok = true; S.data = res.data; }
      else if (res.status === 404) { S.ok = false; S.data = null; }
      return res;
    });
    return S.loading;
  }
  function allowed() { var a = A(); return !!a && !a.admin && !a.share && !(a.inSubSite && a.inSubSite()); }
  P.alerts = {
    ok: function () { return S.ok; },
    probe: function () { if (!allowed()) return Promise.resolve(false); return load(false).then(function () { return S.ok === true; }); }
  };

  // ------------------------------------------------------------------ catalog

  var CH = {
    email: [t('ایمیل'), 'mail'], sms: [t('پیامک'), 'send'], bale: [t('پیام‌رسان بله'), 'send'], telegram: [t('تلگرام'), 'send']
  };
  var EVENTS = {
    'origin.down': [t('سرور اصلی پاسخ نمی‌دهد'), t('بیشتر درخواست‌ها با خطای سرور اصلی شما روبه‌رو می‌شوند.')],
    'origin.up': [t('سرور اصلی دوباره پاسخ می‌دهد'), t('پس از یک هشدار قطعی، وقتی سرور شما دوباره سالم شد.')],
    'tunnel.origin_down': [t('قطعی سرور پشت تونل'), t('نودها به سرور پشت تونل شما وصل نمی‌شوند.')],
    'tunnel.origin_up': [t('اتصال سرور پشت تونل برقرار شد'), t('پس از قطعی، وقتی اتصال دوباره برقرار شد.')],
    'quota.warning': [t('۸۰٪ ترافیک ماهانه مصرف شد'), t('یک بار در ماه برای هر سرویس.')],
    'quota.exceeded': [t('ترافیک ماهانه تمام شد'), t('سرویس تا تمدید یا خرید ترافیک محدود می‌شود.')],
    'ssl.expiring': [t('گواهی SSL رو به انقضاست'), t('۱۴، ۷، ۳ و ۱ روز پیش از انقضا (بیشتر برای گواهی اختصاصی).')],
    'ssl.failed': [t('صدور گواهی SSL ناموفق بود'), t('وقتی صدور یا تمدید خودکار گواهی شکست بخورد.')],
    'attack.detected': [t('حمله شناسایی شد'), t('رویدادهای امنیتی از آستانه گذشت و حالت دفاعی فعال شد.')],
    'site.suspended': [t('سرویس معلق شد'), t('سرویس به هر دلیلی معلق شد.')],
    'site.unsuspended': [t('تعلیق سرویس برداشته شد'), t('سرویس دوباره فعال شد.')],
    'incident.opened': [t('رخداد سکو'), t('اختلال یا تعمیرات اعلام‌شده در صفحهٔ وضعیت (یک پیام برای کل حساب).')],
    'incident.resolved': [t('رخداد سکو برطرف شد'), t('پایان اختلال یا تعمیرات اعلام‌شده.')]
  };
  var SEV = { critical: [t('بحرانی'), 'danger'], warning: [t('هشدار'), 'warning'], info: [t('اطلاع'), 'muted'] };
  function evLabel(e) { return EVENTS[e] ? EVENTS[e][0] : String(e); }
  /** The controller's error codes (§23.5) in words; anything else through P.errorText. */
  var CODES = {
    channel_not_in_plan: t('این کانال در پلن یکی از سرویس‌های انتخاب‌شده فعال نیست.'), channel_unavailable: t('این کانال فعلاً در دسترس نیست.'),
    too_many_subscriptions: t('تعداد اشتراک‌ها از سقف مجاز بیشتر است.'), site_not_in_account: t('این دامنه در حساب شما نیست.'),
    invalid_events: t('رویدادهای انتخاب‌شده معتبر نیستند.'), invalid_channels: t('کانال‌های انتخاب‌شده معتبر نیستند.'), invalid_lang: t('زبان پیام معتبر نیست.'),
    invalid_quiet_hours: t('ساعات سکوت معتبر نیست (شروع و پایان باید متفاوت باشند).'), sms_send_failed: t('ارسال پیامک ممکن نشد؛ کمی بعد دوباره تلاش کنید.'),
    invalid_code: t('کد نادرست یا منقضی است.'), code_expired: t('کد منقضی شده است؛ کد تازه بگیرید.'), too_many_tries: t('تعداد تلاش‌ها به سقف رسید؛ کد تازه بگیرید.'),
    too_many_codes: t('تعداد درخواست کد به سقف رسیده است؛ کمی بعد دوباره تلاش کنید.')
  };
  function errText(res) {
    var d = res && res.data && res.data.detail;
    if (d === 'channel_not_in_plan' && res.data.channel && CH[res.data.channel]) return t('کانال {0} در پلن یکی از سرویس‌های انتخاب‌شده فعال نیست.', CH[res.data.channel][0]);
    return typeof d === 'string' && CODES[d] ? CODES[d] : P.errorText(res);
  }

  // ------------------------------------------------------------------ page

  function render() {
    var wrap = h('div', { className: 'pcdn-stack', 'data-alerts': '1' });
    var body = h('div', { className: 'pcdn-stack' }, P.skeleton(5));
    append(wrap, [P.alertBox('info', t('هشدارها برای همهٔ سرویس‌های CDN حساب شما یکسان است؛ می‌توانید هر اشتراک را به همهٔ سرویس‌ها یا فقط یک سرویس محدود کنید.')), body]);
    load(true).then(function (res) {
      clear(body);
      if (!res.ok) { body.appendChild(P.errorBox(res, t('دریافت تنظیمات هشدار ممکن نشد'))); return; }
      draw(body);
    });
    return wrap;
  }

  function draw(body) {
    clear(body);
    var d = S.data || {};
    append(body, [channelsCard(d, body), subsCard(d, body)]);
    if (A().lockWrites) A().lockWrites(body);
  }
  function reload(body) { return load(true).then(function (res) { if (res.ok) draw(body); else P.toast(P.errorText(res), 'error'); }); }

  function chInfo(d, c) { var x = d.channels && d.channels[c]; return x && typeof x === 'object' ? x : null; }
  function targetsOf(d, c) { return (Array.isArray(d.targets) ? d.targets : []).filter(function (x) { return x && x.channel === c; }); }
  function planNote() {
    return h('div', { className: 'pcdn-alert-plan', 'data-plan-off': '1' }, P.badge(t('در پلن شما فعال نیست'), 'muted', 'lock'),
      h('a', { className: 'pcdn-link', href: A().upgradeUrl, 'data-ro-ok': '1', text: t('ارتقای پلن') }));
  }

  function testBtn(channel, targetId) {
    var b = P.btn(t('ارسال پیام آزمایشی'), { size: 'sm', icon: 'send', write: true, cls: 'pcdn-alert-test', onclick: function () {
      var body = { channel: channel };
      if (targetId) body.target_id = targetId;
      P.busy(b, call('POST', 'test', body)).then(function (res) {
        if (res.ok) P.toast(t('پیام آزمایشی در صف ارسال قرار گرفت.'));
        else P.toast(res.status === 429 ? t('حداکثر ۳ پیام آزمایشی در ساعت مجاز است.') : errText(res), 'error');
      });
    } });
    return b;
  }

  function targetRow(x, body) {
    var del = P.iconBtn('trash', t('حذف این مقصد (لغو دریافت)'), function () {
      P.confirm({ title: t('حذف مقصد هشدار'), danger: true, ok: t('حذف'), body: t('دیگر هیچ هشداری به {0} فرستاده نمی‌شود.', String(x.masked || '')) }).then(function (ok) {
        if (!ok) return;
        call('DELETE', 'targets/' + x.id).then(function (res) {
          if (!res.ok) { P.toast(P.errorText(res), 'error'); return; }
          P.toast(t('مقصد حذف شد.'));
          reload(body);
        });
      });
    }, { write: true, cls: 'pcdn-target-del' });
    var st = x.disabled ? P.badge(t('غیرفعال (خطای پیاپی ارسال)'), 'danger') : x.verified ? P.badge(t('تأییدشده'), 'success') : P.badge(t('در انتظار تأیید'), 'warning');
    var acts = [];
    if (x.channel === 'sms' && !x.verified) acts.push(P.btn(t('وارد کردن کد'), { size: 'sm', write: true, onclick: function () { verifyDialog(x.id, body); } }));
    if (x.verified && !x.disabled) acts.push(testBtn(x.channel, x.id));
    acts.push(del);
    return h('li', { className: 'pcdn-target', 'data-target': String(x.id), 'data-channel': String(x.channel) },
      h('bdi', { className: 'pcdn-target-val', dir: 'ltr', text: String(x.masked || '—') }), st, h('span', { className: 'pcdn-target-acts' }, acts));
  }

  function channelsCard(d, body) {
    var c = P.card({ title: t('کانال‌ها'), icon: 'send', id: 'alert-channels', subtitle: t('هشدارها از این راه‌ها به شما می‌رسند.') });
    var grid = h('div', { className: 'pcdn-ch-grid' });
    // e-mail: always available
    grid.appendChild(h('div', { className: 'pcdn-ch', 'data-ch': 'email' },
      h('div', { className: 'pcdn-ch-head' }, icon('mail'), h('strong', { text: CH.email[0] }), P.badge(t('فعال'), 'success')),
      h('p', { className: 'pcdn-muted pcdn-small', text: t('به ایمیل حساب کاربری شما فرستاده می‌شود؛ ایمیل هیچ‌وقت به تعویق نمی‌افتد.') }),
      h('div', { className: 'pcdn-row-actions' }, testBtn('email'))));
    ['sms', 'bale', 'telegram'].forEach(function (k) {
      var info = chInfo(d, k);
      if (!info || !info.available) return;   // not configured by the operator: hidden
      var box = h('div', { className: 'pcdn-ch', 'data-ch': k }, h('div', { className: 'pcdn-ch-head' }, icon(CH[k][1]), h('strong', { text: CH[k][0] })));
      if (info.plan === false) {
        box.appendChild(planNote());
        grid.appendChild(box);
        return;
      }
      var list = targetsOf(d, k);
      if (list.length) box.appendChild(h('ul', { className: 'pcdn-targets' }, list.map(function (x) { return targetRow(x, body); })));
      else box.appendChild(h('p', { className: 'pcdn-muted pcdn-small', text: k === 'sms' ? t('هنوز شماره‌ای ثبت نشده است.') : t('هنوز حسابی وصل نشده است.') }));
      box.appendChild(h('div', { className: 'pcdn-row-actions' }, k === 'sms'
        ? P.btn(t('افزودن شماره'), { size: 'sm', icon: 'plus', write: true, cls: 'pcdn-sms-add', onclick: function () { smsDialog(body); } })
        : P.btn(t('اتصال'), { size: 'sm', icon: 'link', write: true, cls: 'pcdn-link-' + k, onclick: function () { linkDialog(k, info, body); } })));
      grid.appendChild(box);
    });
    c.body.appendChild(grid);
    return c;
  }

  function latin(s) { return String(s || '').replace(/[۰-۹]/g, function (x) { return String(x.charCodeAt(0) - 0x06f0); }).replace(/[٠-٩]/g, function (x) { return String(x.charCodeAt(0) - 0x0660); }); }
  function e164(raw) {
    var s = latin(raw).replace(/[\s()-]/g, '');
    if (/^09\d{9}$/.test(s)) return '+98' + s.slice(1);
    if (/^989\d{9}$/.test(s)) return '+' + s;
    if (/^00\d{8,15}$/.test(s)) return '+' + s.slice(2);
    return s;
  }

  function smsDialog(body) {
    var d = P.dialog({ title: t('افزودن شمارهٔ پیامک'), icon: 'send' });
    var m = { phone: '' };
    var err = h('div');
    var send = P.btn(t('ارسال کد تأیید'), { kind: 'primary', icon: 'send', write: true, cls: 'pcdn-sms-send', onclick: function () {
      clear(err);
      var p = e164(m.phone);
      if (!/^\+[1-9]\d{7,14}$/.test(p)) { err.appendChild(P.alertBox('danger', t('شماره را مثل ۰۹۱۲۱۲۳۴۵۶۷ یا +989121234567 وارد کنید.'))); return; }
      P.busy(send, call('POST', 'targets/sms', { phone: p })).then(function (res) {
        if (!res.ok) {
          err.appendChild(P.alertBox('danger', res.status === 429 ? t('تعداد درخواست کد به سقف رسیده است؛ کمی بعد دوباره تلاش کنید.') : errText(res)));
          return;
        }
        d.close(true);
        reload(body).then(function () { if (res.data && res.data.target_id) verifyDialog(res.data.target_id, body); });
      });
    } });
    append(d.body, [h('p', { className: 'pcdn-muted', text: t('یک کد ۶ رقمی به این شماره پیامک می‌شود؛ تا تأیید نشود، هشداری به آن فرستاده نمی‌شود.') }),
      P.input(m, 'phone', t('شمارهٔ همراه'), { placeholder: '09121234567', maxlength: 20, type: 'tel' }), err]);
    append(d.foot, [send, P.btn(t('انصراف'), { onclick: function () { d.close(); } })]);
    d.focusFirst();
  }

  function verifyDialog(id, body) {
    var d = P.dialog({ title: t('تأیید شمارهٔ پیامک'), icon: 'checkCircle' });
    var m = { code: '' };
    var err = h('div');
    var ok = P.btn(t('تأیید'), { kind: 'primary', icon: 'check', write: true, cls: 'pcdn-sms-verify', onclick: function () {
      clear(err);
      var c = latin(m.code).trim();
      if (!/^\d{6}$/.test(c)) { err.appendChild(P.alertBox('danger', t('کد ۶ رقمی پیامک‌شده را وارد کنید.'))); return; }
      P.busy(ok, call('POST', 'targets/' + id + '/verify', { code: c })).then(function (res) {
        if (!res.ok) {
          var dd = res.data && res.data.detail;
          err.appendChild(P.alertBox('danger', typeof dd === 'string' && CODES[dd] ? CODES[dd] : res.status === 422 ? t('کد نادرست یا منقضی است.') : res.status === 429 ? t('تعداد تلاش‌ها به سقف رسید؛ کد تازه بگیرید.') : P.errorText(res)));
          return;
        }
        d.close(true);
        P.toast(t('شماره تأیید شد.'));
        reload(body);
      });
    } });
    append(d.body, [P.input(m, 'code', t('کد تأیید'), { placeholder: '123456', maxlength: 6, type: 'text' }), err,
      h('p', { className: 'pcdn-muted pcdn-small', text: t('کد ۱۰ دقیقه اعتبار دارد.') })]);
    append(d.foot, [ok, P.btn(t('بستن'), { onclick: function () { d.close(); } })]);
    d.focusFirst();
  }

  function minutesLeft(iso) {
    var ms = new Date(iso || '').getTime() - Date.now();
    return isNaN(ms) ? 15 : Math.max(1, Math.min(60, Math.round(ms / 60000)));
  }

  function linkDialog(k, info, body) {
    var d = P.dialog({ title: k === 'bale' ? t('اتصال به بله') : t('اتصال به تلگرام'), icon: 'link' });
    var holder = h('div', null, P.skeleton(3));
    d.body.appendChild(holder);
    d.foot.appendChild(P.btn(t('بستن'), { onclick: function () { d.close(); } }));
    var timer = null, stopped = false;
    function stop() { stopped = true; if (timer) clearTimeout(timer); }
    var origClose = d.close;
    d.close = function (s) { stop(); origClose(s); };
    call('POST', 'targets/' + k + '/link', {}).then(function (res) {
      clear(holder);
      if (!res.ok || !res.data || !res.data.code) { holder.appendChild(P.alertBox('danger', [h('strong', { text: t('ساخت کد اتصال ممکن نشد') + ' ' }), errText(res)])); return; }
      var r = res.data, code = String(r.code);
      var link = /^https:\/\//.test(String(r.deep_link || '')) ? String(r.deep_link) : null;
      var status = h('p', { className: 'pcdn-link-status', 'data-link-status': 'waiting' }, icon('clock'), h('span', { text: t('در انتظار پیام شما به ربات…') }));
      append(holder, [
        h('ol', { className: 'pcdn-steps-list' },
          h('li', { text: t('دکمهٔ زیر را بزنید تا ربات {0} باز شود.', info.username ? '@' + String(info.username) : '') }),
          h('li', { text: t('در گفت‌وگو با ربات «Start» را بزنید یا این پیام را بفرستید:') }),
          h('li', { text: t('همین صفحه را باز نگه دارید؛ اتصال خودکار تأیید می‌شود.') })),
        h('div', { className: 'pcdn-key-plain' }, h('code', { className: 'pcdn-key-value', dir: 'ltr', 'data-link-code': code, text: '/start ' + code }),
          P.copyBtn('/start ' + code, t('کپی پیام'), { text: t('کپی') })),
        link ? h('a', { className: 'pcdn-btn pcdn-btn-primary pcdn-open-bot', href: link, target: '_blank', rel: 'noopener noreferrer', 'data-ro-ok': '1' },
          icon('external'), h('span', { text: k === 'bale' ? t('باز کردن ربات در بله') : t('باز کردن ربات در تلگرام') })) : null,
        h('p', { className: 'pcdn-muted pcdn-small', text: t('کد یک‌بارمصرف است و {0} دقیقه اعتبار دارد. با فرستادن /stop به ربات، دریافت هشدار متوقف می‌شود.', num(minutesLeft(r.expires_at))) }),
        status]);
      var n = 0;
      (function poll() {
        if (stopped) return;
        timer = setTimeout(function () {
          if (stopped) return;
          n++;
          call('GET', 'targets/link/' + code).then(function (q) {
            if (stopped) return;
            if (q.ok && q.data && q.data.linked) {
              status.setAttribute('data-link-status', 'linked');
              clear(status);
              append(status, [icon('checkCircle'), h('span', { text: t('اتصال برقرار شد.') })]);
              P.toast(t('اتصال برقرار شد.'));
              stop();
              reload(body);
              return;
            }
            if (q.status === 404 || q.status === 410 || n >= 300) {
              status.setAttribute('data-link-status', 'expired');
              clear(status);
              append(status, [icon('xCircle'), h('span', { text: t('کد منقضی شد؛ پنجره را ببندید و دوباره «اتصال» را بزنید.') })]);
              stop();
              return;
            }
            poll();
          });
        }, Number(window.PCDN_LINK_POLL_MS) > 0 ? Number(window.PCDN_LINK_POLL_MS) : 3000);   // test hook: e2e shortens the interval
      })();
    });
    d.focusFirst();
  }

  // ------------------------------------------------------------------ subscriptions

  function subsCard(d, body) {
    var max = (d.limits && Number(d.limits.max_subscriptions)) || 20;
    var draft = (Array.isArray(d.subscriptions) ? d.subscriptions : []).map(function (s) { return clone(s); });
    var c = P.card({ title: t('اشتراک‌ها'), icon: 'bell', id: 'alert-subs', subtitle: t('کدام رویدادها، از کدام سرویس‌ها و از چه راهی به شما خبر داده شود.') });
    var list = h('div', { className: 'pcdn-subs' });
    var status = h('div');
    var save = P.btn(t('ذخیرهٔ اشتراک‌ها'), { kind: 'primary', icon: 'check', write: true, cls: 'pcdn-subs-save', onclick: function () {
      clear(status);
      var items = draft.map(serialize);
      var bad = items.filter(function (x) { return !x.events.length || !x.channels.length; });
      if (bad.length) { status.appendChild(P.alertBox('danger', t('هر اشتراک باید دست‌کم یک رویداد و یک کانال داشته باشد.'))); return; }
      P.busy(save, call('PUT', 'subscriptions', { items: items })).then(function (res) {
        if (!res.ok) {
          status.appendChild(P.alertBox('danger', errText(res)));
          return;
        }
        if (res.data && res.data.channels) S.data = res.data;
        P.toast(t('اشتراک‌های هشدار ذخیره شد.'));
        draw(body);
      });
    } });
    var add = P.btn(t('افزودن اشتراک'), { size: 'sm', icon: 'plus', write: true, cls: 'pcdn-sub-add', onclick: function () {
      if (draft.length >= max) { P.toast(t('حداکثر {0} اشتراک مجاز است.', num(max)), 'error'); return; }
      draft.push({ site: null, events: ['origin.down', 'origin.up', 'ssl.expiring'].filter(function (e) { return catalog(d).indexOf(e) >= 0; }),
        channels: ['email'], lang: P.isEn ? 'en' : 'fa', quiet_hours: null, enabled: true });
      redraw();
    } });
    function redraw() {
      clear(list);
      if (!draft.length) list.appendChild(P.empty('bell', t('هنوز اشتراکی ندارید'), t('با «افزودن اشتراک» انتخاب کنید کدام رویدادها به شما خبر داده شود.')));
      draft.forEach(function (s, i) { list.appendChild(subEditor(d, s, i, draft, redraw)); });
      if (A().lockWrites) A().lockWrites(list);
    }
    redraw();
    append(c.body, [list, status, h('div', { className: 'pcdn-row-actions' }, add, save),
      h('p', { className: 'pcdn-muted pcdn-small', text: t('حداکثر {0} اشتراک. پیام‌ها خلاصه‌اند و جزئیات در همین پنل است؛ هیچ پیامی اطلاعات داخلی شبکه را ندارد.', num(max)) })]);
    return c;
  }
  function clone(x) { return JSON.parse(JSON.stringify(x || {})); }
  function catalog(d) { return (Array.isArray(d.events) ? d.events : []).map(function (e) { return e && e.event; }).filter(Boolean); }
  function serialize(s) {
    var q = s.quiet_hours && s.quiet_hours.start && s.quiet_hours.end ? { start: s.quiet_hours.start, end: s.quiet_hours.end, bypass_critical: s.quiet_hours.bypass_critical !== false } : null;
    var o = { site: s.site || null, events: (s.events || []).slice(), channels: (s.channels || []).slice(), lang: s.lang === 'en' ? 'en' : 'fa', quiet_hours: q, enabled: s.enabled !== false };
    if (s.id) o.id = s.id;
    return o;
  }

  function subEditor(d, s, i, draft, redraw) {
    var dom = (A().S.site && A().S.site.domain) || '';
    var scopes = [[null, t('همهٔ سرویس‌ها')]];
    if (dom) scopes.push([dom, t('فقط {0}', dom)]);
    if (s.site && s.site !== dom) scopes.push([s.site, t('فقط {0}', s.site)]);
    var evs = (Array.isArray(d.events) ? d.events : []).filter(function (e) { return e && e.event && (s.site ? e.site_scoped !== false : true); });
    var evBox = h('div', { className: 'pcdn-sub-events' }, evs.map(function (e) {
      var id = P.uid('pcdn-ev-');
      var on = (s.events || []).indexOf(e.event) >= 0;
      var sev = SEV[e.severity] || null;
      return h('label', { className: 'pcdn-ev', 'for': id, 'data-event': e.event },
        h('input', { type: 'checkbox', id: id, checked: on, onchange: function (ev) {
          s.events = (s.events || []).filter(function (x) { return x !== e.event; });
          if (ev.target.checked) s.events.push(e.event);
        } }),
        h('span', { className: 'pcdn-ev-text' }, h('span', { className: 'pcdn-ev-title' }, h('span', { text: evLabel(e.event) }), sev ? P.badge(sev[0], sev[1]) : null),
          EVENTS[e.event] ? h('span', { className: 'pcdn-muted pcdn-small', text: EVENTS[e.event][1] }) : null));
    }));
    var chBox = h('div', { className: 'pcdn-checks', role: 'group', 'aria-label': t('کانال‌ها') }, ['email', 'sms', 'bale', 'telegram'].map(function (k) {
      var info = k === 'email' ? { available: true, plan: true } : chInfo(d, k);
      if (!info || !info.available) return null;
      var id = P.uid('pcdn-sc-');
      var off = info.plan === false;
      return h('label', { className: 'pcdn-check' + (off ? ' is-off' : ''), 'for': id, 'data-sub-ch': k, title: off ? t('در پلن شما فعال نیست') : null },
        h('input', { type: 'checkbox', id: id, checked: (s.channels || []).indexOf(k) >= 0 && !off, disabled: off, onchange: function (ev) {
          s.channels = (s.channels || []).filter(function (x) { return x !== k; });
          if (ev.target.checked) s.channels.push(k);
        } }), h('span', { text: CH[k][0] + (off ? ' — ' + t('در پلن شما فعال نیست') : '') }));
    }));
    var quiet = { on: !!s.quiet_hours };
    var qh = s.quiet_hours || { start: '23:00', end: '07:00', bypass_critical: true };
    var qBox = h('div', { className: 'pcdn-quiet', hidden: !quiet.on },
      h('label', { className: 'pcdn-quiet-time' }, h('span', { text: t('از') }),
        h('input', { type: 'time', className: 'pcdn-input pcdn-ltr', dir: 'ltr', value: qh.start, 'aria-label': t('شروع ساعات سکوت'), onchange: function (e) { qh.start = e.target.value; if (quiet.on) s.quiet_hours = qh; } })),
      h('label', { className: 'pcdn-quiet-time' }, h('span', { text: t('تا') }),
        h('input', { type: 'time', className: 'pcdn-input pcdn-ltr', dir: 'ltr', value: qh.end, 'aria-label': t('پایان ساعات سکوت'), onchange: function (e) { qh.end = e.target.value; if (quiet.on) s.quiet_hours = qh; } })),
      P.toggle(qh, 'bypass_critical', t('هشدارهای بحرانی در ساعات سکوت هم ارسال شوند'), { onchange: function () { if (quiet.on) s.quiet_hours = qh; } }),
      h('p', { className: 'pcdn-muted pcdn-small', text: t('به وقت تهران. پیام‌های غیر بحرانی تا پایان ساعات سکوت نگه داشته و یک‌جا فرستاده می‌شوند؛ ایمیل هیچ‌وقت عقب نمی‌افتد.') }));
    var box = h('section', { className: 'pcdn-sub' + (s.enabled === false ? ' is-off' : ''), 'data-sub': String(i) },
      h('div', { className: 'pcdn-sub-head' },
        h('strong', { text: t('اشتراک {0}', num(i + 1)) }),
        P.switchInput(s.enabled !== false, t('فعال'), function (v) { s.enabled = v; box.classList.toggle('is-off', !v); }, { write: true }),
        P.iconBtn('trash', t('حذف این اشتراک'), function () { draft.splice(i, 1); redraw(); }, { write: true, cls: 'pcdn-sub-del' })),
      h('div', { className: 'pcdn-grid' },
        P.select(s, 'site', t('دامنه'), scopes, { onchange: function () { redraw(); } }),
        P.select(s, 'lang', t('زبان پیام‌ها'), [['fa', t('فارسی')], ['en', t('انگلیسی')]])),
      P.field(t('رویدادها'), evBox),
      P.field(t('کانال‌ها'), chBox),
      P.toggle(quiet, 'on', t('ساعات سکوت'), { cls: 'pcdn-quiet-on', onchange: function (v) { qBox.hidden = !v; s.quiet_hours = v ? qh : null; } }),
      qBox);
    return box;
  }

  pages.alerts = {
    title: t('هشدارها'), icon: 'bell', heading: t('هشدارها'),
    desc: t('قطعی سرور اصلی، انقضای SSL، اتمام ترافیک و رخدادهای سکو را با ایمیل، پیامک، بله یا تلگرام دریافت کنید.'),
    hidden: function () { return !allowed() || S.ok !== true; },
    render: function () { return render(); }
  };
})();
