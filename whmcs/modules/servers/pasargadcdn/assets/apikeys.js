/*
 * Pasargad CDN — client app: «API و کلیدها» (SPEC §10.1).
 *
 * Registers PCDN.pages.apikeys. Lists / creates / revokes the site's customer
 * API keys through the api.php proxy (paths sites/{d}/apikeys...). The plaintext
 * key is shown ONCE, right after creation, and never again. All data reaches the
 * DOM through textContent / createElement only.
 */
(function () {
  'use strict';
  var P = window.PCDN = window.PCDN || {};
  var t = P.t;  // i18n.js (SPEC §16.10)
  if (!P.h) return;
  var h = P.h, append = P.append, clear = P.clear, icon = P.icon, num = P.num, api = P.api;
  var pages = P.pages = P.pages || {};
  function A() { return P.app; }

  // Public documentation of the customer API (docs/API.md in the repository).
  var DOCS_URL = 'https://docs.pasargadmizban.com/cdn/api';
  var CAPI_HOST = 'https://cdn-api.pasargadmizban.com';
  var OPENAPI_URL = CAPI_HOST + '/capi/v1/openapi.json';
  var MAX_KEYS = 5;
  var SCOPES = [
    ['purge', t('پاکسازی کش'), t('ارسال درخواست پاکسازی کش (‎/capi/v1/purge)')],
    ['stats', t('آمار و رویدادها'), t('خواندن آنالیتیکس و رویدادها (‎/capi/v1/analytics‎، ‎/capi/v1/events)')],
    // Scopes split by the controller (security review): `dns` = records only, `config` = configuration
    // sections, `functions` = edge functions. Keys created before keep whatever scopes they had.
    ['dns', t('رکوردهای DNS'), t('مدیریت رکوردهای DNS (‎/capi/v1/records)')],
    ['config', t('تنظیمات سایت'), t('خواندن و تغییر بخش‌های پیکربندی مثل کش، امنیت و SSL (‎/capi/v1/config)')],
    ['functions', t('توابع لبه'), t('مدیریت کد و مسیرهای توابع لبه (‎/capi/v1/functions)')]
  ];
  function scopeLabel(s) {
    for (var i = 0; i < SCOPES.length; i++) if (SCOPES[i][0] === s) return SCOPES[i][1];
    return s;
  }

  function curlSnippet(key) {
    return 'curl -X POST ' + CAPI_HOST + '/capi/v1/purge \\\n' +
      '  -H "Authorization: Bearer ' + (key || 'pcdn_...') + '" \\\n' +
      '  -H "Content-Type: application/json" \\\n' +
      "  -d '{\"everything\": true}'";
  }

  function render(Aa) {
    Aa = Aa || A();
    var wrap = h('div', { className: 'pcdn-stack', 'data-panel-body': 'apikeys' });
    var listCard = P.card({ title: t('کلیدهای API'), icon: 'key', id: 'apikeys-list' });
    var listBody = h('div', { 'data-keys': 'list' }, P.skeleton(3));
    append(listCard.body, listBody);
    append(wrap, [createCard(Aa, function () { reload(listBody, Aa); }), listCard, howToCard()]);
    reload(listBody, Aa);
    return wrap;
  }

  function reload(listBody, Aa) {
    clear(listBody);
    listBody.appendChild(P.skeleton(3));
    api('GET', 'apikeys').then(function (res) {
      clear(listBody);
      if (!res.ok) { listBody.appendChild(P.alertBox('danger', P.errorText(res))); return; }
      var keys = Array.isArray(res.data) ? res.data : (res.data && res.data.keys) || [];
      renderList(listBody, keys, Aa);
    });
  }

  function renderList(listBody, keys, Aa) {
    if (!keys.length) {
      listBody.appendChild(P.empty('key', t('هنوز کلیدی نساخته‌اید'),
        t('برای اتصال برنامه‌ها یا اسکریپت‌های خودتان به CDN، یک کلید API با دسترسی محدود بسازید.')));
      return;
    }
    var tbl = h('table', { className: 'pcdn-table pcdn-keys-table' },
      h('thead', null, h('tr', null,
        h('th', { text: t('نام') }), h('th', { text: t('دسترسی‌ها') }), h('th', { text: t('ساخته‌شده') }),
        h('th', { text: t('آخرین استفاده') }), h('th', { className: 'pcdn-th-actions', text: '' }))),
      h('tbody', null, keys.map(function (k) { return keyRow(k, listBody, Aa); })));
    listBody.appendChild(h('div', { className: 'pcdn-table-wrap' }, tbl));
    listBody.appendChild(h('p', { className: 'pcdn-muted pcdn-small', text: t('حداکثر ') + num(MAX_KEYS) + t(' کلید برای هر سرویس. کلید لغوشده دیگر کار نمی‌کند.') }));
  }

  function keyRow(k, listBody, Aa) {
    var scopes = Array.isArray(k.scopes) ? k.scopes : [];
    var revoked = !!k.revoked;
    var scopeCell = h('div', { className: 'pcdn-key-scopes' }, scopes.length
      ? scopes.map(function (s) { return P.badge(scopeLabel(s), 'brand'); })
      : h('span', { className: 'pcdn-muted', text: '—' }));
    var revoke = P.btn(t('لغو'), { icon: 'trash', size: 'sm', kind: 'ghost', write: true, cls: 'pcdn-key-revoke', onclick: function () {
      P.confirm({ title: t('لغو کلید API'), danger: true, ok: t('لغو کلید'),
        body: t('کلید «') + (k.name || '') + t('» بلافاصله از کار می‌افتد و هر برنامه‌ای که از آن استفاده می‌کند دیگر به CDN دسترسی نخواهد داشت. این کار برگشت‌پذیر نیست.') })
        .then(function (ok) {
          if (!ok) return;
          P.busy(revoke, api('DELETE', 'apikeys/' + encodeURIComponent(k.id))).then(function (res) {
            if (!res.ok) { P.toast(P.errorText(res), 'error'); return; }
            P.toast(t('کلید لغو شد.'), 'success');
            reload(listBody, Aa);
          });
        });
    } });
    return h('tr', { className: 'pcdn-key-row' + (revoked ? ' is-revoked' : ''), 'data-key-id': String(k.id) },
      h('td', null, h('span', { className: 'pcdn-key-name', text: k.name || '—' }), revoked ? P.badge(t('لغوشده'), 'danger') : null),
      h('td', null, scopeCell),
      h('td', { className: 'pcdn-key-date', text: k.created_at ? P.date(k.created_at, { dateStyle: 'medium' }) : '—' }),
      h('td', { className: 'pcdn-key-date', text: k.last_used_at ? P.date(k.last_used_at) : t('هرگز') }),
      h('td', { className: 'pcdn-td-actions' }, revoked ? null : revoke));
  }

  function createCard(Aa, onCreated) {
    var c = P.card({ title: t('ساخت کلید جدید'), icon: 'plus', id: 'apikeys-new', tone: 'brand' });
    var model = { name: '', scopes: [] };
    var reveal = h('div', { 'data-keys': 'reveal' });
    var nameInput = P.input(model, 'name', t('نام کلید (برای شناسایی، مثلاً «اسکریپت پاکسازی»)'),
      { ltr: false, maxlength: 60, placeholder: t('اسکریپت من') });
    var scopeBox = P.checks(model, 'scopes', t('دسترسی‌ها'), SCOPES.map(function (s) { return [s[0], s[1] + ' — ' + s[2]]; }));
    var create = P.btn(t('ساخت کلید'), { kind: 'primary', icon: 'key', write: true, cls: 'pcdn-key-create', onclick: function () {
      var name = String(model.name || '').trim();
      if (!name) { P.toast(t('یک نام برای کلید وارد کنید.'), 'error'); return; }
      if (!model.scopes.length) { P.toast(t('دست‌کم یک دسترسی را انتخاب کنید.'), 'error'); return; }
      P.busy(create, api('POST', 'apikeys', { name: name, scopes: model.scopes.slice() })).then(function (res) {
        if (!res.ok) { P.toast(P.errorText(res), 'error'); return; }
        var key = res.data && res.data.key;
        clear(reveal);
        if (key) reveal.appendChild(revealBox(key));
        model.name = ''; model.scopes.length = 0;
        var inp = nameInput.querySelector('input'); if (inp) inp.value = '';
        onCreated(); // refresh only the list card, keeping the one-time key visible
        P.toast(t('کلید ساخته شد.'), 'success');
      });
    } });
    append(c.body, [nameInput, scopeBox, reveal, h('div', { className: 'pcdn-row-actions' }, create)]);
    return c;
  }

  function revealBox(key) {
    return h('div', { className: 'pcdn-key-reveal', 'data-key-plain': '1', role: 'status' },
      P.alertBox('warning', [
        h('strong', { text: t('این کلید دیگر نمایش داده نمی‌شود. ') }),
        t('همین حالا آن را در جای امنی ذخیره کنید؛ اگر گم شود باید کلید جدیدی بسازید.')], { icon: 'warn' }),
      h('div', { className: 'pcdn-key-plain' },
        h('code', { className: 'pcdn-key-value', dir: 'ltr', text: key }),
        P.copyBtn(key, t('کپی کلید'), { text: t('کپی'), done: t('کلید کپی شد') })));
  }

  function howToCard() {
    var c = P.card({ title: t('استفاده از کلید'), icon: 'book', id: 'apikeys-howto' });
    append(c.body, [
      h('p', { className: 'pcdn-muted', text: t('کلید را در هدر Authorization به‌صورت Bearer بفرستید. نمونه پاکسازی کامل کش:') }),
      h('pre', { className: 'pcdn-code-block', dir: 'ltr' }, h('code', { text: curlSnippet(null) }),
        P.copyBtn(curlSnippet(null), t('کپی دستور'), { text: t('کپی'), done: t('کپی شد') })),
      h('p', { className: 'pcdn-muted pcdn-small' }, t('دسترسی هر کلید محدود به همین سرویس است. راهنمای کامل هر بخش (purge / stats / dns): '),
        h('a', { className: 'pcdn-link pcdn-apikeys-docs', href: DOCS_URL, target: '_blank', rel: 'noopener noreferrer', 'data-ro-ok': '1' },
          h('span', { text: t('مستندات API') }), icon('external'))),
      // SPEC §14.3.5: machine-readable description of the same customer API (no auth needed), e.g. for code generators
      h('p', { className: 'pcdn-muted pcdn-small' }, t('مشخصات ماشینی API برای ابزارهای تولید کد و Postman: '),
        h('a', { className: 'pcdn-link pcdn-apikeys-openapi', href: OPENAPI_URL, target: '_blank', rel: 'noopener noreferrer', 'data-ro-ok': '1' },
          h('span', { text: 'OpenAPI (openapi.json)' }), icon('external')))
    ]);
    return c;
  }

  pages.apikeys = {
    title: t('API و کلیدها'), icon: 'key',
    desc: t('کلیدهای API برای اتصال برنامه‌ها و اسکریپت‌های شما به CDN — پاکسازی کش، آمار و مدیریت DNS از راه دور.'),
    render: function (Aa) { return render(Aa); }
  };
})();
