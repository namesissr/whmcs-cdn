/*
 * Pasargad CDN — configuration pages (cache, page rules, image, pools, firewall,
 * WAF, DDoS, rate limit, hotlink, SSL, headers, error pages).
 * Registers into window.PCDN.pages; app.js provides the shell (PCDN.app) at render time.
 */
(function () {
  'use strict';
  var P = window.PCDN = window.PCDN || {};
  var pages = P.pages = P.pages || {};
  var h = P.h, append = P.append, clear = P.clear, icon = P.icon, ltr = P.ltr, clone = P.clone, num = P.num;

  function A() { return P.app; }
  function site() { return P.app.S.site; }
  function domain() { return site().domain; }

  var TTL_PICKS = [[3600, '۱ ساعت'], [86400, '۱ روز'], [604800, '۱ هفته'], [2592000, '۱ ماه']];

  // ------------------------------------------------------------------ shared building blocks

  /** Grid of preset tiles. items: [{id, title, desc, icon, apply(draft), active?(draft), disabled?}] */
  function presets(title, subtitle, items, d, f) {
    var c = P.card({ title: title, subtitle: subtitle, icon: 'sparkles', tone: 'violet', cls: 'pcdn-presets-card', id: 'presets' });
    append(c.body, h('div', { className: 'pcdn-presets', 'data-n': String(items.length) }, items.map(function (it) {
      var act = it.active ? it.active(d) : false;
      var b = h('button', { type: 'button', className: 'pcdn-preset' + (act ? ' is-active' : ''), 'data-preset': it.id, 'data-write': '1',
        disabled: !!it.disabled, title: it.disabled || null, 'aria-pressed': it.active ? String(act) : null,
        onclick: function () {
          it.apply(d);
          f.redraw();
          P.toast(it.done || ('الگوی «' + it.title + '» اعمال شد؛ بررسی کنید و «ذخیره» را بزنید.'), 'info');
          var hl = f.el.querySelector('.is-new');
          if (hl && hl.scrollIntoView) hl.scrollIntoView({ block: 'nearest', behavior: A().reduced() ? 'auto' : 'smooth' });
        } },
        h('span', { className: 'pcdn-preset-icon' }, icon(it.icon || 'sparkles')),
        h('span', { className: 'pcdn-preset-text' }, h('span', { className: 'pcdn-preset-title', text: it.title }), h('span', { className: 'pcdn-preset-desc', text: it.desc })),
        act ? h('span', { className: 'pcdn-preset-badge', text: 'فعلی' }) : null,
        it.disabled ? h('span', { className: 'pcdn-preset-badge is-muted', text: 'سقف پلن' }) : null);
      return b;
    })));
    return c;
  }

  function limitText(n, max, what) {
    return h('span', { className: 'pcdn-limit' + (n >= max ? ' is-full' : '') }, num(n) + ' از ' + num(max) + ' ' + what);
  }

  /** Drawer editor over a clone; ok(copy) is called on «تأیید». sentence(copy) feeds a live preview. */
  function editDrawer(title, subtitle, obj, build, ok, validate, sentence) {
    var copy = clone(obj);
    var d = P.dialog({ title: title, subtitle: subtitle, icon: 'edit', kind: 'drawer', wide: true });
    var holder = h('div', { className: 'pcdn-form' });
    var err = h('div');
    var pv = sentence ? h('div', { className: 'pcdn-sentence', 'aria-live': 'polite' }) : null;
    function updatePreview() { if (pv) { clear(pv); append(pv, sentence(copy)); } }
    if (pv) d.body.appendChild(h('div', { className: 'pcdn-preview' }, h('span', { className: 'pcdn-label', text: 'پیش‌نمایش' }), pv));
    d.body.appendChild(err);
    d.body.appendChild(holder);
    holder.addEventListener('input', updatePreview);
    holder.addEventListener('change', updatePreview);
    function redraw() {
      var all = holder.querySelectorAll('input,select,textarea,button');
      var focusIdx = Array.prototype.indexOf.call(all, document.activeElement);
      clear(holder);
      append(holder, build(copy, redraw));
      A().lockWrites(holder);
      updatePreview();
      if (focusIdx >= 0) { var els = holder.querySelectorAll('input,select,textarea,button'); if (els[focusIdx]) els[focusIdx].focus(); }
    }
    redraw();
    var okBtn = P.btn('تأیید', { kind: 'primary', icon: 'check', write: true, cls: 'pcdn-drawer-ok', onclick: function () {
      clear(err);
      var problem = validate ? validate(copy) : null;
      if (problem) { err.appendChild(P.alertBox('danger', problem)); err.scrollIntoView && err.scrollIntoView({ block: 'nearest' }); return; }
      d.close(true);
      ok(copy);
    } });
    append(d.foot, [okBtn, P.btn('انصراف', { onclick: function () { d.close(); } })]);
    A().lockWrites(d.el);
    d.focusFirst();
    return d;
  }

  /**
   * Ordered rule list with enable switch, reorder, edit (drawer) and delete — all on the form draft.
   * cfg: {key, max, what, sentence(rule) → nodes, edit(rule|null, done(rule)), empty: [icon, title, text], addLabel}
   */
  function ruleList(d, f, cfg) {
    var key = cfg.key || 'rules';
    d[key] = d[key] || [];
    var arr = d[key];
    var full = arr.length >= cfg.max;
    var add = P.btn(cfg.addLabel || 'قانون جدید', { kind: 'primary', icon: 'plus', size: 'sm', write: true, cls: 'pcdn-add-rule', disabled: full,
      title: full ? 'به سقف ' + num(cfg.max) + ' ' + cfg.what + ' پلن رسیده‌اید' : null,
      onclick: function () { cfg.edit(null, function (r) { r._new = true; arr.push(r); f.redraw(); }); } });
    var c = P.card({ title: cfg.title, icon: cfg.icon, id: 'rules', subtitle: cfg.subtitle, actions: [limitText(arr.length, cfg.max, cfg.what), add] });
    if (!arr.length) {
      c.body.appendChild(P.empty(cfg.empty[0], cfg.empty[1], cfg.empty[2]));
      return c;
    }
    var list = h('ol', { className: 'pcdn-rules' });
    arr.forEach(function (r, i) {
      var isNew = !!r._new;
      var li = h('li', { className: 'pcdn-rule' + (r.enabled === false ? ' is-off' : '') + (isNew ? ' is-new' : ''), 'data-rule': r.id || r.name || i },
        h('span', { className: 'pcdn-rule-no', 'aria-hidden': 'true', text: num(i + 1) }),
        h('div', { className: 'pcdn-rule-main' },
          cfg.label ? h('div', { className: 'pcdn-rule-name' }, cfg.label(r), isNew ? P.badge('ذخیره نشده', 'warning') : null) : null,
          h('div', { className: 'pcdn-sentence' }, cfg.sentence(r))),
        h('div', { className: 'pcdn-rule-ctl' },
          'enabled' in r ? P.switchInput(r.enabled, (r.enabled ? 'غیرفعال کردن' : 'فعال کردن') + ' قانون ' + num(i + 1), function (v) { r.enabled = v; f.redraw(); }, { write: true, small: true }) : null,
          P.iconBtn('up', 'انتقال قانون ' + num(i + 1) + ' به بالا', function () { move(arr, i, -1); f.redraw(); focusRule(f, i - 1, 'up'); }, { write: true, disabled: i === 0 }),
          P.iconBtn('down', 'انتقال قانون ' + num(i + 1) + ' به پایین', function () { move(arr, i, 1); f.redraw(); focusRule(f, i + 1, 'down'); }, { write: true, disabled: i === arr.length - 1 }),
          P.iconBtn('edit', 'ویرایش قانون ' + num(i + 1), function () { cfg.edit(r, function (nr) { if (r._new) nr._new = true; arr[i] = nr; f.redraw(); }); }, { write: true }),
          P.iconBtn('trash', 'حذف قانون ' + num(i + 1), function () { arr.splice(i, 1); f.redraw(); P.toast('قانون از فهرست حذف شد؛ برای اعمال «ذخیره» را بزنید.', 'info'); }, { write: true, cls: 'is-danger' })));
      P.reg(key + '.' + i, li);
      list.appendChild(li);
    });
    c.body.appendChild(list);
    if (cfg.foot) c.body.appendChild(cfg.foot);
    return c;
  }
  function move(arr, i, dlt) {
    var j = i + dlt;
    if (j < 0 || j >= arr.length) return;
    var t = arr[i]; arr[i] = arr[j]; arr[j] = t;
  }
  function focusRule(f, i, dir) {
    var li = f.el.querySelectorAll('.pcdn-rule')[i];
    if (!li) return;
    var b = li.querySelector('[aria-label*="' + (dir === 'up' ? 'بالا' : 'پایین') + '"]:not([disabled])') || li.querySelector('button:not([disabled])');
    if (b) b.focus();
  }
  /** Strips client-only markers before PUT. */
  function stripNew(key) {
    return function (d) {
      (d[key] || []).forEach(function (r) { delete r._new; });
      return d;
    };
  }

  function chipsOf(values, o) {
    o = o || {};
    return (Array.isArray(values) ? values : [values]).map(function (v, i, all) {
      var t = String(v);
      return [h('bdi', { className: 'pcdn-vchip', dir: 'ltr', title: o.country ? P.country(t) : null, text: t }),
        o.country && P.country(t) !== t ? h('span', { className: 'pcdn-vcc', text: '(' + P.country(t) + ')' }) : null,
        i < all.length - 1 ? h('span', { className: 'pcdn-sep', text: '، ' }) : null];
    });
  }
  function word(t, cls) { return h('span', { className: cls || 'pcdn-w', text: t }); }

  // ------------------------------------------------------------------ cache

  var CACHE_PRESETS = [
    { id: 'general', title: 'وب‌سایت عمومی', icon: 'globe', desc: 'سایت خبری، شرکتی یا وبلاگ: کش استاندارد یک‌روزه و کش مرورگر ۴ ساعته.',
      v: { enabled: true, level: 'standard', edge_ttl: 86400, browser_ttl: 14400, ignore_query: false, bypass_cookies: ['PHPSESSID', 'wordpress_logged_in'], always_online: true } },
    { id: 'shop', title: 'فروشگاه اینترنتی و وردپرس', icon: 'star', desc: 'ووکامرس و وردپرس: سبد خرید و کاربران واردشده هرگز از کش پاسخ نمی‌گیرند.',
      v: { enabled: true, level: 'standard', edge_ttl: 86400, browser_ttl: 0, ignore_query: false,
        bypass_cookies: ['wordpress_logged_in', 'wp-postpass_', 'comment_author_', 'woocommerce_items_in_cart', 'wp_woocommerce_session_', 'woocommerce_cart_hash', 'PHPSESSID'], always_online: true } },
    { id: 'api', title: 'API و محتوای پویا', icon: 'code', desc: 'پاسخ‌ها طبق Cache-Control سرور و حداکثر ۱ دقیقه کش می‌شوند؛ نسخه قدیمی نمایش داده نمی‌شود.',
      v: { enabled: true, level: 'standard', edge_ttl: 60, browser_ttl: 0, ignore_query: false, bypass_cookies: ['PHPSESSID', 'laravel_session', 'session'], always_online: false } }
  ];
  function sameCache(d, v) {
    return Object.keys(v).every(function (k) { return JSON.stringify(d[k]) === JSON.stringify(v[k]); });
  }

  function renderCache() {
    var f = A().sectionForm('cache', function (d, f2) {
      var settings = P.card({ title: 'تنظیمات کش', icon: 'zap', id: 'settings' });
      append(settings.body, [
        P.toggle(d, 'enabled', 'کش CDN', { help: 'اگر خاموش باشد همه درخواست‌ها مستقیم به سرور اصلی می‌روند.', onchange: f2.redraw }),
        d.enabled ? [
          P.choice(d, 'level', 'سطح کش', [
            ['standard', 'استاندارد', 'از هدر Cache-Control سرور پیروی می‌کند و فایل‌های ثابت (تصویر، CSS، JS) را کش می‌کند. برای اغلب سایت‌ها مناسب است.', 'zap', 'پیشنهادی'],
            ['aggressive', 'تهاجمی', 'همه پاسخ‌های ۲۰۰ و ۳۰۱ کش می‌شوند و کوکی و Cache-Control نادیده گرفته می‌شود. فقط برای سایت‌های کاملاً ایستا.', 'warn']
          ], { cols: 2 }),
          d.level === 'aggressive' ? P.alertBox('warning', 'در حالت تهاجمی صفحاتی مثل سبد خرید یا پنل کاربری هم ممکن است کش شوند و اطلاعات یک کاربر به دیگران نمایش داده شود. برای این مسیرها قانون صفحه «بدون کش» بسازید.') : null,
          h('div', { className: 'pcdn-grid' },
            P.duration(d, 'edge_ttl', 'مدت نگهداری در CDN', { min: 60, max: 31536000, picks: TTL_PICKS, help: 'فایل‌های ثابت حداکثر این مدت در سرورهای CDN می‌مانند.' }),
            P.duration(d, 'browser_ttl', 'مدت نگهداری در مرورگر', { min: 0, zeroText: 'طبق هدر سرور اصلی', picks: [[0, 'طبق سرور'], [3600, '۱ ساعت'], [86400, '۱ روز']], help: '۰ یعنی هدر سرور اصلی دست نمی‌خورد.' })),
          P.toggle(d, 'ignore_query', 'نادیده گرفتن Query String', { help: 'آدرس‌های ‎?a=1 و ‎?a=2 یک نسخه کش مشترک می‌گیرند. اگر از ‎?v= برای نسخه‌بندی فایل‌ها استفاده می‌کنید خاموش بگذارید.' }),
          P.tags(d, 'bypass_cookies', 'کوکی‌های عبور از کش', { placeholder: 'wordpress_logged_in', help: 'اگر بازدیدکننده کوکی‌ای داشته باشد که نامش با یکی از این‌ها شروع شود، پاسخ از کش داده نمی‌شود (مثلاً کاربران واردشده).' }),
          P.toggle(d, 'always_online', 'همیشه آنلاین', { help: 'اگر سرور اصلی خطا بدهد یا در دسترس نباشد، آخرین نسخه کش‌شده نمایش داده می‌شود.' }),
          P.toggle(d, 'dev_mode', 'حالت توسعه', { help: 'کش موقتاً خاموش می‌شود تا تغییرات سایت فوراً دیده شوند. بعد از پایان کار خاموشش کنید.' })
        ] : null
      ]);
      return [presets('الگوهای آماده', 'نوع سایت خود را انتخاب کنید تا تنظیمات مناسب پر شود؛ سپس بررسی و ذخیره کنید.', CACHE_PRESETS.map(function (p) {
        return { id: p.id, title: p.title, desc: p.desc, icon: p.icon, active: function (x) { return sameCache(x, p.v); },
          apply: function (x) { Object.keys(p.v).forEach(function (k) { x[k] = clone(p.v[k]); }); } };
      }), d, f2), settings];
    });
    return [f.el, purgeCard()];
  }

  function purgeCard() {
    var c = P.card({ title: 'پاکسازی کش', icon: 'refresh', id: 'purge', subtitle: 'بعد از تغییر فایل‌های سایت، نسخه قدیمی را از کش حذف کنید.' });
    var st = { urls: '', prefixes: '' };
    var one = P.btn('پاکسازی آدرس‌ها', { kind: 'primary', icon: 'refresh', write: true, cls: 'pcdn-purge-urls', onclick: function () {
      var urls = st.urls.split(/\s+/).map(function (x) { return x.trim(); }).filter(Boolean);
      if (!urls.length) { P.toast('حداقل یک آدرس وارد کنید.', 'warn'); return; }
      if (urls.length > 100) { P.toast('حداکثر ۱۰۰ آدرس در هر درخواست.', 'warn'); return; }
      P.busy(one, P.api('POST', 'purge', { urls: urls })).then(function (res) {
        P.toast(res.ok ? 'درخواست پاکسازی ' + num(urls.length) + ' آدرس ثبت شد و تا چند ثانیه روی همه سرورها اعمال می‌شود.' : P.errorText(res), res.ok ? 'success' : 'error');
      });
    } });
    var pfx = P.btn('پاک‌سازی بر اساس پیشوند', { kind: 'primary', icon: 'refresh', write: true, cls: 'pcdn-purge-prefixes', onclick: function () {
      var prefixes = st.prefixes.split(/\s+/).map(function (x) { return x.trim(); }).filter(Boolean);
      if (!prefixes.length) { P.toast('حداقل یک پیشوند وارد کنید.', 'warn'); return; }
      if (prefixes.length > 20) { P.toast('حداکثر ۲۰ پیشوند در هر درخواست.', 'warn'); return; }
      P.busy(pfx, P.api('POST', 'purge', { prefixes: prefixes })).then(function (res) {
        P.toast(res.ok ? 'درخواست پاک‌سازی ' + num(prefixes.length) + ' پیشوند ثبت شد؛ همه فایل‌های زیر این مسیرها حذف می‌شوند.' : P.errorText(res), res.ok ? 'success' : 'error');
      });
    } });
    var all = P.btn('پاک‌سازی کل کش', { kind: 'danger-soft', icon: 'trash', write: true, cls: 'pcdn-purge-all', onclick: function () {
      P.confirm({ title: 'پاک‌سازی کل کش', danger: true, ok: 'پاک‌سازی کل کش',
        body: 'همه فایل‌های کش‌شده این دامنه حذف می‌شوند و تا پر شدن دوباره کش، سرور اصلی بار بیشتری دریافت می‌کند. اگر فقط چند فایل تغییر کرده، پاکسازی آدرس‌ها بهتر است.' })
        .then(function (ok) {
          if (!ok) return;
          P.busy(all, P.api('POST', 'purge', { everything: true })).then(function (res) {
            P.toast(res.ok ? 'پاک‌سازی کل کش ثبت شد.' : P.errorText(res), res.ok ? 'success' : 'error');
          });
        });
    } });
    append(c.body, [
      P.field('آدرس‌ها (هر آدرس در یک خط، حداکثر ۱۰۰)', h('textarea', { className: 'pcdn-input pcdn-mono pcdn-purge-urls-input', dir: 'ltr', rows: 3, spellcheck: 'false',
        placeholder: 'https://' + domain() + '/css/style.css', oninput: function (e) { st.urls = e.target.value; } }),
      { help: h('span', null, 'نکته: به جای پاکسازی، می‌توانید نسخه را به آدرس فایل اضافه کنید (', ltr('style.css?v=2'), '). ', A().tutLink('cache', 'آموزش کش')) }),
      h('div', { className: 'pcdn-row-actions' }, one),
      h('div', { className: 'pcdn-purge-sep' }),
      P.field('پیشوندهای مسیر (هر پیشوند در یک خط، حداکثر ۲۰)', h('textarea', { className: 'pcdn-input pcdn-mono pcdn-purge-prefixes-input', dir: 'ltr', rows: 2, spellcheck: 'false',
        placeholder: '/blog/', oninput: function (e) { st.prefixes = e.target.value; } }),
      { help: h('span', null, 'پاک‌سازی بر اساس پیشوند همه فایل‌های کش‌شده‌ای را که مسیرشان با پیشوند شروع می‌شود حذف می‌کند؛ مثلاً ', ltr('/blog/'), ' کل کش زیر آن مسیر را پاک می‌کند.') }),
      h('div', { className: 'pcdn-row-actions' }, pfx),
      h('div', { className: 'pcdn-purge-sep' }),
      P.field('پاک‌سازی کل کش', h('p', { className: 'pcdn-muted pcdn-purge-all-help', text: 'همه فایل‌های کش‌شده این دامنه یک‌جا حذف می‌شوند. فقط وقتی لازم است که تغییرات گسترده باشد.' })),
      h('div', { className: 'pcdn-row-actions' }, all)]);
    return c;
  }

  // ------------------------------------------------------------------ page rules

  var CACHE_MODES = [[null, 'طبق تنظیمات کلی'], ['bypass', 'بدون کش'], ['standard', 'استاندارد'], ['everything', 'کش همه‌چیز']];
  function prSentence(r) {
    var out = [word('برای آدرس‌های'), h('bdi', { className: 'pcdn-vchip', dir: 'ltr', text: r.pattern || '/' }), word('←', 'pcdn-arrow')];
    if (r.redirect) {
      out.push(word('ریدایرکت ' + (r.redirect.code === 302 ? 'موقت (۳۰۲)' : 'دائمی (۳۰۱)') + ' به'), h('bdi', { className: 'pcdn-vchip', dir: 'ltr', text: r.redirect.url || '' }));
      return out;
    }
    var parts = [];
    if (r.cache) parts.push({ bypass: 'بدون کش', standard: 'کش استاندارد', everything: 'کش همه‌چیز' }[r.cache]);
    if (r.edge_ttl !== null && r.edge_ttl !== undefined) parts.push('کش CDN ' + P.dur(r.edge_ttl));
    if (r.browser_ttl !== null && r.browser_ttl !== undefined) parts.push('کش مرورگر ' + P.dur(r.browser_ttl));
    if (r.ignore_query === true) parts.push('بدون Query String در کلید کش');
    if (r.ignore_query === false) parts.push('Query String در کلید کش');
    if (r.waf === false) parts.push('WAF خاموش');
    out.push(word(parts.length ? parts.join('، ') : 'بدون تغییر (طبق تنظیمات کلی)', 'pcdn-w pcdn-w-strong'));
    return out;
  }
  function prEditor(r, done) {
    var isNew = !r;
    r = r || { id: P.uid('p'), enabled: true, pattern: '/', cache: null, edge_ttl: null, browser_ttl: null, ignore_query: null, waf: null, redirect: null };
    var mode = { v: r.redirect ? 'redirect' : 'settings' };
    editDrawer(isNew ? 'قانون صفحه جدید' : 'ویرایش قانون صفحه', 'برای مسیرهای خاص، رفتار کش یا ریدایرکت را تعیین کنید.', r, function (x, redraw) {
      return [
        P.input(x, 'pattern', 'الگوی مسیر', { placeholder: '/wp-admin/*', help: h('span', null, 'با ', ltr('/'), ' شروع کنید. ', ltr('*'), ' یعنی هر چیزی (حتی ', ltr('/'), ')؛ مثلاً ', ltr('/static/*'), ' همه فایل‌های پوشه static.') }),
        P.choice(mode, 'v', 'نوع قانون', [['settings', 'تنظیم کش و امنیت', 'رفتار کش یا WAF را برای این مسیر تغییر دهید.', 'zap'], ['redirect', 'ریدایرکت', 'بازدیدکننده را به آدرس دیگری بفرستید.', 'arrowLeft']], {
          cols: 2, onchange: function (v) { x.redirect = v === 'redirect' ? (x.redirect || { url: 'https://' + domain() + '/', code: 301 }) : null; redraw(); } }),
        x.redirect ? h('div', { className: 'pcdn-grid' },
          P.input(x.redirect, 'url', 'آدرس مقصد', { placeholder: 'https://' + domain() + '/new' }),
          P.select(x.redirect, 'code', 'نوع ریدایرکت', [[301, '۳۰۱ — دائمی (برای سئو)'], [302, '۳۰۲ — موقت']])) : [
          P.select(x, 'cache', 'کش', CACHE_MODES, { help: '«کش همه‌چیز» حتی صفحات HTML را کش می‌کند؛ برای صفحات کاربری استفاده نکنید.' }),
          h('div', { className: 'pcdn-grid' },
            P.duration(x, 'edge_ttl', 'مدت کش در CDN', { min: 0, nullable: true, nullText: 'طبق تنظیمات کلی', picks: TTL_PICKS }),
            P.duration(x, 'browser_ttl', 'مدت کش در مرورگر', { min: 0, nullable: true, nullText: 'طبق تنظیمات کلی', picks: [[0, 'طبق سرور'], [3600, '۱ ساعت'], [86400, '۱ روز']] })),
          P.select(x, 'ignore_query', 'Query String', [[null, 'طبق تنظیمات کلی'], [true, 'نادیده گرفتن در کلید کش'], [false, 'در کلید کش لحاظ شود']]),
          P.select(x, 'waf', 'WAF', [[null, 'طبق تنظیمات کلی'], [false, 'خاموش در این مسیر']], { help: 'فقط برای مسیرهایی که مطمئنید (مثلاً وب‌هوک پرداخت) WAF را خاموش کنید.' })],
        P.toggle(x, 'enabled', 'قانون فعال باشد')
      ];
    }, done, function (x) {
      if (!/^\//.test(x.pattern || '')) return 'الگوی مسیر باید با / شروع شود.';
      if (x.redirect && !/^https?:\/\/\S+$/.test(x.redirect.url || '')) return 'آدرس مقصد ریدایرکت باید با http:// یا https:// شروع شود.';
      return null;
    }, prSentence);
  }
  function renderPagerules(Aa) {
    var max = Aa.features().max_page_rules || 0;
    var f = Aa.sectionForm('pagerules', function (d, f2) {
      d.rules = d.rules || [];
      var full = d.rules.length >= max ? 'به سقف قوانین صفحه پلن رسیده‌اید' : null;
      function add(r) { r.id = P.uid('p'); r._new = true; d.rules.push(r); }
      return [presets('الگوهای آماده', 'قوانین پرکاربرد را با یک کلیک اضافه کنید؛ سپس بررسی و ذخیره کنید.', [
        { id: 'wpadmin', title: 'عدم کش پنل مدیریت وردپرس', icon: 'lock', desc: 'مسیر /wp-admin/* هرگز کش نشود.', disabled: full,
          apply: function () { add({ enabled: true, pattern: '/wp-admin/*', cache: 'bypass', edge_ttl: null, browser_ttl: null, ignore_query: null, waf: null, redirect: null }); } },
        { id: 'static', title: 'کش طولانی فایل‌های استاتیک', icon: 'zap', desc: 'همه‌چیز در /static/* به مدت ۳۰ روز در CDN کش شود.', disabled: full,
          apply: function () { add({ enabled: true, pattern: '/static/*', cache: 'everything', edge_ttl: 2592000, browser_ttl: null, ignore_query: null, waf: null, redirect: null }); } },
        { id: 'redirect', title: 'ریدایرکت مسیر قدیمی', icon: 'arrowLeft', desc: 'انتقال دائمی (۳۰۱) یک مسیر قدیمی به آدرس جدید؛ آدرس‌ها را ویرایش کنید.', disabled: full,
          apply: function () { add({ enabled: true, pattern: '/old-page', cache: null, edge_ttl: null, browser_ttl: null, ignore_query: null, waf: null, redirect: { url: 'https://' + domain() + '/new-page', code: 301 } }); } }
      ], d, f2), ruleList(d, f2, {
        title: 'قوانین صفحه', icon: 'sliders', max: max, what: 'قانون', addLabel: 'قانون جدید',
        subtitle: 'اولین قانونی که با آدرس منطبق باشد اعمال می‌شود؛ ترتیب مهم است.',
        sentence: prSentence, edit: prEditor,
        empty: ['sliders', 'هنوز قانون صفحه‌ای ندارید', 'با قانون صفحه می‌توانید برای مسیرهای خاص کش را خاموش یا طولانی کنید یا ریدایرکت بسازید.']
      })];
    }, { serialize: stripNew('rules') });
    return f.el;
  }

  // ------------------------------------------------------------------ image

  function renderImage(Aa) {
    var f = Aa.sectionForm('image', function (d, f2) {
      var c = P.card({ title: 'تغییر اندازه تصویر در لبه', icon: 'image', id: 'settings' });
      var ex = 'https://' + domain() + '/images/photo.jpg?width=800';
      append(c.body, [
        P.toggle(d, 'enabled', 'بهینه‌سازی تصویر', { help: 'تصاویر jpg، png، gif و webp با پارامتر width یا height در سرورهای CDN کوچک و کش می‌شوند.', onchange: f2.redraw }),
        d.enabled ? h('div', { className: 'pcdn-grid' },
          P.input(d, 'quality', 'کیفیت خروجی', { type: 'number', min: 1, max: 100, suffix: 'از ۱۰۰', suffixRtl: true, help: '۸۰ تا ۸۵ تعادل خوبی بین کیفیت و حجم است.' }),
          P.input(d, 'max_width', 'حداکثر عرض', { type: 'number', min: 1, max: 10000, suffix: 'پیکسل', suffixRtl: true, help: 'درخواست‌های بزرگ‌تر از این عرض محدود می‌شوند.' })) : null,
        h('div', { className: 'pcdn-howto' }, h('h4', { text: 'نحوه استفاده' }),
          h('p', { text: 'کافی است در آدرس تصویر عرض یا ارتفاع دلخواه را بنویسید:' }),
          P.copyable(ex, { block: true, label: 'کپی نمونه آدرس' }),
          h('p', { className: 'pcdn-muted' }, 'در HTML می‌توانید برای نمایشگرهای مختلف از ', ltr('srcset'), ' با عرض‌های متفاوت استفاده کنید.'))
      ]);
      return c;
    });
    return f.el;
  }

  // ------------------------------------------------------------------ load balancer pools

  function renderPools(Aa) {
    var max = Aa.features().max_pools || 0;
    var f = Aa.sectionForm('pools', function (d, f2) {
      d.pools = d.pools || [];
      var full = d.pools.length >= max;
      var add = P.btn('استخر جدید', { kind: 'primary', icon: 'plus', size: 'sm', write: true, disabled: full, cls: 'pcdn-add-pool', onclick: function () {
        d.pools.push({ name: 'pool' + (d.pools.length + 1), method: 'weighted', protocol: 'http',
          origins: [{ address: '', port: 80, weight: 10, backup: false }],
          health: { enabled: true, path: '/', interval: 10, timeout: 3, expect: '2xx,3xx', host: null } });
        f2.redraw();
      } });
      var head = P.card({ title: 'استخرهای سرور اصلی', icon: 'lb', id: 'pools', actions: [limitText(d.pools.length, max, 'استخر'), add],
        subtitle: 'پس از ذخیره، در «رکوردها» برای رکورد پروکسی‌شده استخر را انتخاب کنید.' });
      if (!d.pools.length) {
        head.body.appendChild(P.empty('lb', 'هنوز استخری نساخته‌اید', 'با استخر، ترافیک بین چند سرور اصلی تقسیم می‌شود و اگر یکی از کار بیفتد سایت قطع نمی‌شود.'));
        return head;
      }
      var cards = d.pools.map(function (p, i) {
        p.origins = p.origins || [];
        p.health = p.health || { enabled: false, path: '/', interval: 10, timeout: 3, expect: '2xx,3xx', host: null };
        var c = P.card({ title: 'استخر ' + num(i + 1), icon: 'lb', tone: 'muted', cls: 'pcdn-pool', id: 'pool-' + i,
          actions: P.iconBtn('trash', 'حذف استخر ' + (p.name || num(i + 1)), function () { d.pools.splice(i, 1); f2.redraw(); }, { write: true, cls: 'is-danger' }) });
        var origins = h('div', { className: 'pcdn-origins' },
          h('div', { className: 'pcdn-origin pcdn-origin-head', 'aria-hidden': 'true' }, ['آدرس سرور', 'پورت', 'وزن', 'پشتیبان', ''].map(function (t) { return h('span', { text: t }); })),
          p.origins.map(function (o, j) {
            var row = h('div', { className: 'pcdn-origin' },
              P.input(o, 'address', null, { placeholder: '185.1.2.3', aria: 'آدرس سرور ' + num(j + 1) }),
              P.input(o, 'port', null, { type: 'number', min: 1, max: 65535, aria: 'پورت سرور ' + num(j + 1) }),
              P.input(o, 'weight', null, { type: 'number', min: 1, max: 100, aria: 'وزن سرور ' + num(j + 1) }),
              h('label', { className: 'pcdn-inline' }, P.switchInput(o.backup, 'سرور ' + num(j + 1) + ' پشتیبان است', function (v) { o.backup = v; }, { small: true }), h('span', { className: 'pcdn-only-narrow-inline', text: 'پشتیبان' })),
              P.iconBtn('x', 'حذف سرور ' + num(j + 1), function () { p.origins.splice(j, 1); f2.redraw(); }, { write: true }));
            P.reg(P.pathOf(o), row);
            return row;
          }),
          P.btn('افزودن سرور', { icon: 'plus', size: 'sm', write: true, onclick: function () { p.origins.push({ address: '', port: p.protocol === 'https' ? 443 : 80, weight: 10, backup: false }); f2.redraw(); } }));
        append(c.body, [
          h('div', { className: 'pcdn-grid pcdn-grid-3' },
            P.input(p, 'name', 'نام استخر', { placeholder: 'main', help: 'حروف کوچک لاتین، عدد، - و _' }),
            P.select(p, 'method', 'روش تقسیم', [['weighted', 'وزنی (تصادفی)'], ['ip_hash', 'چسبنده (هر IP یک سرور)']]),
            P.select(p, 'protocol', 'پروتکل اتصال', [['http', 'HTTP'], ['https', 'HTTPS']])),
          h('h4', { className: 'pcdn-subhead', text: 'سرورها' }), origins,
          h('div', { className: 'pcdn-subpanel' },
            P.toggle(p.health, 'enabled', 'بررسی سلامت', { help: 'سرورهایی که پاسخ درست نمی‌دهند موقتاً کنار گذاشته می‌شوند.', onchange: f2.redraw }),
            p.health.enabled ? h('div', { className: 'pcdn-grid pcdn-grid-3' },
              P.input(p.health, 'path', 'مسیر بررسی', { placeholder: '/' }),
              P.input(p.health, 'interval', 'هر چند ثانیه', { type: 'number', min: 5, suffix: 'ثانیه', suffixRtl: true }),
              P.input(p.health, 'timeout', 'مهلت پاسخ', { type: 'number', min: 1, suffix: 'ثانیه', suffixRtl: true }),
              P.input(p.health, 'expect', 'کدهای سالم', { placeholder: '2xx,3xx' }),
              P.input(p.health, 'host', 'هدر Host (اختیاری)', { nullable: true, placeholder: domain() })) : null)]);
        return c;
      });
      return [head, cards];
    });
    return f.el;
  }

  // ------------------------------------------------------------------ firewall

  var FW_FIELDS = [['country', 'کشور'], ['ip', 'آی‌پی / CIDR'], ['path', 'مسیر'], ['user_agent', 'User-Agent'], ['method', 'متد'], ['query', 'Query String'],
    ['host', 'هاست'], ['referer', 'Referer'], ['header', 'هدر']];
  var LIST_OPS = [['in', 'یکی از'], ['not_in', 'هیچ‌کدام از']];
  var STR_OPS = [['eq', 'برابر'], ['ne', 'نابرابر'], ['contains', 'شامل'], ['not_contains', 'شامل نباشد'], ['starts_with', 'شروع با'],
    ['ends_with', 'پایان با'], ['regex', 'عبارت منظم (regex)'], ['in', 'یکی از'], ['not_in', 'هیچ‌کدام از']];
  var OP_WORDS = {
    in: ['یکی از', 'باشد'], not_in: ['هیچ‌کدام از', 'نباشد'], eq: ['برابر', 'باشد'], ne: ['برابر', 'نباشد'], contains: ['شامل', 'باشد'],
    not_contains: ['شامل', 'نباشد'], starts_with: ['با', 'شروع شود'], ends_with: ['با', 'تمام شود'], regex: ['با الگوی', 'منطبق باشد']
  };
  var FW_ACTIONS = [
    ['block', 'مسدود', 'خطای ۴۰۳ نمایش داده می‌شود.', 'ban'],
    ['challenge', 'چالش JS', 'مرورگرهای واقعی خودکار عبور می‌کنند؛ ربات‌های ساده نه.', 'shieldBolt'],
    ['captcha', 'کپچا', 'بازدیدکننده باید کپچا حل کند.', 'shieldCheck'],
    ['allow', 'اجازه', 'بدون WAF، DDoS و محدودیت نرخ عبور می‌کند. فقط برای آی‌پی‌های مطمئن.', 'checkCircle'],
    ['log', 'فقط ثبت', 'رویداد ثبت می‌شود و بررسی ادامه می‌یابد.', 'eye']
  ];
  var ACTION_WORDS = { block: 'مسدود شود', challenge: 'چالش JS نمایش داده شود', captcha: 'کپچا نمایش داده شود', allow: 'اجازه عبور بدون بررسی‌های امنیتی', log: 'فقط ثبت شود' };
  var ACTION_TONE = { block: 'danger', challenge: 'warning', captcha: 'warning', allow: 'success', log: 'muted' };
  function fieldLabel(fl) { for (var i = 0; i < FW_FIELDS.length; i++) if (FW_FIELDS[i][0] === fl) return FW_FIELDS[i][1]; return fl; }
  function opsFor(fl) { return fl === 'ip' || fl === 'country' ? LIST_OPS : STR_OPS; }
  function isList(op) { return op === 'in' || op === 'not_in'; }

  function fwSentence(r) {
    var out = [word('اگر')];
    (r.conditions || []).forEach(function (c, i) {
      if (i) out.push(word('و', 'pcdn-w pcdn-w-and'));
      var ow = OP_WORDS[c.op] || [c.op, ''];
      out.push(word(fieldLabel(c.field) + (c.field === 'header' && c.name ? ' ' : ''), 'pcdn-w pcdn-w-strong'));
      if (c.field === 'header' && c.name) out.push(h('bdi', { className: 'pcdn-vchip is-key', dir: 'ltr', text: c.name }));
      out.push(word(ow[0]));
      var empty = c.value === '' || c.value === null || c.value === undefined || (Array.isArray(c.value) && !c.value.length);
      out.push(empty ? word('(خالی)', 'pcdn-w pcdn-w-bad') : chipsOf(c.value, { country: c.field === 'country' }));
      out.push(word(ow[1]));
    });
    if (!(r.conditions || []).length) out.push(word('(بدون شرط — همه درخواست‌ها)', 'pcdn-w pcdn-w-bad'));
    out.push(word('←', 'pcdn-arrow'));
    out.push(h('span', { className: 'pcdn-act pcdn-tone-' + (ACTION_TONE[r.action] || 'muted'), text: ACTION_WORDS[r.action] || r.action }));
    return out;
  }

  var VALUE_HINT = {
    country: ['IR, CN, RU', 'کد دوحرفی کشور (ISO)؛ مثلاً IR برای ایران.'],
    ip: ['1.2.3.4, 10.0.0.0/8', 'آی‌پی یا بازه CIDR.'],
    path: ['/wp-login.php', 'مسیر آدرس بدون دامنه؛ با / شروع می‌شود.'],
    user_agent: ['sqlmap', 'نام مرورگر یا ابزار؛ بزرگی و کوچکی حروف مهم نیست.'],
    method: ['POST', 'GET، POST، PUT و ...'],
    query: ['id=', 'بخش بعد از ؟ در آدرس.'],
    host: [null, 'نام کامل میزبان، مثلاً www.' ],
    referer: ['bad-site.com', 'آدرس صفحه‌ای که کاربر از آن آمده.'],
    header: ['value', 'مقدار هدر.']
  };
  function conditionRow(c, conds, j, redraw) {
    var ops = opsFor(c.field);
    if (!ops.some(function (o) { return o[0] === c.op; })) c.op = ops[0][0];
    if (isList(c.op) && !Array.isArray(c.value)) c.value = c.value ? String(c.value).split(/\s*,\s*/).filter(Boolean) : [];
    if (!isList(c.op) && Array.isArray(c.value)) c.value = c.value.join(',');
    var hint = VALUE_HINT[c.field] || ['', ''];
    var val = isList(c.op)
      ? P.tags(c, 'value', null, { upper: c.field === 'country', placeholder: hint[0] || '', aria: 'مقدار شرط ' + num(j + 1) })
      : P.input(c, 'value', null, { placeholder: c.field === 'host' ? 'www.' + domain() : hint[0], aria: 'مقدار شرط ' + num(j + 1) });
    return h('div', { className: 'pcdn-cond', 'data-cond': j },
      h('div', { className: 'pcdn-cond-head' }, h('span', { className: 'pcdn-cond-no', text: j ? 'و' : 'اگر' }),
        P.select(c, 'field', null, FW_FIELDS, { aria: 'فیلد شرط ' + num(j + 1), onchange: function () { if (c.field !== 'header') delete c.name; else c.name = c.name || ''; redraw(); } }),
        c.field === 'header' ? P.input(c, 'name', null, { placeholder: 'X-Header', aria: 'نام هدر' }) : null,
        P.select(c, 'op', null, ops, { aria: 'عملگر شرط ' + num(j + 1), onchange: redraw }),
        P.iconBtn('trash', 'حذف شرط ' + num(j + 1), function () { conds.splice(j, 1); redraw(); }, { write: true, disabled: conds.length < 2 })),
      val, h('div', { className: 'pcdn-help', text: hint[1] + (isList(c.op) ? ' چند مقدار را با Enter جدا کنید.' : c.op === 'regex' ? ' مثال: (sqlmap|nikto)' : '') }));
  }
  function fwEditor(r, done) {
    var isNew = !r;
    r = r || { id: P.uid('r'), name: '', enabled: true, action: 'block', conditions: [{ field: 'country', op: 'in', value: [] }] };
    editDrawer(isNew ? 'قانون فایروال جدید' : 'ویرایش قانون فایروال', 'اگر همه شرط‌ها برقرار باشند، اقدام انتخاب‌شده اجرا می‌شود.', r, function (x, redraw) {
      x.conditions = x.conditions || [];
      return [
        P.input(x, 'name', 'نام قانون', { ltr: false, placeholder: 'مثلاً: محافظت از صفحه ورود', maxlength: 100 }),
        h('fieldset', { className: 'pcdn-fieldset' }, h('legend', { text: 'شرط‌ها (همه باید برقرار باشند)' }),
          x.conditions.map(function (c, j) { return conditionRow(c, x.conditions, j, redraw); }),
          P.btn('افزودن شرط', { icon: 'plus', size: 'sm', write: true, onclick: function () { x.conditions.push({ field: 'path', op: 'starts_with', value: '' }); redraw(); } })),
        P.choice(x, 'action', 'اقدام', FW_ACTIONS, { cols: 2, onchange: redraw }),
        x.action === 'allow' ? P.alertBox('warning', 'درخواست‌های منطبق از WAF، حفاظت DDoS و محدودیت نرخ عبور می‌کنند. فقط برای آی‌پی‌های مطمئن (مثل دفتر خودتان) استفاده کنید.') : null,
        P.toggle(x, 'enabled', 'قانون فعال باشد')
      ];
    }, done, function (x) {
      if (!x.conditions.length) return 'حداقل یک شرط لازم است.';
      for (var i = 0; i < x.conditions.length; i++) {
        var v = x.conditions[i].value;
        if (v === '' || v === null || v === undefined || (Array.isArray(v) && !v.length)) return 'مقدار شرط ' + num(i + 1) + ' را وارد کنید.';
        if (x.conditions[i].field === 'header' && !x.conditions[i].name) return 'نام هدر در شرط ' + num(i + 1) + ' را وارد کنید.';
      }
      return null;
    }, fwSentence);
  }

  var BAD_BOTS = '(sqlmap|nikto|masscan|zgrab|nmap|wpscan|acunetix|nessus|dirbuster|gobuster|nuclei)';
  function fwPresets(d, max) {
    var full = d.rules.length >= max ? 'به سقف قوانین فایروال پلن رسیده‌اید' : null;
    function add(name, action, conds) { d.rules.push({ id: P.uid('r'), name: name, enabled: true, action: action, conditions: conds, _new: true }); }
    return [
      { id: 'iran', title: 'فقط بازدید از ایران', icon: 'globe', desc: 'بازدیدکنندگان خارج از ایران چالش JS می‌بینند (کاربران واقعی عبور می‌کنند).', disabled: full,
        apply: function () { add('فقط بازدید از ایران', 'challenge', [{ field: 'country', op: 'not_in', value: ['IR'] }]); } },
      { id: 'wplogin', title: 'محافظت از صفحه ورود وردپرس', icon: 'lock', desc: 'برای ‎/wp-login.php کپچا نمایش داده می‌شود.', disabled: full,
        apply: function () { add('محافظت از ورود وردپرس', 'captcha', [{ field: 'path', op: 'starts_with', value: '/wp-login.php' }]); } },
      { id: 'badbots', title: 'مسدود کردن ربات‌های مخرب', icon: 'ban', desc: 'ابزارهای اسکن مثل sqlmap، nikto، masscan و zgrab مسدود می‌شوند.', disabled: full,
        apply: function () { add('مسدود کردن ربات‌های مخرب', 'block', [{ field: 'user_agent', op: 'regex', value: BAD_BOTS }]); } },
      { id: 'xmlrpc', title: 'مسدود کردن xmlrpc.php', icon: 'shield', desc: 'فایل xmlrpc.php وردپرس هدف رایج حملات است و اغلب سایت‌ها به آن نیاز ندارند.', disabled: full,
        apply: function () { add('مسدود کردن xmlrpc.php', 'block', [{ field: 'path', op: 'eq', value: '/xmlrpc.php' }]); } }
    ];
  }
  function renderFirewall(Aa) {
    var max = Aa.features().max_firewall_rules || 0;
    var f = Aa.sectionForm('firewall', function (d, f2) {
      d.rules = d.rules || [];
      var def = P.card({ title: 'اقدام پیش‌فرض', icon: 'wall', tone: 'muted', id: 'default' });
      def.body.appendChild(P.choice(d, 'default_action', null, [
        ['allow', 'اجازه', 'درخواست‌هایی که با هیچ قانونی منطبق نیستند عبور می‌کنند (پیشنهادی).', 'checkCircle'],
        ['block', 'مسدود', 'فقط درخواست‌هایی که قانون «اجازه» دارند عبور می‌کنند. با احتیاط!', 'ban']
      ], { cols: 2 }));
      return [
        presets('الگوهای آماده', 'قوانین پرکاربرد را با یک کلیک اضافه کنید؛ سپس بررسی و «ذخیره» کنید.', fwPresets(d, max), d, f2),
        ruleList(d, f2, {
          title: 'قوانین فایروال', icon: 'wall', max: max, what: 'قانون', addLabel: 'قانون جدید',
          subtitle: 'قوانین از بالا به پایین بررسی می‌شوند و اولین قانون منطبق اجرا می‌شود.',
          label: function (r) { return h('span', { text: r.name || 'بدون نام' }); },
          sentence: fwSentence, edit: fwEditor,
          empty: ['wall', 'هنوز قانونی ندارید', 'با قوانین فایروال می‌توانید کشورها، آی‌پی‌ها، ربات‌ها یا مسیرهای خاص را مسدود کنید یا چالش بگذارید. از الگوهای آماده بالا شروع کنید.']
        }),
        def];
    }, { serialize: stripNew('rules') });
    return f.el;
  }

  // ------------------------------------------------------------------ WAF

  var WAF_GROUPS = [['sqli', 'SQL Injection'], ['xss', 'XSS'], ['lfi', 'LFI / پیمایش مسیر'], ['rce', 'اجرای فرمان (RCE)'],
    ['php', 'حملات PHP'], ['scanner', 'اسکنرها و ربات‌های مخرب'], ['protocol', 'نقض پروتکل HTTP']];
  var ALL_GROUPS = WAF_GROUPS.map(function (g) { return g[0]; });
  var WAF_LEVELS = [
    { id: 'basic', title: 'پایه', icon: 'shield', desc: 'فقط حملات اصلی (SQLi، XSS، LFI، RCE) با کمترین احتمال خطا.', v: { mode: 'block', paranoia: 1, groups: ['sqli', 'xss', 'lfi', 'rce'] } },
    { id: 'recommended', title: 'پیشنهادی', icon: 'shieldCheck', desc: 'همه گروه‌ها با حساسیت ۱؛ مناسب اغلب سایت‌ها و فروشگاه‌ها.', v: { mode: 'block', paranoia: 1, groups: ALL_GROUPS } },
    { id: 'strict', title: 'سخت‌گیرانه', icon: 'shieldBolt', desc: 'همه گروه‌ها با حساسیت ۲؛ امنیت بیشتر ولی احتمال مسدودسازی اشتباه بالاتر.', v: { mode: 'block', paranoia: 2, groups: ALL_GROUPS } }
  ];
  function sameSet(a, b) { a = (a || []).slice().sort(); b = (b || []).slice().sort(); return JSON.stringify(a) === JSON.stringify(b); }
  function renderWaf(Aa) {
    var f = Aa.sectionForm('waf', function (d, f2) {
      d.groups = d.groups || [];
      d.exclusions = d.exclusions || [];
      var levels = presets('سطح حفاظت', 'یکی از سطح‌ها را انتخاب کنید؛ سپس «ذخیره» را بزنید.', WAF_LEVELS.map(function (l) {
        return { id: l.id, title: l.title, desc: l.desc, icon: l.icon, done: 'سطح «' + l.title + '» انتخاب شد؛ برای اعمال «ذخیره» را بزنید.',
          active: function (x) { return x.mode !== 'off' && x.paranoia === l.v.paranoia && sameSet(x.groups, l.v.groups); },
          apply: function (x) { x.mode = x.mode === 'detect' ? 'detect' : 'block'; x.paranoia = l.v.paranoia; x.groups = l.v.groups.slice(); } };
      }), d, f2);
      var mode = P.card({ title: 'حالت کار', icon: 'shield', id: 'mode' });
      append(mode.body, [P.choice(d, 'mode', null, [
        ['off', 'خاموش', 'هیچ درخواستی بررسی نمی‌شود.', 'power'],
        ['detect', 'فقط ثبت', 'حملات شناسایی و در رویدادها ثبت می‌شوند ولی مسدود نمی‌شوند. برای شروع و آزمایش.', 'eye'],
        ['block', 'مسدودسازی', 'درخواست‌های مخرب با خطای ۴۰۳ مسدود می‌شوند.', 'shieldCheck', 'پیشنهادی']
      ], { cols: 3, onchange: f2.redraw }),
      d.mode === 'detect' ? P.alertBox('info', ['در حالت «فقط ثبت» چیزی مسدود نمی‌شود. چند روز ', Aa.goLink('events', 'رویدادهای امنیتی'), ' را بررسی کنید و سپس به «مسدودسازی» بروید.']) : null]);
      var adv = P.collapsible({ title: 'تنظیمات پیشرفته', subtitle: 'حساسیت، گروه قوانین و استثناها', icon: 'sliders', tone: 'muted', id: 'advanced',
        open: d.exclusions.length > 0 || P.store('waf-adv') === '1', onOpen: function () { P.store('waf-adv', '1'); } });
      append(adv.body, [
        P.choice(d, 'paranoia', 'سطح حساسیت', [[1, 'حساسیت ۱', 'کمترین خطا — پیشنهادی'], [2, 'حساسیت ۲', 'امضاهای بیشتر'], [3, 'حساسیت ۳', 'بیشترین پوشش، خطای بیشتر']], { cols: 3, onchange: f2.redraw }),
        P.checks(d, 'groups', 'گروه قوانین', WAF_GROUPS, { onchange: f2.redraw }),
        h('fieldset', { className: 'pcdn-fieldset' }, h('legend', { text: 'استثناها (رفع مسدودسازی اشتباه)' }),
          h('p', { className: 'pcdn-help' }, 'شناسه قانون را از ', Aa.goLink('events', 'رویدادهای امنیتی'), ' بردارید. شناسه ۰ یعنی همه قوانین؛ در مسیر می‌توانید از ', ltr('*'), ' استفاده کنید.'),
          d.exclusions.length ? h('div', { className: 'pcdn-rows' }, d.exclusions.map(function (x, i) {
            var row = h('div', { className: 'pcdn-xrow' },
              P.input(x, 'rule_id', null, { type: 'number', min: 0, placeholder: '942100', aria: 'شناسه قانون استثنای ' + num(i + 1) }),
              P.input(x, 'path', null, { placeholder: '/wp-admin/*', nullable: true, aria: 'مسیر استثنای ' + num(i + 1) }),
              P.iconBtn('trash', 'حذف استثنای ' + num(i + 1), function () { d.exclusions.splice(i, 1); f2.redraw(); }, { write: true, cls: 'is-danger' }));
            P.reg(P.pathOf(x), row);
            return row;
          })) : null,
          P.btn('افزودن استثنا', { icon: 'plus', size: 'sm', write: true, onclick: function () { d.exclusions.push({ rule_id: 0, path: '' }); adv.setOpen(true); f2.redraw(); } }))]);
      return [levels, mode, adv];
    });
    return f.el;
  }

  // ------------------------------------------------------------------ DDoS

  function renderDdos(Aa) {
    var f = Aa.sectionForm('ddos', function (d, f2) {
      var c = P.card({ title: 'حالت حفاظت', icon: 'shieldBolt', id: 'mode' });
      append(c.body, [
        d.mode === 'js' ? P.alertBox('warning', 'حالت «زیر حمله» روشن است: همه بازدیدکنندگان پیش از ورود چالش JS می‌بینند. پس از پایان حمله آن را به «خودکار» برگردانید.') : null,
        P.choice(d, 'mode', null, [
          ['off', 'خاموش', 'بدون چالش.', 'power'],
          ['auto', 'خودکار', 'وقتی درخواست‌ها از آستانه بیشتر شود، بازدیدکنندگان جدید چالش JS می‌بینند.', 'shieldCheck', 'پیشنهادی'],
          ['js', 'زیر حمله (چالش JS برای همه)', 'همه بازدیدکنندگان یک چالش چندثانیه‌ای می‌بینند؛ فقط هنگام حمله.', 'shieldBolt'],
          ['captcha', 'کپچا برای همه', 'سخت‌ترین حالت؛ همه باید کپچا حل کنند.', 'lock']
        ], { cols: 2, onchange: f2.redraw }),
        h('div', { className: 'pcdn-grid' },
          d.mode === 'auto' ? P.input(d, 'threshold_rps', 'آستانه حمله', { type: 'number', min: 1, suffix: 'درخواست در ثانیه', suffixRtl: true, help: 'در هر سرور CDN و در بازه ۱۰ ثانیه سنجیده می‌شود. برای سایت‌های کوچک ۱۰۰ تا ۲۰۰ مناسب است.' }) : null,
          d.mode !== 'off' ? P.duration(d, 'clearance_ttl', 'اعتبار مجوز عبور', { min: 60, picks: [[1800, '۳۰ دقیقه'], [3600, '۱ ساعت'], [86400, '۱ روز']], help: 'بازدیدکننده‌ای که چالش را گذرانده تا این مدت دوباره چالش نمی‌بیند.' }) : null)
      ]);
      return c;
    });
    return f.el;
  }

  // ------------------------------------------------------------------ rate limit

  var METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
  var RL_ACTIONS = { block: 'مسدود (خطای ۴۲۹)', challenge: 'چالش JS', captcha: 'کپچا' };
  function rlSentence(r) {
    var out = [word('اگر یک آی‌پی بیش از'), word(num(r.requests) + ' درخواست', 'pcdn-w pcdn-w-strong')];
    if ((r.methods || []).length) out.push(chipsOf(r.methods));
    out.push(word('در ' + P.dur(r.period) + ' به'), h('bdi', { className: 'pcdn-vchip', dir: 'ltr', text: r.path || '/*' }), word('بفرستد'), word('←', 'pcdn-arrow'));
    out.push(h('span', { className: 'pcdn-act pcdn-tone-' + (r.action === 'block' ? 'danger' : 'warning'), text: r.action === 'block' ? 'مسدود به مدت ' + P.dur(r.block_seconds) : RL_ACTIONS[r.action] || r.action }));
    return out;
  }
  function rlEditor(r, done) {
    var isNew = !r;
    r = r || { id: P.uid('rl'), enabled: true, path: '/*', methods: [], requests: 60, period: 60, action: 'block', block_seconds: 600 };
    editDrawer(isNew ? 'قانون محدودیت نرخ جدید' : 'ویرایش محدودیت نرخ', 'تعداد درخواست هر آی‌پی روی هر سرور CDN شمرده می‌شود.', r, function (x, redraw) {
      x.methods = x.methods || [];
      return [
        P.input(x, 'path', 'مسیر', { placeholder: '/wp-login.php*', help: h('span', null, ltr('*'), ' یعنی هر چیزی؛ مثلاً ', ltr('/api/*')) }),
        P.checks(x, 'methods', 'متدها (هیچ‌کدام = همه)', METHODS.map(function (m) { return [m, m]; }), { ltr: true }),
        h('div', { className: 'pcdn-grid' },
          P.input(x, 'requests', 'حداکثر تعداد درخواست', { type: 'number', min: 1 }),
          P.duration(x, 'period', 'در بازه', { min: 1, picks: [[10, '۱۰ ثانیه'], [60, '۱ دقیقه'], [3600, '۱ ساعت']] })),
        P.select(x, 'action', 'اقدام پس از عبور از حد', [['block', 'مسدود (خطای ۴۲۹)'], ['challenge', 'چالش JS'], ['captcha', 'کپچا']], { onchange: redraw }),
        x.action === 'block' ? P.duration(x, 'block_seconds', 'مدت مسدودی', { min: 1, picks: [[60, '۱ دقیقه'], [600, '۱۰ دقیقه'], [3600, '۱ ساعت']] }) : null,
        P.toggle(x, 'enabled', 'قانون فعال باشد')
      ];
    }, done, function (x) {
      if (!/^\//.test(x.path || '')) return 'مسیر باید با / شروع شود.';
      if (!(x.requests > 0) || !(x.period > 0)) return 'تعداد درخواست و بازه باید بزرگ‌تر از صفر باشند.';
      return null;
    }, rlSentence);
  }
  function renderRatelimit(Aa) {
    var max = Aa.features().max_ratelimit_rules || 0;
    var f = Aa.sectionForm('ratelimit', function (d, f2) {
      d.rules = d.rules || [];
      var full = d.rules.length >= max ? 'به سقف قوانین محدودیت نرخ پلن رسیده‌اید' : null;
      function add(r) { r._new = true; d.rules.push(r); }
      return [presets('الگوهای آماده', 'قوانین پرکاربرد را با یک کلیک اضافه کنید؛ سپس بررسی و «ذخیره» کنید.', [
        { id: 'wplogin', title: 'ورود وردپرس: ۱۰ بار در دقیقه', icon: 'lock', desc: 'بیش از ۱۰ تلاش ورود (POST) در دقیقه از یک آی‌پی، ۱۰ دقیقه مسدود می‌شود.', disabled: full,
          apply: function () { add({ id: P.uid('rl'), enabled: true, path: '/wp-login.php*', methods: ['POST'], requests: 10, period: 60, action: 'block', block_seconds: 600 }); } },
        { id: 'api', title: 'API عمومی: ۶۰ در دقیقه', icon: 'code', desc: 'هر آی‌پی حداکثر ۶۰ درخواست در دقیقه به /api/* می‌فرستد.', disabled: full,
          apply: function () { add({ id: P.uid('rl'), enabled: true, path: '/api/*', methods: [], requests: 60, period: 60, action: 'block', block_seconds: 300 }); } }
      ], d, f2), ruleList(d, f2, {
        title: 'قوانین محدودیت نرخ', icon: 'gauge', max: max, what: 'قانون', addLabel: 'قانون جدید',
        subtitle: 'برای جلوگیری از حدس رمز عبور، اسکرپینگ و فشار روی API.',
        sentence: rlSentence, edit: rlEditor,
        empty: ['gauge', 'هنوز محدودیتی تعریف نکرده‌اید', 'مثلاً تعداد تلاش‌های ورود را محدود کنید تا حمله حدس رمز عبور بی‌اثر شود.']
      })];
    }, { serialize: stripNew('rules') });
    return f.el;
  }

  // ------------------------------------------------------------------ hotlink

  function renderHotlink(Aa) {
    var f = Aa.sectionForm('hotlink', function (d, f2) {
      d.allowed_referers = d.allowed_referers || [];
      var c = P.card({ title: 'جلوگیری از استفاده غیرمجاز فایل‌ها', icon: 'link', id: 'settings' });
      var own = [domain(), '*.' + domain()];
      var missing = own.filter(function (x) { return d.allowed_referers.indexOf(x) < 0; });
      append(c.body, [
        P.toggle(d, 'enabled', 'محافظت Hotlink', { help: 'اگر سایت دیگری مستقیماً تصاویر یا ویدیوهای شما را نمایش دهد، درخواستش مسدود می‌شود و ترافیک شما هدر نمی‌رود.', onchange: f2.redraw }),
        d.enabled && missing.length ? P.alertBox('warning', [h('span', { text: 'دامنه خودتان در فهرست مجاز نیست؛ ممکن است تصاویر سایت خودتان هم نمایش داده نشوند. ' }),
          P.btn('افزودن ' + missing.join(' و '), { size: 'sm', icon: 'plus', write: true, onclick: function () { missing.forEach(function (x) { d.allowed_referers.push(x); }); f2.redraw(); } })]) : null,
        P.tags(d, 'extensions', 'پسوندهای محافظت‌شده', { lower: true, placeholder: 'jpg', help: 'بدون نقطه؛ مثلاً jpg، png، mp4.' }),
        P.tags(d, 'allowed_referers', 'دامنه‌های مجاز', { lower: true, placeholder: domain(), help: h('span', null, 'سایت‌هایی که اجازه نمایش فایل‌های شما را دارند. ', ltr('*.example.com'), ' یعنی همه زیردامنه‌ها. موتورهای جستجو (مثل google.com) را هم می‌توانید اضافه کنید.'), onchange: f2.redraw }),
        P.toggle(d, 'allow_empty', 'اجازه به درخواست‌های بدون Referer', { help: 'پیشنهادی: روشن. برخی مرورگرها و اپلیکیشن‌ها Referer نمی‌فرستند.' })
      ]);
      return c;
    });
    return f.el;
  }

  // ------------------------------------------------------------------ SSL

  var SSL_LABEL = { active: ['فعال', 'success'], pending: ['در حال صدور', 'warning'], failed: ['ناموفق', 'danger'] };
  function renderSsl(Aa) {
    var s = site(), ssl = s.ssl || {}, plan = s.plan || {}, feat = Aa.features();
    var st = SSL_LABEL[ssl.status] || ['صادر نشده', 'muted'];
    var cert = P.card({ title: 'گواهی SSL', icon: 'certificate', tone: st[1] === 'success' ? 'success' : 'brand', id: 'cert',
      actions: h('span', { className: 'pcdn-pill pcdn-tone-' + st[1] }, h('span', { className: 'pcdn-dot' }), h('span', { text: st[0] })) });
    append(cert.body, h('dl', { className: 'pcdn-dl pcdn-dl-cols' },
      h('div', null, h('dt', { text: 'نوع گواهی' }), h('dd', { text: ssl.source === 'custom' ? 'اختصاصی (بارگذاری‌شده)' : ssl.source === 'letsencrypt' ? "رایگان (Let's Encrypt)" : '—' })),
      h('div', null, h('dt', { text: 'تاریخ انقضا' }), h('dd', { text: ssl.expires_at ? P.date(ssl.expires_at, { dateStyle: 'long' }) : '—' })),
      h('div', null, h('dt', { text: 'نام‌های پوشش‌داده‌شده' }), h('dd', null, (ssl.names || []).length ? chipsOf(ssl.names) : '—'))));
    if (ssl.status === 'failed' && ssl.error) {
      append(cert.body, [P.alertBox('danger', ['صدور گواهی ناموفق بود. معمولاً یعنی نیم‌سرورها هنوز کاملاً منتقل نشده‌اند یا رکورد CAA اجازه صدور نمی‌دهد. ', Aa.tutLink('https', 'راهنمای HTTPS')]),
        h('details', { className: 'pcdn-details' }, h('summary', { text: 'جزئیات فنی خطا' }), h('pre', { className: 'pcdn-pre', dir: 'ltr', text: String(ssl.error).slice(-600) }))]);
    }
    if (!plan.ssl_allowed && ssl.source !== 'custom') {
      cert.body.appendChild(h('p', { className: 'pcdn-muted', text: 'SSL رایگان در این پلن فعال نیست.' }));
    } else if (ssl.source !== 'custom') {
      cert.body.appendChild(h('p', { className: 'pcdn-muted' }, "گواهی رایگان برای ", ltr(s.domain), ' و ', ltr('*.' + s.domain), ' پس از تأیید نیم‌سرورها خودکار صادر و پیش از انقضا تمدید می‌شود.'));
      if (s.ns_verified && ssl.status !== 'pending') {
        var req = P.btn(ssl.status === 'active' ? 'صدور مجدد' : 'درخواست صدور', { icon: 'refresh', size: 'sm', write: true, cls: 'pcdn-ssl-request', onclick: function () {
          P.busy(req, P.api('POST', 'ssl')).then(function (res) {
            if (!res.ok) { P.toast(P.errorText(res), 'error'); return; }
            Aa.reloadSite().then(function () { Aa.renderMain(); P.toast('درخواست صدور گواهی ثبت شد.'); });
          });
        } });
        cert.body.appendChild(h('div', { className: 'pcdn-row-actions' }, req));
      }
    }

    var certOk = ssl.status === 'active';
    var f = Aa.sectionForm('ssl', function (d, f2) {
      d.hsts = d.hsts || { enabled: false, max_age: 31536000, include_subdomains: false, preload: false };
      var c = P.card({ title: 'تنظیمات HTTPS', icon: 'lock', id: 'settings' });
      append(c.body, [
        P.toggle(d, 'force_https', 'انتقال خودکار HTTP به HTTPS', { help: certOk ? 'همه بازدیدهای http:// با ریدایرکت ۳۰۱ به https:// منتقل می‌شوند.' : 'تا وقتی گواهی فعال نشود اعمال نمی‌شود.' }),
        P.toggle(d.hsts, 'enabled', 'HSTS', { help: 'مرورگرها تا پایان مدت تعیین‌شده فقط با HTTPS به سایت وصل می‌شوند؛ خاموش کردنش فوری اثر نمی‌کند.', onchange: f2.redraw }),
        d.hsts.enabled ? h('div', { className: 'pcdn-subpanel' },
          P.duration(d.hsts, 'max_age', 'مدت (max-age)', { min: 0, picks: [[86400, '۱ روز (آزمایشی)'], [15552000, '۶ ماه'], [31536000, '۱ سال']] }),
          P.toggle(d.hsts, 'include_subdomains', 'شامل همه زیردامنه‌ها', { help: 'فقط وقتی همه زیردامنه‌ها HTTPS دارند.' }),
          P.toggle(d.hsts, 'preload', 'preload', { onchange: f2.redraw }),
          d.hsts.preload ? P.alertBox('danger', 'preload را فقط وقتی فعال کنید که قصد ثبت دامنه در فهرست preload مرورگرها را دارید. خروج از این فهرست ماه‌ها طول می‌کشد و در این مدت هر زیردامنه بدون HTTPS از دسترس خارج می‌شود.') : null) : null,
        P.choice(d, 'min_tls', 'حداقل نسخه TLS', [['1.2', 'TLS 1.2', 'سازگار با تقریباً همه مرورگرها و دستگاه‌ها.', null, 'پیشنهادی'], ['1.3', 'TLS 1.3', 'امن‌تر، ولی مرورگرها و دستگاه‌های قدیمی وصل نمی‌شوند.']], { cols: 2 }),
        P.choice(d, 'origin_protocol', 'اتصال CDN به سرور اصلی', [
          ['http', 'HTTP (پورت ۸۰)', 'ساده‌ترین حالت؛ سرور اصلی به گواهی نیاز ندارد.'],
          ['https', 'HTTPS (پورت ۴۴۳)', 'رمزنگاری کامل تا سرور اصلی؛ سرور باید گواهی داشته باشد.', null, 'امن‌تر']], { cols: 2, onchange: f2.redraw }),
        d.origin_protocol === 'http' ? P.alertBox('info', ['اگر سرور اصلی (یا وردپرس) خودش به HTTPS ریدایرکت می‌کند، با این حالت خطای «تعداد ریدایرکت زیاد» می‌گیرید. ', Aa.tutLink('redirectloop', 'رفع حلقه ریدایرکت')]) : null,
        d.origin_protocol === 'https' ? P.toggle(d, 'origin_verify', 'بررسی اعتبار گواهی سرور اصلی', { help: 'اگر گواهی سرور اصلی خودامضا یا منقضی باشد، با روشن بودن این گزینه خطای ۵۰۲ می‌گیرید.' }) : null
      ]);
      return c;
    });

    var custom;
    if (!feat.custom_ssl) {
      custom = P.card({ title: 'گواهی اختصاصی', icon: 'lock', tone: 'muted', id: 'custom' });
      custom.body.appendChild(h('p', { className: 'pcdn-muted' }, 'بارگذاری گواهی اختصاصی در پلن شما فعال نیست. ', h('a', { className: 'pcdn-link', href: Aa.upgradeUrl, text: 'ارتقای پلن' })));
    } else {
      custom = P.collapsible({ title: 'گواهی اختصاصی', subtitle: ssl.source === 'custom' ? 'گواهی اختصاصی شما فعال است.' : 'اگر گواهی خریداری‌شده (مثلاً EV یا OV) دارید، اینجا بارگذاری کنید.',
        icon: 'upload', tone: 'muted', id: 'custom', open: ssl.source === 'custom' });
      var cs = { cert: '', key: '' };
      var errs = h('div');
      var up = P.btn('بارگذاری گواهی', { kind: 'primary', icon: 'upload', write: true, cls: 'pcdn-cert-upload', onclick: function () {
        clear(errs);
        P.busy(up, P.api('PUT', 'ssl/custom', cs)).then(function (res) {
          if (!res.ok) { errs.appendChild(P.errorBox(res, 'بارگذاری گواهی انجام نشد')); return; }
          Aa.reloadSite().then(function () { Aa.renderMain(); P.toast('گواهی اختصاصی فعال شد.'); });
        });
      } });
      var rm = ssl.source === 'custom' ? P.btn('حذف گواهی اختصاصی', { kind: 'danger-soft', icon: 'trash', write: true, onclick: function () {
        P.confirm({ title: 'حذف گواهی اختصاصی', danger: true, ok: 'حذف گواهی', body: "گواهی اختصاصی حذف می‌شود و گواهی رایگان Let's Encrypt دوباره صادر می‌شود. تا صدور گواهی جدید (معمولاً چند دقیقه) ممکن است HTTPS در دسترس نباشد." })
          .then(function (ok) {
            if (!ok) return;
            P.busy(rm, P.api('DELETE', 'ssl/custom')).then(function (res) {
              if (!res.ok) { P.toast(P.errorText(res), 'error'); return; }
              Aa.reloadSite().then(function () { Aa.renderMain(); P.toast('گواهی اختصاصی حذف شد.'); });
            });
          });
      } }) : null;
      append(custom.body, [
        h('p', { className: 'pcdn-muted', text: 'گواهی (به همراه زنجیره میانی) و کلید خصوصی را با فرمت PEM وارد کنید. گواهی باید معتبر، منقضی‌نشده و شامل نام دامنه باشد.' }),
        P.textarea(cs, 'cert', 'گواهی و زنجیره (PEM)', { rows: 5, placeholder: '-----BEGIN CERTIFICATE-----' }),
        P.textarea(cs, 'key', 'کلید خصوصی (PEM)', { rows: 5, placeholder: '-----BEGIN PRIVATE KEY-----', help: 'کلید خصوصی فقط برای CDN ارسال می‌شود و جایی نمایش داده نمی‌شود.' }),
        errs, h('div', { className: 'pcdn-row-actions' }, up, rm)]);
    }
    return [cert, f.el, custom];
  }

  // ------------------------------------------------------------------ headers

  function headerRows(d, key, allowRemove, f2) {
    d[key] = d[key] || [];
    return [d[key].length ? h('div', { className: 'pcdn-rows' }, d[key].map(function (x, i) {
      var removing = allowRemove && x.value === null;
      var row = h('div', { className: 'pcdn-hrow' + (removing ? ' is-remove' : '') },
        P.input(x, 'name', null, { placeholder: 'X-Header', aria: 'نام هدر ' + num(i + 1) }),
        removing ? h('span', { className: 'pcdn-muted pcdn-hrow-note', text: 'این هدر از پاسخ حذف می‌شود' }) : P.input(x, 'value', null, { placeholder: 'value', aria: 'مقدار هدر ' + num(i + 1) }),
        allowRemove ? h('label', { className: 'pcdn-inline' }, P.switchInput(removing, 'حذف هدر ' + (x.name || num(i + 1)) + ' از پاسخ', function (v) { x.value = v ? null : ''; f2.redraw(); }, { small: true }), h('span', { text: 'حذف' })) : null,
        P.iconBtn('trash', 'حذف ردیف ' + num(i + 1), function () { d[key].splice(i, 1); f2.redraw(); }, { write: true, cls: 'is-danger' }));
      P.reg(P.pathOf(x), row);
      return row;
    })) : h('p', { className: 'pcdn-muted', text: 'هدری تعریف نشده است.' }),
    d[key].length < 20 ? P.btn('افزودن هدر', { icon: 'plus', size: 'sm', write: true, onclick: function () { d[key].push({ name: '', value: '' }); f2.redraw(); } }) : null];
  }
  function renderHeaders(Aa) {
    var f = Aa.sectionForm('headers', function (d, f2) {
      d.response = d.response || [];
      function has(n) { return d.response.some(function (x) { return String(x.name).toLowerCase() === n.toLowerCase(); }); }
      var sec = [['X-Frame-Options', 'SAMEORIGIN'], ['X-Content-Type-Options', 'nosniff'], ['Referrer-Policy', 'strict-origin-when-cross-origin']];
      var need = sec.filter(function (x) { return !has(x[0]); });
      var p = presets('الگوهای آماده', 'هدرهای پرکاربرد را با یک کلیک اضافه کنید.', [
        { id: 'security', title: 'هدرهای امنیتی پیشنهادی', icon: 'shieldCheck', desc: 'X-Frame-Options، X-Content-Type-Options و Referrer-Policy به پاسخ‌ها اضافه می‌شوند.',
          disabled: need.length ? null : 'این هدرها از قبل اضافه شده‌اند', apply: function () { need.forEach(function (x) { d.response.push({ name: x[0], value: x[1] }); }); } },
        { id: 'server', title: 'مخفی کردن هدر Server', icon: 'eye', desc: 'نام و نسخه وب‌سرور اصلی در پاسخ‌ها نمایش داده نمی‌شود.',
          disabled: has('Server') ? 'از قبل اضافه شده' : null, apply: function () { d.response.push({ name: 'Server', value: null }); } }
      ], d, f2);
      var req = P.card({ title: 'هدرهای درخواست به سرور اصلی', icon: 'arrowLeft', tone: 'muted', id: 'request', subtitle: 'مثلاً برای شناسایی ترافیک CDN در سرور اصلی.' });
      append(req.body, headerRows(d, 'request', false, f2));
      var res = P.card({ title: 'هدرهای پاسخ به بازدیدکننده', icon: 'arrowRight', tone: 'muted', id: 'response', subtitle: 'اضافه، بازنویسی یا حذف هدرهای پاسخ.' });
      append(res.body, headerRows(d, 'response', true, f2));
      return [p, req, res, h('p', { className: 'pcdn-help', text: 'نام هدر فقط حروف لاتین، عدد و خط تیره. هدرهای Host، Content-Length و hop-by-hop مجاز نیستند. حداکثر ۲۰ مورد در هر بخش.' })];
    });
    return f.el;
  }

  // ------------------------------------------------------------------ error pages

  var ERR_SAMPLE = '<!doctype html>\n<html lang="fa" dir="rtl">\n<head><meta charset="utf-8"><title>خطای موقت</title></head>\n<body style="font-family:Tahoma,sans-serif;text-align:center;padding:60px">\n  <h1>سایت موقتاً در دسترس نیست</h1>\n  <p>لطفاً چند دقیقه دیگر دوباره تلاش کنید.</p>\n</body>\n</html>';
  function renderErrorpages(Aa) {
    var f = Aa.sectionForm('errorpages', function (d, f2) {
      function one(key, title, desc) {
        var val = d[key];
        var size = val ? new Blob([val]).size : 0;
        var c = P.card({ title: title, subtitle: desc, icon: 'fileWarn', tone: key === '5xx' ? 'danger' : 'warning', id: 'err-' + key,
          actions: h('span', { className: 'pcdn-pill pcdn-tone-' + (val ? 'success' : 'muted') }, h('span', { className: 'pcdn-dot' }), h('span', { text: val ? 'سفارشی' : 'پیش‌فرض' })) });
        append(c.body, [
          P.textarea(d, key, null, { rows: 8, nullable: true, placeholder: '<html>…</html>' }),
          h('div', { className: 'pcdn-row-actions' },
            h('span', { className: 'pcdn-muted' + (size > 65536 ? ' is-bad' : ''), text: P.bytes(size) + ' از ۶۴ KB' }),
            P.btn('پیش‌نمایش', { icon: 'eye', size: 'sm', onclick: function () { preview(title, d[key] || ''); } }),
            !val ? P.btn('درج نمونه', { icon: 'sparkles', size: 'sm', write: true, onclick: function () { d[key] = ERR_SAMPLE; f2.redraw(); } }) : null,
            val ? P.btn('بازگشت به پیش‌فرض', { icon: 'refresh', size: 'sm', write: true, onclick: function () { d[key] = null; f2.redraw(); } }) : null)]);
        c.querySelector('textarea').setAttribute('aria-label', title);
        return c;
      }
      return [one('5xx', 'صفحه خطای سرور (5xx)', 'وقتی سرور اصلی در دسترس نیست یا خطا می‌دهد (۵۰۲، ۵۰۴ و ...).'),
        one('4xx', 'صفحه خطای کاربر (4xx)', 'برای خطاهایی مثل ۴۰۳ (مسدود) و ۴۲۹ (محدودیت نرخ) که CDN تولید می‌کند.')];
    });
    return f.el;
  }
  function preview(title, html) {
    var d = P.dialog({ title: 'پیش‌نمایش: ' + title, icon: 'eye', wide: true });
    var fr = h('iframe', { className: 'pcdn-preview-frame', sandbox: '', title: 'پیش‌نمایش صفحه خطا', referrerpolicy: 'no-referrer' });
    fr.srcdoc = html || '<p style="font-family:Tahoma;padding:24px">صفحه پیش‌فرض CDN نمایش داده می‌شود.</p>';
    d.body.appendChild(fr);
    d.foot.appendChild(P.btn('بستن', { onclick: function () { d.close(); } }));
    d.focusFirst();
  }

  // ------------------------------------------------------------------ registry

  function def(id, o) { pages[id] = o; }
  def('cache', {
    title: 'کش', icon: 'zap', heading: 'کش و پاکسازی',
    desc: 'فایل‌های سایت در سرورهای CDN نگهداری می‌شوند تا سریع‌تر بارگذاری شوند و بار سرور شما کم شود.',
    guide: { what: 'CDN پاسخ‌های قابل کش (تصاویر، CSS، JS و ...) را نگه می‌دارد و بدون مراجعه به سرور شما تحویل می‌دهد.',
      when: 'همیشه روشن باشد. بعد از به‌روزرسانی سایت، آدرس فایل‌های تغییرکرده را پاکسازی کنید.',
      rec: 'سطح استاندارد، مدت کش CDN یک روز، و الگوی مناسب نوع سایت (برای وردپرس/ووکامرس: «فروشگاه اینترنتی»).',
      mistakes: ['استفاده از سطح «تهاجمی» برای سایت‌هایی که کاربر واردشده دارند.', 'فراموش کردن خاموش کردن حالت توسعه.', 'روشن کردن «نادیده گرفتن Query String» در حالی که فایل‌ها با ‎?v= نسخه‌بندی شده‌اند.'],
      tut: 'cache' },
    render: renderCache
  });
  def('pagerules', {
    title: 'قوانین صفحه', icon: 'sliders',
    desc: 'برای مسیرهای خاص (مثلاً پنل مدیریت یا فایل‌های استاتیک) رفتار کش، WAF یا ریدایرکت را جداگانه تعیین کنید.',
    guide: { what: 'هر قانون یک الگوی مسیر دارد؛ اولین قانون منطبق، تنظیمات کلی را برای آن مسیر تغییر می‌دهد.',
      when: 'وقتی بخشی از سایت باید متفاوت رفتار کند: پنل مدیریت بدون کش، فایل‌های ثابت با کش طولانی، یا ریدایرکت آدرس قدیمی.',
      rec: 'برای وردپرس: ‎/wp-admin/*‎ بدون کش. قوانین خاص‌تر را بالاتر قرار دهید.',
      mistakes: ['قرار دادن قانون کلی (مثل ‎/*‎) بالای قوانین خاص؛ قوانین پایین‌تر هرگز اجرا نمی‌شوند.', '«کش همه‌چیز» برای صفحات سبد خرید یا حساب کاربری.'],
      tut: 'cache' },
    upsell: 'با ارتقای پلن می‌توانید برای بخش‌های مختلف سایت کش و ریدایرکت جداگانه تعریف کنید.',
    lock: function (f) { return !(f.max_page_rules > 0); },
    render: renderPagerules
  });
  def('image', {
    title: 'بهینه‌سازی تصویر', icon: 'image',
    desc: 'تصاویر را در سرورهای CDN با اندازه مناسب هر صفحه تحویل دهید تا صفحات سبک‌تر و سریع‌تر شوند.',
    guide: { what: 'با افزودن ‎?width=‎ یا ‎?height=‎ به آدرس تصویر، نسخه کوچک‌شده در CDN ساخته و کش می‌شود.',
      when: 'وقتی تصاویر بزرگ آپلود می‌کنید ولی در صفحه کوچک نمایش می‌دهید (مثل تصاویر محصول و بندانگشتی‌ها).',
      rec: 'کیفیت ۸۰ تا ۸۵ و حداکثر عرض ۲۰۰۰ پیکسل.', mistakes: ['درخواست عرض‌های بسیار متنوع که کارایی کش را کم می‌کند.'] },
    upsell: 'با ارتقای پلن، تصاویر سایت در لبه تغییر اندازه داده و سبک‌تر تحویل می‌شوند.',
    lock: function (f) { return !f.image_optimization; },
    render: renderImage
  });
  def('pools', {
    title: 'توزیع بار', icon: 'lb', heading: 'توزیع بار (Load Balancer)',
    desc: 'ترافیک را بین چند سرور اصلی تقسیم کنید؛ اگر یکی از کار بیفتد، بقیه جواب می‌دهند.',
    guide: { what: 'استخر گروهی از سرورهای اصلی است. CDN بر اساس وزن بین آن‌ها تقسیم می‌کند و سرورهای ناسالم را کنار می‌گذارد.',
      when: 'وقتی بیش از یک سرور دارید یا می‌خواهید سرور پشتیبان برای زمان خرابی داشته باشید.',
      rec: 'روش وزنی با بررسی سلامت روی مسیری سبک (مثل ‎/health‎) هر ۱۰ ثانیه.',
      mistakes: ['ساختن استخر ولی انتخاب نکردن آن در رکورد DNS.', 'مسیر بررسی سلامتی که به ورود نیاز دارد یا ریدایرکت می‌کند.'], tut: 'loadbalancing' },
    upsell: 'با ارتقای پلن می‌توانید چند سرور اصلی داشته باشید و در زمان خرابی یکی، سایت قطع نشود.',
    lock: function (f) { return !(f.load_balancer && f.max_pools > 0); },
    render: renderPools
  });
  def('firewall', {
    title: 'فایروال', icon: 'wall',
    desc: 'بر اساس کشور، آی‌پی، مسیر یا ربات تصمیم بگیرید چه کسی به سایت دسترسی داشته باشد.',
    guide: { what: 'قوانین فایروال پیش از رسیدن درخواست به سایت اجرا می‌شوند و می‌توانند مسدود کنند، چالش بگذارند یا اجازه دهند.',
      when: 'برای محافظت از صفحه ورود، محدود کردن کشورها، مسدود کردن آی‌پی‌های مزاحم و ربات‌های اسکنر.',
      rec: 'از الگوهای آماده شروع کنید؛ به جای «مسدود» برای کشورها از «چالش JS» استفاده کنید تا کاربران واقعی با VPN هم وارد شوند.',
      mistakes: ['قانون «اجازه» برای بازه‌های بزرگ آی‌پی (همه بررسی‌های امنیتی را دور می‌زند).', 'قرار دادن قانون کلی بالای قوانین خاص.', 'اقدام پیش‌فرض «مسدود» بدون قانون اجازه.'],
      tut: 'firewall' },
    upsell: 'با ارتقای پلن، قوانین فایروال برای کشور، آی‌پی و مسیر در اختیار شماست.',
    lock: function (f) { return !(f.max_firewall_rules > 0); },
    render: renderFirewall
  });
  def('waf', {
    title: 'WAF', icon: 'shield', heading: 'فایروال برنامه وب (WAF)',
    desc: 'حملات رایج وب مثل SQL Injection و XSS پیش از رسیدن به سایت شما شناسایی و متوقف می‌شوند.',
    guide: { what: 'WAF محتوای هر درخواست را با هزاران امضای حمله مقایسه می‌کند.',
      when: 'برای همه سایت‌ها، مخصوصاً وردپرس، فروشگاه‌ها و سایت‌هایی با فرم.',
      rec: 'سطح «پیشنهادی» در حالت مسدودسازی. اگر سایت فرم یا API پیچیده دارد، اول چند روز «فقط ثبت».',
      mistakes: ['خاموش کردن کل WAF به خاطر یک مسدودسازی اشتباه (به جای ساختن استثنا).', 'حساسیت ۳ بدون بررسی رویدادها.'], tut: 'waf' },
    upsell: 'با ارتقای پلن، سایت شما در برابر حملات رایج وب (SQLi، XSS و ...) محافظت می‌شود.',
    lock: function (f) { return !f.waf; },
    render: renderWaf
  });
  def('ddos', {
    title: 'DDoS', icon: 'shieldBolt', heading: 'حفاظت DDoS',
    desc: 'در زمان حجم غیرعادی درخواست‌ها، بازدیدکنندگان پیش از ورود یک چالش کوتاه می‌بینند تا ربات‌ها متوقف شوند.',
    guide: { what: 'چالش JS در چند ثانیه و بدون دخالت کاربر، مرورگر واقعی را از ربات تشخیص می‌دهد.',
      when: 'حالت خودکار همیشه؛ حالت «زیر حمله» فقط در زمان حمله.',
      rec: 'خودکار با آستانه ۲۰۰ درخواست در ثانیه و اعتبار ۱ ساعت.',
      mistakes: ['روشن ماندن طولانی حالت زیر حمله (ربات‌های مفید مثل گوگل هم چالش می‌بینند).', 'نبستن دسترسی مستقیم به آی‌پی سرور اصلی.'], tut: 'underattack' },
    upsell: 'با ارتقای پلن، در زمان حمله DDoS سایت شما با چالش خودکار محافظت می‌شود.',
    lock: function (f) { return !f.ddos; },
    render: renderDdos
  });
  def('ratelimit', {
    title: 'محدودیت نرخ', icon: 'gauge',
    desc: 'تعداد درخواست‌های هر آی‌پی به یک مسیر را محدود کنید تا حدس رمز عبور و فشار روی API بی‌اثر شود.',
    guide: { what: 'اگر یک آی‌پی در بازه مشخص بیش از حد درخواست بفرستد، مسدود می‌شود یا چالش می‌بیند.',
      when: 'برای صفحات ورود، فرم‌ها، جستجو و API.', rec: 'ورود: ۱۰ درخواست POST در دقیقه. API: ۶۰ در دقیقه.',
      mistakes: ['محدودیت روی کل سایت (‎/*‎) با عدد کم؛ کاربران عادی هم خطای ۴۲۹ می‌گیرند.'], tut: 'underattack' },
    upsell: 'با ارتقای پلن می‌توانید برای صفحات حساس محدودیت تعداد درخواست بگذارید.',
    lock: function (f) { return !(f.max_ratelimit_rules > 0); },
    render: renderRatelimit
  });
  def('hotlink', {
    title: 'Hotlink', icon: 'link', heading: 'جلوگیری از Hotlink',
    desc: 'نگذارید سایت‌های دیگر تصاویر و ویدیوهای شما را مستقیم نمایش دهند و ترافیک شما را مصرف کنند.',
    guide: { what: 'درخواست فایل‌هایی با پسوندهای انتخابی، اگر از سایتی خارج از فهرست مجاز آمده باشد، مسدود می‌شود.',
      when: 'وقتی تصاویر یا ویدیوهای شما در سایت‌های دیگر استفاده می‌شوند.', rec: 'دامنه خودتان و ‎*.دامنه‌تان را مجاز کنید و «بدون Referer» را روشن نگه دارید.',
      mistakes: ['اضافه نکردن دامنه خودتان به فهرست مجاز.', 'خاموش کردن «بدون Referer» که باعث مشکل در برخی اپلیکیشن‌ها می‌شود.'] },
    render: renderHotlink
  });
  def('ssl', {
    title: 'SSL/TLS', icon: 'lock', heading: 'SSL/TLS و HTTPS',
    desc: 'گواهی امنیتی، انتقال به HTTPS و نحوه اتصال CDN به سرور اصلی را مدیریت کنید.',
    guide: { what: 'گواهی SSL ارتباط بازدیدکننده با CDN را رمز می‌کند. «اتصال به سرور اصلی» تعیین می‌کند CDN با HTTP یا HTTPS به سرور شما وصل شود.',
      when: 'بعد از تأیید نیم‌سرورها گواهی خودکار صادر می‌شود؛ سپس HTTPS اجباری را روشن کنید.',
      rec: 'HTTPS اجباری روشن، TLS 1.2، و اگر سرور اصلی گواهی معتبر دارد اتصال HTTPS.',
      mistakes: ['ریدایرکت HTTPS روی سرور اصلی همراه با اتصال HTTP (حلقه ریدایرکت).', 'فعال کردن preload بدون آمادگی.'], tut: 'https' },
    render: renderSsl
  });
  def('headers', {
    title: 'هدرها', icon: 'code', heading: 'هدرهای HTTP',
    desc: 'هدرهای درخواست به سرور اصلی و هدرهای پاسخ به بازدیدکننده را اضافه، بازنویسی یا حذف کنید.',
    guide: { what: 'هدرها اطلاعات جانبی هر درخواست و پاسخ HTTP هستند (مثلاً سیاست‌های امنیتی مرورگر).',
      when: 'برای افزودن هدرهای امنیتی، مخفی کردن اطلاعات سرور یا فرستادن یک کلید مخفی به سرور اصلی.',
      rec: 'هدرهای امنیتی پیشنهادی را اضافه کنید.', mistakes: ['X-Frame-Options: DENY وقتی سایت در iframe خودتان نمایش داده می‌شود.'] },
    render: renderHeaders
  });
  def('errorpages', {
    title: 'صفحات خطا', icon: 'fileWarn', heading: 'صفحات خطای سفارشی',
    desc: 'به جای صفحه پیش‌فرض، صفحه خطای هم‌رنگ با برند خود را به بازدیدکنندگان نشان دهید.',
    guide: { what: 'وقتی سرور اصلی در دسترس نیست یا درخواست مسدود می‌شود، این HTML نمایش داده می‌شود.',
      when: 'اختیاری؛ برای تجربه کاربری بهتر در زمان قطعی.', rec: 'یک صفحه ساده و سبک (بدون وابستگی به فایل‌های سرور اصلی).',
      mistakes: ['لینک دادن به CSS یا تصاویر روی سرور اصلی که در زمان قطعی بارگذاری نمی‌شوند.'], tut: 'troubleshoot' },
    render: renderErrorpages
  });
})();
