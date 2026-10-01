/*
 * Pasargad CDN — configuration pages (cache, page rules, image, pools, firewall,
 * WAF, DDoS, rate limit, hotlink, SSL, headers, error pages).
 * Registers into window.PCDN.pages; app.js provides the shell (PCDN.app) at render time.
 * The Wave 6B (SPEC §14.2) cards on the WAF and SSL pages come from rules.js (PCDN.sec6b),
 * which in turn reuses this file's building blocks through PCDN.kit.
 */
(function () {
  'use strict';
  var P = window.PCDN = window.PCDN || {};
  var t = P.t;  // i18n.js (SPEC §16.10)
  var pages = P.pages = P.pages || {};
  var h = P.h, append = P.append, clear = P.clear, icon = P.icon, ltr = P.ltr, clone = P.clone, num = P.num;

  function A() { return P.app; }
  function site() { return P.app.S.site; }
  function domain() { return site().domain; }
  function has(o, k) { return !!o && typeof o === 'object' && Object.prototype.hasOwnProperty.call(o, k); }
  /**
   * True when the controller knows the Wave 6A fields (SPEC §14.1). It always returns whole sections
   * with defaults, so a section without the new keys means an older controller that would reject them.
   */
  function perf6a() {
    var c = site().config || {};
    return has(c.cache, 'stale_while_revalidate') || has(c.ssl, 'http3') || has(c.image, 'auto_webp')
      || !!(c.pagerules && (c.pagerules.rules || []).some(function (r) { return has(r, 'preload'); }));
  }

  var TTL_PICKS = [[3600, t('۱ ساعت')], [86400, t('۱ روز')], [604800, t('۱ هفته')], [2592000, t('۱ ماه')]];

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
          P.toast(it.done || (t('الگوی «') + it.title + t('» اعمال شد؛ بررسی کنید و «ذخیره» را بزنید.')), 'info');
          var hl = f.el.querySelector('.is-new');
          if (hl && hl.scrollIntoView) hl.scrollIntoView({ block: 'nearest', behavior: A().reduced() ? 'auto' : 'smooth' });
        } },
        h('span', { className: 'pcdn-preset-icon' }, icon(it.icon || 'sparkles')),
        h('span', { className: 'pcdn-preset-text' }, h('span', { className: 'pcdn-preset-title', text: it.title }), h('span', { className: 'pcdn-preset-desc', text: it.desc })),
        act ? h('span', { className: 'pcdn-preset-badge', text: t('فعلی') }) : null,
        it.disabled ? h('span', { className: 'pcdn-preset-badge is-muted', text: t('سقف پلن') }) : null);
      return b;
    })));
    return c;
  }

  /** A counted noun ("قانون" / "rule"): English lower-cases it and adds the plural s (Persian needs neither). */
  function noun(what, n) {
    if (!P.isEn) return what;
    what = String(what).charAt(0).toLowerCase() + String(what).slice(1);
    return n === 1 || /(s|\))$/.test(what) ? what : what + 's';
  }
  function limitText(n, max, what) {
    return h('span', { className: 'pcdn-limit' + (n >= max ? ' is-full' : '') }, num(n) + t(' از ') + num(max) + ' ' + noun(what, max));
  }

  /** Drawer editor over a clone; ok(copy) is called on «تأیید». sentence(copy) feeds a live preview. */
  function editDrawer(title, subtitle, obj, build, ok, validate, sentence) {
    var copy = clone(obj);
    var d = P.dialog({ title: title, subtitle: subtitle, icon: 'edit', kind: 'drawer', wide: true });
    var holder = h('div', { className: 'pcdn-form' });
    var err = h('div');
    var pv = sentence ? h('div', { className: 'pcdn-sentence', 'aria-live': 'polite' }) : null;
    function updatePreview() { if (pv) { clear(pv); append(pv, sentence(copy)); } }
    if (pv) d.body.appendChild(h('div', { className: 'pcdn-preview' }, h('span', { className: 'pcdn-label', text: t('پیش‌نمایش') }), pv));
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
    var okBtn = P.btn(t('تأیید'), { kind: 'primary', icon: 'check', write: true, cls: 'pcdn-drawer-ok', onclick: function () {
      clear(err);
      var problem = validate ? validate(copy) : null;
      if (problem) { err.appendChild(P.alertBox('danger', problem)); err.scrollIntoView && err.scrollIntoView({ block: 'nearest' }); return; }
      d.close(true);
      ok(copy);
    } });
    append(d.foot, [okBtn, P.btn(t('انصراف'), { onclick: function () { d.close(); } })]);
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
    var add = P.btn(cfg.addLabel || t('قانون جدید'), { kind: 'primary', icon: 'plus', size: 'sm', write: true, cls: 'pcdn-add-rule', disabled: full,
      title: full ? t('به سقف ') + num(cfg.max) + ' ' + noun(cfg.what, cfg.max) + t(' پلن رسیده‌اید') : null,
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
          cfg.label ? h('div', { className: 'pcdn-rule-name' }, cfg.label(r), isNew ? P.badge(t('ذخیره نشده'), 'warning') : null) : null,
          h('div', { className: 'pcdn-sentence' }, cfg.sentence(r))),
        h('div', { className: 'pcdn-rule-ctl' },
          'enabled' in r ? P.switchInput(r.enabled, (r.enabled ? t('غیرفعال کردن') : t('فعال کردن')) + t(' قانون ') + num(i + 1), function (v) { r.enabled = v; f.redraw(); }, { write: true, small: true }) : null,
          P.iconBtn('up', t('انتقال قانون ') + num(i + 1) + t(' به بالا'), function () { move(arr, i, -1); f.redraw(); focusRule(f, i - 1, 'up'); }, { write: true, disabled: i === 0 }),
          P.iconBtn('down', t('انتقال قانون ') + num(i + 1) + t(' به پایین'), function () { move(arr, i, 1); f.redraw(); focusRule(f, i + 1, 'down'); }, { write: true, disabled: i === arr.length - 1 }),
          P.iconBtn('edit', t('ویرایش قانون ') + num(i + 1), function () { cfg.edit(r, function (nr) { if (r._new) nr._new = true; arr[i] = nr; f.redraw(); }); }, { write: true }),
          P.iconBtn('trash', t('حذف قانون ') + num(i + 1), function () { arr.splice(i, 1); f.redraw(); P.toast(t('قانون از فهرست حذف شد؛ برای اعمال «ذخیره» را بزنید.'), 'info'); }, { write: true, cls: 'is-danger' })));
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
    var tx = arr[i]; arr[i] = arr[j]; arr[j] = tx;
  }
  function focusRule(f, i, dir) {
    var li = f.el.querySelectorAll('.pcdn-rule')[i];
    if (!li) return;
    var b = li.querySelector('[aria-label*="' + (dir === 'up' ? t('بالا') : t('پایین')) + '"]:not([disabled])') || li.querySelector('button:not([disabled])');
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
      var tx = String(v);
      return [h('bdi', { className: 'pcdn-vchip', dir: 'ltr', title: o.country ? P.country(tx) : null, text: tx }),
        o.country && P.country(tx) !== tx ? h('span', { className: 'pcdn-vcc', text: '(' + P.country(tx) + ')' }) : null,
        i < all.length - 1 ? h('span', { className: 'pcdn-sep', text: t('، ') }) : null];
    });
  }
  function word(tx, cls) { return h('span', { className: cls || 'pcdn-w', text: tx }); }

  // ------------------------------------------------------------------ cache

  var CACHE_PRESETS = [
    { id: 'general', title: t('وب‌سایت عمومی'), icon: 'globe', desc: t('سایت خبری، شرکتی یا وبلاگ: کش استاندارد یک‌روزه و کش مرورگر ۴ ساعته.'),
      v: { enabled: true, level: 'standard', edge_ttl: 86400, browser_ttl: 14400, ignore_query: false, bypass_cookies: ['PHPSESSID', 'wordpress_logged_in'], always_online: true } },
    { id: 'shop', title: t('فروشگاه اینترنتی و وردپرس'), icon: 'star', desc: t('ووکامرس و وردپرس: سبد خرید و کاربران واردشده هرگز از کش پاسخ نمی‌گیرند.'),
      v: { enabled: true, level: 'standard', edge_ttl: 86400, browser_ttl: 0, ignore_query: false,
        bypass_cookies: ['wordpress_logged_in', 'wp-postpass_', 'comment_author_', 'woocommerce_items_in_cart', 'wp_woocommerce_session_', 'woocommerce_cart_hash', 'PHPSESSID'], always_online: true } },
    { id: 'api', title: t('API و محتوای پویا'), icon: 'code', desc: t('پاسخ‌ها طبق Cache-Control سرور و حداکثر ۱ دقیقه کش می‌شوند؛ نسخه قدیمی نمایش داده نمی‌شود.'),
      v: { enabled: true, level: 'standard', edge_ttl: 60, browser_ttl: 0, ignore_query: false, bypass_cookies: ['PHPSESSID', 'laravel_session', 'session'], always_online: false } }
  ];
  function sameCache(d, v) {
    return Object.keys(v).every(function (k) { return JSON.stringify(d[k]) === JSON.stringify(v[k]); });
  }

  // Wave 6A (SPEC §14.1): stale content, origin shield and cache-key options. Each control is shown
  // only when the controller's section carries the field (older controllers reject unknown fields).
  var STALE_ERROR_PICKS = [[0, t('خاموش')], [3600, t('۱ ساعت')], [21600, t('۶ ساعت')], [86400, t('۱ روز')], [604800, t('۷ روز')]];
  var MAX_STALE_ERROR = 604800;
  var MAX_KEY_COOKIES = 10, MAX_KEY_QUERY = 50;
  var COOKIE_NAME_RE = /^[A-Za-z0-9_.-]{1,64}$/;      // same rule as the controller's cookie names
  var QUERY_NAME_RE = /^[A-Za-z0-9_.[\]-]{1,64}$/;    // plus [] for array parameters (ids[])
  var KEY_QUERY_CONFLICT = t('فهرست پارامترهای مجاز کلید کش با «نادیده گرفتن Query String» قابل جمع نیست؛ یکی از آن دو را خاموش یا خالی کنید.');

  function staleErrorOptions(v) {
    var opts = STALE_ERROR_PICKS.slice();
    if (typeof v === 'number' && !opts.some(function (o) { return o[0] === v; })) opts.push([v, P.dur(v) + t(' (مقدار فعلی)')]);
    return opts;
  }
  function nameProblems(d, key, max, re, what, chars, out) {
    if (!has(d, key)) return;
    var list = Array.isArray(d[key]) ? d[key] : [];
    if (list.length > max) out.push({ path: key, msg: t('حداکثر ') + num(max) + ' ' + noun(what, max) + t(' مجاز است؛ ') + num(list.length) + t(' مورد وارد شده.') });
    var bad = list.filter(function (x) { return !re.test(String(x)); });
    if (bad.length) out.push({ path: key, msg: t('نام نامعتبر: ') + bad.join(t('، ')) + t(' — فقط ') + chars + t(' (حداکثر ۶۴ نویسه).') });
  }
  /** Client-side mirror of the controller's cache-section rules (the controller still has the last word). */
  function validateCache(d) {
    var out = [];
    if (has(d, 'stale_if_error')) {
      var v = d.stale_if_error;
      if (typeof v !== 'number' || Math.floor(v) !== v || v < 0 || v > MAX_STALE_ERROR) {
        out.push({ path: 'stale_if_error', msg: t('مدت باید بین ۰ تا ') + num(MAX_STALE_ERROR) + t(' ثانیه (۷ روز) باشد.') });
      }
    }
    nameProblems(d, 'key_cookies', MAX_KEY_COOKIES, COOKIE_NAME_RE, t('کوکی'), t('حروف لاتین، عدد، نقطه، - و _'), out);
    nameProblems(d, 'key_query_allow', MAX_KEY_QUERY, QUERY_NAME_RE, t('پارامتر'), t('حروف لاتین، عدد، نقطه، -، _ و []'), out);
    if (d.ignore_query === true && Array.isArray(d.key_query_allow) && d.key_query_allow.length) out.push({ path: 'key_query_allow', msg: KEY_QUERY_CONFLICT });
    return out;
  }

  function freshnessCard(d) {
    if (!has(d, 'stale_while_revalidate') && !has(d, 'stale_if_error')) return null;
    var c = P.card({ title: t('تازگی و محتوای قدیمی'), icon: 'clock', id: 'freshness', subtitle: t('وقتی نسخه کش‌شده منقضی شده یا سرور اصلی خطا می‌دهد چه اتفاقی بیفتد.') });
    append(c.body, [
      has(d, 'stale_while_revalidate') ? P.toggle(d, 'stale_while_revalidate', t('به‌روزرسانی در پس‌زمینه'), { cls: 'pcdn-swr',
        help: t('وقتی مدت کش فایلی تمام شده، بازدیدکننده بی‌درنگ همان نسخه قبلی را می‌گیرد و CDN نسخه تازه را در پس‌زمینه از سرور اصلی دریافت می‌کند؛ هیچ بازدیدکننده‌ای منتظر سرور اصلی نمی‌ماند. پیشنهادی: روشن.') }) : null,
      has(d, 'stale_if_error') ? P.select(d, 'stale_if_error', t('نمایش نسخه قدیمی هنگام خطای سرور اصلی'), staleErrorOptions(d.stale_if_error), { cls: 'pcdn-stale-error',
        help: t('اگر سرور اصلی خطای ۵xx بدهد یا پاسخ ندهد، تا این مدت پس از انقضا نسخه کش‌شده نمایش داده می‌شود تا سایت از دسترس خارج نشود.') }) : null,
      h('p', { className: 'pcdn-help' }, t('اگر سرور اصلی در هدر '), ltr('Cache-Control'), t(' مقدار '), ltr('stale-while-revalidate'), t(' یا '), ltr('stale-if-error'), t(' بفرستد، همان هم رعایت می‌شود.'))
    ]);
    return c;
  }

  function shieldCard(d) {
    if (!has(d, 'shield')) return null;
    var c = P.card({ title: 'Origin Shield', icon: 'server', id: 'shield', subtitle: t('یک لایه کش میانی جلوی سرور اصلی شما.') });
    append(c.body, [
      P.toggle(d, 'shield', t('Origin Shield (کش لایه‌ای)'), {
        help: t('نودهای CDN فایل‌های کش‌نشده را به‌جای سرور اصلی از نودهای Shield می‌گیرند و فقط Shield به سرور اصلی وصل می‌شود؛ درخواست‌های کمتری به سرور شما می‌رسد و نرخ کش بالاتر می‌رود. برای سایت‌های پربازدید یا سرور اصلی کم‌توان مناسب است.') }),
      h('p', { className: 'pcdn-help pcdn-shield-note' }, icon('info'), h('span', { text: t('فقط وقتی اثر دارد که سکو نود Shield فعال داشته باشد. اگر نود Shield وجود نداشته باشد یا در دسترس نباشد، نودها مثل قبل مستقیم به سرور اصلی وصل می‌شوند و سایت قطع نمی‌شود.') }))
    ]);
    return c;
  }

  /** Tag list with a live «n از max» counter in its help line. */
  function keyList(d, key, label, max, o) {
    var cnt = h('span', { className: 'pcdn-limit' });
    function count() {
      var n = (d[key] || []).length;
      cnt.className = 'pcdn-limit' + (n >= max ? ' is-full' : '');
      cnt.textContent = num(n) + t(' از ') + num(max);
    }
    var el = P.tags(d, key, label, { placeholder: o.placeholder,
      help: h('span', null, o.help + t(' با Enter یا کاما اضافه کنید. '), cnt),
      onchange: function () { count(); if (o.onchange) o.onchange(); } });
    count();
    return el;
  }

  /** «کلید کش» card; returns {card, sync()} — sync() refreshes the ignore_query conflict warning in place. */
  function cacheKeyCard(d) {
    if (!has(d, 'key_device') && !has(d, 'key_cookies') && !has(d, 'key_query_allow')) return { card: null, sync: function () {} };
    var conflict = h('div', { className: 'pcdn-key-conflict', 'aria-live': 'polite' });
    function sync() {
      clear(conflict);
      if (d.ignore_query === true && Array.isArray(d.key_query_allow) && d.key_query_allow.length) conflict.appendChild(P.alertBox('warning', KEY_QUERY_CONFLICT));
    }
    var c = P.card({ title: t('کلید کش'), icon: 'key', id: 'cachekey', subtitle: t('تعیین کنید چه چیزهایی نسخه‌های جداگانه در کش بسازند.') });
    append(c.body, [
      has(d, 'key_device') ? P.toggle(d, 'key_device', t('نسخه جدا برای موبایل و دسکتاپ'), { cls: 'pcdn-key-device',
        help: t('فقط اگر سایت برای موبایل HTML متفاوتی می‌فرستد (نه صرفاً طراحی واکنش‌گرا) روشن کنید؛ وگرنه نرخ کش بی‌دلیل نصف می‌شود.') }) : null,
      has(d, 'key_cookies') ? keyList(d, 'key_cookies', t('کوکی‌های مؤثر در کلید کش'), MAX_KEY_COOKIES, { placeholder: 'lang',
        help: t('مقدار این کوکی‌ها بخشی از کلید کش می‌شود؛ مثلاً کوکی زبان یا واحد پول، تا هر زبان نسخه کش خودش را داشته باشد. کوکی ورود کاربر را اینجا نگذارید؛ برای آن «کوکی‌های عبور از کش» را به کار ببرید.') }) : null,
      has(d, 'key_query_allow') ? keyList(d, 'key_query_allow', t('پارامترهای مجاز Query String'), MAX_KEY_QUERY, { placeholder: 'page', onchange: sync,
        help: t('اگر پر باشد فقط همین پارامترها در کلید کش لحاظ می‌شوند و بقیه (مثل utm_source یا fbclid) نادیده گرفته می‌شوند. خالی یعنی همه پارامترها.') }) : null,
      conflict]);
    sync();
    return { card: c, sync: sync };
  }

  function renderCache() {
    var f = A().sectionForm('cache', function (d, f2) {
      var ck = d.enabled ? cacheKeyCard(d) : null;
      var settings = P.card({ title: t('تنظیمات کش'), icon: 'zap', id: 'settings' });
      append(settings.body, [
        P.toggle(d, 'enabled', t('کش CDN'), { help: t('اگر خاموش باشد همه درخواست‌ها مستقیم به سرور اصلی می‌روند.'), onchange: f2.redraw }),
        d.enabled ? [
          P.choice(d, 'level', t('سطح کش'), [
            ['standard', t('استاندارد'), t('از هدر Cache-Control سرور پیروی می‌کند و فایل‌های ثابت (تصویر، CSS، JS) را کش می‌کند. برای اغلب سایت‌ها مناسب است.'), 'zap', t('پیشنهادی')],
            ['aggressive', t('تهاجمی'), t('همه پاسخ‌های ۲۰۰ و ۳۰۱ کش می‌شوند و کوکی و Cache-Control نادیده گرفته می‌شود. فقط برای سایت‌های کاملاً ایستا.'), 'warn']
          ], { cols: 2 }),
          d.level === 'aggressive' ? P.alertBox('warning', t('در حالت تهاجمی صفحاتی مثل سبد خرید یا پنل کاربری هم ممکن است کش شوند و اطلاعات یک کاربر به دیگران نمایش داده شود. برای این مسیرها قانون صفحه «بدون کش» بسازید.')) : null,
          h('div', { className: 'pcdn-grid' },
            P.duration(d, 'edge_ttl', t('مدت نگهداری در CDN'), { min: 60, max: 31536000, picks: TTL_PICKS, help: t('فایل‌های ثابت حداکثر این مدت در سرورهای CDN می‌مانند.') }),
            P.duration(d, 'browser_ttl', t('مدت نگهداری در مرورگر'), { min: 0, zeroText: t('طبق هدر سرور اصلی'), picks: [[0, t('طبق سرور')], [3600, t('۱ ساعت')], [86400, t('۱ روز')]], help: t('۰ یعنی هدر سرور اصلی دست نمی‌خورد.') })),
          P.toggle(d, 'ignore_query', t('نادیده گرفتن Query String'), { help: t('آدرس‌های ‎?a=1 و ‎?a=2 یک نسخه کش مشترک می‌گیرند. اگر از ‎?v= برای نسخه‌بندی فایل‌ها استفاده می‌کنید خاموش بگذارید.'),
            onchange: function () { if (ck) ck.sync(); } }),
          P.tags(d, 'bypass_cookies', t('کوکی‌های عبور از کش'), { placeholder: 'wordpress_logged_in', help: t('اگر بازدیدکننده کوکی‌ای داشته باشد که نامش با یکی از این‌ها شروع شود، پاسخ از کش داده نمی‌شود (مثلاً کاربران واردشده).') }),
          P.toggle(d, 'always_online', t('همیشه آنلاین'), { help: t('اگر سرور اصلی خطا بدهد یا در دسترس نباشد، آخرین نسخه کش‌شده نمایش داده می‌شود.') }),
          P.toggle(d, 'dev_mode', t('حالت توسعه'), { help: t('کش موقتاً خاموش می‌شود تا تغییرات سایت فوراً دیده شوند. بعد از پایان کار خاموشش کنید.') })
        ] : null
      ]);
      return [presets(t('الگوهای آماده'), t('نوع سایت خود را انتخاب کنید تا تنظیمات مناسب پر شود؛ سپس بررسی و ذخیره کنید.'), CACHE_PRESETS.map(function (p) {
        return { id: p.id, title: p.title, desc: p.desc, icon: p.icon, active: function (x) { return sameCache(x, p.v); },
          apply: function (x) { Object.keys(p.v).forEach(function (k) { x[k] = clone(p.v[k]); }); } };
      }), d, f2), settings, d.enabled ? [freshnessCard(d), shieldCard(d), ck.card] : null];
    }, { validate: validateCache });
    return [f.el, purgeCard()];
  }

  function purgeCard() {
    var c = P.card({ title: t('پاکسازی کش'), icon: 'refresh', id: 'purge', subtitle: t('بعد از تغییر فایل‌های سایت، نسخه قدیمی را از کش حذف کنید.') });
    var st = { urls: '', prefixes: '' };
    var one = P.btn(t('پاکسازی آدرس‌ها'), { kind: 'primary', icon: 'refresh', write: true, cls: 'pcdn-purge-urls', onclick: function () {
      var urls = st.urls.split(/\s+/).map(function (x) { return x.trim(); }).filter(Boolean);
      if (!urls.length) { P.toast(t('حداقل یک آدرس وارد کنید.'), 'warn'); return; }
      if (urls.length > 100) { P.toast(t('حداکثر ۱۰۰ آدرس در هر درخواست.'), 'warn'); return; }
      P.busy(one, P.api('POST', 'purge', { urls: urls })).then(function (res) {
        P.toast(res.ok ? t('درخواست پاکسازی ') + num(urls.length) + t(' آدرس ثبت شد و تا چند ثانیه روی همه سرورها اعمال می‌شود.') : P.errorText(res), res.ok ? 'success' : 'error');
      });
    } });
    var pfx = P.btn(t('پاک‌سازی بر اساس پیشوند'), { kind: 'primary', icon: 'refresh', write: true, cls: 'pcdn-purge-prefixes', onclick: function () {
      var prefixes = st.prefixes.split(/\s+/).map(function (x) { return x.trim(); }).filter(Boolean);
      if (!prefixes.length) { P.toast(t('حداقل یک پیشوند وارد کنید.'), 'warn'); return; }
      if (prefixes.length > 20) { P.toast(t('حداکثر ۲۰ پیشوند در هر درخواست.'), 'warn'); return; }
      P.busy(pfx, P.api('POST', 'purge', { prefixes: prefixes })).then(function (res) {
        P.toast(res.ok ? t('درخواست پاک‌سازی ') + num(prefixes.length) + t(' پیشوند ثبت شد؛ همه فایل‌های زیر این مسیرها حذف می‌شوند.') : P.errorText(res), res.ok ? 'success' : 'error');
      });
    } });
    var all = P.btn(t('پاک‌سازی کل کش'), { kind: 'danger-soft', icon: 'trash', write: true, cls: 'pcdn-purge-all', onclick: function () {
      P.confirm({ title: t('پاک‌سازی کل کش'), danger: true, ok: t('پاک‌سازی کل کش'),
        body: t('همه فایل‌های کش‌شده این دامنه حذف می‌شوند و تا پر شدن دوباره کش، سرور اصلی بار بیشتری دریافت می‌کند. اگر فقط چند فایل تغییر کرده، پاکسازی آدرس‌ها بهتر است.') })
        .then(function (ok) {
          if (!ok) return;
          P.busy(all, P.api('POST', 'purge', { everything: true })).then(function (res) {
            P.toast(res.ok ? t('پاک‌سازی کل کش ثبت شد.') : P.errorText(res), res.ok ? 'success' : 'error');
          });
        });
    } });
    append(c.body, [
      P.field(t('آدرس‌ها (هر آدرس در یک خط، حداکثر ۱۰۰)'), h('textarea', { className: 'pcdn-input pcdn-mono pcdn-purge-urls-input', dir: 'ltr', rows: 3, spellcheck: 'false',
        placeholder: 'https://' + domain() + '/css/style.css', oninput: function (e) { st.urls = e.target.value; } }),
      { help: h('span', null, t('نکته: به جای پاکسازی، می‌توانید نسخه را به آدرس فایل اضافه کنید ('), ltr('style.css?v=2'), '). ', A().tutLink('cache', t('آموزش کش'))) }),
      h('div', { className: 'pcdn-row-actions' }, one),
      h('div', { className: 'pcdn-purge-sep' }),
      P.field(t('پیشوندهای مسیر (هر پیشوند در یک خط، حداکثر ۲۰)'), h('textarea', { className: 'pcdn-input pcdn-mono pcdn-purge-prefixes-input', dir: 'ltr', rows: 2, spellcheck: 'false',
        placeholder: '/blog/', oninput: function (e) { st.prefixes = e.target.value; } }),
      { help: h('span', null, t('پاک‌سازی بر اساس پیشوند همه فایل‌های کش‌شده‌ای را که مسیرشان با پیشوند شروع می‌شود حذف می‌کند؛ مثلاً '), ltr('/blog/'), t(' کل کش زیر آن مسیر را پاک می‌کند.')) }),
      h('div', { className: 'pcdn-row-actions' }, pfx),
      h('div', { className: 'pcdn-purge-sep' }),
      P.field(t('پاک‌سازی کل کش'), h('p', { className: 'pcdn-muted pcdn-purge-all-help', text: t('همه فایل‌های کش‌شده این دامنه یک‌جا حذف می‌شوند. فقط وقتی لازم است که تغییرات گسترده باشد.') })),
      h('div', { className: 'pcdn-row-actions' }, all)]);
    return c;
  }

  // ------------------------------------------------------------------ page rules

  var CACHE_MODES = [[null, t('طبق تنظیمات کلی')], ['bypass', t('بدون کش')], ['standard', t('استاندارد')], ['everything', t('کش همه‌چیز')]];
  function prSentence(r) {
    var out = [word(t('برای آدرس‌های')), h('bdi', { className: 'pcdn-vchip', dir: 'ltr', text: r.pattern || '/' }), word(P.arrow, 'pcdn-arrow')];
    if (r.redirect) {
      out.push(word(t('ریدایرکت ') + (r.redirect.code === 302 ? t('موقت (۳۰۲)') : t('دائمی (۳۰۱)')) + t(' به')), h('bdi', { className: 'pcdn-vchip', dir: 'ltr', text: r.redirect.url || '' }));
      return out;
    }
    var parts = [];
    if (r.cache) parts.push({ bypass: t('بدون کش'), standard: t('کش استاندارد'), everything: t('کش همه‌چیز') }[r.cache]);
    if (r.edge_ttl !== null && r.edge_ttl !== undefined) parts.push(t('کش CDN ') + P.dur(r.edge_ttl));
    if (r.browser_ttl !== null && r.browser_ttl !== undefined) parts.push(t('کش مرورگر ') + P.dur(r.browser_ttl));
    if (r.ignore_query === true) parts.push(t('بدون Query String در کلید کش'));
    if (r.ignore_query === false) parts.push(t('Query String در کلید کش'));
    if (r.waf === false) parts.push(t('WAF خاموش'));
    if (Array.isArray(r.preload) && r.preload.length) parts.push(t('پیش‌بارگذاری ') + num(r.preload.length) + t(' منبع'));
    out.push(word(parts.length ? parts.join(t('، ')) : t('بدون تغییر (طبق تنظیمات کلی)'), 'pcdn-w pcdn-w-strong'));
    return out;
  }

  // Preload / Early Hints (SPEC §14.1): page-rule field preload: [{url, as}] (≤10).
  var PRELOAD_AS = [['style', t('استایل (style)')], ['script', t('اسکریپت (script)')], ['font', t('فونت (font)')], ['image', t('تصویر (image)')], ['fetch', t('داده (fetch)')]];
  var MAX_PRELOAD = 10;
  function preloadEditor(x, redraw) {
    if (!Array.isArray(x.preload)) x.preload = [];
    var full = x.preload.length >= MAX_PRELOAD;
    return h('fieldset', { className: 'pcdn-fieldset pcdn-preload' }, h('legend', { text: t('Preload (پیش‌بارگذاری منابع)') }),
      h('p', { className: 'pcdn-help' }, t('مرورگر این فایل‌ها را هم‌زمان با HTML و زودتر از معمول دریافت می‌کند (هدر '), ltr('Link: rel=preload'),
        t('). روی نودهایی که Early Hints را پشتیبانی می‌کنند، همین فهرست با پاسخ '), ltr('103'), t(' حتی پیش از آماده شدن صفحه فرستاده می‌شود. فقط منابع مهم بالای صفحه (مثل CSS اصلی یا فونت) را اضافه کنید؛ آدرس، مسیری مثل '),
        ltr('/app.css'), t(' یا آدرس کامل '), ltr('https://'), t(' است.')),
      x.preload.length ? h('div', { className: 'pcdn-rows' }, x.preload.map(function (p, i) {
        if (!PRELOAD_AS.some(function (a) { return a[0] === p.as; })) p.as = 'style';
        return h('div', { className: 'pcdn-plrow', 'data-preload': String(i) },
          P.input(p, 'url', null, { placeholder: '/assets/main.css', aria: t('آدرس منبع ') + num(i + 1), maxlength: 2048 }),
          P.select(p, 'as', null, PRELOAD_AS, { aria: t('نوع منبع ') + num(i + 1) }),
          P.iconBtn('trash', t('حذف منبع ') + num(i + 1), function () { x.preload.splice(i, 1); redraw(); }, { write: true, cls: 'is-danger' }));
      })) : null,
      h('div', { className: 'pcdn-row-actions' },
        P.btn(t('افزودن منبع'), { icon: 'plus', size: 'sm', write: true, cls: 'pcdn-add-preload', disabled: full,
          title: full ? t('حداکثر ') + num(MAX_PRELOAD) + t(' منبع در هر قانون') : null,
          onclick: function () { x.preload.push({ url: '', as: 'style' }); redraw(); } }),
        limitText(x.preload.length, MAX_PRELOAD, t('منبع'))));
  }
  // Same rules as the controller: the URL ends up inside a `Link: <…>` header rendered into nginx config,
  // so only URL characters (no quotes, <>, whitespace/CR/LF, backslash, $ or braces), and either a path
  // starting with a single / or an absolute https:// address.
  var PRELOAD_URL_CHARS = /^[A-Za-z0-9\-._~:/?#[\]@!&()*+,;=%]+$/;
  var PRELOAD_ABS = /^https:\/\/[A-Za-z0-9.-]+(:\d{1,5})?(\/|$)/i;
  /** Client-side mirror of the controller's preload rules; returns a Persian problem or null. */
  function preloadProblem(list) {
    if (!Array.isArray(list)) return null;
    if (list.length > MAX_PRELOAD) return t('حداکثر ') + num(MAX_PRELOAD) + t(' منبع Preload در هر قانون مجاز است.');
    for (var i = 0; i < list.length; i++) {
      var u = String(list[i].url || '').trim(), n = num(i + 1);
      list[i].url = u;
      if (!u) return t('آدرس منبع Preload شماره ') + n + t(' را وارد کنید.');
      if (u.length > 2048) return t('آدرس منبع Preload شماره ') + n + t(' بیش از حد طولانی است (حداکثر ۲۰۴۸ نویسه).');
      if (/["'<>\s]/.test(u)) return t('آدرس منبع Preload شماره ') + n + t(' نباید کوتیشن (" یا \')، علامت‌های < و >، فاصله یا شکست خط داشته باشد.');
      if (!PRELOAD_URL_CHARS.test(u)) return t('آدرس منبع Preload شماره ') + n + t(' نویسهٔ غیرمجاز دارد (مثل \\، $ یا { }).');
      if (u.charAt(0) === '/' ? u.charAt(1) === '/' : !PRELOAD_ABS.test(u)) {
        return t('آدرس منبع Preload شماره ') + n + t(' باید مسیری با / (مثل /app.css) یا آدرس کامل https:// باشد.');
      }
      if (!PRELOAD_AS.some(function (a) { return a[0] === list[i].as; })) return t('نوع منبع Preload شماره ') + n + t(' نامعتبر است.');
    }
    return null;
  }

  function prEditor(r, done) {
    var isNew = !r;
    r = r || { id: P.uid('p'), enabled: true, pattern: '/', cache: null, edge_ttl: null, browser_ttl: null, ignore_query: null, waf: null, redirect: null };
    // Preload is offered only when the controller knows the field (an older one rejects it).
    var withPreload = has(r, 'preload') || perf6a();
    if (isNew && withPreload) r.preload = [];
    var mode = { v: r.redirect ? 'redirect' : 'settings' };
    editDrawer(isNew ? t('قانون صفحه جدید') : t('ویرایش قانون صفحه'), t('برای مسیرهای خاص، رفتار کش یا ریدایرکت را تعیین کنید.'), r, function (x, redraw) {
      return [
        P.input(x, 'pattern', t('الگوی مسیر'), { placeholder: '/wp-admin/*', help: h('span', null, t('با '), ltr('/'), t(' شروع کنید. '), ltr('*'), t(' یعنی هر چیزی (حتی '), ltr('/'), t(')؛ مثلاً '), ltr('/static/*'), t(' همه فایل‌های پوشه static.')) }),
        P.choice(mode, 'v', t('نوع قانون'), [['settings', t('تنظیم کش و امنیت'), t('رفتار کش یا WAF را برای این مسیر تغییر دهید.'), 'zap'], ['redirect', t('ریدایرکت'), t('بازدیدکننده را به آدرس دیگری بفرستید.'), 'arrowLeft']], {
          cols: 2, onchange: function (v) {
            x.redirect = v === 'redirect' ? (x.redirect || { url: 'https://' + domain() + '/', code: 301 }) : null;
            if (v === 'redirect' && Array.isArray(x.preload)) x.preload = [];  // a redirect has no page to preload for
            redraw();
          } }),
        x.redirect ? h('div', { className: 'pcdn-grid' },
          P.input(x.redirect, 'url', t('آدرس مقصد'), { placeholder: 'https://' + domain() + '/new' }),
          P.select(x.redirect, 'code', t('نوع ریدایرکت'), [[301, t('۳۰۱ — دائمی (برای سئو)')], [302, t('۳۰۲ — موقت')]])) : [
          P.select(x, 'cache', t('کش'), CACHE_MODES, { help: t('«کش همه‌چیز» حتی صفحات HTML را کش می‌کند؛ برای صفحات کاربری استفاده نکنید.') }),
          h('div', { className: 'pcdn-grid' },
            P.duration(x, 'edge_ttl', t('مدت کش در CDN'), { min: 0, nullable: true, nullText: t('طبق تنظیمات کلی'), picks: TTL_PICKS }),
            P.duration(x, 'browser_ttl', t('مدت کش در مرورگر'), { min: 0, nullable: true, nullText: t('طبق تنظیمات کلی'), picks: [[0, t('طبق سرور')], [3600, t('۱ ساعت')], [86400, t('۱ روز')]] })),
          P.select(x, 'ignore_query', 'Query String', [[null, t('طبق تنظیمات کلی')], [true, t('نادیده گرفتن در کلید کش')], [false, t('در کلید کش لحاظ شود')]]),
          P.select(x, 'waf', 'WAF', [[null, t('طبق تنظیمات کلی')], [false, t('خاموش در این مسیر')]], { help: t('فقط برای مسیرهایی که مطمئنید (مثلاً وب‌هوک پرداخت) WAF را خاموش کنید.') }),
          withPreload ? preloadEditor(x, redraw) : null],
        P.toggle(x, 'enabled', t('قانون فعال باشد'))
      ];
    }, done, function (x) {
      if (!/^\//.test(x.pattern || '')) return t('الگوی مسیر باید با / شروع شود.');
      if (x.redirect && !/^https?:\/\/\S+$/.test(x.redirect.url || '')) return t('آدرس مقصد ریدایرکت باید با http:// یا https:// شروع شود.');
      return preloadProblem(x.preload);
    }, prSentence);
  }
  function renderPagerules(Aa) {
    var max = Aa.features().max_page_rules || 0;
    var f = Aa.sectionForm('pagerules', function (d, f2) {
      d.rules = d.rules || [];
      var full = d.rules.length >= max ? t('به سقف قوانین صفحه پلن رسیده‌اید') : null;
      function add(r) { r.id = P.uid('p'); r._new = true; d.rules.push(r); }
      return [presets(t('الگوهای آماده'), t('قوانین پرکاربرد را با یک کلیک اضافه کنید؛ سپس بررسی و ذخیره کنید.'), [
        { id: 'wpadmin', title: t('عدم کش پنل مدیریت وردپرس'), icon: 'lock', desc: t('مسیر /wp-admin/* هرگز کش نشود.'), disabled: full,
          apply: function () { add({ enabled: true, pattern: '/wp-admin/*', cache: 'bypass', edge_ttl: null, browser_ttl: null, ignore_query: null, waf: null, redirect: null }); } },
        { id: 'static', title: t('کش طولانی فایل‌های استاتیک'), icon: 'zap', desc: t('همه‌چیز در /static/* به مدت ۳۰ روز در CDN کش شود.'), disabled: full,
          apply: function () { add({ enabled: true, pattern: '/static/*', cache: 'everything', edge_ttl: 2592000, browser_ttl: null, ignore_query: null, waf: null, redirect: null }); } },
        { id: 'redirect', title: t('ریدایرکت مسیر قدیمی'), icon: 'arrowLeft', desc: t('انتقال دائمی (۳۰۱) یک مسیر قدیمی به آدرس جدید؛ آدرس‌ها را ویرایش کنید.'), disabled: full,
          apply: function () { add({ enabled: true, pattern: '/old-page', cache: null, edge_ttl: null, browser_ttl: null, ignore_query: null, waf: null, redirect: { url: 'https://' + domain() + '/new-page', code: 301 } }); } }
      ], d, f2), ruleList(d, f2, {
        title: t('قوانین صفحه'), icon: 'sliders', max: max, what: t('قانون'), addLabel: t('قانون جدید'),
        subtitle: t('اولین قانونی که با آدرس منطبق باشد اعمال می‌شود؛ ترتیب مهم است.'),
        sentence: prSentence, edit: prEditor,
        empty: ['sliders', t('هنوز قانون صفحه‌ای ندارید'), t('با قانون صفحه می‌توانید برای مسیرهای خاص کش را خاموش یا طولانی کنید یا ریدایرکت بسازید.')]
      })];
    }, { serialize: stripNew('rules') });
    return f.el;
  }

  // ------------------------------------------------------------------ image

  function renderImage(Aa) {
    var f = Aa.sectionForm('image', function (d, f2) {
      var c = P.card({ title: t('تغییر اندازه تصویر در لبه'), icon: 'image', id: 'settings' });
      var ex = 'https://' + domain() + '/images/photo.jpg?width=800';
      append(c.body, [
        P.toggle(d, 'enabled', t('بهینه‌سازی تصویر'), { help: t('تصاویر jpg، png، gif و webp با پارامتر width یا height در سرورهای CDN کوچک و کش می‌شوند.'), onchange: f2.redraw }),
        d.enabled ? h('div', { className: 'pcdn-grid' },
          P.input(d, 'quality', t('کیفیت خروجی'), { type: 'number', min: 1, max: 100, suffix: t('از ۱۰۰'), suffixRtl: true, help: t('۸۰ تا ۸۵ تعادل خوبی بین کیفیت و حجم است.') }),
          P.input(d, 'max_width', t('حداکثر عرض'), { type: 'number', min: 1, max: 10000, suffix: t('پیکسل'), suffixRtl: true, help: t('درخواست‌های بزرگ‌تر از این عرض محدود می‌شوند.') })) : null,
        h('div', { className: 'pcdn-howto' }, h('h4', { text: t('نحوه استفاده') }),
          h('p', { text: t('کافی است در آدرس تصویر عرض یا ارتفاع دلخواه را بنویسید:') }),
          P.copyable(ex, { block: true, label: t('کپی نمونه آدرس') }),
          h('p', { className: 'pcdn-muted' }, t('در HTML می‌توانید برای نمایشگرهای مختلف از '), ltr('srcset'), t(' با عرض‌های متفاوت استفاده کنید.')))
      ]);
      // WebP (SPEC §14.1) — independent of resizing; shown only when the controller knows the field.
      var webp = null;
      if (has(d, 'auto_webp')) {
        webp = P.card({ title: t('فرمت WebP'), icon: 'sparkles', id: 'webp' });
        append(webp.body, [
          P.toggle(d, 'auto_webp', t('تبدیل خودکار به WebP'), { cls: 'pcdn-auto-webp',
            help: t('اگر مرورگر بازدیدکننده WebP را پشتیبانی کند، تصاویر JPEG و PNG با فرمت WebP (معمولاً ۲۵ تا ۳۵ درصد کم‌حجم‌تر) تحویل داده می‌شوند و بقیه مرورگرها همان فایل اصلی را می‌گیرند. لازم نیست آدرس تصاویر را تغییر دهید.') }),
          h('p', { className: 'pcdn-help' }, t('روی نودهایی که امکان تبدیل ندارند، کش بر اساس پشتیبانی مرورگر از WebP جدا نگه داشته می‌شود (مانند '), ltr('Vary: Accept'),
            t(')؛ پس اگر سرور اصلی خودش نسخه WebP می‌سازد، به هر مرورگر نسخه درست می‌رسد.'))
        ]);
      }
      // Images v2 (SPEC §16.6, w8.js): AVIF, smart crop, URL transform parameters and signed URLs.
      return [c, webp].concat(P.w8 ? P.w8.imageCards(d, f2) : []);
    }, { serialize: function (x) { return P.w8 ? P.w8.imageSerialize(x) : x; } });
    return f.el;
  }

  // ------------------------------------------------------------------ load balancer pools

  function renderPools(Aa) {
    var max = Aa.features().max_pools || 0;
    var f = Aa.sectionForm('pools', function (d, f2) {
      d.pools = d.pools || [];
      var full = d.pools.length >= max;
      var add = P.btn(t('استخر جدید'), { kind: 'primary', icon: 'plus', size: 'sm', write: true, disabled: full, cls: 'pcdn-add-pool', onclick: function () {
        d.pools.push({ name: 'pool' + (d.pools.length + 1), method: 'weighted', protocol: 'http',
          origins: [{ address: '', port: 80, weight: 10, backup: false }],
          health: { enabled: true, path: '/', interval: 10, timeout: 3, expect: '2xx,3xx', host: null } });
        f2.redraw();
      } });
      var head = P.card({ title: t('استخرهای سرور اصلی'), icon: 'lb', id: 'pools', actions: [limitText(d.pools.length, max, t('استخر')), add],
        subtitle: t('پس از ذخیره، در «رکوردها» برای رکورد پروکسی‌شده استخر را انتخاب کنید.') });
      if (!d.pools.length) {
        head.body.appendChild(P.empty('lb', t('هنوز استخری نساخته‌اید'), t('با استخر، ترافیک بین چند سرور اصلی تقسیم می‌شود و اگر یکی از کار بیفتد سایت قطع نمی‌شود.')));
        return head;
      }
      var cards = d.pools.map(function (p, i) {
        p.origins = p.origins || [];
        p.health = p.health || { enabled: false, path: '/', interval: 10, timeout: 3, expect: '2xx,3xx', host: null };
        var c = P.card({ title: t('استخر ') + num(i + 1), icon: 'lb', tone: 'muted', cls: 'pcdn-pool', id: 'pool-' + i,
          actions: P.iconBtn('trash', t('حذف استخر ') + (p.name || num(i + 1)), function () { d.pools.splice(i, 1); f2.redraw(); }, { write: true, cls: 'is-danger' }) });
        var origins = h('div', { className: 'pcdn-origins' },
          h('div', { className: 'pcdn-origin pcdn-origin-head', 'aria-hidden': 'true' }, [t('آدرس سرور'), t('پورت'), t('وزن'), t('پشتیبان'), ''].map(function (tx) { return h('span', { text: tx }); })),
          p.origins.map(function (o, j) {
            var row = h('div', { className: 'pcdn-origin' },
              P.input(o, 'address', null, { placeholder: '185.1.2.3', aria: t('آدرس سرور ') + num(j + 1) }),
              P.input(o, 'port', null, { type: 'number', min: 1, max: 65535, aria: t('پورت سرور ') + num(j + 1) }),
              P.input(o, 'weight', null, { type: 'number', min: 1, max: 100, aria: t('وزن سرور ') + num(j + 1) }),
              h('label', { className: 'pcdn-inline' }, P.switchInput(o.backup, t('سرور ') + num(j + 1) + t(' پشتیبان است'), function (v) { o.backup = v; }, { small: true }), h('span', { className: 'pcdn-only-narrow-inline', text: t('پشتیبان') })),
              P.iconBtn('x', t('حذف سرور ') + num(j + 1), function () { p.origins.splice(j, 1); f2.redraw(); }, { write: true }));
            P.reg(P.pathOf(o), row);
            return row;
          }),
          P.btn(t('افزودن سرور'), { icon: 'plus', size: 'sm', write: true, onclick: function () { p.origins.push({ address: '', port: p.protocol === 'https' ? 443 : 80, weight: 10, backup: false }); f2.redraw(); } }));
        append(c.body, [
          h('div', { className: 'pcdn-grid pcdn-grid-3' },
            P.input(p, 'name', t('نام استخر'), { placeholder: 'main', help: t('حروف کوچک لاتین، عدد، - و _') }),
            P.select(p, 'method', t('روش تقسیم'), [['weighted', t('وزنی (تصادفی)')], ['ip_hash', t('چسبنده (هر IP یک سرور)')]]),
            P.select(p, 'protocol', t('پروتکل اتصال'), [['http', 'HTTP'], ['https', 'HTTPS']])),
          h('h4', { className: 'pcdn-subhead', text: t('سرورها') }), origins,
          h('div', { className: 'pcdn-subpanel' },
            P.toggle(p.health, 'enabled', t('بررسی سلامت'), { help: t('سرورهایی که پاسخ درست نمی‌دهند موقتاً کنار گذاشته می‌شوند.'), onchange: f2.redraw }),
            p.health.enabled ? h('div', { className: 'pcdn-grid pcdn-grid-3' },
              P.input(p.health, 'path', t('مسیر بررسی'), { placeholder: '/' }),
              P.input(p.health, 'interval', t('هر چند ثانیه'), { type: 'number', min: 5, suffix: t('ثانیه'), suffixRtl: true }),
              P.input(p.health, 'timeout', t('مهلت پاسخ'), { type: 'number', min: 1, suffix: t('ثانیه'), suffixRtl: true }),
              P.input(p.health, 'expect', t('کدهای سالم'), { placeholder: '2xx,3xx' }),
              P.input(p.health, 'host', t('هدر Host (اختیاری)'), { nullable: true, placeholder: domain() })) : null)]);
        return c;
      });
      return [head, cards];
    });
    return f.el;
  }

  // ------------------------------------------------------------------ firewall

  var FW_FIELDS = [['country', t('کشور')], ['ip', t('آی‌پی / CIDR')], ['path', t('مسیر')], ['user_agent', 'User-Agent'], ['method', t('متد')], ['query', 'Query String'],
    ['host', t('هاست')], ['referer', 'Referer'], ['header', t('هدر')]];
  var LIST_OPS = [['in', t('یکی از')], ['not_in', t('هیچ‌کدام از')]];
  var STR_OPS = [['eq', t('برابر')], ['ne', t('نابرابر')], ['contains', t('شامل')], ['not_contains', t('شامل نباشد')], ['starts_with', t('شروع با')],
    ['ends_with', t('پایان با')], ['regex', t('عبارت منظم (regex)')], ['in', t('یکی از')], ['not_in', t('هیچ‌کدام از')]];
  // Sentence pieces around the value ({0}); the word order differs per language.
  var OP_WORDS = {
    in: t('یکی از {0} باشد'), not_in: t('هیچ‌کدام از {0} نباشد'), eq: t('برابر {0} باشد'), ne: t('برابر {0} نباشد'), contains: t('شامل {0} باشد'),
    not_contains: t('شامل {0} نباشد'), starts_with: t('با {0} شروع شود'), ends_with: t('با {0} تمام شود'), regex: t('با الگوی {0} منطبق باشد')
  };
  var FW_ACTIONS = [
    ['block', t('مسدود'), t('خطای ۴۰۳ نمایش داده می‌شود.'), 'ban'],
    ['challenge', t('چالش JS'), t('مرورگرهای واقعی خودکار عبور می‌کنند؛ ربات‌های ساده نه.'), 'shieldBolt'],
    ['captcha', t('کپچا'), t('بازدیدکننده باید کپچا حل کند.'), 'shieldCheck'],
    ['allow', t('اجازه'), t('بدون WAF، DDoS و محدودیت نرخ عبور می‌کند. فقط برای آی‌پی‌های مطمئن.'), 'checkCircle'],
    ['log', t('فقط ثبت'), t('رویداد ثبت می‌شود و بررسی ادامه می‌یابد.'), 'eye']
  ];
  var ACTION_WORDS = { block: t('مسدود شود'), challenge: t('چالش JS نمایش داده شود'), captcha: t('کپچا نمایش داده شود'), allow: t('اجازه عبور بدون بررسی‌های امنیتی'), log: t('فقط ثبت شود') };
  var ACTION_TONE = { block: 'danger', challenge: 'warning', captcha: 'warning', allow: 'success', log: 'muted' };
  function fieldLabel(fl) { for (var i = 0; i < FW_FIELDS.length; i++) if (FW_FIELDS[i][0] === fl) return FW_FIELDS[i][1]; return fl; }
  function opsFor(fl) { return fl === 'ip' || fl === 'country' ? LIST_OPS : STR_OPS; }
  function isList(op) { return op === 'in' || op === 'not_in'; }

  function fwSentence(r) {
    var out = [word(t('اگر'))];
    (r.conditions || []).forEach(function (c, i) {
      if (i) out.push(word(t('و'), 'pcdn-w pcdn-w-and'));
      var ow = (OP_WORDS[c.op] || c.op + ' {0}').split('{0}').map(function (x) { return x.trim(); });
      out.push(word(fieldLabel(c.field) + (c.field === 'header' && c.name ? ' ' : ''), 'pcdn-w pcdn-w-strong'));
      if (c.field === 'header' && c.name) out.push(h('bdi', { className: 'pcdn-vchip is-key', dir: 'ltr', text: c.name }));
      out.push(word(ow[0]));
      var empty = c.value === '' || c.value === null || c.value === undefined || (Array.isArray(c.value) && !c.value.length);
      out.push(empty ? word(t('(خالی)'), 'pcdn-w pcdn-w-bad') : chipsOf(c.value, { country: c.field === 'country' }));
      if (ow[1]) out.push(word(ow[1]));
    });
    if (!(r.conditions || []).length) out.push(word(t('(بدون شرط — همه درخواست‌ها)'), 'pcdn-w pcdn-w-bad'));
    out.push(word(P.arrow, 'pcdn-arrow'));
    out.push(h('span', { className: 'pcdn-act pcdn-tone-' + (ACTION_TONE[r.action] || 'muted'), text: ACTION_WORDS[r.action] || r.action }));
    return out;
  }

  var VALUE_HINT = {
    country: ['IR, CN, RU', t('کد دوحرفی کشور (ISO)؛ مثلاً IR برای ایران.')],
    ip: ['1.2.3.4, 10.0.0.0/8', t('آی‌پی یا بازه CIDR.')],
    path: ['/wp-login.php', t('مسیر آدرس بدون دامنه؛ با / شروع می‌شود.')],
    user_agent: ['sqlmap', t('نام مرورگر یا ابزار؛ بزرگی و کوچکی حروف مهم نیست.')],
    method: ['POST', t('GET، POST، PUT و ...')],
    query: ['id=', t('بخش بعد از ؟ در آدرس.')],
    host: [null, t('نام کامل میزبان، مثلاً www.') ],
    referer: ['bad-site.com', t('آدرس صفحه‌ای که کاربر از آن آمده.')],
    header: ['value', t('مقدار هدر.')]
  };
  function conditionRow(c, conds, j, redraw) {
    var ops = opsFor(c.field);
    if (!ops.some(function (o) { return o[0] === c.op; })) c.op = ops[0][0];
    if (isList(c.op) && !Array.isArray(c.value)) c.value = c.value ? String(c.value).split(/\s*,\s*/).filter(Boolean) : [];
    if (!isList(c.op) && Array.isArray(c.value)) c.value = c.value.join(',');
    var hint = VALUE_HINT[c.field] || ['', ''];
    var val = isList(c.op)
      ? P.tags(c, 'value', null, { upper: c.field === 'country', placeholder: hint[0] || '', aria: t('مقدار شرط ') + num(j + 1) })
      : P.input(c, 'value', null, { placeholder: c.field === 'host' ? 'www.' + domain() : hint[0], aria: t('مقدار شرط ') + num(j + 1) });
    return h('div', { className: 'pcdn-cond', 'data-cond': j },
      h('div', { className: 'pcdn-cond-head' }, h('span', { className: 'pcdn-cond-no', text: j ? t('و') : t('اگر') }),
        P.select(c, 'field', null, FW_FIELDS, { aria: t('فیلد شرط ') + num(j + 1), onchange: function () { if (c.field !== 'header') delete c.name; else c.name = c.name || ''; redraw(); } }),
        c.field === 'header' ? P.input(c, 'name', null, { placeholder: 'X-Header', aria: t('نام هدر') }) : null,
        P.select(c, 'op', null, ops, { aria: t('عملگر شرط ') + num(j + 1), onchange: redraw }),
        P.iconBtn('trash', t('حذف شرط ') + num(j + 1), function () { conds.splice(j, 1); redraw(); }, { write: true, disabled: conds.length < 2 })),
      val, h('div', { className: 'pcdn-help', text: hint[1] + (isList(c.op) ? t(' چند مقدار را با Enter جدا کنید.') : c.op === 'regex' ? t(' مثال: (sqlmap|nikto)') : '') }));
  }
  function fwEditor(r, done) {
    var isNew = !r;
    r = r || { id: P.uid('r'), name: '', enabled: true, action: 'block', conditions: [{ field: 'country', op: 'in', value: [] }] };
    editDrawer(isNew ? t('قانون فایروال جدید') : t('ویرایش قانون فایروال'), t('اگر همه شرط‌ها برقرار باشند، اقدام انتخاب‌شده اجرا می‌شود.'), r, function (x, redraw) {
      x.conditions = x.conditions || [];
      return [
        P.input(x, 'name', t('نام قانون'), { ltr: false, placeholder: t('مثلاً: محافظت از صفحه ورود'), maxlength: 100 }),
        h('fieldset', { className: 'pcdn-fieldset' }, h('legend', { text: t('شرط‌ها (همه باید برقرار باشند)') }),
          x.conditions.map(function (c, j) { return conditionRow(c, x.conditions, j, redraw); }),
          P.btn(t('افزودن شرط'), { icon: 'plus', size: 'sm', write: true, onclick: function () { x.conditions.push({ field: 'path', op: 'starts_with', value: '' }); redraw(); } })),
        P.choice(x, 'action', t('اقدام'), FW_ACTIONS, { cols: 2, onchange: redraw }),
        x.action === 'allow' ? P.alertBox('warning', t('درخواست‌های منطبق از WAF، حفاظت DDoS و محدودیت نرخ عبور می‌کنند. فقط برای آی‌پی‌های مطمئن (مثل دفتر خودتان) استفاده کنید.')) : null,
        P.toggle(x, 'enabled', t('قانون فعال باشد'))
      ];
    }, done, function (x) {
      if (!x.conditions.length) return t('حداقل یک شرط لازم است.');
      for (var i = 0; i < x.conditions.length; i++) {
        var v = x.conditions[i].value;
        if (v === '' || v === null || v === undefined || (Array.isArray(v) && !v.length)) return t('مقدار شرط ') + num(i + 1) + t(' را وارد کنید.');
        if (x.conditions[i].field === 'header' && !x.conditions[i].name) return t('نام هدر در شرط ') + num(i + 1) + t(' را وارد کنید.');
      }
      return null;
    }, fwSentence);
  }

  var BAD_BOTS = '(sqlmap|nikto|masscan|zgrab|nmap|wpscan|acunetix|nessus|dirbuster|gobuster|nuclei)';
  function fwPresets(d, max) {
    var full = d.rules.length >= max ? t('به سقف قوانین فایروال پلن رسیده‌اید') : null;
    function add(name, action, conds) { d.rules.push({ id: P.uid('r'), name: name, enabled: true, action: action, conditions: conds, _new: true }); }
    return [
      { id: 'iran', title: t('فقط بازدید از ایران'), icon: 'globe', desc: t('بازدیدکنندگان خارج از ایران چالش JS می‌بینند (کاربران واقعی عبور می‌کنند).'), disabled: full,
        apply: function () { add(t('فقط بازدید از ایران'), 'challenge', [{ field: 'country', op: 'not_in', value: ['IR'] }]); } },
      { id: 'wplogin', title: t('محافظت از صفحه ورود وردپرس'), icon: 'lock', desc: t('برای ‎/wp-login.php کپچا نمایش داده می‌شود.'), disabled: full,
        apply: function () { add(t('محافظت از ورود وردپرس'), 'captcha', [{ field: 'path', op: 'starts_with', value: '/wp-login.php' }]); } },
      { id: 'badbots', title: t('مسدود کردن ربات‌های مخرب'), icon: 'ban', desc: t('ابزارهای اسکن مثل sqlmap، nikto، masscan و zgrab مسدود می‌شوند.'), disabled: full,
        apply: function () { add(t('مسدود کردن ربات‌های مخرب'), 'block', [{ field: 'user_agent', op: 'regex', value: BAD_BOTS }]); } },
      { id: 'xmlrpc', title: t('مسدود کردن xmlrpc.php'), icon: 'shield', desc: t('فایل xmlrpc.php وردپرس هدف رایج حملات است و اغلب سایت‌ها به آن نیاز ندارند.'), disabled: full,
        apply: function () { add(t('مسدود کردن xmlrpc.php'), 'block', [{ field: 'path', op: 'eq', value: '/xmlrpc.php' }]); } }
    ];
  }
  function renderFirewall(Aa) {
    var max = Aa.features().max_firewall_rules || 0;
    var f = Aa.sectionForm('firewall', function (d, f2) {
      d.rules = d.rules || [];
      var def = P.card({ title: t('اقدام پیش‌فرض'), icon: 'wall', tone: 'muted', id: 'default' });
      def.body.appendChild(P.choice(d, 'default_action', null, [
        ['allow', t('اجازه'), t('درخواست‌هایی که با هیچ قانونی منطبق نیستند عبور می‌کنند (پیشنهادی).'), 'checkCircle'],
        ['block', t('مسدود'), t('فقط درخواست‌هایی که قانون «اجازه» دارند عبور می‌کنند. با احتیاط!'), 'ban']
      ], { cols: 2 }));
      return [
        presets(t('الگوهای آماده'), t('قوانین پرکاربرد را با یک کلیک اضافه کنید؛ سپس بررسی و «ذخیره» کنید.'), fwPresets(d, max), d, f2),
        ruleList(d, f2, {
          title: t('قوانین فایروال'), icon: 'wall', max: max, what: t('قانون'), addLabel: t('قانون جدید'),
          subtitle: t('قوانین از بالا به پایین بررسی می‌شوند و اولین قانون منطبق اجرا می‌شود.'),
          label: function (r) { return h('span', { text: r.name || t('بدون نام') }); },
          sentence: fwSentence, edit: fwEditor,
          empty: ['wall', t('هنوز قانونی ندارید'), t('با قوانین فایروال می‌توانید کشورها، آی‌پی‌ها، ربات‌ها یا مسیرهای خاص را مسدود کنید یا چالش بگذارید. از الگوهای آماده بالا شروع کنید.')]
        }),
        def];
    }, { serialize: stripNew('rules') });
    return f.el;
  }

  // ------------------------------------------------------------------ WAF

  var WAF_GROUPS = [['sqli', 'SQL Injection'], ['xss', 'XSS'], ['lfi', t('LFI / پیمایش مسیر')], ['rce', t('اجرای فرمان (RCE)')],
    ['php', t('حملات PHP')], ['scanner', t('اسکنرها و ربات‌های مخرب')], ['protocol', t('نقض پروتکل HTTP')]];
  var ALL_GROUPS = WAF_GROUPS.map(function (g) { return g[0]; });
  var WAF_LEVELS = [
    { id: 'basic', title: t('پایه'), icon: 'shield', desc: t('فقط حملات اصلی (SQLi، XSS، LFI، RCE) با کمترین احتمال خطا.'), v: { mode: 'block', paranoia: 1, groups: ['sqli', 'xss', 'lfi', 'rce'] } },
    { id: 'recommended', title: t('پیشنهادی'), icon: 'shieldCheck', desc: t('همه گروه‌ها با حساسیت ۱؛ مناسب اغلب سایت‌ها و فروشگاه‌ها.'), v: { mode: 'block', paranoia: 1, groups: ALL_GROUPS } },
    { id: 'strict', title: t('سخت‌گیرانه'), icon: 'shieldBolt', desc: t('همه گروه‌ها با حساسیت ۲؛ امنیت بیشتر ولی احتمال مسدودسازی اشتباه بالاتر.'), v: { mode: 'block', paranoia: 2, groups: ALL_GROUPS } }
  ];
  function sameSet(a, b) { a = (a || []).slice().sort(); b = (b || []).slice().sort(); return JSON.stringify(a) === JSON.stringify(b); }
  /** Wave 6B (§14.2) hooks from rules.js; absent → the 6A behaviour. */
  function sec6b() { return P.sec6b || {}; }
  function renderWaf(Aa) {
    var f = Aa.sectionForm('waf', function (d, f2) {
      d.groups = d.groups || [];
      d.exclusions = d.exclusions || [];
      var levels = presets(t('سطح حفاظت'), t('یکی از سطح‌ها را انتخاب کنید؛ سپس «ذخیره» را بزنید.'), WAF_LEVELS.map(function (l) {
        return { id: l.id, title: l.title, desc: l.desc, icon: l.icon, done: t('سطح «') + l.title + t('» انتخاب شد؛ برای اعمال «ذخیره» را بزنید.'),
          active: function (x) { return x.mode !== 'off' && x.paranoia === l.v.paranoia && sameSet(x.groups, l.v.groups); },
          apply: function (x) { x.mode = x.mode === 'detect' ? 'detect' : 'block'; x.paranoia = l.v.paranoia; x.groups = l.v.groups.slice(); } };
      }), d, f2);
      var mode = P.card({ title: t('حالت کار'), icon: 'shield', id: 'mode' });
      append(mode.body, [P.choice(d, 'mode', null, [
        ['off', t('خاموش'), t('هیچ درخواستی بررسی نمی‌شود.'), 'power'],
        ['detect', t('فقط ثبت'), t('حملات شناسایی و در رویدادها ثبت می‌شوند ولی مسدود نمی‌شوند. برای شروع و آزمایش.'), 'eye'],
        ['block', t('مسدودسازی'), t('درخواست‌های مخرب با خطای ۴۰۳ مسدود می‌شوند.'), 'shieldCheck', t('پیشنهادی')]
      ], { cols: 3, onchange: f2.redraw }),
      d.mode === 'detect' ? P.alertBox('info', [t('در حالت «فقط ثبت» چیزی مسدود نمی‌شود. چند روز '), Aa.goLink('events', t('رویدادهای امنیتی')), t(' را بررسی کنید و سپس به «مسدودسازی» بروید.')]) : null]);
      var adv = P.collapsible({ title: t('تنظیمات پیشرفته'), subtitle: t('حساسیت، گروه قوانین و استثناها'), icon: 'sliders', tone: 'muted', id: 'advanced',
        open: d.exclusions.length > 0 || P.store('waf-adv') === '1', onOpen: function () { P.store('waf-adv', '1'); } });
      append(adv.body, [
        P.choice(d, 'paranoia', t('سطح حساسیت'), [[1, t('حساسیت ۱'), t('کمترین خطا — پیشنهادی')], [2, t('حساسیت ۲'), t('امضاهای بیشتر')], [3, t('حساسیت ۳'), t('بیشترین پوشش، خطای بیشتر')]], { cols: 3, onchange: f2.redraw }),
        P.checks(d, 'groups', t('گروه قوانین'), WAF_GROUPS, { onchange: f2.redraw }),
        h('fieldset', { className: 'pcdn-fieldset' }, h('legend', { text: t('استثناها (رفع مسدودسازی اشتباه)') }),
          h('p', { className: 'pcdn-help' }, t('شناسه قانون را از '), Aa.goLink('events', t('رویدادهای امنیتی')), t(' بردارید. شناسه ۰ یعنی همه قوانین؛ در مسیر می‌توانید از '), ltr('*'), t(' استفاده کنید.')),
          d.exclusions.length ? h('div', { className: 'pcdn-rows' }, d.exclusions.map(function (x, i) {
            var row = h('div', { className: 'pcdn-xrow' },
              P.input(x, 'rule_id', null, { type: 'number', min: 0, placeholder: '942100', aria: t('شناسه قانون استثنای ') + num(i + 1) }),
              P.input(x, 'path', null, { placeholder: '/wp-admin/*', nullable: true, aria: t('مسیر استثنای ') + num(i + 1) }),
              P.iconBtn('trash', t('حذف استثنای ') + num(i + 1), function () { d.exclusions.splice(i, 1); f2.redraw(); }, { write: true, cls: 'is-danger' }));
            P.reg(P.pathOf(x), row);
            return row;
          })) : null,
          P.btn(t('افزودن استثنا'), { icon: 'plus', size: 'sm', write: true, onclick: function () { d.exclusions.push({ rule_id: 0, path: '' }); adv.setOpen(true); f2.redraw(); } }))]);
      // Managed rule packs (§14.2) — only when the controller's waf section carries `packs`.
      var packs = sec6b().wafPacks ? sec6b().wafPacks(d, f2, Aa) : null;
      return [levels, mode, packs, adv];
    }, { validate: sec6b().validateWaf });
    return f.el;
  }

  // ------------------------------------------------------------------ DDoS

  function renderDdos(Aa) {
    var f = Aa.sectionForm('ddos', function (d, f2) {
      var c = P.card({ title: t('حالت حفاظت'), icon: 'shieldBolt', id: 'mode' });
      append(c.body, [
        d.mode === 'js' ? P.alertBox('warning', t('حالت «زیر حمله» روشن است: همه بازدیدکنندگان پیش از ورود چالش JS می‌بینند. پس از پایان حمله آن را به «خودکار» برگردانید.')) : null,
        P.choice(d, 'mode', null, [
          ['off', t('خاموش'), t('بدون چالش.'), 'power'],
          ['auto', t('خودکار'), t('وقتی درخواست‌ها از آستانه بیشتر شود، بازدیدکنندگان جدید چالش JS می‌بینند.'), 'shieldCheck', t('پیشنهادی')],
          ['js', t('زیر حمله (چالش JS برای همه)'), t('همه بازدیدکنندگان یک چالش چندثانیه‌ای می‌بینند؛ فقط هنگام حمله.'), 'shieldBolt'],
          ['captcha', t('کپچا برای همه'), t('سخت‌ترین حالت؛ همه باید کپچا حل کنند.'), 'lock']
        ], { cols: 2, onchange: f2.redraw }),
        h('div', { className: 'pcdn-grid' },
          d.mode === 'auto' ? P.input(d, 'threshold_rps', t('آستانه حمله'), { type: 'number', min: 1, suffix: t('درخواست در ثانیه'), suffixRtl: true, help: t('در هر سرور CDN و در بازه ۱۰ ثانیه سنجیده می‌شود. برای سایت‌های کوچک ۱۰۰ تا ۲۰۰ مناسب است.') }) : null,
          d.mode !== 'off' ? P.duration(d, 'clearance_ttl', t('اعتبار مجوز عبور'), { min: 60, picks: [[1800, t('۳۰ دقیقه')], [3600, t('۱ ساعت')], [86400, t('۱ روز')]], help: t('بازدیدکننده‌ای که چالش را گذرانده تا این مدت دوباره چالش نمی‌بیند.') }) : null)
      ]);
      return c;
    });
    return f.el;
  }

  // ------------------------------------------------------------------ rate limit

  var METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
  var RL_ACTIONS = { block: t('مسدود (خطای ۴۲۹)'), challenge: t('چالش JS'), captcha: t('کپچا') };
  function rlSentence(r) {
    var out = [word(t('اگر یک آی‌پی بیش از')), word(num(r.requests) + t(' درخواست'), 'pcdn-w pcdn-w-strong')];
    if ((r.methods || []).length) out.push(chipsOf(r.methods));
    out.push(word(t('در ') + P.dur(r.period) + t(' به')), h('bdi', { className: 'pcdn-vchip', dir: 'ltr', text: r.path || '/*' }), word(t('بفرستد')), word(P.arrow, 'pcdn-arrow'));
    out.push(h('span', { className: 'pcdn-act pcdn-tone-' + (r.action === 'block' ? 'danger' : 'warning'), text: r.action === 'block' ? t('مسدود به مدت ') + P.dur(r.block_seconds) : RL_ACTIONS[r.action] || r.action }));
    return out;
  }
  function rlEditor(r, done) {
    var isNew = !r;
    r = r || { id: P.uid('rl'), enabled: true, path: '/*', methods: [], requests: 60, period: 60, action: 'block', block_seconds: 600 };
    editDrawer(isNew ? t('قانون محدودیت نرخ جدید') : t('ویرایش محدودیت نرخ'), t('تعداد درخواست هر آی‌پی روی هر سرور CDN شمرده می‌شود.'), r, function (x, redraw) {
      x.methods = x.methods || [];
      return [
        P.input(x, 'path', t('مسیر'), { placeholder: '/wp-login.php*', help: h('span', null, ltr('*'), t(' یعنی هر چیزی؛ مثلاً '), ltr('/api/*')) }),
        P.checks(x, 'methods', t('متدها (هیچ‌کدام = همه)'), METHODS.map(function (m) { return [m, m]; }), { ltr: true }),
        h('div', { className: 'pcdn-grid' },
          P.input(x, 'requests', t('حداکثر تعداد درخواست'), { type: 'number', min: 1 }),
          P.duration(x, 'period', t('در بازه'), { min: 1, picks: [[10, t('۱۰ ثانیه')], [60, t('۱ دقیقه')], [3600, t('۱ ساعت')]] })),
        P.select(x, 'action', t('اقدام پس از عبور از حد'), [['block', t('مسدود (خطای ۴۲۹)')], ['challenge', t('چالش JS')], ['captcha', t('کپچا')]], { onchange: redraw }),
        x.action === 'block' ? P.duration(x, 'block_seconds', t('مدت مسدودی'), { min: 1, picks: [[60, t('۱ دقیقه')], [600, t('۱۰ دقیقه')], [3600, t('۱ ساعت')]] }) : null,
        P.toggle(x, 'enabled', t('قانون فعال باشد'))
      ];
    }, done, function (x) {
      if (!/^\//.test(x.path || '')) return t('مسیر باید با / شروع شود.');
      if (!(x.requests > 0) || !(x.period > 0)) return t('تعداد درخواست و بازه باید بزرگ‌تر از صفر باشند.');
      return null;
    }, rlSentence);
  }
  function renderRatelimit(Aa) {
    var max = Aa.features().max_ratelimit_rules || 0;
    var f = Aa.sectionForm('ratelimit', function (d, f2) {
      d.rules = d.rules || [];
      var full = d.rules.length >= max ? t('به سقف قوانین محدودیت نرخ پلن رسیده‌اید') : null;
      function add(r) { r._new = true; d.rules.push(r); }
      return [presets(t('الگوهای آماده'), t('قوانین پرکاربرد را با یک کلیک اضافه کنید؛ سپس بررسی و «ذخیره» کنید.'), [
        { id: 'wplogin', title: t('ورود وردپرس: ۱۰ بار در دقیقه'), icon: 'lock', desc: t('بیش از ۱۰ تلاش ورود (POST) در دقیقه از یک آی‌پی، ۱۰ دقیقه مسدود می‌شود.'), disabled: full,
          apply: function () { add({ id: P.uid('rl'), enabled: true, path: '/wp-login.php*', methods: ['POST'], requests: 10, period: 60, action: 'block', block_seconds: 600 }); } },
        { id: 'api', title: t('API عمومی: ۶۰ در دقیقه'), icon: 'code', desc: t('هر آی‌پی حداکثر ۶۰ درخواست در دقیقه به /api/* می‌فرستد.'), disabled: full,
          apply: function () { add({ id: P.uid('rl'), enabled: true, path: '/api/*', methods: [], requests: 60, period: 60, action: 'block', block_seconds: 300 }); } }
      ], d, f2), ruleList(d, f2, {
        title: t('قوانین محدودیت نرخ'), icon: 'gauge', max: max, what: t('قانون'), addLabel: t('قانون جدید'),
        subtitle: t('برای جلوگیری از حدس رمز عبور، اسکرپینگ و فشار روی API.'),
        sentence: rlSentence, edit: rlEditor,
        empty: ['gauge', t('هنوز محدودیتی تعریف نکرده‌اید'), t('مثلاً تعداد تلاش‌های ورود را محدود کنید تا حمله حدس رمز عبور بی‌اثر شود.')]
      })];
    }, { serialize: stripNew('rules') });
    return f.el;
  }

  // ------------------------------------------------------------------ hotlink

  function renderHotlink(Aa) {
    var f = Aa.sectionForm('hotlink', function (d, f2) {
      d.allowed_referers = d.allowed_referers || [];
      var c = P.card({ title: t('جلوگیری از استفاده غیرمجاز فایل‌ها'), icon: 'link', id: 'settings' });
      var own = [domain(), '*.' + domain()];
      var missing = own.filter(function (x) { return d.allowed_referers.indexOf(x) < 0; });
      append(c.body, [
        P.toggle(d, 'enabled', t('محافظت Hotlink'), { help: t('اگر سایت دیگری مستقیماً تصاویر یا ویدیوهای شما را نمایش دهد، درخواستش مسدود می‌شود و ترافیک شما هدر نمی‌رود.'), onchange: f2.redraw }),
        d.enabled && missing.length ? P.alertBox('warning', [h('span', { text: t('دامنه خودتان در فهرست مجاز نیست؛ ممکن است تصاویر سایت خودتان هم نمایش داده نشوند. ') }),
          P.btn(t('افزودن ') + missing.join(t(' و ')), { size: 'sm', icon: 'plus', write: true, onclick: function () { missing.forEach(function (x) { d.allowed_referers.push(x); }); f2.redraw(); } })]) : null,
        P.tags(d, 'extensions', t('پسوندهای محافظت‌شده'), { lower: true, placeholder: 'jpg', help: t('بدون نقطه؛ مثلاً jpg، png، mp4.') }),
        P.tags(d, 'allowed_referers', t('دامنه‌های مجاز'), { lower: true, placeholder: domain(), help: h('span', null, t('سایت‌هایی که اجازه نمایش فایل‌های شما را دارند. '), ltr('*.example.com'), t(' یعنی همه زیردامنه‌ها. موتورهای جستجو (مثل google.com) را هم می‌توانید اضافه کنید.')), onchange: f2.redraw }),
        P.toggle(d, 'allow_empty', t('اجازه به درخواست‌های بدون Referer'), { help: t('پیشنهادی: روشن. برخی مرورگرها و اپلیکیشن‌ها Referer نمی‌فرستند.') })
      ]);
      return c;
    });
    return f.el;
  }

  // ------------------------------------------------------------------ SSL

  var SSL_LABEL = { active: [t('فعال'), 'success'], pending: [t('در حال صدور'), 'warning'], failed: [t('ناموفق'), 'danger'] };
  function renderSsl(Aa) {
    var s = site(), ssl = s.ssl || {}, plan = s.plan || {}, feat = Aa.features();
    var st = SSL_LABEL[ssl.status] || [t('صادر نشده'), 'muted'];
    var cert = P.card({ title: t('گواهی SSL'), icon: 'certificate', tone: st[1] === 'success' ? 'success' : 'brand', id: 'cert',
      actions: h('span', { className: 'pcdn-pill pcdn-tone-' + st[1] }, h('span', { className: 'pcdn-dot' }), h('span', { text: st[0] })) });
    append(cert.body, h('dl', { className: 'pcdn-dl pcdn-dl-cols' },
      h('div', null, h('dt', { text: t('نوع گواهی') }), h('dd', { text: ssl.source === 'custom' ? t('اختصاصی (بارگذاری‌شده)') : ssl.source === 'letsencrypt' ? t("رایگان (Let's Encrypt)") : '—' })),
      h('div', null, h('dt', { text: t('تاریخ انقضا') }), h('dd', { text: ssl.expires_at ? P.date(ssl.expires_at, { dateStyle: 'long' }) : '—' })),
      h('div', null, h('dt', { text: t('نام‌های پوشش‌داده‌شده') }), h('dd', null, (ssl.names || []).length ? chipsOf(ssl.names) : '—'))));
    if (ssl.status === 'failed' && ssl.error) {
      append(cert.body, [P.alertBox('danger', [t('صدور گواهی ناموفق بود. معمولاً یعنی نیم‌سرورها هنوز کاملاً منتقل نشده‌اند یا رکورد CAA اجازه صدور نمی‌دهد. '), Aa.tutLink('https', t('راهنمای HTTPS'))]),
        h('details', { className: 'pcdn-details' }, h('summary', { text: t('جزئیات فنی خطا') }), h('pre', { className: 'pcdn-pre', dir: 'ltr', text: String(ssl.error).slice(-600) }))]);
    }
    if (!plan.ssl_allowed && ssl.source !== 'custom') {
      cert.body.appendChild(h('p', { className: 'pcdn-muted', text: t('SSL رایگان در این پلن فعال نیست.') }));
    } else if (ssl.source !== 'custom') {
      cert.body.appendChild(h('p', { className: 'pcdn-muted' }, t("گواهی رایگان برای "), ltr(s.domain), t(' و '), ltr('*.' + s.domain), t(' پس از تأیید نیم‌سرورها خودکار صادر و پیش از انقضا تمدید می‌شود.')));
      if (s.ns_verified && ssl.status !== 'pending') {
        var req = P.btn(ssl.status === 'active' ? t('صدور مجدد') : t('درخواست صدور'), { icon: 'refresh', size: 'sm', write: true, cls: 'pcdn-ssl-request', onclick: function () {
          P.busy(req, P.api('POST', 'ssl')).then(function (res) {
            if (!res.ok) { P.toast(P.errorText(res), 'error'); return; }
            Aa.reloadSite().then(function () { Aa.renderMain(); P.toast(t('درخواست صدور گواهی ثبت شد.')); });
          });
        } });
        cert.body.appendChild(h('div', { className: 'pcdn-row-actions' }, req));
      }
    }

    var certOk = ssl.status === 'active';
    var f = Aa.sectionForm('ssl', function (d, f2) {
      d.hsts = d.hsts || { enabled: false, max_age: 31536000, include_subdomains: false, preload: false };
      var c = P.card({ title: t('تنظیمات HTTPS'), icon: 'lock', id: 'settings' });
      append(c.body, [
        P.toggle(d, 'force_https', t('انتقال خودکار HTTP به HTTPS'), { help: certOk ? t('همه بازدیدهای http:// با ریدایرکت ۳۰۱ به https:// منتقل می‌شوند.') : t('تا وقتی گواهی فعال نشود اعمال نمی‌شود.') }),
        // HSTS presets (§14.2): client-side only, they fill the existing ssl.hsts fields.
        sec6b().hstsPresets ? sec6b().hstsPresets(d, f2) : null,
        P.toggle(d.hsts, 'enabled', 'HSTS', { help: t('مرورگرها تا پایان مدت تعیین‌شده فقط با HTTPS به سایت وصل می‌شوند؛ خاموش کردنش فوری اثر نمی‌کند.'), onchange: f2.redraw }),
        d.hsts.enabled ? h('div', { className: 'pcdn-subpanel' },
          P.duration(d.hsts, 'max_age', t('مدت (max-age)'), { min: 0, picks: [[86400, t('۱ روز (آزمایشی)')], [15552000, t('۶ ماه')], [31536000, t('۱ سال')]] }),
          P.toggle(d.hsts, 'include_subdomains', t('شامل همه زیردامنه‌ها'), { help: t('فقط وقتی همه زیردامنه‌ها HTTPS دارند.') }),
          P.toggle(d.hsts, 'preload', 'preload', { onchange: f2.redraw }),
          d.hsts.preload ? P.alertBox('danger', t('preload را فقط وقتی فعال کنید که قصد ثبت دامنه در فهرست preload مرورگرها را دارید. خروج از این فهرست ماه‌ها طول می‌کشد و در این مدت هر زیردامنه بدون HTTPS از دسترس خارج می‌شود.')) : null) : null,
        P.choice(d, 'min_tls', t('حداقل نسخه TLS'), [['1.2', 'TLS 1.2', t('سازگار با تقریباً همه مرورگرها و دستگاه‌ها.'), null, t('پیشنهادی')], ['1.3', 'TLS 1.3', t('امن‌تر، ولی مرورگرها و دستگاه‌های قدیمی وصل نمی‌شوند.')]], { cols: 2 }),
        P.choice(d, 'origin_protocol', t('اتصال CDN به سرور اصلی'), [
          ['http', t('HTTP (پورت ۸۰)'), t('ساده‌ترین حالت؛ سرور اصلی به گواهی نیاز ندارد.')],
          ['https', t('HTTPS (پورت ۴۴۳)'), t('رمزنگاری کامل تا سرور اصلی؛ سرور باید گواهی داشته باشد.'), null, t('امن‌تر')]], { cols: 2, onchange: f2.redraw }),
        d.origin_protocol === 'http' ? P.alertBox('info', [t('اگر سرور اصلی (یا وردپرس) خودش به HTTPS ریدایرکت می‌کند، با این حالت خطای «تعداد ریدایرکت زیاد» می‌گیرید. '), Aa.tutLink('redirectloop', t('رفع حلقه ریدایرکت'))]) : null,
        d.origin_protocol === 'https' ? P.toggle(d, 'origin_verify', t('بررسی اعتبار گواهی سرور اصلی'), { help: t('اگر گواهی سرور اصلی خودامضا یا منقضی باشد، با روشن بودن این گزینه خطای ۵۰۲ می‌گیرید.') }) : null
      ]);
      // HTTP/3 (SPEC §14.1) — shown only when the controller knows the field.
      var h3 = null;
      if (has(d, 'http3')) {
        h3 = P.card({ title: 'HTTP/3', icon: 'rocket', id: 'http3', subtitle: t('نسل جدید پروتکل HTTP روی QUIC') });
        append(h3.body, [
          P.toggle(d, 'http3', 'HTTP/3 (QUIC)', { cls: 'pcdn-http3',
            help: t('روی اینترنت موبایل و شبکه‌های ناپایدار، صفحات سریع‌تر و پایدارتر بارگذاری می‌شوند. مرورگرهایی که پشتیبانی می‌کنند خودکار از آن استفاده می‌کنند و بقیه مثل قبل با HTTP/2 وصل می‌شوند.') }),
          h('p', { className: 'pcdn-help' }, t('فقط روی نودهایی اعمال می‌شود که HTTP/3 را پشتیبانی می‌کنند؛ نیازی به تغییر در سرور اصلی نیست.') +
            (certOk ? '' : t(' تا وقتی گواهی SSL فعال نشود اعمال نمی‌شود.')))
        ]);
      }
      // Authenticated origin pulls (§14.2) — only when the controller knows ssl.origin_client_auth.
      var mtls = sec6b().mtlsCard ? sec6b().mtlsCard(d, f2, Aa) : null;
      return [c, h3, mtls];
    }, { validate: sec6b().validateSsl });

    var custom;
    if (!feat.custom_ssl) {
      custom = P.card({ title: t('گواهی اختصاصی'), icon: 'lock', tone: 'muted', id: 'custom' });
      custom.body.appendChild(h('p', { className: 'pcdn-muted' }, t('بارگذاری گواهی اختصاصی در پلن شما فعال نیست. '), h('a', { className: 'pcdn-link', href: Aa.upgradeUrl, text: t('ارتقای پلن') })));
    } else {
      custom = P.collapsible({ title: t('گواهی اختصاصی'), subtitle: ssl.source === 'custom' ? t('گواهی اختصاصی شما فعال است.') : t('اگر گواهی خریداری‌شده (مثلاً EV یا OV) دارید، اینجا بارگذاری کنید.'),
        icon: 'upload', tone: 'muted', id: 'custom', open: ssl.source === 'custom' });
      var cs = { cert: '', key: '' };
      var errs = h('div');
      var up = P.btn(t('بارگذاری گواهی'), { kind: 'primary', icon: 'upload', write: true, cls: 'pcdn-cert-upload', onclick: function () {
        clear(errs);
        P.busy(up, P.api('PUT', 'ssl/custom', cs)).then(function (res) {
          if (!res.ok) { errs.appendChild(P.errorBox(res, t('بارگذاری گواهی انجام نشد'))); return; }
          Aa.reloadSite().then(function () { Aa.renderMain(); P.toast(t('گواهی اختصاصی فعال شد.')); });
        });
      } });
      var rm = ssl.source === 'custom' ? P.btn(t('حذف گواهی اختصاصی'), { kind: 'danger-soft', icon: 'trash', write: true, onclick: function () {
        P.confirm({ title: t('حذف گواهی اختصاصی'), danger: true, ok: t('حذف گواهی'), body: t("گواهی اختصاصی حذف می‌شود و گواهی رایگان Let's Encrypt دوباره صادر می‌شود. تا صدور گواهی جدید (معمولاً چند دقیقه) ممکن است HTTPS در دسترس نباشد.") })
          .then(function (ok) {
            if (!ok) return;
            P.busy(rm, P.api('DELETE', 'ssl/custom')).then(function (res) {
              if (!res.ok) { P.toast(P.errorText(res), 'error'); return; }
              Aa.reloadSite().then(function () { Aa.renderMain(); P.toast(t('گواهی اختصاصی حذف شد.')); });
            });
          });
      } }) : null;
      append(custom.body, [
        h('p', { className: 'pcdn-muted', text: t('گواهی (به همراه زنجیره میانی) و کلید خصوصی را با فرمت PEM وارد کنید. گواهی باید معتبر، منقضی‌نشده و شامل نام دامنه باشد.') }),
        P.textarea(cs, 'cert', t('گواهی و زنجیره (PEM)'), { rows: 5, placeholder: '-----BEGIN CERTIFICATE-----' }),
        P.textarea(cs, 'key', t('کلید خصوصی (PEM)'), { rows: 5, placeholder: '-----BEGIN PRIVATE KEY-----', help: t('کلید خصوصی فقط برای CDN ارسال می‌شود و جایی نمایش داده نمی‌شود.') }),
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
        P.input(x, 'name', null, { placeholder: 'X-Header', aria: t('نام هدر ') + num(i + 1) }),
        removing ? h('span', { className: 'pcdn-muted pcdn-hrow-note', text: t('این هدر از پاسخ حذف می‌شود') }) : P.input(x, 'value', null, { placeholder: 'value', aria: t('مقدار هدر ') + num(i + 1) }),
        allowRemove ? h('label', { className: 'pcdn-inline' }, P.switchInput(removing, t('حذف هدر ') + (x.name || num(i + 1)) + t(' از پاسخ'), function (v) { x.value = v ? null : ''; f2.redraw(); }, { small: true }), h('span', { text: t('حذف') })) : null,
        P.iconBtn('trash', t('حذف ردیف ') + num(i + 1), function () { d[key].splice(i, 1); f2.redraw(); }, { write: true, cls: 'is-danger' }));
      P.reg(P.pathOf(x), row);
      return row;
    })) : h('p', { className: 'pcdn-muted', text: t('هدری تعریف نشده است.') }),
    d[key].length < 20 ? P.btn(t('افزودن هدر'), { icon: 'plus', size: 'sm', write: true, onclick: function () { d[key].push({ name: '', value: '' }); f2.redraw(); } }) : null];
  }
  function renderHeaders(Aa) {
    var f = Aa.sectionForm('headers', function (d, f2) {
      d.response = d.response || [];
      function has(n) { return d.response.some(function (x) { return String(x.name).toLowerCase() === n.toLowerCase(); }); }
      var sec = [['X-Frame-Options', 'SAMEORIGIN'], ['X-Content-Type-Options', 'nosniff'], ['Referrer-Policy', 'strict-origin-when-cross-origin']];
      var need = sec.filter(function (x) { return !has(x[0]); });
      var p = presets(t('الگوهای آماده'), t('هدرهای پرکاربرد را با یک کلیک اضافه کنید.'), [
        { id: 'security', title: t('هدرهای امنیتی پیشنهادی'), icon: 'shieldCheck', desc: t('X-Frame-Options، X-Content-Type-Options و Referrer-Policy به پاسخ‌ها اضافه می‌شوند.'),
          disabled: need.length ? null : t('این هدرها از قبل اضافه شده‌اند'), apply: function () { need.forEach(function (x) { d.response.push({ name: x[0], value: x[1] }); }); } },
        { id: 'server', title: t('مخفی کردن هدر Server'), icon: 'eye', desc: t('نام و نسخه وب‌سرور اصلی در پاسخ‌ها نمایش داده نمی‌شود.'),
          disabled: has('Server') ? t('از قبل اضافه شده') : null, apply: function () { d.response.push({ name: 'Server', value: null }); } }
      ], d, f2);
      var req = P.card({ title: t('هدرهای درخواست به سرور اصلی'), icon: 'arrowLeft', tone: 'muted', id: 'request', subtitle: t('مثلاً برای شناسایی ترافیک CDN در سرور اصلی.') });
      append(req.body, headerRows(d, 'request', false, f2));
      var res = P.card({ title: t('هدرهای پاسخ به بازدیدکننده'), icon: 'arrowRight', tone: 'muted', id: 'response', subtitle: t('اضافه، بازنویسی یا حذف هدرهای پاسخ.') });
      append(res.body, headerRows(d, 'response', true, f2));
      return [p, req, res, h('p', { className: 'pcdn-help', text: t('نام هدر فقط حروف لاتین، عدد و خط تیره. هدرهای Host، Content-Length و hop-by-hop مجاز نیستند. حداکثر ۲۰ مورد در هر بخش.') })];
    });
    return f.el;
  }

  // ------------------------------------------------------------------ error pages

  var ERR_SAMPLE = t('<!doctype html>\n<html lang="fa" dir="rtl">\n<head><meta charset="utf-8"><title>خطای موقت</title></head>\n<body style="font-family:Tahoma,sans-serif;text-align:center;padding:60px">\n  <h1>سایت موقتاً در دسترس نیست</h1>\n  <p>لطفاً چند دقیقه دیگر دوباره تلاش کنید.</p>\n</body>\n</html>');
  function renderErrorpages(Aa) {
    var f = Aa.sectionForm('errorpages', function (d, f2) {
      function one(key, title, desc) {
        var val = d[key];
        var size = val ? new Blob([val]).size : 0;
        var c = P.card({ title: title, subtitle: desc, icon: 'fileWarn', tone: key === '5xx' ? 'danger' : 'warning', id: 'err-' + key,
          actions: h('span', { className: 'pcdn-pill pcdn-tone-' + (val ? 'success' : 'muted') }, h('span', { className: 'pcdn-dot' }), h('span', { text: val ? t('سفارشی') : t('پیش‌فرض') })) });
        append(c.body, [
          P.textarea(d, key, null, { rows: 8, nullable: true, placeholder: '<html>…</html>' }),
          h('div', { className: 'pcdn-row-actions' },
            h('span', { className: 'pcdn-muted' + (size > 65536 ? ' is-bad' : ''), text: P.bytes(size) + t(' از ۶۴ KB') }),
            P.btn(t('پیش‌نمایش'), { icon: 'eye', size: 'sm', onclick: function () { preview(title, d[key] || ''); } }),
            !val ? P.btn(t('درج نمونه'), { icon: 'sparkles', size: 'sm', write: true, onclick: function () { d[key] = ERR_SAMPLE; f2.redraw(); } }) : null,
            val ? P.btn(t('بازگشت به پیش‌فرض'), { icon: 'refresh', size: 'sm', write: true, onclick: function () { d[key] = null; f2.redraw(); } }) : null)]);
        c.querySelector('textarea').setAttribute('aria-label', title);
        return c;
      }
      return [one('5xx', t('صفحه خطای سرور (5xx)'), t('وقتی سرور اصلی در دسترس نیست یا خطا می‌دهد (۵۰۲، ۵۰۴ و ...).')),
        one('4xx', t('صفحه خطای کاربر (4xx)'), t('برای خطاهایی مثل ۴۰۳ (مسدود) و ۴۲۹ (محدودیت نرخ) که CDN تولید می‌کند.'))];
    });
    return f.el;
  }
  function preview(title, html) {
    var d = P.dialog({ title: t('پیش‌نمایش: ') + title, icon: 'eye', wide: true });
    var fr = h('iframe', { className: 'pcdn-preview-frame', sandbox: '', title: t('پیش‌نمایش صفحه خطا'), referrerpolicy: 'no-referrer' });
    fr.srcdoc = html || t('<p style="font-family:Tahoma;padding:24px">صفحه پیش‌فرض CDN نمایش داده می‌شود.</p>');
    d.body.appendChild(fr);
    d.foot.appendChild(P.btn(t('بستن'), { onclick: function () { d.close(); } }));
    d.focusFirst();
  }

  // ------------------------------------------------------------------ shared with rules.js (Wave 6B pages)

  P.kit = { has: has, editDrawer: editDrawer, ruleList: ruleList, presets: presets, limitText: limitText, chipsOf: chipsOf,
    word: word, stripNew: stripNew, move: move, METHODS: METHODS };

  // ------------------------------------------------------------------ registry

  function def(id, o) { pages[id] = o; }
  def('cache', {
    title: t('کش'), icon: 'zap', heading: t('کش و پاکسازی'),
    desc: t('فایل‌های سایت در سرورهای CDN نگهداری می‌شوند تا سریع‌تر بارگذاری شوند و بار سرور شما کم شود.'),
    guide: { what: t('CDN پاسخ‌های قابل کش (تصاویر، CSS، JS و ...) را نگه می‌دارد و بدون مراجعه به سرور شما تحویل می‌دهد.'),
      when: t('همیشه روشن باشد. بعد از به‌روزرسانی سایت، آدرس فایل‌های تغییرکرده را پاکسازی کنید.'),
      rec: t('سطح استاندارد، مدت کش CDN یک روز، و الگوی مناسب نوع سایت (برای وردپرس/ووکامرس: «فروشگاه اینترنتی»).'),
      mistakes: [t('استفاده از سطح «تهاجمی» برای سایت‌هایی که کاربر واردشده دارند.'), t('فراموش کردن خاموش کردن حالت توسعه.'), t('روشن کردن «نادیده گرفتن Query String» در حالی که فایل‌ها با ‎?v= نسخه‌بندی شده‌اند.'),
        t('روشن کردن «نسخه جدا برای موبایل و دسکتاپ» برای سایت واکنش‌گرا؛ نرخ کش بی‌دلیل نصف می‌شود.')],
      tut: 'cache' },
    render: renderCache
  });
  def('pagerules', {
    title: t('قوانین صفحه'), icon: 'sliders',
    desc: t('برای مسیرهای خاص (مثلاً پنل مدیریت یا فایل‌های استاتیک) رفتار کش، WAF یا ریدایرکت را جداگانه تعیین کنید.'),
    guide: { what: t('هر قانون یک الگوی مسیر دارد؛ اولین قانون منطبق، تنظیمات کلی را برای آن مسیر تغییر می‌دهد.'),
      when: t('وقتی بخشی از سایت باید متفاوت رفتار کند: پنل مدیریت بدون کش، فایل‌های ثابت با کش طولانی، یا ریدایرکت آدرس قدیمی.'),
      rec: t('برای وردپرس: ‎/wp-admin/*‎ بدون کش. قوانین خاص‌تر را بالاتر قرار دهید.'),
      mistakes: [t('قرار دادن قانون کلی (مثل ‎/*‎) بالای قوانین خاص؛ قوانین پایین‌تر هرگز اجرا نمی‌شوند.'), t('«کش همه‌چیز» برای صفحات سبد خرید یا حساب کاربری.')],
      tut: 'cache' },
    upsell: t('با ارتقای پلن می‌توانید برای بخش‌های مختلف سایت کش و ریدایرکت جداگانه تعریف کنید.'),
    lock: function (f) { return !(f.max_page_rules > 0); },
    render: renderPagerules
  });
  def('image', {
    title: t('بهینه‌سازی تصویر'), icon: 'image',
    desc: t('تصاویر را در سرورهای CDN با اندازه مناسب هر صفحه تحویل دهید تا صفحات سبک‌تر و سریع‌تر شوند.'),
    guide: { what: t('با افزودن ‎?width=‎ یا ‎?height=‎ به آدرس تصویر، نسخه کوچک‌شده در CDN ساخته و کش می‌شود.'),
      when: t('وقتی تصاویر بزرگ آپلود می‌کنید ولی در صفحه کوچک نمایش می‌دهید (مثل تصاویر محصول و بندانگشتی‌ها).'),
      rec: t('کیفیت ۸۰ تا ۸۵ و حداکثر عرض ۲۰۰۰ پیکسل.'), mistakes: [t('درخواست عرض‌های بسیار متنوع که کارایی کش را کم می‌کند.')] },
    upsell: t('با ارتقای پلن، تصاویر سایت در لبه تغییر اندازه داده و سبک‌تر تحویل می‌شوند.'),
    lock: function (f) { return !f.image_optimization; },
    render: renderImage
  });
  def('pools', {
    title: t('توزیع بار'), icon: 'lb', heading: t('توزیع بار (Load Balancer)'),
    desc: t('ترافیک را بین چند سرور اصلی تقسیم کنید؛ اگر یکی از کار بیفتد، بقیه جواب می‌دهند.'),
    guide: { what: t('استخر گروهی از سرورهای اصلی است. CDN بر اساس وزن بین آن‌ها تقسیم می‌کند و سرورهای ناسالم را کنار می‌گذارد.'),
      when: t('وقتی بیش از یک سرور دارید یا می‌خواهید سرور پشتیبان برای زمان خرابی داشته باشید.'),
      rec: t('روش وزنی با بررسی سلامت روی مسیری سبک (مثل ‎/health‎) هر ۱۰ ثانیه.'),
      mistakes: [t('ساختن استخر ولی انتخاب نکردن آن در رکورد DNS.'), t('مسیر بررسی سلامتی که به ورود نیاز دارد یا ریدایرکت می‌کند.')], tut: 'loadbalancing' },
    upsell: t('با ارتقای پلن می‌توانید چند سرور اصلی داشته باشید و در زمان خرابی یکی، سایت قطع نشود.'),
    lock: function (f) { return !(f.load_balancer && f.max_pools > 0); },
    render: renderPools
  });
  def('firewall', {
    title: t('فایروال'), icon: 'wall',
    desc: t('بر اساس کشور، آی‌پی، مسیر یا ربات تصمیم بگیرید چه کسی به سایت دسترسی داشته باشد.'),
    guide: { what: t('قوانین فایروال پیش از رسیدن درخواست به سایت اجرا می‌شوند و می‌توانند مسدود کنند، چالش بگذارند یا اجازه دهند.'),
      when: t('برای محافظت از صفحه ورود، محدود کردن کشورها، مسدود کردن آی‌پی‌های مزاحم و ربات‌های اسکنر.'),
      rec: t('از الگوهای آماده شروع کنید؛ به جای «مسدود» برای کشورها از «چالش JS» استفاده کنید تا کاربران واقعی با VPN هم وارد شوند.'),
      mistakes: [t('قانون «اجازه» برای بازه‌های بزرگ آی‌پی (همه بررسی‌های امنیتی را دور می‌زند).'), t('قرار دادن قانون کلی بالای قوانین خاص.'), t('اقدام پیش‌فرض «مسدود» بدون قانون اجازه.')],
      tut: 'firewall' },
    upsell: t('با ارتقای پلن، قوانین فایروال برای کشور، آی‌پی و مسیر در اختیار شماست.'),
    lock: function (f) { return !(f.max_firewall_rules > 0); },
    render: renderFirewall
  });
  def('waf', {
    title: 'WAF', icon: 'shield', heading: t('فایروال برنامه وب (WAF)'),
    desc: t('حملات رایج وب مثل SQL Injection و XSS پیش از رسیدن به سایت شما شناسایی و متوقف می‌شوند.'),
    guide: { what: t('WAF محتوای هر درخواست را با هزاران امضای حمله مقایسه می‌کند.'),
      when: t('برای همه سایت‌ها، مخصوصاً وردپرس، فروشگاه‌ها و سایت‌هایی با فرم.'),
      rec: t('سطح «پیشنهادی» در حالت مسدودسازی. اگر سایت فرم یا API پیچیده دارد، اول چند روز «فقط ثبت».'),
      mistakes: [t('خاموش کردن کل WAF به خاطر یک مسدودسازی اشتباه (به جای ساختن استثنا).'), t('حساسیت ۳ بدون بررسی رویدادها.')], tut: 'waf' },
    upsell: t('با ارتقای پلن، سایت شما در برابر حملات رایج وب (SQLi، XSS و ...) محافظت می‌شود.'),
    lock: function (f) { return !f.waf; },
    render: renderWaf
  });
  def('ddos', {
    title: 'DDoS', icon: 'shieldBolt', heading: t('حفاظت DDoS'),
    desc: t('در زمان حجم غیرعادی درخواست‌ها، بازدیدکنندگان پیش از ورود یک چالش کوتاه می‌بینند تا ربات‌ها متوقف شوند.'),
    guide: { what: t('چالش JS در چند ثانیه و بدون دخالت کاربر، مرورگر واقعی را از ربات تشخیص می‌دهد.'),
      when: t('حالت خودکار همیشه؛ حالت «زیر حمله» فقط در زمان حمله.'),
      rec: t('خودکار با آستانه ۲۰۰ درخواست در ثانیه و اعتبار ۱ ساعت.'),
      mistakes: [t('روشن ماندن طولانی حالت زیر حمله (ربات‌های مفید مثل گوگل هم چالش می‌بینند).'), t('نبستن دسترسی مستقیم به آی‌پی سرور اصلی.')], tut: 'underattack' },
    upsell: t('با ارتقای پلن، در زمان حمله DDoS سایت شما با چالش خودکار محافظت می‌شود.'),
    lock: function (f) { return !f.ddos; },
    render: renderDdos
  });
  def('ratelimit', {
    title: t('محدودیت نرخ'), icon: 'gauge',
    desc: t('تعداد درخواست‌های هر آی‌پی به یک مسیر را محدود کنید تا حدس رمز عبور و فشار روی API بی‌اثر شود.'),
    guide: { what: t('اگر یک آی‌پی در بازه مشخص بیش از حد درخواست بفرستد، مسدود می‌شود یا چالش می‌بیند.'),
      when: t('برای صفحات ورود، فرم‌ها، جستجو و API.'), rec: t('ورود: ۱۰ درخواست POST در دقیقه. API: ۶۰ در دقیقه.'),
      mistakes: [t('محدودیت روی کل سایت (‎/*‎) با عدد کم؛ کاربران عادی هم خطای ۴۲۹ می‌گیرند.')], tut: 'underattack' },
    upsell: t('با ارتقای پلن می‌توانید برای صفحات حساس محدودیت تعداد درخواست بگذارید.'),
    lock: function (f) { return !(f.max_ratelimit_rules > 0); },
    render: renderRatelimit
  });
  def('hotlink', {
    title: 'Hotlink', icon: 'link', heading: t('جلوگیری از Hotlink'),
    desc: t('نگذارید سایت‌های دیگر تصاویر و ویدیوهای شما را مستقیم نمایش دهند و ترافیک شما را مصرف کنند.'),
    guide: { what: t('درخواست فایل‌هایی با پسوندهای انتخابی، اگر از سایتی خارج از فهرست مجاز آمده باشد، مسدود می‌شود.'),
      when: t('وقتی تصاویر یا ویدیوهای شما در سایت‌های دیگر استفاده می‌شوند.'), rec: t('دامنه خودتان و ‎*.دامنه‌تان را مجاز کنید و «بدون Referer» را روشن نگه دارید.'),
      mistakes: [t('اضافه نکردن دامنه خودتان به فهرست مجاز.'), t('خاموش کردن «بدون Referer» که باعث مشکل در برخی اپلیکیشن‌ها می‌شود.')] },
    render: renderHotlink
  });
  def('ssl', {
    title: 'SSL/TLS', icon: 'lock', heading: t('SSL/TLS و HTTPS'),
    desc: t('گواهی امنیتی، انتقال به HTTPS و نحوه اتصال CDN به سرور اصلی را مدیریت کنید.'),
    guide: { what: t('گواهی SSL ارتباط بازدیدکننده با CDN را رمز می‌کند. «اتصال به سرور اصلی» تعیین می‌کند CDN با HTTP یا HTTPS به سرور شما وصل شود.'),
      when: t('بعد از تأیید نیم‌سرورها گواهی خودکار صادر می‌شود؛ سپس HTTPS اجباری را روشن کنید.'),
      rec: t('HTTPS اجباری روشن، TLS 1.2، و اگر سرور اصلی گواهی معتبر دارد اتصال HTTPS.'),
      mistakes: [t('ریدایرکت HTTPS روی سرور اصلی همراه با اتصال HTTP (حلقه ریدایرکت).'), t('فعال کردن preload بدون آمادگی.')], tut: 'https' },
    render: renderSsl
  });
  def('headers', {
    title: t('هدرها'), icon: 'code', heading: t('هدرهای HTTP'),
    desc: t('هدرهای درخواست به سرور اصلی و هدرهای پاسخ به بازدیدکننده را اضافه، بازنویسی یا حذف کنید.'),
    guide: { what: t('هدرها اطلاعات جانبی هر درخواست و پاسخ HTTP هستند (مثلاً سیاست‌های امنیتی مرورگر).'),
      when: t('برای افزودن هدرهای امنیتی، مخفی کردن اطلاعات سرور یا فرستادن یک کلید مخفی به سرور اصلی.'),
      rec: t('هدرهای امنیتی پیشنهادی را اضافه کنید.'), mistakes: [t('X-Frame-Options: DENY وقتی سایت در iframe خودتان نمایش داده می‌شود.')] },
    render: renderHeaders
  });
  def('errorpages', {
    title: t('صفحات خطا'), icon: 'fileWarn', heading: t('صفحات خطای سفارشی'),
    desc: t('به جای صفحه پیش‌فرض، صفحه خطای هم‌رنگ با برند خود را به بازدیدکنندگان نشان دهید.'),
    guide: { what: t('وقتی سرور اصلی در دسترس نیست یا درخواست مسدود می‌شود، این HTML نمایش داده می‌شود.'),
      when: t('اختیاری؛ برای تجربه کاربری بهتر در زمان قطعی.'), rec: t('یک صفحه ساده و سبک (بدون وابستگی به فایل‌های سرور اصلی).'),
      mistakes: [t('لینک دادن به CSS یا تصاویر روی سرور اصلی که در زمان قطعی بارگذاری نمی‌شوند.')], tut: 'troubleshoot' },
    render: renderErrorpages
  });
})();
