/*
 * Pasargad CDN — Wave 8 (SPEC §16.4–§16.7) client-app pages and cards:
 *   - «پروکسی TCP/UDP» (section `l4`, plan features l4_proxy / max_l4_apps): apps list, drawer editor,
 *     connection address (hostname:edge_port), origin firewall guide;
 *   - «تحویل ویدیو» (section `video`): HLS/DASH manifest/segment TTLs and next-segment prefetch;
 *   - image v2 cards for the «بهینه‌سازی تصویر» page (AVIF, smart crop, URL transform parameters,
 *     signed URLs with a one-time transform secret from POST image/transform-secret + signing guide);
 *   - «DNS ثانویه» (section `dns_secondary`): primary elsewhere (AXFR from the customer's primaries,
 *     optional TSIG with a write-only secret) and allow_axfr for the customer's own secondaries;
 *   - record weight / health-check fields for the DNS record dialog (P.w8.recordFields, used by app.js).
 *
 * Feature detection like Waves 6A–7: every page appears only when the controller's site payload carries
 * its section, and every new field only when the returned section/record has the key — an older
 * controller (pydantic extra="forbid") never receives anything it would reject.
 * Secrets (TSIG secret, image transform secret) are never kept in app state, storage or the DOM after
 * the dialog that shows them closes. Data reaches the DOM only through textContent / createElement.
 */
(function () {
  'use strict';
  var P = window.PCDN = window.PCDN || {};
  var pages = P.pages = P.pages || {};
  if (!P.h) return;
  var h = P.h, append = P.append, clear = P.clear, icon = P.icon, ltr = P.ltr, num = P.num, clone = P.clone;

  function A() { return P.app; }
  function site() { return P.app.S.site; }
  function domain() { return site().domain; }
  function has(o, k) { return !!o && typeof o === 'object' && Object.prototype.hasOwnProperty.call(o, k); }
  /** The controller returned this config section. */
  function sectionOf(s, name) { var c = s && s.config && s.config[name]; return !!c && typeof c === 'object' && !Array.isArray(c); }
  /** Plan feature from site.plan.features, or `def` when the plan predates the key. */
  function feat(key, def) { var f = A().features(); var v = f ? f[key] : undefined; return v === undefined || v === null ? def : v; }

  // ------------------------------------------------------------------ shared validators (mirror controller/app/validation.py)

  function ipv4(v) {
    var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(v);
    return !!m && m.slice(1).every(function (x) { return Number(x) <= 255 && (x === '0' || x.charAt(0) !== '0'); });
  }
  function ipv6(v) {
    if (!/^[0-9a-f:.]+$/i.test(v) || v.indexOf(':') < 0 || /:::/.test(v) || (v.match(/::/g) || []).length > 1) return false;
    var parts = v.split(':');
    if (parts.length > 8) return false;
    var tail = parts[parts.length - 1];
    if (tail.indexOf('.') >= 0) { if (!ipv4(tail)) return false; parts.pop(); parts.push('0', '0'); }
    if (parts.length > 8 || (v.indexOf('::') < 0 && parts.length !== 8)) return false;
    return parts.every(function (p, i) { return p === '' ? (i === 0 || i === parts.length - 1 || v.indexOf('::') >= 0) : /^[0-9a-f]{1,4}$/i.test(p); });
  }
  function ip(v) { v = String(v || '').trim(); return ipv4(v) || ipv6(v); }
  /** IP or CIDR (IPv4 /0..32, IPv6 /0..128). */
  function cidr(v) {
    v = String(v || '').trim();
    var m = /^([^/]+)(?:\/(\d{1,3}))?$/.exec(v);
    if (!m) return false;
    if (ipv4(m[1])) return m[2] === undefined || Number(m[2]) <= 32;
    if (ipv6(m[1])) return m[2] === undefined || Number(m[2]) <= 128;
    return false;
  }
  function hostname(v) {
    return /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/i.test(String(v || '').trim());
  }
  /**
   * Not a public address — mirrors Python's ipaddress is_private / is_loopback / is_unspecified / is_multicast /
   * is_link_local / is_reserved that the controller applies (documentation ranges such as 192.0.2.0/24,
   * 198.51.100.0/24, 203.0.113.0/24 and 2001:db8::/32 count as private there too).
   */
  function privateIp(v) {
    v = String(v || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
    if (ipv4(v)) {
      var o = v.split('.').map(Number);
      return o[0] === 0 || o[0] === 10 || o[0] === 127 || o[0] >= 224 || (o[0] === 169 && o[1] === 254) || (o[0] === 172 && o[1] >= 16 && o[1] <= 31)
        || (o[0] === 192 && o[1] === 168) || (o[0] === 192 && o[1] === 0 && (o[2] === 0 || o[2] === 2)) || (o[0] === 198 && (o[1] === 18 || o[1] === 19))
        || (o[0] === 198 && o[1] === 51 && o[2] === 100) || (o[0] === 203 && o[1] === 0 && o[2] === 113);
    }
    if (ipv6(v)) {
      if (v === '::1' || v === '::' || /^(fe[89ab]|f[cd]|ff)/.test(v) || /^::ffff:/.test(v) || /^2001:0?db8:/.test(v) || /^100::?/.test(v) || /^64:ff9b:1:/.test(v)) return true;
      var g = v.split(':');
      return g[0] === '2001' && parseInt(g[1] || '0', 16) < 0x200;
    }
    return false;
  }

  function codeBlock(text, caption) {
    return h('figure', { className: 'pcdn-codeblock' },
      h('figcaption', null, icon('terminal'), h('span', { dir: 'ltr', text: caption }),
        P.copyBtn(text, 'کپی کد ' + caption, { text: 'کپی', cls: 'pcdn-copy-code', done: 'کد کپی شد' })),
      h('pre', { dir: 'ltr', tabindex: '0' }, h('code', { text: text })));
  }
  function dl(rows) {
    return h('dl', { className: 'pcdn-dl' }, rows.filter(Boolean).map(function (r) { return h('div', null, h('dt', { text: r[0] }), h('dd', null, r[1])); }));
  }
  function stripKeys(keys) {
    return function (d) {
      var out = {};
      Object.keys(d || {}).forEach(function (k) { if (keys.indexOf(k) < 0) out[k] = d[k]; });
      return out;
    };
  }

  // ================================================================== §16.4 TCP/UDP proxy («پروکسی TCP/UDP»)

  var L4_RANGE_DEFAULT = [20000, 29999];
  var L4_RESERVED = [22, 53, 80, 443];   // sections.ALWAYS_RESERVED_PORTS (+ the operator's L4_RESERVED_PORTS, checked by the controller)
  /** Allocated port range: the controller may publish it (site.l4_port_range / config.l4.port_range), else the SPEC default. */
  function l4Range() {
    var s = site() || {}, c = (s.config && s.config.l4) || {};
    var r = Array.isArray(s.l4_port_range) ? s.l4_port_range : Array.isArray(c.port_range) ? c.port_range : null;
    if (r && r.length === 2 && Number(r[0]) >= 1024 && Number(r[1]) <= 65535 && Number(r[0]) <= Number(r[1])) return [Number(r[0]), Number(r[1])];
    return L4_RANGE_DEFAULT;
  }
  function l4Max() { var m = feat('max_l4_apps', 0); return typeof m === 'number' && m > 0 ? m : 0; }
  /** Output-only keys of an app (hostname / status from the controller) — never sent back. */
  var L4_OUT = ['hostname', 'status', 'error', '_new'];
  var L4_SECTION_OUT = ['port_range'];
  function l4Clean(a) {
    var o = {};
    Object.keys(a || {}).forEach(function (k) { if (L4_OUT.indexOf(k) < 0) o[k] = a[k]; });
    if (o.protocol === 'udp') o.proxy_protocol = 'off';
    if (o.origin && typeof o.origin === 'object') o.origin = { address: String(o.origin.address || '').trim(), port: o.origin.port };
    o.ip_allow = Array.isArray(o.ip_allow) ? o.ip_allow.map(function (x) { return String(x).trim(); }).filter(Boolean) : [];
    return o;
  }
  function l4Serialize(d) {
    var out = stripKeys(L4_SECTION_OUT)(d);
    out.apps = (d.apps || []).map(l4Clean);
    return out;
  }
  function l4NewId(apps) {
    var used = {};
    apps.forEach(function (a) { used[a.id] = 1; });
    // the app's hostname l4-<id>.<domain> must not clash with an existing record (controller 422)
    (site().records || []).forEach(function (r) { var m = /^l4-(.+)$/.exec(String(r.name || '')); if (m) used[m[1]] = 1; });
    for (var i = 1; i < 1000; i++) if (!used['app' + i]) return 'app' + i;
    return 'app' + Date.now().toString(36);
  }
  function l4FreePort(apps, proto, self) {
    var r = l4Range(), taken = {};
    apps.forEach(function (a) { if (a !== self) taken[Number(a.edge_port)] = 1; });
    for (var tries = 0; tries < 200; tries++) {
      var p = r[0] + Math.floor(Math.random() * (r[1] - r[0] + 1));
      if (!taken[p] && L4_RESERVED.indexOf(p) < 0) return p;
    }
    return r[0];
  }
  /** Problems of one app ([{path, msg}], paths relative to the app). */
  function l4AppProblems(a, apps, self) {
    var out = [], r = l4Range();
    function bad(p, m) { out.push({ path: p, msg: m }); }
    if (a.protocol !== 'tcp' && a.protocol !== 'udp') bad('protocol', 'پروتکل باید TCP یا UDP باشد.');
    var ep = Number(a.edge_port), auto = a.edge_port === null || a.edge_port === '' || a.edge_port === undefined;
    if (!/^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$/.test(String(a.id || ''))) bad('id', 'شناسهٔ برنامه نامعتبر است.');
    if (auto) { /* allocated by the controller on save */ }
    else if (!Number.isInteger(ep)) bad('edge_port', 'پورت روی CDN باید عدد صحیح باشد (یا خالی برای تعیین خودکار).');
    else if (L4_RESERVED.indexOf(ep) >= 0) bad('edge_port', 'پورت ' + P.fa(ep) + ' رزرو شده است (۲۲، ۵۳، ۸۰ و ۴۴۳ هرگز داده نمی‌شوند).');
    else if (ep < 1024 || ep > 65535) bad('edge_port', 'پورت روی CDN باید بین ۱۰۲۴ و ۶۵۵۳۵ باشد.');
    else if (ep < r[0] || ep > r[1]) bad('edge_port', 'پورت روی CDN باید در بازهٔ ' + P.fa(r[0]) + ' تا ' + P.fa(r[1]) + ' باشد (این بازه روی نودها باز است).');
    else if ((apps || []).some(function (x) { return x !== self && x.edge_port !== null && x.edge_port !== undefined && Number(x.edge_port) === ep; })) bad('edge_port', 'این پورت را برنامهٔ دیگری از همین سایت گرفته است.');
    if ((apps || []).some(function (x) { return x !== self && x.id === a.id; })) bad('id', 'شناسهٔ برنامه تکراری است.');
    var o = a.origin || {}, addr = String(o.address || '').trim().replace(/^\[|\]$/g, '');
    if (!addr) bad('origin.address', 'آدرس سرور مقصد را وارد کنید.');
    else if (!ip(addr) && !hostname(addr)) bad('origin.address', 'آدرس سرور باید IPv4، IPv6 یا نام دامنه باشد.');
    else if (privateIp(addr) || /^localhost$/i.test(addr)) bad('origin.address', 'آدرس سرور باید عمومی باشد (نه آی‌پی داخلی یا localhost).');
    var op = Number(o.port);
    if (o.port === null || o.port === '' || o.port === undefined || !Number.isInteger(op) || op < 1 || op > 65535) bad('origin.port', 'پورت سرور مقصد باید بین ۱ و ۶۵۵۳۵ باشد.');
    if (['off', 'v1'].indexOf(a.proxy_protocol) < 0) bad('proxy_protocol', 'PROXY protocol نامعتبر است.');
    else if (a.protocol === 'udp' && a.proxy_protocol !== 'off') bad('proxy_protocol', 'PROXY protocol فقط برای TCP است.');
    (a.ip_allow || []).forEach(function (x) { if (!cidr(x)) bad('ip_allow', 'آدرس یا بازهٔ نامعتبر: ' + x + ' (مثل 203.0.113.7 یا 198.51.100.0/24)'); });
    if ((a.ip_allow || []).length > 100) bad('ip_allow', 'حداکثر ۱۰۰ آدرس یا بازه مجاز است.');
    var it = Number(a.idle_timeout);
    if (!Number.isInteger(it) || it < 10 || it > 3600) bad('idle_timeout', 'مهلت بیکاری باید بین ۱۰ و ۳۶۰۰ ثانیه باشد.');
    return out;
  }
  function l4Problems(d) {
    var out = [];
    (d.apps || []).forEach(function (a, i) {
      l4AppProblems(a, d.apps, a).forEach(function (x) { out.push({ path: 'apps.' + i + '.' + x.path, msg: 'برنامهٔ ' + num(i + 1) + ': ' + x.msg }); });
    });
    var max = l4Max();
    if ((d.apps || []).length > max) out.push({ path: 'apps', msg: 'پلن شما حداکثر ' + num(max) + ' برنامه را مجاز می‌داند.' });
    return out;
  }
  // nginx stream sends PROXY protocol v1 only (sections.L4App: off | v1)
  var PP_OPTS = [['off', 'خاموش'], ['v1', 'روشن (نسخهٔ ۱)']];
  function ppLabel(v) { for (var i = 0; i < PP_OPTS.length; i++) if (PP_OPTS[i][0] === v) return PP_OPTS[i][1]; return String(v || '—'); }
  function l4Host(a) { return a.hostname || 'l4-' + a.id + '.' + domain(); }
  function l4Address(a) { return l4Host(a) + ':' + (a.edge_port === null || a.edge_port === undefined ? '…' : a.edge_port); }
  function l4Ready(a) { return a.edge_port !== null && a.edge_port !== undefined && a.edge_port !== '' && !a._new; }

  function l4Drawer(d, f, idx) {
    var apps = d.apps, orig = idx >= 0 ? apps[idx] : null;
    var draft = orig ? clone(orig) : { id: l4NewId(apps), protocol: 'tcp', edge_port: null, origin: { address: '', port: null },
      proxy_protocol: 'off', ip_allow: [], idle_timeout: 300, enabled: true };
    if (!draft.origin || typeof draft.origin !== 'object') draft.origin = { address: '', port: null };
    if (!Array.isArray(draft.ip_allow)) draft.ip_allow = [];
    var r = l4Range();
    var dlg = P.dialog({ title: orig ? 'ویرایش برنامهٔ TCP/UDP' : 'برنامهٔ TCP/UDP جدید', subtitle: orig ? l4Address(orig) : 'پورتی روی CDN که ترافیک آن به سرور شما می‌رسد.', icon: 'port', kind: 'drawer', wide: true });
    dlg.el.classList.add('pcdn-l4-drawer');
    var err = h('div'), form = h('form', { className: 'pcdn-form', novalidate: true, onsubmit: function (e) { e.preventDefault(); ok(); } });
    var ctx = null;
    function draw() {
      clear(form);
      P.beginForm(draft);
      var portIn = P.input(draft, 'edge_port', 'پورت روی CDN', { type: 'number', min: r[0], max: r[1], nullable: true, placeholder: 'خودکار',
        help: 'کاربران به این پورت روی نشانی CDN وصل می‌شوند. خالی بگذارید تا هنگام ذخیره اولین پورت آزاد داده شود؛ یا پورتی در بازهٔ ' + P.fa(r[0]) + ' تا ' + P.fa(r[1]) + ' بدهید (اگر سرویس دیگری آن را گرفته باشد هنگام ذخیره خبر می‌دهیم).' });
      var pick = h('div', { className: 'pcdn-chips-row' },
        h('button', { type: 'button', className: 'pcdn-chip-btn pcdn-l4-auto', 'data-write': '1', text: 'تعیین خودکار', onclick: function () { draft.edge_port = null; draw(); } }),
        h('button', { type: 'button', className: 'pcdn-chip-btn pcdn-l4-pick', 'data-write': '1', text: 'پورت تصادفی', onclick: function () { draft.edge_port = l4FreePort(apps, draft.protocol, orig); draw(); } }));
      append(form, [
        P.choice(draft, 'protocol', 'پروتکل', [['tcp', 'TCP', 'برای بازی‌های TCP، SSH، پایگاه داده، MQTT، RDP و هر سرویس اتصال‌گرا.', 'link'],
          ['udp', 'UDP', 'برای بازی‌های UDP، DNS، VoIP و پخش زنده؛ PROXY protocol ندارد.', 'zap']], { cols: 2, onchange: function (v) { if (v === 'udp') draft.proxy_protocol = 'off'; draw(); } }),
        h('div', { className: 'pcdn-grid' }, h('div', null, portIn, pick),
          P.input(draft, 'idle_timeout', 'مهلت بیکاری اتصال', { type: 'number', min: 10, max: 3600, suffix: 'ثانیه', suffixRtl: true,
            help: 'اتصالی که این مدت هیچ داده‌ای رد و بدل نکند بسته می‌شود (۱۰ تا ۳۶۰۰؛ پیش‌فرض ۳۰۰).' })),
        h('div', { className: 'pcdn-grid' },
          P.input(draft.origin, 'address', 'آدرس سرور مقصد', { placeholder: '185.1.2.3', maxlength: 253, help: 'آی‌پی عمومی یا نام دامنهٔ سرور شما (نه آی‌پی داخلی).' }),
          P.input(draft.origin, 'port', 'پورت سرور مقصد', { type: 'number', min: 1, max: 65535, nullable: true, placeholder: '25565' })),
        draft.protocol === 'tcp' ? P.select(draft, 'proxy_protocol', 'PROXY protocol', PP_OPTS,
          { help: 'روشن کنید تا سرور شما آی‌پی واقعی کاربر را ببیند (هدر PROXY protocol نسخهٔ ۱)؛ فقط اگر نرم‌افزار سرور آن را پشتیبانی می‌کند و روشن کرده‌اید (وگرنه اتصال‌ها خراب می‌شوند).' })
          : h('p', { className: 'pcdn-help' }, icon('info'), ' در UDP آی‌پی کاربر به سرور شما نمی‌رسد و سرور آی‌پی نودهای CDN را می‌بیند.'),
        P.tags(draft, 'ip_allow', 'فقط این آی‌پی‌ها (اختیاری)', { placeholder: '198.51.100.0/24',
          help: 'خالی = همه می‌توانند وصل شوند. با آی‌پی یا بازهٔ CIDR دسترسی را محدود کنید (مثلاً فقط دفتر شما). با Enter یا کاما اضافه کنید.' }),
        P.toggle(draft, 'enabled', 'فعال', { help: 'برنامهٔ غیرفعال نگه داشته می‌شود ولی پورت آن روی نودها بسته است.' }),
        h('button', { type: 'submit', hidden: true, tabindex: '-1', 'aria-hidden': 'true' })]);
      ctx = P.endForm();
      A().lockWrites(form);
    }
    function ok() {
      clear(err);
      P.clearErrors(form);
      if (draft.edge_port !== null && draft.edge_port !== undefined && draft.edge_port !== '') draft.edge_port = Number(draft.edge_port); else draft.edge_port = null;
      if (orig && Number(orig.edge_port) !== Number(draft.edge_port) && orig.hostname) delete draft.hostname;
      var probs = l4AppProblems(draft, apps, orig);
      if (probs.length) {
        var rest = P.placeErrors(ctx, probs);
        if (rest.length) err.appendChild(P.alertBox('danger', h('ul', { className: 'pcdn-errlist' }, rest.map(function (x) { return h('li', { text: x.msg }); }))));
        var b = form.querySelector('[aria-invalid]');
        if (b) b.focus();
        return;
      }
      dlg.close(true);
      var nw = clone(draft);
      if (orig) { if (orig._new) nw._new = true; apps[idx] = nw; } else { nw._new = true; apps.push(nw); }
      f.redraw();
      P.toast(orig ? 'تغییرات برنامه اعمال شد؛ برای ثبت «ذخیره» را بزنید.' : 'برنامه به فهرست اضافه شد؛ برای ثبت «ذخیره» را بزنید.', 'info');
    }
    var okBtn = P.btn('تأیید', { kind: 'primary', icon: 'check', write: true, cls: 'pcdn-l4-ok', onclick: ok });
    append(dlg.foot, [okBtn, P.btn('انصراف', { onclick: function () { dlg.close(); } })]);
    append(dlg.body, [err, form]);
    draw();
    dlg.focusFirst();
    return dlg;
  }

  function renderL4(Aa) {
    var max = l4Max(), r = l4Range();
    var f = Aa.sectionForm('l4', function (d, f2) {
      d.apps = Array.isArray(d.apps) ? d.apps : [];
      var apps = d.apps, full = apps.length >= max;
      var add = P.btn('برنامهٔ جدید', { kind: 'primary', icon: 'plus', size: 'sm', write: true, cls: 'pcdn-l4-add', disabled: full,
        title: full ? 'به سقف ' + num(max) + ' برنامهٔ پلن رسیده‌اید' : null, onclick: function () { l4Drawer(d, f2, -1); } });
      var c = P.card({ title: 'برنامه‌های TCP/UDP', icon: 'port', id: 'l4-apps', subtitle: 'هر برنامه یک پورت روی CDN است که ترافیک را به سرور شما می‌رساند.',
        actions: [P.kit && P.kit.limitText ? P.kit.limitText(apps.length, max, 'برنامه') : null, add] });
      if (!apps.length) {
        c.body.appendChild(P.empty('port', 'هنوز برنامه‌ای نساخته‌اید', 'برای سرویس‌های غیر وب (سرور بازی، SSH، پایگاه داده، MQTT، VoIP) یک پورت TCP یا UDP روی CDN بسازید تا آی‌پی سرورتان پنهان بماند و ترافیک از نودهای CDN عبور کند.'));
      } else {
        var ul = h('ul', { className: 'pcdn-whs pcdn-l4s' });
        apps.forEach(function (a, i) {
          var on = a.enabled !== false, o = a.origin || {};
          var addr = l4Address(a);
          var li = h('li', { className: 'pcdn-wh pcdn-l4' + (on ? '' : ' is-off') + (a._new ? ' is-new' : ''), 'data-l4': String(a.id || i) },
            h('div', { className: 'pcdn-wh-main' },
              h('div', { className: 'pcdn-wh-urlline' },
                P.badge(String(a.protocol || '').toUpperCase(), a.protocol === 'udp' ? 'violet' : 'brand'),
                l4Ready(a) ? h('span', { className: 'pcdn-l4-addr' }, P.copyable(addr, { label: 'کپی نشانی اتصال ' + addr }))
                  : h('span', { className: 'pcdn-l4-addr' }, h('bdi', { className: 'pcdn-wh-url', dir: 'ltr', text: addr }),
                    h('span', { className: 'pcdn-muted', text: a.edge_port === null || a.edge_port === undefined ? ' — پورت هنگام ذخیره تعیین می‌شود' : ' — پس از ذخیره فعال می‌شود' })),
                on ? null : P.badge('غیرفعال', 'muted'), a._new ? P.badge('ذخیره نشده', 'warning') : null,
                a.status && a.status !== 'active' && a.status !== 'ok' ? P.badge(String(a.status), 'warning') : null),
              h('div', { className: 'pcdn-l4-meta' },
                h('span', null, 'مقصد: ', ltr(String(o.address || '—') + ':' + String(o.port || '—'))),
                a.protocol === 'tcp' && a.proxy_protocol && a.proxy_protocol !== 'off' ? h('span', { text: 'PROXY protocol ' + ppLabel(a.proxy_protocol) }) : null,
                h('span', { text: (a.ip_allow || []).length ? 'محدود به ' + num(a.ip_allow.length) + ' آدرس/بازه' : 'دسترسی برای همه' }),
                h('span', { text: 'مهلت بیکاری ' + P.dur(Number(a.idle_timeout) || 0) })),
              a.error ? h('div', { className: 'pcdn-help pcdn-tone-danger', dir: 'auto', text: String(a.error) }) : null),
            h('div', { className: 'pcdn-wh-ctl' },
              P.switchInput(on, (on ? 'غیرفعال کردن' : 'فعال کردن') + ' برنامهٔ پورت ' + a.edge_port, function (v) { a.enabled = v; f2.redraw(); }, { write: true, small: true }),
              P.iconBtn('edit', 'ویرایش برنامهٔ پورت ' + a.edge_port, function () { l4Drawer(d, f2, i); }, { write: true, cls: 'pcdn-l4-edit' }),
              P.iconBtn('trash', 'حذف برنامهٔ پورت ' + a.edge_port, function () {
                apps.splice(i, 1); f2.redraw(); P.toast('برنامه از فهرست حذف شد؛ برای اعمال «ذخیره» را بزنید.', 'info');
              }, { write: true, cls: 'is-danger pcdn-l4-del' })));
          P.reg('apps.' + i, li);
          ul.appendChild(li);
        });
        c.body.appendChild(ul);
      }
      return [c, l4GuideCard(r)];
    }, { serialize: l4Serialize, validate: l4Problems, savedMsg: 'برنامه‌ها ذخیره شد و تا چند ثانیه روی نودهای CDN باز می‌شوند.' });
    return [f.el, usageCard('l4')];
  }

  /**
   * 30-day traffic of the TCP/UDP apps / of video (analytics totals.l4 / totals.video, SPEC §16.4/§16.5).
   * Hidden when the controller's analytics have no such totals.
   */
  function usageCard(kind) {
    var c = P.card({ title: 'ترافیک ۳۰ روز اخیر', icon: 'chart', tone: 'muted', id: kind + '-usage' });
    c.hidden = true;
    A().ensureAnalytics('30d').then(function (res) {
      var t = res.ok && res.data && res.data.totals;
      if (!t || !document.body.contains(c)) return;
      if (kind === 'l4' && t.l4 && typeof t.l4 === 'object') {
        var apps = t.l4.apps && typeof t.l4.apps === 'object' ? t.l4.apps : {};
        var ids = Object.keys(apps);
        append(c.body, [
          dl([['ورودی (کاربران ← سرور شما)', h('span', { text: P.bytes(t.l4.bytes_in || 0) })], ['خروجی (سرور شما ← کاربران)', h('span', { text: P.bytes(t.l4.bytes_out || 0) })],
            ['نشست‌ها', h('span', { text: num(t.l4.sessions || 0) })]]),
          ids.length ? h('div', { className: 'pcdn-table-wrap' }, h('table', { className: 'pcdn-table pcdn-rtable pcdn-l4-usage' },
            h('caption', { className: 'pcdn-sr', text: 'ترافیک هر برنامه' }),
            h('thead', null, h('tr', null, ['برنامه', 'ورودی', 'خروجی', 'نشست‌ها'].map(function (x) { return h('th', { scope: 'col', text: x }); }))),
            h('tbody', null, ids.map(function (id) {
              var a = apps[id] || {};
              return h('tr', { 'data-l4-usage': id }, h('td', { 'data-label': 'برنامه' }, ltr(id)), h('td', { 'data-label': 'ورودی', text: P.bytes(a.bytes_in || 0) }),
                h('td', { 'data-label': 'خروجی', text: P.bytes(a.bytes_out || 0) }), h('td', { 'data-label': 'نشست‌ها', text: num(a.sessions || 0) }));
            })))) : h('p', { className: 'pcdn-muted', text: 'هنوز ترافیکی از برنامه‌ها ثبت نشده است.' }),
          h('p', { className: 'pcdn-help', text: 'ترافیک هر دو جهت از سهمیهٔ ماهانهٔ همین سرویس کم می‌شود.' })]);
        c.hidden = false;
      } else if (kind === 'video' && t.video && typeof t.video === 'object') {
        var all = Number(t.bytes) || 0, vb = Number(t.video.bytes) || 0;
        append(c.body, [dl([['حجم ویدیو', h('span', { text: P.bytes(vb) })], ['درخواست‌های ویدیو', h('span', { text: num(t.video.requests || 0) })],
          all > 0 ? ['سهم از کل ترافیک سایت', h('span', { text: P.pct(vb, all) })] : null])]);
        c.hidden = false;
      }
    });
    return c;
  }

  function l4GuideCard(r) {
    var ips = A().edgeIps();
    var c = P.collapsible ? P.collapsible({ title: 'راه‌اندازی و فایروال سرور', icon: 'book', tone: 'muted', id: 'l4-guide',
      subtitle: 'کاربران به نشانی CDN وصل می‌شوند و نودها اتصال را به سرور شما می‌رسانند.' }) : P.card({ title: 'راه‌اندازی و فایروال سرور', icon: 'book', id: 'l4-guide' });
    append(c.body, [
      h('ol', { className: 'pcdn-ol' },
        h('li', { text: 'برنامه را بسازید و ذخیره کنید؛ نشانی اتصال (نام میزبان:پورت) در فهرست نمایش داده می‌شود.' }),
        h('li', { text: 'در برنامهٔ کاربر (کلاینت بازی، SSH و …) به‌جای آی‌پی سرور، همین نشانی و پورت را بدهید.' }),
        h('li', { text: 'در فایروال سرور خودتان پورت مقصد را فقط برای آی‌پی نودهای CDN باز کنید تا کسی مستقیم به سرور نرسد.' }),
        h('li', { text: 'اگر PROXY protocol را روشن کرده‌اید، آن را در نرم‌افزار سرور هم روشن کنید (مثلاً proxy_protocol در nginx یا send-proxy در HAProxy).' })),
      ips.length ? h('div', null, h('p', { className: 'pcdn-help', text: 'آی‌پی نودهای CDN (اتصال‌ها از این آدرس‌ها به سرور شما می‌رسد):' }),
        h('div', { className: 'pcdn-chips-row' }, ips.map(function (x) { return P.copyable(x, { label: 'کپی ' + x }); }))) : null,
      h('p', { className: 'pcdn-help' }, 'پورت‌ها از بازهٔ ', ltr(r[0] + '–' + r[1]), ' انتخاب می‌شوند. ترافیک برنامه‌ها (ورودی و خروجی) مثل ترافیک وب از سهمیهٔ همین سرویس کم می‌شود.')
    ]);
    return c;
  }

  // ================================================================== §16.5 video («تحویل ویدیو»)

  var VIDEO_LIMITS = { segment_ttl: [60, 31536000], manifest_ttl: [1, 3600] };
  function videoProblems(d) {
    var out = [];
    if (!d.enabled) return out;
    Object.keys(VIDEO_LIMITS).forEach(function (k) {
      if (!has(d, k)) return;
      var v = Number(d[k]), lim = VIDEO_LIMITS[k];
      if (!Number.isInteger(v) || v < lim[0] || v > lim[1]) {
        out.push({ path: k, msg: (k === 'segment_ttl' ? 'مدت کش قطعه‌ها' : 'مدت کش فهرست پخش') + ' باید بین ' + num(lim[0]) + ' و ' + num(lim[1]) + ' ثانیه باشد.' });
      }
    });
    if (!out.length && has(d, 'segment_ttl') && has(d, 'manifest_ttl') && Number(d.manifest_ttl) > Number(d.segment_ttl)) {
      out.push({ path: 'manifest_ttl', msg: 'مدت کش فهرست پخش نباید از مدت کش قطعه‌ها بیشتر باشد.' });
    }
    return out;
  }
  function renderVideo(Aa) {
    var f = Aa.sectionForm('video', function (d, f2) {
      var c = P.card({ title: 'تحویل ویدیو (HLS / DASH)', icon: 'play', id: 'video' });
      append(c.body, [
        P.toggle(d, 'enabled', 'بهینه‌سازی تحویل ویدیو', { cls: 'pcdn-video-on', onchange: f2.redraw,
          help: 'فهرست‌های پخش (m3u8 / mpd) با کش کوتاه و قطعه‌ها (ts، m4s، mp4، aac) با کش طولانی تحویل می‌شوند؛ فایل‌های بزرگ mp4 تکه‌تکه (۱ مگابایتی) کش می‌شوند تا جلو/عقب زدن سریع باشد.' }),
        d.enabled ? h('div', { className: 'pcdn-grid' },
          has(d, 'manifest_ttl') ? P.duration(d, 'manifest_ttl', 'مدت کش فهرست پخش', { min: VIDEO_LIMITS.manifest_ttl[0], max: VIDEO_LIMITS.manifest_ttl[1],
            picks: [[2, '۲ ثانیه'], [5, '۵ ثانیه'], [60, '۱ دقیقه']], help: 'برای پخش زنده کوتاه (۱ تا ۴ ثانیه، حدود نصف طول هر قطعه)؛ برای ویدیوی آماده (VOD) می‌تواند طولانی‌تر باشد.' }) : null,
          has(d, 'segment_ttl') ? P.duration(d, 'segment_ttl', 'مدت کش قطعه‌ها', { min: VIDEO_LIMITS.segment_ttl[0], max: VIDEO_LIMITS.segment_ttl[1],
            picks: [[3600, '۱ ساعت'], [86400, '۱ روز'], [604800, '۱ هفته']], help: 'قطعه‌ها پس از ساخته شدن تغییر نمی‌کنند؛ مقدار پیشنهادی ۱ روز یا بیشتر.' }) : null) : null,
        d.enabled && has(d, 'prefetch_next') ? P.toggle(d, 'prefetch_next', 'پیش‌بارگذاری قطعهٔ بعدی', { cls: 'pcdn-video-prefetch',
          help: 'وقتی قطعه‌ای (مثل seg_120.ts) برای اولین بار درخواست شود، CDN قطعهٔ بعدی (seg_121.ts) را هم از سرور شما می‌گیرد تا بینندهٔ بعدی بدون انتظار ببیند. فقط برای نام‌هایی که به عدد ختم می‌شوند.' }) : null
      ]);
      var how = P.card({ title: 'نحوهٔ استفاده', icon: 'book', tone: 'muted', id: 'video-how' });
      var ex = 'https://' + domain() + '/live/stream.m3u8';
      append(how.body, [
        h('p', { text: 'کافی است رکورد سایت پروکسی‌شده باشد و پخش‌کننده (hls.js، video.js، Shaka، ExoPlayer یا AVPlayer) فایل را از همین دامنه بخواند:' }),
        P.copyable(ex, { block: true, label: 'کپی نمونه آدرس' }),
        h('ul', { className: 'pcdn-ul' },
          h('li', null, 'پسوندهای ', ltr('.m3u8 .mpd'), ' فهرست پخش و ', ltr('.ts .m4s .mp4 .aac'), ' قطعه حساب می‌شوند؛ مسیر و نام دیگری لازم نیست.'),
          h('li', { text: 'پاسخ فایل‌های ویدیو هدر CORS (Access-Control-Allow-Origin: *) دارند تا پخش‌کننده روی دامنهٔ دیگری هم کار کند.' }),
          h('li', { text: 'برای پخش زنده، فهرست پخش در CDN تقریباً هم‌زمان با سرور شما به‌روز می‌شود و در صورت کندی سرور، نسخهٔ قبلی تا رسیدن نسخهٔ تازه تحویل داده می‌شود.' }),
          h('li', { text: 'ترافیک ویدیو جداگانه شمرده می‌شود (کارت «ترافیک ۳۰ روز اخیر» در همین صفحه) و از همان سهمیهٔ سرویس کم می‌شود.' }))]);
      return [c, how];
    }, { validate: videoProblems, savedMsg: 'تنظیمات ویدیو ذخیره شد و تا چند ثانیه روی همهٔ نودها اعمال می‌شود.' });
    return [f.el, usageCard('video')];
  }

  // ================================================================== §16.6 images v2 (cards on the image page)

  /**
   * Image section as sent: never the output-only transform_secret_set, and never transform_secret —
   * the key is only created by POST image/transform-secret (an omitted key keeps the stored one).
   */
  function imageSerialize(d) { return stripKeys(['transform_secret_set', 'transform_secret'])(d); }
  function imageV2(d) { return has(d, 'avif') || has(d, 'smart_crop') || has(d, 'transform_secret_set'); }

  /**
   * Signing guide — the algorithm of controller/app/images.py and the edge (njs imgSigBase): canonical =
   * path (as requested, still percent-encoded) + "?" + the signed parameters present, in the FIXED order
   * w, h, fit, q, fmt, width, height, as k=v joined by "&" (raw values); sig = lowercase hex
   * HMAC-SHA256(secret, canonical), sent as &sig=. A missing / wrong signature is refused (403).
   */
  var SIGN = {
    php: function (path) {
      return [
        '<?php',
        '// Pasargad CDN — signed image transform URL',
        "function pcdn_image_url(string $path, array $params): string {",
        "    $secret = getenv('PCDN_IMAGE_SECRET');                  // imgsec_... (shown once)",
        '    $pairs = [];',
        "    foreach (['w', 'h', 'fit', 'q', 'fmt', 'width', 'height'] as $k) {   // this fixed order",
        "        if (isset($params[$k])) { $pairs[] = $k . '=' . rawurlencode((string) $params[$k]); }",
        '    }',
        "    $canonical = $path . '?' . implode('&', $pairs);",
        "    $sig = hash_hmac('sha256', $canonical, $secret);        // lowercase hex",
        "    return 'https://" + domain() + "' . $canonical . '&sig=' . $sig;",
        '}',
        '',
        "// a 800x600 WebP crop",
        "echo pcdn_image_url('" + path + "', ['w' => 800, 'h' => 600, 'fit' => 'cover', 'fmt' => 'webp']);"
      ].join('\n');
    },
    node: function (path) {
      return [
        '// Node.js — Pasargad CDN signed image transform URL',
        "const crypto = require('crypto');",
        '',
        'function pcdnImageUrl(path, params) {',
        '  const secret = process.env.PCDN_IMAGE_SECRET;                // imgsec_... (shown once)',
        "  const canonical = path + '?' + ['w', 'h', 'fit', 'q', 'fmt', 'width', 'height']   // this fixed order",
        '    .filter((k) => params[k] !== undefined)',
        "    .map((k) => k + '=' + encodeURIComponent(String(params[k])))",
        "    .join('&');",
        "  const sig = crypto.createHmac('sha256', secret).update(canonical).digest('hex');",
        "  return 'https://" + domain() + "' + canonical + '&sig=' + sig;",
        '}',
        '',
        "// a 800x600 WebP crop",
        "console.log(pcdnImageUrl('" + path + "', { w: 800, h: 600, fit: 'cover', fmt: 'webp' }));"
      ].join('\n');
    }
  };

  /** The one-time transform-secret dialog. Nothing is kept once it is closed. */
  function secretDialog(secret, rotated) {
    var d = P.dialog({ title: rotated ? 'کلید امضای تصویر جدید' : 'کلید امضای تصویر', icon: 'key', tone: 'warning', wide: true });
    d.el.classList.add('pcdn-img-secret-dlg');
    append(d.body, [
      P.alertBox('warning', [h('strong', { text: 'این کلید فقط همین یک بار نمایش داده می‌شود. ' }),
        'همین حالا آن را کپی کنید و در تنظیمات برنامهٔ سایت (مثلاً متغیر محیطی PCDN_IMAGE_SECRET) ذخیره کنید؛ اگر گم شود باید کلید تازه بسازید.'], { icon: 'warn' }),
      rotated ? P.alertBox('info', 'کلید قبلی باطل شد؛ نشانی‌های امضاشده با کلید قبلی از این پس رد می‌شوند و باید با کلید تازه دوباره امضا شوند.') : null,
      h('div', { className: 'pcdn-key-plain pcdn-img-secret' }, h('code', { className: 'pcdn-key-value', dir: 'ltr', text: String(secret) }),
        P.copyBtn(String(secret), 'کپی کلید امضای تصویر', { text: 'کپی', done: 'کلید امضا کپی شد' })),
      h('p', { className: 'pcdn-help', text: 'این کلید را هرگز در کد سمت مرورگر (JavaScript صفحه) قرار ندهید؛ امضا باید روی سرور شما ساخته شود.' })]);
    var done = P.btn('کلید را ذخیره کردم', { kind: 'primary', icon: 'check', cls: 'pcdn-img-secret-ok', onclick: function () { d.close(); } });
    done.setAttribute('data-ro-ok', '1');
    d.foot.appendChild(done);
    d.focusFirst();
    return d;
  }

  /**
   * Extra cards for the image page (pages.js renderImage) when the controller knows the images v2 keys.
   * d is the form draft, f the section form. Returns [] for an older controller.
   */
  function imageCards(d, f) {
    if (!imageV2(d)) return [];
    var out = [];
    var fmt = P.card({ title: 'AVIF و برش هوشمند', icon: 'sparkles', id: 'image-v2' });
    append(fmt.body, [
      has(d, 'avif') ? P.toggle(d, 'avif', 'تبدیل خودکار به AVIF', { cls: 'pcdn-img-avif',
        help: 'برای مرورگرهایی که AVIF را می‌پذیرند (Accept: image/avif) تصاویر JPEG و PNG به AVIF تبدیل می‌شوند که معمولاً از WebP هم کم‌حجم‌تر است. نودهایی که ابزار تبدیل AVIF ندارند WebP یا همان فایل اصلی را می‌دهند؛ هیچ تصویری خراب نمی‌شود.' }) : null,
      has(d, 'smart_crop') ? P.toggle(d, 'smart_crop', 'برش هوشمند', { cls: 'pcdn-img-smart',
        help: 'وقتی عرض و ارتفاع با fit=cover خواسته شود، به‌جای برش از وسط، بخشِ پرجزئیات‌تر تصویر (معمولاً سوژه) نگه داشته می‌شود.' }) : null
    ]);
    out.push(fmt);

    var params = P.card({ title: 'پارامترهای تبدیل در آدرس', icon: 'link', tone: 'muted', id: 'image-params' });
    var ex = 'https://' + domain() + '/images/photo.jpg?w=800&h=600&fit=cover&q=80&fmt=webp';
    var rows = [['w', 'عرض به پیکسل', '۱ تا ۴۰۹۶'], ['h', 'ارتفاع به پیکسل', '۱ تا ۴۰۹۶'], ['fit', 'cover: پر کردن کادر با برش / contain: جا شدن کامل بدون برش', 'cover | contain'],
      ['q', 'کیفیت خروجی', '۱ تا ۱۰۰'], ['fmt', 'فرمت خروجی (اگر ندهید بر اساس مرورگر انتخاب می‌شود)', 'webp | avif | jpeg']];
    append(params.body, [
      h('div', { className: 'pcdn-table-wrap' }, h('table', { className: 'pcdn-table pcdn-rtable pcdn-img-params' },
        h('caption', { className: 'pcdn-sr', text: 'پارامترهای تبدیل تصویر' }),
        h('thead', null, h('tr', null, ['پارامتر', 'کاربرد', 'مقدار مجاز'].map(function (t) { return h('th', { scope: 'col', text: t }); }))),
        h('tbody', null, rows.map(function (r) {
          return h('tr', null, h('td', { 'data-label': 'پارامتر' }, ltr(r[0])), h('td', { 'data-label': 'کاربرد', text: r[1] }), h('td', { 'data-label': 'مقدار مجاز' }, /[a-z]/.test(r[2]) ? ltr(r[2]) : h('span', { text: r[2] })));
        })))),
      P.copyable(ex, { block: true, label: 'کپی نمونه آدرس' }),
      h('p', { className: 'pcdn-help', text: 'مقدار خارج از بازه یا پارامتر ناشناخته نادیده گرفته می‌شود و اگر تبدیل ممکن نباشد همان تصویر اصلی تحویل داده می‌شود.' })]);
    out.push(params);

    if (has(d, 'transform_secret_set')) out.push(signCard(d, f));
    return out;
  }

  function signCard(d, f) {
    var set = !!d.transform_secret_set;
    var c = P.card({ title: 'نشانی‌های امضاشده', icon: 'key', id: 'image-sign',
      subtitle: 'جلوگیری از ساختن نسخه‌های بی‌شمار تصویر توسط دیگران',
      actions: h('span', { className: 'pcdn-pill pcdn-tone-' + (set ? 'success' : 'muted'), 'data-secret-set': set ? '1' : '0' }, h('span', { className: 'pcdn-dot' }),
        h('span', { text: set ? 'فقط نشانی امضاشده' : 'امضا لازم نیست' })) });
    function stored(v) {
      // the stored section only learns whether a key exists — the value lives only in the dialog
      var cur = A().config('image') || {};
      cur.transform_secret_set = v;
      delete cur.transform_secret;
      A().setConfig('image', cur);
      d.transform_secret_set = v;   // output-only: not part of the PUT body nor of the dirty check
    }
    var gen = P.btn(set ? 'ساخت کلید جدید' : 'ساخت کلید امضا', { kind: set ? '' : 'primary', icon: 'key', size: 'sm', write: true, cls: 'pcdn-img-secret-gen', onclick: function () {
      var pre = set ? P.confirm({ title: 'ساخت کلید امضای جدید', danger: true, ok: 'ساخت کلید جدید',
        body: 'کلید فعلی بلافاصله باطل می‌شود و همهٔ نشانی‌هایی که با آن امضا شده‌اند (با خطای ۴۰۳) رد می‌شوند تا با کلید تازه دوباره امضا شوند.' }) : Promise.resolve(true);
      pre.then(function (ok) {
        if (!ok) return;
        P.busy(gen, P.api('POST', 'image/transform-secret')).then(function (res) {
          if (!res.ok) { P.toast(P.errorText(res), 'error'); return; }
          var sec = res.data && typeof res.data.secret === 'string' ? res.data.secret : (res.data && typeof res.data.transform_secret === 'string' ? res.data.transform_secret : '');
          stored(true);
          f.redraw();
          if (sec) secretDialog(sec, set); else P.toast('کلید امضای تصویر ساخته شد.');
        });
      });
    } });
    var del = set ? P.btn('حذف کلید', { kind: 'danger-soft', icon: 'trash', size: 'sm', write: true, cls: 'pcdn-img-secret-del', onclick: function () {
      P.confirm({ title: 'حذف کلید امضای تصویر', danger: true, ok: 'حذف کلید',
        body: 'پس از حذف، هر کسی می‌تواند با پارامترهای w، h، fit، q و fmt نسخه‌های تازه از تصاویر بسازد؛ نشانی‌های امضاشدهٔ فعلی هم بدون بررسی امضا کار می‌کنند.' })
        .then(function (ok) {
          if (!ok) return;
          P.busy(del, P.api('DELETE', 'image/transform-secret')).then(function (res) {
            if (!res.ok) { P.toast(P.errorText(res), 'error'); return; }
            stored(false);
            f.redraw();
            P.toast('کلید امضای تصویر حذف شد؛ تبدیل بدون امضا دوباره مجاز است.');
          });
        });
    } }) : null;
    append(c.body, [
      h('p', { text: set ? 'کلید امضا ساخته شده است: درخواستی که پارامتر تبدیل (w، h، fit، q، fmt یا width/height) دارد فقط با امضای معتبر (sig) پاسخ می‌گیرد و بقیه با خطای ۴۰۳ رد می‌شوند. نشانی خود تصویر بدون پارامتر مثل همیشه تحویل داده می‌شود.'
        : 'بدون کلید، هر کسی می‌تواند با تغییر پارامترها نسخه‌های بی‌شماری از تصاویر بسازد و ترافیک و پردازش شما را مصرف کند. با ساختن کلید، فقط نشانی‌هایی که سرور شما امضا کرده تبدیل می‌شوند.' }),
      h('div', { className: 'pcdn-row-actions' }, gen, del),
      h('p', { className: 'pcdn-help', text: set ? 'کلید فعلی دیگر قابل نمایش نیست. اگر آن را گم کرده‌اید کلید جدید بسازید و در برنامهٔ سایت جایگزین کنید.'
        : 'کلید پس از ساخت فقط یک بار نمایش داده می‌شود. پیش از ساختن، کد امضا را در سایت آماده کنید؛ از همان لحظه نشانی‌های تبدیل بدون امضا با خطای ۴۰۳ رد می‌شوند.' })]);
    var g = P.collapsible({ title: 'راهنمای امضای نشانی', icon: 'code', tone: 'muted', id: 'image-sign-guide', subtitle: 'ساخت sig روی سرور شما (PHP / Node.js)' });
    var path = '/images/photo.jpg';
    append(g.body, [
      h('ol', { className: 'pcdn-ol' },
        h('li', null, 'رشتهٔ امضا = مسیر تصویر (همان‌طور که در نشانی است) + ', ltr('?'), ' + پارامترهایی از ', ltr('w, h, fit, q, fmt, width, height'),
          ' که در نشانی دارید، دقیقاً به همین ترتیب و به شکل ', ltr('k=v'), ' با ', ltr('&'), '.'),
        h('li', null, 'امضا = ', ltr('HMAC-SHA256(secret, رشتهٔ امضا)'), ' به‌صورت hex با حروف کوچک (۶۴ نویسه).'),
        h('li', null, 'امضا را با پارامتر ', ltr('sig'), ' به نشانی اضافه کنید؛ ترتیب پارامترها در خود نشانی مهم نیست.'),
        h('li', null, 'درخواست دارای پارامتر تبدیل با امضای نادرست یا بدون امضا با خطای ۴۰۳ رد می‌شود.')),
      h('ul', { className: 'pcdn-ul pcdn-help' },
        h('li', null, 'نشانی: ', ltr('/images/photo.jpg?fit=cover&w=300')),
        h('li', null, 'رشتهٔ امضا: ', ltr('/images/photo.jpg?w=300&fit=cover')),
        h('li', null, 'نشانی نهایی: ', ltr('/images/photo.jpg?fit=cover&w=300&sig=…'))),
      codeBlock(SIGN.php(path), 'PHP'),
      codeBlock(SIGN.node(path), 'Node.js'),
      h('p', { className: 'pcdn-help', text: 'نشانی بدون پارامتر تبدیل (خود تصویر اصلی) امضا لازم ندارد. امضا را روی سرور بسازید، نه در مرورگر.' })]);
    return h('div', { className: 'pcdn-stack' }, c, g);
  }

  // ================================================================== §16.7 DNS: secondary + weighted/health records

  // controller/app/sections.py (TsigKey / DnsSecondary)
  var TSIG_ALGS = ['hmac-sha256', 'hmac-sha384', 'hmac-sha512', 'hmac-sha1', 'hmac-md5'];
  var TSIG_NAME_RE = /^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*$/;
  /** Output-only keys a controller may add to the section (transfer status) — never sent back. */
  var DS_OUT = ['status', 'serial', 'last_transfer', 'last_error', 'last_check', 'transfer_ips', 'notify_from', 'axfr_from', 'nameservers'];
  function storedTsigName() {
    var c = site() && site().config && site().config.dns_secondary;
    return c && c.tsig && typeof c.tsig === 'object' ? String(c.tsig.name || '') : '';
  }
  /** The section as sent: writable keys only; the TSIG secret only when typed (write-only on the controller). */
  function dsSerialize(d) {
    var out = {};
    Object.keys(d || {}).forEach(function (k) { if (DS_OUT.indexOf(k) < 0) out[k] = d[k]; });
    out.primaries = (out.primaries || []).map(function (x) { return String(x).trim(); }).filter(Boolean);
    if (Array.isArray(out.allow_axfr)) out.allow_axfr = out.allow_axfr.map(function (x) { return String(x).trim(); }).filter(Boolean);
    if (out.tsig && typeof out.tsig === 'object') {
      var t = { name: String(out.tsig.name || '').trim().toLowerCase().replace(/\.$/, ''), algorithm: out.tsig.algorithm || 'hmac-sha256' };
      if (typeof out.tsig.secret === 'string' && out.tsig.secret.trim() !== '') t.secret = out.tsig.secret.trim();
      out.tsig = t;
    } else if (has(out, 'tsig')) {
      out.tsig = null;
    }
    return out;
  }
  function b64Bytes(v) {
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(v) || v.length % 4 !== 0) return -1;
    return v.length / 4 * 3 - (v.match(/=+$/) || [''])[0].length;
  }
  function publicIp(v, allowCidr) {
    var m = /^([^/]+)(?:\/(\d{1,3}))?$/.exec(v);
    if (!m || (m[2] !== undefined && !allowCidr)) return 'invalid';
    if (!(allowCidr ? cidr(v) : ip(v))) return 'invalid';
    return privateIp(m[1]) ? 'private' : 'ok';
  }
  function dsProblems(d) {
    var out = [];
    function bad(p, m) { out.push({ path: p, msg: m }); }
    var pr = (d.primaries || []).map(function (x) { return String(x).trim(); }).filter(Boolean);
    if (d.mode === 'primary_elsewhere' && !pr.length) bad('primaries', 'دست‌کم آی‌پی یک سرور DNS اصلی را وارد کنید.');
    if (pr.length > 10) bad('primaries', 'حداکثر ۱۰ سرور اصلی مجاز است.');
    pr.forEach(function (x) {
      var st = publicIp(x, false);
      if (st === 'invalid') bad('primaries', 'آی‌پی نامعتبر: ' + x + ' (فقط آی‌پی، نه نام دامنه یا بازه)');
      else if (st === 'private') bad('primaries', 'آی‌پی ' + x + ' عمومی نیست.');
    });
    var ax = (d.allow_axfr || []).map(function (x) { return String(x).trim(); }).filter(Boolean);
    if (ax.length > 20) bad('allow_axfr', 'حداکثر ۲۰ آدرس مجاز است.');
    ax.forEach(function (x) {
      var st = publicIp(x, true);
      if (st === 'invalid') bad('allow_axfr', 'آی‌پی یا بازهٔ نامعتبر: ' + x);
      else if (st === 'private') bad('allow_axfr', 'آدرس ' + x + ' عمومی نیست.');
    });
    var t = d.tsig;
    if (ax.length && !(t && typeof t === 'object')) bad('allow_axfr', 'انتقال زون به سرورهای شما فقط با کلید TSIG مجاز است؛ «امضای انتقال با TSIG» را روشن کنید.');
    if (t && typeof t === 'object') {
      var name = String(t.name || '').trim().toLowerCase().replace(/\.$/, '');
      if (!TSIG_NAME_RE.test(name)) bad('tsig.name', 'نام کلید TSIG معتبر نیست (مثل transfer-key یا key.example.com).');
      if (TSIG_ALGS.indexOf(t.algorithm) < 0) bad('tsig.algorithm', 'الگوریتم TSIG را انتخاب کنید.');
      var sec = typeof t.secret === 'string' ? t.secret.trim() : '';
      var n = sec ? b64Bytes(sec) : 0;
      if (sec && n < 0) bad('tsig.secret', 'کلید مخفی TSIG باید base64 معتبر باشد (مثل خروجی tsig-keygen).');
      else if (sec && n < 16) bad('tsig.secret', 'کلید مخفی TSIG باید دست‌کم ۱۶ بایت (۱۲۸ بیت) باشد.');
      else if (sec.length > 512) bad('tsig.secret', 'کلید مخفی TSIG حداکثر ۵۱۲ نویسه است.');
      // a stored secret is kept only for the same key name (controller _same_tsig)
      if (!sec && !(t.secret_set && name === storedTsigName())) {
        bad('tsig.secret', t.secret_set ? 'با تغییر نام کلید، کلید مخفی را هم دوباره وارد کنید.' : 'کلید مخفی TSIG را وارد کنید.');
      }
    }
    return out;
  }

  function renderSecondary(Aa) {
    var nss = (site().nameservers || []).filter(function (x) { return typeof x === 'string'; });
    var f = Aa.sectionForm('dns_secondary', function (d, f2) {
      if (!d.mode) d.mode = 'off';
      if (!Array.isArray(d.primaries)) d.primaries = [];
      var out = [], slave = d.mode === 'primary_elsewhere';
      var c = P.card({ title: 'DNS اصلی دامنه کجاست؟', icon: 'server', id: 'dns-mode' });
      append(c.body, [
        P.choice(d, 'mode', 'حالت DNS', [
          ['off', 'پاسارگاد CDN', 'رکوردها را در همین پنل مدیریت می‌کنید (حالت عادی).', 'cloud'],
          ['primary_elsewhere', 'سرور DNS خودم؛ پاسارگاد ثانویه', 'رکوردها روی سرور DNS شما می‌مانند و نیم‌سرورهای ما زون را با AXFR از آن کپی و پاسخ می‌دهند.', 'swap']],
          { cols: 2, onchange: function () { f2.redraw(); } })]);
      out.push(c);
      if (slave) {
        var p = P.card({ title: 'سرورهای DNS اصلی شما', icon: 'download', id: 'dns-primaries' });
        append(p.body, [
          P.tags(d, 'primaries', 'آی‌پی سرورهای اصلی', { placeholder: '203.0.113.53',
            help: 'حداکثر ۱۰ آی‌پی عمومی. نیم‌سرورهای ما زون را از این سرورها انتقال می‌دهند؛ روی آن‌ها انتقال زون (AXFR) را برای نیم‌سرورهای ما مجاز کنید و NOTIFY را به آن‌ها بفرستید.' }),
          P.alertBox('info', [h('strong', { text: 'در این حالت ' }), 'رکوردهای صفحهٔ «رکوردها» منتشر نمی‌شوند و هر تغییر را باید روی سرور DNS خودتان بدهید. برای عبور ترافیک از CDN، نام‌های وب را در زون خودتان به آی‌پی‌های CDN اشاره دهید.'])]);
        out.push(p);
      }
      var ax = P.card({ title: 'انتقال زون به سرور ثانویهٔ شما', icon: 'upload', id: 'dns-axfr', tone: 'muted' });
      append(ax.body, [P.tags(d, 'allow_axfr', 'آی‌پی‌های مجاز برای AXFR (اختیاری)', { placeholder: '198.51.100.53',
        help: 'اگر خودتان سرور DNS ثانویه دارید، آی‌پی یا بازهٔ آن را اضافه کنید تا زون را از نیم‌سرورهای ما انتقال دهد (حداکثر ۲۰؛ همیشه با کلید TSIG).' }),
        P.alertBox('warning', [h('strong', { text: 'توجه: ' }), 'نام‌های پروکسی‌شده (و نشانی‌های TCP/UDP) در زون انتقالی به‌صورت رکورد LUA در PowerDNS هستند تا هر بار آی‌پی نودهای سالم را برگردانند. سرور ثانویه‌ای که PowerDNS (با LUA records فعال) نباشد — مثل BIND یا Knot — این رکوردها را نمی‌فهمد و برای آن نام‌ها پاسخ درست نمی‌دهد؛ چنین سروری را فقط برای نام‌های بدون پروکسی به کار ببرید.'], { cls: 'pcdn-ds-lua' })]);
      out.push(ax);
      var tc = P.card({ title: 'کلید TSIG', icon: 'key', id: 'dns-tsig', tone: 'muted', subtitle: 'امضای انتقال زون با کلید مشترک — نام، الگوریتم و کلید باید در هر دو طرف یکسان باشد.' });
      var tsigOn = { on: !!(d.tsig && typeof d.tsig === 'object') };
      tc.body.appendChild(P.toggle(tsigOn, 'on', 'امضای انتقال با TSIG', { cls: 'pcdn-ds-tsig',
        help: slave ? 'پیشنهاد می‌شود: انتقال از سرورهای اصلی شما با این کلید امضا می‌شود.' : 'برای «آی‌پی‌های مجاز AXFR» لازم است.',
        onchange: function (v) { d.tsig = v ? { name: '', algorithm: 'hmac-sha256', secret: '' } : null; f2.redraw(); } }));
      if (tsigOn.on) tc.body.appendChild(tsigFields(d.tsig));
      out.push(tc);
      out.push(dsStatusCard(d, nss));
      return out;
    }, { serialize: dsSerialize, validate: dsProblems, savedMsg: 'تنظیمات DNS ثانویه ذخیره شد و تا چند ثانیه روی نیم‌سرورها اعمال می‌شود.',
      onSaved: function () {
        // the TSIG secret is write-only: never keep a typed value in the stored copy
        var c = A().config('dns_secondary');
        if (c && c.tsig && typeof c.tsig === 'object' && typeof c.tsig.secret === 'string' && c.tsig.secret !== '') {
          c.tsig.secret = ''; c.tsig.secret_set = true; A().setConfig('dns_secondary', c);
          if (A().S.form && A().S.form.section === 'dns_secondary') A().S.form.reset();
        }
      } });
    return f.el;
  }
  function tsigFields(t) {
    var set = !!t.secret_set;
    if (typeof t.secret !== 'string') t.secret = '';
    var sec = P.input(t, 'secret', 'کلید مخفی (base64)', { type: 'password', maxlength: 512,
      placeholder: set ? 'ذخیره شده — برای تغییر مقدار جدید وارد کنید' : 'خروجی tsig-keygen',
      help: set ? 'کلید فعلی رمزنگاری‌شده نگهداری می‌شود و هرگز نمایش داده نمی‌شود؛ خالی بگذارید تا همان بماند (فقط اگر نام کلید عوض نشود).'
        : 'مثلاً با دستور tsig-keygen -a hmac-sha256 transfer-key بسازید و مقدار secret آن را اینجا بگذارید.' });
    var si = sec.querySelector('input');
    if (si) { si.setAttribute('autocomplete', 'new-password'); si.setAttribute('data-secret-input', '1'); }
    return h('div', { className: 'pcdn-subpanel pcdn-ds-tsig-fields' },
      h('div', { className: 'pcdn-grid' },
        P.input(t, 'name', 'نام کلید', { placeholder: 'transfer-key', maxlength: 253 }),
        P.select(t, 'algorithm', 'الگوریتم', TSIG_ALGS.map(function (a) { return [a, a]; }), { ltr: true })),
      sec);
  }
  function dsStatusCard(d, nss) {
    var c = P.card({ title: 'نیم‌سرورها و وضعیت', icon: 'activity', tone: 'muted', id: 'dns-status' });
    var st = d.status ? String(d.status) : null, slave = d.mode === 'primary_elsewhere';
    var good = st === 'ok' || st === 'active' || st === 'synced';
    var tone = good ? 'success' : st === 'error' || st === 'failed' ? 'danger' : 'muted';
    var src = d.transfer_ips || d.axfr_from || d.notify_from;
    append(c.body, [
      dl([
        nss.length ? ['نیم‌سرورهای ما', h('span', null, nss.map(function (x) { return P.copyable(x, { label: 'کپی ' + x }); }))] : null,
        Array.isArray(src) && src.length ? ['آی‌پی درخواست‌های انتقال', h('span', null, src.filter(function (x) { return typeof x === 'string'; }).map(function (x) { return P.copyable(x, { label: 'کپی ' + x }); }))] : null,
        slave && st ? ['آخرین انتقال', P.badge(good ? 'موفق' : st === 'pending' ? 'در انتظار' : st, tone)] : null,
        slave && d.serial ? ['سریال زون', ltr(String(d.serial))] : null,
        slave && d.last_transfer ? ['زمان آخرین انتقال', h('span', { text: P.date(d.last_transfer) })] : null,
        d.last_error ? ['خطا', h('span', { dir: 'auto', text: String(d.last_error) })] : null
      ]),
      h('p', { className: 'pcdn-help', text: slave
        ? 'نیم‌سرورهای ما را در ثبت‌کنندهٔ دامنه (کنار نیم‌سرورهای خودتان) و در رکوردهای NS زون اصلی وارد کنید. زون با هر NOTIFY و در فواصل SOA (refresh) به‌روز می‌شود.'
        : 'در حالت عادی نیم‌سرورهای ما DNS اصلی دامنه هستند و رکوردها را در صفحهٔ «رکوردها» مدیریت می‌کنید.' })]);
    return c;
  }

  /** The zone is served from the customer's primary (DNS page banner). */
  function secondaryMode() {
    var c = site() && site().config && site().config.dns_secondary;
    return !!c && c.mode === 'primary_elsewhere';
  }

  // ------------------------------------------------------------------ record weight + health check (used by app.js recordModal)

  /** A Wave 8 controller (weighted / health-checked records): it returns `weight` on every record. */
  function recordsV2(recs) {
    var s = site();
    return (recs || s.records || []).some(function (r) { return has(r, 'weight'); }) || (!(s.records || []).length && sectionOf(s, 'dns_secondary'));
  }
  var HC_TYPES = [['tcp', 'TCP (اتصال به پورت)'], ['http', 'HTTP'], ['https', 'HTTPS']];
  /** SPEC §16.7: weight and health check on non-proxied A / AAAA / CNAME. */
  function weightable(r) { return !r.proxied && (r.type === 'A' || r.type === 'AAAA' || r.type === 'CNAME'); }
  function hcHttp(r) { return r.health_protocol === 'http' || r.health_protocol === 'https'; }
  function weighted(r) { return r.weight !== null && r.weight !== undefined && r.weight !== ''; }
  /** Health check is possible: A/AAAA, or a weighted CNAME (a lone CNAME has nothing to fail over to — routes_admin). */
  function hcable(r) { return weightable(r) && (r.type !== 'CNAME' || weighted(r)); }
  /**
   * Adds the Wave 8 keys to body (recordBody in app.js) — for a Wave 8 controller only, and only when they
   * differ from the controller defaults (null): a record PUT replaces the record, so an omitted key resets it.
   */
  function recordBodyExtra(r, body) {
    if (!recordsV2()) return body;
    var ok = weightable(r);
    if (ok && weighted(r)) body.weight = Number(r.weight);
    var hc = hcable(r) && !!r.health_check;
    body.health_check = hc;
    body.health_port = hc && r.health_port !== null && r.health_port !== undefined && r.health_port !== '' ? Number(r.health_port) : null;
    if (hc && r.health_protocol && r.health_protocol !== 'tcp') body.health_protocol = r.health_protocol;
    if (hc && hcHttp(r)) body.health_path = String(r.health_path || '').trim() || '/';
    return body;
  }
  /** b = recordBody(r) (normalized); r = the dialog draft (for the CNAME-without-weight hint). */
  function recordProblems(b, r) {
    var out = [];
    if (!recordsV2()) return out;
    if (r && r.type === 'CNAME' && !r.proxied && r.health_check && !weighted(r)) out.push({ path: 'weight', msg: 'برای بررسی سلامت CNAME وزن را هم تعیین کنید (CNAME تنها جایگزینی ندارد).' });
    if (has(b, 'weight') && (!Number.isInteger(b.weight) || b.weight < 0 || b.weight > 100)) out.push({ path: 'weight', msg: 'وزن باید عدد صحیحی بین ۰ و ۱۰۰ باشد.' });
    if (b.health_check) {
      if (b.health_port !== null && (!Number.isInteger(b.health_port) || b.health_port < 1 || b.health_port > 65535)) out.push({ path: 'health_port', msg: 'پورت بررسی سلامت باید بین ۱ و ۶۵۵۳۵ باشد.' });
      if (has(b, 'health_path') && (b.health_path.length > 512 || !/^\/[^\s"'<>\\]*$/.test(b.health_path))) out.push({ path: 'health_path', msg: 'مسیر بررسی باید با / شروع شود و فاصله یا نویسهٔ نامعتبر نداشته باشد.' });
    }
    return out;
  }
  /** Fields for the record dialog — weight + health check of a non-proxied A/AAAA/CNAME. null when not applicable. */
  function recordFields(r, redraw) {
    if (!recordsV2() || !weightable(r)) return null;
    var box = h('div', { className: 'pcdn-rec-w8' });
    append(box, [
      P.input(r, 'weight', 'وزن (اختیاری)', { type: 'number', min: 0, max: 100, nullable: true, placeholder: '—', cls: 'pcdn-rec-weight',
        help: r.type === 'CNAME' ? 'چند CNAME هم‌نام فقط وقتی مجازند که همه وزن‌دار و بدون پروکسی باشند؛ در هر پاسخ یکی به نسبت وزن انتخاب می‌شود. ۰ = پشتیبان.'
          : 'برای چند رکورد هم‌نام: سهم هر کدام از پاسخ‌ها به نسبت وزن (۱ تا ۱۰۰). ۰ = پشتیبان؛ فقط وقتی پاسخ داده می‌شود که هیچ عضو دیگری سالم نباشد. خالی = بدون وزن.' }),
      P.toggle(r, 'health_check', 'بررسی سلامت', { cls: 'pcdn-rec-hc', onchange: redraw,
        help: 'هر ۶۰ ثانیه از سرور ما بررسی می‌شود؛ آدرسی که پاسخ ندهد از پاسخ‌های DNS کنار گذاشته می‌شود — ولی هرگز همه با هم (اگر همه ناسالم باشند همه برگردانده می‌شوند).'
          + (r.type === 'CNAME' ? ' برای CNAME فقط همراه با وزن (CNAME تنها جایگزینی ندارد).' : '') })]);
    if (r.health_check) {
      if (!r.health_protocol) r.health_protocol = 'tcp';
      box.appendChild(h('div', { className: 'pcdn-grid' },
        P.select(r, 'health_protocol', 'نوع بررسی', HC_TYPES, { onchange: redraw, cls: 'pcdn-rec-hctype' }),
        P.input(r, 'health_port', 'پورت', { type: 'number', min: 1, max: 65535, nullable: true, placeholder: r.health_protocol === 'https' ? '443' : '80' })));
      if (hcHttp(r)) box.appendChild(P.input(r, 'health_path', 'مسیر بررسی', { placeholder: '/health', maxlength: 512, help: 'پاسخ 2xx یا 3xx سالم حساب می‌شود.' }));
      var hb = recordHealthLine(r);
      if (hb) box.appendChild(hb);
    }
    return box;
  }
  /** Extras for the record list (weight). */
  function recordExtras(r) {
    return r.weight !== null && r.weight !== undefined && !r.proxied ? [['وزن', String(r.weight)]] : [];
  }
  /** The controller's last probe of a health-checked record: r.health = {ok, ms, fail, at, error, advertised} (services.record_to_dict). */
  function healthOf(r) { return r && r.health_check && !r.proxied && r.health && typeof r.health === 'object' ? r.health : null; }
  function recordHealthBadge(r) {
    var x = healthOf(r);
    if (!x) return null;
    var st = x.ok === true ? ['سالم', 'success', 'checkCircle'] : x.ok === false ? ['ناسالم', 'danger', 'xCircle'] : ['در انتظار بررسی', 'muted', 'clock'];
    var tip = [x.at ? 'آخرین بررسی: ' + P.date(x.at) : '', typeof x.ms === 'number' ? 'زمان پاسخ: ' + num(x.ms) + ' ms' : '',
      x.advertised === false ? 'از پاسخ‌های DNS کنار گذاشته شده' : '', x.error ? String(x.error) : ''].filter(Boolean).join(' — ');
    var b = P.badge(st[0] + (x.advertised === false ? ' — کنار گذاشته شده' : ''), st[1], st[2]);
    b.classList.add('pcdn-rec-health');
    b.setAttribute('data-health', x.ok === true ? 'up' : x.ok === false ? 'down' : 'pending');
    if (tip) b.title = tip;
    return b;
  }
  function recordHealthLine(r) {
    var x = healthOf(r), b = recordHealthBadge(r);
    if (!b) return null;
    return h('p', { className: 'pcdn-help pcdn-rec-health-line' }, b, x.at ? ' آخرین بررسی ' + P.rel(x.at) : null,
      typeof x.ms === 'number' && x.ok ? ' — ' + num(x.ms) + ' ms' : null,
      x.ok === false && x.error ? h('span', { dir: 'auto', text: ' — ' + String(x.error) }) : null,
      x.ok === false && x.advertised === true ? h('span', { text: ' — چون عضو سالم دیگری نیست، هنوز پاسخ داده می‌شود.' }) : null);
  }

  // ================================================================== registry

  pages.tcpudp = {
    title: 'پروکسی TCP/UDP', icon: 'port', heading: 'پروکسی TCP/UDP',
    desc: 'سرویس‌های غیر وب (سرور بازی، SSH، پایگاه داده، MQTT، VoIP) را با یک پورت روی CDN منتشر کنید؛ آی‌پی سرور پنهان می‌ماند و ترافیک از نودهای CDN عبور می‌کند.',
    guide: {
      what: 'هر «برنامه» یک پورت TCP یا UDP روی نودهای CDN است؛ نودها هر اتصال را بدون تغییر محتوا به سرور و پورتی که تعیین کرده‌اید می‌رسانند.',
      when: 'وقتی سرویسی غیر از وب (HTTP/HTTPS) دارید که باید از اینترنت در دسترس باشد ولی نمی‌خواهید آی‌پی سرور را منتشر کنید.',
      rec: 'دسترسی را در صورت امکان به آی‌پی‌های مشخص محدود کنید، در فایروال سرور فقط آی‌پی نودهای CDN را باز کنید و PROXY protocol را فقط اگر نرم‌افزار سرور پشتیبانی می‌کند روشن کنید.',
      mistakes: ['روشن کردن PROXY protocol بدون پشتیبانی سرور (اتصال‌ها خراب می‌شوند).', 'باز گذاشتن پورت سرور برای همه (دور زدن CDN با آی‌پی مستقیم).', 'استفاده از این بخش برای وب سایت؛ برای وب رکورد پروکسی‌شده کافی است.']
    },
    upsell: 'با ارتقای پلن می‌توانید سرویس‌های TCP و UDP (بازی، SSH، پایگاه داده و …) را هم از پشت CDN منتشر کنید.',
    hidden: function (s) { return !sectionOf(s, 'l4'); },
    lock: function (f) { return f.l4_proxy !== true || !(Number(f.max_l4_apps) > 0); },
    render: function (Aa) { return renderL4(Aa); }
  };
  pages.video = {
    title: 'تحویل ویدیو', icon: 'play', heading: 'تحویل ویدیو (HLS / DASH)',
    desc: 'کش و تحویل بهینهٔ ویدیوی پخش زنده و آماده: فهرست پخش تازه، قطعه‌ها با کش طولانی و پیش‌بارگذاری قطعهٔ بعدی.',
    guide: {
      what: 'پخش‌کننده‌های HLS و DASH ابتدا فهرست پخش (m3u8 / mpd) و سپس قطعه‌های چندثانیه‌ای ویدیو را می‌گیرند؛ CDN هر کدام را با قاعدهٔ مناسب خودش کش می‌کند.',
      when: 'وقتی ویدیو (زنده یا آماده) را با HLS یا DASH از سایت خود پخش می‌کنید.',
      rec: 'کش فهرست پخش ۲ ثانیه برای زنده، کش قطعه‌ها ۱ روز و پیش‌بارگذاری روشن.',
      mistakes: ['کش طولانی فهرست پخش در پخش زنده (بیننده عقب می‌ماند).', 'تغییر محتوای قطعه با همان نام فایل (نسخهٔ کش‌شدهٔ قدیمی دیده می‌شود).']
    },
    upsell: 'با ارتقای پلن، ویدیوی سایت با تنظیمات مخصوص HLS/DASH تحویل داده می‌شود.',
    hidden: function (s) { return !sectionOf(s, 'video'); },
    lock: function (f) { return f.video === false; },
    render: function (Aa) { return renderVideo(Aa); }
  };
  pages.secondary = {
    title: 'DNS ثانویه', icon: 'swap', heading: 'DNS ثانویه و انتقال زون',
    desc: 'اگر DNS اصلی دامنه جای دیگری است، سرورهای ما می‌توانند ثانویه باشند؛ یا به سرور ثانویهٔ خودتان اجازهٔ انتقال زون بدهید.',
    guide: {
      what: 'در حالت «اصلی جای دیگر»، زون با AXFR از سرور شما کپی و از نیم‌سرورهای ما هم پاسخ داده می‌شود. «AXFR مجاز» برعکس، به سرور ثانویهٔ شما اجازهٔ کپی زون از ما را می‌دهد.',
      when: 'برای افزونگی DNS بین دو ارائه‌دهنده، یا وقتی سامانهٔ DNS خودتان را دارید و نمی‌خواهید رکوردها را جابه‌جا کنید.',
      rec: 'همیشه TSIG با hmac-sha256 و فقط آی‌پی‌های مشخص.',
      mistakes: ['فراموش کردن مجاز کردن انتقال زون روی سرور اصلی.', 'وارد نکردن نیم‌سرورهای ما در رکوردهای NS زون اصلی.', 'گم کردن کلید TSIG (نمایش داده نمی‌شود؛ مقدار تازه بدهید).']
    },
    hidden: function (s) { return !sectionOf(s, 'dns_secondary'); },
    render: function (Aa) { return renderSecondary(Aa); }
  };

  P.w8 = {
    imageCards: imageCards, imageSerialize: imageSerialize, imageV2: imageV2,
    recordFields: recordFields, recordBodyExtra: recordBodyExtra, recordProblems: recordProblems, recordExtras: recordExtras,
    recordHealthBadge: recordHealthBadge, recordsV2: recordsV2, secondaryMode: secondaryMode,
    // exported for tests
    l4Serialize: l4Serialize, l4Problems: l4Problems, l4AppProblems: l4AppProblems, videoProblems: videoProblems,
    dsSerialize: dsSerialize, dsProblems: dsProblems, cidr: cidr, ip: ip, privateIp: privateIp
  };
})();
