/*
 * Pasargad CDN — «تونل / VPN» page (docs/SPEC.md §7): customers run Xray / V2Ray / sing-box
 * behind the CDN over gRPC, XHTTP, WebSocket, HTTPUpgrade or raw HTTP/2.
 *
 * Registers PCDN.pages.tunnel (shell in app.js). Also exports:
 *   PCDN.qr(text, 'L'|'M')      tiny QR encoder (byte mode), used for the share link — no external libraries
 *   PCDN.tunnelConfig(o)        share link + Xray server inbound + sing-box outbound for one path (pure; tests use it)
 * Section API: GET/PUT config/tunnel, GET tunnel/stats?hours=24|168, POST tunnel/check (all via api.php).
 */
(function () {
  'use strict';
  var P = window.PCDN = window.PCDN || {};
  var t = P.t;  // i18n.js (SPEC §16.10)
  var pages = P.pages = P.pages || {};
  var h = P.h, append = P.append, clear = P.clear, icon = P.icon, ltr = P.ltr, clone = P.clone, num = P.num;

  function A() { return P.app; }

  // ------------------------------------------------------------------ QR code (byte mode, versions 1–40, no external libraries)
  //
  // Compact port of the standard algorithm (ISO/IEC 18004): data → Reed–Solomon blocks → matrix → best of 8 masks.
  // qr(text, 'M'|'L') → {size, dark(x, y)} or null when the text does not fit.

  var QR_ECC = { L: [7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
    M: [10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28] };
  var QR_BLOCKS = { L: [1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
    M: [1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49] };
  var QR_FMT = { L: 1, M: 0 };

  function qrRawModules(v) {
    var r = (16 * v + 128) * v + 64;
    if (v >= 2) { var na = Math.floor(v / 7) + 2; r -= (25 * na - 10) * na - 55; if (v >= 7) r -= 36; }
    return r;
  }
  function gfMul(x, y) {
    var z = 0;
    for (var i = 7; i >= 0; i--) { z = (z << 1) ^ ((z >>> 7) * 0x11D); z ^= ((y >>> i) & 1) * x; }
    return z & 0xFF;
  }
  function rsDivisor(deg) {
    var res = []; for (var i = 0; i < deg - 1; i++) res.push(0); res.push(1);
    var root = 1;
    for (i = 0; i < deg; i++) {
      for (var j = 0; j < res.length; j++) { res[j] = gfMul(res[j], root); if (j + 1 < res.length) res[j] ^= res[j + 1]; }
      root = gfMul(root, 0x02);
    }
    return res;
  }
  function rsRemainder(data, div) {
    var res = div.map(function () { return 0; });
    data.forEach(function (b) {
      var f = b ^ res.shift(); res.push(0);
      div.forEach(function (c, i) { res[i] ^= gfMul(c, f); });
    });
    return res;
  }

  function qr(text, ecl) {
    ecl = QR_ECC[ecl] ? ecl : 'M';
    var bytes = [], s = unescape(encodeURIComponent(String(text)));
    for (var i = 0; i < s.length; i++) bytes.push(s.charCodeAt(i));
    var ver = 0, cap = 0;
    for (var v = 1; v <= 40; v++) {
      cap = Math.floor(qrRawModules(v) / 8) - QR_ECC[ecl][v - 1] * QR_BLOCKS[ecl][v - 1];
      if (4 + (v < 10 ? 8 : 16) + bytes.length * 8 <= cap * 8) { ver = v; break; }
    }
    if (!ver) return null;
    // data bits
    var bits = [];
    function put(val, n) { for (var k = n - 1; k >= 0; k--) bits.push((val >>> k) & 1); }
    put(4, 4); put(bytes.length, ver < 10 ? 8 : 16);
    bytes.forEach(function (b) { put(b, 8); });
    put(0, Math.min(4, cap * 8 - bits.length));
    put(0, (8 - bits.length % 8) % 8);
    var data = [];
    for (i = 0; i < bits.length; i += 8) data.push(parseInt(bits.slice(i, i + 8).join(''), 2));
    for (var pad = 0xEC; data.length < cap; pad ^= 0xEC ^ 0x11) data.push(pad);
    // error correction + interleaving
    var nb = QR_BLOCKS[ecl][ver - 1], el = QR_ECC[ecl][ver - 1], raw = Math.floor(qrRawModules(ver) / 8);
    var nShort = nb - raw % nb, shortLen = Math.floor(raw / nb), div = rsDivisor(el), blocks = [];
    for (var b = 0, k2 = 0; b < nb; b++) {
      var dat = data.slice(k2, k2 + shortLen - el + (b < nShort ? 0 : 1));
      k2 += dat.length;
      var ecc = rsRemainder(dat, div);
      if (b < nShort) dat.push(0);
      blocks.push(dat.concat(ecc));
    }
    var cw = [];
    for (i = 0; i < blocks[0].length; i++) {
      for (b = 0; b < nb; b++) if (i !== shortLen - el || b >= nShort) cw.push(blocks[b][i]);
    }
    // matrix
    var size = ver * 4 + 17, mod = [], fn = [];
    for (i = 0; i < size; i++) { mod.push(new Array(size).fill(false)); fn.push(new Array(size).fill(false)); }
    function setF(x, y, d) { mod[y][x] = d; fn[y][x] = true; }
    for (i = 0; i < size; i++) { setF(6, i, i % 2 === 0); setF(i, 6, i % 2 === 0); }
    [[3, 3], [size - 4, 3], [3, size - 4]].forEach(function (c) {
      for (var dy = -4; dy <= 4; dy++) for (var dx = -4; dx <= 4; dx++) {
        var x = c[0] + dx, y = c[1] + dy, dist = Math.max(Math.abs(dx), Math.abs(dy));
        if (x >= 0 && x < size && y >= 0 && y < size) setF(x, y, dist !== 2 && dist !== 4);
      }
    });
    if (ver > 1) {
      var na = Math.floor(ver / 7) + 2, step = ver === 32 ? 26 : Math.ceil((ver * 4 + 4) / (na * 2 - 2)) * 2, pos = [6];
      for (var p2 = size - 7; pos.length < na; p2 -= step) pos.splice(1, 0, p2);
      pos.forEach(function (ay, ii) {
        pos.forEach(function (ax, jj) {
          if ((ii === 0 && jj === 0) || (ii === 0 && jj === na - 1) || (ii === na - 1 && jj === 0)) return;
          for (var dy = -2; dy <= 2; dy++) for (var dx = -2; dx <= 2; dx++) setF(ax + dx, ay + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
        });
      });
    }
    function drawFormat(mask) {
      var d = QR_FMT[ecl] << 3 | mask, r = d;
      for (var q = 0; q < 10; q++) r = (r << 1) ^ ((r >>> 9) * 0x537);
      var fb = (d << 10 | r) ^ 0x5412;
      function bit(n) { return ((fb >>> n) & 1) !== 0; }
      for (q = 0; q <= 5; q++) setF(8, q, bit(q));
      setF(8, 7, bit(6)); setF(8, 8, bit(7)); setF(7, 8, bit(8));
      for (q = 9; q < 15; q++) setF(14 - q, 8, bit(q));
      for (q = 0; q < 8; q++) setF(size - 1 - q, 8, bit(q));
      for (q = 8; q < 15; q++) setF(8, size - 15 + q, bit(q));
      setF(8, size - 8, true);
    }
    drawFormat(0);
    if (ver >= 7) {
      var r = ver;
      for (i = 0; i < 12; i++) r = (r << 1) ^ ((r >>> 11) * 0x1F25);
      var vb = ver << 12 | r;
      for (i = 0; i < 18; i++) {
        var bt = ((vb >>> i) & 1) !== 0, a = size - 11 + i % 3, c = Math.floor(i / 3);
        setF(a, c, bt); setF(c, a, bt);
      }
    }
    // codewords, zigzag
    var n = 0;
    for (var right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (var vert = 0; vert < size; vert++) {
        for (var j = 0; j < 2; j++) {
          var x = right - j, y = ((right + 1) & 2) === 0 ? size - 1 - vert : vert;
          if (!fn[y][x] && n < cw.length * 8) { mod[y][x] = ((cw[n >>> 3] >>> (7 - (n & 7))) & 1) !== 0; n++; }
        }
      }
    }
    var MASKS = [
      function (x, y) { return (x + y) % 2 === 0; }, function (x, y) { return y % 2 === 0; },
      function (x) { return x % 3 === 0; }, function (x, y) { return (x + y) % 3 === 0; },
      function (x, y) { return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0; }, function (x, y) { return x * y % 2 + x * y % 3 === 0; },
      function (x, y) { return (x * y % 2 + x * y % 3) % 2 === 0; }, function (x, y) { return ((x + y) % 2 + x * y % 3) % 2 === 0; }
    ];
    function applyMask(m) {
      for (var yy = 0; yy < size; yy++) for (var xx = 0; xx < size; xx++) if (!fn[yy][xx] && MASKS[m](xx, yy)) mod[yy][xx] = !mod[yy][xx];
    }
    function penalty() {
      var score = 0, dark = 0, line, xx, yy;
      function runs(get) {
        for (var a = 0; a < size; a++) {
          line = [];
          for (var c2 = 0; c2 < size; c2++) line.push(get(a, c2));
          for (var st = 0; st < size;) {
            var e = st; while (e < size && line[e] === line[st]) e++;
            if (e - st >= 5) score += e - st - 2;
            st = e;
          }
          var str = line.map(function (d) { return d ? '1' : '0'; }).join('');
          [/(?=00001011101)/g, /(?=10111010000)/g].forEach(function (re) { var m2 = str.match(re); if (m2) score += 40 * m2.length; });
        }
      }
      runs(function (a, c2) { return mod[a][c2]; });
      runs(function (a, c2) { return mod[c2][a]; });
      for (yy = 0; yy < size - 1; yy++) for (xx = 0; xx < size - 1; xx++) {
        var c3 = mod[yy][xx];
        if (c3 === mod[yy][xx + 1] && c3 === mod[yy + 1][xx] && c3 === mod[yy + 1][xx + 1]) score += 3;
      }
      for (yy = 0; yy < size; yy++) for (xx = 0; xx < size; xx++) if (mod[yy][xx]) dark++;
      return score + Math.floor(Math.abs(dark * 20 - size * size * 10) / (size * size)) * 10;
    }
    var best = 0, bestScore = Infinity;
    for (var m = 0; m < 8; m++) {
      applyMask(m); drawFormat(m);
      var sc = penalty();
      if (sc < bestScore) { bestScore = sc; best = m; }
      applyMask(m);
    }
    applyMask(best); drawFormat(best);
    return { size: size, version: ver, mask: best, dark: function (x, y) { return mod[y][x]; } };
  }

  function qrSvg(text, px) {
    var q = qr(text, 'M');
    if (!q) return null;
    var n = q.size + 8, d = '';
    for (var y = 0; y < q.size; y++) {
      for (var x = 0; x < q.size; x++) if (q.dark(x, y)) d += 'M' + (x + 4) + ' ' + (y + 4) + 'h1v1h-1z';
    }
    var svg = P.s('svg', { viewBox: '0 0 ' + n + ' ' + n, width: px || 220, height: px || 220, role: 'img', 'aria-label': t('کد QR لینک اشتراک'),
      'shape-rendering': 'crispEdges', class: 'pcdn-qr-svg', 'data-qr-version': q.version });
    svg.appendChild(P.s('rect', { width: n, height: n, style: 'fill:var(--pc-qr-bg)' }));
    svg.appendChild(P.s('path', { d: d, style: 'fill:var(--pc-qr-fg)' }));
    return svg;
  }
  P.qr = qr;

  // ------------------------------------------------------------------ model

  var DEFAULT = { enabled: false, paths: [], idle_timeout: 3600, per_connection_mbps: 0, max_connections_per_ip: 0, allowed_countries: [], fallback: 'origin' };
  var PATH_RE = /^\/[A-Za-z0-9._~\/-]{1,200}$/;
  var PROTOCOLS = [
    ['grpc', 'gRPC', t('پایدار و سریع: چند جریان روی یک اتصال HTTP/2. برای بیشتر کاربران بهترین انتخاب است.'), 'zap', t('پیشنهادی')],
    ['xhttp', 'XHTTP', t('جدیدترین روش Xray؛ ترافیک شبیه درخواست‌های عادی وب است و در شبکه‌های سخت‌گیر خوب کار می‌کند. فقط کلاینت‌های با هسته Xray.'), 'sparkles', t('جدیدترین')],
    ['ws', 'WebSocket', t('سازگارترین: تقریباً همه کلاینت‌ها (v2rayNG، v2rayN، Hiddify، NekoBox، sing-box) پشتیبانی می‌کنند.'), 'link', t('سازگارترین')],
    ['httpupgrade', 'HTTPUpgrade', t('مثل WebSocket ولی سبک‌تر (بدون فریم‌بندی WebSocket)؛ در Xray و sing-box نسخه‌های جدید.'), 'up'],
    ['h2', t('HTTP/2 خام (h2)'), t('جریان‌های HTTP/2 مستقیم به سرور h2c شما (XHTTP در حالت stream-one)؛ برای کاربران حرفه‌ای.'), 'code']
  ];
  var PROTO = {};
  PROTOCOLS.forEach(function (p) { PROTO[p[0]] = { label: p[1], desc: p[2], icon: p[3] }; });
  var XHTTP_MODES = [['auto', t('auto — خودکار (پیشنهادی)')], ['packet-up', t('packet-up — سازگارترین با شبکه‌های محدود')], ['stream-up', t('stream-up — سریع‌تر')]];
  var FALLBACKS = [
    ['origin', t('سایت عادی'), t('مسیرهای دیگر مثل همیشه به سرور اصلی سایت شما می‌روند. وقتی روی این دامنه سایت واقعی دارید.'), 'globe'],
    ['decoy', t('صفحه استتار'), t('بقیه مسیرها یک صفحه ساده و خنثی (کد ۲۰۰) می‌بینند تا دامنه شبیه یک سایت معمولی باشد و سرور شما دیده نشود.'), 'eye', t('پیشنهادی')],
    ['404', t('خطای ۴۰۴'), t('همه مسیرهای دیگر پاسخ «یافت نشد» می‌گیرند.'), 'ban']
  ];

  function S() { return A().S; }
  function site() { return S().site; }
  function feats() { return A().features(); }
  function saved() { var c = site().config && site().config.tunnel; return c && typeof c === 'object' ? c : clone(DEFAULT); }
  function fqdn(name) { var d = site().domain; return !name || name === '@' ? d : (name === d || /\.$/.test(name) || name.slice(-d.length - 1) === '.' + d ? name.replace(/\.$/, '') : name + '.' + d); }
  /** Proxied host names of the site (the addresses a tunnel client can connect to). */
  function hosts() {
    var out = [];
    (site().records || []).forEach(function (r) {
      if (r && r.proxied && (r.type === 'A' || r.type === 'AAAA' || r.type === 'CNAME')) {
        var n = fqdn(String(r.name || '@'));
        if (out.indexOf(n) < 0) out.push(n);
      }
    });
    return out;
  }
  function recordOf(host) {
    return (site().records || []).filter(function (r) { return r && r.proxied && fqdn(String(r.name || '@')) === host; })[0] || null;
  }
  function pools() {
    var c = site().config && site().config.pools;
    return c && Array.isArray(c.pools) ? c.pools.filter(function (p) { return p && p.name; }) : [];
  }
  function rnd(n, abc) {
    var out = '', a = new Uint8Array(n);
    try { window.crypto.getRandomValues(a); } catch (e) { for (var i = 0; i < n; i++) a[i] = Math.floor(Math.random() * 256); }
    for (var j = 0; j < n; j++) out += abc.charAt(a[j] % abc.length);
    return out;
  }
  function randomPath() { return '/' + rnd(18, 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'); }
  function uuid4() {
    if (window.crypto && typeof window.crypto.randomUUID === 'function') return window.crypto.randomUUID();
    var x = rnd(32, '0123456789abcdef').split('');
    x[12] = '4'; x[16] = '89ab'.charAt(parseInt(x[16], 16) % 4);
    x = x.join('');
    return x.slice(0, 8) + '-' + x.slice(8, 12) + '-' + x.slice(12, 16) + '-' + x.slice(16, 20) + '-' + x.slice(20);
  }
  function newId(list, proto) {
    for (var i = 1; ; i++) {
      var id = proto + i;
      if (!list.some(function (p) { return p.id === id; })) return id;
    }
  }
  function capMbps() { return Math.max(0, Number(feats().tunnel_max_mbps) || 0); }
  /** Wave 13 (§22): the tunnel profile when this controller serves it (tguide.js), else null — gates every wave-13 piece. */
  function tp() { return P.tprofile && P.tprofile.ok() === true ? P.tprofile : null; }
  /** SPEC §22.4 plan feature max_tunnel_origins (1..10); null when the controller does not know it (older controller). */
  function maxOrigins() { var m = feats().max_tunnel_origins; return m === undefined || m === null ? null : Math.max(1, Math.min(10, Math.floor(Number(m) || 1))); }
  function multi(p) { return !!(p && Array.isArray(p.origins) && p.origins.length); }
  var BALANCES = [['failover', t('جایگزینی خودکار (اصلی/پشتیبان)'), t('همه‌ی اتصال‌ها به سرور اول می‌روند؛ اگر از دسترس خارج شد اتصال‌های تازه به سرور بعدی می‌روند.'), 'refresh', t('پیشنهادی')],
    ['round_robin', t('چرخشی'), t('اتصال‌های تازه به نسبت وزن بین سرورهای اصلی پخش می‌شوند.'), 'lb'],
    ['sticky_ip', t('ثابت برای هر IP کاربر'), t('هر کاربر (بر اساس IP) همیشه به یک سرور مشخص می‌رسد.'), 'link']];
  var BAL = {};
  BALANCES.forEach(function (b) { BAL[b[0]] = b[1]; });
  function maxPaths() { var m = feats().max_tunnel_paths; return m === undefined || m === null ? 10 : Math.max(0, Number(m) || 0); }

  function originText(p) {
    if (multi(p)) return t('{0} سرور مبدأ — {1}', num(p.origins.length), BAL[p.balance || 'failover'] || BAL.failover);
    if (p.pool) return t('استخر توزیع بار «') + p.pool + '»';
    if (p.origin) return (p.origin.address || '?') + ':' + (p.origin.port || (p.origin.tls ? 443 : 80)) + (p.origin.tls ? ' (TLS)' : '');
    return t('همان سرور اصلی سایت');
  }
  /** Where the tunnel reaches the customer's server: {port, tls, note}. */
  function listenOf(p, host) {
    if (multi(p)) {
      var prim = p.origins.filter(function (x) { return x && !x.backup; })[0] || p.origins[0];
      return { port: Number(prim.port) || (prim.tls ? 443 : 80), tls: !!prim.tls };
    }
    if (p.origin) return { port: Number(p.origin.port) || (p.origin.tls ? 443 : 80), tls: !!p.origin.tls };
    var sslc = (site().config && site().config.ssl) || {}, https = sslc.origin_protocol === 'https';
    if (p.pool) {
      var pl = pools().filter(function (x) { return x.name === p.pool; })[0];
      var o = pl && (pl.origins || []).filter(function (x) { return !x.backup; })[0];
      return { port: o && o.port ? Number(o.port) : (pl && pl.protocol === 'https' ? 443 : 80), tls: !!(pl && pl.protocol === 'https') };
    }
    var r = host ? recordOf(host) : null;
    return { port: r && r.origin_port ? Number(r.origin_port) : (https ? 443 : 80), tls: https };
  }

  /** SPEC §22.4: every listen port the CDN may use for this path (each origin of a multi-origin path; the checker accepts all). */
  function portsOf(p, host) {
    if (multi(p)) {
      var out = [];
      p.origins.forEach(function (x) { var v = Number(x && x.port) || (x && x.tls ? 443 : 80); if (out.indexOf(v) < 0) out.push(v); });
      return out;
    }
    return [listenOf(p, host).port];
  }

  /**
   * Ready-to-use configs for one path.
   * o = {protocol, path, host, uuid, port (origin listen port), tls (origin TLS), mode (xhttp), remark,
   *      rec (wave 13 recommended values, tguide.js recommend(); optional), h3 (xhttp over HTTP/3 variant; optional)}
   * → {link, xray (server config.json text), singbox (outbound JSON text | null), serviceName, alpn}
   */
  function tunnelConfig(o) {
    var proto = o.protocol, path = String(o.path || '/'), host = String(o.host || ''), uuid = String(o.uuid || '');
    var svc = path.replace(/^\/+/, '');
    var mode = proto === 'h2' ? 'stream-one' : (o.mode || 'auto');
    var alpn = proto === 'grpc' || proto === 'h2' ? ['h2'] : proto === 'xhttp' ? (o.h3 ? ['h3'] : ['h2', 'http/1.1']) : ['http/1.1'];
    var rec = o.rec && typeof o.rec === 'object' ? o.rec : null;
    var extra = rec && proto === 'xhttp' && P.tguide ? P.tguide.xmuxExtra(rec.xmux) : null;
    var q = [['encryption', 'none'], ['security', 'tls'], ['sni', host], ['fp', 'chrome'], ['alpn', alpn.join(',')],
      ['type', proto === 'h2' ? 'xhttp' : proto]];
    if (proto === 'grpc') q.push(['serviceName', svc], ['mode', 'gun']);
    else if (proto === 'xhttp' || proto === 'h2') q.push(['host', host], ['path', path], ['mode', mode]);
    // §22.11: the recommended XMUX values travel in the share link's `extra` (Xray share-link format); stability only
    if (extra) q.push(['extra', JSON.stringify(extra)]);
    else q.push(['host', host], ['path', path]);
    var link = 'vless://' + uuid + '@' + host + ':443?' + q.map(function (kv) { return kv[0] + '=' + encodeURIComponent(kv[1]); }).join('&') +
      '#' + encodeURIComponent(o.remark || host);

    // Xray server (the origin): the CDN terminates the visitor TLS, so the inbound only has TLS when origin.tls is on.
    var ss = { network: proto === 'h2' ? 'xhttp' : proto, security: o.tls ? 'tls' : 'none' };
    if (o.tls) {
      ss.tlsSettings = { alpn: proto === 'grpc' || proto === 'h2' ? ['h2'] : ['http/1.1'],
        certificates: [{ certificateFile: '/etc/ssl/pcdn/fullchain.pem', keyFile: '/etc/ssl/pcdn/privkey.pem' }] };
    }
    if (proto === 'grpc') ss.grpcSettings = { serviceName: svc };
    else if (proto === 'ws') ss.wsSettings = rec && rec.ws_heartbeat_s ? { path: path, heartbeatPeriod: rec.ws_heartbeat_s } : { path: path };
    else if (proto === 'httpupgrade') ss.httpupgradeSettings = { path: path };
    else ss.xhttpSettings = { path: path, mode: proto === 'h2' ? 'stream-one' : 'auto' };
    var xray = {
      log: { loglevel: 'warning' },
      inbounds: [{
        tag: 'pcdn-' + (o.id || proto), listen: '0.0.0.0', port: Number(o.port) || 80, protocol: 'vless',
        settings: { clients: [{ id: uuid }], decryption: 'none' },
        streamSettings: ss,
        sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'] }
      }],
      outbounds: [{ protocol: 'freedom', tag: 'direct' }]
    };

    // sing-box client outbound (sing-box has no XHTTP transport).
    var sb = null;
    if (proto === 'grpc' || proto === 'ws' || proto === 'httpupgrade') {
      var gr = rec && rec.grpc ? rec.grpc : null;
      var tr = proto === 'grpc' ? (gr ? { type: 'grpc', service_name: svc, idle_timeout: gr.idle_timeout_s + 's', ping_timeout: gr.health_check_timeout_s + 's', permit_without_stream: false }
        : { type: 'grpc', service_name: svc })
        : proto === 'ws' ? { type: 'ws', path: path, headers: { Host: host } } : { type: 'httpupgrade', host: host, path: path };
      sb = { type: 'vless', tag: 'pcdn-' + (o.id || proto), server: host, server_port: 443, uuid: uuid,
        tls: { enabled: true, server_name: host, alpn: alpn, utls: { enabled: true, fingerprint: 'chrome' } }, transport: tr };
      if (rec) sb.multiplex = { enabled: false };
    }
    return { link: link, xray: JSON.stringify(xray, null, 2), singbox: sb ? JSON.stringify(sb, null, 2) : null, serviceName: svc, alpn: alpn };
  }
  P.tunnelConfig = tunnelConfig;
  // Wave 7: the config checker (tunnelq.js) compares a pasted server config with these.
  P.tunnelListen = listenOf;
  P.tunnelPorts = portsOf;
  P.tunnelHosts = hosts;

  // ------------------------------------------------------------------ small pieces

  function protoBadge(proto) {
    var p = PROTO[proto] || { label: proto };
    return h('span', { className: 'pcdn-tn-proto pcdn-tn-' + proto, text: p.label });
  }
  function codeBlock(text, label, id) {
    return h('figure', { className: 'pcdn-codeblock', 'data-code': id || null },
      h('figcaption', null, icon('terminal'), h('span', { dir: 'ltr', text: label }),
        P.copyBtn(text, t('کپی ') + label, { text: t('کپی'), cls: 'pcdn-copy-code', done: t('کپی شد') })),
      h('pre', { dir: 'ltr', tabindex: '0' }, h('code', { text: text })));
  }
  function dl(rows) {
    return h('dl', { className: 'pcdn-dl pcdn-dl-cols' }, rows.map(function (r) { return h('div', null, h('dt', { text: r[0] }), h('dd', null, r[1])); }));
  }

  // ------------------------------------------------------------------ path editor (drawer)

  function blankOrigin(tls) { return { address: '', port: 2053, tls: !!tls, sni: null, verify: false, weight: 1, backup: false }; }

  /**
   * A wave-13 controller always returns origins / balance / health / idle_timeout on every path (null when unused): keep the key as
   * null then (no spurious «unsaved» state); an older controller never had it, so the key stays absent (extra="forbid").
   */
  function unset(x, k) { if (Object.prototype.hasOwnProperty.call(x, k) && (x[k] !== null || tp())) x[k] = null; }

  /** ctx = {idle: the section's (draft) idle_timeout} — for the per-path idle timeout and keepalive hint (wave 13). */
  function pathEditor(orig, list, done, ctx) {
    ctx = ctx || {};
    var isNew = !orig;
    var x = orig ? clone(orig) : { id: '', path: randomPath(), protocol: 'grpc', origin: null, pool: null };
    var st = { mode: multi(x) ? 'multi' : x.pool ? 'pool' : x.origin ? 'custom' : 'site', ownIdle: typeof x.idle_timeout === 'number' };
    var maxO = maxOrigins();
    var first = multi(x) ? x.origins[0] : null;
    // §22.4: every origin of a path shares tls / verify / sni — edited once here, copied to each origin on «تأیید»
    var mo = { tls: !!(first && first.tls), sni: first ? first.sni || null : null, verify: !!(first && first.verify) };
    var pl = pools(), lb = !!feats().load_balancer && pl.length > 0;
    var d = P.dialog({ title: isNew ? t('مسیر تونل جدید') : t('ویرایش مسیر تونل'), subtitle: t('آدرس مخفی، پروتکل و سرور مقصد این مسیر را تعیین کنید.'), icon: 'tunnel', kind: 'drawer', wide: true });
    d.el.classList.add('pcdn-tn-editor');
    var err = h('div'), holder = h('div', { className: 'pcdn-form' });
    append(d.body, [err, holder]);
    function siteIdle() { return Number(ctx.idle) || 3600; }
    function multiPanel() {
      var n = x.origins.length, full = n >= (maxO || 1);
      var ol = h('ol', { className: 'pcdn-tn-origins' });
      x.origins.forEach(function (o, i) {
        if (o.weight === undefined || o.weight === null) o.weight = 1;
        ol.appendChild(h('li', { className: 'pcdn-tn-origin' + (o.backup ? ' is-backup' : ''), 'data-origin': String(i) },
          h('span', { className: 'pcdn-rule-no', 'aria-hidden': 'true', text: num(i + 1) }),
          h('div', { className: 'pcdn-tn-origin-fields' },
            P.input(o, 'address', t('آدرس سرور'), { placeholder: '185.1.2.3', cls: 'pcdn-tn-o-addr' }),
            P.input(o, 'port', t('پورت'), { type: 'number', min: 1, max: 65535, cls: 'pcdn-tn-o-port' }),
            P.input(o, 'weight', t('وزن'), { type: 'number', min: 1, max: 100, cls: 'pcdn-tn-o-weight' }),
            P.toggle(o, 'backup', t('پشتیبان'), { cls: 'pcdn-tn-o-backup', onchange: draw })),
          h('div', { className: 'pcdn-tn-origin-ctl' },
            P.iconBtn('up', t('بالا بردن سرور {0}', num(i + 1)), function () { if (i > 0) { x.origins.splice(i - 1, 0, x.origins.splice(i, 1)[0]); draw(); } }, { write: true, disabled: i === 0, cls: 'pcdn-tn-o-up' }),
            P.iconBtn('down', t('پایین بردن سرور {0}', num(i + 1)), function () { if (i < x.origins.length - 1) { x.origins.splice(i + 1, 0, x.origins.splice(i, 1)[0]); draw(); } }, { write: true, disabled: i === x.origins.length - 1, cls: 'pcdn-tn-o-down' }),
            P.iconBtn('trash', t('حذف سرور ') + num(i + 1), function () { x.origins.splice(i, 1); draw(); }, { write: true, disabled: x.origins.length <= 2, cls: 'is-danger pcdn-tn-o-del' }))));
      });
      var add = P.btn(t('افزودن سرور'), { icon: 'plus', size: 'sm', write: true, cls: 'pcdn-tn-o-add', disabled: full, title: full ? t('به سقف مبدأهای پلن رسیده‌اید') : null,
        onclick: function () { x.origins.push(blankOrigin(mo.tls)); draw(); } });
      var http = x.health.type === 'http';
      return h('div', { className: 'pcdn-subpanel pcdn-tn-multi', 'data-multi': '1' },
        h('div', { className: 'pcdn-tn-multi-head' }, h('h5', { text: t('سرورهای مبدأ') }),
          h('span', { className: 'pcdn-limit' + (n > (maxO || 1) ? ' is-full' : ''), 'data-origins-limit': String(maxO || 1) }, t('{0} از {1} سرور', num(n), num(maxO || 1))), add),
        h('p', { className: 'pcdn-muted pcdn-small', text: t('ترتیب مهم است: در «جایگزینی خودکار» سرور اول اصلی است و بقیه به ترتیب جایگزین می‌شوند. اتصال‌های برقرار جابه‌جا نمی‌شوند؛ فقط اتصال‌های تازه به سرور سالم بعدی می‌روند.') }),
        ol,
        n > (maxO || 1) ? P.alertBox('warning', t('پلن فعلی فقط {0} مبدأ برای هر مسیر اجازه می‌دهد؛ سرورهای اضافه را حذف کنید.', num(maxO || 1))) : null,
        P.toggle(mo, 'tls', t('اتصال CDN به سرورها با TLS'), { help: t('برای همه‌ی سرورهای این مسیر یکسان است.'), onchange: draw }),
        mo.tls ? h('div', { className: 'pcdn-grid' },
          P.input(mo, 'sni', t('SNI (اختیاری)'), { nullable: true, placeholder: site().domain, help: t('خالی = نام دامنه سایت. باید با گواهی سرور شما بخواند.') }),
          P.toggle(mo, 'verify', t('بررسی اعتبار گواهی سرور'), { help: t('فقط اگر گواهی معتبر (مثلاً Let\'s Encrypt) روی سرور دارید.') })) : null,
        P.choice(x, 'balance', t('روش توزیع'), BALANCES, { cols: 1, onchange: draw }),
        P.choice(x.health, 'type', t('بررسی سلامت'), [['tcp', t('اتصال TCP (پیشنهادی)'), t('هر چند ثانیه اتصال TCP به پورت هر سرور؛ برای Xray / sing-box مناسب است.'), 'zap'],
          ['http', 'HTTP', t('درخواست HTTP به مسیر زیر؛ فقط اگر سرور شما به آن پاسخ معمولی می‌دهد.'), 'globe']], { cols: 2, onchange: draw }),
        h('div', { className: 'pcdn-grid' },
          http ? P.input(x.health, 'path', t('مسیر بررسی'), { placeholder: '/' }) : null,
          http ? P.input(x.health, 'expect', t('کدهای سالم'), { placeholder: '2xx,3xx,4xx' }) : null,
          P.input(x.health, 'interval', t('فاصله‌ی بررسی'), { type: 'number', min: 5, max: 300, suffix: t('ثانیه'), suffixRtl: true }),
          P.input(x.health, 'timeout', t('مهلت هر بررسی'), { type: 'number', min: 1, max: 30, suffix: t('ثانیه'), suffixRtl: true })),
        http && x.protocol === 'grpc' ? P.alertBox('warning', t('بیشتر سرورهای gRPC به درخواست HTTP معمولی پاسخ ۲xx نمی‌دهند؛ نوع بررسی را tcp بگذارید.')) : null);
    }
    function idlePanel() {
      if (!tp()) return null;
      var eff = st.ownIdle && Number(x.idle_timeout) > 0 ? Number(x.idle_timeout) : siteIdle();
      var k = P.tguide.keepalive(eff, P.tprofile.edge().client_idle_s);
      var hint = h('p', { className: 'pcdn-muted pcdn-small pcdn-tn-kahint', 'data-keepalive': String(k) },
        t('keepalive پیشنهادی برنامه‌ها برای این مسیر: {0} ثانیه', num(k)));
      return h('div', { className: 'pcdn-subpanel pcdn-tn-idle', 'data-idle': '1' },
        P.toggle(st, 'ownIdle', t('مهلت بیکاری جدا برای این مسیر'), { help: t('خاموش = همان «مهلت بیکاری اتصال» سایت ({0}).', P.dur(siteIdle())),
          onchange: function (v) { if (v && typeof x.idle_timeout !== 'number') x.idle_timeout = siteIdle(); draw(); } }),
        st.ownIdle ? P.duration(x, 'idle_timeout', t('مهلت بیکاری این مسیر'), { min: 60, max: 86400, picks: [[300, t('۵ دقیقه')], [600, t('۱۰ دقیقه')], [3600, t('۱ ساعت')], [21600, t('۶ ساعت')]],
          help: t('اتصال تونلی این مسیر که این مدت هیچ داده‌ای نداشته باشد بسته می‌شود.'),
          oninput: function () {
            var e2 = Number(x.idle_timeout) > 0 ? Number(x.idle_timeout) : siteIdle(), k2 = P.tguide.keepalive(e2, P.tprofile.edge().client_idle_s);
            hint.textContent = t('keepalive پیشنهادی برنامه‌ها برای این مسیر: {0} ثانیه', num(k2));
            hint.setAttribute('data-keepalive', String(k2));
          } }) : null,
        hint);
    }
    function draw() {
      clear(holder);
      var pathIn = P.input(x, 'path', t('مسیر (آدرس مخفی)'), { placeholder: '/my-secret-service', maxlength: 201,
        help: h('span', null, t('با '), ltr('/'), t(' شروع شود؛ فقط حروف انگلیسی، عدد و '), ltr('. _ ~ / -'), t('. هر چه طولانی‌تر و تصادفی‌تر، امن‌تر. '),
          x.protocol === 'grpc' ? h('span', null, t('در gRPC همین مسیر بدون '), ltr('/'), t(' اول، serviceName است.')) : null) });
      var gen = P.btn(t('ساخت مسیر تصادفی'), { icon: 'refresh', size: 'sm', write: true, cls: 'pcdn-tn-random', onclick: function () {
        x.path = randomPath();
        var inp = holder.querySelector('.pcdn-tn-pathrow input');
        if (inp) { inp.value = x.path; inp.dispatchEvent(new Event('input', { bubbles: true })); }
      } });
      var modes = [
        ['site', t('همان سرور اصلی سایت'), t('به آدرس و پورت رکورد پروکسی‌شده (و پروتکل «اتصال به سرور اصلی» در SSL) وصل می‌شود.'), 'server'],
        ['custom', t('آدرس و پورت دلخواه'), t('مثلاً سرور جداگانه Xray روی پورت ۲۰۵۳. پیشنهادی وقتی روی همین سرور سایت هم دارید.'), 'edit'],
        ['pool', t('استخر توزیع بار'), lb ? t('بین چند سرور VPN تقسیم می‌شود و سرور خراب کنار گذاشته می‌شود.') : t('ابتدا در بخش «توزیع بار» یک استخر بسازید (در پلن شما: ') + (feats().load_balancer ? t('فعال') : t('غیرفعال')) + ').', 'lb']
      ];
      // §22.4: inline origins with failover — offered when the plan allows more than one origin per path (or the path already has them)
      if (maxO !== null && (maxO > 1 || multi(x))) modes.push(['multi', t('چند سرور مبدأ'), t('دو تا {0} سرور VPN با جایگزینی خودکار وقتی یکی از دسترس خارج شود.', num(Math.max(2, maxO))), 'refresh', t('پایدارتر')]);
      append(holder, [
        h('div', { className: 'pcdn-tn-pathrow' }, pathIn, gen),
        P.choice(x, 'protocol', t('پروتکل'), PROTOCOLS, { cols: 2, onchange: draw }),
        P.choice(st, 'mode', t('سرور مقصد (سرور VPN شما)'), modes, { cols: modes.length > 3 ? 2 : 3, onchange: function (v) {
          if (v !== 'multi') { unset(x, 'origins'); unset(x, 'balance'); unset(x, 'health'); }
          if (v === 'custom') { x.origin = x.origin || { address: '', port: 2053, tls: false, sni: null, verify: false }; x.pool = null; }
          else if (v === 'pool') { x.origin = null; x.pool = x.pool || (pl[0] ? pl[0].name : null); }
          else if (v === 'multi') {
            if (!multi(x)) {
              x.origins = x.origin && String(x.origin.address || '').trim() ? [Object.assign(blankOrigin(), x.origin, { weight: 1, backup: false }), blankOrigin(x.origin.tls)] : [blankOrigin(), blankOrigin()];
              mo = { tls: !!x.origins[0].tls, sni: x.origins[0].sni || null, verify: !!x.origins[0].verify };
            }
            x.origin = null; x.pool = null;
            x.balance = x.balance || 'failover';
            x.health = x.health && typeof x.health === 'object' ? x.health : { type: 'tcp', interval: 10, timeout: 3, path: '/', expect: '2xx,3xx,4xx' };
          } else { x.origin = null; x.pool = null; }
          draw();
        } }),
        maxO === 1 && !multi(x) ? h('div', { className: 'pcdn-tn-upsell-origins', 'data-tn-upsell': 'origins' }, P.alertBox('info', [h('strong', { text: t('چند سرور مبدأ با جایگزینی خودکار: ') }),
          t('برای چند سرور مبدأ پلن را ارتقا دهید.')], { icon: 'sparkles' })) : null,
        st.mode === 'custom' ? h('div', { className: 'pcdn-subpanel' },
          h('div', { className: 'pcdn-grid' },
            P.input(x.origin, 'address', t('آدرس سرور'), { placeholder: '185.1.2.3', help: t('IPv4، IPv6 یا نام میزبان.') }),
            P.input(x.origin, 'port', t('پورت'), { type: 'number', min: 1, max: 65535, placeholder: x.origin.tls ? '443' : '80' })),
          P.toggle(x.origin, 'tls', t('اتصال CDN به سرور با TLS'), { help: t('معمولاً خاموش: CDN خودش TLS بازدیدکننده را باز می‌کند و سرور Xray بدون TLS گوش می‌دهد (ساده‌تر، بدون نیاز به گواهی روی سرور).'), onchange: draw }),
          x.origin.tls ? h('div', { className: 'pcdn-grid' },
            P.input(x.origin, 'sni', t('SNI (اختیاری)'), { nullable: true, placeholder: site().domain, help: t('خالی = نام دامنه سایت. باید با گواهی سرور شما بخواند.') }),
            P.toggle(x.origin, 'verify', t('بررسی اعتبار گواهی سرور'), { help: t('فقط اگر گواهی معتبر (مثلاً Let\'s Encrypt) روی سرور دارید.') })) : null) : null,
        st.mode === 'pool' ? (lb ? P.select(x, 'pool', t('استخر'), pl.map(function (p) { return [p.name, p.name + ' (' + num((p.origins || []).length) + t(' سرور)')]; }))
          : P.alertBox('warning', [t('هنوز استخری ندارید. '), A().goLink('pools', t('ساخت استخر در «توزیع بار»'))])) : null,
        st.mode === 'multi' ? multiPanel() : null,
        idlePanel(),
        x.protocol === 'grpc' && /\/.*\//.test(x.path) ? P.alertBox('warning', t('برای gRPC مسیر تک‌بخشی (بدون / میانی) بگذارید؛ بعضی کلاینت‌ها serviceName چندبخشی را پشتیبانی نمی‌کنند.')) : null,
        x.protocol === 'h2' ? P.alertBox('info', t('حالت h2: سرور شما باید HTTP/2 بدون TLS (h2c) یا با TLS را بپذیرد؛ در Xray، ورودی XHTTP با حالت stream-one.')) : null
      ]);
      A().lockWrites(holder);
    }
    draw();
    function multiProblem() {
      var n = x.origins.length, seen = {};
      if (n < 2) return t('برای چند سرور مبدأ دست‌کم ۲ سرور لازم است؛ برای یک سرور «آدرس و پورت دلخواه» را انتخاب کنید.');
      if (n > (maxO || 1)) return t('حداکثر {0} مبدأ برای هر مسیر تونل در پلن شما مجاز است.', num(maxO || 1));
      for (var i = 0; i < n; i++) {
        var o = x.origins[i], a = String(o.address || '').trim();
        if (!a || /\s/.test(a)) return t('آدرس سرور {0} را وارد کنید.', num(i + 1));
        if (!(Number(o.port) >= 1 && Number(o.port) <= 65535 && Math.floor(Number(o.port)) === Number(o.port))) return t('پورت سرور {0} باید عددی بین ۱ و ۶۵۵۳۵ باشد.', num(i + 1));
        if (!(Number(o.weight) >= 1 && Number(o.weight) <= 100 && Math.floor(Number(o.weight)) === Number(o.weight))) return t('وزن سرور {0} باید عددی بین ۱ و ۱۰۰ باشد.', num(i + 1));
        var key = a.toLowerCase() + ':' + Number(o.port);
        if (seen[key]) return t('هر سرور (آدرس و پورت) فقط یک بار می‌تواند در فهرست باشد.');
        seen[key] = true;
      }
      if (!x.origins.some(function (o) { return !o.backup; })) return t('دست‌کم یک سرور باید اصلی (غیر پشتیبان) باشد.');
      var hc = x.health, iv = Number(hc.interval), to = Number(hc.timeout);
      if (!(iv >= 5 && iv <= 300) || !(to >= 1 && to <= 30) || to >= iv || Math.floor(iv) !== iv || Math.floor(to) !== to) return t('فاصله‌ی بررسی سلامت ۵ تا ۳۰۰ ثانیه و مهلت هر بررسی ۱ تا ۳۰ ثانیه و کمتر از فاصله باشد.');
      if (hc.type === 'http' && !/^\/\S{0,200}$/.test(String(hc.path || ''))) return t('مسیر بررسی HTTP باید با / شروع شود.');
      return null;
    }
    var ok = P.btn(t('تأیید'), { kind: 'primary', icon: 'check', write: true, cls: 'pcdn-drawer-ok', onclick: function () {
      clear(err);
      x.path = String(x.path || '').trim();
      var problem = null;
      if (!PATH_RE.test(x.path)) problem = t('مسیر باید با / شروع شود و فقط حروف انگلیسی، عدد و . _ ~ / - داشته باشد (حداکثر ۲۰۰ کاراکتر).');
      else if (/^\/__pcdn/i.test(x.path)) problem = t('مسیرهای /__pcdn رزرو شده‌اند.');
      else if (list.some(function (p) { return p !== orig && p.path === x.path; })) problem = t('این مسیر قبلاً برای مسیر دیگری استفاده شده است.');
      else if (st.mode === 'custom' && !String(x.origin.address || '').trim()) problem = t('آدرس سرور مقصد را وارد کنید.');
      else if (st.mode === 'custom' && !(Number(x.origin.port) >= 1 && Number(x.origin.port) <= 65535)) problem = t('پورت باید عددی بین ۱ و ۶۵۵۳۵ باشد.');
      else if (st.mode === 'pool' && !x.pool) problem = t('یک استخر انتخاب کنید.');
      else if (st.mode === 'multi') problem = multiProblem();
      if (!problem && tp() && st.ownIdle && !(Number(x.idle_timeout) >= 60 && Number(x.idle_timeout) <= 86400 && Math.floor(Number(x.idle_timeout)) === Number(x.idle_timeout))) {
        problem = t('مهلت بیکاری مسیر باید بین ۶۰ ثانیه و ۱ روز باشد.');
      }
      if (problem) { err.appendChild(P.alertBox('danger', problem)); return; }
      if (x.origin) { x.origin.address = String(x.origin.address).trim(); x.origin.port = Number(x.origin.port); if (!x.origin.tls) { x.origin.sni = null; x.origin.verify = false; } }
      if (st.mode === 'multi') {
        x.origins = x.origins.map(function (o) {
          return { address: String(o.address).trim(), port: Number(o.port), tls: !!mo.tls, sni: mo.tls && mo.sni ? String(mo.sni).trim() || null : null,
            verify: !!(mo.tls && mo.verify), weight: Number(o.weight) || 1, backup: !!o.backup };
        });
        var hc = x.health;
        x.health = hc.type === 'http' ? { type: 'http', interval: Number(hc.interval), timeout: Number(hc.timeout), path: String(hc.path || '/'), expect: String(hc.expect || '2xx,3xx,4xx') }
          : { type: 'tcp', interval: Number(hc.interval), timeout: Number(hc.timeout) };
        x.origin = null; x.pool = null;
      }
      // per-path idle timeout only when set (an older controller never receives the key)
      if (!tp() || !st.ownIdle) unset(x, 'idle_timeout');
      else x.idle_timeout = Number(x.idle_timeout);
      if (!x.id) x.id = newId(list, x.protocol);
      d.close(true);
      done(x);
    } });
    append(d.foot, [ok, P.btn(t('انصراف'), { onclick: function () { d.close(); } })]);
    A().lockWrites(d.el);
    d.focusFirst();
  }

  // ------------------------------------------------------------------ client apps: short steps next to the link / QR (Wave 7, §15.7)

  /** App picker + Persian steps for v2rayNG, NekoBox, Hiddify, Streisand, v2rayN, sing-box, Shadowrocket (data: tutorials.js). */
  function appGuide(p, st) {
    var apps = Array.isArray(window.PCDN_TUNNEL_APPS) ? window.PCDN_TUNNEL_APPS : [];
    if (!apps.length) return null;
    st = st || {};
    var cur = apps.some(function (a) { return a.id === st.app; }) ? st.app : apps[0].id;
    var body = h('div', { className: 'pcdn-tn-app-body', 'aria-live': 'polite' });
    var seg = P.segmented(apps.map(function (a) { return [a.id, a.name]; }), cur, function (v) { cur = st.app = v; draw(); }, t('برنامه‌ی کلاینت'));
    seg.classList.add('pcdn-tn-app-seg');
    seg.setAttribute('data-seg', 'tn-app');
    function draw() {
      Array.prototype.forEach.call(seg.querySelectorAll('.pcdn-seg-btn'), function (b) {
        var on = b.getAttribute('data-value') === cur;
        b.classList.toggle('is-active', on); b.setAttribute('aria-pressed', on ? 'true' : 'false');
      });
      clear(body);
      var a = apps.filter(function (x) { return x.id === cur; })[0] || apps[0];
      // §22.11: one app ↔ protocol table (tguide.js) for the six apps it covers; the app's own entry otherwise (Shadowrocket)
      var sup = P.tguide && P.tguide.SUPPORT[a.id] ? P.tguide.support(a.id, p.protocol) : (a.support || {})[p.protocol] || 'yes', label = PROTO[p.protocol] ? PROTO[p.protocol].label : p.protocol;
      append(body, [
        h('p', { className: 'pcdn-muted pcdn-small', text: a.name + ' — ' + a.os + t(' — هسته ') + a.core }),
        sup === 'no' ? P.alertBox('danger', a.name + t(' پروتکل ') + label + t(' را پشتیبانی نمی‌کند؛ برای کاربران این برنامه یک مسیر gRPC یا WebSocket بسازید.'))
          : sup === 'maybe' ? P.alertBox('warning', t('پشتیبانی ') + a.name + t(' از ') + label + t(' به نسخه‌ی برنامه بستگی دارد؛ اگر وصل نشد برنامه را به‌روز کنید یا از مسیر gRPC / WebSocket استفاده کنید.')) : null,
        h('ol', { className: 'pcdn-ol pcdn-steps-ol pcdn-tn-app-steps', 'data-app': a.id }, (a.steps || []).map(function (x) { return h('li', { text: x }); }))]);
    }
    draw();
    return h('div', { className: 'pcdn-tn-apps', 'data-apps': '1' }, h('h5', { className: 'pcdn-tn-apps-title', text: t('گام‌به‌گام در برنامه‌ی کاربر') }), seg, body);
  }

  // ------------------------------------------------------------------ ready-to-use configs (drawer)

  function configDrawer(p) {
    var key = 'tn-' + A().serviceId + '-' + p.id, mem = {};
    try { mem = JSON.parse(P.store(key) || '{}') || {}; } catch (e) { mem = {}; }
    var hs = hosts();
    var st = { host: hs.indexOf(mem.host) >= 0 ? mem.host : (hs[0] || ''), uuid: /^[0-9a-f-]{36}$/i.test(mem.uuid || '') ? mem.uuid : uuid4(), mode: mem.mode || 'auto' };
    // wave 13 (§22.9 / §22.11): recommended keepalive / mux values in the configs, and the HTTP/3 variant of an xhttp path
    // only when EVERY node serving this site speaks HTTP/3 (profile http3.available) — never a gamble.
    var prof = tp(), pp = prof && !p._new ? prof.path(p.id) : null;
    var h3ok = !!(prof && p.protocol === 'xhttp' && pp && pp.http3 && prof.http3() && prof.http3().available);
    st.h3 = h3ok && mem.h3 === true;
    function recOf() {
      if (!prof) return null;
      var base = pp && pp.protocol === p.protocol && pp.idle_timeout_s === (typeof p.idle_timeout === 'number' ? p.idle_timeout : pp.idle_timeout_s) ? pp
        : (typeof p.idle_timeout === 'number' ? { protocol: p.protocol, idle_timeout: p.idle_timeout } : { protocol: p.protocol });
      return P.tguide.recommend(base, prof.edge(), saved().idle_timeout);
    }
    var d = P.dialog({ title: t('پیکربندی آماده — ') + PROTO[p.protocol].label, subtitle: p.path, icon: 'qr', kind: 'drawer', wide: true });
    d.el.classList.add('pcdn-tn-config');
    var out = h('div', { className: 'pcdn-stack' });
    function remember() { P.store(key, JSON.stringify({ host: st.host, uuid: st.uuid, mode: st.mode, h3: !!st.h3 })); }
    function guideLink() { var a = A().goLink('tguide', t('تنظیمات پیشنهادی هر برنامه')); a.addEventListener('click', function () { d.close(); }); return a; }
    function draw() {
      clear(out);
      remember();
      var lis = listenOf(p, st.host);
      var rec = recOf();
      var c = tunnelConfig({ id: p.id, protocol: p.protocol, path: p.path, host: st.host || 'YOUR-HOST', uuid: st.uuid, port: lis.port, tls: lis.tls,
        mode: st.mode, remark: (st.host || site().domain) + '-' + p.id + (st.h3 ? '-h3' : ''), rec: rec, h3: !!st.h3 });
      var q = qrSvg(c.link, 232);
      append(out, [
        h('section', { className: 'pcdn-tn-share', 'data-share': '1' },
          h('div', { className: 'pcdn-tn-share-text' },
            h('h4', { text: t('۱. لینک اشتراک برای کلاینت') }),
            h('p', { className: 'pcdn-muted', text: t('در v2rayNG، v2rayN، Hiddify، Streisand یا NekoBox: لینک را کپی و «Import from clipboard» را بزنید یا QR را اسکن کنید.') }),
            h('div', { className: 'pcdn-tn-link' }, h('code', { dir: 'ltr', className: 'pcdn-tn-link-text', text: c.link }),
              P.copyBtn(c.link, t('کپی لینک اشتراک'), { text: t('کپی لینک'), cls: 'pcdn-copy-link', done: t('لینک کپی شد') })),
            p.protocol === 'xhttp' || p.protocol === 'h2' ? P.alertBox('info', t('XHTTP فقط در کلاینت‌های با هسته Xray (v2rayNG و v2rayN نسخه‌های جدید، Hiddify با هسته Xray، Streisand) کار می‌کند.')) : null,
            p.protocol === 'xhttp' && prof ? (h3ok
              ? h('div', { className: 'pcdn-tn-h3', 'data-h3': 'available' }, P.toggle(st, 'h3', t('نسخه‌ی HTTP/3 (QUIC)'), {
                help: t('همه‌ی نودهای این سرویس HTTP/3 دارند؛ لینک با alpn=h3 ساخته می‌شود. اگر شبکه‌ی کاربر UDP را محدود می‌کند همان نسخه‌ی h2 را بدهید.'), onchange: draw }))
              : h('div', { className: 'pcdn-tn-h3', 'data-h3': 'unavailable' }, P.alertBox('info', t('همه‌ی نودهای این سرویس هنوز HTTP/3 ندارند؛ نسخه‌ی HTTP/3 این مسیر فعلاً ارائه نمی‌شود.')))) : null,
            rec ? h('p', { className: 'pcdn-muted pcdn-small pcdn-tn-recline', 'data-rec': String(rec.keepalive_s) }, icon('bulb'),
              h('span', { text: t('مقدارهای پایداری (keepalive {0} ثانیه، Mux {1}) در لینک و کانفیگ‌ها گذاشته شده است.', num(rec.keepalive_s), rec.mux === 'off' ? t('خاموش') : t('کم')) + ' ' }),
              guideLink()) : null,
            appGuide(p, st)),
          q ? h('div', { className: 'pcdn-tn-qr', 'data-qr': '1' }, q) : h('p', { className: 'pcdn-muted', text: t('لینک برای QR بیش از حد طولانی است.') })),
        h('section', { 'data-server': '1' },
          h('h4', { text: t('۲. تنظیم سرور شما (Xray)') }),
          h('p', { className: 'pcdn-muted' }, t('این فایل را در '), ltr('/usr/local/etc/xray/config.json'), t(' بگذارید (یا فقط بخش inbounds را به پیکربندی فعلی اضافه کنید) و '), ltr('systemctl restart xray'), t(' را اجرا کنید. '),
            lis.tls ? t('چون اتصال CDN به سرور با TLS است، مسیر گواهی و کلید را اصلاح کنید.') : t('ورودی بدون TLS گوش می‌دهد؛ رمزنگاری بین بازدیدکننده و CDN انجام می‌شود.')),
          codeBlock(c.xray, t('config.json — Xray (سرور)'), 'xray'),
          p.origin || p.pool ? null : P.alertBox('warning', [t('مقصد این مسیر «همان سرور اصلی سایت» است، یعنی پورت '), ltr(String(lis.port)),
            t('. اگر وب‌سرور (nginx/Apache) روی این پورت است، یا مسیر را در وب‌سرور به Xray پاس دهید یا مقصد مسیر را «آدرس و پورت دلخواه» بگذارید. '), A().tutLink('tunnel', t('راهنما'))])),
        h('section', { 'data-singbox': '1' },
          h('h4', { text: t('۳. کلاینت sing-box (اختیاری)') }),
          c.singbox ? codeBlock(c.singbox, 'outbound — sing-box', 'singbox')
            : P.alertBox('info', t('sing-box از XHTTP پشتیبانی نمی‌کند؛ برای این مسیر از لینک اشتراک در کلاینت‌های مبتنی بر Xray استفاده کنید.')))
      ]);
    }
    var hostCtl = hs.length ? P.select(st, 'host', t('نام میزبان (رکورد پروکسی‌شده)'), hs.map(function (x) { return [x, x]; }), { ltr: true, onchange: draw,
      help: t('کلاینت به این نام روی پورت ۴۴۳ وصل می‌شود. رکورد باید در «رکوردها» پروکسی‌شده باشد.') })
      : P.alertBox('warning', [t('هیچ رکورد پروکسی‌شده‌ای ندارید؛ ابتدا یک رکورد (مثلاً '), ltr('vpn'), t(') با پروکسی روشن بسازید. '), A().goLink('dns', t('رکوردها'))]);
    var uuidCtl = P.input(st, 'uuid', t('UUID کاربر'), { oninput: function () { if (/^[0-9a-f-]{36}$/i.test(st.uuid)) draw(); },
      help: t('شناسه کاربر در Xray؛ در سرور و کلاینت باید یکسان باشد. برای هر کاربر یک UUID جدا بسازید.') });
    var newUuid = P.btn(t('UUID جدید'), { icon: 'refresh', size: 'sm', cls: 'pcdn-tn-uuid', onclick: function () {
      st.uuid = uuid4();
      var inp = uuidCtl.querySelector('input'); if (inp) inp.value = st.uuid;
      draw();
    } });
    newUuid.setAttribute('data-ro-ok', '1');
    append(d.body, [
      h('div', { className: 'pcdn-grid pcdn-tn-cfg-ctl' }, hostCtl, h('div', { className: 'pcdn-tn-pathrow' }, uuidCtl, newUuid),
        p.protocol === 'xhttp' ? P.select(st, 'mode', t('حالت XHTTP کلاینت'), XHTTP_MODES, { onchange: draw }) : null),
      out]);
    Array.prototype.forEach.call(d.body.querySelectorAll('input,select'), function (x) { x.setAttribute('data-ro-ok', '1'); });
    draw();
    d.foot.appendChild(P.btn(t('بستن'), { onclick: function () { d.close(); } }));
    d.focusFirst();
    return d;
  }

  // ------------------------------------------------------------------ connectivity check + stats

  function checkCard(Aa) {
    var c = P.card({ title: t('تست اتصال به سرور من'), icon: 'activity', tone: 'success', id: 'check',
      subtitle: t('CDN از سمت سرورهای خود به مقصد هر مسیر وصل می‌شود (TCP و در صورت نیاز TLS) تا مطمئن شوید سرور VPN شما در دسترس است.') });
    var res = h('div', { className: 'pcdn-tn-results', 'aria-live': 'polite' });
    var b = P.btn(t('تست اتصال'), { kind: 'primary', icon: 'refresh', write: true, cls: 'pcdn-tn-check', onclick: function () {
      if (!saved().paths || !saved().paths.length) { P.toast(t('ابتدا یک مسیر تونل بسازید و ذخیره کنید.'), 'warn'); return; }
      clear(res);
      res.appendChild(P.skeleton(2));
      P.busy(b, P.api('POST', 'tunnel/check')).then(function (r) {
        clear(res);
        if (!r.ok) { res.appendChild(P.errorBox(r, t('تست انجام نشد'))); return; }
        var list = (r.data && Array.isArray(r.data.results)) ? r.data.results : [];
        var byId = {};
        (saved().paths || []).forEach(function (p) { byId[p.id] = p; });
        var bad = 0;
        res.appendChild(h('ul', { className: 'pcdn-tn-reslist' }, list.map(function (x) {
          var p = byId[x.id] || { path: x.id, protocol: '' };
          if (!x.ok) bad++;
          return h('li', { className: 'pcdn-tn-res ' + (x.ok ? 'is-ok' : 'is-bad'), 'data-result': x.id },
            h('span', { className: 'pcdn-tn-res-icon pcdn-tone-' + (x.ok ? 'success' : 'danger') }, icon(x.ok ? 'checkCircle' : 'xCircle')),
            h('div', { className: 'pcdn-tn-res-main' },
              h('div', { className: 'pcdn-tn-res-head' }, p.protocol ? protoBadge(p.protocol) : null, h('bdi', { className: 'pcdn-vchip', dir: 'ltr', text: p.path }),
                h('span', { className: 'pcdn-muted pcdn-tn-note', text: P.arrow + ' ' + originText(p) })),
              h('div', { className: 'pcdn-tn-res-msg', text: x.ok ? t('در دسترس است') + (x.ms !== null && x.ms !== undefined ? ' — ' + num(x.ms) + t(' میلی‌ثانیه') : '') : (x.error || t('در دسترس نیست')) })));
        })));
        if (!list.length) res.appendChild(h('p', { className: 'pcdn-muted', text: t('مسیری برای تست وجود ندارد.') }));
        if (bad) {
          res.appendChild(P.alertBox('warning', [h('strong', { text: t('سرور در دسترس نیست؟ ') }),
            t('بررسی کنید سرویس Xray روشن است، پورت درست است، فایروال سرور (ufw / iptables / فایروال دیتاسنتر) آی‌پی‌های CDN را مسدود نکرده، و اگر TLS روشن است SNI و گواهی درست باشند. '),
            Aa.tutLink('tunnel', t('عیب‌یابی تونل'))]));
        }
        P.toast(bad ? num(bad) + t(' مسیر در دسترس نیست.') : t('همه مسیرها در دسترس‌اند.'), bad ? 'warn' : 'success');
      });
    } });
    append(c.body, [h('div', { className: 'pcdn-row-actions' }, b, h('span', { className: 'pcdn-muted pcdn-tn-note', text: t('تست روی تنظیمات ذخیره‌شده انجام می‌شود.') })), res]);
    return c;
  }

  var PERIODS = [['24', t('۲۴ ساعت')], ['168', t('۷ روز')]];
  function statsCard(Aa) {
    var st = S();
    st.tnHours = st.tnHours || '24';
    var c = P.card({ title: t('آمار تونل'), icon: 'chart', tone: 'violet', id: 'tstats',
      actions: P.segmented(PERIODS, st.tnHours, function (v) { st.tnHours = v; draw(); }, t('بازه آمار تونل')) });
    var holder = h('div', { className: 'pcdn-stack' });
    c.body.appendChild(holder);
    function draw() {
      Array.prototype.forEach.call(c.querySelectorAll('.pcdn-seg-btn'), function (b) {
        var on = b.getAttribute('data-value') === st.tnHours;
        b.classList.toggle('is-active', on); b.setAttribute('aria-pressed', on ? 'true' : 'false');
      });
      clear(holder);
      holder.appendChild(P.skeleton(3));
      var hours = st.tnHours;
      P.api('GET', 'tunnel/stats', undefined, { hours: hours }).then(function (r) {
        if (hours !== st.tnHours || !document.body.contains(holder)) return;
        clear(holder);
        if (!r.ok) { holder.appendChild(P.errorBox(r, t('آمار تونل در دسترس نیست'))); return; }
        var data = r.data || {}, list = Array.isArray(data.hours) ? data.hours : [], tx = data.totals || {};
        var secs = list.reduce(function (a, x) { return a + (Number(x.seconds) || 0); }, 0);
        var up = Number(tx.bytes_up) || 0, down = Number(tx.bytes_down) || 0;
        function kpi(ic, tone, label, value, sub, id) {
          return h('div', { className: 'pcdn-kpi', 'data-kpi': id }, h('div', { className: 'pcdn-kpi-top' }, h('span', { className: 'pcdn-kpi-icon pcdn-tone-' + tone }, icon(ic)), h('span', { className: 'pcdn-kpi-label', text: label })),
            h('div', { className: 'pcdn-kpi-value', text: value }), sub ? h('div', { className: 'pcdn-kpi-sub', text: sub }) : null);
        }
        append(holder, h('div', { className: 'pcdn-kpis' },
          kpi('link', 'brand', t('نشست‌ها'), num(tx.sessions || 0), t('جریان‌های تونل پایان‌یافته'), 'sessions'),
          kpi('clock', 'violet', t('ساعت اتصال'), P.num1(secs / 3600), t('مجموع مدت نشست‌ها'), 'hours'),
          kpi('upload', 'warning', t('آپلود'), P.bytes(up), t('از کاربران به سرور شما'), 'up'),
          kpi('download', 'success', t('دانلود'), P.bytes(down), t('از سرور شما به کاربران'), 'down')));
        if (!list.length || up + down === 0) {
          holder.appendChild(P.empty('chart', t('هنوز ترافیک تونلی ثبت نشده است'), t('پس از اتصال اولین کاربر، آمار با چند دقیقه تأخیر اینجا نمایش داده می‌شود.')));
          return;
        }
        // hourly for 24 h, daily for 7 d
        var daily = Number(hours) > 48, buckets = [], labels = [];
        list.forEach(function (x) {
          var k = daily ? String(x.hour || '').slice(0, 10) : String(x.hour || '');
          var last = buckets[buckets.length - 1];
          var v = (Number(x.bytes_up) || 0) + (Number(x.bytes_down) || 0);
          if (last && last.k === k) last.v += v;
          else { buckets.push({ k: k, v: v }); labels.push(P.date(x.hour, daily ? { month: 'short', day: 'numeric' } : { hour: '2-digit', minute: '2-digit' })); }
        });
        var chart = h('div', { className: 'pcdn-tn-chart' });
        holder.appendChild(chart);
        if (P.charts) P.charts.bar(chart, labels, buckets.map(function (b) { return b.v; }), 'var(--pc-c-bytes)', P.bytes, t('نمودار ترافیک تونل'), t('ترافیک (آپلود + دانلود)'));
        var bp = data.by_protocol || {}, keys = Object.keys(bp).filter(function (k) { return PROTO[k] && Number(bp[k]) > 0; })
          .sort(function (a, b) { return bp[b] - bp[a]; });
        if (keys.length) {
          var max = Number(bp[keys[0]]) || 1, sum = keys.reduce(function (a, k) { return a + Number(bp[k]); }, 0);
          holder.appendChild(h('div', { className: 'pcdn-tn-byproto' }, h('h4', { text: t('بر اساس پروتکل') }),
            h('ul', { className: 'pcdn-barlist' }, keys.map(function (k) {
              return h('li', { 'data-proto': k }, h('div', { className: 'pcdn-barlist-row' },
                h('span', { className: 'pcdn-barlist-label' }, h('span', { text: PROTO[k].label })),
                h('span', { className: 'pcdn-barlist-val' }, h('strong', { text: P.bytes(bp[k]) }), h('span', { className: 'pcdn-muted', text: P.pct(bp[k], sum) }))),
              h('span', { className: 'pcdn-barlist-track' }, h('span', { className: 'pcdn-barlist-bar', style: 'width:' + Math.max(1, Math.round(bp[k] * 100 / max)) + '%' })));
            }))));
        }
      });
    }
    draw();
    return c;
  }

  // ------------------------------------------------------------------ page

  /** §22.5: «مهلت بیکاری: …، keepalive پیشنهادی: …» under a path (wave 13 controllers only; drafts computed like the controller). */
  function timeoutsLine(p, d) {
    if (!tp()) return null;
    var rec = P.tguide.recommend(typeof p.idle_timeout === 'number' ? { protocol: p.protocol, idle_timeout: p.idle_timeout } : { protocol: p.protocol },
      P.tprofile.edge(), d.idle_timeout);
    return h('div', { className: 'pcdn-sentence pcdn-tn-timeouts', 'data-tn-timeouts': rec.idle_s + '/' + rec.keepalive_s },
      icon('clock'), h('span', { className: 'pcdn-w', text: t('مهلت بیکاری: ') + P.dur(rec.idle_s) + (typeof p.idle_timeout === 'number' ? t(' (ویژه‌ی این مسیر)') : '') }),
      h('span', { className: 'pcdn-w', text: t('keepalive پیشنهادی: ') + num(rec.keepalive_s) + t(' ثانیه') }));
  }

  function renderTunnel(Aa) {
    var f = feats(), cap = capMbps(), maxP = maxPaths(), hs = hosts(), s = site();
    var notes = [];
    if (!hs.length) notes.push(P.alertBox('warning', [h('strong', { text: t('رکورد پروکسی‌شده ندارید. ') }), t('کلاینت‌ها به یک نام پروکسی‌شده (مثلاً '), ltr('vpn.' + s.domain), t(') روی پورت ۴۴۳ وصل می‌شوند. ابتدا در «رکوردها» یک رکورد A به آی‌پی سرور خود بسازید و پروکسی را روشن کنید. '), Aa.goLink('dns', t('رکوردها'))]));
    if (s.status !== 'active') notes.push(P.alertBox('info', t('تونل پس از فعال شدن سایت روی CDN (تأیید نیم‌سرورها) کار می‌کند؛ تا آن زمان می‌توانید مسیرها را آماده کنید.')));
    else if (!s.ssl || s.ssl.status !== 'active') {
      var needTls = (saved().paths || []).filter(function (p) { return p.protocol === 'grpc' || p.protocol === 'h2'; });
      notes.push(P.alertBox('warning', [h('strong', { text: t('گواهی SSL سایت هنوز فعال نیست. ') }),
        needTls.length ? t('مسیرهای gRPC و HTTP/2 (') + num(needTls.length) + t(' مسیر) فقط روی HTTPS با ALPN h2 کار می‌کنند و تا صدور گواهی وصل نمی‌شوند. ') : t('کلاینت‌ها روی HTTPS (پورت ۴۴۳) وصل می‌شوند. '),
        t('گواهی پس از تأیید نیم‌سرورها خودکار صادر می‌شود.')], { icon: 'lock' }));
    }

    var form = Aa.sectionForm('tunnel', function (d, f2) {
      d.paths = Array.isArray(d.paths) ? d.paths : [];
      d.allowed_countries = Array.isArray(d.allowed_countries) ? d.allowed_countries : [];
      var full = d.paths.length >= maxP;

      var sc = P.card({ title: t('وضعیت تونل'), icon: 'tunnel', id: 'tstate' });
      append(sc.body, [
        P.toggle(d, 'enabled', t('تونل فعال باشد'), { help: t('وقتی روشن است، مسیرهای زیر بدون کش، بدون بافر و بدون WAF و چالش مستقیم به سرور VPN شما می‌رسند.'), onchange: f2.redraw }),
        dl([
          [t('مسیرهای مجاز پلن'), num(maxP)],
          [t('اتصال همزمان هر نود'), f.max_tunnel_connections ? num(f.max_tunnel_connections) : t('نامحدود')],
          [t('نودهای پاسخ‌دهنده'), f.edge_group === 'tunnel' ? t('نودهای مخصوص تونل') : t('نودهای عمومی')]
        ]),
        d.enabled && !d.paths.length ? P.alertBox('info', t('تونل روشن است ولی هنوز مسیری ندارد؛ یک مسیر اضافه کنید.')) : null]);

      var add = P.btn(t('مسیر جدید'), { kind: 'primary', icon: 'plus', size: 'sm', write: true, cls: 'pcdn-tn-add', disabled: full,
        title: full ? t('به سقف ') + num(maxP) + t(' مسیر پلن رسیده‌اید') : null,
        onclick: function () { pathEditor(null, d.paths, function (np) { np._new = true; d.paths.push(np); f2.redraw(); }, { idle: d.idle_timeout }); } });
      var pc = P.card({ title: t('مسیرهای تونل'), icon: 'link', id: 'tpaths', subtitle: t('هر مسیر یک آدرس مخفی روی دامنه شماست که با پروتکل انتخابی به سرور VPN می‌رسد.'),
        actions: [h('span', { className: 'pcdn-limit' + (full ? ' is-full' : '') }, num(d.paths.length) + t(' از ') + num(maxP) + t(' مسیر')), add] });
      if (!d.paths.length) {
        pc.body.appendChild(P.empty('tunnel', t('هنوز مسیری نساخته‌اید'), t('با «مسیر جدید» یک آدرس مخفی (مثلاً ') + randomPath().slice(0, 9) + t('…) بسازید؛ پروتکل پیشنهادی gRPC است.')));
      } else {
        var ol = h('ol', { className: 'pcdn-rules pcdn-tn-paths' });
        d.paths.forEach(function (p, i) {
          var li = h('li', { className: 'pcdn-rule pcdn-tn-path' + (p._new ? ' is-new' : ''), 'data-path': p.id || i },
            h('span', { className: 'pcdn-rule-no', 'aria-hidden': 'true', text: num(i + 1) }),
            h('div', { className: 'pcdn-rule-main' },
              h('div', { className: 'pcdn-rule-name' }, protoBadge(p.protocol), h('bdi', { className: 'pcdn-vchip pcdn-tn-pathval', dir: 'ltr', text: p.path }),
                p._new ? P.badge(t('ذخیره نشده'), 'warning') : null),
              h('div', { className: 'pcdn-sentence' }, h('span', { className: 'pcdn-w', text: t('مقصد:') }), h('span', { className: 'pcdn-w pcdn-w-strong', text: originText(p) }),
                h('span', { className: 'pcdn-mini', dir: 'ltr', text: 'id: ' + (p.id || '—') })),
              timeoutsLine(p, d)),
            h('div', { className: 'pcdn-rule-ctl' },
              h('button', { type: 'button', className: 'pcdn-btn pcdn-btn-sm pcdn-tn-cfg', 'data-ro-ok': '1', onclick: function () { configDrawer(p); } }, icon('qr'), h('span', { text: t('پیکربندی آماده') })),
              P.iconBtn('edit', t('ویرایش مسیر ') + num(i + 1), function () { pathEditor(p, d.paths, function (np) { if (p._new) np._new = true; d.paths[i] = np; f2.redraw(); }, { idle: d.idle_timeout }); }, { write: true }),
              P.iconBtn('trash', t('حذف مسیر ') + num(i + 1), function () { d.paths.splice(i, 1); f2.redraw(); P.toast(t('مسیر از فهرست حذف شد؛ برای اعمال «ذخیره» را بزنید.'), 'info'); }, { write: true, cls: 'is-danger' })));
          P.reg('paths.' + i, li);
          ol.appendChild(li);
        });
        pc.body.appendChild(ol);
      }

      var cc = P.card({ title: t('تنظیمات اتصال'), icon: 'sliders', id: 'tsettings' });
      var iran = P.btn(t('فقط ایران'), { size: 'sm', write: true, cls: 'pcdn-tn-onlyir', onclick: function () { d.allowed_countries = ['IR']; f2.redraw(); } });
      var all = P.btn(t('همه کشورها'), { size: 'sm', write: true, cls: 'pcdn-tn-allcc', onclick: function () { d.allowed_countries = []; f2.redraw(); } });
      var mbps = P.input(d, 'per_connection_mbps', t('سقف سرعت هر اتصال'), { type: 'number', min: 0, max: cap || 100000, suffix: 'Mbps', suffixRtl: false, cls: 'pcdn-tn-mbps',
        help: t('فعلاً اعمال نمی‌شود: محدودسازی سرعت روی جریان‌های تونل (gRPC، WebSocket و …) هنوز در نودها پشتیبانی نمی‌شود.') });
      // Stored value is sent back unchanged; not editable while the edges cannot enforce a per-stream rate on tunnel traffic.
      mbps.querySelector('input').disabled = true;
      mbps.querySelector('input').setAttribute('data-ro-ok', '1');
      append(cc.body, [
        h('div', { className: 'pcdn-grid' },
          P.duration(d, 'idle_timeout', t('مهلت بیکاری اتصال'), { min: 60, max: 86400, picks: [[600, t('۱۰ دقیقه')], [3600, t('۱ ساعت')], [21600, t('۶ ساعت')], [86400, t('۱ روز')]],
            help: t('اتصالی که این مدت هیچ داده‌ای نداشته باشد بسته می‌شود (۶۰ ثانیه تا ۱ روز).') }),
          mbps,
          P.input(d, 'max_connections_per_ip', t('حداکثر اتصال همزمان هر IP'), { type: 'number', min: 0, max: 10000,
            help: t('۰ یعنی نامحدود (روی هر نود). هر جریان WebSocket یا gRPC یک اتصال حساب می‌شود و کلاینت‌ها چند جریان همزمان باز می‌کنند؛ کمتر از ۱۰ نگذارید. اضافه‌ها خطای ۴۲۹ می‌گیرند.') })),
        h('div', { className: 'pcdn-tn-cc' },
          P.tags(d, 'allowed_countries', t('کشورهای مجاز'), { upper: true, placeholder: 'IR', help: t('خالی = همه. کاربران کشورهای دیگر روی مسیرهای تونل خطای ۴۰۳ می‌گیرند (کد دوحرفی ISO، مثل IR).') }),
          h('div', { className: 'pcdn-chips-row' }, iran, all)),
        P.choice(d, 'fallback', t('بقیه مسیرهای دامنه'), FALLBACKS, { cols: 3,
          help: t('صفحه استتار (decoy) یعنی هر کس دامنه را در مرورگر باز کند یک سایت ساده و بی‌خطر می‌بیند، نه خطا یا سرور VPN شما.') })
      ]);
      return [sc, pc, cc];
    }, {
      serialize: function (d) {
        (d.paths || []).forEach(function (p) { delete p._new; });
        return d;
      },
      // wave 13: the profile (timeouts, recommended values) follows the saved paths
      onSaved: function () { if (P.tprofile) P.tprofile.invalidate(); },
      savedMsg: t('تغییرات ذخیره شد و تا چند ثانیه روی همه نودهای تونل اعمال می‌شود.')
    });
    return [notes, form.el, h('div', { className: 'pcdn-grid-2 pcdn-tn-bottom' }, checkCard(Aa), guideCard(Aa)), statsCard(Aa)];
  }

  function guideCard(Aa) {
    var c = P.card({ title: t('راه‌اندازی در ۴ قدم'), icon: 'rocket', id: 'tsteps' });
    append(c.body, [
      h('ol', { className: 'pcdn-ol pcdn-steps-ol' },
        h('li', { text: t('در «رکوردها» یک رکورد A (مثلاً vpn) به آی‌پی سرور VPN بسازید و پروکسی را روشن کنید.') }),
        h('li', { text: t('تونل را روشن کنید، یک مسیر با پروتکل gRPC بسازید و ذخیره کنید.') }),
        h('li', { text: t('از «پیکربندی آماده» فایل config.json سرور Xray را کپی و Xray را راه‌اندازی کنید.') }),
        h('li', { text: t('لینک اشتراک یا QR را در کلاینت (v2rayNG، v2rayN، Hiddify) وارد و وصل شوید.') })),
      Aa.tutLink('tunnel', t('آموزش کامل و عیب‌یابی'))]);
    return c;
  }

  pages.tunnel = {
    title: t('تونل / VPN'), icon: 'tunnel', heading: t('تونل / VPN پشت CDN'),
    desc: t('Xray / V2Ray / sing-box را با gRPC، XHTTP، WebSocket، HTTPUpgrade یا HTTP/2 از طریق نودهای داخل ایران به سرور خود برسانید.'),
    guide: {
      what: t('کاربران به نودهای CDN (داخل ایران) وصل می‌شوند و CDN جریان‌های طولانی را بدون کش و بافر به سرور VPN شما (مثلاً در خارج) می‌رساند؛ آی‌پی سرور شما پنهان می‌ماند.'),
      when: t('وقتی سرور Xray/V2Ray دارید و می‌خواهید اتصال کاربران پایدارتر باشد یا آی‌پی سرور مستقیم فیلتر یا کند شده است.'),
      rec: t('پروتکل gRPC، مسیر تصادفی طولانی، صفحه استتار برای بقیه مسیرها و در صورت نیاز «فقط ایران».'),
      mistakes: [t('پروکسی نکردن رکورد DNS (ترافیک مستقیم به سرور می‌رود).'), t('روشن کردن TLS روی ورودی Xray در حالی که «اتصال با TLS» در مسیر خاموش است (یا برعکس).'), t('مسیر یا UUID متفاوت در سرور و کلاینت.'), t('بستن آی‌پی‌های CDN در فایروال سرور.')],
      tut: 'tunnel'
    },
    upsell: t('تونل / VPN در همه پلن‌های CDN گنجانده شده است. سرور Xray / V2Ray خود را پشت CDN و نودهای داخل ایران قرار دهید: اتصال پایدارتر، آی‌پی پنهان و بدون نیاز به دامنه یا سرور اضافه. اگر این بخش فعال نیست، پلن سرویس را به‌روزرسانی کنید یا با پشتیبانی تماس بگیرید.'),
    upsellMore: function () {
      return h('ul', { className: 'pcdn-tn-upsell' }, PROTOCOLS.map(function (p) {
        return h('li', null, protoBadge(p[0]), h('span', { text: p[2] }));
      }));
    },
    lock: function (f) { return !f.tunnel; },
    render: renderTunnel
  };
})();
