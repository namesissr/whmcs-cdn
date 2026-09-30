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
    var svg = P.s('svg', { viewBox: '0 0 ' + n + ' ' + n, width: px || 220, height: px || 220, role: 'img', 'aria-label': 'کد QR لینک اشتراک',
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
    ['grpc', 'gRPC', 'پایدار و سریع: چند جریان روی یک اتصال HTTP/2. برای بیشتر کاربران بهترین انتخاب است.', 'zap', 'پیشنهادی'],
    ['xhttp', 'XHTTP', 'جدیدترین روش Xray؛ ترافیک شبیه درخواست‌های عادی وب است و در شبکه‌های سخت‌گیر خوب کار می‌کند. فقط کلاینت‌های با هسته Xray.', 'sparkles', 'جدیدترین'],
    ['ws', 'WebSocket', 'سازگارترین: تقریباً همه کلاینت‌ها (v2rayNG، v2rayN، Hiddify، NekoBox، sing-box) پشتیبانی می‌کنند.', 'link', 'سازگارترین'],
    ['httpupgrade', 'HTTPUpgrade', 'مثل WebSocket ولی سبک‌تر (بدون فریم‌بندی WebSocket)؛ در Xray و sing-box نسخه‌های جدید.', 'up'],
    ['h2', 'HTTP/2 خام (h2)', 'جریان‌های HTTP/2 مستقیم به سرور h2c شما (XHTTP در حالت stream-one)؛ برای کاربران حرفه‌ای.', 'code']
  ];
  var PROTO = {};
  PROTOCOLS.forEach(function (p) { PROTO[p[0]] = { label: p[1], desc: p[2], icon: p[3] }; });
  var XHTTP_MODES = [['auto', 'auto — خودکار (پیشنهادی)'], ['packet-up', 'packet-up — سازگارترین با شبکه‌های محدود'], ['stream-up', 'stream-up — سریع‌تر']];
  var FALLBACKS = [
    ['origin', 'سایت عادی', 'مسیرهای دیگر مثل همیشه به سرور اصلی سایت شما می‌روند. وقتی روی این دامنه سایت واقعی دارید.', 'globe'],
    ['decoy', 'صفحه استتار', 'بقیه مسیرها یک صفحه ساده و خنثی (کد ۲۰۰) می‌بینند تا دامنه شبیه یک سایت معمولی باشد و سرور شما دیده نشود.', 'eye', 'پیشنهادی'],
    ['404', 'خطای ۴۰۴', 'همه مسیرهای دیگر پاسخ «یافت نشد» می‌گیرند.', 'ban']
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
  function maxPaths() { var m = feats().max_tunnel_paths; return m === undefined || m === null ? 10 : Math.max(0, Number(m) || 0); }

  function originText(p) {
    if (p.pool) return 'استخر توزیع بار «' + p.pool + '»';
    if (p.origin) return (p.origin.address || '?') + ':' + (p.origin.port || (p.origin.tls ? 443 : 80)) + (p.origin.tls ? ' (TLS)' : '');
    return 'همان سرور اصلی سایت';
  }
  /** Where the tunnel reaches the customer's server: {port, tls, note}. */
  function listenOf(p, host) {
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

  /**
   * Ready-to-use configs for one path.
   * o = {protocol, path, host, uuid, port (origin listen port), tls (origin TLS), mode (xhttp), remark}
   * → {link, xray (server config.json text), singbox (outbound JSON text | null), serviceName, alpn}
   */
  function tunnelConfig(o) {
    var proto = o.protocol, path = String(o.path || '/'), host = String(o.host || ''), uuid = String(o.uuid || '');
    var svc = path.replace(/^\/+/, '');
    var mode = proto === 'h2' ? 'stream-one' : (o.mode || 'auto');
    var alpn = proto === 'grpc' || proto === 'h2' ? ['h2'] : proto === 'xhttp' ? ['h2', 'http/1.1'] : ['http/1.1'];
    var q = [['encryption', 'none'], ['security', 'tls'], ['sni', host], ['fp', 'chrome'], ['alpn', alpn.join(',')],
      ['type', proto === 'h2' ? 'xhttp' : proto]];
    if (proto === 'grpc') q.push(['serviceName', svc], ['mode', 'gun']);
    else if (proto === 'xhttp' || proto === 'h2') q.push(['host', host], ['path', path], ['mode', mode]);
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
    else if (proto === 'ws') ss.wsSettings = { path: path };
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
      var tr = proto === 'grpc' ? { type: 'grpc', service_name: svc }
        : proto === 'ws' ? { type: 'ws', path: path, headers: { Host: host } } : { type: 'httpupgrade', host: host, path: path };
      sb = { type: 'vless', tag: 'pcdn-' + (o.id || proto), server: host, server_port: 443, uuid: uuid,
        tls: { enabled: true, server_name: host, alpn: alpn, utls: { enabled: true, fingerprint: 'chrome' } }, transport: tr };
    }
    return { link: link, xray: JSON.stringify(xray, null, 2), singbox: sb ? JSON.stringify(sb, null, 2) : null, serviceName: svc, alpn: alpn };
  }
  P.tunnelConfig = tunnelConfig;

  // ------------------------------------------------------------------ small pieces

  function protoBadge(proto) {
    var p = PROTO[proto] || { label: proto };
    return h('span', { className: 'pcdn-tn-proto pcdn-tn-' + proto, text: p.label });
  }
  function codeBlock(text, label, id) {
    return h('figure', { className: 'pcdn-codeblock', 'data-code': id || null },
      h('figcaption', null, icon('terminal'), h('span', { dir: 'ltr', text: label }),
        P.copyBtn(text, 'کپی ' + label, { text: 'کپی', cls: 'pcdn-copy-code', done: 'کپی شد' })),
      h('pre', { dir: 'ltr', tabindex: '0' }, h('code', { text: text })));
  }
  function dl(rows) {
    return h('dl', { className: 'pcdn-dl pcdn-dl-cols' }, rows.map(function (r) { return h('div', null, h('dt', { text: r[0] }), h('dd', null, r[1])); }));
  }

  // ------------------------------------------------------------------ path editor (drawer)

  function pathEditor(orig, list, done) {
    var isNew = !orig;
    var x = orig ? clone(orig) : { id: '', path: randomPath(), protocol: 'grpc', origin: null, pool: null };
    var st = { mode: x.pool ? 'pool' : x.origin ? 'custom' : 'site' };
    var pl = pools(), lb = !!feats().load_balancer && pl.length > 0;
    var d = P.dialog({ title: isNew ? 'مسیر تونل جدید' : 'ویرایش مسیر تونل', subtitle: 'آدرس مخفی، پروتکل و سرور مقصد این مسیر را تعیین کنید.', icon: 'tunnel', kind: 'drawer', wide: true });
    d.el.classList.add('pcdn-tn-editor');
    var err = h('div'), holder = h('div', { className: 'pcdn-form' });
    append(d.body, [err, holder]);
    function draw() {
      clear(holder);
      var pathIn = P.input(x, 'path', 'مسیر (آدرس مخفی)', { placeholder: '/my-secret-service', maxlength: 201,
        help: h('span', null, 'با ', ltr('/'), ' شروع شود؛ فقط حروف انگلیسی، عدد و ', ltr('. _ ~ / -'), '. هر چه طولانی‌تر و تصادفی‌تر، امن‌تر. ',
          x.protocol === 'grpc' ? h('span', null, 'در gRPC همین مسیر بدون ', ltr('/'), ' اول، serviceName است.') : null) });
      var gen = P.btn('ساخت مسیر تصادفی', { icon: 'refresh', size: 'sm', write: true, cls: 'pcdn-tn-random', onclick: function () {
        x.path = randomPath();
        var inp = holder.querySelector('.pcdn-tn-pathrow input');
        if (inp) { inp.value = x.path; inp.dispatchEvent(new Event('input', { bubbles: true })); }
      } });
      append(holder, [
        h('div', { className: 'pcdn-tn-pathrow' }, pathIn, gen),
        P.choice(x, 'protocol', 'پروتکل', PROTOCOLS, { cols: 2, onchange: draw }),
        P.choice(st, 'mode', 'سرور مقصد (سرور VPN شما)', [
          ['site', 'همان سرور اصلی سایت', 'به آدرس و پورت رکورد پروکسی‌شده (و پروتکل «اتصال به سرور اصلی» در SSL) وصل می‌شود.', 'server'],
          ['custom', 'آدرس و پورت دلخواه', 'مثلاً سرور جداگانه Xray روی پورت ۲۰۵۳. پیشنهادی وقتی روی همین سرور سایت هم دارید.', 'edit'],
          ['pool', 'استخر توزیع بار', lb ? 'بین چند سرور VPN تقسیم می‌شود و سرور خراب کنار گذاشته می‌شود.' : 'ابتدا در بخش «توزیع بار» یک استخر بسازید (در پلن شما: ' + (feats().load_balancer ? 'فعال' : 'غیرفعال') + ').', 'lb']
        ], { cols: 3, onchange: function (v) {
          if (v === 'custom') { x.origin = x.origin || { address: '', port: 2053, tls: false, sni: null, verify: false }; x.pool = null; }
          else if (v === 'pool') { x.origin = null; x.pool = x.pool || (pl[0] ? pl[0].name : null); }
          else { x.origin = null; x.pool = null; }
          draw();
        } }),
        st.mode === 'custom' ? h('div', { className: 'pcdn-subpanel' },
          h('div', { className: 'pcdn-grid' },
            P.input(x.origin, 'address', 'آدرس سرور', { placeholder: '185.1.2.3', help: 'IPv4، IPv6 یا نام میزبان.' }),
            P.input(x.origin, 'port', 'پورت', { type: 'number', min: 1, max: 65535, placeholder: x.origin.tls ? '443' : '80' })),
          P.toggle(x.origin, 'tls', 'اتصال CDN به سرور با TLS', { help: 'معمولاً خاموش: CDN خودش TLS بازدیدکننده را باز می‌کند و سرور Xray بدون TLS گوش می‌دهد (ساده‌تر، بدون نیاز به گواهی روی سرور).', onchange: draw }),
          x.origin.tls ? h('div', { className: 'pcdn-grid' },
            P.input(x.origin, 'sni', 'SNI (اختیاری)', { nullable: true, placeholder: site().domain, help: 'خالی = نام دامنه سایت. باید با گواهی سرور شما بخواند.' }),
            P.toggle(x.origin, 'verify', 'بررسی اعتبار گواهی سرور', { help: 'فقط اگر گواهی معتبر (مثلاً Let\'s Encrypt) روی سرور دارید.' })) : null) : null,
        st.mode === 'pool' ? (lb ? P.select(x, 'pool', 'استخر', pl.map(function (p) { return [p.name, p.name + ' (' + num((p.origins || []).length) + ' سرور)']; }))
          : P.alertBox('warning', ['هنوز استخری ندارید. ', A().goLink('pools', 'ساخت استخر در «توزیع بار»')])) : null,
        x.protocol === 'grpc' && /\/.*\//.test(x.path) ? P.alertBox('warning', 'برای gRPC مسیر تک‌بخشی (بدون / میانی) بگذارید؛ بعضی کلاینت‌ها serviceName چندبخشی را پشتیبانی نمی‌کنند.') : null,
        x.protocol === 'h2' ? P.alertBox('info', 'حالت h2: سرور شما باید HTTP/2 بدون TLS (h2c) یا با TLS را بپذیرد؛ در Xray، ورودی XHTTP با حالت stream-one.') : null
      ]);
      A().lockWrites(holder);
    }
    draw();
    var ok = P.btn('تأیید', { kind: 'primary', icon: 'check', write: true, cls: 'pcdn-drawer-ok', onclick: function () {
      clear(err);
      x.path = String(x.path || '').trim();
      var problem = null;
      if (!PATH_RE.test(x.path)) problem = 'مسیر باید با / شروع شود و فقط حروف انگلیسی، عدد و . _ ~ / - داشته باشد (حداکثر ۲۰۰ کاراکتر).';
      else if (/^\/__pcdn/i.test(x.path)) problem = 'مسیرهای /__pcdn رزرو شده‌اند.';
      else if (list.some(function (p) { return p !== orig && p.path === x.path; })) problem = 'این مسیر قبلاً برای مسیر دیگری استفاده شده است.';
      else if (st.mode === 'custom' && !String(x.origin.address || '').trim()) problem = 'آدرس سرور مقصد را وارد کنید.';
      else if (st.mode === 'custom' && !(Number(x.origin.port) >= 1 && Number(x.origin.port) <= 65535)) problem = 'پورت باید عددی بین ۱ و ۶۵۵۳۵ باشد.';
      else if (st.mode === 'pool' && !x.pool) problem = 'یک استخر انتخاب کنید.';
      if (problem) { err.appendChild(P.alertBox('danger', problem)); return; }
      if (x.origin) { x.origin.address = String(x.origin.address).trim(); x.origin.port = Number(x.origin.port); if (!x.origin.tls) { x.origin.sni = null; x.origin.verify = false; } }
      if (!x.id) x.id = newId(list, x.protocol);
      d.close(true);
      done(x);
    } });
    append(d.foot, [ok, P.btn('انصراف', { onclick: function () { d.close(); } })]);
    A().lockWrites(d.el);
    d.focusFirst();
  }

  // ------------------------------------------------------------------ ready-to-use configs (drawer)

  function configDrawer(p) {
    var key = 'tn-' + A().serviceId + '-' + p.id, mem = {};
    try { mem = JSON.parse(P.store(key) || '{}') || {}; } catch (e) { mem = {}; }
    var hs = hosts();
    var st = { host: hs.indexOf(mem.host) >= 0 ? mem.host : (hs[0] || ''), uuid: /^[0-9a-f-]{36}$/i.test(mem.uuid || '') ? mem.uuid : uuid4(), mode: mem.mode || 'auto' };
    var d = P.dialog({ title: 'پیکربندی آماده — ' + PROTO[p.protocol].label, subtitle: p.path, icon: 'qr', kind: 'drawer', wide: true });
    d.el.classList.add('pcdn-tn-config');
    var out = h('div', { className: 'pcdn-stack' });
    function remember() { P.store(key, JSON.stringify({ host: st.host, uuid: st.uuid, mode: st.mode })); }
    function draw() {
      clear(out);
      remember();
      var lis = listenOf(p, st.host);
      var c = tunnelConfig({ id: p.id, protocol: p.protocol, path: p.path, host: st.host || 'YOUR-HOST', uuid: st.uuid, port: lis.port, tls: lis.tls,
        mode: st.mode, remark: (st.host || site().domain) + '-' + p.id });
      var q = qrSvg(c.link, 232);
      append(out, [
        h('section', { className: 'pcdn-tn-share', 'data-share': '1' },
          h('div', { className: 'pcdn-tn-share-text' },
            h('h4', { text: '۱. لینک اشتراک برای کلاینت' }),
            h('p', { className: 'pcdn-muted', text: 'در v2rayNG، v2rayN، Hiddify، Streisand یا NekoBox: لینک را کپی و «Import from clipboard» را بزنید یا QR را اسکن کنید.' }),
            h('div', { className: 'pcdn-tn-link' }, h('code', { dir: 'ltr', className: 'pcdn-tn-link-text', text: c.link }),
              P.copyBtn(c.link, 'کپی لینک اشتراک', { text: 'کپی لینک', cls: 'pcdn-copy-link', done: 'لینک کپی شد' })),
            p.protocol === 'xhttp' || p.protocol === 'h2' ? P.alertBox('info', 'XHTTP فقط در کلاینت‌های با هسته Xray (v2rayNG و v2rayN نسخه‌های جدید، Hiddify با هسته Xray، Streisand) کار می‌کند.') : null),
          q ? h('div', { className: 'pcdn-tn-qr', 'data-qr': '1' }, q) : h('p', { className: 'pcdn-muted', text: 'لینک برای QR بیش از حد طولانی است.' })),
        h('section', { 'data-server': '1' },
          h('h4', { text: '۲. تنظیم سرور شما (Xray)' }),
          h('p', { className: 'pcdn-muted' }, 'این فایل را در ', ltr('/usr/local/etc/xray/config.json'), ' بگذارید (یا فقط بخش inbounds را به پیکربندی فعلی اضافه کنید) و ', ltr('systemctl restart xray'), ' را اجرا کنید. ',
            lis.tls ? 'چون اتصال CDN به سرور با TLS است، مسیر گواهی و کلید را اصلاح کنید.' : 'ورودی بدون TLS گوش می‌دهد؛ رمزنگاری بین بازدیدکننده و CDN انجام می‌شود.'),
          codeBlock(c.xray, 'config.json — Xray (سرور)', 'xray'),
          p.origin || p.pool ? null : P.alertBox('warning', ['مقصد این مسیر «همان سرور اصلی سایت» است، یعنی پورت ', ltr(String(lis.port)),
            '. اگر وب‌سرور (nginx/Apache) روی این پورت است، یا مسیر را در وب‌سرور به Xray پاس دهید یا مقصد مسیر را «آدرس و پورت دلخواه» بگذارید. ', A().tutLink('tunnel', 'راهنما')])),
        h('section', { 'data-singbox': '1' },
          h('h4', { text: '۳. کلاینت sing-box (اختیاری)' }),
          c.singbox ? codeBlock(c.singbox, 'outbound — sing-box', 'singbox')
            : P.alertBox('info', 'sing-box از XHTTP پشتیبانی نمی‌کند؛ برای این مسیر از لینک اشتراک در کلاینت‌های مبتنی بر Xray استفاده کنید.'))
      ]);
    }
    var hostCtl = hs.length ? P.select(st, 'host', 'نام میزبان (رکورد پروکسی‌شده)', hs.map(function (x) { return [x, x]; }), { ltr: true, onchange: draw,
      help: 'کلاینت به این نام روی پورت ۴۴۳ وصل می‌شود. رکورد باید در «رکوردها» پروکسی‌شده باشد.' })
      : P.alertBox('warning', ['هیچ رکورد پروکسی‌شده‌ای ندارید؛ ابتدا یک رکورد (مثلاً ', ltr('vpn'), ') با پروکسی روشن بسازید. ', A().goLink('dns', 'رکوردها')]);
    var uuidCtl = P.input(st, 'uuid', 'UUID کاربر', { oninput: function () { if (/^[0-9a-f-]{36}$/i.test(st.uuid)) draw(); },
      help: 'شناسه کاربر در Xray؛ در سرور و کلاینت باید یکسان باشد. برای هر کاربر یک UUID جدا بسازید.' });
    var newUuid = P.btn('UUID جدید', { icon: 'refresh', size: 'sm', cls: 'pcdn-tn-uuid', onclick: function () {
      st.uuid = uuid4();
      var inp = uuidCtl.querySelector('input'); if (inp) inp.value = st.uuid;
      draw();
    } });
    newUuid.setAttribute('data-ro-ok', '1');
    append(d.body, [
      h('div', { className: 'pcdn-grid pcdn-tn-cfg-ctl' }, hostCtl, h('div', { className: 'pcdn-tn-pathrow' }, uuidCtl, newUuid),
        p.protocol === 'xhttp' ? P.select(st, 'mode', 'حالت XHTTP کلاینت', XHTTP_MODES, { onchange: draw }) : null),
      out]);
    Array.prototype.forEach.call(d.body.querySelectorAll('input,select'), function (x) { x.setAttribute('data-ro-ok', '1'); });
    draw();
    d.foot.appendChild(P.btn('بستن', { onclick: function () { d.close(); } }));
    d.focusFirst();
    return d;
  }

  // ------------------------------------------------------------------ connectivity check + stats

  function checkCard(Aa) {
    var c = P.card({ title: 'تست اتصال به سرور من', icon: 'activity', tone: 'success', id: 'check',
      subtitle: 'CDN از سمت سرورهای خود به مقصد هر مسیر وصل می‌شود (TCP و در صورت نیاز TLS) تا مطمئن شوید سرور VPN شما در دسترس است.' });
    var res = h('div', { className: 'pcdn-tn-results', 'aria-live': 'polite' });
    var b = P.btn('تست اتصال', { kind: 'primary', icon: 'refresh', write: true, cls: 'pcdn-tn-check', onclick: function () {
      if (!saved().paths || !saved().paths.length) { P.toast('ابتدا یک مسیر تونل بسازید و ذخیره کنید.', 'warn'); return; }
      clear(res);
      res.appendChild(P.skeleton(2));
      P.busy(b, P.api('POST', 'tunnel/check')).then(function (r) {
        clear(res);
        if (!r.ok) { res.appendChild(P.errorBox(r, 'تست انجام نشد')); return; }
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
                h('span', { className: 'pcdn-muted pcdn-tn-note', text: '← ' + originText(p) })),
              h('div', { className: 'pcdn-tn-res-msg', text: x.ok ? 'در دسترس است' + (x.ms !== null && x.ms !== undefined ? ' — ' + num(x.ms) + ' میلی‌ثانیه' : '') : (x.error || 'در دسترس نیست') })));
        })));
        if (!list.length) res.appendChild(h('p', { className: 'pcdn-muted', text: 'مسیری برای تست وجود ندارد.' }));
        if (bad) {
          res.appendChild(P.alertBox('warning', [h('strong', { text: 'سرور در دسترس نیست؟ ' }),
            'بررسی کنید سرویس Xray روشن است، پورت درست است، فایروال سرور (ufw / iptables / فایروال دیتاسنتر) آی‌پی‌های CDN را مسدود نکرده، و اگر TLS روشن است SNI و گواهی درست باشند. ',
            Aa.tutLink('tunnel', 'عیب‌یابی تونل')]));
        }
        P.toast(bad ? num(bad) + ' مسیر در دسترس نیست.' : 'همه مسیرها در دسترس‌اند.', bad ? 'warn' : 'success');
      });
    } });
    append(c.body, [h('div', { className: 'pcdn-row-actions' }, b, h('span', { className: 'pcdn-muted pcdn-tn-note', text: 'تست روی تنظیمات ذخیره‌شده انجام می‌شود.' })), res]);
    return c;
  }

  var PERIODS = [['24', '۲۴ ساعت'], ['168', '۷ روز']];
  function statsCard(Aa) {
    var st = S();
    st.tnHours = st.tnHours || '24';
    var c = P.card({ title: 'آمار تونل', icon: 'chart', tone: 'violet', id: 'tstats',
      actions: P.segmented(PERIODS, st.tnHours, function (v) { st.tnHours = v; draw(); }, 'بازه آمار تونل') });
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
        if (!r.ok) { holder.appendChild(P.errorBox(r, 'آمار تونل در دسترس نیست')); return; }
        var data = r.data || {}, list = Array.isArray(data.hours) ? data.hours : [], t = data.totals || {};
        var secs = list.reduce(function (a, x) { return a + (Number(x.seconds) || 0); }, 0);
        var up = Number(t.bytes_up) || 0, down = Number(t.bytes_down) || 0;
        function kpi(ic, tone, label, value, sub, id) {
          return h('div', { className: 'pcdn-kpi', 'data-kpi': id }, h('div', { className: 'pcdn-kpi-top' }, h('span', { className: 'pcdn-kpi-icon pcdn-tone-' + tone }, icon(ic)), h('span', { className: 'pcdn-kpi-label', text: label })),
            h('div', { className: 'pcdn-kpi-value', text: value }), sub ? h('div', { className: 'pcdn-kpi-sub', text: sub }) : null);
        }
        append(holder, h('div', { className: 'pcdn-kpis' },
          kpi('link', 'brand', 'نشست‌ها', num(t.sessions || 0), 'جریان‌های تونل پایان‌یافته', 'sessions'),
          kpi('clock', 'violet', 'ساعت اتصال', P.num1(secs / 3600), 'مجموع مدت نشست‌ها', 'hours'),
          kpi('upload', 'warning', 'آپلود', P.bytes(up), 'از کاربران به سرور شما', 'up'),
          kpi('download', 'success', 'دانلود', P.bytes(down), 'از سرور شما به کاربران', 'down')));
        if (!list.length || up + down === 0) {
          holder.appendChild(P.empty('chart', 'هنوز ترافیک تونلی ثبت نشده است', 'پس از اتصال اولین کاربر، آمار با چند دقیقه تأخیر اینجا نمایش داده می‌شود.'));
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
        if (P.charts) P.charts.bar(chart, labels, buckets.map(function (b) { return b.v; }), 'var(--pc-c-bytes)', P.bytes, 'نمودار ترافیک تونل', 'ترافیک (آپلود + دانلود)');
        var bp = data.by_protocol || {}, keys = Object.keys(bp).filter(function (k) { return PROTO[k] && Number(bp[k]) > 0; })
          .sort(function (a, b) { return bp[b] - bp[a]; });
        if (keys.length) {
          var max = Number(bp[keys[0]]) || 1, sum = keys.reduce(function (a, k) { return a + Number(bp[k]); }, 0);
          holder.appendChild(h('div', { className: 'pcdn-tn-byproto' }, h('h4', { text: 'بر اساس پروتکل' }),
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

  function renderTunnel(Aa) {
    var f = feats(), cap = capMbps(), maxP = maxPaths(), hs = hosts(), s = site();
    var notes = [];
    if (!hs.length) notes.push(P.alertBox('warning', [h('strong', { text: 'رکورد پروکسی‌شده ندارید. ' }), 'کلاینت‌ها به یک نام پروکسی‌شده (مثلاً ', ltr('vpn.' + s.domain), ') روی پورت ۴۴۳ وصل می‌شوند. ابتدا در «رکوردها» یک رکورد A به آی‌پی سرور خود بسازید و پروکسی را روشن کنید. ', Aa.goLink('dns', 'رکوردها')]));
    if (s.status !== 'active') notes.push(P.alertBox('info', 'تونل پس از فعال شدن سایت روی CDN (تأیید نیم‌سرورها) کار می‌کند؛ تا آن زمان می‌توانید مسیرها را آماده کنید.'));
    else if (!s.ssl || s.ssl.status !== 'active') {
      var needTls = (saved().paths || []).filter(function (p) { return p.protocol === 'grpc' || p.protocol === 'h2'; });
      notes.push(P.alertBox('warning', [h('strong', { text: 'گواهی SSL سایت هنوز فعال نیست. ' }),
        needTls.length ? 'مسیرهای gRPC و HTTP/2 (' + num(needTls.length) + ' مسیر) فقط روی HTTPS با ALPN h2 کار می‌کنند و تا صدور گواهی وصل نمی‌شوند. ' : 'کلاینت‌ها روی HTTPS (پورت ۴۴۳) وصل می‌شوند. ',
        'گواهی پس از تأیید نیم‌سرورها خودکار صادر می‌شود.'], { icon: 'lock' }));
    }

    var form = Aa.sectionForm('tunnel', function (d, f2) {
      d.paths = Array.isArray(d.paths) ? d.paths : [];
      d.allowed_countries = Array.isArray(d.allowed_countries) ? d.allowed_countries : [];
      var full = d.paths.length >= maxP;

      var sc = P.card({ title: 'وضعیت تونل', icon: 'tunnel', id: 'tstate' });
      append(sc.body, [
        P.toggle(d, 'enabled', 'تونل فعال باشد', { help: 'وقتی روشن است، مسیرهای زیر بدون کش، بدون بافر و بدون WAF و چالش مستقیم به سرور VPN شما می‌رسند.', onchange: f2.redraw }),
        dl([
          ['مسیرهای مجاز پلن', num(maxP)],
          ['اتصال همزمان هر نود', f.max_tunnel_connections ? num(f.max_tunnel_connections) : 'نامحدود'],
          ['نودهای پاسخ‌دهنده', f.edge_group === 'tunnel' ? 'نودهای مخصوص تونل' : 'نودهای عمومی']
        ]),
        d.enabled && !d.paths.length ? P.alertBox('info', 'تونل روشن است ولی هنوز مسیری ندارد؛ یک مسیر اضافه کنید.') : null]);

      var add = P.btn('مسیر جدید', { kind: 'primary', icon: 'plus', size: 'sm', write: true, cls: 'pcdn-tn-add', disabled: full,
        title: full ? 'به سقف ' + num(maxP) + ' مسیر پلن رسیده‌اید' : null,
        onclick: function () { pathEditor(null, d.paths, function (np) { np._new = true; d.paths.push(np); f2.redraw(); }); } });
      var pc = P.card({ title: 'مسیرهای تونل', icon: 'link', id: 'tpaths', subtitle: 'هر مسیر یک آدرس مخفی روی دامنه شماست که با پروتکل انتخابی به سرور VPN می‌رسد.',
        actions: [h('span', { className: 'pcdn-limit' + (full ? ' is-full' : '') }, num(d.paths.length) + ' از ' + num(maxP) + ' مسیر'), add] });
      if (!d.paths.length) {
        pc.body.appendChild(P.empty('tunnel', 'هنوز مسیری نساخته‌اید', 'با «مسیر جدید» یک آدرس مخفی (مثلاً ' + randomPath().slice(0, 9) + '…) بسازید؛ پروتکل پیشنهادی gRPC است.'));
      } else {
        var ol = h('ol', { className: 'pcdn-rules pcdn-tn-paths' });
        d.paths.forEach(function (p, i) {
          var li = h('li', { className: 'pcdn-rule pcdn-tn-path' + (p._new ? ' is-new' : ''), 'data-path': p.id || i },
            h('span', { className: 'pcdn-rule-no', 'aria-hidden': 'true', text: num(i + 1) }),
            h('div', { className: 'pcdn-rule-main' },
              h('div', { className: 'pcdn-rule-name' }, protoBadge(p.protocol), h('bdi', { className: 'pcdn-vchip pcdn-tn-pathval', dir: 'ltr', text: p.path }),
                p._new ? P.badge('ذخیره نشده', 'warning') : null),
              h('div', { className: 'pcdn-sentence' }, h('span', { className: 'pcdn-w', text: 'مقصد:' }), h('span', { className: 'pcdn-w pcdn-w-strong', text: originText(p) }),
                h('span', { className: 'pcdn-mini', dir: 'ltr', text: 'id: ' + (p.id || '—') }))),
            h('div', { className: 'pcdn-rule-ctl' },
              h('button', { type: 'button', className: 'pcdn-btn pcdn-btn-sm pcdn-tn-cfg', 'data-ro-ok': '1', onclick: function () { configDrawer(p); } }, icon('qr'), h('span', { text: 'پیکربندی آماده' })),
              P.iconBtn('edit', 'ویرایش مسیر ' + num(i + 1), function () { pathEditor(p, d.paths, function (np) { if (p._new) np._new = true; d.paths[i] = np; f2.redraw(); }); }, { write: true }),
              P.iconBtn('trash', 'حذف مسیر ' + num(i + 1), function () { d.paths.splice(i, 1); f2.redraw(); P.toast('مسیر از فهرست حذف شد؛ برای اعمال «ذخیره» را بزنید.', 'info'); }, { write: true, cls: 'is-danger' })));
          P.reg('paths.' + i, li);
          ol.appendChild(li);
        });
        pc.body.appendChild(ol);
      }

      var cc = P.card({ title: 'تنظیمات اتصال', icon: 'sliders', id: 'tsettings' });
      var iran = P.btn('فقط ایران', { size: 'sm', write: true, cls: 'pcdn-tn-onlyir', onclick: function () { d.allowed_countries = ['IR']; f2.redraw(); } });
      var all = P.btn('همه کشورها', { size: 'sm', write: true, cls: 'pcdn-tn-allcc', onclick: function () { d.allowed_countries = []; f2.redraw(); } });
      var mbps = P.input(d, 'per_connection_mbps', 'سقف سرعت هر اتصال', { type: 'number', min: 0, max: cap || 100000, suffix: 'Mbps', suffixRtl: false, cls: 'pcdn-tn-mbps',
        help: 'فعلاً اعمال نمی‌شود: محدودسازی سرعت روی جریان‌های تونل (gRPC، WebSocket و …) هنوز در نودها پشتیبانی نمی‌شود.' });
      // Stored value is sent back unchanged; not editable while the edges cannot enforce a per-stream rate on tunnel traffic.
      mbps.querySelector('input').disabled = true;
      mbps.querySelector('input').setAttribute('data-ro-ok', '1');
      append(cc.body, [
        h('div', { className: 'pcdn-grid' },
          P.duration(d, 'idle_timeout', 'مهلت بیکاری اتصال', { min: 60, max: 86400, picks: [[600, '۱۰ دقیقه'], [3600, '۱ ساعت'], [21600, '۶ ساعت'], [86400, '۱ روز']],
            help: 'اتصالی که این مدت هیچ داده‌ای نداشته باشد بسته می‌شود (۶۰ ثانیه تا ۱ روز).' }),
          mbps,
          P.input(d, 'max_connections_per_ip', 'حداکثر اتصال همزمان هر IP', { type: 'number', min: 0, max: 10000,
            help: '۰ یعنی نامحدود (روی هر نود). هر جریان WebSocket یا gRPC یک اتصال حساب می‌شود و کلاینت‌ها چند جریان همزمان باز می‌کنند؛ کمتر از ۱۰ نگذارید. اضافه‌ها خطای ۴۲۹ می‌گیرند.' })),
        h('div', { className: 'pcdn-tn-cc' },
          P.tags(d, 'allowed_countries', 'کشورهای مجاز', { upper: true, placeholder: 'IR', help: 'خالی = همه. کاربران کشورهای دیگر روی مسیرهای تونل خطای ۴۰۳ می‌گیرند (کد دوحرفی ISO، مثل IR).' }),
          h('div', { className: 'pcdn-chips-row' }, iran, all)),
        P.choice(d, 'fallback', 'بقیه مسیرهای دامنه', FALLBACKS, { cols: 3,
          help: 'صفحه استتار (decoy) یعنی هر کس دامنه را در مرورگر باز کند یک سایت ساده و بی‌خطر می‌بیند، نه خطا یا سرور VPN شما.' })
      ]);
      return [sc, pc, cc];
    }, {
      serialize: function (d) {
        (d.paths || []).forEach(function (p) { delete p._new; });
        return d;
      },
      savedMsg: 'تغییرات ذخیره شد و تا چند ثانیه روی همه نودهای تونل اعمال می‌شود.'
    });
    return [notes, form.el, h('div', { className: 'pcdn-grid-2 pcdn-tn-bottom' }, checkCard(Aa), guideCard(Aa)), statsCard(Aa)];
  }

  function guideCard(Aa) {
    var c = P.card({ title: 'راه‌اندازی در ۴ قدم', icon: 'rocket', id: 'tsteps' });
    append(c.body, [
      h('ol', { className: 'pcdn-ol pcdn-steps-ol' },
        h('li', { text: 'در «رکوردها» یک رکورد A (مثلاً vpn) به آی‌پی سرور VPN بسازید و پروکسی را روشن کنید.' }),
        h('li', { text: 'تونل را روشن کنید، یک مسیر با پروتکل gRPC بسازید و ذخیره کنید.' }),
        h('li', { text: 'از «پیکربندی آماده» فایل config.json سرور Xray را کپی و Xray را راه‌اندازی کنید.' }),
        h('li', { text: 'لینک اشتراک یا QR را در کلاینت (v2rayNG، v2rayN، Hiddify) وارد و وصل شوید.' })),
      Aa.tutLink('tunnel', 'آموزش کامل و عیب‌یابی')]);
    return c;
  }

  pages.tunnel = {
    title: 'تونل / VPN', icon: 'tunnel', heading: 'تونل / VPN پشت CDN',
    desc: 'Xray / V2Ray / sing-box را با gRPC، XHTTP، WebSocket، HTTPUpgrade یا HTTP/2 از طریق نودهای داخل ایران به سرور خود برسانید.',
    guide: {
      what: 'کاربران به نودهای CDN (داخل ایران) وصل می‌شوند و CDN جریان‌های طولانی را بدون کش و بافر به سرور VPN شما (مثلاً در خارج) می‌رساند؛ آی‌پی سرور شما پنهان می‌ماند.',
      when: 'وقتی سرور Xray/V2Ray دارید و می‌خواهید اتصال کاربران پایدارتر باشد یا آی‌پی سرور مستقیم فیلتر یا کند شده است.',
      rec: 'پروتکل gRPC، مسیر تصادفی طولانی، صفحه استتار برای بقیه مسیرها و در صورت نیاز «فقط ایران».',
      mistakes: ['پروکسی نکردن رکورد DNS (ترافیک مستقیم به سرور می‌رود).', 'روشن کردن TLS روی ورودی Xray در حالی که «اتصال با TLS» در مسیر خاموش است (یا برعکس).', 'مسیر یا UUID متفاوت در سرور و کلاینت.', 'بستن آی‌پی‌های CDN در فایروال سرور.'],
      tut: 'tunnel'
    },
    upsell: 'تونل / VPN در همه پلن‌های CDN گنجانده شده است. سرور Xray / V2Ray خود را پشت CDN و نودهای داخل ایران قرار دهید: اتصال پایدارتر، آی‌پی پنهان و بدون نیاز به دامنه یا سرور اضافه. اگر این بخش فعال نیست، پلن سرویس را به‌روزرسانی کنید یا با پشتیبانی تماس بگیرید.',
    upsellMore: function () {
      return h('ul', { className: 'pcdn-tn-upsell' }, PROTOCOLS.map(function (p) {
        return h('li', null, protoBadge(p[0]), h('span', { text: p[2] }));
      }));
    },
    lock: function (f) { return !f.tunnel; },
    render: renderTunnel
  };
})();
