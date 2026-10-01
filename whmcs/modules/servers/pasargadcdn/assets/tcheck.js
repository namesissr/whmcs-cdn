/*
 * Pasargad CDN — «بررسی کانفیگ سرور» checker (docs/SPEC.md §15.7). Pure logic, no DOM, no network.
 *
 * The customer pastes an Xray or sing-box SERVER config; it is parsed and checked here, in the
 * browser only — never sent to WHMCS or the controller, never stored (not even localStorage).
 * Secrets (UUIDs, passwords, private keys, short ids) are never echoed back in full: every text
 * the checker returns goes through mask().
 *
 *   PCDN.tunnelCheck.run(text, ctx) → {ok, kind: 'xray'|'singbox'|null, error, findings: [...], summary}
 *     ctx = {domain, paths: [{id, path, protocol, ports: [int], tls: bool, mode: 'site'|'custom'|'pool'}]}
 *     finding = {level: 'error'|'warning'|'ok'|'info', code, title, fix|null, inbound|null, path|null}
 *   PCDN.tunnelCheck.mask(text) → text with secrets shortened (…ab12)
 *   PCDN.tunnelCheck.parse(text) → {data} | {error, line, col, near}
 *
 * Loaded in the browser before tunnelq.js; also require()-able from node for the unit tests.
 */
(function (root) {
  'use strict';
  var P = root.PCDN = root.PCDN || {};

  // ------------------------------------------------------------------ masking

  var UUID_RE = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi;
  var SECRET_KEYS = /^(id|uuid|password|pass|psk|privatekey|private_key|privkey|shortids?|short_ids?|short_id|secret|key|seed|auth|auth_str|token)$/i;

  function tail(s) { s = String(s); return s.length <= 4 ? '…' : '…' + s.slice(-4); }
  /** Shortens every UUID and every value of a secret-looking JSON key (password, privateKey, …). */
  function mask(text) {
    var s = String(text === undefined || text === null ? '' : text);
    s = s.replace(UUID_RE, function (u) { return '********-****-****-****-****' + u.slice(-4); });
    // "privateKey": "…", "password": "…", "short_id": ["…"]
    s = s.replace(/("(?:[A-Za-z_]+)"\s*:\s*)("(?:[^"\\]|\\.)*"|\[[^\]]*\])/g, function (m, k, v) {
      var name = k.replace(/[\s":]/g, '');
      if (!SECRET_KEYS.test(name)) return m;
      if (v.charAt(0) === '[') return k + v.replace(/"((?:[^"\\]|\\.)*)"/g, function (x, inner) { return '"' + tail(inner) + '"'; });
      return k + '"' + tail(v.slice(1, -1)) + '"';
    });
    // share links: vless://<uuid>@host, trojan://<password>@host
    s = s.replace(/\b(vless|vmess|trojan|ss|hysteria2?|tuic):\/\/([^@\s]{5,})@/gi, function (m, proto, secret) { return proto + '://' + tail(secret) + '@'; });
    return s;
  }

  // ------------------------------------------------------------------ tolerant JSON (comments, trailing commas)

  /** Removes // and /* *\/ comments and trailing commas outside strings, keeping line breaks (positions). */
  function strip(text) {
    var out = '', i = 0, n = text.length, inStr = false;
    while (i < n) {
      var c = text.charAt(i), d = text.charAt(i + 1);
      if (inStr) {
        out += c;
        if (c === '\\') { out += d; i += 2; continue; }
        if (c === '"') inStr = false;
        i++;
        continue;
      }
      if (c === '"') { inStr = true; out += c; i++; continue; }
      if (c === '/' && d === '/') { while (i < n && text.charAt(i) !== '\n') { out += ' '; i++; } continue; }
      if (c === '/' && d === '*') {
        out += '  '; i += 2;
        while (i < n && !(text.charAt(i) === '*' && text.charAt(i + 1) === '/')) { out += text.charAt(i) === '\n' ? '\n' : ' '; i++; }
        out += '  '; i += 2;
        continue;
      }
      if (c === '#' && /(^|\n)\s*$/.test(out)) { while (i < n && text.charAt(i) !== '\n') { out += ' '; i++; } continue; }
      out += c;
      i++;
    }
    // trailing commas before } or ]
    return out.replace(/,(\s*[}\]])/g, ' $1');
  }

  function lineCol(text, pos) {
    var line = 1, col = 1;
    for (var i = 0; i < pos && i < text.length; i++) { if (text.charAt(i) === '\n') { line++; col = 1; } else col++; }
    return { line: line, col: col };
  }

  function parse(text) {
    var raw = String(text || '').replace(/^﻿/, '');
    if (!raw.trim()) return { error: 'empty' };
    var t = raw.trim();
    if (/^(vless|vmess|trojan|ss|hysteria2?|tuic):\/\//i.test(t)) return { error: 'link' };
    if (/^(proxies|port|mixed-port|allow-lan)\s*:/m.test(t) && t.charAt(0) !== '{') return { error: 'yaml' };
    var s = strip(raw);
    try {
      return { data: JSON.parse(s) };
    } catch (e) {
      var m = /position\s+(\d+)/i.exec(String(e && e.message));
      var lc = null;
      if (m) lc = lineCol(s, Number(m[1]));
      else {
        var m2 = /line\s+(\d+)\s+column\s+(\d+)/i.exec(String(e && e.message));
        if (m2) lc = { line: Number(m2[1]), col: Number(m2[2]) };
      }
      var near = lc ? (raw.split('\n')[lc.line - 1] || '').trim().slice(0, 120) : '';
      return { error: 'json', line: lc ? lc.line : null, col: lc ? lc.col : null, near: mask(near) };
    }
  }

  // ------------------------------------------------------------------ inbound model

  var PROTO_LABEL = { grpc: 'gRPC', xhttp: 'XHTTP', ws: 'WebSocket', httpupgrade: 'HTTPUpgrade', h2: 'HTTP/2 (h2)' };
  var TUNNEL_PROTOCOLS = { vless: 1, vmess: 1, trojan: 1 };
  var LOOPBACK = /^(127\.\d+\.\d+\.\d+|localhost|::1|\[::1\])$/i;

  function obj(x) { return x && typeof x === 'object' && !Array.isArray(x) ? x : null; }
  function str(x) { return typeof x === 'string' ? x : x === undefined || x === null ? '' : String(x); }
  function portOf(v) {
    if (typeof v === 'number' && isFinite(v)) return Math.floor(v);
    if (typeof v === 'string' && /^\d{1,5}$/.test(v.trim())) return Number(v.trim());
    return null;
  }

  /** Normalised inbound: {idx, tag, proto, network, path, pathKey, port, portRaw, listen, security, alpn, certs, mode, host, flow, decryption, clients, proxyProtocol, kind} */
  function xrayInbound(ib, idx) {
    var ss = obj(ib.streamSettings) || {};
    var net = str(ss.network || 'tcp').toLowerCase();
    if (net === 'raw') net = 'tcp';
    if (net === 'splithttp') net = 'xhttp';
    if (net === 'http') net = 'h2';
    var path = null, field = null, mode = null, host = null;
    if (net === 'ws') { var w = obj(ss.wsSettings) || {}; path = w.path; field = 'wsSettings.path'; host = w.host || (obj(w.headers) || {}).Host || null; }
    else if (net === 'httpupgrade') { var hu = obj(ss.httpupgradeSettings) || {}; path = hu.path; field = 'httpupgradeSettings.path'; host = hu.host || null; }
    else if (net === 'xhttp') {
      var xs = obj(ss.xhttpSettings) || obj(ss.splithttpSettings) || {};
      path = xs.path; field = 'xhttpSettings.path'; mode = xs.mode ? str(xs.mode) : 'auto'; host = xs.host || null;
    } else if (net === 'grpc') { var g = obj(ss.grpcSettings) || {}; path = g.serviceName; field = 'grpcSettings.serviceName'; }
    else if (net === 'h2') { var hs = obj(ss.httpSettings) || {}; path = hs.path; field = 'httpSettings.path'; }
    var settings = obj(ib.settings) || {};
    var clients = Array.isArray(settings.clients) ? settings.clients : [];
    var sec = str(ss.security || 'none').toLowerCase();
    var tls = obj(ss.tlsSettings) || {};
    var sock = obj(ss.sockopt) || {};
    return {
      kind: 'xray', idx: idx, tag: str(ib.tag), proto: str(ib.protocol).toLowerCase(), network: net,
      path: path === undefined || path === null ? null : str(path), pathField: field,
      port: portOf(ib.port), portRaw: ib.port, listen: ib.listen === undefined || ib.listen === null ? '' : str(ib.listen),
      security: sec === '' ? 'none' : sec, alpn: Array.isArray(tls.alpn) ? tls.alpn.map(str) : null,
      certs: Array.isArray(tls.certificates) ? tls.certificates.length : 0, mode: mode, host: host ? str(host) : null,
      flows: clients.map(function (c) { return str((obj(c) || {}).flow); }).filter(Boolean),
      decryption: settings.decryption === undefined ? null : str(settings.decryption), clients: clients.length,
      proxyProtocol: !!(sock.acceptProxyProtocol || (obj(ss.wsSettings) || {}).acceptProxyProtocol || (obj(ss.tcpSettings) || {}).acceptProxyProtocol
        || (obj(ss.rawSettings) || {}).acceptProxyProtocol || (obj(ss.httpupgradeSettings) || {}).acceptProxyProtocol)
    };
  }

  function singboxInbound(ib, idx) {
    var tr = obj(ib.transport) || {};
    var t = str(tr.type).toLowerCase();
    var net = t === '' ? 'tcp' : t === 'http' ? 'h2' : t;
    var path = null, field = null, host = null;
    if (net === 'ws') { path = tr.path; field = 'transport.path'; host = (obj(tr.headers) || {}).Host || null; }
    else if (net === 'httpupgrade') { path = tr.path; field = 'transport.path'; host = tr.host || null; }
    else if (net === 'grpc') { path = tr.service_name; field = 'transport.service_name'; }
    else if (net === 'h2') { path = tr.path; field = 'transport.path'; }
    var tls = obj(ib.tls) || {};
    var reality = obj(tls.reality) || {};
    var users = Array.isArray(ib.users) ? ib.users : [];
    return {
      kind: 'singbox', idx: idx, tag: str(ib.tag), proto: str(ib.type).toLowerCase(), network: net,
      path: path === undefined || path === null ? null : str(path), pathField: field,
      port: portOf(ib.listen_port), portRaw: ib.listen_port, listen: ib.listen === undefined || ib.listen === null ? '' : str(ib.listen),
      security: reality.enabled ? 'reality' : tls.enabled ? 'tls' : 'none', alpn: Array.isArray(tls.alpn) ? tls.alpn.map(str) : null,
      certs: tls.certificate_path || tls.certificate || (obj(tls.acme) || null) ? 1 : 0, mode: null, host: host ? str(host) : null,
      flows: users.map(function (u) { return str((obj(u) || {}).flow); }).filter(Boolean),
      decryption: null, clients: users.length, proxyProtocol: !!ib.proxy_protocol
    };
  }

  /** {kind, inbounds, clientish} from parsed JSON (full config, an inbounds array or one inbound object). */
  function model(data) {
    var list = null, kind = null;
    if (Array.isArray(data)) list = data;
    else if (obj(data) && Array.isArray(data.inbounds)) list = data.inbounds;
    else if (obj(data) && (data.protocol || data.type) && (data.port !== undefined || data.listen_port !== undefined || data.streamSettings || data.transport)) list = [data];
    if (!list) {
      var hasOut = obj(data) && Array.isArray(data.outbounds) && data.outbounds.some(function (o) { var p = str((obj(o) || {}).protocol || (obj(o) || {}).type).toLowerCase(); return !!TUNNEL_PROTOCOLS[p]; });
      return { kind: null, inbounds: [], clientish: !!hasOut };
    }
    var items = list.filter(obj);
    var sb = items.some(function (x) { return x.type !== undefined && x.protocol === undefined; });
    var xr = items.some(function (x) { return x.protocol !== undefined; });
    kind = sb && !xr ? 'singbox' : 'xray';
    var inbounds = items.map(function (x, i) { return kind === 'singbox' ? singboxInbound(x, i) : xrayInbound(x, i); });
    var tunnelish = inbounds.filter(function (x) { return TUNNEL_PROTOCOLS[x.proto]; });
    var localOnly = inbounds.length > 0 && !tunnelish.length && inbounds.every(function (x) { return /^(socks|mixed|http|tun|dokodemo-door|tproxy|redirect)$/.test(x.proto); });
    var hasOut2 = obj(data) && Array.isArray(data.outbounds) && data.outbounds.some(function (o) { var p = str((obj(o) || {}).protocol || (obj(o) || {}).type).toLowerCase(); return !!TUNNEL_PROTOCOLS[p]; });
    return { kind: kind, inbounds: inbounds, clientish: localOnly && hasOut2 };
  }

  // ------------------------------------------------------------------ checks

  function cdnProtocolOf(ib) {
    if (ib.network === 'grpc') return 'grpc';
    if (ib.network === 'ws') return 'ws';
    if (ib.network === 'httpupgrade') return 'httpupgrade';
    if (ib.network === 'xhttp') return ib.mode === 'stream-one' ? 'h2' : 'xhttp';
    return null;
  }
  function pathKey(proto, p) {
    p = str(p).split('?')[0];
    if (proto === 'grpc') return p.replace(/^\/+/, '');
    return p;
  }
  function label(ib) {
    return 'ورودی ' + (ib.tag ? '«' + mask(ib.tag) + '»' : 'شماره ' + (ib.idx + 1));
  }

  /**
   * Checks one config text against the site's tunnel paths.
   * @return {ok:boolean, kind, error, findings, summary:{error, warning, ok, info}}
   */
  function run(text, ctx) {
    ctx = ctx || {};
    var paths = Array.isArray(ctx.paths) ? ctx.paths : [];
    var findings = [];
    function add(level, code, title, fix, ib, p) {
      findings.push({ level: level, code: code, title: mask(title), fix: fix ? mask(fix) : null,
        inbound: ib ? label(ib) : null, path: p ? p.id : null });
    }
    var pr = parse(text);
    if (pr.error) {
      var msg = {
        empty: ['کانفیگی وارد نشده است.', 'محتوای فایل config.json سرور (Xray یا sing-box) را در کادر بچسبانید.'],
        link: ['این یک لینک اشتراک کلاینت است، نه کانفیگ سرور.', 'فایل JSON سرور را بچسبانید؛ برای Xray معمولاً ‎/usr/local/etc/xray/config.json و برای sing-box ‎/etc/sing-box/config.json است.'],
        yaml: ['این کانفیگ Clash / YAML به نظر می‌رسد، نه کانفیگ JSON سرور.', 'فایل JSON سرور Xray یا sing-box را بچسبانید.'],
        json: ['JSON نامعتبر است' + (pr.line ? ' (خط ' + pr.line + '، ستون ' + pr.col + ')' : '') + '.',
          'معمولاً یک کاما، گیومه یا آکولاد جا افتاده یا اضافه است.' + (pr.near ? ' نزدیک: ' + pr.near : '')]
      }[pr.error];
      add('error', 'parse-' + pr.error, msg[0], msg[1]);
      return finish(null, pr.error);
    }
    var m = model(pr.data);
    if (!m.inbounds.length) {
      if (m.clientish) add('error', 'client-config', 'این کانفیگ کلاینت است (فقط outbound دارد)، نه کانفیگ سرور.', 'کانفیگ سروری را بچسبانید که بخش inbounds با پروتکل vless / vmess / trojan دارد.');
      else add('error', 'no-inbounds', 'بخش inbounds در این کانفیگ پیدا نشد.', 'کانفیگ کامل سرور (با کلید "inbounds") را بچسبانید.');
      return finish(null, 'structure');
    }
    if (m.clientish) {
      add('error', 'client-config', 'این کانفیگ کلاینت است (ورودی‌ها socks / mixed / tun هستند)، نه کانفیگ سرور.', 'کانفیگ سرور Xray / sing-box را بچسبانید، نه کانفیگ برنامه روی گوشی یا کامپیوتر.');
      return finish(m.kind, 'structure');
    }
    if (!paths.length) add('warning', 'no-site-paths', 'هنوز هیچ مسیر تونلی برای این سایت ذخیره نشده است؛ فقط بررسی‌های عمومی انجام شد.', 'در صفحه «تونل / VPN» یک مسیر بسازید و ذخیره کنید، سپس دوباره بررسی کنید.');

    var tunnelIbs = m.inbounds.filter(function (ib) { return TUNNEL_PROTOCOLS[ib.proto]; });
    m.inbounds.forEach(function (ib) {
      if (!TUNNEL_PROTOCOLS[ib.proto] && ib.proto) {
        add('info', 'other-inbound', label(ib) + ' با پروتکل ' + ib.proto + ' ربطی به تونل CDN ندارد و بررسی نشد.', null, ib);
      }
    });
    if (!tunnelIbs.length) {
      add('error', 'no-tunnel-inbound', 'هیچ ورودی vless / vmess / trojan در کانفیگ نیست.', 'یک ورودی VLESS با یکی از انتقال‌های gRPC، WebSocket، HTTPUpgrade یا XHTTP اضافه کنید؛ «پیکربندی آماده» در صفحه تونل نمونه کامل می‌دهد.');
    }
    var covered = {};
    tunnelIbs.forEach(function (ib) { checkInbound(ib, m.kind, paths, ctx, add, covered); });
    if (tunnelIbs.length) {
      paths.forEach(function (p) {
        if (!covered[p.id]) {
          add('info', 'path-not-in-config', 'مسیر ' + p.path + ' (' + (PROTO_LABEL[p.protocol] || p.protocol) + ') در این کانفیگ نیست.',
            'اگر این مسیر به سرور دیگری می‌رود اشکالی ندارد؛ وگرنه ورودی آن را از «پیکربندی آماده» اضافه کنید.', null, p);
        }
      });
    }
    return finish(m.kind, null);

    function finish(kind, err) {
      var sum = { error: 0, warning: 0, ok: 0, info: 0 };
      findings.forEach(function (f) { sum[f.level]++; });
      var order = { error: 0, warning: 1, info: 2, ok: 3 };
      findings.sort(function (a, b) { return order[a.level] - order[b.level]; });
      return { ok: sum.error === 0 && !err, kind: kind, error: err, findings: findings, summary: sum };
    }
  }

  function checkInbound(ib, kind, paths, ctx, add, covered) {
    var L = label(ib);
    // transport
    if (ib.network === 'tcp' || ib.network === 'kcp' || ib.network === 'mkcp' || ib.network === 'quic' || ib.network === 'domainsocket') {
      add('error', 'transport-unsupported', L + ': انتقال ' + (ib.network === 'tcp' ? 'TCP / RAW' : ib.network) + ' از CDN عبور نمی‌کند.',
        'CDN فقط ترافیک HTTP را عبور می‌دهد؛ network را یکی از grpc، ws، httpupgrade یا xhttp بگذارید (مطابق پروتکل مسیر در صفحه تونل).', ib);
      return;
    }
    if (ib.network === 'h2') {
      add('error', 'transport-h2-legacy', L + ': انتقال قدیمی HTTP/2 (' + (kind === 'singbox' ? 'transport http' : 'network: http / h2') + ') با مسیرهای تونل سازگار نیست.',
        kind === 'singbox' ? 'در sing-box انتقال grpc یا ws را استفاده کنید.' : 'برای مسیر «HTTP/2 خام (h2)»، ورودی XHTTP با mode: "stream-one" بسازید؛ یا از gRPC استفاده کنید.', ib);
      return;
    }
    // security
    if (ib.security === 'reality') {
      add('error', 'reality', L + ': REALITY پشت CDN کار نمی‌کند.', 'CDN خودش TLS را باز می‌کند؛ security را "none" بگذارید (یا "tls" با گواهی معتبر اگر «اتصال با TLS» در مسیر روشن است).', ib);
    }
    if (ib.proxyProtocol) {
      add('error', 'proxy-protocol', L + ': acceptProxyProtocol روشن است ولی CDN هدر PROXY نمی‌فرستد.', 'acceptProxyProtocol را حذف یا false کنید؛ وگرنه همه اتصال‌ها رد می‌شوند.', ib);
    }
    if (ib.proto === 'vless') {
      if (ib.decryption !== null && ib.decryption !== 'none') add('error', 'vless-decryption', L + ': در VLESS مقدار decryption باید "none" باشد.', 'در settings بنویسید: "decryption": "none".', ib);
      if (ib.flows.some(function (f) { return /vision/i.test(f); })) {
        add('error', 'vision-flow', L + ': flow «xtls-rprx-vision» فقط با TCP/RAW و TLS/REALITY مستقیم کار می‌کند، نه پشت CDN.', 'flow را از کلاینت‌های این ورودی حذف کنید (خالی بگذارید).', ib);
      }
    }
    if (!ib.clients) add('error', 'no-clients', L + ': هیچ کاربری (clients / users) تعریف نشده است.', 'دست‌کم یک کاربر با UUID اضافه کنید؛ همان UUID باید در لینک کلاینت باشد.', ib);
    if (kind === 'xray' && ib.network === 'xhttp' && !/^(auto|packet-up|stream-up|stream-one)$/.test(ib.mode || '')) {
      add('warning', 'xhttp-mode-unknown', L + ': mode «' + ib.mode + '» برای XHTTP شناخته‌شده نیست.', 'یکی از auto، packet-up، stream-up یا stream-one را بگذارید.', ib);
    }
    // path syntax
    var proto = cdnProtocolOf(ib);
    if (ib.path === null || ib.path === '') {
      add('error', 'path-missing', L + ': ' + (ib.network === 'grpc' ? 'serviceName' : 'path') + ' تعیین نشده است.',
        'مقدار ' + (ib.pathField || 'path') + ' را دقیقاً برابر مسیر ساخته‌شده در صفحه تونل بگذارید' + (ib.network === 'grpc' ? ' (بدون / اول).' : ' (با / اول).'), ib);
      return;
    }
    if (ib.network === 'grpc') {
      if (/^\//.test(ib.path)) add('warning', 'grpc-leading-slash', L + ': serviceName نباید با / شروع شود.', 'serviceName همان مسیر تونل بدون / اول است؛ مثلاً برای /abc بنویسید "abc".', ib);
      if (/\/.+/.test(ib.path.replace(/^\/+/, ''))) add('warning', 'grpc-multi-segment', L + ': serviceName چندبخشی (با / میانی) در بعضی کلاینت‌ها کار نمی‌کند.', 'یک مسیر تک‌بخشی بسازید.', ib);
    } else if (!/^\//.test(ib.path)) {
      add('error', 'path-no-slash', L + ': مسیر «' + ib.path + '» با / شروع نمی‌شود.', 'در ' + (ib.pathField || 'path') + ' مسیر را با / بنویسید: "/' + ib.path + '".', ib);
    }
    if (/\s/.test(ib.path)) add('error', 'path-space', L + ': مسیر فاصله دارد.', 'فاصله‌های اول/آخر یا وسط مسیر را حذف کنید.', ib);
    // match against the site's paths
    var key = pathKey(ib.network === 'grpc' ? 'grpc' : 'other', ib.path.trim());
    var keyFixed = ib.network === 'grpc' ? key : (key.charAt(0) === '/' ? key : '/' + key);
    var match = null, protoMismatch = null;
    paths.forEach(function (p) {
      var pk = p.protocol === 'grpc' ? pathKey('grpc', p.path) : pathKey('other', p.path);
      var ik = p.protocol === 'grpc' ? key.replace(/^\/+/, '') : keyFixed;
      if (pk === ik) { if (p.protocol === proto || (p.protocol === 'h2' && ib.network === 'xhttp') || (p.protocol === 'xhttp' && ib.network === 'xhttp')) match = match || p; else protoMismatch = protoMismatch || p; }
    });
    if (/\?/.test(ib.path) && ib.network !== 'ws') add('warning', 'path-query', L + ': مسیر علامت ? دارد.', 'پارامتر را از مسیر حذف کنید؛ فقط در WebSocket پارامتر ?ed= برای early-data معنی دارد.', ib);
    if (!match && protoMismatch) {
      covered[protoMismatch.id] = true;
      add('error', 'protocol-mismatch', L + ': مسیر ' + protoMismatch.path + ' در صفحه تونل «' + (PROTO_LABEL[protoMismatch.protocol] || protoMismatch.protocol) + '» است ولی این ورودی «' + (PROTO_LABEL[proto] || ib.network) + '» است.',
        'یا network ورودی را ' + netFor(protoMismatch.protocol, kind) + ' کنید، یا پروتکل مسیر را در صفحه تونل تغییر دهید.', ib, protoMismatch);
      return;
    }
    if (!match) {
      var similar = paths.filter(function (p) { return p.protocol === proto; }).map(function (p) { return p.path; });
      add('error', 'path-unknown', L + ': مسیر «' + ib.path + '» در مسیرهای تونل این سایت نیست.',
        similar.length ? 'مسیرهای ' + (PROTO_LABEL[proto] || '') + ' سایت: ' + similar.join('، ') + ' — یکی را دقیقاً (حروف کوچک و بزرگ مهم است) در ' + (ib.pathField || 'path') + ' بگذارید.'
          : 'در صفحه تونل یک مسیر ' + (PROTO_LABEL[proto] || '') + ' بسازید و همان را اینجا بگذارید.', ib);
      return;
    }
    covered[match.id] = true;
    add('ok', 'path-match', L + ': مسیر و پروتکل با مسیر ' + match.path + ' (' + (PROTO_LABEL[match.protocol] || match.protocol) + ') یکی است.', null, ib, match);
    if (kind === 'singbox' && match.protocol === 'xhttp') {
      add('error', 'singbox-xhttp', L + ': sing-box انتقال XHTTP ندارد.', 'برای این مسیر از Xray استفاده کنید یا پروتکل مسیر را gRPC / WebSocket بگذارید.', ib, match);
    }
    // xhttp mode hints
    if (ib.network === 'xhttp') {
      if (match.protocol === 'h2' && ib.mode !== 'stream-one') add('error', 'xhttp-mode-h2', L + ': مسیر از نوع «HTTP/2 خام (h2)» است و ورودی باید mode: "stream-one" داشته باشد.', 'در xhttpSettings بنویسید: "mode": "stream-one".', ib, match);
      else if (match.protocol === 'xhttp' && ib.mode === 'stream-one') add('warning', 'xhttp-mode-stream-one', L + ': mode «stream-one» برای مسیر XHTTP مناسب نیست.', 'mode را "auto" بگذارید (پیشنهادی)؛ stream-one فقط برای مسیر h2 است.', ib, match);
      else if (match.protocol === 'xhttp' && ib.mode === 'stream-up') add('info', 'xhttp-mode-stream-up', L + ': mode «stream-up» سریع‌تر است ولی در شبکه‌های محدود packet-up یا auto پایدارتر است.', null, ib, match);
    }
    if (ib.host && ctx.domain && !hostOk(ib.host, ctx.domain)) {
      add('warning', 'host-mismatch', L + ': host «' + ib.host + '» زیر دامنه ' + ctx.domain + ' نیست.', 'host را خالی بگذارید یا نام پروکسی‌شده همین دامنه را بنویسید؛ CDN درخواست را با نام دامنه شما به سرور می‌فرستد.', ib, match);
    }
    // port
    var ports = Array.isArray(match.ports) ? match.ports.filter(function (x) { return typeof x === 'number'; }) : [];
    if (ib.port === null) {
      add('warning', 'port-unknown', L + ': پورت «' + mask(str(ib.portRaw)) + '» عدد ثابت نیست و قابل بررسی نیست.', 'پورت را یک عدد ثابت بگذارید' + (ports.length ? ' (' + ports.join(' یا ') + ').' : '.'), ib, match);
    } else if (ports.length && ports.indexOf(ib.port) < 0) {
      add('error', 'port-mismatch', L + ': پورت ' + ib.port + ' است ولی CDN برای مسیر ' + match.path + ' به پورت ' + ports.join(' یا ') + ' وصل می‌شود.',
        match.mode === 'custom' ? 'پورت ورودی را ' + ports[0] + ' کنید یا در صفحه تونل پورت سرور مقصد این مسیر را ' + ib.port + ' بگذارید.'
          : 'پورت ورودی را ' + ports[0] + ' کنید یا مقصد مسیر را «آدرس و پورت دلخواه» با پورت ' + ib.port + ' بگذارید.', ib, match);
    } else if (ports.length) {
      add('ok', 'port-match', L + ': پورت ' + ib.port + ' با پورت مقصد مسیر یکی است.', null, ib, match);
      if (match.mode === 'site' && (ib.port === 80 || ib.port === 443)) {
        add('info', 'port-webserver', L + ': اگر وب‌سرور (nginx / Apache) هم روی پورت ' + ib.port + ' این سرور است، Xray نمی‌تواند همزمان روی آن گوش دهد.', 'یا مسیر را در وب‌سرور به Xray پاس دهید، یا مقصد مسیر را «آدرس و پورت دلخواه» (مثلاً ۲۰۵۳) بگذارید.', ib, match);
      }
    }
    // listen address
    var lis = ib.listen.trim();
    if (lis && (LOOPBACK.test(lis) || /^\/|^@/.test(lis))) {
      if (match.mode === 'site') add('warning', 'listen-local', L + ': روی ' + (/^\/|^@/.test(lis) ? 'سوکت محلی' : lis) + ' گوش می‌دهد؛ فقط وقتی کار می‌کند که وب‌سرور همین سرور مسیر را به آن پاس دهد.', 'اگر وب‌سروری جلوی Xray نیست، listen را "0.0.0.0" بگذارید.', ib, match);
      else add('error', 'listen-local', L + ': روی ' + (/^\/|^@/.test(lis) ? 'سوکت محلی' : lis) + ' گوش می‌دهد و نودهای CDN نمی‌توانند به آن وصل شوند.', 'listen را "0.0.0.0" (یا "::") بگذارید یا کلاً حذف کنید.', ib, match);
    }
    // TLS expectation (origin.tls)
    var want = !!match.tls;
    if (ib.security === 'tls' && !want) {
      add('error', 'tls-unexpected', L + ': TLS روی ورودی روشن است ولی «اتصال CDN به سرور با TLS» در مسیر خاموش است.', 'security را "none" کنید و tlsSettings را حذف کنید (پیشنهادی)، یا در صفحه تونل «اتصال با TLS» این مسیر را روشن کنید.', ib, match);
    } else if (ib.security === 'none' && want) {
      add('error', 'tls-missing', L + ': مسیر با TLS به سرور وصل می‌شود ولی ورودی TLS ندارد.', 'security را "tls" با گواهی معتبر بگذارید، یا در صفحه تونل «اتصال با TLS» را خاموش کنید.', ib, match);
    } else if (ib.security === 'tls' && want) {
      if (!ib.certs) add('error', 'tls-no-cert', L + ': TLS روشن است ولی گواهی (certificates) تعریف نشده است.', 'مسیر فایل گواهی و کلید را در tlsSettings.certificates بگذارید.', ib, match);
      else add('ok', 'tls-match', L + ': تنظیم TLS با مسیر هماهنگ است.', null, ib, match);
      var needH2 = match.protocol === 'grpc' || match.protocol === 'h2';
      if (ib.alpn && ib.alpn.length && needH2 && ib.alpn.indexOf('h2') < 0) add('warning', 'alpn-h2', L + ': برای ' + PROTO_LABEL[match.protocol] + ' مقدار alpn باید h2 داشته باشد.', 'در tlsSettings بنویسید: "alpn": ["h2"].', ib, match);
      if (ib.alpn && ib.alpn.length && !needH2 && match.protocol !== 'xhttp' && ib.alpn.indexOf('http/1.1') < 0) add('warning', 'alpn-http11', L + ': برای ' + PROTO_LABEL[match.protocol] + ' مقدار alpn باید http/1.1 داشته باشد.', 'در tlsSettings بنویسید: "alpn": ["http/1.1"].', ib, match);
    } else if (ib.security === 'none' && !want) {
      add('ok', 'tls-match', L + ': بدون TLS؛ درست است (CDN خودش TLS بازدیدکننده را باز می‌کند).', null, ib, match);
    }
  }

  function netFor(proto, kind) {
    if (proto === 'h2') return kind === 'singbox' ? 'grpc (sing-box مسیر h2 را پشتیبانی نمی‌کند)' : '"xhttp" با mode: "stream-one"';
    return '"' + proto + '"';
  }
  function hostOk(host, domain) {
    host = str(host).toLowerCase().replace(/\.$/, '');
    domain = str(domain).toLowerCase();
    return host === domain || host.slice(-domain.length - 1) === '.' + domain;
  }

  P.tunnelCheck = { run: run, parse: parse, mask: mask, strip: strip, _model: model };
  if (typeof module !== 'undefined' && module.exports) module.exports = P.tunnelCheck;
})(typeof window !== 'undefined' ? window : this);
