/*
 * Pasargad CDN — «بررسی کانفیگ سرور» checker (docs/SPEC.md §15.7). Pure logic, no DOM, no network.
 *
 * The customer pastes an Xray or sing-box SERVER config; it is parsed and checked here, in the
 * browser only — never sent to WHMCS or the controller, never stored (not even localStorage).
 * Secrets (UUIDs, passwords, private keys, short ids) are never echoed back in full: every text
 * the checker returns goes through mask().
 *
 *   PCDN.tunnelCheck.run(text, ctx) → {ok, kind: 'xray'|'singbox'|null, error, findings: [...], summary}
 *     ctx = {domain, paths: [{id, path, protocol, ports: [int], tls: bool, mode: 'site'|'custom'|'pool'|'multi',
 *                             idle_timeout_s?: int, keepalive_s?: int}]}
 *       idle_timeout_s / keepalive_s come from GET tunnel/profile (wave 13, §22.5); without them (older controller) the
 *       keepalive / idle-timeout findings (codes timeout.*) are skipped.
 *     finding = {level: 'error'|'warning'|'ok'|'info', code, title, fix|null, inbound|null, path|null}
 *   PCDN.tunnelCheck.mask(text) → text with secrets shortened (…ab12)
 *   PCDN.tunnelCheck.parse(text) → {data} | {error, line, col, near}
 *
 * Loaded in the browser before tunnelq.js; also require()-able from node for the unit tests.
 */
(function (root) {
  'use strict';
  var P = root.PCDN = root.PCDN || {};
  // i18n.js (SPEC §16.10); identity outside the browser (node unit tests)
  var t = P.t || function (s) { var a = arguments; return String(s).replace(/\{(\d+)\}/g, function (m, i) { return a[+i + 1] === undefined ? m : String(a[+i + 1]); }); };

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
    var tx = raw.trim();
    if (/^(vless|vmess|trojan|ss|hysteria2?|tuic):\/\//i.test(tx)) return { error: 'link' };
    if (/^(proxies|port|mixed-port|allow-lan)\s*:/m.test(tx) && tx.charAt(0) !== '{') return { error: 'yaml' };
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
  /** Seconds of an Xray integer / sing-box duration string ("60s", "1m30s", "500ms"); null when unknown. */
  function secsOf(v) {
    if (typeof v === 'number' && isFinite(v)) return v;
    if (typeof v !== 'string' || !v.trim()) return null;
    var x = v.trim();
    if (/^\d+(\.\d+)?$/.test(x)) return Number(x);
    var re = /(\d+(?:\.\d+)?)(ms|h|m|s)/g, m2, tot = 0, used = '';
    while ((m2 = re.exec(x))) { tot += Number(m2[1]) * { ms: 0.001, h: 3600, m: 60, s: 1 }[m2[2]]; used += m2[0]; }
    return used === x ? tot : null;
  }
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
    var g2 = obj(ss.grpcSettings) || {}, xs2 = obj(ss.xhttpSettings) || obj(ss.splithttpSettings) || {};
    var xm = obj((obj(xs2.extra) || {}).xmux) || obj(xs2.xmux) || {};
    var timers = {
      ws_heartbeat: net === 'ws' ? secsOf((obj(ss.wsSettings) || {}).heartbeatPeriod) : null,
      grpc_idle: net === 'grpc' ? secsOf(g2.idle_timeout) : null, grpc_idle_field: 'grpcSettings.idle_timeout',
      grpc_ping: net === 'grpc' ? secsOf(g2.health_check_timeout) : null, grpc_ping_field: 'grpcSettings.health_check_timeout',
      xmux_keepalive: net === 'xhttp' ? secsOf(xm.hKeepAlivePeriod) : null,
      origin_idle: null, origin_idle_field: null,
      tcp_keepalive: sock.tcpKeepAliveIdle !== undefined || sock.tcpKeepAliveInterval !== undefined
    };
    return {
      timers: timers,
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
    var tx = str(tr.type).toLowerCase();
    var net = tx === '' ? 'tcp' : tx === 'http' ? 'h2' : tx;
    var path = null, field = null, host = null;
    if (net === 'ws') { path = tr.path; field = 'transport.path'; host = (obj(tr.headers) || {}).Host || null; }
    else if (net === 'httpupgrade') { path = tr.path; field = 'transport.path'; host = tr.host || null; }
    else if (net === 'grpc') { path = tr.service_name; field = 'transport.service_name'; }
    else if (net === 'h2') { path = tr.path; field = 'transport.path'; }
    var tls = obj(ib.tls) || {};
    var reality = obj(tls.reality) || {};
    var users = Array.isArray(ib.users) ? ib.users : [];
    // sing-box: grpc transport idle_timeout / ping_timeout are the HTTP/2 ping; an inbound or other transport idle_timeout closes idle connections
    var oi = ib.idle_timeout !== undefined ? secsOf(ib.idle_timeout) : (net !== 'grpc' && tr.idle_timeout !== undefined ? secsOf(tr.idle_timeout) : null);
    var timers = {
      ws_heartbeat: null,
      grpc_idle: net === 'grpc' ? secsOf(tr.idle_timeout) : null, grpc_idle_field: 'transport.idle_timeout',
      grpc_ping: net === 'grpc' ? secsOf(tr.ping_timeout) : null, grpc_ping_field: 'transport.ping_timeout',
      xmux_keepalive: null,
      origin_idle: oi, origin_idle_field: ib.idle_timeout !== undefined ? 'idle_timeout' : 'transport.idle_timeout',
      tcp_keepalive: false
    };
    return {
      timers: timers,
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
    // Xray closes a connection idle for policy.levels.<level>.connIdle seconds (default 300) — an origin-side idle timeout
    if (kind === 'xray' && obj(data)) {
      var lv = obj((obj(data.policy) || {}).levels) || {}, ci = null;
      Object.keys(lv).forEach(function (k) { var v = secsOf((obj(lv[k]) || {}).connIdle); if (v !== null && (ci === null || v < ci)) ci = v; });
      if (ci !== null) inbounds.forEach(function (ib) { ib.timers.origin_idle = ci; ib.timers.origin_idle_field = 'policy.levels.connIdle'; });
    }
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
    return t('ورودی ') + (ib.tag ? '«' + mask(ib.tag) + '»' : t('شماره ') + (ib.idx + 1));
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
        empty: [t('کانفیگی وارد نشده است.'), t('محتوای فایل config.json سرور (Xray یا sing-box) را در کادر بچسبانید.')],
        link: [t('این یک لینک اشتراک کلاینت است، نه کانفیگ سرور.'), t('فایل JSON سرور را بچسبانید؛ برای Xray معمولاً ‎/usr/local/etc/xray/config.json و برای sing-box ‎/etc/sing-box/config.json است.')],
        yaml: [t('این کانفیگ Clash / YAML به نظر می‌رسد، نه کانفیگ JSON سرور.'), t('فایل JSON سرور Xray یا sing-box را بچسبانید.')],
        json: [t('JSON نامعتبر است') + (pr.line ? t(' (خط ') + pr.line + t('، ستون ') + pr.col + ')' : '') + '.',
          t('معمولاً یک کاما، گیومه یا آکولاد جا افتاده یا اضافه است.') + (pr.near ? t(' نزدیک: ') + pr.near : '')]
      }[pr.error];
      add('error', 'parse-' + pr.error, msg[0], msg[1]);
      return finish(null, pr.error);
    }
    var m = model(pr.data);
    if (!m.inbounds.length) {
      if (m.clientish) add('error', 'client-config', t('این کانفیگ کلاینت است (فقط outbound دارد)، نه کانفیگ سرور.'), t('کانفیگ سروری را بچسبانید که بخش inbounds با پروتکل vless / vmess / trojan دارد.'));
      else add('error', 'no-inbounds', t('بخش inbounds در این کانفیگ پیدا نشد.'), t('کانفیگ کامل سرور (با کلید "inbounds") را بچسبانید.'));
      return finish(null, 'structure');
    }
    if (m.clientish) {
      add('error', 'client-config', t('این کانفیگ کلاینت است (ورودی‌ها socks / mixed / tun هستند)، نه کانفیگ سرور.'), t('کانفیگ سرور Xray / sing-box را بچسبانید، نه کانفیگ برنامه روی گوشی یا کامپیوتر.'));
      return finish(m.kind, 'structure');
    }
    if (!paths.length) add('warning', 'no-site-paths', t('هنوز هیچ مسیر تونلی برای این سایت ذخیره نشده است؛ فقط بررسی‌های عمومی انجام شد.'), t('در صفحه «تونل / VPN» یک مسیر بسازید و ذخیره کنید، سپس دوباره بررسی کنید.'));

    var tunnelIbs = m.inbounds.filter(function (ib) { return TUNNEL_PROTOCOLS[ib.proto]; });
    m.inbounds.forEach(function (ib) {
      if (!TUNNEL_PROTOCOLS[ib.proto] && ib.proto) {
        add('info', 'other-inbound', label(ib) + t(' با پروتکل ') + ib.proto + t(' ربطی به تونل CDN ندارد و بررسی نشد.'), null, ib);
      }
    });
    if (!tunnelIbs.length) {
      add('error', 'no-tunnel-inbound', t('هیچ ورودی vless / vmess / trojan در کانفیگ نیست.'), t('یک ورودی VLESS با یکی از انتقال‌های gRPC، WebSocket، HTTPUpgrade یا XHTTP اضافه کنید؛ «پیکربندی آماده» در صفحه تونل نمونه کامل می‌دهد.'));
    }
    var covered = {};
    tunnelIbs.forEach(function (ib) { checkInbound(ib, m.kind, paths, ctx, add, covered); });
    if (tunnelIbs.length) {
      paths.forEach(function (p) {
        if (!covered[p.id]) {
          add('info', 'path-not-in-config', t('مسیر ') + p.path + ' (' + (PROTO_LABEL[p.protocol] || p.protocol) + t(') در این کانفیگ نیست.'),
            t('اگر این مسیر به سرور دیگری می‌رود اشکالی ندارد؛ وگرنه ورودی آن را از «پیکربندی آماده» اضافه کنید.'), null, p);
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
      add('error', 'transport-unsupported', L + t(': انتقال ') + (ib.network === 'tcp' ? 'TCP / RAW' : ib.network) + t(' از CDN عبور نمی‌کند.'),
        t('CDN فقط ترافیک HTTP را عبور می‌دهد؛ network را یکی از grpc، ws، httpupgrade یا xhttp بگذارید (مطابق پروتکل مسیر در صفحه تونل).'), ib);
      return;
    }
    if (ib.network === 'h2') {
      add('error', 'transport-h2-legacy', L + t(': انتقال قدیمی HTTP/2 (') + (kind === 'singbox' ? 'transport http' : 'network: http / h2') + t(') با مسیرهای تونل سازگار نیست.'),
        kind === 'singbox' ? t('در sing-box انتقال grpc یا ws را استفاده کنید.') : t('برای مسیر «HTTP/2 خام (h2)»، ورودی XHTTP با mode: "stream-one" بسازید؛ یا از gRPC استفاده کنید.'), ib);
      return;
    }
    // security
    if (ib.security === 'reality') {
      add('error', 'reality', L + t(': REALITY پشت CDN کار نمی‌کند.'), t('CDN خودش TLS را باز می‌کند؛ security را "none" بگذارید (یا "tls" با گواهی معتبر اگر «اتصال با TLS» در مسیر روشن است).'), ib);
    }
    if (ib.proxyProtocol) {
      add('error', 'proxy-protocol', L + t(': acceptProxyProtocol روشن است ولی CDN هدر PROXY نمی‌فرستد.'), t('acceptProxyProtocol را حذف یا false کنید؛ وگرنه همه اتصال‌ها رد می‌شوند.'), ib);
    }
    if (ib.proto === 'vless') {
      if (ib.decryption !== null && ib.decryption !== 'none') add('error', 'vless-decryption', L + t(': در VLESS مقدار decryption باید "none" باشد.'), t('در settings بنویسید: "decryption": "none".'), ib);
      if (ib.flows.some(function (f) { return /vision/i.test(f); })) {
        add('error', 'vision-flow', L + t(': flow «xtls-rprx-vision» فقط با TCP/RAW و TLS/REALITY مستقیم کار می‌کند، نه پشت CDN.'), t('flow را از کلاینت‌های این ورودی حذف کنید (خالی بگذارید).'), ib);
      }
    }
    if (!ib.clients) add('error', 'no-clients', L + t(': هیچ کاربری (clients / users) تعریف نشده است.'), t('دست‌کم یک کاربر با UUID اضافه کنید؛ همان UUID باید در لینک کلاینت باشد.'), ib);
    if (kind === 'xray' && ib.network === 'xhttp' && !/^(auto|packet-up|stream-up|stream-one)$/.test(ib.mode || '')) {
      add('warning', 'xhttp-mode-unknown', L + ': mode «' + ib.mode + t('» برای XHTTP شناخته‌شده نیست.'), t('یکی از auto، packet-up، stream-up یا stream-one را بگذارید.'), ib);
    }
    // path syntax
    var proto = cdnProtocolOf(ib);
    if (ib.path === null || ib.path === '') {
      add('error', 'path-missing', L + ': ' + (ib.network === 'grpc' ? 'serviceName' : 'path') + t(' تعیین نشده است.'),
        t('مقدار ') + (ib.pathField || 'path') + t(' را دقیقاً برابر مسیر ساخته‌شده در صفحه تونل بگذارید') + (ib.network === 'grpc' ? t(' (بدون / اول).') : t(' (با / اول).')), ib);
      return;
    }
    if (ib.network === 'grpc') {
      if (/^\//.test(ib.path)) add('warning', 'grpc-leading-slash', L + t(': serviceName نباید با / شروع شود.'), t('serviceName همان مسیر تونل بدون / اول است؛ مثلاً برای /abc بنویسید "abc".'), ib);
      if (/\/.+/.test(ib.path.replace(/^\/+/, ''))) add('warning', 'grpc-multi-segment', L + t(': serviceName چندبخشی (با / میانی) در بعضی کلاینت‌ها کار نمی‌کند.'), t('یک مسیر تک‌بخشی بسازید.'), ib);
    } else if (!/^\//.test(ib.path)) {
      add('error', 'path-no-slash', L + t(': مسیر «') + ib.path + t('» با / شروع نمی‌شود.'), t('در ') + (ib.pathField || 'path') + t(' مسیر را با / بنویسید: "/') + ib.path + '".', ib);
    }
    if (/\s/.test(ib.path)) add('error', 'path-space', L + t(': مسیر فاصله دارد.'), t('فاصله‌های اول/آخر یا وسط مسیر را حذف کنید.'), ib);
    // match against the site's paths
    var key = pathKey(ib.network === 'grpc' ? 'grpc' : 'other', ib.path.trim());
    var keyFixed = ib.network === 'grpc' ? key : (key.charAt(0) === '/' ? key : '/' + key);
    var match = null, protoMismatch = null;
    paths.forEach(function (p) {
      var pk = p.protocol === 'grpc' ? pathKey('grpc', p.path) : pathKey('other', p.path);
      var ik = p.protocol === 'grpc' ? key.replace(/^\/+/, '') : keyFixed;
      if (pk === ik) { if (p.protocol === proto || (p.protocol === 'h2' && ib.network === 'xhttp') || (p.protocol === 'xhttp' && ib.network === 'xhttp')) match = match || p; else protoMismatch = protoMismatch || p; }
    });
    if (/\?/.test(ib.path) && ib.network !== 'ws') add('warning', 'path-query', L + t(': مسیر علامت ? دارد.'), t('پارامتر را از مسیر حذف کنید؛ فقط در WebSocket پارامتر ?ed= برای early-data معنی دارد.'), ib);
    if (!match && protoMismatch) {
      covered[protoMismatch.id] = true;
      add('error', 'protocol-mismatch', L + t(': مسیر ') + protoMismatch.path + t(' در صفحه تونل «') + (PROTO_LABEL[protoMismatch.protocol] || protoMismatch.protocol) + t('» است ولی این ورودی «') + (PROTO_LABEL[proto] || ib.network) + t('» است.'),
        t('یا network ورودی را ') + netFor(protoMismatch.protocol, kind) + t(' کنید، یا پروتکل مسیر را در صفحه تونل تغییر دهید.'), ib, protoMismatch);
      return;
    }
    if (!match) {
      var similar = paths.filter(function (p) { return p.protocol === proto; }).map(function (p) { return p.path; });
      add('error', 'path-unknown', L + t(': مسیر «') + ib.path + t('» در مسیرهای تونل این سایت نیست.'),
        similar.length ? t('مسیرهای ') + (PROTO_LABEL[proto] || '') + t(' سایت: ') + similar.join(t('، ')) + t(' — یکی را دقیقاً (حروف کوچک و بزرگ مهم است) در ') + (ib.pathField || 'path') + t(' بگذارید.')
          : t('در صفحه تونل یک مسیر ') + (PROTO_LABEL[proto] || '') + t(' بسازید و همان را اینجا بگذارید.'), ib);
      return;
    }
    covered[match.id] = true;
    add('ok', 'path-match', L + t(': مسیر و پروتکل با مسیر ') + match.path + ' (' + (PROTO_LABEL[match.protocol] || match.protocol) + t(') یکی است.'), null, ib, match);
    if (kind === 'singbox' && match.protocol === 'xhttp') {
      add('error', 'singbox-xhttp', L + t(': sing-box انتقال XHTTP ندارد.'), t('برای این مسیر از Xray استفاده کنید یا پروتکل مسیر را gRPC / WebSocket بگذارید.'), ib, match);
    }
    // xhttp mode hints
    if (ib.network === 'xhttp') {
      if (match.protocol === 'h2' && ib.mode !== 'stream-one') add('error', 'xhttp-mode-h2', L + t(': مسیر از نوع «HTTP/2 خام (h2)» است و ورودی باید mode: "stream-one" داشته باشد.'), t('در xhttpSettings بنویسید: "mode": "stream-one".'), ib, match);
      else if (match.protocol === 'xhttp' && ib.mode === 'stream-one') add('warning', 'xhttp-mode-stream-one', L + t(': mode «stream-one» برای مسیر XHTTP مناسب نیست.'), t('mode را "auto" بگذارید (پیشنهادی)؛ stream-one فقط برای مسیر h2 است.'), ib, match);
      else if (match.protocol === 'xhttp' && ib.mode === 'stream-up') add('info', 'xhttp-mode-stream-up', L + t(': mode «stream-up» سریع‌تر است ولی در شبکه‌های محدود packet-up یا auto پایدارتر است.'), null, ib, match);
    }
    if (ib.host && ctx.domain && !hostOk(ib.host, ctx.domain)) {
      add('warning', 'host-mismatch', L + ': host «' + ib.host + t('» زیر دامنه ') + ctx.domain + t(' نیست.'), t('host را خالی بگذارید یا نام پروکسی‌شده همین دامنه را بنویسید؛ CDN درخواست را با نام دامنه شما به سرور می‌فرستد.'), ib, match);
    }
    // port
    var ports = Array.isArray(match.ports) ? match.ports.filter(function (x) { return typeof x === 'number'; }) : [];
    if (ib.port === null) {
      add('warning', 'port-unknown', L + t(': پورت «') + mask(str(ib.portRaw)) + t('» عدد ثابت نیست و قابل بررسی نیست.'), t('پورت را یک عدد ثابت بگذارید') + (ports.length ? ' (' + ports.join(t(' یا ')) + ').' : '.'), ib, match);
    } else if (ports.length && ports.indexOf(ib.port) < 0) {
      add('error', 'port-mismatch', L + t(': پورت ') + ib.port + t(' است ولی CDN برای مسیر ') + match.path + t(' به پورت ') + ports.join(t(' یا ')) + t(' وصل می‌شود.'),
        match.mode === 'custom' ? t('پورت ورودی را ') + ports[0] + t(' کنید یا در صفحه تونل پورت سرور مقصد این مسیر را ') + ib.port + t(' بگذارید.')
          : t('پورت ورودی را ') + ports[0] + t(' کنید یا مقصد مسیر را «آدرس و پورت دلخواه» با پورت ') + ib.port + t(' بگذارید.'), ib, match);
    } else if (ports.length) {
      add('ok', 'port-match', L + t(': پورت ') + ib.port + t(' با پورت مقصد مسیر یکی است.'), null, ib, match);
      if (match.mode === 'site' && (ib.port === 80 || ib.port === 443)) {
        add('info', 'port-webserver', L + t(': اگر وب‌سرور (nginx / Apache) هم روی پورت ') + ib.port + t(' این سرور است، Xray نمی‌تواند همزمان روی آن گوش دهد.'), t('یا مسیر را در وب‌سرور به Xray پاس دهید، یا مقصد مسیر را «آدرس و پورت دلخواه» (مثلاً ۲۰۵۳) بگذارید.'), ib, match);
      }
    }
    // listen address
    var lis = ib.listen.trim();
    if (lis && (LOOPBACK.test(lis) || /^\/|^@/.test(lis))) {
      if (match.mode === 'site') add('warning', 'listen-local', L + t(': روی ') + (/^\/|^@/.test(lis) ? t('سوکت محلی') : lis) + t(' گوش می‌دهد؛ فقط وقتی کار می‌کند که وب‌سرور همین سرور مسیر را به آن پاس دهد.'), t('اگر وب‌سروری جلوی Xray نیست، listen را "0.0.0.0" بگذارید.'), ib, match);
      else add('error', 'listen-local', L + t(': روی ') + (/^\/|^@/.test(lis) ? t('سوکت محلی') : lis) + t(' گوش می‌دهد و نودهای CDN نمی‌توانند به آن وصل شوند.'), t('listen را "0.0.0.0" (یا "::") بگذارید یا کلاً حذف کنید.'), ib, match);
    }
    // TLS expectation (origin.tls)
    var want = !!match.tls;
    if (ib.security === 'tls' && !want) {
      add('error', 'tls-unexpected', L + t(': TLS روی ورودی روشن است ولی «اتصال CDN به سرور با TLS» در مسیر خاموش است.'), t('security را "none" کنید و tlsSettings را حذف کنید (پیشنهادی)، یا در صفحه تونل «اتصال با TLS» این مسیر را روشن کنید.'), ib, match);
    } else if (ib.security === 'none' && want) {
      add('error', 'tls-missing', L + t(': مسیر با TLS به سرور وصل می‌شود ولی ورودی TLS ندارد.'), t('security را "tls" با گواهی معتبر بگذارید، یا در صفحه تونل «اتصال با TLS» را خاموش کنید.'), ib, match);
    } else if (ib.security === 'tls' && want) {
      if (!ib.certs) add('error', 'tls-no-cert', L + t(': TLS روشن است ولی گواهی (certificates) تعریف نشده است.'), t('مسیر فایل گواهی و کلید را در tlsSettings.certificates بگذارید.'), ib, match);
      else add('ok', 'tls-match', L + t(': تنظیم TLS با مسیر هماهنگ است.'), null, ib, match);
      var needH2 = match.protocol === 'grpc' || match.protocol === 'h2';
      if (ib.alpn && ib.alpn.length && needH2 && ib.alpn.indexOf('h2') < 0) add('warning', 'alpn-h2', L + t(': برای ') + PROTO_LABEL[match.protocol] + t(' مقدار alpn باید h2 داشته باشد.'), t('در tlsSettings بنویسید: "alpn": ["h2"].'), ib, match);
      if (ib.alpn && ib.alpn.length && !needH2 && match.protocol !== 'xhttp' && ib.alpn.indexOf('http/1.1') < 0) add('warning', 'alpn-http11', L + t(': برای ') + PROTO_LABEL[match.protocol] + t(' مقدار alpn باید http/1.1 داشته باشد.'), t('در tlsSettings بنویسید: "alpn": ["http/1.1"].'), ib, match);
    } else if (ib.security === 'none' && !want) {
      add('ok', 'tls-match', L + t(': بدون TLS؛ درست است (CDN خودش TLS بازدیدکننده را باز می‌کند).'), null, ib, match);
    }
    checkTimers(ib, match, add, L);
  }

  /**
   * Wave 13 (§22.5): keepalive / ping intervals of the server inbound against the edge idle timeout of the matched path.
   * Codes: timeout.edge_idle (info), timeout.ws_heartbeat, timeout.grpc_idle, timeout.xmux_keepalive, timeout.origin_idle
   * (warnings with the recommended value), timeout.tcp_keepalive (info: socket keepalive does not keep a tunnel stream alive).
   */
  function checkTimers(ib, match, add, L) {
    var idle = match.idle_timeout_s;
    if (typeof idle !== 'number' || !isFinite(idle) || idle <= 0) return;
    var k = typeof match.keepalive_s === 'number' && match.keepalive_s > 0 ? match.keepalive_s : Math.max(10, Math.min(60, Math.floor(Math.min(idle, 600) / 3)));
    var tm = ib.timers || {};
    var LATE = t('فاصله‌ی keepalive از مهلت بیکاری لبه بیشتر است؛ اتصال بیکار قبل از ping قطع می‌شود.');
    add('info', 'timeout.edge_idle', L + t(': مهلت بیکاری لبه برای این مسیر: {0} ثانیه؛ keepalive پیشنهادی: {1} ثانیه.', idle, k), null, ib, match);
    function late(code, field, v, rec) {
      if (v === null || v === undefined || !(v >= idle - 5)) return;
      add('warning', code, L + ': ' + field + ' = ' + fmt(v) + ' — ' + LATE, t('مقدار پیشنهادی: ') + field + ' = ' + rec, ib, match);
    }
    function fmt(v) { return ib.kind === 'singbox' ? v + 's' : String(v); }
    late('timeout.ws_heartbeat', 'wsSettings.heartbeatPeriod', tm.ws_heartbeat, String(k));
    late('timeout.grpc_idle', tm.grpc_idle_field, tm.grpc_idle, ib.kind === 'singbox' ? k + 's' : String(k));
    late('timeout.grpc_idle', tm.grpc_ping_field, tm.grpc_ping, ib.kind === 'singbox' ? '20s' : '20');
    late('timeout.xmux_keepalive', 'xhttpSettings.extra.xmux.hKeepAlivePeriod', tm.xmux_keepalive, String(k));
    if (tm.origin_idle !== null && tm.origin_idle !== undefined && tm.origin_idle > 0 && tm.origin_idle < k) {
      add('warning', 'timeout.origin_idle', L + ': ' + tm.origin_idle_field + ' = ' + fmt(tm.origin_idle) + ' — ' + t('سرور شما اتصال بیکار را زودتر از ping کلاینت می‌بندد.'),
        t('مقدار پیشنهادی: {0} دست‌کم {1}', tm.origin_idle_field, ib.kind === 'singbox' ? Math.max(k * 2, 120) + 's' : String(Math.max(k * 2, 300))), ib, match);
    }
    if (tm.tcp_keepalive) {
      add('info', 'timeout.tcp_keepalive', L + t(': sockopt.tcpKeepAlive* فقط اتصال TCP بین نود و سرور را زنده نگه می‌دارد، نه جریان بیکار تونل را؛ برای آن keepalive برنامه‌ی کاربر را طبق «تنظیمات پیشنهادی» بگذارید.'), null, ib, match);
    }
  }

  function netFor(proto, kind) {
    if (proto === 'h2') return kind === 'singbox' ? t('grpc (sing-box مسیر h2 را پشتیبانی نمی‌کند)') : t('"xhttp" با mode: "stream-one"');
    return '"' + proto + '"';
  }
  function hostOk(host, domain) {
    host = str(host).toLowerCase().replace(/\.$/, '');
    domain = str(domain).toLowerCase();
    return host === domain || host.slice(-domain.length - 1) === '.' + domain;
  }

  P.tunnelCheck = { run: run, parse: parse, mask: mask, strip: strip, secs: secsOf, _model: model };
  if (typeof module !== 'undefined' && module.exports) module.exports = P.tunnelCheck;
})(typeof window !== 'undefined' ? window : this);
