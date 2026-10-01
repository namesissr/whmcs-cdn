// Pasargad CDN edge functions runtime (SPEC §16.9) — runs INSIDE the sandboxed QuickJS worker.
//
// This file is trusted glue, but it is NOT a security boundary: customer code runs in the same
// QuickJS context and can reach everything here (and `import("std")` / `import("os")`). Isolation is
// enforced outside the engine by pcdn-fn (one process per invocation, Landlock, seccomp, rlimits,
// CPU timer, systemd sandbox). Everything the worker writes is validated by pcdn-fn.
//
// Wire protocol with pcdn-fn (stdin / stdout of this process):
//   in : one JSON line {"v":1,"code_len":N,"body_len":M,"req":{method,url,headers,client}} then N
//        bytes of UTF-8 customer source, then M bytes of request body
//   out: zero or more fetch frames  {"t":"fetch",method,url,headers,body_text?|body_len}\n[body]
//        each answered on stdin by   {"status","headers","body_len"}\n<body> | {"error":"..."}\n
//        then exactly one final frame:
//          {"t":"resp","status":S,"headers":[[k,v],...]}\n<body bytes until EOF>
//          {"t":"pass"}\n                  (continue to the origin)
//          {"t":"error","message":"..."}\n (on_error applies)
import * as std from "std";
import * as os from "os";

const IN = std.in, OUT = std.out;

// ------------------------------------------------------------------ helpers

function readExact(n) {
  const ab = new ArrayBuffer(n);
  let off = 0;
  while (off < n) {
    const r = IN.read(ab, off, n - off);
    if (!(r > 0)) throw new Error("short read");
    off += r;
  }
  return new Uint8Array(ab);
}

function binStr(u8) {
  let s = "";
  for (let i = 0; i < u8.length; i += 8192) s += String.fromCharCode.apply(null, u8.subarray(i, i + 8192));
  return s;
}

function utf8Decode(u8) {
  const b = binStr(u8);
  try {
    return decodeURIComponent(escape(b));
  } catch (e) {   // invalid UTF-8: replace bad bytes with U+FFFD
    let out = "";
    for (let i = 0; i < u8.length;) {
      const c = u8[i];
      let n = c < 0x80 ? 1 : (c >> 5) === 6 ? 2 : (c >> 4) === 14 ? 3 : (c >> 3) === 30 ? 4 : 0;
      if (n === 0 || i + n > u8.length) { out += "�"; i++; continue; }
      try { out += decodeURIComponent(escape(b.substr(i, n))); } catch (e2) { out += "�"; i++; continue; }
      i += n;
    }
    return out;
  }
}

function utf8Encode(s) {
  const b = unescape(encodeURIComponent(String(s)));
  const u8 = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) u8[i] = b.charCodeAt(i);
  return u8;
}

function toBytes(body) {
  if (body == null) return null;
  if (body instanceof Uint8Array) return body;
  if (body instanceof ArrayBuffer) return new Uint8Array(body);
  if (ArrayBuffer.isView(body)) return new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
  return null;
}

// ------------------------------------------------------------------ Web-like API (subset)

class Headers {
  constructor(init) {
    this._h = [];   // [lowercase name, original name, value]
    if (init instanceof Headers) init.forEach((v, k) => this.append(k, v));
    else if (Array.isArray(init)) init.forEach((p) => this.append(p[0], p[1]));
    else if (init && typeof init === "object") Object.keys(init).forEach((k) => this.append(k, init[k]));
  }
  append(k, v) { this._h.push([String(k).toLowerCase(), String(k), String(v)]); }
  set(k, v) { this.delete(k); this.append(k, v); }
  delete(k) { const l = String(k).toLowerCase(); this._h = this._h.filter((e) => e[0] !== l); }
  has(k) { const l = String(k).toLowerCase(); return this._h.some((e) => e[0] === l); }
  get(k) {
    const l = String(k).toLowerCase();
    const v = this._h.filter((e) => e[0] === l).map((e) => e[2]);
    return v.length ? v.join(", ") : null;
  }
  getSetCookie() { return this._h.filter((e) => e[0] === "set-cookie").map((e) => e[2]); }
  forEach(fn) { this._h.forEach((e) => fn(e[2], e[0], this)); }
  *entries() { for (const e of this._h) yield [e[0], e[2]]; }
  *keys() { for (const e of this._h) yield e[0]; }
  *values() { for (const e of this._h) yield e[2]; }
  [Symbol.iterator]() { return this.entries(); }
  _list() { return this._h.map((e) => [e[1], e[2]]); }
}

class URLSearchParams {
  constructor(init) {
    this._p = [];
    if (typeof init === "string") {
      const s = init.charAt(0) === "?" ? init.slice(1) : init;
      for (const part of s.split("&")) {
        if (!part) continue;
        const i = part.indexOf("=");
        const k = i < 0 ? part : part.slice(0, i), v = i < 0 ? "" : part.slice(i + 1);
        this._p.push([dec(k), dec(v)]);
      }
    } else if (init && typeof init === "object") Object.keys(init).forEach((k) => this._p.push([k, String(init[k])]));
    function dec(x) { try { return decodeURIComponent(x.replace(/\+/g, " ")); } catch (e) { return x; } }
  }
  get(k) { const e = this._p.find((p) => p[0] === k); return e ? e[1] : null; }
  getAll(k) { return this._p.filter((p) => p[0] === k).map((p) => p[1]); }
  has(k) { return this._p.some((p) => p[0] === k); }
  set(k, v) { this.delete(k); this._p.push([String(k), String(v)]); }
  append(k, v) { this._p.push([String(k), String(v)]); }
  delete(k) { this._p = this._p.filter((p) => p[0] !== k); }
  forEach(fn) { this._p.forEach((p) => fn(p[1], p[0], this)); }
  *entries() { for (const p of this._p) yield [p[0], p[1]]; }
  [Symbol.iterator]() { return this.entries(); }
  toString() { return this._p.map((p) => encodeURIComponent(p[0]) + "=" + encodeURIComponent(p[1])).join("&"); }
}

const URL_RE = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^/?#@]*@)?(\[[0-9a-fA-F:.]+\]|[^/?#:]*)(?::(\d*))?([^?#]*)(\?[^#]*)?(#.*)?$/;

class URL {
  constructor(input, base) {
    let s = String(input);
    if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(s)) {
      if (base === undefined) throw new TypeError("Invalid URL: " + s);
      const b = new URL(base);
      if (s.startsWith("//")) s = b.protocol + s;
      else if (s.startsWith("/")) s = b.origin + s;
      else if (s.startsWith("?")) s = b.origin + b.pathname + s;
      else if (s.startsWith("#")) s = b.origin + b.pathname + b.search + s;
      else s = b.origin + b.pathname.replace(/[^/]*$/, "") + s;
    }
    const m = URL_RE.exec(s);
    if (!m) throw new TypeError("Invalid URL: " + s);
    this.protocol = m[1].toLowerCase() + ":";
    this.hostname = m[3].toLowerCase();
    this.port = m[4] || "";
    this.pathname = m[5] || "/";
    this.search = m[6] && m[6] !== "?" ? m[6] : "";
    this.hash = m[7] && m[7] !== "#" ? m[7] : "";
    this.searchParams = new URLSearchParams(this.search);
  }
  get host() { return this.hostname + (this.port ? ":" + this.port : ""); }
  get origin() { return this.protocol + "//" + this.host; }
  get href() { return this.origin + this.pathname + this.search + this.hash; }
  toString() { return this.href; }
  toJSON() { return this.href; }
}

class Body {
  _initBody(body) {
    const b = toBytes(body);
    this._bytes = b;
    this._text = b ? null : (body == null ? null : String(body));
    this.bodyUsed = false;
  }
  get body() { return this._bytes || this._text; }
  async text() { this.bodyUsed = true; return this._text != null ? this._text : this._bytes ? utf8Decode(this._bytes) : ""; }
  async json() { return JSON.parse(await this.text()); }
  async arrayBuffer() {
    this.bodyUsed = true;
    const b = this._bytes || utf8Encode(this._text || "");
    return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
  }
}

class Request extends Body {
  constructor(input, init) {
    super();
    init = init || {};
    const src = input instanceof Request ? input : null;
    this.url = src ? src.url : String(input);
    this.method = String(init.method || (src ? src.method : "GET")).toUpperCase();
    this.headers = new Headers(init.headers || (src ? src.headers : undefined));
    this._initBody(init.body !== undefined ? init.body : src ? src.body : null);
    this.client = src ? src.client : {};
  }
}

class Response extends Body {
  constructor(body, init) {
    super();
    init = init || {};
    this.status = init.status === undefined ? 200 : init.status | 0;
    this.statusText = init.statusText || "";
    this.headers = new Headers(init.headers);
    this._initBody(body);
  }
  get ok() { return this.status >= 200 && this.status < 300; }
  static json(data, init) {
    const r = new Response(JSON.stringify(data), init);
    if (!r.headers.has("content-type")) r.headers.set("content-type", "application/json");
    return r;
  }
  static redirect(url, status) {
    return new Response(null, { status: status || 302, headers: { location: String(url) } });
  }
}

// ------------------------------------------------------------------ host calls

const LOG_MAX = 4096;
let logLen = 0;
function logLine() {   // console output is bounded and discarded (never reaches the journal)
  logLen += Array.prototype.join.call(arguments, " ").length;
  if (logLen > LOG_MAX) logLen = LOG_MAX;
}

function frame(obj) { OUT.puts(JSON.stringify(obj) + "\n"); OUT.flush(); }

function hostFetch(input, init) {
  const req = input instanceof Request && init === undefined ? input : new Request(input, init);
  const f = { t: "fetch", method: req.method, url: String(req.url), headers: req.headers._list() };
  if (req._bytes) f.body_len = req._bytes.length;
  else if (req._text != null) f.body_text = req._text;
  frame(f);
  if (req._bytes) { OUT.write(req._bytes.buffer, req._bytes.byteOffset, req._bytes.length); OUT.flush(); }
  const line = IN.getline();
  if (line === null) throw new TypeError("fetch failed");
  const r = JSON.parse(line);
  if (r.error) throw new TypeError("fetch failed: " + r.error);
  const body = r.body_len ? readExact(r.body_len) : new Uint8Array(0);
  return new Response(body, { status: r.status, headers: r.headers });
}

globalThis.fetch = function (input, init) {
  try { return Promise.resolve(hostFetch(input, init)); } catch (e) { return Promise.reject(e); }
};
globalThis.Headers = Headers;
globalThis.Request = Request;
globalThis.Response = Response;
globalThis.URL = URL;
globalThis.URLSearchParams = URLSearchParams;
globalThis.TextEncoder = class TextEncoder { get encoding() { return "utf-8"; } encode(s) { return utf8Encode(s === undefined ? "" : s); } };
globalThis.TextDecoder = class TextDecoder { get encoding() { return "utf-8"; } decode(b) { const u = toBytes(b); return u ? utf8Decode(u) : ""; } };
globalThis.btoa = function (s) {
  const T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  s = String(s);
  let out = "";
  for (let i = 0; i < s.length; i += 3) {
    const a = s.charCodeAt(i), b = s.charCodeAt(i + 1), c = s.charCodeAt(i + 2);
    if (a > 255 || b > 255 || c > 255) throw new Error("btoa: non-latin1 character");
    out += T[a >> 2] + T[((a & 3) << 4) | (b >> 4 || 0)]
      + (i + 1 < s.length ? T[((b & 15) << 2) | (c >> 6 || 0)] : "=") + (i + 2 < s.length ? T[c & 63] : "=");
  }
  return out;
};
globalThis.atob = function (s) {
  const T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  s = String(s).replace(/[\s=]+/g, "");
  let out = "", bits = 0, acc = 0;
  for (const ch of s) {
    const v = T.indexOf(ch);
    if (v < 0) throw new Error("atob: invalid character");
    acc = (acc << 6) | v; bits += 6;
    if (bits >= 8) { bits -= 8; out += String.fromCharCode((acc >> bits) & 255); }
  }
  return out;
};
globalThis.setTimeout = (fn, ms, ...args) => os.setTimeout(() => fn(...args), Math.max(0, ms | 0));
globalThis.clearTimeout = (h) => { if (h) os.clearTimeout(h); };
globalThis.queueMicrotask = (fn) => { Promise.resolve().then(fn); };
globalThis.console = { log: logLine, info: logLine, warn: logLine, error: logLine, debug: logLine };
globalThis.print = logLine;

const listeners = [];
globalThis.addEventListener = function (type, fn) { if (type === "fetch" && typeof fn === "function") listeners.push(fn); };

// ------------------------------------------------------------------ run one invocation

let done = false;

function finish(obj, body) {
  if (done) return;
  done = true;
  frame(obj);
  if (body != null) {
    const b = toBytes(body);
    if (b) OUT.write(b.buffer, b.byteOffset, b.length);
    else OUT.puts(String(body));
  }
  OUT.flush();
  std.exit(0);
}

function fail(e) {
  finish({ t: "error", message: String((e && (e.name ? e.name + ": " + e.message : e)) || "error").slice(0, 200) });
}

function deliver(res) {
  if (res === null || res === undefined) return finish({ t: "pass" });
  if (!(res instanceof Response)) return fail(new TypeError("handler must return a Response, null or undefined"));
  finish({ t: "resp", status: res.status, headers: res.headers._list() }, res._bytes || res._text);
}

try {
  const hdr = JSON.parse(IN.getline());
  const code = hdr.code_len ? IN.readAsString(hdr.code_len) : "";
  const body = hdr.body_len ? readExact(hdr.body_len) : null;
  const rq = hdr.req || {};
  const request = new Request(String(rq.url), { method: rq.method, headers: rq.headers || [], body });
  request.client = Object.freeze({ ip: String((rq.client || {}).ip || ""), country: String((rq.client || {}).country || "") });

  std.evalScript(code);

  let result;
  if (listeners.length) {
    let responded = false, passOnError = false;
    const ev = {
      request,
      respondWith(r) { if (!responded) { responded = true; result = r; } },
      passThroughOnException() { passOnError = true; },
      waitUntil() {},
    };
    try {
      listeners[0](ev);
    } catch (e) {
      if (passOnError) result = null; else throw e;
    }
    if (!responded) result = null;
    if (passOnError) result = Promise.resolve(result).catch(() => null);
  } else if (typeof globalThis.handleRequest === "function") {
    result = globalThis.handleRequest(request);
  } else {
    throw new TypeError("no handler: define handleRequest(request) or addEventListener('fetch', ...)");
  }
  Promise.resolve(result).then(deliver, fail);
} catch (e) {
  fail(e);
}
