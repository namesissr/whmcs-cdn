/*
 * پاسارگاد سی‌دی‌ان — فرم عمومی گزارش تخلف (SPEC §23.10). بدون وابستگی، RTL فارسی با گزینهٔ انگلیسی.
 * Pasargad CDN — public abuse report form (SPEC §23.10). No dependencies; Persian RTL with an English toggle.
 *
 * Controller endpoints (public, CORS *; 404 while ABUSE_ENABLED=false):
 *   GET  /public/v1/abuse/challenge              -> {id, salt, bits, expires_at}
 *   POST /public/v1/abuse/reports                -> 201 {ticket, status_token}
 *   GET  /public/v1/abuse/reports/{ticket}?token= -> {ticket, status, created_at, updated_at, public_note}
 *
 * Proof of work: find a decimal nonce such that sha256(UTF-8(salt + nonce)) starts with at least `bits`
 * zero bits (salt = the hex string exactly as received). It costs a browser ~1 s at 20 bits and makes
 * scripted mass reports expensive. Controller origin: ?api=  ->  API_BASE  ->  this page's origin
 * (same rule as status.js).
 */
const ABUSE_API_BASE = ""; // e.g. "https://cdn-api.example.com" — empty = this page's origin

(function (root) {
  "use strict";

  // ---------------------------------------------------------------- SHA-256 (synchronous, small inputs)
  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);
  const W = new Uint32Array(64);

  function utf8(str) {
    if (typeof TextEncoder !== "undefined") return new TextEncoder().encode(str);
    return Uint8Array.from(Buffer.from(str, "utf8")); // very old node only
  }

  /** sha256 of a byte array -> Uint8Array(32). */
  function sha256(bytes) {
    const len = bytes.length;
    const total = ((len + 9 + 63) >> 6) << 6;
    const m = new Uint8Array(total);
    m.set(bytes);
    m[len] = 0x80;
    const bits = len * 8;
    const dv = new DataView(m.buffer);
    dv.setUint32(total - 8, Math.floor(bits / 0x100000000));
    dv.setUint32(total - 4, bits >>> 0);
    let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
    let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
    for (let off = 0; off < total; off += 64) {
      for (let i = 0; i < 16; i++) W[i] = dv.getUint32(off + i * 4);
      for (let i = 16; i < 64; i++) {
        const a = W[i - 15], b = W[i - 2];
        const s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3);
        const s1 = ((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10);
        W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
      }
      let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
      for (let i = 0; i < 64; i++) {
        const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        const ch = (e & f) ^ (~e & g);
        const t1 = (h + S1 + ch + K[i] + W[i]) | 0;
        const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0;
      h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + h) | 0;
    }
    const out = new Uint8Array(32);
    const odv = new DataView(out.buffer);
    [h0, h1, h2, h3, h4, h5, h6, h7].forEach((v, i) => odv.setUint32(i * 4, v >>> 0));
    return out;
  }

  function hex(bytes) {
    let s = "";
    for (let i = 0; i < bytes.length; i++) s += (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16);
    return s;
  }

  function sha256Hex(str) { return hex(sha256(utf8(str))); }

  /** number of leading zero bits of a digest */
  function leadingZeroBits(d) {
    let n = 0;
    for (let i = 0; i < d.length; i++) {
      if (d[i] === 0) { n += 8; continue; }
      return n + Math.clz32(d[i]) - 24;
    }
    return n;
  }

  /**
   * Find a nonce with sha256(salt + nonce) >= bits leading zero bits.
   * Works in slices of `slice` hashes; `yieldFn(next)` schedules the next slice (setTimeout in the
   * browser, synchronous when omitted). onProgress(tried) is called after each slice.
   * Returns a Promise of {nonce: string, tried: number}.
   */
  function solve(salt, bits, opts) {
    opts = opts || {};
    const slice = opts.slice || 20000;
    const max = opts.max || Math.pow(2, Math.min(bits + 8, 40));
    const yieldFn = opts.yieldFn || null;
    const prefix = utf8(String(salt));
    let n = opts.start || 0;
    return new Promise((resolve, reject) => {
      function run() {
        const end = Math.min(n + slice, max);
        for (; n < end; n++) {
          const ns = String(n);
          const buf = new Uint8Array(prefix.length + ns.length);
          buf.set(prefix);
          for (let i = 0; i < ns.length; i++) buf[prefix.length + i] = ns.charCodeAt(i);
          if (leadingZeroBits(sha256(buf)) >= bits) return resolve({ nonce: ns, tried: n + 1 });
        }
        if (opts.onProgress) opts.onProgress(n);
        if (opts.cancelled && opts.cancelled()) return reject(new Error("cancelled"));
        if (n >= max) return reject(new Error("no nonce found"));
        if (yieldFn) yieldFn(run); else run();
      }
      run();
    });
  }

  /** Client-side checks mirroring the controller (1..10 http(s) URLs, ≤ 2048 chars each). */
  function parseUrls(text) {
    const urls = String(text || "").split(/\s+/).map((s) => s.trim()).filter(Boolean);
    const bad = urls.filter((u) => u.length > 2048 || !/^https?:\/\/[^\s/?#]+[^\s]*$/i.test(u));
    return { urls, bad, ok: urls.length >= 1 && urls.length <= 10 && bad.length === 0 };
  }

  const api = { sha256Hex, leadingZeroBits, solve, parseUrls, sha256, utf8 };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.PcdnAbuse = api;

  if (typeof document === "undefined") return; // node (tests)

  // ---------------------------------------------------------------- page
  const T = {
    fa: {
      title: "گزارش تخلف", sub: "پاسارگاد سی‌دی‌ان", lang: "English",
      intro: "اگر سایتی که از طریق پاسارگاد سی‌دی‌ان سرو می‌شود محتوای فیشینگ، بدافزار، غیرقانونی، هرزنامه یا نقض حق نشر دارد، آن را این‌جا گزارش کنید. گزارش‌ها را تیم پشتیبانی بررسی می‌کند.",
      category: "نوع تخلف", urls: "نشانی‌ها (هر خط یک نشانی، حداکثر ۱۰)", desc: "توضیحات", email: "ایمیل شما (اختیاری؛ فقط برای اطلاع‌رسانی وضعیت)",
      submit: "ارسال گزارش", solving: "در حال آماده‌سازی ارسال (چند ثانیه)…", sending: "در حال ارسال…",
      cats: { phishing: "فیشینگ", malware: "بدافزار", illegal: "محتوای غیرقانونی", spam: "هرزنامه", copyright: "نقض حق نشر", other: "سایر" },
      badUrls: "نشانی‌ها معتبر نیستند (۱ تا ۱۰ نشانی http یا https).", longDesc: "توضیحات حداکثر ۴۰۰۰ نویسه است.",
      done: "گزارش ثبت شد.", ticket: "شمارهٔ پیگیری", token: "کد پیگیری",
      keep: "این کد فقط همین یک بار نمایش داده می‌شود؛ آن را نگه دارید تا بتوانید وضعیت را ببینید.",
      lookup: "پیگیری وضعیت گزارش", check: "نمایش وضعیت", status: "وضعیت", created: "ثبت", updated: "آخرین به‌روزرسانی", note: "یادداشت",
      st: { new: "جدید", triage: "در حال بررسی", notified: "به صاحب سایت اطلاع داده شد", actioned: "اقدام شد", closed: "بسته شد", rejected: "رد شد" },
      disabled: "ثبت گزارش تخلف در حال حاضر فعال نیست.", rate: "تعداد گزارش‌های شما زیاد است؛ کمی بعد دوباره تلاش کنید.",
      invalid: "اطلاعات فرم معتبر نیست؛ آن را بررسی کنید.", notFound: "گزارشی با این شماره و کد پیدا نشد.", fail: "ارسال ممکن نشد؛ دوباره تلاش کنید.",
      privacy: "اطلاعات شما منتشر نمی‌شود و نشانی ایمیل فقط برای اطلاع‌رسانی وضعیت همین گزارش به کار می‌رود.", back: "صفحهٔ وضعیت",
    },
    en: {
      title: "Report abuse", sub: "Pasargad CDN", lang: "فارسی",
      intro: "If a site served through Pasargad CDN hosts phishing, malware, illegal content, spam or copyright infringement, report it here. Reports are reviewed by our support team.",
      category: "Category", urls: "URLs (one per line, up to 10)", desc: "Description", email: "Your e-mail (optional; only for status updates)",
      submit: "Send report", solving: "Preparing the submission (a few seconds)…", sending: "Sending…",
      cats: { phishing: "Phishing", malware: "Malware", illegal: "Illegal content", spam: "Spam", copyright: "Copyright", other: "Other" },
      badUrls: "The URLs are not valid (1 to 10 http or https URLs).", longDesc: "The description is limited to 4000 characters.",
      done: "Your report was received.", ticket: "Ticket", token: "Status code",
      keep: "This code is shown only once; keep it to check the status later.",
      lookup: "Check a report", check: "Show status", status: "Status", created: "Received", updated: "Last update", note: "Note",
      st: { new: "New", triage: "Under review", notified: "Site owner notified", actioned: "Action taken", closed: "Closed", rejected: "Rejected" },
      disabled: "Abuse reporting is not enabled at the moment.", rate: "Too many reports from you; please try again later.",
      invalid: "The form is not valid; please check it.", notFound: "No report with this ticket and code.", fail: "Could not send; please try again.",
      privacy: "Nothing you send is published; the e-mail address is used only for status updates of this report.", back: "Status page",
    },
  };

  let lang = "fa";
  try { lang = new URLSearchParams(location.search).get("lang") === "en" ? "en" : (localStorage.getItem("pcdn_lang") === "en" ? "en" : "fa"); } catch (e) { /* storage blocked */ }

  function base() {
    try {
      const q = new URLSearchParams(location.search).get("api");
      if (q) return q.trim().replace(/\/+$/, "");
    } catch (e) { /* no-op */ }
    return (ABUSE_API_BASE || "").trim().replace(/\/+$/, "");
  }
  const url = (p) => base() + p;
  const $ = (id) => document.getElementById(id);

  function setText(id, text) { const el = $(id); if (el) el.textContent = text; }

  function applyLang() {
    const t = T[lang];
    document.documentElement.lang = lang;
    document.documentElement.dir = lang === "fa" ? "rtl" : "ltr";
    document.title = t.title + " — " + t.sub;
    document.querySelectorAll("[data-t]").forEach((el) => { el.textContent = t[el.getAttribute("data-t")] || ""; });
    const sel = $("category");
    Array.from(sel.options).forEach((o) => { o.textContent = t.cats[o.value]; });
  }

  function msg(id, text, kind) {
    const el = $(id);
    el.textContent = text || "";
    el.className = "msg" + (kind ? " msg-" + kind : "");
    el.hidden = !text;
  }

  function errorText(status) {
    const t = T[lang];
    if (status === 404) return t.disabled;
    if (status === 429) return t.rate;
    if (status === 422) return t.invalid;
    return t.fail;
  }

  async function submit(ev) {
    ev.preventDefault();
    const t = T[lang];
    const btn = $("send");
    const u = parseUrls($("urls").value);
    const desc = $("desc").value.trim();
    if (!u.ok) return msg("formMsg", t.badUrls, "bad");
    if (desc.length > 4000) return msg("formMsg", t.longDesc, "bad");
    btn.disabled = true;
    msg("formMsg", t.solving, "info");
    try {
      const cr = await fetch(url("/public/v1/abuse/challenge"), { credentials: "omit", cache: "no-store" });
      if (!cr.ok) throw { status: cr.status };
      const ch = await cr.json();
      const sol = await solve(ch.salt, Number(ch.bits) || 20, { yieldFn: (f) => setTimeout(f, 0) });
      msg("formMsg", t.sending, "info");
      const body = {
        category: $("category").value, urls: u.urls, description: desc,
        challenge: { id: ch.id, salt: ch.salt, nonce: sol.nonce }, website: $("website").value,
      };
      const email = $("email").value.trim();
      if (email) body.email = email;
      const r = await fetch(url("/public/v1/abuse/reports"), {
        method: "POST", credentials: "omit", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
      });
      if (r.status !== 201 && r.status !== 200) throw { status: r.status };
      const res = await r.json();
      $("form").reset();
      msg("formMsg", "", null);
      $("result").hidden = false;
      setText("resTicket", res.ticket);
      setText("resToken", res.status_token);
      $("ticketIn").value = res.ticket;
    } catch (e) {
      msg("formMsg", errorText(e && e.status), "bad");
    } finally {
      btn.disabled = false;
    }
  }

  async function lookup(ev) {
    ev.preventDefault();
    const t = T[lang];
    const ticket = $("ticketIn").value.trim().toUpperCase();
    const token = $("tokenIn").value.trim();
    $("statusBox").hidden = true;
    if (!/^AB-[0-9A-Z]{8}$/.test(ticket) || !token) return msg("lookupMsg", t.notFound, "bad");
    try {
      const r = await fetch(url("/public/v1/abuse/reports/" + encodeURIComponent(ticket) + "?token=" + encodeURIComponent(token)),
        { credentials: "omit", cache: "no-store" });
      if (r.status === 404 || r.status === 403 || r.status === 401) throw { status: r.status === 404 ? 0 : r.status, nf: true };
      if (!r.ok) throw { status: r.status };
      const s = await r.json();
      msg("lookupMsg", "", null);
      setText("stStatus", t.st[s.status] || s.status);
      setText("stCreated", fmt(s.created_at));
      setText("stUpdated", fmt(s.updated_at));
      setText("stNote", s.public_note || "—");
      $("statusBox").hidden = false;
    } catch (e) {
      msg("lookupMsg", e && e.nf ? t.notFound : errorText(e && e.status), "bad");
    }
  }

  function fmt(iso) {
    const d = Date.parse(iso || "");
    if (isNaN(d)) return "—";
    try {
      return new Intl.DateTimeFormat(lang === "fa" ? "fa-IR" : "en-GB", { dateStyle: "medium", timeStyle: "short" }).format(new Date(d));
    } catch (e) { return new Date(d).toISOString(); }
  }

  document.addEventListener("DOMContentLoaded", () => {
    applyLang();
    const back = $("backLink");
    if (back) back.href = "index.html" + (location.search || "");
    $("langBtn").addEventListener("click", () => {
      lang = lang === "fa" ? "en" : "fa";
      try { localStorage.setItem("pcdn_lang", lang); } catch (e) { /* no-op */ }
      applyLang();
    });
    $("form").addEventListener("submit", submit);
    $("lookupForm").addEventListener("submit", lookup);
    try {
      const q = new URLSearchParams(location.search);
      if (q.get("ticket")) $("ticketIn").value = q.get("ticket");
    } catch (e) { /* no-op */ }
  });
})(typeof window !== "undefined" ? window : globalThis);
