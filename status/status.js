/*
 * صفحه وضعیت پاسارگاد سی‌دی‌ان — بدون وابستگی. /status.json را می‌گیرد و نمایش می‌دهد.
 *
 * مبدأ کنترلر (به ترتیب اولویت): پارامتر ?api=  ←  ثابت API_BASE  ←  همان مبدأ صفحه.
 */
const API_BASE = ""; // مثال: "https://cdn-api.example.com" — خالی یعنی همان دامنه صفحه.

const REFRESH_MS = 30000;

(function () {
  "use strict";

  function apiBase() {
    try {
      const q = new URLSearchParams(location.search).get("api");
      if (q) return q.trim();
    } catch (e) { /* no-op */ }
    return (API_BASE || "").trim();
  }

  function statusUrl() {
    const base = apiBase();
    if (!base) return "status.json".replace(/^/, "/"); // مبدأ صفحه: /status.json
    return base.replace(/\/+$/, "") + "/status.json";
  }

  // ---- کمک‌کارها: اعداد و زمان فارسی --------------------------------------
  const FA_DIGITS = ["۰", "۱", "۲", "۳", "۴", "۵", "۶", "۷", "۸", "۹"];
  function faNum(n) {
    return String(n).replace(/[0-9]/g, (d) => FA_DIGITS[+d]);
  }

  function parseTime(iso) {
    if (!iso) return null;
    const t = Date.parse(iso);
    return isNaN(t) ? null : t;
  }

  function absTime(iso) {
    const t = parseTime(iso);
    if (t === null) return "";
    const d = new Date(t);
    try {
      return new Intl.DateTimeFormat("fa-IR", {
        dateStyle: "medium", timeStyle: "short",
      }).format(d);
    } catch (e) {
      return faNum(d.toLocaleString());
    }
  }

  function relTime(iso) {
    const t = parseTime(iso);
    if (t === null) return "";
    let s = Math.round((Date.now() - t) / 1000);
    const future = s < 0;
    s = Math.abs(s);
    let val, unit;
    if (s < 60) return "لحظاتی پیش";
    if (s < 3600) { val = Math.floor(s / 60); unit = "دقیقه"; }
    else if (s < 86400) { val = Math.floor(s / 3600); unit = "ساعت"; }
    else if (s < 2592000) { val = Math.floor(s / 86400); unit = "روز"; }
    else if (s < 31536000) { val = Math.floor(s / 2592000); unit = "ماه"; }
    else { val = Math.floor(s / 31536000); unit = "سال"; }
    return faNum(val) + " " + unit + (future ? " بعد" : " پیش");
  }

  // ---- نگاشت وضعیت‌ها ------------------------------------------------------
  const OVERALL = {
    operational:  { cls: "ok",          title: "همه‌چیز عادی است",        sub: "همه سرویس‌ها به‌درستی کار می‌کنند." },
    degraded:     { cls: "degraded",    title: "اختلال جزئی",             sub: "برخی سرویس‌ها با کندی یا اختلال همراه‌اند." },
    maintenance:  { cls: "maintenance", title: "تعمیرات برنامه‌ریزی‌شده", sub: "کار نگهداری برنامه‌ریزی‌شده در جریان است." },
    major_outage: { cls: "major",       title: "قطعی گسترده",             sub: "بخش عمده‌ای از سرویس‌ها در دسترس نیستند." },
  };

  const COMP = {
    operational:  { cls: "ok",          label: "عادی" },
    degraded:     { cls: "degraded",    label: "اختلال جزئی" },
    partial_outage: { cls: "degraded",  label: "اختلال جزئی" },
    maintenance:  { cls: "maintenance", label: "تعمیرات" },
    major_outage: { cls: "major",       label: "قطعی" },
  };

  const INC_STATUS = {
    investigating: "در حال بررسی",
    identified:    "علت شناسایی شد",
    monitoring:    "در حال پایش",
    resolved:      "برطرف شد",
  };
  const INC_STATUS_CLS = {
    investigating: "major",
    identified:    "degraded",
    monitoring:    "maintenance",
    resolved:      "ok",
  };
  const SEVERITY = {
    minor:       { cls: "degraded",    label: "کم‌اهمیت" },
    major:       { cls: "major",       label: "پراهمیت" },
    maintenance: { cls: "maintenance", label: "تعمیرات" },
  };

  // آیکون‌های SVG برای بنر
  function bannerIcon(cls) {
    const p = {
      ok: '<path d="M20 6 9 17l-5-5"/>',
      degraded: '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0zM12 9v4M12 17h.01"/>',
      maintenance: '<path d="M14.7 6.3a4 4 0 0 1-5.4 5.4L4 17v3h3l5.3-5.3a4 4 0 0 0 5.4-5.4l-2.6 2.6-2-2 2.6-2.6z"/>',
      major: '<path d="M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM15 9l-6 6M9 9l6 6"/>',
      loading: '<path d="M12 2a10 10 0 1 0 10 10"/>',
    };
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' + (p[cls] || p.loading) + "</svg>";
  }

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  // ---- المان‌ها -----------------------------------------------------------
  const el = {
    banner: document.getElementById("banner"),
    bannerIcon: document.getElementById("bannerIcon"),
    bannerTitle: document.getElementById("bannerTitle"),
    bannerSub: document.getElementById("bannerSub"),
    errbox: document.getElementById("errbox"),
    componentsCard: document.getElementById("componentsCard"),
    components: document.getElementById("components"),
    nodes: document.getElementById("nodes"),
    incidentsCard: document.getElementById("incidentsCard"),
    incidents: document.getElementById("incidents"),
    updated: document.getElementById("updated"),
    tick: document.getElementById("tick"),
    refresh: document.getElementById("refresh"),
  };

  let lastData = null;
  let lastOkAt = null;

  function setBanner(cls, title, sub) {
    el.banner.className = "banner banner-" + cls;
    el.bannerIcon.innerHTML = bannerIcon(cls);
    el.bannerTitle.textContent = title;
    el.bannerSub.textContent = sub || "";
  }

  function renderComponents(data) {
    const comps = Array.isArray(data.components) ? data.components : [];
    if (!comps.length) { el.componentsCard.hidden = true; return; }
    el.components.innerHTML = comps.map((c) => {
      const m = COMP[c.status] || { cls: "neutral", label: c.status || "—" };
      return '<li><span class="comp-name">' + esc(c.name) + "</span>" +
        '<span class="pill pill-' + m.cls + '"><span class="dot"></span>' + esc(m.label) + "</span></li>";
    }).join("");
    // خط خلاصهٔ نودها — فقط شمارش، بدون IP/نام
    const nodes = data.nodes || {};
    if (nodes && (nodes.total != null)) {
      const total = +nodes.total || 0;
      const online = +nodes.online || 0;
      el.nodes.innerHTML = "نودهای پردازش محتوا: <b>" + faNum(online) + "</b> از <b>" +
        faNum(total) + "</b> نود آنلاین.";
      el.nodes.hidden = false;
    } else {
      el.nodes.hidden = true;
    }
    el.componentsCard.hidden = false;
  }

  function timelineHtml(updates) {
    const ups = Array.isArray(updates) ? updates.slice() : [];
    if (!ups.length) return "";
    // جدیدترین بالا
    ups.sort((a, b) => (parseTime(b.at) || 0) - (parseTime(a.at) || 0));
    return '<ul class="timeline">' + ups.map((u) => {
      const cls = INC_STATUS_CLS[u.status] || "neutral";
      const label = INC_STATUS[u.status] || u.status || "";
      return '<li class="t-' + cls + '"><div class="tl-head">' +
        '<span class="tl-status">' + esc(label) + "</span>" +
        '<span class="tl-time" title="' + esc(absTime(u.at)) + '">' + esc(relTime(u.at)) + "</span>" +
        "</div>" + (u.body ? '<div class="tl-body">' + esc(u.body) + "</div>" : "") + "</li>";
    }).join("") + "</ul>";
  }

  function incidentHtml(inc) {
    const resolved = inc.status === "resolved";
    const sev = SEVERITY[inc.severity] || { cls: "neutral", label: inc.severity || "" };
    const stCls = INC_STATUS_CLS[inc.status] || "neutral";
    const stLabel = INC_STATUS[inc.status] || inc.status || "";
    const badges = '<span class="incident-badges">' +
      '<span class="pill pill-' + sev.cls + '">' + esc(sev.label) + "</span>" +
      '<span class="pill pill-' + stCls + '">' + esc(stLabel) + "</span></span>";
    const head =
      '<div class="incident-titles">' +
        '<p class="incident-title">' + esc(inc.title) + "</p>" + badges +
      "</div>" +
      '<span class="incident-when" title="' + esc(absTime(inc.updated_at || inc.created_at)) + '">' +
        esc(relTime(inc.updated_at || inc.created_at)) + "</span>";
    const body = inc.body ? '<div class="incident-body">' + esc(inc.body) + "</div>" : "";
    const timeline = timelineHtml(inc.updates);
    if (resolved) {
      // برطرف‌شده‌ها جمع‌شده (details)
      return '<details class="incident collapsible sev-' + esc(inc.severity) + '">' +
        '<summary class="incident-head">' + head + "</summary>" +
        body + timeline + "</details>";
    }
    // بازها گسترده
    return '<div class="incident open sev-' + esc(inc.severity) + '">' +
      '<div class="incident-head">' + head + "</div>" +
      body + timeline + "</div>";
  }

  function renderIncidents(data) {
    const list = Array.isArray(data.incidents) ? data.incidents : [];
    const open = list.filter((i) => i.status !== "resolved");
    const resolved = list.filter((i) => i.status === "resolved");
    // بازها به‌ترتیب جدیدترین، سپس برطرف‌شده‌ها
    open.sort((a, b) => (parseTime(b.updated_at || b.created_at) || 0) - (parseTime(a.updated_at || a.created_at) || 0));
    resolved.sort((a, b) => (parseTime(b.updated_at || b.created_at) || 0) - (parseTime(a.updated_at || a.created_at) || 0));

    let html = "";
    if (!open.length) {
      html += '<p class="calm">در حال حاضر هیچ رخداد بازی وجود ندارد.</p>';
    } else {
      html += open.map(incidentHtml).join("");
    }
    if (resolved.length) {
      html += '<h2 class="card-title">رخدادهای برطرف‌شدهٔ اخیر</h2>' + resolved.map(incidentHtml).join("");
    }
    el.incidents.innerHTML = html;
    el.incidentsCard.hidden = false;
  }

  function render(data) {
    lastData = data;
    lastOkAt = Date.now();
    el.errbox.hidden = true;
    const o = OVERALL[data.status] || OVERALL.operational;
    setBanner(o.cls, o.title, o.sub);
    renderComponents(data);
    renderIncidents(data);
    updateStamp();
  }

  function showError() {
    el.errbox.hidden = false;
    if (!lastData) {
      setBanner("degraded", "وضعیت در دسترس نیست", "اتصال به سرویس وضعیت برقرار نشد.");
      el.componentsCard.hidden = true;
      el.incidentsCard.hidden = true;
    }
    updateStamp();
  }

  function updateStamp() {
    if (lastOkAt) {
      el.updated.textContent = "آخرین به‌روزرسانی: " + relTime(new Date(lastOkAt).toISOString());
    } else {
      el.updated.textContent = "";
    }
  }

  let loading = false;
  function load() {
    if (loading) return;
    loading = true;
    el.refresh.classList.add("spin");
    const ctrl = ("AbortController" in window) ? new AbortController() : null;
    const timer = setTimeout(() => { if (ctrl) ctrl.abort(); }, 12000);
    fetch(statusUrl(), {
      cache: "no-store",
      headers: { "Accept": "application/json" },
      signal: ctrl ? ctrl.signal : undefined,
    })
      .then((r) => { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
      .then((data) => { render(data); })
      .catch(() => { showError(); })
      .finally(() => {
        clearTimeout(timer);
        loading = false;
        el.refresh.classList.remove("spin");
      });
  }

  el.refresh.addEventListener("click", load);
  // به‌روزرسانی برچسب زمان هر ۲۰ ثانیه بدون درخواست تازه
  setInterval(updateStamp, 20000);
  setInterval(load, REFRESH_MS);
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) load();
  });
  load();
})();
