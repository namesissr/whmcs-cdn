/*
 * افزونهٔ «آخرین وضعیت شناخته‌شده» برای صفحهٔ وضعیتِ میزبانی‌شده روی میزبان جداگانه (deploy/status).
 * mirror.sh هر چند ثانیه /status.json کنترلر را می‌گیرد؛ اگر کنترلر در دسترس نباشد همان نسخهٔ قبلی
 * را نگه می‌دارد و فقط /mirror.json را به‌روز می‌کند. این اسکریپت /mirror.json را می‌خواند و وقتی
 * داده کهنه است، یک اعلان بالای صفحه نشان می‌دهد تا کاربر بداند وضعیت نمایش‌داده‌شده زنده نیست.
 * بدون وابستگی؛ status.js را تغییر نمی‌دهد.
 */
(function () {
  "use strict";

  var REFRESH_MS = 30000;
  var FA = ["۰", "۱", "۲", "۳", "۴", "۵", "۶", "۷", "۸", "۹"];
  function faNum(n) { return String(n).replace(/[0-9]/g, function (d) { return FA[+d]; }); }

  function ago(iso) {
    var t = Date.parse(iso || "");
    if (isNaN(t)) return null;
    var s = Math.max(0, Math.round((Date.now() - t) / 1000));
    if (s < 90) return "لحظاتی پیش";
    if (s < 5400) return faNum(Math.round(s / 60)) + " دقیقه پیش";
    if (s < 172800) return faNum(Math.round(s / 3600)) + " ساعت پیش";
    return faNum(Math.round(s / 86400)) + " روز پیش";
  }

  function notice() {
    var el = document.getElementById("mirrorNotice");
    if (el) return el;
    el = document.createElement("section");
    el.id = "mirrorNotice";
    el.className = "errbox";
    el.setAttribute("role", "status");
    el.hidden = true;
    var banner = document.getElementById("banner");
    if (banner && banner.parentNode) banner.parentNode.insertBefore(el, banner.nextSibling);
    else document.body.insertBefore(el, document.body.firstChild);
    return el;
  }

  function show(meta) {
    var el = notice();
    var interval = (meta && meta.interval_seconds) || 20;
    var lastOk = meta && meta.last_ok_at;
    var fresh = meta && meta.ok && lastOk && (Date.now() - Date.parse(lastOk)) < interval * 4000;
    if (fresh) { el.hidden = true; return; }
    var when = ago(lastOk);
    el.textContent = when
      ? "ارتباط با سرور وضعیت موقتاً برقرار نیست؛ آخرین وضعیت شناخته‌شده (دریافت‌شده " + when + ") نمایش داده می‌شود."
      : "ارتباط با سرور وضعیت برقرار نیست و هنوز وضعیتی دریافت نشده است.";
    el.hidden = false;
  }

  function load() {
    if (!window.fetch) return;
    fetch("/mirror.json", { cache: "no-store", headers: { "Accept": "application/json" } })
      .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
      .then(show)
      // the mirror itself is unreachable: status.js already shows its own error box
      .catch(function () { notice().hidden = true; });
  }

  load();
  setInterval(load, REFRESH_MS);
  document.addEventListener("visibilitychange", function () { if (!document.hidden) load(); });
})();
