/*
 * Pasargad CDN — WHMCS admin addon. Progressive enhancement only: every page
 * works without this file. No globals; everything is scoped to .pcdna.
 */
(function () {
  'use strict';
  var root = document.querySelector('.pcdna');
  if (!root) return;

  var FA = '۰۱۲۳۴۵۶۷۸۹';
  function faNum(v, dec) {
    var s = Number(v).toLocaleString('en-US', { maximumFractionDigits: dec || 0 });
    return s.replace(/[0-9]/g, function (d) { return FA[d]; }).replace(/,/g, '٬').replace(/\./g, '٫');
  }
  function toLatin(s) {
    return String(s || '').replace(/[۰-۹]/g, function (d) { return FA.indexOf(d); }).replace(/[٬,\s]/g, '').replace(/٫/g, '.');
  }

  // After a POST the address bar shows the GET URL, so refresh never re-submits.
  var clean = root.getAttribute('data-clean-url');
  if (clean && window.history && window.history.replaceState) {
    try { window.history.replaceState(null, '', clean + (window.location.hash || '')); } catch (e) { /* ignore */ }
  }

  // Confirmations + double-submit protection.
  root.addEventListener('submit', function (ev) {
    var f = ev.target;
    if (!f || f.tagName !== 'FORM') return;
    var msg = f.getAttribute('data-confirm');
    if (msg && !window.confirm(msg)) { ev.preventDefault(); return; }
    var typed = f.getAttribute('data-confirm-type');
    if (typed) {
      var v = window.prompt('برای تأیید حذف، نام دامنه را تایپ کنید:\n' + typed, '');
      if (v === null || v.trim().toLowerCase() !== typed.toLowerCase()) {
        ev.preventDefault();
        if (v !== null) window.alert('نام دامنه مطابقت ندارد؛ چیزی حذف نشد.');
        return;
      }
      var inp = f.querySelector('input[name="confirm"]');
      if (inp) inp.value = v.trim();
    }
    var btns = f.querySelectorAll('button[type="submit"]');
    window.setTimeout(function () {
      for (var i = 0; i < btns.length; i++) btns[i].disabled = true;
    }, 0);
  }, true);

  // Copy buttons.
  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
    return new Promise(function (resolve, reject) {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy') ? resolve() : reject(); } catch (e) { reject(e); }
      document.body.removeChild(ta);
    });
  }
  root.addEventListener('click', function (ev) {
    var b = ev.target.closest ? ev.target.closest('[data-copy]') : null;
    if (!b || !root.contains(b)) return;
    var label = b.querySelector('span');
    var old = label ? label.textContent : '';
    copyText(b.getAttribute('data-copy')).then(function () {
      if (label) label.textContent = 'کپی شد';
      b.classList.add('is-done');
      window.setTimeout(function () { if (label) label.textContent = old; b.classList.remove('is-done'); }, 1600);
    }, function () {
      var code = b.parentNode && b.parentNode.querySelector('code');
      if (code && window.getSelection) {
        var r = document.createRange();
        r.selectNodeContents(code);
        window.getSelection().removeAllRanges();
        window.getSelection().addRange(r);
      }
    });
  });

  // Row menus: one open at a time, positioned fixed so table scrolling never clips them.
  var menus = root.querySelectorAll('details.pcdna-menu');
  function closeMenus(except) {
    for (var i = 0; i < menus.length; i++) if (menus[i] !== except) menus[i].open = false;
  }
  function place(d) {
    var list = d.querySelector('.pcdna-menu-list');
    var s = d.querySelector('summary');
    if (!list || !s) return;
    list.classList.add('is-fixed');
    var r = s.getBoundingClientRect();
    var w = list.offsetWidth, hgt = list.offsetHeight;
    var left = Math.max(8, Math.min(r.left, window.innerWidth - w - 8));
    var top = r.bottom + 4;
    if (top + hgt > window.innerHeight - 8 && r.top - hgt - 4 > 8) top = r.top - hgt - 4;
    list.style.left = left + 'px';
    list.style.top = top + 'px';
  }
  Array.prototype.forEach.call(menus, function (d) {
    d.addEventListener('toggle', function () {
      if (d.open) { closeMenus(d); place(d); }
    });
  });
  document.addEventListener('click', function (ev) {
    if (!ev.target.closest || !ev.target.closest('details.pcdna-menu')) closeMenus(null);
  });
  document.addEventListener('keydown', function (ev) {
    if (ev.key === 'Escape') closeMenus(null);
  });
  // Keep an open menu attached to its button while the page or a table scrolls.
  function replaceOpen() {
    for (var i = 0; i < menus.length; i++) if (menus[i].open) place(menus[i]);
  }
  window.addEventListener('scroll', replaceOpen, true);
  window.addEventListener('resize', replaceOpen);

  // Wizard helpers.
  var wiz = root.querySelector('form[data-wizard]');
  if (wiz) {
    var op = wiz.querySelector('[data-per-mb]');
    var out = wiz.querySelector('[data-per-mb-out]');
    if (op && out) {
      var upd = function () {
        var v = parseFloat(toLatin(op.value));
        out.textContent = isFinite(v) && v >= 0
          ? 'WHMCS قیمت را به ازای هر مگابایت ذخیره می‌کند: ' + faNum(Math.round(v / 1024 * 10000) / 10000, 4) + ' هر MB'
          : 'عدد معتبر وارد کنید.';
      };
      op.addEventListener('input', upd);
    }
    // Monthly price → suggested multi-period prices, until the admin edits those cells.
    var FACTOR = { quarterly: 2.85, semiannually: 5.4, annually: 10 };
    function nice(v) {
      if (v >= 100000) return Math.round(v / 1000) * 1000;
      if (v >= 1000) return Math.round(v / 100) * 100;
      return Math.round(v * 100) / 100;
    }
    wiz.addEventListener('input', function (ev) {
      var t = ev.target;
      if (!t || !t.getAttribute) return;
      var cycle = t.getAttribute('data-cycle');
      if (!cycle) return;
      if (cycle !== 'monthly') { t.setAttribute('data-touched', '1'); return; }
      var row = t.closest('tr');
      var m = parseFloat(toLatin(t.value));
      Object.keys(FACTOR).forEach(function (c) {
        var cell = row && row.querySelector('[data-cycle="' + c + '"]');
        if (!cell || cell.getAttribute('data-touched')) return;
        cell.value = isFinite(m) && m > 0 ? String(nice(m * FACTOR[c])) : '';
      });
    });
  }
})();
