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
    // Billing mode: highlight the chosen card and show only the fields that apply to it.
    var syncBilling = function () {
      var sel = wiz.querySelector('input[name="billing"]:checked');
      var mode = sel ? sel.value : 'prepaid';
      Array.prototype.forEach.call(wiz.querySelectorAll('.pcdna-radio-card'), function (c) {
        var inp = c.querySelector('input');
        c.classList.toggle('is-on', !!(inp && inp.checked));
      });
      Array.prototype.forEach.call(wiz.querySelectorAll('[data-billing-show]'), function (el) {
        el.hidden = (' ' + el.getAttribute('data-billing-show') + ' ').indexOf(' ' + mode + ' ') < 0;
      });
    };
    wiz.addEventListener('change', function (ev) { if (ev.target && ev.target.name === 'billing') syncBilling(); });
    syncBilling();
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

  // Sortable tables (availability report). Progressive enhancement over the
  // server-rendered order; clicking a header re-orders the rows client-side.
  function sortValue(td, kind) {
    if (!td) return kind === 'num' ? 0 : '';
    var raw = td.getAttribute('data-sort-value');
    if (raw === null) raw = td.textContent || '';
    return kind === 'num' ? (parseFloat(toLatin(raw)) || 0) : String(raw).trim();
  }
  Array.prototype.forEach.call(root.querySelectorAll('table.pcdna-sortable'), function (table) {
    var heads = table.tHead ? table.tHead.rows[0].cells : [];
    var body = table.tBodies[0];
    if (!body) return;
    Array.prototype.forEach.call(heads, function (th, col) {
      var kind = th.getAttribute('data-sort');
      if (!kind) return;
      th.classList.add('pcdna-th-sort');
      th.setAttribute('role', 'button');
      th.setAttribute('tabindex', '0');
      function apply(dir) {
        var rows = Array.prototype.slice.call(body.rows);
        rows.sort(function (a, b) {
          var av = sortValue(a.cells[col], kind), bv = sortValue(b.cells[col], kind);
          var cmp = kind === 'num' ? av - bv : String(av).localeCompare(String(bv), 'fa');
          return dir === 'asc' ? cmp : -cmp;
        });
        rows.forEach(function (r) { body.appendChild(r); });
        Array.prototype.forEach.call(heads, function (h) { if (h.getAttribute('data-sort')) h.setAttribute('aria-sort', 'none'); });
        th.setAttribute('aria-sort', dir === 'asc' ? 'ascending' : 'descending');
      }
      function toggle() { apply(th.getAttribute('aria-sort') === 'ascending' ? 'desc' : 'asc'); }
      th.addEventListener('click', toggle);
      th.addEventListener('keydown', function (ev) {
        if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); toggle(); }
      });
    });
  });

  // SPEC §22.1: live countdown of a node drain («۱۲:۰۵ مانده») next to «در حال تخلیه (تا HH:MM)».
  var cds = root.querySelectorAll('[data-countdown]');
  if (cds.length) {
    var tick = function () {
      Array.prototype.forEach.call(cds, function (el) {
        var t = Date.parse(el.getAttribute('data-countdown') || '');
        if (isNaN(t)) return;
        var s = Math.round((t - Date.now()) / 1000);
        el.textContent = s <= 0 ? 'رو به پایان' : faNum(Math.floor(s / 60)) + ':' + (s % 60 < 10 ? '۰' : '') + faNum(s % 60) + ' مانده';
      });
    };
    tick();
    window.setInterval(tick, 1000);
  }
})();

// SPEC §23 (wave 14): live preview of the customer label of a node («نود {شهر}» / "{City} node") while the admin types,
// and the 20-second refresh of a running rollout (paused while a form or menu is in use).
(function () {
  'use strict';
  var root = document.querySelector('.pcdna');
  if (!root) return;
  var list = document.getElementById('pcdna-cities');
  function en(fa) {
    if (!list) return '';
    var o = list.querySelector('option[value="' + String(fa).replace(/"/g, '') + '"]');
    return o ? o.getAttribute('data-en') || '' : '';
  }
  root.addEventListener('input', function (ev) {
    var f = ev.target && ev.target.closest ? ev.target.closest('form[data-city-form]') : null;
    if (!f) return;
    var fa = (f.querySelector('[data-city-input]') || {}).value || '';
    var ov = (f.querySelector('[data-city-en]') || {}).value || '';
    fa = fa.trim();
    var p = f.querySelector('[data-city-preview]'), pe = f.querySelector('[data-city-preview-en]');
    if (p) p.textContent = fa ? 'نود ' + fa : 'پیش‌فرض منطقه';
    var e2 = ov.trim() || en(fa) || fa;
    if (pe) pe.textContent = fa ? e2 + ' node' : '';
  });
  var live = root.querySelector('[data-autorefresh]');
  if (live) {
    var secs = parseInt(live.getAttribute('data-autorefresh'), 10) || 20;
    window.setInterval(function () {
      var busy = root.querySelector('details[open]') || (document.activeElement && /INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName));
      if (!busy && !document.hidden) window.location.reload();
    }, secs * 1000);
  }
})();
