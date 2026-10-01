/*
 * Pasargad CDN — client-app i18n (docs/SPEC.md §16.10). Loaded first; every other asset uses PCDN.t.
 *
 * Persian is the source language. Every user-facing string in the assets is written in Persian and
 * wrapped in t('…'): the Persian text itself is the key, so the fa dictionary is the identity and
 * the EN map (assets/i18n-en.js, window.PCDN_I18N_EN) maps each key to English. Leading/trailing
 * whitespace of a key is kept around the translation, so fragments still concatenate
 * (t(' مورد') + … → ' item' + …); an empty EN value drops the fragment. t(key, a, b, …) also replaces {0}, {1}, … with the arguments (both languages).
 *
 * Language: boot.lang ('fa' | 'en'), chosen server side by pasargadcdn_lang(): the viewer's in-app
 * choice (cookie pcdn_lang), else the WHMCS client language, else Persian. The server ships
 * i18n-en.js only for an English page, so the dictionary costs Persian viewers nothing. The in-app
 * switch keeps the choice in localStorage (pcdn:lang) and mirrors it to the cookie; if the two
 * disagree (cookie cleared) the page re-sets the cookie and reloads once. The admin addon's embed
 * (#pcdn-app[data-admin]) is always Persian. A key without an EN entry falls back to Persian and
 * is listed in PCDN.i18n.missing (the English e2e asserts it stays empty).
 */
(function () {
  'use strict';
  var P = window.PCDN = window.PCDN || {};

  var EN = window.PCDN_I18N_EN || null;  // i18n-en.js, shipped only when the page is English

  var root = document.getElementById('pcdn-app');
  var admin = !!(root && root.getAttribute('data-admin'));
  var bootLang = 'fa';
  try {
    var bootEl = document.getElementById('pcdn-boot');
    var boot = bootEl ? JSON.parse(bootEl.textContent || '{}') : {};
    if (boot && boot.lang === 'en') bootLang = 'en';
  } catch (e) { /* bad boot JSON: app.js reports it */ }
  var chosen = null;
  if (!admin) {
    try { chosen = window.localStorage.getItem('pcdn:lang'); } catch (e) { chosen = null; }
    if (chosen !== 'fa' && chosen !== 'en') chosen = null;
  }
  function setCookie(l) {
    try {
      document.cookie = 'pcdn_lang=' + (l || '') + '; path=/; SameSite=Lax' + (l ? '; max-age=31536000' : '; max-age=0')
        + (window.location.protocol === 'https:' ? '; Secure' : '');
    } catch (e) { /* cookies blocked */ }
  }
  // The stored choice and the language the server rendered disagree (cookie cleared or blocked):
  // put the cookie back and reload once (sessionStorage guard against a loop).
  if (chosen && chosen !== bootLang) {
    var retried = false;
    try { retried = window.sessionStorage.getItem('pcdn:langfix') === chosen; window.sessionStorage.setItem('pcdn:langfix', chosen); } catch (e) { retried = true; }
    setCookie(chosen);
    if (!retried) { window.location.reload(); }
  } else if (chosen) {
    try { window.sessionStorage.removeItem('pcdn:langfix'); } catch (e) { /* ignore */ }
  }
  var lang = bootLang === 'en' && EN ? 'en' : 'fa';
  var en = lang === 'en';
  var missing = [];
  var has = Object.prototype.hasOwnProperty;

  function fmt(s, args) {
    if (!args.length) return s;
    return String(s).replace(/\{(\d+)\}/g, function (m, i) { return args[+i] === undefined ? m : String(args[+i]); });
  }
  function t(s) {
    var args = Array.prototype.slice.call(arguments, 1);
    if (!en || typeof s !== 'string') return fmt(s, args);
    var m = /^(\s*)([\s\S]*?)(\s*)$/.exec(s);
    if (!m[2]) return s;
    if (!has.call(EN, m[2])) {
      if (missing.indexOf(m[2]) < 0) missing.push(m[2]);
      return fmt(s, args);
    }
    return EN[m[2]] === '' ? '' : fmt(m[1] + EN[m[2]] + m[3], args);
  }

  P.t = t;
  P.lang = lang;
  P.isEn = en;
  P.dir = en ? 'ltr' : 'rtl';
  P.locale = en ? 'en-US' : 'fa-IR';
  /** The "leads to" arrow in rule sentences (points along the reading direction). */
  P.arrow = en ? '→' : '←';
  P.i18n = {
    lang: lang, admin: admin, chosen: chosen, missing: missing,
    has: function (k) { return !!EN && has.call(EN, String(k).trim()); },
    /** In-app switch ('fa' | 'en' | null = follow WHMCS): remember it and reload; false when storage is blocked. */
    set: function (l) {
      if (l !== 'fa' && l !== 'en') l = null;
      try {
        if (l) window.localStorage.setItem('pcdn:lang', l);
        else window.localStorage.removeItem('pcdn:lang');
      } catch (e) { return false; /* storage blocked: the caller tells the viewer */ }
      setCookie(l);
      window.location.reload();
      return true;
    }
  };
  if (root) { root.setAttribute('dir', P.dir); root.setAttribute('lang', lang); }
})();
