// Customers never see the name of the billing software (SPEC §23.1 security checklist, wave 14).
// Self-contained repo-local check: `node --test whmcs/tests/*.test.js` or `node whmcs/tests/customer-text.test.js` (exit 1 on failure).
//   1. every t('…') key of the client app (modules/servers/pasargadcdn/assets/*.js);
//   2. every key and English value of assets/i18n-en.js;
//   3. every quoted string literal of the client-facing PHP files (server module, addon client pages / e-mail templates).
// Allowlisted: the admin-only banners of the «مدیریت کامل» view (app.js, boot.admin), merge fields like {$whmcs_url},
// class names (\WHMCS\…), defined('WHMCS') and PHP comments.
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const test = require('node:test');
const assert = require('node:assert');

const M = path.join(__dirname, '..', 'modules');
const A = path.join(M, 'servers', 'pasargadcdn', 'assets');
const has = (s) => /whmcs/i.test(String(s).replace(/\{\$whmcs_[a-z_]+\}/g, ''));
const ALLOW_JS = ['صفحه سرویس در WHMCS', '(وضعیت WHMCS:', '. تغییرات شما در گزارش فعالیت WHMCS ثبت می‌شود.',
  '. بدون سرویس WHMCS و بدون صورت‌حساب؛ تغییرات شما با نام مدیر در گزارش فعالیت WHMCS ثبت می‌شود.'];

test('client app t() keys never name the billing software', () => {
  const bad = [];
  const RE = /(?<![\w$.])t\((['"])((?:\\.|(?!\1)[^\\\n])*)\1/g;
  for (const f of fs.readdirSync(A).filter((x) => x.endsWith('.js') && x !== 'i18n-en.js')) {
    const src = fs.readFileSync(path.join(A, f), 'utf8');
    let m;
    while ((m = RE.exec(src))) {
      const k = Function('return ' + m[1] + m[2] + m[1])().trim();
      if (has(k) && !(f === 'app.js' && ALLOW_JS.includes(k))) bad.push(f + ': ' + k);
    }
  }
  assert.deepStrictEqual(bad, []);
});

test('i18n-en.js keys and English values never name the billing software', () => {
  const sb = { window: {} };
  vm.runInNewContext(fs.readFileSync(path.join(A, 'i18n-en.js'), 'utf8'), sb);
  const bad = Object.entries(sb.window.PCDN_I18N_EN).filter(([k, v]) => (has(k) || has(v)) && !ALLOW_JS.includes(k.trim())).map(([k]) => k);
  assert.deepStrictEqual(bad, []);
});

test('client-facing PHP string literals never name the billing software', () => {
  const files = [];
  for (const d of [path.join(M, 'servers', 'pasargadcdn'), path.join(M, 'servers', 'pasargadcdn', 'lib')]) {
    for (const f of fs.readdirSync(d)) if (f.endsWith('.php')) files.push(path.join(d, f));
  }
  for (const f of ['hooks.php', 'lib/CustomerTransfer.php', 'lib/Referrals.php', 'lib/Prepaid.php', 'lib/Pricing.php', 'lib/Trials.php', 'lib/Reports.php',
    'lib/TunnelAlerts.php', 'lib/AddonTraffic.php', 'lib/CartValidator.php', 'lib/AlertMail.php', 'lib/AbusePage.php']) {
    files.push(path.join(M, 'addons', 'pasargadcdn_admin', f));
  }
  const bad = [];
  for (const f of files) {
    // drop comments, then look at quoted literals
    const src = fs.readFileSync(f, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"\\])\/\/[^\n]*/g, '$1').replace(/^\s*#[^\n]*/gm, '');
    const RE = /'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)"/g;
    let m;
    while ((m = RE.exec(src))) {
      const s = m[1] !== undefined ? m[1] : m[2];
      if (!has(s) || /^\\*WHMCS(\\+[A-Za-z_]+)*$/.test(s) || /^\\*WHMCS\\/.test(s)) continue;
      bad.push(path.relative(M, f) + ': ' + s.slice(0, 100));
    }
  }
  assert.deepStrictEqual(bad, []);
});
