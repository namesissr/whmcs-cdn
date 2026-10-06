/*
 * fm.js (SPEC §16.8 file manager) — the pure helpers, with a minimal PCDN stub.
 *
 * The drawer itself needs a DOM, but the parts that decide what reaches the storage server do not:
 * a customer's file name becomes one key segment (no path separator, no control character ever
 * leaves the browser), the key is always inside the folder being viewed, and the upload shape
 * (single PUT vs multipart) follows the file's size.
 *
 * Run: node --test whmcs/tests/
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ASSETS = path.join(__dirname, '..', 'modules', 'servers', 'pasargadcdn', 'assets');

function load() {
  const stub = {
    t: (s) => s,
    h: () => ({}),
    append: () => {},
    clear: () => {},
    icon: () => ({}),
    ltr: (s) => s,
    num: (n) => String(n)
  };
  global.window = { PCDN: stub, XMLHttpRequest: function () {} };
  global.XMLHttpRequest = function () {};
  global.document = { createElement: () => ({ setAttribute() {}, appendChild() {} }) };
  new Function(fs.readFileSync(path.join(ASSETS, 'fm.js'), 'utf8')).call(global);
  return global.window.PCDN;
}

test('a file name becomes one safe key segment', () => {
  const P = load();
  const { safeName, joinKey } = P.fmInternals;
  assert.equal(safeName('photo.jpg'), 'photo.jpg');
  assert.equal(safeName('عکس ۱.jpg'), 'عکس ۱.jpg');
  // a path separator or a control character can never leave the browser inside a key
  assert.equal(safeName('../../etc/passwd'), '.._.._etc_passwd');
  assert.equal(safeName('a\\b.txt'), 'a_b.txt');
  assert.equal(safeName('tab\there.txt'), 'tab_here.txt');
  assert.equal(safeName('..'), '_');
  assert.equal(safeName(''), 'file');
  assert.equal(safeName('   '), 'file');
  // and the key always sits inside the folder being viewed
  assert.equal(joinKey('photos/', 'a.jpg'), 'photos/a.jpg');
  assert.equal(joinKey('', 'a.jpg'), 'a.jpg');
  assert.equal(joinKey('photos/', '../a.jpg'), 'photos/.._a.jpg');
});

test('the upload shape follows the file size', () => {
  const P = load();
  const { MULTIPART_FROM, PART } = P.fmInternals;
  assert.equal(MULTIPART_FROM, 32 * 1048576);
  assert.equal(PART, 32 * 1048576);
  // the 7 GB cap must fit in the 1000 parts S3 allows, with room to spare
  assert.ok(Math.ceil(7 * 1024 * 1048576 / PART) < 1000);
});

test('no api() call glues a query string onto the path', () => {
  // api() sends the sub-path as ONE encoded value, so `path?prefix=…` reaches the server inside the
  // path and matches no route (HTTP 404). The query belongs in api()'s fourth argument.
  const src = fs.readFileSync(path.join(ASSETS, 'fm.js'), 'utf8')
    .split('\n').filter((l) => !l.trim().startsWith('//')).join('\n');
  const paths = apiPathArgs(src);
  assert.ok(paths.length >= 10, 'expected the api() calls to be found, got ' + paths.length);
  for (const a of paths) assert.ok(!a.includes('?'), 'query glued onto an api() path: ' + a);
});

// The second argument of every `P.api(` call, read with balanced parentheses so `base(name) + x`
// is one argument rather than cut at its own ')'.
function apiPathArgs(src) {
  const out = [];
  for (let i = src.indexOf('P.api('); i >= 0; i = src.indexOf('P.api(', i + 1)) {
    let depth = 0, arg = 1, buf = '';
    for (let j = i + 5; j < src.length; j++) {
      const c = src[j];
      if (c === '(' || c === '[' || c === '{') depth++;
      else if (c === ')' || c === ']' || c === '}') { depth--; if (depth === 0) break; }
      else if (c === ',' && depth === 1) { arg++; continue; }
      if (arg === 2 && depth >= 1) buf += c;
    }
    out.push(buf.trim());
  }
  return out;
}

test('every file icon exists in ui.js', () => {
  const P = load();
  const ui = fs.readFileSync(path.join(ASSETS, 'ui.js'), 'utf8');
  const icons = new Set([...ui.matchAll(/^\s*'?([A-Za-z0-9_-]+)'?\s*:/gm)].map((m) => m[1]));
  for (const name of ['photo.jpg', 'clip.mp4', 'doc.pdf', 'code.js', 'bundle.zip', 'what.unknown']) {
    assert.ok(icons.has(P.fmInternals.fileIcon(name)), name + ' -> ' + P.fmInternals.fileIcon(name));
  }
});
