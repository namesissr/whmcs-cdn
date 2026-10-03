// node --test status/tests  — PoW solver and helpers of status/abuse.js (SPEC §23.10)
"use strict";
const test = require("node:test");
const assert = require("node:assert");
const crypto = require("node:crypto");
const path = require("node:path");

const abuse = require(path.join(__dirname, "..", "abuse.js"));

test("sha256 matches node:crypto (empty, abc, multi-block, UTF-8)", () => {
  const inputs = ["", "abc", "a".repeat(55), "a".repeat(56), "a".repeat(64), "x".repeat(1000), "سلام-nonce-42"];
  for (const s of inputs) {
    assert.strictEqual(abuse.sha256Hex(s), crypto.createHash("sha256").update(s, "utf8").digest("hex"), s.slice(0, 20));
  }
  assert.strictEqual(abuse.sha256Hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
});

test("leadingZeroBits", () => {
  assert.strictEqual(abuse.leadingZeroBits(Uint8Array.from([0x00, 0x00, 0x80])), 16);
  assert.strictEqual(abuse.leadingZeroBits(Uint8Array.from([0x00, 0x0f])), 12);
  assert.strictEqual(abuse.leadingZeroBits(Uint8Array.from([0x01])), 7);
  assert.strictEqual(abuse.leadingZeroBits(Uint8Array.from([0xff])), 0);
  assert.strictEqual(abuse.leadingZeroBits(new Uint8Array(4)), 32);
});

function zeroBits(hexDigest) {
  let n = 0;
  for (const ch of hexDigest) {
    const v = parseInt(ch, 16);
    if (v === 0) { n += 4; continue; }
    return n + (Math.clz32(v) - 28);
  }
  return n;
}

test("solve finds a nonce the controller can verify: sha256(salt + nonce)", async () => {
  const salt = crypto.randomBytes(16).toString("hex");
  for (const bits of [8, 12, 16]) {
    const sol = await abuse.solve(salt, bits, { slice: 5000 });
    assert.match(sol.nonce, /^\d+$/);
    const digest = crypto.createHash("sha256").update(salt + sol.nonce, "utf8").digest("hex");
    assert.ok(zeroBits(digest) >= bits, `${bits} bits: ${digest}`);
    // the first solution: no smaller nonce satisfies the target
    for (let n = 0; n < Number(sol.nonce); n++) {
      const d = crypto.createHash("sha256").update(salt + n, "utf8").digest("hex");
      assert.ok(zeroBits(d) < bits);
    }
  }
});

test("solve yields between slices, reports progress and honours max / cancel", async () => {
  let yields = 0;
  const progress = [];
  const sol = await abuse.solve("00ff", 14, { slice: 500, yieldFn: (f) => { yields++; setImmediate(f); }, onProgress: (n) => progress.push(n) });
  assert.ok(sol.tried >= 1);
  assert.strictEqual(yields, progress.length);
  await assert.rejects(abuse.solve("ab", 30, { slice: 100, max: 1000 }), /no nonce found/);
  await assert.rejects(abuse.solve("ab", 30, { slice: 100, cancelled: () => true }), /cancelled/);
});

test("parseUrls mirrors the controller limits", () => {
  assert.ok(abuse.parseUrls("https://a.example/x\nhttp://b.example").ok);
  assert.ok(!abuse.parseUrls("").ok);
  assert.ok(!abuse.parseUrls("ftp://a.example").ok);
  assert.ok(!abuse.parseUrls(Array.from({ length: 11 }, (_, i) => `https://x${i}.example`).join("\n")).ok);
  assert.ok(!abuse.parseUrls("https://a.example/" + "x".repeat(2050)).ok);
  assert.deepStrictEqual(abuse.parseUrls(" https://a.example  ").urls, ["https://a.example"]);
});
