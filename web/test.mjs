// Run with: node --test web/test.mjs
// Verifies the Rust-signed vectors in tests/vectors with the web verifier,
// both through WebCrypto and through the vendored pure-JS fallback.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { canonicalize, verify } from "./cnry-canary.js";
import * as noble from "./vendor/noble-ed25519.js";

const dir = new URL("../tests/vectors/", import.meta.url);
const text = readFileSync(new URL("valid.json", dir), "utf8");
const key = readFileSync(new URL("key.pub", dir), "utf8").trim();
const now = new Date("2026-11-16T12:00:00Z");

const edit = (f) => { const o = JSON.parse(text); f(o); return JSON.stringify(o); };

test("the Rust-signed vector is present", async () => {
  const st = await verify(text, key, now);
  assert.equal(st?.system, "corbet.ch");
});

test("expiry, tampering, wrong key, junk are absent", async () => {
  assert.equal(await verify(text, key, new Date("2027-01-01T00:00:00Z")), null);
  assert.equal(await verify(text, key, new Date("2026-11-15T10:00:00Z")), null);
  assert.equal(await verify(edit((o) => { o.statement = "Everything is fine."; }), key, now), null);
  assert.equal(await verify(edit((o) => { o.extra = 1; }), key, now), null);
  assert.equal(await verify(edit((o) => { o.expires = "2026-12-15T13:00:00+01:00"; }), key, now), null);
  assert.equal(await verify(edit((o) => { o.freshness.time = "2026-11-10T00:00:00Z"; }), key, now), null);
  const other = "ed25519pub:" + key.slice("ed25519pub:".length).replace(/^./, (c) => (c === "A" ? "B" : "A"));
  assert.equal(await verify(text, other, now), null);
  assert.equal(await verify("", key, now), null);
  assert.equal(await verify("{}", key, now), null);
  assert.equal(await verify(text, "garbage", now), null);
});

test("the vendored pure-JS verifier agrees with the vector", async () => {
  const st = JSON.parse(text);
  const { signature, ...unsigned } = st;
  const b = (s) => Uint8Array.from(Buffer.from(s, "base64url"));
  const msg = new TextEncoder().encode(canonicalize(unsigned));
  const pub = b(key.slice("ed25519pub:".length));
  assert.equal(await noble.verifyAsync(b(signature), msg, pub, { zip215: false }), true);
  msg[0] ^= 1;
  assert.equal(await noble.verifyAsync(b(signature), msg, pub, { zip215: false }), false);
});

test("canonicalisation matches RFC 8785 sorting", () => {
  const v = JSON.parse('{"\\u20ac":"E","\\r":"C","\\ufb33":"H","1":"1","\\ud83d\\ude00":"G","\\u0080":"X","\\u00f6":"O"}');
  assert.equal(canonicalize(v), '{"\\r":"C","1":"1","\u0080":"X","\u00f6":"O","\u20ac":"E","\u{1f600}":"G","\ufb33":"H"}');
});
