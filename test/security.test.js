import assert from "node:assert/strict";
import test from "node:test";
import {
  ENCRYPTED_VALUE_PREFIX,
  createSessionToken,
  decryptKvValue,
  encryptKvValue,
  parseCookies,
  timingSafeStringEqual,
  verifySessionToken,
} from "../src/security.js";

const sessionSecret = "session-secret-with-at-least-thirty-two-characters";
const dataSecret = "data-secret-with-at-least-thirty-two-characters";

test("constant-time string comparison accepts only identical values", async () => {
  assert.equal(await timingSafeStringEqual("correct horse", "correct horse"), true);
  assert.equal(await timingSafeStringEqual("correct horse", "correct battery"), false);
});

test("session tokens are signed, expire, and are bound to the user agent", async () => {
  const now = Date.UTC(2026, 8, 12, 10, 0, 0);
  const token = await createSessionToken(sessionSecret, "test-agent", { now, ttlSeconds: 300 });
  const signatureStart = token.lastIndexOf(".") + 1;
  const tamperedToken = `${token.slice(0, signatureStart)}${token[signatureStart] === "A" ? "B" : "A"}${token.slice(signatureStart + 1)}`;

  assert.ok(await verifySessionToken(token, sessionSecret, "test-agent", { now: now + 1_000 }));
  assert.equal(await verifySessionToken(token, sessionSecret, "other-agent", { now: now + 1_000 }), null);
  assert.equal(await verifySessionToken(tamperedToken, sessionSecret, "test-agent", { now: now + 1_000 }), null);
  assert.equal(await verifySessionToken(token, sessionSecret, "test-agent", { now: now + 301_000 }), null);
});

test("AES-GCM storage encryption authenticates both key name and ciphertext", async () => {
  const encrypted = await encryptKvValue("config.json", "{\"safe\":true}", dataSecret);
  const ciphertextStart = encrypted.lastIndexOf(":") + 1;
  const tamperedCiphertext = `${encrypted.slice(0, ciphertextStart)}${encrypted[ciphertextStart] === "A" ? "B" : "A"}${encrypted.slice(ciphertextStart + 1)}`;

  assert.ok(encrypted.startsWith(ENCRYPTED_VALUE_PREFIX));
  assert.deepEqual(await decryptKvValue("config.json", encrypted, dataSecret), {
    value: "{\"safe\":true}",
    encrypted: true,
  });
  await assert.rejects(() => decryptKvValue("tg.json", encrypted, dataSecret));
  await assert.rejects(() => decryptKvValue("config.json", tamperedCiphertext, dataSecret));
});

test("legacy plaintext values are detected for automatic migration", async () => {
  assert.deepEqual(await decryptKvValue("config.json", "plaintext", dataSecret), {
    value: "plaintext",
    encrypted: false,
  });
});

test("cookie parsing preserves values containing equals signs", () => {
  const cookies = parseCookies("one=1; session=abc==; ignored; two=2");
  assert.equal(cookies.get("session"), "abc==");
  assert.equal(cookies.get("two"), "2");
});
