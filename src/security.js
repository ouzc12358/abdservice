const encoder = new TextEncoder();
const decoder = new TextDecoder();

export const SESSION_COOKIE = "__Host-abd_session";
export const SESSION_TTL_SECONDS = 24 * 60 * 60;
export const ENCRYPTED_VALUE_PREFIX = "enc:v1:";

const SENSITIVE_KV_KEYS = new Set([
  "config.json",
  "cf.json",
  "tg.json",
  "ADD.txt",
  "log.json",
]);

export function bytesToBase64Url(bytes) {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

export function base64UrlToBytes(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/u.test(value)) {
    throw new TypeError("Invalid base64url value");
  }

  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function digest(algorithm, value) {
  return new Uint8Array(await crypto.subtle.digest(algorithm, value));
}

function timingSafeEqualBytes(left, right) {
  if (left.byteLength !== right.byteLength) return false;
  if (typeof crypto.subtle.timingSafeEqual === "function") {
    return crypto.subtle.timingSafeEqual(left, right);
  }

  // Node's Web Crypto does not expose timingSafeEqual yet. Both inputs reaching
  // this fallback are fixed-size digests, so the loop does not leak their length.
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

export async function timingSafeStringEqual(provided, expected) {
  const [providedHash, expectedHash] = await Promise.all([
    digest("SHA-256", encoder.encode(String(provided ?? ""))),
    digest("SHA-256", encoder.encode(String(expected ?? ""))),
  ]);
  return timingSafeEqualBytes(providedHash, expectedHash);
}

async function importHmacKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
}

async function hmac(secret, message) {
  const key = await importHmacKey(secret);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(message)));
}

async function userAgentFingerprint(userAgent) {
  const fingerprint = await digest("SHA-256", encoder.encode(userAgent || ""));
  return bytesToBase64Url(fingerprint.subarray(0, 18));
}

export async function createSessionToken(secret, userAgent, options = {}) {
  const nowSeconds = Math.floor((options.now ?? Date.now()) / 1000);
  const ttlSeconds = Math.min(
    Math.max(Number(options.ttlSeconds ?? SESSION_TTL_SECONDS), 60),
    SESSION_TTL_SECONDS,
  );
  const nonce = new Uint8Array(18);
  crypto.getRandomValues(nonce);

  const payload = {
    v: 1,
    iat: nowSeconds,
    exp: nowSeconds + ttlSeconds,
    ua: await userAgentFingerprint(userAgent),
    n: bytesToBase64Url(nonce),
  };
  const encodedPayload = bytesToBase64Url(encoder.encode(JSON.stringify(payload)));
  const signature = bytesToBase64Url(await hmac(secret, encodedPayload));
  return `${encodedPayload}.${signature}`;
}

export async function verifySessionToken(token, secret, userAgent, options = {}) {
  if (typeof token !== "string" || token.length > 2048) return null;
  const parts = token.split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) return null;

  try {
    const expectedSignature = await hmac(secret, parts[0]);
    const providedSignature = base64UrlToBytes(parts[1]);
    if (!timingSafeEqualBytes(expectedSignature, providedSignature)) return null;

    const payload = JSON.parse(decoder.decode(base64UrlToBytes(parts[0])));
    const nowSeconds = Math.floor((options.now ?? Date.now()) / 1000);
    if (
      payload?.v !== 1
      || !Number.isInteger(payload.iat)
      || !Number.isInteger(payload.exp)
      || typeof payload.ua !== "string"
      || typeof payload.n !== "string"
      || payload.iat > nowSeconds + 60
      || payload.exp <= nowSeconds
      || payload.exp - payload.iat > SESSION_TTL_SECONDS
    ) {
      return null;
    }

    const expectedFingerprint = await userAgentFingerprint(userAgent);
    if (!(await timingSafeStringEqual(payload.ua, expectedFingerprint))) return null;
    return payload;
  } catch {
    return null;
  }
}

export function parseCookies(header) {
  const cookies = new Map();
  for (const item of String(header || "").split(";")) {
    const separator = item.indexOf("=");
    if (separator < 1) continue;
    const name = item.slice(0, separator).trim();
    const value = item.slice(separator + 1).trim();
    if (name) cookies.set(name, value);
  }
  return cookies;
}

export function sessionCookie(token, maxAge = SESSION_TTL_SECONDS) {
  return `${SESSION_COOKIE}=${token}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Strict`;
}

export function clearSessionCookie() {
  return `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`;
}

export async function requestActorKey(request) {
  const address = request.headers.get("CF-Connecting-IP") || "unknown";
  const userAgent = request.headers.get("User-Agent") || "unknown";
  const hashed = await digest("SHA-256", encoder.encode(`${address}\u0000${userAgent}`));
  return bytesToBase64Url(hashed.subarray(0, 18));
}

export async function legacyAuthValue(userAgent, key, adminPassword) {
  const first = await digest("MD5", encoder.encode(`${userAgent}${key}${adminPassword}`));
  const firstHex = [...first].map((value) => value.toString(16).padStart(2, "0")).join("");
  const second = await digest("MD5", encoder.encode(firstHex.slice(7, 27)));
  return [...second].map((value) => value.toString(16).padStart(2, "0")).join("");
}

async function deriveEncryptionKey(secret) {
  const material = await digest("SHA-256", encoder.encode(`abdservice:data:v1\u0000${secret}`));
  return crypto.subtle.importKey("raw", material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

export async function encryptKvValue(keyName, value, secret) {
  const key = await deriveEncryptionKey(secret);
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const additionalData = encoder.encode(`abdservice:${keyName}:v1`);
  const encrypted = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData, tagLength: 128 },
    key,
    encoder.encode(value),
  ));
  return `${ENCRYPTED_VALUE_PREFIX}${bytesToBase64Url(iv)}:${bytesToBase64Url(encrypted)}`;
}

export async function decryptKvValue(keyName, storedValue, secret) {
  if (!storedValue.startsWith(ENCRYPTED_VALUE_PREFIX)) {
    return { value: storedValue, encrypted: false };
  }

  const parts = storedValue.split(":");
  if (parts.length !== 4 || parts[0] !== "enc" || parts[1] !== "v1") {
    throw new Error(`Unsupported encrypted KV value for ${keyName}`);
  }

  const iv = base64UrlToBytes(parts[2]);
  const ciphertext = base64UrlToBytes(parts[3]);
  if (iv.byteLength !== 12 || ciphertext.byteLength < 16) {
    throw new Error(`Invalid encrypted KV value for ${keyName}`);
  }

  const key = await deriveEncryptionKey(secret);
  const additionalData = encoder.encode(`abdservice:${keyName}:v1`);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, additionalData, tagLength: 128 },
    key,
    ciphertext,
  );
  return { value: decoder.decode(plaintext), encrypted: true };
}

function convertTextValue(value, type) {
  if (type === "json") return JSON.parse(value);
  if (type === "arrayBuffer") return encoder.encode(value).buffer;
  if (type === "stream") return new Blob([value]).stream();
  return value;
}

export function createEncryptedKvNamespace(namespace, secret, ctx) {
  const getType = (options) => typeof options === "string" ? options : options?.type || "text";

  return {
    async get(key, options) {
      if (!SENSITIVE_KV_KEYS.has(key)) return namespace.get(key, options);
      const storedValue = await namespace.get(key, "text");
      if (storedValue === null) return null;
      const decrypted = await decryptKvValue(key, storedValue, secret);
      if (!decrypted.encrypted) {
        ctx.waitUntil(encryptKvValue(key, decrypted.value, secret).then((encrypted) => namespace.put(key, encrypted)));
      }
      return convertTextValue(decrypted.value, getType(options));
    },

    async getWithMetadata(key, options) {
      if (!SENSITIVE_KV_KEYS.has(key)) return namespace.getWithMetadata(key, options);
      const result = await namespace.getWithMetadata(key, "text");
      if (result.value === null) return result;
      const decrypted = await decryptKvValue(key, result.value, secret);
      if (!decrypted.encrypted) {
        ctx.waitUntil(encryptKvValue(key, decrypted.value, secret).then((encrypted) => namespace.put(key, encrypted)));
      }
      return { ...result, value: convertTextValue(decrypted.value, getType(options)) };
    },

    async put(key, value, options) {
      if (!SENSITIVE_KV_KEYS.has(key)) return namespace.put(key, value, options);
      if (typeof value !== "string") throw new TypeError(`Sensitive KV value ${key} must be text`);
      const encrypted = await encryptKvValue(key, value, secret);
      return namespace.put(key, encrypted, options);
    },

    delete(key) {
      return namespace.delete(key);
    },

    list(options) {
      return namespace.list(options);
    },
  };
}
