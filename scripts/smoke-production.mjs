import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";

const baseUrl = new URL(process.argv[2] || "");
const keychainService = process.argv[3] || "abdservice-secure.cloudflare";
const userAgent = "abdservice-production-smoke/1.0";

if (baseUrl.protocol !== "https:") throw new Error("The smoke-test URL must use HTTPS");

const adminPassword = execFileSync("/usr/bin/security", [
  "find-generic-password",
  "-s",
  keychainService,
  "-a",
  "ADMIN",
  "-w",
], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();

const results = {};

const loginPage = await fetch(new URL("/login", baseUrl), {
  headers: { Accept: "text/html", "User-Agent": userAgent },
  redirect: "manual",
});
assert.equal(loginPage.status, 200);
assert.match(loginPage.headers.get("strict-transport-security") || "", /max-age=63072000/u);
assert.match(loginPage.headers.get("content-security-policy") || "", /frame-ancestors 'none'/u);
results.loginPage = loginPage.status;

const unauthorizedAdmin = await fetch(new URL("/admin", baseUrl), {
  headers: { Accept: "text/html", "User-Agent": userAgent },
  redirect: "manual",
});
assert.equal(unauthorizedAdmin.status, 302);
assert.equal(unauthorizedAdmin.headers.get("location"), "/login");
results.unauthorizedAdmin = unauthorizedAdmin.status;

const csrfAttempt = await fetch(new URL("/login", baseUrl), {
  method: "POST",
  headers: {
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": userAgent,
  },
  body: new URLSearchParams({ password: adminPassword }),
});
assert.equal(csrfAttempt.status, 403);
results.csrfRejected = csrfAttempt.status;

const login = await fetch(new URL("/login", baseUrl), {
  method: "POST",
  headers: {
    Origin: baseUrl.origin,
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": userAgent,
  },
  body: new URLSearchParams({ password: adminPassword }),
});
assert.equal(login.status, 200);
const cookie = (login.headers.get("set-cookie") || "").split(";", 1)[0];
assert.match(cookie, /^__Host-abd_session=/u);
results.login = login.status;

const authenticatedAdmin = await fetch(new URL("/admin", baseUrl), {
  headers: { Accept: "text/html", Cookie: cookie, "User-Agent": userAgent },
});
assert.equal(authenticatedAdmin.status, 200);
assert.match(authenticatedAdmin.headers.get("content-type") || "", /text\/html/u);
results.authenticatedAdmin = authenticatedAdmin.status;

const configResponse = await fetch(new URL("/admin/config.json", baseUrl), {
  headers: { Cookie: cookie, "User-Agent": userAgent },
});
assert.equal(configResponse.status, 200);
const config = await configResponse.json();
assert.match(config.UUID, /^[0-9a-f-]{36}$/u);
results.encryptedKvInitialization = configResponse.status;

const coverPage = await fetch(baseUrl, { headers: { "User-Agent": userAgent } });
assert.equal(coverPage.status, 200);
results.coverPage = coverPage.status;

const webSocketUrl = new URL(baseUrl);
webSocketUrl.protocol = "wss:";
await new Promise((resolve, reject) => {
  const socket = new WebSocket(webSocketUrl);
  const timeout = setTimeout(() => {
    socket.close();
    reject(new Error("WebSocket handshake timed out"));
  }, 10_000);
  socket.addEventListener("open", () => {
    clearTimeout(timeout);
    socket.close(1000, "smoke-test");
    resolve();
  }, { once: true });
  socket.addEventListener("error", () => {
    clearTimeout(timeout);
    reject(new Error("WebSocket handshake failed"));
  }, { once: true });
});
results.webSocketHandshake = 101;

console.log(JSON.stringify(results, null, 2));
