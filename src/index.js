import upstream from "../_worker.js";
import {
  SESSION_COOKIE,
  clearSessionCookie,
  createEncryptedKvNamespace,
  createSessionToken,
  legacyAuthValue,
  parseCookies,
  requestActorKey,
  sessionCookie,
  timingSafeStringEqual,
  verifySessionToken,
} from "./security.js";

const LOGIN_BODY_LIMIT = 8 * 1024;
const ADMIN_BODY_LIMIT = 512 * 1024;
const REQUIRED_SECRET_MINIMUMS = {
  ADMIN: 16,
  KEY: 16,
  SESSION_SECRET: 32,
  DATA_ENCRYPTION_KEY: 32,
};

const HTML_SECURITY_POLICY = [
  "default-src 'self'",
  "base-uri 'self'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "form-action 'self'",
  "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
  "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com",
  "font-src 'self' data: https://fonts.gstatic.com",
  "img-src 'self' data: blob: https:",
  "connect-src 'self' https:",
  "frame-src 'self' blob:",
  "upgrade-insecure-requests",
].join("; ");

function jsonResponse(payload, status = 200, headers = {}) {
  return Response.json(payload, {
    status,
    headers: {
      "Cache-Control": "no-store",
      ...headers,
    },
  });
}

function validateSecrets(env) {
  for (const [name, minimum] of Object.entries(REQUIRED_SECRET_MINIMUMS)) {
    if (typeof env[name] !== "string" || env[name].length < minimum) return name;
  }
  return null;
}

async function readLimitedBody(request, limit) {
  const declaredLength = Number(request.headers.get("Content-Length") || 0);
  if (Number.isFinite(declaredLength) && declaredLength > limit) {
    throw new RangeError("Request body is too large");
  }
  if (!request.body) return new Uint8Array();

  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > limit) {
        await reader.cancel("Request body is too large");
        throw new RangeError("Request body is too large");
      }
      chunks.push(value);
    }
  } finally {
    try { reader.releaseLock(); } catch { /* The stream may already be released. */ }
  }

  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

function isSameOriginMutation(request, url) {
  const origin = request.headers.get("Origin");
  const fetchSite = request.headers.get("Sec-Fetch-Site");
  return origin === url.origin && (!fetchSite || fetchSite === "same-origin");
}

function isHtmlNavigation(request) {
  return (request.headers.get("Accept") || "").includes("text/html")
    || request.headers.get("Sec-Fetch-Mode") === "navigate";
}

async function rateLimit(binding, key) {
  if (!binding || typeof binding.limit !== "function") {
    throw new Error("Required rate limiter binding is unavailable");
  }
  return binding.limit({ key });
}

async function assetResponse(env, request, path) {
  if (!env.ASSETS || typeof env.ASSETS.fetch !== "function") {
    return jsonResponse({ error: "Static asset binding is unavailable" }, 503);
  }
  const assetUrl = new URL(request.url);
  assetUrl.pathname = path;
  assetUrl.search = "";
  return env.ASSETS.fetch(new Request(assetUrl, { method: request.method === "HEAD" ? "HEAD" : "GET" }));
}

function addSecurityHeaders(response, { html = false, sensitive = false } = {}) {
  if (response.status === 101) return response;
  const headers = new Headers(response.headers);
  headers.set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()");
  headers.set("Cross-Origin-Opener-Policy", "same-origin");
  headers.set("Cross-Origin-Resource-Policy", "same-origin");
  headers.set("X-Robots-Tag", "noindex, nofollow, noarchive");
  if (html) headers.set("Content-Security-Policy", HTML_SECURITY_POLICY);
  if (sensitive) headers.set("Cache-Control", "no-store");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function routeCategory(pathname, request) {
  if ((request.headers.get("Upgrade") || "").toLowerCase() === "websocket") return "websocket";
  if (pathname === "/login") return "login";
  if (pathname === "/admin" || pathname.startsWith("/admin/")) return "admin";
  if (pathname === "/sub") return "subscription";
  if (request.method === "POST") return "tunnel_http";
  return "cover";
}

function recordMetric(env, request, category, status, startedAt) {
  try {
    env.SECURITY_ANALYTICS?.writeDataPoint({
      indexes: [category],
      blobs: [request.method, String(status), request.cf?.colo || "unknown"],
      doubles: [status, Date.now() - startedAt],
    });
  } catch (error) {
    console.error(JSON.stringify({ event: "analytics_write_failed", error: error instanceof Error ? error.message : "unknown" }));
  }
}

function replaceLegacyAuthCookie(request, value) {
  const headers = new Headers(request.headers);
  const retained = String(headers.get("Cookie") || "")
    .split(";")
    .map((item) => item.trim())
    .filter((item) => item && !item.startsWith("auth="));
  retained.push(`auth=${value}`);
  headers.set("Cookie", retained.join("; "));
  return new Request(request, { headers });
}

function requestForUpstream(request) {
  const url = new URL(request.url);
  if (url.protocol === "http:" && ["localhost", "127.0.0.1"].includes(url.hostname)) {
    url.protocol = "https:";
    return new Request(url, request);
  }
  return request;
}

function securedEnvironment(env, ctx) {
  const encryptedKv = createEncryptedKvNamespace(env.KV, env.DATA_ENCRYPTION_KEY, ctx);
  return new Proxy(env, {
    get(target, property, receiver) {
      if (property === "KV") return encryptedKv;
      return Reflect.get(target, property, receiver);
    },
  });
}

async function authenticateRequest(request, env) {
  const token = parseCookies(request.headers.get("Cookie")).get(SESSION_COOKIE);
  if (!token) return null;
  const payload = await verifySessionToken(token, env.SESSION_SECRET, request.headers.get("User-Agent") || "");
  return payload ? { token, payload } : null;
}

async function handleLogin(request, env, url) {
  if (request.method === "GET" || request.method === "HEAD") {
    if (await authenticateRequest(request, env)) {
      return new Response(null, { status: 302, headers: { Location: "/admin", "Cache-Control": "no-store" } });
    }
    return assetResponse(env, request, "/login/index.html");
  }

  if (request.method !== "POST") {
    return jsonResponse({ error: "Method not allowed" }, 405, { Allow: "GET, HEAD, POST" });
  }
  if (!isSameOriginMutation(request, url)) return jsonResponse({ error: "Cross-origin request rejected" }, 403);
  if (!(request.headers.get("Content-Type") || "").toLowerCase().startsWith("application/x-www-form-urlencoded")) {
    return jsonResponse({ error: "Unsupported media type" }, 415);
  }

  const actorKey = await requestActorKey(request);
  const outcome = await rateLimit(env.LOGIN_RATE_LIMITER, actorKey);
  if (!outcome.success) return jsonResponse({ error: "Too many login attempts" }, 429, { "Retry-After": "60" });

  let body;
  try {
    body = await readLimitedBody(request, LOGIN_BODY_LIMIT);
  } catch (error) {
    if (error instanceof RangeError) return jsonResponse({ error: error.message }, 413);
    throw error;
  }
  const password = new URLSearchParams(new TextDecoder().decode(body)).get("password") || "";
  if (!(await timingSafeStringEqual(password.replace(/[\r\n]/gu, ""), env.ADMIN.replace(/[\r\n]/gu, "")))) {
    return jsonResponse({ error: "Invalid credentials" }, 401);
  }

  const token = await createSessionToken(env.SESSION_SECRET, request.headers.get("User-Agent") || "");
  return jsonResponse({ success: true }, 200, { "Set-Cookie": sessionCookie(token) });
}

async function handleAuthenticatedRoute(request, env, ctx, url, auth) {
  if (!auth) {
    if ((url.pathname === "/admin" || url.pathname === "/admin/") && isHtmlNavigation(request)) {
      return new Response(null, { status: 302, headers: { Location: "/login", "Cache-Control": "no-store" } });
    }
    return jsonResponse({ error: "Authentication required" }, 401);
  }

  const actorKey = await requestActorKey(request);
  const outcome = await rateLimit(env.ADMIN_RATE_LIMITER, `${auth.payload.n}:${actorKey}`);
  if (!outcome.success) return jsonResponse({ error: "Too many admin requests" }, 429, { "Retry-After": "60" });

  let forwardedRequest = request;
  if (!["GET", "HEAD", "OPTIONS"].includes(request.method)) {
    if (!isSameOriginMutation(request, url)) return jsonResponse({ error: "Cross-origin request rejected" }, 403);
    try {
      const body = await readLimitedBody(request, ADMIN_BODY_LIMIT);
      forwardedRequest = new Request(request, { body });
    } catch (error) {
      if (error instanceof RangeError) return jsonResponse({ error: error.message }, 413);
      throw error;
    }
  }

  if ((url.pathname === "/admin" || url.pathname === "/admin/") && ["GET", "HEAD"].includes(request.method)) {
    return assetResponse(env, request, "/admin/index.html");
  }

  const userAgent = request.headers.get("User-Agent") || "null";
  const legacyValue = await legacyAuthValue(userAgent, env.KEY, env.ADMIN);
  forwardedRequest = replaceLegacyAuthCookie(forwardedRequest, legacyValue);
  return upstream.fetch(requestForUpstream(forwardedRequest), securedEnvironment(env, ctx), ctx);
}

export default {
  async fetch(request, env, ctx) {
    const startedAt = Date.now();
    let url = null;
    let category = "cover";
    let response;

    try {
      url = new URL(request.url);
      category = routeCategory(url.pathname, request);
      const invalidSecret = validateSecrets(env);
      if (invalidSecret) {
        response = jsonResponse({ error: `Security configuration is invalid: ${invalidSecret}` }, 503);
      } else if (url.protocol !== "https:" && !["localhost", "127.0.0.1"].includes(url.hostname)) {
        url.protocol = "https:";
        response = Response.redirect(url.toString(), 308);
      } else if (url.pathname === "/login") {
        response = await handleLogin(request, env, url);
      } else if (url.pathname === "/logout") {
        response = new Response(null, {
          status: 302,
          headers: {
            Location: "/login",
            "Cache-Control": "no-store",
            "Set-Cookie": clearSessionCookie(),
          },
        });
      } else if (url.pathname === "/admin" || url.pathname.startsWith("/admin/") || url.pathname === "/locations") {
        const auth = await authenticateRequest(request, env);
        response = await handleAuthenticatedRoute(request, env, ctx, url, auth);
      } else {
        response = await upstream.fetch(requestForUpstream(request), securedEnvironment(env, ctx), ctx);
      }
    } catch (error) {
      console.error(JSON.stringify({
        event: "request_failed",
        path: url?.pathname || "/",
        category,
        error: error instanceof Error ? error.message : "unknown",
      }));
      response = jsonResponse({ error: "Internal server error" }, 500);
    }

    recordMetric(env, request, category, response.status, startedAt);
    const pathname = url?.pathname || "/";
    const html = ["/login", "/admin", "/admin/"].includes(pathname)
      && (response.headers.get("Content-Type") || "").includes("text/html");
    const sensitive = category === "login" || category === "admin" || category === "subscription";
    return addSecurityHeaders(response, { html, sensitive });
  },
};
