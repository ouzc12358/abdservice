const baseUrl = (process.argv[2] || process.env.WORKER_URL || '').replace(/\/+$/u, '');

if (!baseUrl) {
  throw new Error('Usage: node scripts/smoke-public.mjs https://worker.example');
}

const response = await fetch(`${baseUrl}/login`, {
  headers: {
    Accept: 'text/html',
    'User-Agent': 'edge-github-smoke/1.0',
  },
});
const body = await response.text();

if (response.status !== 200) {
  throw new Error(`GET /login returned ${response.status}: ${body.slice(0, 120)}`);
}
for (const header of ['strict-transport-security', 'content-security-policy', 'x-content-type-options']) {
  if (!response.headers.get(header)) throw new Error(`GET /login missing ${header}`);
}
if (!/<(?:!doctype|html)\b/iu.test(body)) throw new Error('GET /login did not return an HTML document');

console.log(JSON.stringify({
  url: `${baseUrl}/login`,
  status: response.status,
  contentType: response.headers.get('content-type'),
  securityHeaders: ['strict-transport-security', 'content-security-policy', 'x-content-type-options'],
}));
