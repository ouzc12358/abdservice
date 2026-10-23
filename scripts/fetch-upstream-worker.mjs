import { createHash } from 'node:crypto';
import { appendFile, rename, unlink, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const repository = process.env.UPSTREAM_REPOSITORY || 'cmliu/edgetunnel';
const ref = process.env.UPSTREAM_REF || 'main';
const directUrl = process.env.UPSTREAM_WORKER_URL || '';
const outputPath = resolve(process.env.UPSTREAM_WORKER_PATH || new URL('../_worker.js', import.meta.url).pathname);
const githubOutput = process.env.GITHUB_OUTPUT || '';

if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(repository)) {
  throw new Error('UPSTREAM_REPOSITORY must use the owner/repository form');
}
if (!/^[A-Za-z0-9._/-]+$/u.test(ref) || ref.includes('..')) {
  throw new Error('UPSTREAM_REF contains unsupported characters');
}

const githubHeaders = {
  Accept: 'application/vnd.github+json',
  'User-Agent': 'abdservice-updater/2.0',
  'X-GitHub-Api-Version': '2022-11-28',
};
if (process.env.GITHUB_TOKEN) githubHeaders.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;

let commit = 'direct-url';
let upstreamUrl = directUrl;
if (!upstreamUrl) {
  const commitResponse = await fetch(`https://api.github.com/repos/${repository}/commits/${encodeURIComponent(ref)}`, {
    headers: githubHeaders,
  });
  if (!commitResponse.ok) throw new Error(`Upstream commit lookup failed: HTTP ${commitResponse.status}`);
  const metadata = await commitResponse.json();
  if (!/^[0-9a-f]{40}$/u.test(metadata?.sha || '')) throw new Error('Upstream commit lookup returned an invalid SHA');
  commit = metadata.sha;
  upstreamUrl = `https://raw.githubusercontent.com/${repository}/${commit}/_worker.js`;
}

const parsedUrl = new URL(upstreamUrl);

if (parsedUrl.protocol !== 'https:' || parsedUrl.hostname !== 'raw.githubusercontent.com' || !parsedUrl.pathname.endsWith('/_worker.js')) {
  throw new Error('UPSTREAM_WORKER_URL must be an HTTPS raw.githubusercontent.com _worker.js URL');
}

const response = await fetch(parsedUrl, {
  headers: {
    Accept: 'text/plain',
    'User-Agent': 'abdservice-updater/2.0',
  },
});
if (!response.ok) throw new Error(`Upstream fetch failed: HTTP ${response.status}`);

const bytes = new Uint8Array(await response.arrayBuffer());
const maxBytes = 8 * 1024 * 1024;
if (bytes.byteLength < 1024 || bytes.byteLength > maxBytes) {
  throw new Error(`Unexpected upstream size: ${bytes.byteLength} bytes`);
}

const source = new TextDecoder().decode(bytes);
const expectedSignatures = [
  /export\s+default\s*\{/u,
  /const\s+Version\s*=/u,
  /new\s+WebSocketPair\s*\(/u,
  /async\s+fetch\s*\(/u,
];
if (source.includes('\u0000') || expectedSignatures.some((signature) => !signature.test(source))) {
  throw new Error('Upstream response failed the Worker source validation');
}

const version = source.match(/const\s+Version\s*=\s*['"]([^'"]+)/u)?.[1] || 'unknown';
const sha256 = createHash('sha256').update(bytes).digest('hex');
const temporaryPath = `${outputPath}.tmp-${process.pid}`;
await writeFile(temporaryPath, bytes, { mode: 0o644 });
try {
  await rename(temporaryPath, outputPath);
} catch (error) {
  await unlink(temporaryPath).catch(() => {});
  throw error;
}

const result = {
  repository,
  ref,
  commit,
  source: parsedUrl.toString(),
  output: outputPath,
  version,
  bytes: bytes.byteLength,
  sha256,
};

if (githubOutput) {
  await appendFile(githubOutput, [
    `upstream_commit=${commit}`,
    `upstream_version=${version}`,
    `upstream_sha256=${sha256}`,
    '',
  ].join('\n'));
}

console.log(JSON.stringify(result));
