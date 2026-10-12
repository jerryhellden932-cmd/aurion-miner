#!/usr/bin/env node
// Dependency-free private R2 artifact client. Requires Node.js 24 and GitHub id-token: write.
import { createReadStream, createWriteStream } from 'node:fs';
import { appendFile, glob, lstat, mkdir, readdir, realpath, rename, rm, writeFile } from 'node:fs/promises';
import { basename, dirname, join, parse, relative, resolve, sep } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { pathToFileURL } from 'node:url';

export const DEFAULT_GATEWAY = 'https://14d.space/api/artifacts';
const PART_SIZE = 64 * 1024 * 1024;
const MAX_JSON = 1024 * 1024;
const MAX_FILE_SIZE = 32 * 1024 * 1024 * 1024;
function error(message) { throw new Error(message); }
function gatewayError(action, status, code) {
  const failure = new Error('Private R2 artifact gateway rejected the request.');
  failure.artifactFailure = { action, status, code };
  throw failure;
}
export function formatFailure(failure) {
  const detail = failure?.artifactFailure;
  if (detail && /^[a-z-]{1,40}$/.test(detail.action) && Number.isInteger(detail.status) && detail.status >= 0 && detail.status <= 599 && /^[a-z_0-9]{1,100}$/.test(detail.code)) {
    return `Private R2 artifact transfer failed: action=${detail.action} status=${detail.status} code=${detail.code}.`;
  }
  return 'Private R2 artifact transfer failed. Check permissions, source run/attempt and file integrity; rerun the entire workflow if artifacts are missing.';
}
function id(value, label) { if (!/^[1-9][0-9]{0,19}$/.test(value || '')) error(`Invalid ${label}.`); return value; }
function name(value) { if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(value || '') || value.endsWith('.')) error('Invalid artifact name.'); return value; }
export function safePath(value) {
  if (typeof value !== 'string' || !value || value.length > 1024 || /[\\\x00-\x1f\x7f:]/.test(value) || value.startsWith('/') || value.endsWith('/')) error('Unsafe artifact path.');
  if (value.split('/').some(p => !p || p === '.' || p === '..' || p.endsWith('.') || p.endsWith(' ') || /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(p))) error('Unsafe artifact path.');
  return value;
}
function hash(value) { if (!/^[a-f0-9]{64}$/.test(value || '')) error('Invalid SHA256.'); return value; }
export function parseArguments(args, env = process.env) {
  const command = args.shift(); if (!['upload', 'download'].includes(command)) error('Usage: r2-artifacts.mjs upload|download --name NAME --path FILE|--directory DIR');
  const values = { command, paths: [], mergeMultiple: false, includeHidden: false, ifNoFilesFound: 'error' };
  const options = new Map([['--name', 'name'], ['--pattern', 'pattern'], ['--run-id', 'runId'], ['--run-attempt', 'runAttempt'], ['--directory', 'directory'], ['--expected-sha', 'expectedSha'], ['--expected-count', 'expectedCount'], ['--manifest', 'manifest'], ['--if-no-files-found', 'ifNoFilesFound']]);
  while (args.length) {
    const flag = args.shift();
    if (flag === '--merge-multiple') { values.mergeMultiple = true; continue; }
    if (flag === '--include-hidden-files') { values.includeHidden = true; continue; }
    if (flag === '--path') { const path = args.shift(); if (!path || path.startsWith('--')) error('Missing --path value.'); values.paths.push(path); continue; }
    const field = options.get(flag); if (!field) error(`Unknown option ${flag}.`);
    const value = args.shift(); if (!value || value.startsWith('--')) error(`Missing ${flag} value.`);
    if (Object.hasOwn(values, field) && field !== 'ifNoFilesFound') error(`Repeated ${flag}.`);
    values[field] = value;
  }
  if (!['error', 'warn', 'ignore'].includes(values.ifNoFilesFound)) error('Invalid --if-no-files-found mode.');
  if (values.name) name(values.name);
  if (command === 'upload') {
    if (!values.name || !values.paths.length || values.pattern || values.directory || values.runId || values.runAttempt) error('Upload requires --name and one or more --path values.');
  } else {
    if (Boolean(values.name) === Boolean(values.pattern) || !values.directory || values.paths.length) error('Download requires exactly one --name or --pattern and --directory.');
    if (values.pattern && (values.pattern.length > 128 || !/^[A-Za-z0-9*?_.-]+$/.test(values.pattern))) error('Invalid artifact pattern.');
    values.runId = id(values.runId || env.GITHUB_RUN_ID, 'run ID');
    values.runAttempt = id(values.runAttempt || env.GITHUB_RUN_ATTEMPT, 'run attempt');
    values.expectedSha = values.expectedSha || env.GITHUB_SHA;
    if (!/^[a-f0-9]{40}$/.test(values.expectedSha || '')) error('Supply --expected-sha with the source commit.');
    if (values.expectedCount !== undefined && (!/^[1-9][0-9]{0,3}$/.test(values.expectedCount) || Number(values.expectedCount) > 1000)) error('Invalid expected count.');
  }
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(env.GITHUB_REPOSITORY || '')) error('GITHUB_REPOSITORY is required.');
  return values;
}
export function globMatches(pattern, value) {
  const expression = '^' + [...pattern].map(c => c === '*' ? '.*' : c === '?' ? '.' : c.replace(/[\\^$+.[\]{}()|]/g, '\\$&')).join('') + '$';
  return new RegExp(expression).test(value);
}
function hidden(path) { return path.split(/[\\/]/).some(p => p !== '.' && p !== '..' && p.startsWith('.')); }
async function shaFile(path, start, end) {
  const digest = createHash('sha256'); let size = 0;
  for await (const chunk of createReadStream(path, start === undefined ? undefined : { start, end })) { digest.update(chunk); size += chunk.byteLength; }
  return { size, sha256: digest.digest('hex') };
}
export async function collectFiles(paths, includeHidden = false, cwd = process.cwd()) {
  const files = new Map(); const sources = new Set();
  async function add(path, outputPath) {
    await rejectSymlinkAncestors(path);
    const info = await lstat(path);
    if (info.isSymbolicLink()) error('Symbolic links cannot be uploaded.');
    if (!includeHidden && hidden(relative(cwd, path))) return;
    if (info.isDirectory()) {
      for (const entry of (await readdir(path)).sort()) {
        if (entry === '.git' || (!includeHidden && entry.startsWith('.'))) continue;
        await add(join(path, entry), outputPath ? `${outputPath}/${entry}` : entry);
      }
    } else if (info.isFile()) {
      if (sources.has(path)) return;
      const output = safePath(outputPath || basename(path));
      if (info.size > MAX_FILE_SIZE) error('Artifact file exceeds 32 GiB.');
      const folded = output.toLowerCase();
      if (files.has(folded) && files.get(folded).localPath !== path) error('Artifact files have conflicting paths.');
      files.set(folded, { path: output, localPath: path, size: info.size });
      sources.add(path);
    } else error('Only regular files can be uploaded.');
  }
  for (const input of paths) {
    const absolute = resolve(cwd, input); let matches;
    const magic = input.search(/[*?\[\]{}]/);
    let globRoot;
    if (magic >= 0) {
      const fixed = input.slice(0, magic); const lastSlash = Math.max(fixed.lastIndexOf('/'), fixed.lastIndexOf('\\'));
      globRoot = resolve(cwd, lastSlash < 0 ? '.' : fixed.slice(0, lastSlash + 1));
      await rejectSymlinkAncestors(globRoot);
      matches = []; for await (const path of glob(input, { cwd })) matches.push(resolve(cwd, path)); matches.sort();
    }
    else { try { await lstat(absolute); matches = [absolute]; } catch (failure) { if (failure.code !== 'ENOENT') throw failure; matches = []; } }
    for (const path of matches) await add(path, globRoot ? relative(globRoot, path).split(sep).join('/') : '');
  }
  const result = [...files.values()].sort((a, b) => a.path.localeCompare(b.path));
  if (result.length > 256) error('Artifact exceeds 256 files. Split it into multiple named artifacts.');
  const names = new Set(result.map(f => f.path.toLowerCase()));
  for (const file of result) { const segments = file.path.toLowerCase().split('/'); segments.pop(); while (segments.length) { if (names.has(segments.join('/'))) error('Artifact file and directory paths conflict.'); segments.pop(); } }
  for (const file of result) { const actual = await shaFile(file.localPath); if (actual.size !== file.size) error('An upload file changed while hashing.'); file.sha256 = actual.sha256; }
  return result;
}
async function readJson(response, limit = MAX_JSON) {
  if (Number(response.headers.get('content-length')) > limit) error('Artifact response exceeds metadata limit.');
  const reader = response.body?.getReader(); if (!reader) error('Missing artifact response.');
  const chunks = []; let size = 0;
  try { while (true) { const { done, value } = await reader.read(); if (done) break; size += value.byteLength; if (size > limit) error('Artifact response exceeds metadata limit.'); chunks.push(Buffer.from(value)); } return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
}
export function createClient(env = process.env, fetcher = fetch, options = {}) {
  const gateway = new URL(env.R2_ARTIFACT_GATEWAY || DEFAULT_GATEWAY);
  if (gateway.protocol !== 'https:' || gateway.username || gateway.password || gateway.search || gateway.hash || gateway.pathname !== '/api/artifacts') error('Invalid R2_ARTIFACT_GATEWAY.');
  let token; let expiration = 0;
  async function oidc() {
    if (token && expiration > Date.now() + 60000) return token;
    const requestUrl = new URL(env.ACTIONS_ID_TOKEN_REQUEST_URL || 'https://invalid.invalid');
    if (requestUrl.protocol !== 'https:' || !requestUrl.hostname.endsWith('.actions.githubusercontent.com') || !env.ACTIONS_ID_TOKEN_REQUEST_TOKEN) error('GitHub OIDC is unavailable; add permissions: id-token: write.');
    requestUrl.searchParams.set('audience', DEFAULT_GATEWAY);
    const response = await fetcher(requestUrl, { headers: { authorization: `Bearer ${env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}` }, redirect: 'error', signal: AbortSignal.timeout(15000) });
    if (!response.ok) error('GitHub OIDC token request failed.');
    const data = await readJson(response, 65536); if (typeof data.value !== 'string' || data.value.length > 20000) error('Invalid GitHub OIDC response.');
    let claims; try { claims = JSON.parse(Buffer.from(data.value.split('.')[1], 'base64url').toString('utf8')); } catch { error('Invalid GitHub OIDC response.'); }
    if (!Number.isSafeInteger(claims.exp)) error('Invalid GitHub OIDC expiration.');
    token = data.value; expiration = claims.exp * 1000; return token;
  }
  return {
    async request(action, params = {}, { method = 'GET', body, headers = {}, stream = false, retries = 6 } = {}) {
      const url = new URL(gateway); url.searchParams.set('action', action);
      for (const [key, value] of Object.entries(params)) if (value !== undefined) url.searchParams.set(key, String(value));
      const started = Date.now();
      for (let attempt = 0; ; attempt++) {
        const authorization = `Bearer ${await oidc()}`;
        let response;
        try {
          response = await fetcher(url, { method, headers: { ...headers, authorization }, body,
            duplex: body && typeof body !== 'string' ? 'half' : undefined, redirect: 'error', signal: AbortSignal.timeout(stream ? 300000 : 180000) });
        } catch { gatewayError(action, 0, 'transport_failed'); }
        if (response.ok) return stream ? response : readJson(response);
        // Bootstrap retries only: authorization, integrity and conflict errors fail immediately.
        if ([404, 503].includes(response.status) && (method === 'GET' || (action === 'start' && typeof body === 'string')) && attempt < retries && Date.now() - started < (options.bootstrapTimeout ?? 150000)) {
          await response.body?.cancel(); await new Promise(resolveWait => setTimeout(resolveWait, options.retryDelay ?? Math.min(10000 * (attempt + 1), 40000))); continue;
        }
        let code = 'unrecognized_response';
        try { const data = await readJson(response, 65536); if (/^[a-z_]+$/.test(data.error || '')) code = data.error; } catch {}
        gatewayError(action, response.status, code);
      }
    },
  };
}
export function validateManifest(manifest, expected) {
  if (!manifest || manifest.schema !== 1 || manifest.repository !== expected.repository || manifest.sha !== expected.sha || manifest.run_id !== expected.runId || manifest.run_attempt !== expected.runAttempt || manifest.name !== expected.name || !/^[a-f0-9-]{36}$/.test(manifest.upload || '') || !Array.isArray(manifest.files) || !manifest.files.length || manifest.files.length > 256) error('Artifact provenance mismatch.');
  const prefix = `artifacts/${manifest.repository}/${manifest.run_id}/${manifest.run_attempt}/${name(manifest.name)}/.uploads/${manifest.upload}/files/`;
  const names = new Set();
  for (const file of manifest.files) {
    safePath(file.path); hash(file.sha256);
    if (!Number.isSafeInteger(file.size) || file.size < 0 || file.size > MAX_FILE_SIZE || typeof file.key !== 'string' || !file.key.startsWith(prefix) || !/^[0-9]{5}$/.test(file.key.slice(prefix.length))) error('Invalid artifact file metadata.');
    const folded = file.path.toLowerCase(); if (names.has(folded)) error('Duplicate artifact path.'); names.add(folded);
  }
  for (const path of names) { const segments = path.split('/'); segments.pop(); while (segments.length) { if (names.has(segments.join('/'))) error('Artifact file and directory paths conflict.'); segments.pop(); } }
  return manifest;
}
async function saveManifest(path, value) {
  if (!path) return;
  const absolute = resolve(path); await ensureSafeDirectory(dirname(absolute)); await rejectSymlinkAncestors(absolute);
  const temp = join(dirname(absolute), `.r2-manifest-${randomUUID()}.tmp`);
  try { await writeFile(temp, JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o600 }); await rename(temp, absolute); }
  catch (failure) { await rm(temp, { force: true }); throw failure; }
}
export async function uploadArtifact(args, env, client, log = console.log) {
  const files = await collectFiles(args.paths, args.includeHidden);
  if (!files.length) { if (args.ifNoFilesFound === 'error') error('No artifact files matched.'); if (args.ifNoFilesFound === 'warn') log('No artifact files matched; upload skipped.'); return null; }
  const input = { name: args.name, files: files.map(({ path, size, sha256 }) => ({ path, size, sha256 })) };
  const start = await client.request('start', {}, { method: 'POST', body: JSON.stringify(input), headers: { 'content-type': 'application/json' } });
  let manifest;
  if (start.existing) manifest = start.manifest;
  else {
    if (start.part_size !== PART_SIZE || start.name !== args.name || !/^[a-f0-9-]{36}$/.test(start.upload || '') || !Array.isArray(start.files) || start.files.length !== files.length) error('Invalid upload session.');
    const common = { name: args.name, upload: start.upload };
    try {
      for (let index = 0; index < files.length; index++) {
        const file = files[index]; const assigned = start.files[index];
        if (assigned.id !== index || assigned.path !== file.path || assigned.size !== file.size) error('Upload session file mismatch.');
        for (let number = 1; number <= Math.ceil(file.size / PART_SIZE); number++) {
          const offset = (number - 1) * PART_SIZE; const length = Math.min(PART_SIZE, file.size - offset);
          const actual = await shaFile(file.localPath, offset, offset + length - 1); if (actual.size !== length) error('Upload file changed.');
          const response = await client.request('part', { ...common, file: index, part: number }, { method: 'PUT', body: createReadStream(file.localPath, { start: offset, end: offset + length - 1 }), headers: { 'content-length': String(length), 'content-type': 'application/octet-stream', 'x-artifact-sha256': actual.sha256 }, stream: true, retries: 0 });
          await response.body?.cancel();
        }
        await client.request('complete-file', { ...common, file: index }, { method: 'POST' });
      }
      manifest = await client.request('complete', common, { method: 'POST' });
    } catch (failure) { await client.request('abort', common, { method: 'DELETE', retries: 0 }).catch(() => {}); throw failure; }
  }
  validateManifest(manifest, { repository: env.GITHUB_REPOSITORY, sha: env.GITHUB_SHA, runId: env.GITHUB_RUN_ID, runAttempt: env.GITHUB_RUN_ATTEMPT, name: args.name });
  await saveManifest(args.manifest, manifest);
  log(`Uploaded ${files.length} file(s) to private R2 artifact ${args.name}.`);
  return manifest;
}
async function rejectSymlinkAncestors(path) {
  const absolute = resolve(path); const base = parse(absolute).root; let current = base;
  for (const segment of relative(base, absolute).split(sep).filter(Boolean)) {
    current = join(current, segment);
    try { if ((await lstat(current)).isSymbolicLink()) error('Artifact path contains an unsafe symbolic link.'); }
    catch (failure) { if (failure.code === 'ENOENT') return; throw failure; }
  }
}
async function ensureSafeDirectory(path) {
  const absolute = resolve(path); const base = parse(absolute).root; let current = base;
  for (const segment of relative(base, absolute).split(sep).filter(Boolean)) {
    current = join(current, segment); let info;
    try { info = await lstat(current); }
    catch (failure) {
      if (failure.code !== 'ENOENT') throw failure;
      try { await mkdir(current); } catch (creation) { if (creation.code !== 'EEXIST') throw creation; }
      info = await lstat(current);
    }
    if (info.isSymbolicLink() || !info.isDirectory()) error('Download destination contains an unsafe symbolic link or non-directory.');
  }
  return absolute;
}
async function safeDestination(root, path) {
  const target = resolve(root, ...safePath(path).split('/'));
  if (!target.startsWith(root + sep)) error('Unsafe download destination.');
  await ensureSafeDirectory(dirname(target));
  const realParent = await realpath(dirname(target));
  if (realParent !== root && !realParent.startsWith(root + sep)) error('Download destination contains an unsafe symbolic link.');
  try { const info = await lstat(target); if (!info.isFile() || info.isSymbolicLink()) error('Download would overwrite an unsafe path.'); }
  catch (failure) { if (failure.code !== 'ENOENT') throw failure; }
  return target;
}
export async function downloadArtifact(args, env, client, log = console.log) {
  const params = { run_id: args.runId, run_attempt: args.runAttempt }; let names = [];
  if (args.name) names = [args.name];
  else {
    let cursor; const seenCursors = new Set();
    do {
      const page = await client.request('list', { ...params, cursor });
      if (page.repository !== env.GITHUB_REPOSITORY || page.run_id !== args.runId || page.run_attempt !== args.runAttempt || !Array.isArray(page.names)) error('Invalid artifact listing.');
      for (const item of page.names) { name(item); if (globMatches(args.pattern, item)) names.push(item); }
      cursor = page.cursor;
      if (cursor && (typeof cursor !== 'string' || seenCursors.has(cursor))) error('Invalid artifact listing cursor.');
      seenCursors.add(cursor);
    } while (cursor);
  }
  names.sort();
  if (!names.length || new Set(names).size !== names.length || (args.expectedCount && names.length !== Number(args.expectedCount))) error('Expected R2 artifacts are missing or duplicated. Rerun the entire producing workflow.');
  const manifests = [];
  for (const artifact of names) {
    const manifest = await client.request('manifest', { ...params, name: artifact });
    manifests.push(validateManifest(manifest, { repository: env.GITHUB_REPOSITORY, sha: args.expectedSha, runId: args.runId, runAttempt: args.runAttempt, name: artifact }));
  }
  // Validate the complete restore plan before making directories or fetching bodies.
  // Individually valid artifacts can conflict when merged (file "node" vs "node/child").
  const destinations = new Map();
  for (const manifest of manifests) {
    for (const file of manifest.files) {
      const output = args.name || args.mergeMultiple ? file.path : `${manifest.name}/${file.path}`;
      safePath(output); const folded = output.toLowerCase();
      if (destinations.has(folded)) {
        const prior = destinations.get(folded).file;
        if (prior.sha256 !== file.sha256 || prior.size !== file.size) error('Merged artifacts have conflicting file paths.');
        continue;
      }
      destinations.set(folded, { file, manifest, output });
    }
  }
  for (const path of destinations.keys()) {
    const segments = path.split('/'); segments.pop();
    while (segments.length) { if (destinations.has(segments.join('/'))) error('Merged artifacts have conflicting file and directory paths.'); segments.pop(); }
  }
  const root = await ensureSafeDirectory(resolve(args.directory));
  const staged = [];
  try {
    for (const { file, manifest, output } of destinations.values()) {
        const target = await safeDestination(root, output); const temp = join(dirname(target), `.r2-download-${randomUUID()}.tmp`);
        const response = await client.request('file', { ...params, name: manifest.name, path: file.path }, { stream: true });
        if (response.headers.get('content-length') !== String(file.size) || response.headers.get('x-artifact-sha256') !== file.sha256 || !response.body) error('Artifact download metadata mismatch.');
        const digest = createHash('sha256'); let size = 0;
        const source = Readable.fromWeb(response.body);
        source.on('data', chunk => { size += chunk.byteLength; digest.update(chunk); if (size > file.size) source.destroy(new Error('Artifact download exceeds its recorded size.')); });
        staged.push({ temp, target });
        await pipeline(source, createWriteStream(temp, { flags: 'wx', mode: 0o600 }));
        if (size !== file.size || digest.digest('hex') !== file.sha256) error('Artifact download integrity check failed.');
    }
    // No final files are replaced until every downloaded body passes its hash check.
    for (const file of staged) await rename(file.temp, file.target);
  } catch (failure) { await Promise.allSettled(staged.map(file => rm(file.temp, { force: true }))); throw failure; }
  await saveManifest(args.manifest, args.name ? manifests[0] : manifests);
  log(`Downloaded and verified ${destinations.size} file(s) from ${names.length} private R2 artifact(s).`);
  return manifests;
}
export async function main(argv = process.argv.slice(2), env = process.env, fetcher = fetch) {
  const args = parseArguments([...argv], env); const client = createClient(env, fetcher);
  const result = args.command === 'upload' ? await uploadArtifact(args, env, client) : await downloadArtifact(args, env, client);
  if (env.GITHUB_OUTPUT && result) await appendFile(env.GITHUB_OUTPUT, `artifact-name=${args.name || args.pattern}\nartifact-count=${Array.isArray(result) ? result.length : 1}\n`);
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(failure => { console.error(formatFailure(failure)); process.exitCode = 1; });
}
