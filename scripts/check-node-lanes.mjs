import fs from 'node:fs/promises';
import https from 'node:https';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const root = path.resolve(import.meta.dirname, '..');
const DEFAULT_LANES = path.join(root, 'ci', 'node-lanes.json');
const KEYS = Object.freeze(['current', 'floor', 'lts', 'source', 'verifiedAt']);
const INDEX_KEYS = Object.freeze(['date', 'files', 'lts', 'modules', 'npm', 'openssl', 'security', 'uv', 'v8', 'version', 'zlib']);
const VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/u;
const DATE = /^\d{4}-\d{2}-\d{2}$/u;
const MAX_INDEX_BYTES = 4 * 1024 * 1024;
const failures = new WeakSet();

function failure() {
  const error = new Error('The configured Node lanes are stale or invalid.');
  error.code = 'NODE_LANES_STALE'; failures.add(error); return error;
}

function exact(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return (prototype === Object.prototype || prototype === null)
    && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}

function parts(value) {
  if (typeof value !== 'string' || !VERSION.test(value)) throw failure();
  const result = value.split('.').map(Number);
  if (result.some((part) => !Number.isSafeInteger(part))) throw failure();
  return result;
}

function compare(left, right) {
  for (let index = 0; index < 3; index += 1) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return 0;
}

export function validateNodeLanes(value) {
  try {
    if (!exact(value, KEYS) || value.source !== 'https://nodejs.org/dist/index.json' || !DATE.test(value.verifiedAt)) throw failure();
    const floor = parts(value.floor); const lts = parts(value.lts); const current = parts(value.current);
    if (floor[0] !== 22 || lts[0] !== 24 || current[0] !== 26 || compare(floor, lts) >= 0 || compare(lts, current) >= 0) throw failure();
    const timestamp = Date.parse(`${value.verifiedAt}T00:00:00.000Z`);
    if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString().slice(0, 10) !== value.verifiedAt) throw failure();
    return Object.freeze({ ...value });
  } catch (error) {
    if (failures.has(error)) throw error;
    throw failure();
  }
}

function parseIndex(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 2 || bytes.length > MAX_INDEX_BYTES) throw failure();
  let value;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { throw failure(); }
  if (!Array.isArray(value) || value.length < 2 || value.length > 10_000) throw failure();
  const relevant = [];
  for (const entry of value) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry) || typeof entry.version !== 'string'
      || !/^v\d+\.\d+\.\d+$/u.test(entry.version)) throw failure();
    const version = entry.version.slice(1); const parsed = parts(version);
    if (parsed[0] < 22) continue;
    if (!exact(entry, INDEX_KEYS) || !DATE.test(entry.date) || !Array.isArray(entry.files) || entry.files.length < 1
      || entry.files.length > 128 || new Set(entry.files).size !== entry.files.length
      || entry.files.some((file) => typeof file !== 'string' || !/^[a-z0-9-]+$/u.test(file))
      || !['npm', 'v8', 'uv', 'zlib', 'openssl', 'modules'].every((key) => typeof entry[key] === 'string'
        && entry[key].length > 0 && entry[key].length <= 128 && !/[\u0000\r\n]/u.test(entry[key]))
      || typeof entry.security !== 'boolean'
      || entry.lts !== false && (typeof entry.lts !== 'string' || entry.lts.length < 1 || entry.lts.length > 64
        || /[\u0000\r\n]/u.test(entry.lts))) throw failure();
    relevant.push(Object.freeze({ version, parts: parsed, lts: entry.lts }));
  }
  if (relevant.length < 2 || new Set(relevant.map(({ version }) => version)).size !== relevant.length) throw failure();
  return relevant;
}

export function compareNodeIndex(lanesValue, indexBytes) {
  const lanes = validateNodeLanes(lanesValue); const entries = parseIndex(indexBytes);
  const latestLts = entries.filter(({ lts }) => lts !== false).sort((left, right) => compare(right.parts, left.parts))[0];
  const latestCurrent = entries.filter(({ lts }) => lts === false).sort((left, right) => compare(right.parts, left.parts))[0];
  if (!latestLts || latestLts.lts === false || latestLts.version !== lanes.lts
    || !latestCurrent || latestCurrent.lts !== false || latestCurrent.version !== lanes.current) throw failure();
  return Object.freeze({ lts: latestLts.version, current: latestCurrent.version });
}

export function proposeNodeLanes(lanesValue, indexBytes, verifiedAt) {
  const lanes = validateNodeLanes(lanesValue);
  if (typeof verifiedAt !== 'string' || !DATE.test(verifiedAt)
    || new Date(`${verifiedAt}T00:00:00.000Z`).toISOString().slice(0, 10) !== verifiedAt) throw failure();
  const entries = parseIndex(indexBytes);
  const lts = entries.filter(({ lts: name }) => name !== false).sort((left, right) => compare(right.parts, left.parts))[0];
  const current = entries.filter(({ lts: name }) => name === false).sort((left, right) => compare(right.parts, left.parts))[0];
  if (!lts || lts.lts === false || !current || current.lts !== false) throw failure();
  return validateNodeLanes({ ...lanes, lts: lts.version, current: current.version, verifiedAt });
}

async function readRegular(target, maximum = MAX_INDEX_BYTES) {
  const before = await fs.lstat(target, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n || before.size < 2n || before.size > BigInt(maximum)) throw failure();
  const handle = await fs.open(target, 'r');
  try {
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || opened.nlink !== 1n || opened.dev !== before.dev || opened.ino !== before.ino
      || opened.size !== before.size || opened.mtimeNs !== before.mtimeNs) throw failure();
    const bytes = await handle.readFile(); const after = await handle.stat({ bigint: true });
    if (after.dev !== opened.dev || after.ino !== opened.ino || after.size !== opened.size || after.mtimeNs !== opened.mtimeNs
      || BigInt(bytes.length) !== opened.size) throw failure();
    return bytes;
  } finally { await handle.close(); }
}

function downloadIndex(url) {
  return new Promise((resolve, reject) => {
    if (!(url instanceof URL) || url.href !== 'https://nodejs.org/dist/index.json') { reject(failure()); return; }
    const request = https.get(url, { headers: { accept: 'application/json', 'user-agent': 'claudex-node-lane-check/1' } }, (response) => {
      if (response.statusCode !== 200 || response.headers.location) { response.resume(); reject(failure()); return; }
      const declared = response.headers['content-length'];
      if (declared !== undefined && (!/^\d+$/u.test(declared) || Number(declared) > MAX_INDEX_BYTES)) {
        response.destroy(); reject(failure()); return;
      }
      const chunks = []; let total = 0;
      response.on('data', (chunk) => {
        total += chunk.length;
        if (total > MAX_INDEX_BYTES) response.destroy(failure()); else chunks.push(chunk);
      });
      response.on('end', () => resolve(Buffer.concat(chunks)));
      response.on('error', () => reject(failure()));
    });
    request.setTimeout(15_000, () => request.destroy(failure()));
    request.on('error', () => reject(failure()));
  });
}

async function stdin() {
  const chunks = []; let total = 0;
  for await (const chunk of process.stdin) {
    total += chunk.length; if (total > MAX_INDEX_BYTES) throw failure(); chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

async function main(argv) {
  const lanes = validateNodeLanes(JSON.parse((await readRegular(DEFAULT_LANES, 4096)).toString('utf8')));
  if (argv.length === 2 && argv[0] === '--validate') {
    const candidate = path.resolve(argv[1]);
    if (candidate !== DEFAULT_LANES) validateNodeLanes(JSON.parse((await readRegular(candidate, 4096)).toString('utf8')));
    process.stdout.write('node lanes: valid\n'); return;
  }
  if (argv.length === 1 && argv[0] === '--index-stdin') {
    const current = compareNodeIndex(lanes, await stdin());
    process.stdout.write(`node lanes: current (lts ${current.lts}, current ${current.current})\n`); return;
  }
  if (argv.length === 2 && argv[0] === '--propose-index-stdin') {
    process.stdout.write(`${JSON.stringify(proposeNodeLanes(lanes, await stdin(), argv[1]), null, 2)}\n`); return;
  }
  if (argv.length === 1 && argv[0] === '--online') {
    const current = compareNodeIndex(lanes, await downloadIndex(new URL(lanes.source)));
    process.stdout.write(`node lanes: current (lts ${current.lts}, current ${current.current})\n`); return;
  }
  throw failure();
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main(process.argv.slice(2)).catch(() => {
    process.stderr.write('error[NODE_LANES_STALE]: The configured Node release lanes are stale or invalid.\n');
    process.exitCode = 1;
  });
}
