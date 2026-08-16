import { randomBytes as nodeRandomBytes } from 'node:crypto';
import * as nodeFs from 'node:fs/promises';
import * as nodePath from 'node:path';

import { createSha256Verifier, parseChecksumManifest } from './checksum.js';
import { ClaudeyError } from './errors.js';
import { LIMITS } from './limits.js';
import { resolveReleaseAsset as resolvePlatformAsset } from '../platform/asset-map.js';

const API_ORIGIN = 'https://api.github.com';
const RELEASE_ORIGIN = 'https://github.com/router-for-me/CLIProxyAPI/releases/download';
const API_HOSTS = new Set(['api.github.com']);
const DOWNLOAD_HOSTS = new Set(['github.com', 'objects.githubusercontent.com', 'release-assets.githubusercontent.com']);
const CHECKSUM_NAMES = new Set(['checksums.txt', 'checksums.sha256', 'sha256sums', 'sha256sum', 'sha256sums.txt', 'sha256sum.txt']);

export const RELEASE_LIMITS = Object.freeze({
  maxRedirects: 5,
  maxReleasePages: 10,
  metadataDeadlineMs: 30_000,
  downloadDeadlineMs: 120_000,
  checksumBytes: 1_048_576,
  partNameAttempts: 3
});

const BASELINE = Object.freeze([7, 2, 130]);

function error(code, message, details = {}) {
  return new ClaudeyError(code, message, { details });
}

function safeUrl(url) {
  try {
    const parsed = new URL(url);
    return `${parsed.origin}${parsed.pathname}`;
  } catch {
    return '<invalid-url>';
  }
}

function networkFailure(message, url) {
  return error('NETWORK_FAILURE', message, url ? { url: safeUrl(url) } : {});
}

function isClaudeyError(value) {
  return value instanceof ClaudeyError;
}

function parseVersion(value, { code = 'USAGE_ERROR' } = {}) {
  if (typeof value !== 'string') throw error(code, 'Release version must be a semantic version.');
  const match = /^(?:v)?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.exec(value);
  if (!match) throw error(code, 'Release version must be a stable semantic version.');
  return match.slice(1).map(Number);
}

function versionText(parts) {
  return parts.join('.');
}

function compareVersions(left, right) {
  for (let index = 0; index < 3; index += 1) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return 0;
}

function normalizeRequestedVersion(value) {
  const parts = parseVersion(value);
  if (compareVersions(parts, BASELINE) < 0) {
    throw error('PREREQUISITE_MISSING', `CLIProxyAPI ${versionText(parts)} is older than the supported baseline.`);
  }
  const version = versionText(parts);
  return { version, tag: `v${version}`, parts };
}

function headerValue(headers, name) {
  if (!headers) return undefined;
  if (typeof headers.get === 'function') return headers.get(name) ?? headers.get(name.toLowerCase()) ?? undefined;
  const target = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === target) return Array.isArray(value) ? value[0] : value;
  }
  return undefined;
}

function allowedHostsFor(purpose) {
  if (purpose === 'metadata') return API_HOSTS;
  if (purpose === 'download') return DOWNLOAD_HOSTS;
  throw error('USAGE_ERROR', 'Release request purpose is invalid.');
}

function validateOfficialUrl(rawUrl, purpose) {
  if (typeof rawUrl !== 'string') throw networkFailure('Release URL is invalid.');
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw networkFailure('Release URL is invalid.');
  }
  if (
    parsed.protocol !== 'https:' ||
    parsed.username ||
    parsed.password ||
    parsed.hash ||
    (parsed.port && parsed.port !== '443') ||
    parsed.hostname.startsWith('xn--') ||
    !allowedHostsFor(purpose).has(parsed.hostname.toLowerCase())
  ) {
    throw networkFailure('Release URL is not an approved official HTTPS endpoint.', rawUrl);
  }
  return parsed;
}

function createRequestContext(parentSignal, deadlineMs) {
  if (!Number.isSafeInteger(deadlineMs) || deadlineMs <= 0) throw error('USAGE_ERROR', 'Release request deadline is invalid.');
  const controller = new AbortController();
  let timer;
  let parentAbort;
  const abort = () => controller.abort();
  if (parentSignal) {
    parentAbort = () => controller.abort();
    if (parentSignal.aborted) controller.abort();
    else parentSignal.addEventListener('abort', parentAbort, { once: true });
  }
  timer = setTimeout(abort, deadlineMs);
  timer.unref?.();
  return {
    signal: controller.signal,
    abort,
    finish() {
      clearTimeout(timer);
      if (parentSignal && parentAbort) parentSignal.removeEventListener('abort', parentAbort);
    }
  };
}

function attachRequestContext(response, context) {
  Object.defineProperties(response, {
    __claudeyAbort: { value: context.abort, enumerable: false },
    __claudeyFinish: { value: context.finish, enumerable: false },
    __claudeySignal: { value: context.signal, enumerable: false }
  });
  return response;
}

function finishResponse(response) {
  response?.__claudeyFinish?.();
}

function abortResponse(response) {
  response?.__claudeyAbort?.();
  finishResponse(response);
}

export async function fetchOfficialResponse({ http, url, purpose, deadlineMs, signal, maxRedirects = RELEASE_LIMITS.maxRedirects }) {
  if (!http || typeof http.get !== 'function') throw error('USAGE_ERROR', 'A release HTTP client is required.');
  if (!Number.isSafeInteger(maxRedirects) || maxRedirects < 0) throw error('USAGE_ERROR', 'Release redirect limit is invalid.');
  if (signal?.aborted) throw networkFailure('Release request was aborted.');

  let current = validateOfficialUrl(url, purpose).href;
  const seen = new Set();
  for (let redirects = 0; ; redirects += 1) {
    if (seen.has(current)) throw networkFailure('Release redirect cycle was rejected.', current);
    seen.add(current);
    const context = createRequestContext(signal, deadlineMs);
    let response;
    try {
      response = await http.get(current, { signal: context.signal, deadlineMs });
    } catch (cause) {
      context.finish();
      throw networkFailure('Release request failed.', current);
    }
    if (context.signal.aborted) {
      context.finish();
      throw networkFailure('Release request was aborted.', current);
    }
    if (!response || !Number.isInteger(response.status)) {
      context.finish();
      throw networkFailure('Release response was malformed.', current);
    }
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = headerValue(response.headers, 'location');
      context.abort();
      context.finish();
      if (redirects >= maxRedirects || typeof location !== 'string' || !/^https:\/\//i.test(location)) {
        throw networkFailure('Release redirect was rejected.', current);
      }
      current = validateOfficialUrl(location, purpose).href;
      continue;
    }
    if (response.status !== 200) {
      context.abort();
      context.finish();
      throw networkFailure('Release endpoint returned an unexpected status.', current);
    }
    return attachRequestContext(response, context);
  }
}

async function* chunksFrom(body) {
  if (body === undefined || body === null) return;
  if (typeof body[Symbol.asyncIterator] === 'function') {
    yield* body;
    return;
  }
  if (typeof body[Symbol.iterator] === 'function' && typeof body !== 'string') {
    yield* body;
    return;
  }
  throw networkFailure('Release response body was malformed.');
}

function parseContentLength(response) {
  const raw = headerValue(response.headers, 'content-length');
  if (raw === undefined) return undefined;
  if (typeof raw !== 'string' || !/^(0|[1-9]\d*)$/.test(raw)) throw networkFailure('Release content length was malformed.');
  const value = Number(raw);
  if (!Number.isSafeInteger(value)) throw networkFailure('Release content length was malformed.');
  return value;
}

export async function readResponseBytes(response, { limit, signal } = {}) {
  if (!Number.isSafeInteger(limit) || limit < 0) throw error('USAGE_ERROR', 'Release byte limit is invalid.');
  if (!response || response.status !== 200) throw networkFailure('Release response was malformed.');
  const expectedLength = parseContentLength(response);
  if (expectedLength !== undefined && expectedLength > limit) {
    abortResponse(response);
    throw networkFailure('Release response exceeded the allowed byte limit.');
  }
  const buffers = [];
  let total = 0;
  try {
    for await (const value of chunksFrom(response.body)) {
      if (signal?.aborted || response.__claudeySignal?.aborted) throw networkFailure('Release request was aborted.');
      const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
      if (total > limit - chunk.length) throw networkFailure('Release response exceeded the allowed byte limit.');
      total += chunk.length;
      buffers.push(chunk);
    }
    if (expectedLength !== undefined && total !== expectedLength) throw networkFailure('Release response ended at an unexpected length.');
    return Buffer.concat(buffers, total);
  } catch (cause) {
    abortResponse(response);
    if (isClaudeyError(cause)) throw cause;
    throw networkFailure('Release response stream failed.');
  } finally {
    finishResponse(response);
  }
}

export async function readResponseText(response, { limit, signal } = {}) {
  const bytes = await readResponseBytes(response, { limit, signal });
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw networkFailure('Release response was not valid UTF-8.');
  }
}

async function fetchJson({ http, url, purpose, deadlineMs, signal }) {
  const response = await fetchOfficialResponse({ http, url, purpose, deadlineMs, signal });
  const text = await readResponseText(response, { limit: RELEASE_LIMITS.checksumBytes, signal });
  try {
    return JSON.parse(text);
  } catch {
    throw networkFailure('Release metadata was not valid JSON.', url);
  }
}

function releaseMetadataUrl(tag) {
  return `${API_ORIGIN}/repos/router-for-me/CLIProxyAPI/releases/tags/${tag}`;
}

function releaseListUrl(page) {
  return `${API_ORIGIN}/repos/router-for-me/CLIProxyAPI/releases?per_page=100&page=${page}`;
}

function parseNextLink(headers) {
  const link = headerValue(headers, 'link');
  if (!link) return undefined;
  const match = /<([^>]+)>\s*;\s*rel="next"/i.exec(link);
  return match?.[1];
}

function assertReleaseRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || typeof value.tag_name !== 'string' || typeof value.draft !== 'boolean' || typeof value.prerelease !== 'boolean' || !Array.isArray(value.assets)) {
    throw networkFailure('Release metadata was malformed.');
  }
  return value;
}

function stableVersionFor(record) {
  if (record.draft || record.prerelease) return undefined;
  try {
    return parseVersion(record.tag_name, { code: 'NETWORK_FAILURE' });
  } catch {
    throw networkFailure('Stable release metadata had an invalid tag.');
  }
}

function isAllowedChecksumName(name) {
  return typeof name === 'string' && CHECKSUM_NAMES.has(name.toLowerCase());
}

function expectedAssetUrl(tag, name) {
  return `${RELEASE_ORIGIN}/${tag}/${name}`;
}

function mediaType(contentType) {
  const value = typeof contentType === 'string' ? contentType.toLowerCase() : '';
  return value.split(';')[0].trim();
}

function allowedContentType(kind, contentType) {
  const value = mediaType(contentType);
  if (kind === 'zip') return ['application/zip', 'application/x-zip-compressed', 'application/octet-stream'].includes(value);
  return ['application/gzip', 'application/x-gzip', 'application/octet-stream'].includes(value);
}

function allowedChecksumContentType(contentType) {
  return ['text/plain', 'text/x-shellscript', 'application/octet-stream'].includes(mediaType(contentType));
}

function validateAsset(asset, { tag, expectedName, kind, checksum = false }) {
  if (!asset || typeof asset !== 'object' || Array.isArray(asset) || typeof asset.name !== 'string' || typeof asset.browser_download_url !== 'string' || !Number.isSafeInteger(asset.size) || asset.size < 0) {
    throw networkFailure('Release asset metadata was malformed.');
  }
  if (checksum ? !isAllowedChecksumName(asset.name) : asset.name !== expectedName) {
    throw networkFailure('Release asset name was invalid.');
  }
  if (asset.size > (checksum ? RELEASE_LIMITS.checksumBytes : LIMITS.archiveBytes)) {
    throw networkFailure('Release asset metadata exceeded the allowed byte limit.');
  }
  const parsed = validateOfficialUrl(asset.browser_download_url, 'download');
  if (parsed.search || parsed.pathname !== `/router-for-me/CLIProxyAPI/releases/download/${tag}/${asset.name}`) {
    throw networkFailure('Release asset URL was not canonical.', asset.browser_download_url);
  }
  if (!checksum && !allowedContentType(kind, asset.content_type)) {
    throw networkFailure('Release asset content type was invalid.', asset.browser_download_url);
  }
  if (checksum && !allowedChecksumContentType(asset.content_type)) {
    throw networkFailure('Release checksum asset content type was invalid.', asset.browser_download_url);
  }
  return Object.freeze({
    name: asset.name,
    url: expectedAssetUrl(tag, asset.name),
    size: asset.size,
    contentType: asset.content_type,
    ...(checksum ? { kind: 'checksum' } : { kind })
  });
}

function describeRelease(record, requested, platform) {
  const parts = parseVersion(record.tag_name, { code: 'NETWORK_FAILURE' });
  const version = versionText(parts);
  const tag = `v${version}`;
  if (record.tag_name !== tag || compareVersions(parts, BASELINE) < 0 || (requested && tag !== requested.tag)) {
    throw networkFailure('Release metadata did not match the requested stable version.');
  }
  const asset = platform ? resolveReleaseAsset({ version, platform }) : undefined;
  const matchingArchiveAssets = asset ? record.assets.filter((candidate) => {
    if (typeof candidate?.name !== 'string') return false;
    const archiveStem = asset.name.slice(0, -(asset.kind.length + 1));
    return candidate.name === asset.name || candidate.name.startsWith(archiveStem);
  }) : [];
  if (asset && (matchingArchiveAssets.length !== 1 || matchingArchiveAssets[0].name !== asset.name)) {
    throw networkFailure('Release did not contain exactly one required platform asset.');
  }
  const checksumAssets = record.assets.filter((candidate) => isAllowedChecksumName(candidate?.name));
  if (checksumAssets.length !== 1) throw networkFailure('Release did not contain exactly one supported checksum asset.');
  return Object.freeze({
    version,
    tag,
    asset: asset ? Object.freeze({ ...asset, ...validateAsset(matchingArchiveAssets[0], { tag, expectedName: asset.name, kind: asset.kind }) }) : undefined,
    checksumAsset: validateAsset(checksumAssets[0], { tag, checksum: true })
  });
}

export function resolveReleaseAsset({ version, platform }) {
  const normalized = normalizeRequestedVersion(version);
  const mapped = resolvePlatformAsset({
    version: normalized.version,
    platform: {
      runtimePlatform: platform?.runtimePlatform ?? platform?.platform ?? platform?.nodePlatform,
      runtimeArch: platform?.runtimeArch ?? platform?.arch
    }
  });
  return Object.freeze({
    version: normalized.version,
    tag: normalized.tag,
    name: mapped.archiveName,
    url: expectedAssetUrl(normalized.tag, mapped.archiveName),
    kind: mapped.archiveKind,
    platform
  });
}

export async function resolveRelease({ requestedVersion, platform, http, signal }) {
  if (requestedVersion !== undefined) {
    const requested = normalizeRequestedVersion(requestedVersion);
    const record = assertReleaseRecord(await fetchJson({
      http,
      url: releaseMetadataUrl(requested.tag),
      purpose: 'metadata',
      deadlineMs: RELEASE_LIMITS.metadataDeadlineMs,
      signal
    }));
    if (record.draft || record.prerelease) throw networkFailure('Requested release is not a stable published release.');
    return describeRelease(record, requested, platform);
  }

  let next = releaseListUrl(1);
  const stable = [];
  const seenVersions = new Set();
  for (let page = 0; next; page += 1) {
    if (page >= RELEASE_LIMITS.maxReleasePages) throw networkFailure('Release metadata paging exceeded the allowed limit.');
    const response = await fetchOfficialResponse({
      http,
      url: next,
      purpose: 'metadata',
      deadlineMs: RELEASE_LIMITS.metadataDeadlineMs,
      signal
    });
    const nextLink = parseNextLink(response.headers);
    const text = await readResponseText(response, { limit: RELEASE_LIMITS.checksumBytes, signal });
    let records;
    try {
      records = JSON.parse(text);
    } catch {
      throw networkFailure('Release metadata was not valid JSON.', next);
    }
    if (!Array.isArray(records)) throw networkFailure('Release metadata list was malformed.', next);
    for (const rawRecord of records) {
      const record = assertReleaseRecord(rawRecord);
      const parts = stableVersionFor(record);
      if (!parts) continue;
      const version = versionText(parts);
      if (seenVersions.has(version)) throw networkFailure('Release metadata contained duplicate stable versions.');
      seenVersions.add(version);
      if (compareVersions(parts, BASELINE) >= 0) stable.push({ record, parts });
    }
    next = nextLink;
  }
  if (stable.length === 0) throw networkFailure('No supported stable CLIProxyAPI release was found.');
  stable.sort((left, right) => compareVersions(right.parts, left.parts));
  return describeRelease(stable[0].record, undefined, platform);
}

function assertArchiveBasename(name) {
  if (
    typeof name !== 'string' ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(name) ||
    name === '.' ||
    name === '..' ||
    name.includes('..') ||
    name.startsWith('-') ||
    /[\\/:]/.test(name)
  ) {
    throw error('USAGE_ERROR', 'Release archive filename is invalid.');
  }
  return name;
}

function assertDownloadAssetDescriptor(asset, { tag, version, checksum = false }) {
  if (!asset || typeof asset !== 'object' || Array.isArray(asset)) {
    throw error('USAGE_ERROR', 'Release asset descriptor is invalid.');
  }
  const name = assertArchiveBasename(asset.name);
  if (!Number.isSafeInteger(asset.size) || asset.size < 0) {
    throw error('USAGE_ERROR', 'Release asset size is invalid.');
  }
  if (checksum ? !isAllowedChecksumName(name) : !asset.platform) {
    throw error('USAGE_ERROR', 'Release asset descriptor is incomplete.');
  }
  if (asset.size > (checksum ? RELEASE_LIMITS.checksumBytes : LIMITS.archiveBytes)) {
    throw networkFailure('Release asset metadata exceeded the allowed byte limit.');
  }
  if (!checksum) {
    const expected = resolveReleaseAsset({ version, platform: asset.platform });
    if (asset.name !== expected.name || asset.kind !== expected.kind) {
      throw error('USAGE_ERROR', 'Release archive descriptor did not match its platform.');
    }
  }
  const parsed = validateOfficialUrl(asset.url, 'download');
  const expectedUrl = expectedAssetUrl(tag, name);
  if (parsed.href !== expectedUrl) {
    throw networkFailure('Release download did not start from its canonical official URL.', asset.url);
  }
  return Object.freeze({
    ...asset,
    name,
    url: parsed.href,
    size: asset.size
  });
}

function assertDownloadRelease(release, asset) {
  if (!release || typeof release !== 'object' || Array.isArray(release)) {
    throw error('USAGE_ERROR', 'Release descriptor is invalid.');
  }
  const normalized = normalizeRequestedVersion(release.version);
  if (release.tag !== normalized.tag) {
    throw error('USAGE_ERROR', 'Release descriptor tag did not match its version.');
  }
  const selected = assertDownloadAssetDescriptor(asset, { tag: normalized.tag, version: normalized.version });
  if (release.asset && (release.asset.name !== selected.name || release.asset.url !== selected.url)) {
    throw error('USAGE_ERROR', 'Selected release asset did not match the release descriptor.');
  }
  const checksumAsset = assertDownloadAssetDescriptor(release.checksumAsset, {
    tag: normalized.tag,
    version: normalized.version,
    checksum: true
  });
  return { selected, checksumAsset };
}

function archiveByteLimit(limits) {
  const requested = limits?.archiveBytes;
  if (requested === undefined) return LIMITS.archiveBytes;
  if (!Number.isSafeInteger(requested) || requested <= 0) {
    throw error('USAGE_ERROR', 'Release archive byte limit is invalid.');
  }
  return Math.min(requested, LIMITS.archiveBytes);
}

function downloadDeadline(deps) {
  const deadlineMs = deps?.downloadDeadlineMs ?? RELEASE_LIMITS.downloadDeadlineMs;
  if (!Number.isSafeInteger(deadlineMs) || deadlineMs <= 0) {
    throw error('USAGE_ERROR', 'Release download deadline is invalid.');
  }
  return deadlineMs;
}

function createPartPath(stagingRoot, archiveName, randomBytes) {
  const value = randomBytes(12);
  const bytes = Buffer.isBuffer(value) ? value : value instanceof Uint8Array ? Buffer.from(value) : undefined;
  if (!bytes || bytes.length < 12) throw error('NETWORK_FAILURE', 'Release staging nonce generation failed.');
  return nodePath.join(stagingRoot, `.${archiveName}.${bytes.toString('hex')}.part`);
}

async function removeOwnedPart(fs, partPath) {
  if (!partPath) return;
  try {
    await fs.rm(partPath, { force: true });
  } catch {
    // The primary failure is more useful than a best-effort cleanup failure.
  }
}

async function writeFully(handle, chunk) {
  let offset = 0;
  while (offset < chunk.length) {
    const result = await handle.write(chunk, offset, chunk.length - offset, null);
    const written = typeof result === 'number' ? result : result?.bytesWritten;
    if (!Number.isSafeInteger(written) || written <= 0 || written > chunk.length - offset) {
      throw networkFailure('Release staging write failed.');
    }
    offset += written;
  }
}

async function streamVerifiedArchive(response, { handle, expectedDigest, asset, limit, signal }) {
  const declaredLength = parseContentLength(response);
  if (declaredLength !== undefined && (declaredLength > limit || declaredLength !== asset.size)) {
    throw networkFailure('Release archive length did not match its accepted metadata.');
  }
  const verifier = createSha256Verifier(expectedDigest, asset.name);
  let total = 0;
  try {
    for await (const value of chunksFrom(response.body)) {
      if (signal?.aborted || response.__claudeySignal?.aborted) {
        throw networkFailure('Release archive download was aborted.');
      }
      const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
      if (total > limit - chunk.length || total > asset.size - chunk.length) {
        throw networkFailure('Release archive exceeded its accepted byte limit.');
      }
      await writeFully(handle, chunk);
      verifier.update(chunk);
      total += chunk.length;
    }
    if (total !== asset.size || (declaredLength !== undefined && total !== declaredLength)) {
      throw networkFailure('Release archive ended at an unexpected length.');
    }
    return verifier.finish();
  } catch (cause) {
    abortResponse(response);
    if (isClaudeyError(cause)) throw cause;
    throw networkFailure('Release archive stream failed.');
  } finally {
    finishResponse(response);
  }
}

/**
 * Download an archive only after its checksum artifact parsed successfully.
 * This routine never extracts, executes, or otherwise consumes the archive.
 */
export async function downloadVerifiedRelease(release, asset, stagingRoot, deps = {}) {
  const { selected, checksumAsset } = assertDownloadRelease(release, asset);
  if (typeof stagingRoot !== 'string' || !nodePath.isAbsolute(stagingRoot)) {
    throw error('USAGE_ERROR', 'Release staging root must be an absolute path.');
  }
  if (!deps.http || typeof deps.http.get !== 'function') {
    throw error('USAGE_ERROR', 'A release HTTP client is required.');
  }

  const fs = deps.fs ?? nodeFs;
  const randomBytes = deps.randomBytes ?? nodeRandomBytes;
  const root = nodePath.resolve(stagingRoot);
  const limit = archiveByteLimit(deps.limits);
  const deadlineMs = downloadDeadline(deps);

  const checksumResponse = await fetchOfficialResponse({
    http: deps.http,
    url: checksumAsset.url,
    purpose: 'download',
    deadlineMs: RELEASE_LIMITS.metadataDeadlineMs,
    signal: deps.signal
  });
  const checksumText = await readResponseText(checksumResponse, {
    limit: RELEASE_LIMITS.checksumBytes,
    signal: deps.signal
  });
  const expectedDigest = parseChecksumManifest(checksumText, selected.name);

  let partPath;
  let handle;
  let response;
  let promoted = false;
  try {
    await fs.mkdir(root, { recursive: true, mode: 0o700 });
    for (let attempt = 0; attempt < RELEASE_LIMITS.partNameAttempts; attempt += 1) {
      partPath = createPartPath(root, selected.name, randomBytes);
      try {
        handle = await fs.open(partPath, 'wx', 0o600);
        break;
      } catch (cause) {
        if (cause?.code !== 'EEXIST' || attempt === RELEASE_LIMITS.partNameAttempts - 1) {
          throw networkFailure('Release staging file could not be created.');
        }
      }
    }

    response = await fetchOfficialResponse({
      http: deps.http,
      url: selected.url,
      purpose: 'download',
      deadlineMs,
      signal: deps.signal
    });
    const verified = await streamVerifiedArchive(response, {
      handle,
      expectedDigest,
      asset: selected,
      limit,
      signal: deps.signal
    });
    await handle.sync?.();
    await handle.close();
    handle = undefined;
    const target = nodePath.join(root, selected.name);
    await fs.rename(partPath, target);
    promoted = true;
    return Object.freeze({
      path: target,
      name: selected.name,
      bytes: verified.bytes,
      sha256: verified.sha256,
      kind: selected.kind
    });
  } catch (cause) {
    if (response) abortResponse(response);
    if (isClaudeyError(cause)) throw cause;
    throw networkFailure('Release archive download failed.');
  } finally {
    if (handle) {
      try {
        await handle.close();
      } catch {
        // Best effort only; owned part cleanup follows.
      }
    }
    if (!promoted) await removeOwnedPart(fs, partPath);
  }
}
