import fs from 'node:fs/promises';
import path from 'node:path';

import { ClaudeyError } from './errors.js';

function safetyRefusal(message) {
  return new ClaudeyError('SAFETY_REFUSAL', message);
}

function pathApiFor(platform) {
  return platform === 'win32' ? path.win32 : path.posix;
}

function equivalentPath(left, right, platform) {
  if (platform === 'win32') return left.toLowerCase() === right.toLowerCase();
  return left === right;
}

function normalizedAbsolute(value, { platform, pathApi = pathApiFor(platform) }) {
  if (typeof value !== 'string' || value.length === 0 || /[\0\r\n]/.test(value) || !pathApi.isAbsolute(value)) {
    throw safetyRefusal('Managed path must be an absolute safe path.');
  }
  return pathApi.normalize(value);
}

function pathIsContained(root, target, { platform, pathApi = pathApiFor(platform) }) {
  const relative = pathApi.relative(root, target);
  return relative !== '' && relative !== '..' && !relative.startsWith(`..${pathApi.sep}`) && !pathApi.isAbsolute(relative);
}

function pathSegments(child, platform) {
  return child.split(platform === 'win32' ? /[\\/]+/ : /\/+?/).filter(Boolean);
}

export function assertRelativeManagedChild(child, { platform = process.platform } = {}) {
  if (typeof child !== 'string' || child.length === 0 || /[\0\r\n]/.test(child)) {
    throw safetyRefusal('Managed child path must be a non-empty relative path.');
  }
  const pathApi = pathApiFor(platform);
  if (pathApi.isAbsolute(child) || (platform === 'win32' && (/^[a-zA-Z]:/.test(child) || /^\\\\[?.]?\\/.test(child) || child.includes(':')))) {
    throw safetyRefusal('Managed child path must not be absolute or drive-qualified.');
  }
  const segments = pathSegments(child, platform);
  if (segments.length === 0 || segments.some((segment) => segment === '.' || segment === '..')) {
    throw safetyRefusal('Managed child path must not traverse parent paths.');
  }
  return child;
}

export function resolveManagedChild(root, child, { platform = process.platform } = {}) {
  const pathApi = pathApiFor(platform);
  const canonicalRoot = normalizedAbsolute(root, { platform, pathApi });
  assertRelativeManagedChild(child, { platform });
  const target = pathApi.resolve(canonicalRoot, child);
  if (!pathIsContained(canonicalRoot, target, { platform, pathApi })) {
    throw safetyRefusal('Managed child path escapes its declared root.');
  }
  return target;
}

export function assertManagedRoot(root, {
  platform = process.platform,
  expectedRoot,
  homeRoot,
  repositoryRoot,
  isLink = false,
  isReparsePoint = false
} = {}) {
  const pathApi = pathApiFor(platform);
  const canonicalRoot = normalizedAbsolute(root, { platform, pathApi });
  const filesystemRoot = pathApi.parse(canonicalRoot).root;
  if (equivalentPath(canonicalRoot, filesystemRoot, platform)
    || (homeRoot && equivalentPath(canonicalRoot, normalizedAbsolute(homeRoot, { platform, pathApi }), platform))
    || (repositoryRoot && equivalentPath(canonicalRoot, normalizedAbsolute(repositoryRoot, { platform, pathApi }), platform))
    || (expectedRoot && !equivalentPath(canonicalRoot, normalizedAbsolute(expectedRoot, { platform, pathApi }), platform))
    || isLink || isReparsePoint) {
    throw safetyRefusal('Managed root is not eligible for mutation.');
  }
  return canonicalRoot;
}

export async function canonicalize(target, { platform = process.platform, realpath = fs.realpath } = {}) {
  const pathApi = pathApiFor(platform);
  const resolved = normalizedAbsolute(target, { platform, pathApi });
  const canonical = await realpath(resolved);
  return pathApi.normalize(canonical);
}

export async function lstatNoFollow(target, { lstat = fs.lstat } = {}) {
  const entry = await lstat(target);
  if (entry?.isSymbolicLink?.() || entry?.isReparsePoint === true) {
    throw safetyRefusal('Managed path must not resolve through a link or reparse point.');
  }
  return entry;
}

function missingPath(error) {
  return error?.code === 'ENOENT';
}

export async function assertContainedNoLinks({ root, child, platform = process.platform }, {
  canonicalize: canonicalizePath = canonicalize,
  lstat = fs.lstat
} = {}) {
  const pathApi = pathApiFor(platform);
  const declaredRoot = assertManagedRoot(root, { platform });
  const canonicalRoot = await canonicalizePath(declaredRoot, { platform });
  if (!equivalentPath(declaredRoot, canonicalRoot, platform)) {
    throw safetyRefusal('Managed root canonical path changed or resolves through a link.');
  }
  const target = resolveManagedChild(canonicalRoot, child, { platform });
  const segments = pathApi.relative(canonicalRoot, target).split(pathApi.sep);
  let current = canonicalRoot;
  for (const segment of ['', ...segments]) {
    if (segment) current = pathApi.join(current, segment);
    try {
      await lstatNoFollow(current, { lstat });
    } catch (error) {
      if (missingPath(error)) return target;
      throw error;
    }
  }
  return target;
}
