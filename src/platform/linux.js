import { ClaudexError } from '../core/errors.js';

function unsupported(message) {
  return new ClaudexError('PLATFORM_UNSUPPORTED', message);
}

function parseVersion(value) {
  if (typeof value !== 'string' || !/^\d+(?:\.\d+)*$/.test(value)) return undefined;
  return value.split('.').map((segment) => Number(segment));
}

function atLeast(actual, minimum) {
  for (let index = 0; index < minimum.length; index += 1) {
    const current = actual[index] ?? 0;
    if (current !== minimum[index]) return current > minimum[index];
  }
  return true;
}

function detectWsl(input) {
  const markers = `${input?.kernelRelease ?? ''}\n${input?.procVersion ?? ''}`.toLowerCase();
  if (!markers.includes('microsoft')) return { isWsl: false };
  return { isWsl: true, wslVersion: markers.includes('wsl2') ? 2 : 1 };
}

export function parseOsRelease(text) {
  const parsed = {};
  if (typeof text !== 'string') return parsed;
  for (const line of text.split(/\r?\n/u)) {
    const match = /^([A-Z][A-Z0-9_]*)=(.*)$/u.exec(line);
    if (!match) continue;
    const [, key, rawValue] = match;
    const quoted = /^("|')(.*)\1$/u.exec(rawValue);
    parsed[key] = quoted ? quoted[2] : rawValue;
  }
  return parsed;
}

export const family = 'linux';

export function detectLinux(input) {
  const distribution = typeof input?.osRelease?.ID === 'string' ? input.osRelease.ID.toLowerCase() : undefined;
  const version = typeof input?.osRelease?.VERSION_ID === 'string' ? input.osRelease.VERSION_ID : undefined;
  const parsedVersion = parseVersion(version);
  const glibcVersion = input?.processReport?.header?.glibcVersionRuntime;
  if (typeof glibcVersion !== 'string' || glibcVersion.length === 0) {
    throw unsupported('Only glibc-based Linux distributions are supported.');
  }
  if (!parsedVersion) throw unsupported('Structured Linux distribution metadata is required.');
  if (distribution === 'ubuntu') {
    if (parsedVersion.length < 2 || !atLeast(parsedVersion, [20, 4])) {
      throw unsupported('Ubuntu 20.04 or newer is required.');
    }
  } else if (distribution === 'debian') {
    if (!atLeast(parsedVersion, [10])) throw unsupported('Debian 10 or newer is required.');
  } else {
    throw unsupported('Only Ubuntu and Debian Linux distributions are supported.');
  }
  return { family, ...detectWsl(input), distribution, version, libc: 'glibc' };
}
