import { ClaudeyError } from '../core/errors.js';

function unsupported(message) {
  return new ClaudeyError('PLATFORM_UNSUPPORTED', message);
}

function macMajor(version) {
  const match = typeof version === 'string' && /^(\d+)(?:\.\d+){0,2}$/.exec(version);
  return match ? Number(match[1]) : undefined;
}

export const family = 'macos';

export function detectMacos(input) {
  if ((macMajor(input?.macVersion) ?? 0) < 13) {
    throw unsupported('macOS 13 or newer is required.');
  }
  return { family };
}
