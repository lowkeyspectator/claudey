import { ClaudexError } from '../core/errors.js';

function unsupported(message) {
  return new ClaudexError('PLATFORM_UNSUPPORTED', message);
}

function isAtLeastWindows1809(version) {
  if (!version || !Number.isInteger(version.major) || !Number.isInteger(version.minor) || !Number.isInteger(version.build)) {
    return false;
  }
  if (version.major !== 10) return version.major > 10;
  if (version.minor !== 0) return version.minor > 0;
  return version.build >= 17763;
}

export const family = 'windows';

export function detectWindows(input) {
  if (!isAtLeastWindows1809(input?.windowsVersion)) {
    throw unsupported('Windows 10 version 1809 or newer is required.');
  }
  return { family };
}
