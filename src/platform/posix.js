import fs from 'node:fs/promises';

import { ClaudeyError } from '../core/errors.js';
import { lstatNoFollow } from '../core/fs-safe.js';

function safetyRefusal(message) {
  return new ClaudeyError('SAFETY_REFUSAL', message);
}

export async function assertPosixProtection({ target, type, mode }, { lstat = fs.lstat } = {}) {
  const entry = await lstatNoFollow(target, { lstat });
  const correctType = type === 'file' ? entry.isFile?.() : entry.isDirectory?.();
  if (!correctType || (entry.mode & 0o777) !== mode) {
    throw safetyRefusal('Managed POSIX path does not have the required protected type and mode.');
  }
  return { target, type, mode };
}
