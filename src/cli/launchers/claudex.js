import { createHash } from 'node:crypto';
import path from 'node:path';

import { ClaudexError } from '../../core/errors.js';
import { parseLauncherArgs } from '../parse.js';
import { launchClaudeProvider } from '../../providers/claude.js';

const PROFILES = Object.freeze([
  Object.freeze({ child: 'claudexctl', args: Object.freeze([]) }),
  Object.freeze({ child: 'claudex', args: Object.freeze(['launcher', 'claudex']) }),
  Object.freeze({ child: 'claude-agy', args: Object.freeze(['launcher', 'claude-agy']) })
]);

function safety(message = 'Launcher staging could not be completed safely.') {
  return new ClaudexError('SAFETY_REFUSAL', message);
}

function safePosixPath(value) {
  return typeof value === 'string' && value.length > 1 && value.length <= 4096 && path.posix.isAbsolute(value)
    && !value.startsWith('//') && !/[\u0000-\u001f\u007f]/.test(value) && path.posix.normalize(value) === value;
}

function shellQuote(value) {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function renderLauncher(nodePath, managerPath, profileArgs) {
  const fixed = [nodePath, managerPath, ...profileArgs].map(shellQuote).join(' ');
  return Buffer.from(`#!/bin/sh\nexec ${fixed} "$@"\n`, 'utf8');
}

function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export async function runClaudex(argv, environment, context = {}) {
  const parsed = parseLauncherArgs(argv, environment);
  const launch = context.launch ?? launchClaudeProvider;
  if (typeof launch !== 'function') throw safety();
  return launch({ ...context, provider: 'codex', parsed });
}

export async function stageLaunchers({ platform, nodePath, managerPath, stageFile } = {}) {
  if (platform !== 'linux' && platform !== 'darwin') throw new ClaudexError('PLATFORM_UNSUPPORTED', 'POSIX launchers require Linux, WSL, or macOS.');
  if (!safePosixPath(nodePath) || !safePosixPath(managerPath) || typeof stageFile !== 'function') throw safety();
  const files = PROFILES.map(({ child, args }) => Object.freeze({
    child,
    mode: 0o755,
    bytes: renderLauncher(nodePath, managerPath, args)
  }));
  try {
    for (const file of files) {
      const request = Object.freeze({ child: file.child, mode: file.mode, bytes: Buffer.from(file.bytes) });
      const expected = digest(request.bytes);
      await stageFile(request);
      if (digest(request.bytes) !== expected) throw safety();
    }
  } catch { throw safety(); }
  return Object.freeze(files);
}
