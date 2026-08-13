import assert from 'node:assert/strict';
import test from 'node:test';

import { resolveVerifiedExecutable, revalidateExecutable } from '../../../src/core/executable.js';

const CLAUDE_EXE = 'C:\\Tools\\Claude\\claude.exe';
const NODE_EXE = 'C:\\Users\\person\\AppData\\Roaming\\npm\\node.exe';
const CLAUDE_ENTRY = 'C:\\Users\\person\\AppData\\Roaming\\npm\\node_modules\\@anthropic-ai\\claude-code\\cli.js';

function native(path = CLAUDE_EXE) {
  return { path, canonicalPath: path, type: 'native', isLink: false };
}


function checked(input) {
  return resolveVerifiedExecutable({ ...input, adapter: { inspect: (path) => input.candidates.find((candidate) => candidate.path === path) } });
}

function npmShim(overrides = {}) {
  return {
    path: 'C:\\Users\\person\\AppData\\Roaming\\npm\\claude.cmd',
    canonicalPath: 'C:\\Users\\person\\AppData\\Roaming\\npm\\claude.cmd',
    type: 'npm-shim',
    isLink: false,
    node: { path: NODE_EXE, canonicalPath: NODE_EXE, type: 'native', isLink: false },
    entryPath: CLAUDE_ENTRY,
    script: '@ECHO off\r\n"%~dp0\\node.exe" "%~dp0\\node_modules\\@anthropic-ai\\claude-code\\cli.js" %*\r\n',
    ...overrides
  };
}

test('prefers one verified native Windows executable and returns its canonical absolute identity', () => {
  const result = checked({ command: 'claude', platform: 'win32', candidates: [npmShim(), native()] });
  assert.deepEqual(result, { kind: 'native', executablePath: CLAUDE_EXE, argsPrefix: [], identity: CLAUDE_EXE });
});

test('structurally resolves only the known Claude npm shim into a verified Node entry point', () => {
  const result = checked({ command: 'claude', platform: 'win32', candidates: [npmShim()] });
  assert.deepEqual(result, {
    kind: 'node-entry', executablePath: NODE_EXE, argsPrefix: [CLAUDE_ENTRY], identity: `${NODE_EXE}\u0000${CLAUDE_ENTRY}`
  });
});

test('rejects hostile paths, reparse points, relative identities, ambiguous aliases, and identity swaps', () => {
  const unsafeCandidates = [
    native('claude.exe'),
    { ...native(), canonicalPath: 'C:\\Elsewhere\\claude.exe' },
    { ...native(), isLink: true },
    native('C:\\Tools\\Claude\\claude.exe '),
    [native(), native('C:\\Other\\claude.exe')]
  ];

  for (const candidates of unsafeCandidates) {
    assert.throws(
      () => checked({ command: 'claude', platform: 'win32', candidates: Array.isArray(candidates) ? candidates : [candidates] }),
      (error) => error.code === 'PREREQUISITE_MISSING'
    );
  }

  assert.throws(
    () => checked({ command: 'claude', platform: 'win32', candidates: [native()], expectedIdentity: 'C:\\Other\\claude.exe' }),
    (error) => error.code === 'PROCESS_IDENTITY_MISMATCH'
  );
});

test('rejects unknown command shims and npm shims with quoted extras, foreign entries, or a nonnative Node identity', () => {
  for (const candidate of [
    { ...native(), type: 'cmd' },
    { ...native(), type: 'bat' },
    { ...native(), type: 'ps1' },
    npmShim({ script: '@ECHO off\r\n"%~dp0\\node.exe" "%~dp0\\node_modules\\@anthropic-ai\\claude-code\\cli.js" --unsafe %*\r\n' }),
    npmShim({ entryPath: 'C:\\Users\\person\\AppData\\Roaming\\npm\\node_modules\\other\\cli.js' }),
    npmShim({ node: { path: 'node.exe', canonicalPath: 'node.exe', type: 'native', isLink: false } })
  ]) {
    assert.throws(
      () => checked({ command: 'claude', platform: 'win32', candidates: [candidate] }),
      (error) => error.code === 'PREREQUISITE_MISSING'
    );
  }
});

test('requires filesystem inspection rather than trusting a caller supplied native identity', () => {
  assert.throws(() => resolveVerifiedExecutable({ command: 'claude', platform: 'win32', candidates: [native()] }), (error) => error.code === 'PREREQUISITE_MISSING');
});

test('revalidates a bound native identity and refuses a leaf swap before spawn', () => {
  const records = new Map([['C:\\Tools\\Claude\\claude.exe', native()]]);
  const adapter = { inspect: (path) => records.get(path) };
  const resolved = checked({ command: 'claude', platform: 'win32', candidates: [native()], adapter });
  records.set(CLAUDE_EXE, { ...native(), stableId: 'swapped' });
  assert.equal(revalidateExecutable(resolved, adapter), false);
});