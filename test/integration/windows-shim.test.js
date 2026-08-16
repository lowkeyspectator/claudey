import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { buildWindowsCommandLine, quoteWindowsArgument } from '../../scripts/windows-command-line.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

test('portable Microsoft quoting preserves empty, whitespace, Unicode, quotes, slash runs, and hostile shell text', () => {
  const vectors = [
    ['', '""'], ['plain', 'plain'], ['two words', '"two words"'], ['雪', '雪'], ['"', '"\\\""'],
    ['a"b', '"a\\\"b"'], ['a\\"b', '"a\\\\\\\"b"'], ['a\\\\"b', '"a\\\\\\\\\\\"b"'],
    ['ends\\', 'ends\\'], ['ends slash \\', '"ends slash \\\\"'], ['--leading', '--leading'],
    [';&|`$()%VAR%', ';&|`$()%VAR%'], ['line\r\nbreak', '"line\r\nbreak"']
  ];
  for (const [value, expected] of vectors) assert.equal(quoteWindowsArgument(value), expected, JSON.stringify(value));
  assert.equal(buildWindowsCommandLine(['C:\\Program Files\\node.exe', 'C:\\manager\\index.mjs', '', '雪', 'a"b']),
    '"C:\\Program Files\\node.exe" C:\\manager\\index.mjs "" 雪 "a\\\"b"');
  assert.throws(() => quoteWindowsArgument('x\0y'), (error) => error.code === 'ARGUMENT_UNSAFE');
});

test('native shim sources enforce fixed profiles, authenticated metadata, wide CreateProcess, stdio, signals, and exact exit relay', async () => {
  const main = await fs.readFile(path.join(root, 'native/windows-shim/src/main.c'), 'utf8');
  const quote = await fs.readFile(path.join(root, 'native/windows-shim/src/quote.c'), 'utf8');
  const header = await fs.readFile(path.join(root, 'native/windows-shim/src/quote.h'), 'utf8');
  const cmake = await fs.readFile(path.join(root, 'native/windows-shim/CMakeLists.txt'), 'utf8');
  for (const token of ['claudeyctl.exe', 'claudexctl.exe', 'claude-codex.exe', 'claudex.exe', 'claude-agy.exe', 'claude-grok.exe', 'claudey.exe',
    'claudey-launcher.bin', 'claudey-launcher.key', 'claudex-launcher.bin',
    'claudex-launcher.key', 'BCryptOpenAlgorithmProvider', 'BCryptHashData', 'BCryptFinishHash',
    'CreateProcessW', 'CREATE_UNICODE_ENVIRONMENT', 'GetStdHandle', 'SetConsoleCtrlHandler',
    'WaitForSingleObject', 'GetExitCodeProcess', 'pin_executable_leaf']) assert.match(main, new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.match(main, /L"launcher"[\s\S]+L"claude-codex"/u);
  assert.match(main, /L"launcher"[\s\S]+L"claude-agy"/u);
  assert.match(main, /L"launcher"[\s\S]+L"claude-grok"/u);
  assert.match(main, /L"launcher"[\s\S]+L"claudey"/u);
  assert.doesNotMatch(`${main}\n${quote}`, /cmd\.exe|\.cmd\b|powershell|%\*/iu);
  assert.match(quote, /2\s*\*\s*backslashes\s*\+\s*1/u);
  assert.match(header, /claudex_quote_argument/u);
  assert.match(cmake, /UNICODE/u);
  assert.match(cmake, /bcrypt/u);
});

test('portable C quote implementation passes the same vectors when a local C compiler is available', async (t) => {
  const compiler = process.platform === 'win32' ? 'cc.exe' : 'cc';
  if (spawnSync(compiler, ['--version'], { encoding: 'utf8' }).status !== 0) {
    assert.match(await fs.readFile(path.join(root, 'native/windows-shim/test/quote-vectors.c'), 'utf8'), /line\\r\\nbreak/u);
    return;
  }
  const output = path.join(root, `.tmp-quote-vectors${process.platform === 'win32' ? '.exe' : ''}`);
  t.after(() => fs.rm(output, { force: true }));
  const compiled = spawnSync(compiler, ['-std=c11', '-Wall', '-Wextra', '-Werror',
    path.join(root, 'native/windows-shim/src/quote.c'), path.join(root, 'native/windows-shim/test/quote-vectors.c'),
    '-I', path.join(root, 'native/windows-shim/src'), '-o', output], { cwd: root, encoding: 'utf8' });
  assert.equal(compiled.status, 0, compiled.stderr);
  const executed = spawnSync(output, [], { encoding: 'utf8' });
  assert.equal(executed.status, 0, executed.stderr);
});

test('build script has fixed x64/ARM64 schemas and records immutable compiler, flags, compatibility, hash, and size', async (t) => {
  const script = await fs.readFile(path.join(root, 'scripts/build-windows-shim.ps1'), 'utf8');
  for (const token of ['ValidateSet(\'x64\', \'arm64\')', 'managerShimCompatibilityVersion',
    'SourceRevision', 'sourceRevision', 'compiler', 'flags', 'sha256', 'size', 'windows-${Architecture}', 'cmake.exe',
    'windows-shim-capture.mjs']) assert.match(script, new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));

  if (process.platform !== 'win32' || spawnSync('where.exe', ['cmake.exe'], { encoding: 'utf8' }).status !== 0
    || spawnSync('where.exe', ['cl.exe'], { encoding: 'utf8' }).status !== 0) {
    t.skip('Local native MSVC/CMake execution is unavailable; blocking x64 and ARM64 CI jobs build and capture-test both artifacts.');
    return;
  }
  const output = path.join(root, '.tmp-native-shim-test');
  const built = spawnSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
    path.join(root, 'scripts/build-windows-shim.ps1'), '-Architecture', 'x64', '-SourceRevision', 'a'.repeat(40),
    '-OutputDirectory', output],
  { cwd: root, encoding: 'utf8' });
  assert.equal(built.status, 0, built.stderr);
  const descriptor = JSON.parse(await fs.readFile(path.join(output, 'claudex-windows-x64.exe.json'), 'utf8'));
  assert.match(descriptor.sha256, /^[0-9a-f]{64}$/u);
  assert.equal(descriptor.managerShimCompatibilityVersion, 1);
  assert.equal(descriptor.sourceRevision, 'a'.repeat(40));
});
