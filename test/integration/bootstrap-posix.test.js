import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import test from 'node:test';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const installer = path.join(root, 'install.sh');
const REVISION = 'a'.repeat(40);
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const shellQuote = (value) => `'${value.replaceAll("'", `'"'"'`)}'`;

function shellPath() {
  if (process.platform !== 'win32') return '/bin/sh';
  const candidate = 'C:\\Program Files\\Git\\bin\\sh.exe';
  return spawnSync(candidate, ['-c', 'exit 0']).status === 0 ? candidate : undefined;
}

function shellPathFor(value) {
  if (process.platform !== 'win32') return value;
  return value.replace(/^([A-Za-z]):/u, (_, drive) => `/${drive.toLowerCase()}`).replaceAll('\\', '/');
}

function octal(value, length) { return `${value.toString(8).padStart(length - 1, '0')}\0`; }

function tar(entries) {
  const blocks = [];
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name, 'en'))) {
    const bytes = Buffer.from(entry.bytes);
    const header = Buffer.alloc(512);
    header.write(entry.name, 0, 100, 'utf8');
    header.write(octal(entry.mode, 8), 100, 8, 'ascii');
    header.write(octal(0, 8), 108, 8, 'ascii');
    header.write(octal(0, 8), 116, 8, 'ascii');
    header.write(octal(bytes.length, 12), 124, 12, 'ascii');
    header.write(octal(0, 12), 136, 12, 'ascii');
    header.fill(0x20, 148, 156);
    header.write('0', 156, 1, 'ascii');
    header.write('ustar\0', 257, 6, 'ascii');
    header.write('00', 263, 2, 'ascii');
    const checksum = header.reduce((sum, byte) => sum + byte, 0);
    header.write(`${checksum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');
    blocks.push(header, bytes, Buffer.alloc((512 - bytes.length % 512) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  const compressed = Buffer.from(zlib.gzipSync(Buffer.concat(blocks), { level: 9, mtime: 0 }));
  compressed.fill(0, 4, 8); compressed[9] = 255;
  return compressed;
}

function payload(version) {
  const manager = `#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
const args = process.argv.slice(2);
fs.appendFileSync(path.join(process.env.HOME, 'bootstrap-capture.jsonl'), JSON.stringify({ version: '${version}', args }) + '\\n');
if (args.length === 1 && args[0] === '--help') process.stdout.write('claudexctl setup\\n');
else if (args[0] !== 'setup' && args[0] !== 'launcher') process.exitCode = 2;
`;
  return tar([
    { name: 'bin/claudexctl.js', mode: 0o755, bytes: manager },
    { name: 'bin/claudexctl', mode: 0o755, bytes: '#!/bin/sh\nexit 99\n' },
    { name: 'bin/claudex', mode: 0o755, bytes: '#!/bin/sh\nexit 99\n' },
    { name: 'bin/claude-agy', mode: 0o755, bytes: '#!/bin/sh\nexit 99\n' },
    { name: 'package.json', mode: 0o644, bytes: `${JSON.stringify({ name: 'claudexctl', version, type: 'module' })}\n` },
    { name: 'LICENSE', mode: 0o644, bytes: 'test license\n' }
  ]);
}

function manifest(version, bytes) {
  const payloadArtifact = { name: `claudex-manager-${version}.tar.gz`, sha256: sha256(bytes), size: bytes.length };
  const x64 = { name: 'claudex-windows-x64.exe', sha256: 'b'.repeat(64), size: 1,
    compiler: { name: 'MSVC', version: '19.44.35211', flags: ['/O2'] } };
  const arm64 = { name: 'claudex-windows-arm64.exe', sha256: 'c'.repeat(64), size: 1,
    compiler: { name: 'MSVC', version: '19.44.35211', flags: ['/O2'] } };
  const sbom = { name: `claudex-manager-${version}.spdx.json`, sha256: 'd'.repeat(64), size: 1 };
  const target = (shim = null) => ({ payload: payloadArtifact.name, shim });
  return {
    schemaVersion: 1, managerVersion: version, sourceRevision: REVISION, managerShimCompatibilityVersion: 1,
    payload: payloadArtifact, shims: { 'windows-x64': x64, 'windows-arm64': arm64 },
    targets: { 'windows-x64': target(x64.name), 'windows-arm64': target(arm64.name),
      'darwin-x64': target(), 'darwin-arm64': target(), 'linux-x64': target(), 'linux-arm64': target() },
    sbom,
    provenanceSubjects: [payloadArtifact, sbom, arm64, x64].map(({ name, sha256: digest }) => ({ name, sha256: digest }))
      .sort((left, right) => left.name.localeCompare(right.name, 'en'))
  };
}

async function runShell(shell, script, args, env) {
  return new Promise((resolve) => {
    const child = spawn(shell, [script, ...args], { env, stdio: ['ignore', 'pipe', 'pipe'] });
    const stdout = []; const stderr = [];
    child.stdout.on('data', (chunk) => stdout.push(chunk));
    child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.on('error', (error) => resolve({ error, status: null, stdout: '', stderr: '' }));
    child.on('close', (status, signal) => resolve({ status, signal,
      stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') }));
  });
}

test('bootstrap parser accepts only the fixed manager options before any persistent write', async (t) => {
  const shell = shellPath();
  if (!shell) return t.skip('A POSIX shell is unavailable on this host.');
  for (const args of [
    ['--unknown'], ['--version'], ['--version', 'v1.0.0'], ['--yes', '--yes'],
    ['--rollback-manager', '--version', '1.0.0'], ['--rollback-manager', '--no-path']
  ]) {
    const result = spawnSync(shell, [installer, ...args], { encoding: 'utf8', env: { PATH: process.env.PATH } });
    assert.equal(result.status, 64, `${args.join(' ')}\n${result.stderr}`);
    assert.equal(result.stdout, '');
  }
});

test('checked-in bootstrap is valid POSIX shell with fixed HTTPS project origin and no OAuth or npm execution', async (t) => {
  const shell = shellPath();
  if (!shell) return t.skip('A POSIX shell is unavailable on this host.');
  const syntax = spawnSync(shell, ['-n', installer], { encoding: 'utf8' });
  assert.equal(syntax.status, 0, syntax.stderr);
  const source = await fs.readFile(installer, 'utf8');
  assert.match(source, /PROJECT_ORIGIN='https:\/\/github\.com\/ramsaijanapana\/claude_code_cliProxy'/u);
  assert.equal(/(?:npm install|npm ci|auth codex|auth antigravity|cursor login)/u.test(source), false);
  const embedded = /<<'NODE'\n([\s\S]+)\nNODE\n/u.exec(source);
  assert.ok(embedded);
  const nodeSyntax = spawnSync(process.execPath, ['--check', '--input-type=module'], {
    input: embedded[1], encoding: 'utf8'
  });
  assert.equal(nodeSyntax.status, 0, nodeSyntax.stderr);
  const shellcheck = spawnSync('shellcheck', ['--version'], { encoding: 'utf8' });
  if (shellcheck.status === 0) {
    const checked = spawnSync('shellcheck', ['--shell=sh', installer], { encoding: 'utf8' });
    assert.equal(checked.status, 0, checked.stdout + checked.stderr);
  }
});

test('bootstrap rejects root and unsupported Node lines while accepting a supported absolute Node path with spaces', async (t) => {
  const shell = shellPath();
  if (!shell) return t.skip('A POSIX shell is unavailable on this host.');
  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'claudex-bootstrap-prereq-'));
  t.after(() => fs.rm(temporary, { recursive: true, force: true }));
  const fakeBin = path.join(temporary, 'fake bin'); await fs.mkdir(fakeBin);
  const fakeNode = path.join(fakeBin, 'node');
  const fakeNodeShellPath = shellPathFor(fakeNode).replaceAll("'", `'"'"'`);
  const runVersion = (version) => fs.writeFile(fakeNode, `#!/bin/sh\ncase "$2" in\n  process.versions.node) printf '%s\\n' '${version}' ;;\n  process.execPath) printf '%s\\n' '${fakeNodeShellPath}' ;;\n  process.arch) printf '%s\\n' 'x64' ;;\n  *) exit 91 ;;\nesac\n`, { mode: 0o755 });
  const pathValue = `${shellPathFor(fakeBin)}:/usr/bin:/bin`;
  await runVersion('22.19.9');
  let result = spawnSync(shell, [shellPathFor(installer)], { encoding: 'utf8', env: { PATH: pathValue, HOME: '/tmp/test-home' } });
  assert.equal(result.status, 69); assert.match(result.stderr, /Node\.js 22\.20\.0/u);
  await runVersion('28.0.0');
  result = spawnSync(shell, [shellPathFor(installer)], { encoding: 'utf8', env: { PATH: pathValue, HOME: '/tmp/test-home' } });
  assert.equal(result.status, 69); assert.match(result.stderr, /Node\.js 22, 24, or 26/u);
  await runVersion('24.19.0');
  result = spawnSync(shell, [shellPathFor(installer)], { encoding: 'utf8', env: { PATH: pathValue, HOME: '/tmp/test-home' } });
  assert.equal(result.status, 69); assert.match(result.stderr, /PLATFORM_UNSUPPORTED/u);

  const fakeId = path.join(temporary, 'id');
  await fs.writeFile(fakeId, '#!/bin/sh\nprintf \'0\\n\'\n', { mode: 0o755 });
  const rootScript = path.join(temporary, 'install-root.sh');
  await fs.writeFile(rootScript, (await fs.readFile(installer, 'utf8')).replace('/usr/bin/id -u', `${shellPathFor(fakeId)} -u`), { mode: 0o755 });
  result = spawnSync(shell, [shellPathFor(rootScript)], { encoding: 'utf8', env: { PATH: pathValue, HOME: '/tmp/test-home' } });
  assert.equal(result.status, 7); assert.match(result.stderr, /Do not run.*root/u);
});

test('actual checked-in POSIX launchers preserve every hostile argument as a discrete value', async (t) => {
  const shell = shellPath();
  if (!shell) return t.skip('A POSIX shell is unavailable on this host.');
  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'claudex-launcher-posix-'));
  t.after(() => fs.rm(temporary, { recursive: true, force: true }));
  const capture = path.join(temporary, 'capture.mjs');
  const output = path.join(temporary, 'capture.jsonl');
  await fs.writeFile(capture, "import fs from 'node:fs'; fs.appendFileSync(process.env.CLDX_CAPTURE_FILE, JSON.stringify(process.argv.slice(2)) + '\\n');\n");
  const hostile = ['', 'two words', 'quote"value', "single'value", '$()', '%PATH%', '--flag', 'line\nbreak', '\\end\\'];
  const expected = {
    claudexctl: hostile,
    claudex: ['launcher', 'claudex', ...hostile],
    'claude-agy': ['launcher', 'claude-agy', ...hostile]
  };
  for (const name of Object.keys(expected)) {
    const template = await fs.readFile(path.join(root, 'bin', name), 'utf8');
    const rendered = template.replace('__CLAUDEX_NODE__', process.execPath.replaceAll("'", `'"'"'`))
      .replace('__CLAUDEX_MANAGER__', capture.replaceAll("'", `'"'"'`));
    const target = path.join(temporary, name); await fs.writeFile(target, rendered, { mode: 0o755 });
    const driver = path.join(temporary, `${name}-driver.sh`);
    await fs.writeFile(driver, `#!/bin/sh\nexec ${shellQuote(shellPathFor(target))} ${hostile.map(shellQuote).join(' ')}\n`, { mode: 0o755 });
    const result = spawnSync(shell, [shellPathFor(driver)], {
      encoding: 'utf8', env: { PATH: process.env.PATH, CLDX_CAPTURE_FILE: output }
    });
    assert.equal(result.status, 0, result.stderr);
  }
  const rows = (await fs.readFile(output, 'utf8')).trim().split('\n').map(JSON.parse);
  assert.deepEqual(rows, Object.values(expected));
});

test('native POSIX bootstrap verifies, activates, updates, forwards exact setup flags, and consumes one rollback', async (t) => {
  if (process.platform === 'win32') return t.skip('Native POSIX filesystem and launcher proof runs on Linux/macOS CI.');
  const temporary = await fs.mkdtemp(path.join(os.homedir(), '.claudex-bootstrap-posix-'));
  t.after(() => fs.rm(temporary, { recursive: true, force: true }));
  const home = path.join(temporary, 'home'); await fs.mkdir(home);
  const releases = new Map([['1.0.0', payload('1.0.0')], ['1.0.1', payload('1.0.1')]]);
  const requests = [];
  const server = http.createServer((request, response) => {
    requests.push(request.url);
    const match = /^\/releases\/download\/v(1\.0\.[01])\/(project-manifest\.json|claudex-manager-\1\.tar\.gz)$/u.exec(request.url);
    if (!match) { response.writeHead(404).end(); return; }
    const bytes = releases.get(match[1]);
    const body = match[2] === 'project-manifest.json' ? Buffer.from(`${JSON.stringify(manifest(match[1], bytes))}\n`) : bytes;
    response.writeHead(200, { 'content-length': body.length }); response.end(body);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const rendered = path.join(temporary, 'install.sh');
  const source = (await fs.readFile(installer, 'utf8')).replace(
    "PROJECT_ORIGIN='https://github.com/ramsaijanapana/claude_code_cliProxy'", `PROJECT_ORIGIN='${origin}'`);
  await fs.writeFile(rendered, source, { mode: 0o755 });
  const env = { PATH: process.env.PATH, HOME: home, XDG_DATA_HOME: path.join(home, 'data'),
    XDG_CONFIG_HOME: path.join(home, 'config'), XDG_STATE_HOME: path.join(home, 'state'), LANG: 'C.UTF-8' };
  for (const version of ['1.0.0', '1.0.1']) {
    const result = await runShell('/bin/sh', rendered, ['--version', version, '--yes', '--no-path'], env);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout.includes('OAuth'), false);
  }
  const managerRoot = path.join(home, 'data', 'claudexctl');
  assert.equal((await fs.lstat(managerRoot)).mode & 0o777, 0o700);
  assert.equal((await fs.lstat(path.join(managerRoot, 'current'))).isSymbolicLink(), true);
  assert.match(await fs.readlink(path.join(managerRoot, 'current')), /1\.0\.1/u);
  const active = await fs.realpath(path.join(managerRoot, 'current'));
  assert.equal(await fs.lstat(path.join(active, 'capture')).then(() => true, () => false), false);
  const bin = path.join(home, '.local', 'bin');
  const hostile = ['', 'two words', 'quote"value', "single'value", '$()', '%PATH%', '--flag', 'line\nbreak'];
  const launch = await runShell('/bin/sh', path.join(bin, 'claudex'), ['--model', 'live', '--', ...hostile], env);
  assert.equal(launch.status, 0, launch.stderr);
  const captured = (await fs.readFile(path.join(home, 'bootstrap-capture.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
  assert.deepEqual(captured.filter(({ args }) => args[0] === 'setup').map(({ version, args }) => ({ version, args })), [
    { version: '1.0.0', args: ['setup', '--yes', '--no-path'] },
    { version: '1.0.1', args: ['setup', '--yes', '--no-path'] }
  ]);
  assert.deepEqual(captured.at(-1), { version: '1.0.1', args: ['launcher', 'claudex', '--model', 'live', '--', ...hostile] });
  const rollback = await runShell('/bin/sh', rendered, ['--rollback-manager'], env);
  assert.equal(rollback.status, 0, rollback.stderr);
  assert.match(await fs.readlink(path.join(managerRoot, 'current')), /1\.0\.0/u);
  assert.equal(await fs.lstat(path.join(managerRoot, 'previous')).then(() => true, () => false), false);
  assert.deepEqual(requests, [
    '/releases/download/v1.0.0/project-manifest.json', '/releases/download/v1.0.0/claudex-manager-1.0.0.tar.gz',
    '/releases/download/v1.0.1/project-manifest.json', '/releases/download/v1.0.1/claudex-manager-1.0.1.tar.gz'
  ]);
});
