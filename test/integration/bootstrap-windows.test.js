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
const installer = path.join(root, 'install.ps1');
const powershell = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
const csc = 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe';
const REVISION = 'a'.repeat(40);
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');

function octal(value, length) { return `${value.toString(8).padStart(length - 1, '0')}\0`; }

function tar(entries) {
  const blocks = [];
  for (const entry of entries.sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0)) {
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

function payload(version, { failSetup = false } = {}) {
  const manager = `#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
const args = process.argv.slice(2);
fs.appendFileSync(path.join(process.env.LOCALAPPDATA, 'bootstrap-capture.jsonl'), JSON.stringify({ version: '${version}', args }) + '\\n');
if (args.length === 1 && args[0] === '--help') process.stdout.write('claudexctl setup\\n');
else if (args[0] === 'setup') process.exitCode = ${failSetup ? '23' : '0'};
else if (args[0] !== 'launcher') process.exitCode = 2;
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

function payloadWithNonzeroNamePadding(bytes) {
  const archive = Buffer.from(zlib.gunzipSync(bytes));
  const terminator = archive.subarray(0, 100).indexOf(0);
  assert.ok(terminator > 0 && terminator < 99);
  archive[terminator + 1] = 0x58;
  archive.fill(0x20, 148, 156);
  const checksum = archive.subarray(0, 512).reduce((sum, byte) => sum + byte, 0);
  archive.write(`${checksum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');
  const compressed = Buffer.from(zlib.gzipSync(archive, { level: 9, mtime: 0 }));
  compressed.fill(0, 4, 8); compressed[9] = 255;
  return compressed;
}

function manifest(version, payloadBytes, shimBytes, target = 'windows-x64') {
  const payloadArtifact = { name: `claudex-manager-${version}.tar.gz`, sha256: sha256(payloadBytes), size: payloadBytes.length };
  const x64Bytes = target === 'windows-x64' ? shimBytes : Buffer.from('other-x64');
  const arm64Bytes = target === 'windows-arm64' ? shimBytes : Buffer.from('other-arm64');
  const x64 = { name: 'claudex-windows-x64.exe', sha256: sha256(x64Bytes), size: x64Bytes.length,
    compiler: { name: 'MSVC', version: '19.44.35211', flags: ['/O2'] } };
  const arm64 = { name: 'claudex-windows-arm64.exe', sha256: sha256(arm64Bytes), size: arm64Bytes.length,
    compiler: { name: 'MSVC', version: '19.44.35211', flags: ['/O2'] } };
  const sbom = { name: `claudex-manager-${version}.spdx.json`, sha256: 'd'.repeat(64), size: 1 };
  const mapping = (shim = null) => ({ payload: payloadArtifact.name, shim });
  return {
    schemaVersion: 1, managerVersion: version, sourceRevision: REVISION, managerShimCompatibilityVersion: 1,
    payload: payloadArtifact, shims: { 'windows-x64': x64, 'windows-arm64': arm64 },
    targets: { 'windows-x64': mapping(x64.name), 'windows-arm64': mapping(arm64.name),
      'darwin-x64': mapping(), 'darwin-arm64': mapping(), 'linux-x64': mapping(), 'linux-arm64': mapping() },
    sbom,
    provenanceSubjects: [payloadArtifact, sbom, arm64, x64].map(({ name, sha256: digest }) => ({ name, sha256: digest }))
      .sort((left, right) => left.name.localeCompare(right.name, 'en'))
  };
}

async function buildFixtureShim(directory) {
  const source = path.join(directory, 'fixture-shim.cs');
  const output = path.join(directory, 'fixture-shim.exe');
  const code = String.raw`using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;
public static class FixtureShim {
  static string Quote(string value) {
    if (value.Length == 0) return "\"\"";
    bool quoted = false; foreach (char c in value) if (Char.IsWhiteSpace(c) || c == '"') quoted = true;
    if (!quoted) return value;
    StringBuilder result = new StringBuilder("\""); int slashes = 0;
    foreach (char c in value) { if (c == '\\') { slashes++; continue; }
      if (c == '"') { result.Append('\\', slashes * 2 + 1); result.Append('"'); slashes = 0; }
      else { result.Append('\\', slashes); slashes = 0; result.Append(c); } }
    result.Append('\\', slashes * 2); result.Append('"'); return result.ToString();
  }
  public static int Main(string[] args) {
    try {
      string directory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
      byte[] metadata = File.ReadAllBytes(Path.Combine(directory, "claudex-launcher.bin"));
      if (metadata.Length < 72 || Encoding.ASCII.GetString(metadata, 0, 8) != "CLDXL001"
          || BitConverter.ToInt32(metadata, 8) != 1 || BitConverter.ToInt32(metadata, 12) != 1) return 7;
      int nodeChars = BitConverter.ToInt32(metadata, 16); int managerChars = BitConverter.ToInt32(metadata, 20);
      string node = Encoding.Unicode.GetString(metadata, 72, nodeChars * 2);
      string manager = Encoding.Unicode.GetString(metadata, 72 + nodeChars * 2, managerChars * 2);
      List<string> child = new List<string>(); child.Add(manager);
      string name = Path.GetFileName(Assembly.GetExecutingAssembly().Location).ToLowerInvariant();
      if (name == "claudex.exe") { child.Add("launcher"); child.Add("claudex"); }
      else if (name == "claude-agy.exe") { child.Add("launcher"); child.Add("claude-agy"); }
      else if (name != "claudexctl.exe") return 7;
      child.AddRange(args); List<string> quoted = new List<string>(); foreach (string item in child) quoted.Add(Quote(item));
      ProcessStartInfo start = new ProcessStartInfo(node, String.Join(" ", quoted.ToArray())); start.UseShellExecute = false;
      Process process = Process.Start(start); process.WaitForExit(); return process.ExitCode;
    } catch { return 7; }
  }
}`;
  await fs.writeFile(source, code);
  const result = spawnSync(csc, ['/nologo', '/target:exe', `/out:${output}`, source], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stdout + result.stderr);
  return fs.readFile(output);
}

function runPowerShell(script, args, env, timeout = 120_000) {
  return new Promise((resolve) => {
    const child = spawn(powershell, ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
      '-File', script, ...args], { env, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    const stdout = []; const stderr = [];
    const timer = setTimeout(() => child.kill(), timeout);
    child.stdout.on('data', (chunk) => stdout.push(chunk)); child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.on('error', (error) => { clearTimeout(timer); resolve({ error, status: null, stdout: '', stderr: '' }); });
    child.on('close', (status, signal) => { clearTimeout(timer); resolve({ status, signal,
      stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') }); });
  });
}

function testEnvironment(temporary) {
  const local = path.join(temporary, 'local app data');
  return { ...process.env, SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR, PATH: process.env.PATH,
    LOCALAPPDATA: local, APPDATA: path.join(temporary, 'roaming app data'), USERPROFILE: temporary,
    TEMP: path.join(temporary, 'temp'), TMP: path.join(temporary, 'temp') };
}

async function renderedInstaller(temporary, origin) {
  const target = path.join(temporary, 'install.ps1');
  const source = (await fs.readFile(installer, 'utf8')).replace(
    "$ProjectOrigin = 'https://github.com/ramsaijanapana/claude_code_cliProxy'", `$ProjectOrigin = '${origin}'`);
  await fs.writeFile(target, source);
  return target;
}

async function fixtureServer(t, releases, target) {
  const requests = [];
  const server = http.createServer((request, response) => {
    requests.push(request.url);
    const match = /^\/releases\/download\/v(1\.0\.[0-9])\/(project-manifest\.json|claudex-manager-\1\.tar\.gz|claudex-windows-(?:x64|arm64)\.exe)$/u.exec(request.url);
    if (!match || !releases.has(match[1])) { response.writeHead(404).end(); return; }
    const release = releases.get(match[1]); let body;
    if (match[2] === 'project-manifest.json') body = release.servedManifest ?? Buffer.from(`${JSON.stringify(release.manifest)}\n`);
    else if (match[2].endsWith('.tar.gz')) body = release.servedPayload ?? release.payload;
    else if (match[2] === `claudex-${target}.exe`) body = release.servedShim ?? release.shim;
    else { response.writeHead(404).end(); return; }
    response.writeHead(200, { 'content-length': body.length }); response.end(body);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  return { origin: `http://127.0.0.1:${server.address().port}`, requests };
}

test('checked-in bootstrap has fixed syntax, origin, options, static embedded Node, protected DACLs, and array splatting', async () => {
  const source = await fs.readFile(installer, 'utf8');
  const parsed = spawnSync(powershell, ['-NoProfile', '-NonInteractive', '-Command',
    `$errors=$null; [Management.Automation.Language.Parser]::ParseFile('${installer.replaceAll("'", "''")}',[ref]$null,[ref]$errors)|Out-Null; if($errors.Count){$errors|% Message;exit 1}`], { encoding: 'utf8' });
  assert.equal(parsed.status, 0, parsed.stdout + parsed.stderr);
  assert.match(source, /\$ProjectOrigin = 'https:\/\/github\.com\/ramsaijanapana\/claude_code_cliProxy'/u);
  for (const token of ["'-Version'", "'-Yes'", "'-NoPath'", "'-RollbackManager'", 'SetAccessRuleProtection',
    'ContainerInherit', 'ObjectInherit', 'FileShare]::None', 'ClaudexBootstrapDirectoryPin', 'CreateFileW',
    'BackupSemanticsOpenReparse', '& $launcherPath @setupArgs']) assert.match(source, new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.equal(/(?:npm install|npm ci|auth codex|auth antigravity|cursor login|cmd\.exe|\.cmd\b)/iu.test(source), false);
  assert.doesNotMatch(source, /(?:Start-Process[^\r\n]+-Verb\s+RunAs|require[^\r\n]+administrator)/iu);
  const embedded = /\$NodeProgram = @'\r?\n([\s\S]+?)\r?\n'@/u.exec(source);
  assert.ok(embedded);
  const nodeSyntax = spawnSync(process.execPath, ['--check', '--input-type=module'], { input: embedded[1], encoding: 'utf8' });
  assert.equal(nodeSyntax.status, 0, nodeSyntax.stderr);
});

test('bootstrap rejects unknown, duplicate, malformed, conflicting, and missing-Node invocations before managed writes', async (t) => {
  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'claudex-bootstrap-windows-parser-'));
  t.after(() => fs.rm(temporary, { recursive: true, force: true }));
  for (const args of [['-Unknown'], ['-Version'], ['-Version', 'v1.0.0'], ['-Yes', '-Yes'],
    ['-RollbackManager', '-Version', '1.0.0'], ['-RollbackManager', '-NoPath']]) {
    const env = testEnvironment(path.join(temporary, crypto.randomUUID()));
    await fs.mkdir(env.TEMP, { recursive: true });
    const result = await runPowerShell(installer, args, env);
    assert.equal(result.status, 64, `${args.join(' ')}\n${result.stdout}\n${result.stderr}`);
    await assert.rejects(fs.lstat(path.join(env.LOCALAPPDATA, 'claudexctl')), { code: 'ENOENT' });
  }
  const absentNodeRoot = path.join(temporary, 'absent-node'); const env = testEnvironment(absentNodeRoot);
  env.PATH = `${process.env.SystemRoot}\\System32;${process.env.SystemRoot}`; await fs.mkdir(env.TEMP, { recursive: true });
  const result = await runPowerShell(installer, ['-Version', '1.0.0'], env);
  assert.equal(result.status, 69, result.stderr);
  assert.match(result.stderr, /PREREQUISITE_MISSING/u);
  await assert.rejects(fs.lstat(path.join(env.LOCALAPPDATA, 'claudexctl')), { code: 'ENOENT' });

  const unsafeRoot = path.join(temporary, 'unsafe-root'); const unsafeEnv = testEnvironment(unsafeRoot);
  unsafeEnv.LOCALAPPDATA = `${unsafeRoot}\\base\\..\\escaped`;
  await fs.mkdir(unsafeEnv.TEMP, { recursive: true });
  const unsafe = await runPowerShell(installer, ['-Version', '1.0.0'], unsafeEnv);
  assert.equal(unsafe.status, 7, unsafe.stderr);
  await assert.rejects(fs.lstat(path.join(unsafeRoot, 'escaped', 'claudexctl')), { code: 'ENOENT' });
});

test('native bootstrap verifies target artifacts, self-tests shims, activates, forwards exact setup flags, and consumes rollback', async (t) => {
  if (process.platform !== 'win32' || spawnSync(csc, ['/nologo', '/?'], { encoding: 'utf8' }).status !== 0) {
    return t.skip('Native Windows bootstrap proof requires the inbox .NET C# compiler.');
  }
  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'claudex-bootstrap-windows-native-'));
  t.after(() => fs.rm(temporary, { recursive: true, force: true }));
  const env = testEnvironment(temporary); await fs.mkdir(env.TEMP, { recursive: true });
  const shim = await buildFixtureShim(temporary);
  const target = process.arch === 'arm64' ? 'windows-arm64' : 'windows-x64';
  const releases = new Map();
  for (const version of ['1.0.0', '1.0.1']) {
    const bytes = payload(version); releases.set(version, { payload: bytes, shim, manifest: manifest(version, bytes, shim, target) });
  }
  const served = await fixtureServer(t, releases, target);
  const rendered = await renderedInstaller(temporary, served.origin);
  for (const version of releases.keys()) {
    const result = await runPowerShell(rendered, ['-Version', version, '-Yes', '-NoPath'], env);
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    assert.equal(`${result.stdout}${result.stderr}`.includes('OAuth'), false);
  }
  const managerRoot = path.join(env.LOCALAPPDATA, 'claudexctl');
  const current = JSON.parse(await fs.readFile(path.join(managerRoot, 'current.json'), 'utf8'));
  const previous = JSON.parse(await fs.readFile(path.join(managerRoot, 'previous.json'), 'utf8'));
  assert.match(current.target, /1\.0\.1/u); assert.match(previous.target, /1\.0\.0/u);
  const bin = path.join(managerRoot, 'bin');
  const launcherBytes = await Promise.all(['claudexctl.exe', 'claudex.exe', 'claude-agy.exe']
    .map((name) => fs.readFile(path.join(bin, name))));
  assert.ok(launcherBytes.every((bytes) => bytes.equals(shim)));
  assert.equal((await fs.readFile(path.join(bin, 'claudex-launcher.key'))).length, 32);
  assert.equal((await fs.readFile(path.join(bin, 'claudex-launcher.bin'))).subarray(0, 8).toString('ascii'), 'CLDXL001');
  assert.deepEqual((await fs.readdir(path.join(managerRoot, 'staging'))).sort(), []);
  const aclScript = `$a=Get-Acl -LiteralPath '${managerRoot.replaceAll("'", "''")}';$r=@($a.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier]));[pscustomobject]@{protected=$a.AreAccessRulesProtected;count=$r.Count;sids=@($r|%{$_.IdentityReference.Value}|sort)}|ConvertTo-Json -Compress`;
  const acl = spawnSync(powershell, ['-NoProfile', '-NonInteractive', '-Command', aclScript], { env, encoding: 'utf8' });
  assert.equal(acl.status, 0, acl.stderr);
  const aclRecord = JSON.parse(acl.stdout);
  assert.equal(aclRecord.protected, true); assert.equal(aclRecord.count, 3);
  assert.deepEqual(aclRecord.sids, ['S-1-5-18', 'S-1-5-32-544', spawnSync(powershell,
    ['-NoProfile', '-NonInteractive', '-Command', '[Security.Principal.WindowsIdentity]::GetCurrent().User.Value'],
    { env, encoding: 'utf8' }).stdout.trim()].sort());
  const hostile = ['', 'two words', 'quote"value', '%PATH%', '--flag', 'line\r\nbreak'];
  const launch = spawnSync(path.join(bin, 'claudex.exe'), hostile, { env, encoding: 'utf8', windowsHide: true });
  assert.equal(launch.status, 0, launch.stderr);
  let rows = (await fs.readFile(path.join(env.LOCALAPPDATA, 'bootstrap-capture.jsonl'), 'utf8')).trim().split(/\r?\n/u).map(JSON.parse);
  assert.deepEqual(rows.filter(({ args }) => args[0] === 'setup').map(({ version, args }) => ({ version, args })), [
    { version: '1.0.0', args: ['setup', '--yes', '--no-path'] },
    { version: '1.0.1', args: ['setup', '--yes', '--no-path'] }
  ]);
  assert.deepEqual(rows.at(-1), { version: '1.0.1', args: ['launcher', 'claudex', ...hostile] });
  const rollback = await runPowerShell(rendered, ['-RollbackManager'], env);
  assert.equal(rollback.status, 0, rollback.stderr);
  assert.match(JSON.parse(await fs.readFile(path.join(managerRoot, 'current.json'), 'utf8')).target, /1\.0\.0/u);
  await assert.rejects(fs.lstat(path.join(managerRoot, 'previous.json')), { code: 'ENOENT' });
  rows = (await fs.readFile(path.join(env.LOCALAPPDATA, 'bootstrap-capture.jsonl'), 'utf8')).trim().split(/\r?\n/u).map(JSON.parse);
  assert.equal(rows.some(({ args }) => args.includes('1.0.1')), false, 'manager version was forwarded to setup');
  assert.deepEqual(served.requests, [
    '/releases/download/v1.0.0/project-manifest.json', '/releases/download/v1.0.0/claudex-manager-1.0.0.tar.gz',
    `/releases/download/v1.0.0/claudex-${target}.exe`,
    '/releases/download/v1.0.1/project-manifest.json', '/releases/download/v1.0.1/claudex-manager-1.0.1.tar.gz',
    `/releases/download/v1.0.1/claudex-${target}.exe`
  ]);
});

test('failed post-switch setup and an interrupted journal restore the last verified manager without OAuth or downloads on rollback', async (t) => {
  if (process.platform !== 'win32' || spawnSync(csc, ['/nologo', '/?'], { encoding: 'utf8' }).status !== 0) {
    return t.skip('Native Windows bootstrap proof requires the inbox .NET C# compiler.');
  }
  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'claudex-bootstrap-windows-recovery-'));
  t.after(() => fs.rm(temporary, { recursive: true, force: true }));
  const env = testEnvironment(temporary); await fs.mkdir(env.TEMP, { recursive: true });
  const shim = await buildFixtureShim(temporary);
  const target = process.arch === 'arm64' ? 'windows-arm64' : 'windows-x64';
  const good = payload('1.0.0'); const bad = payload('1.0.1', { failSetup: true });
  const releases = new Map([
    ['1.0.0', { payload: good, shim, manifest: manifest('1.0.0', good, shim, target) }],
    ['1.0.1', { payload: bad, shim, manifest: manifest('1.0.1', bad, shim, target) }]
  ]);
  const served = await fixtureServer(t, releases, target); const rendered = await renderedInstaller(temporary, served.origin);
  let result = await runPowerShell(rendered, ['-Version', '1.0.0', '-Yes'], env);
  assert.equal(result.status, 0, result.stderr);
  result = await runPowerShell(rendered, ['-Version', '1.0.1', '-Yes'], env);
  assert.notEqual(result.status, 0);
  const managerRoot = path.join(env.LOCALAPPDATA, 'claudexctl');
  const journalPath = path.join(managerRoot, 'state', 'manager-journal.json');
  const oldCurrent = JSON.parse(await fs.readFile(path.join(managerRoot, 'current.json'), 'utf8'));
  assert.match(oldCurrent.target, /1\.0\.0/u);
  await assert.rejects(fs.lstat(journalPath), { code: 'ENOENT' });

  const badTarget = `releases/1.0.1-${sha256(bad)}`;
  await fs.writeFile(journalPath, `${JSON.stringify({ schemaVersion: 1, operation: 'activate',
    oldCurrent: oldCurrent.target, oldPrevious: null, newCurrent: badTarget })}\n`);
  await fs.writeFile(path.join(managerRoot, 'current.json'), `${JSON.stringify({ schemaVersion: 1, target: badTarget })}\n`);
  const before = served.requests.length;
  result = await runPowerShell(rendered, ['-RollbackManager'], env);
  assert.equal(result.status, 8, result.stderr);
  assert.match(JSON.parse(await fs.readFile(path.join(managerRoot, 'current.json'), 'utf8')).target, /1\.0\.0/u);
  await assert.rejects(fs.lstat(journalPath), { code: 'ENOENT' });
  assert.equal(served.requests.length, before, 'manager rollback unexpectedly downloaded an artifact');
});

test('manifest, payload, target mapping, compatibility, and shim corruption fail before activation', async (t) => {
  if (process.platform !== 'win32' || spawnSync(csc, ['/nologo', '/?'], { encoding: 'utf8' }).status !== 0) {
    return t.skip('Native Windows bootstrap proof requires the inbox .NET C# compiler.');
  }
  const fixtureRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'claudex-bootstrap-windows-integrity-'));
  t.after(() => fs.rm(fixtureRoot, { recursive: true, force: true }));
  const shim = await buildFixtureShim(fixtureRoot);
  const target = process.arch === 'arm64' ? 'windows-arm64' : 'windows-x64';
  const cases = [
    (release) => { const changed = structuredClone(release.manifest); changed.targets[target].shim = null;
      release.servedManifest = Buffer.from(`${JSON.stringify(changed)}\n`); },
    (release) => { const changed = structuredClone(release.manifest); changed.managerShimCompatibilityVersion = 2;
      release.servedManifest = Buffer.from(`${JSON.stringify(changed)}\n`); },
    (release) => { release.servedPayload = Buffer.concat([release.payload, Buffer.from('changed')]); },
    (release) => { release.servedShim = Buffer.concat([release.shim, Buffer.from('changed')]); },
    (release) => { release.payload = payloadWithNonzeroNamePadding(release.payload);
      release.manifest = manifest('1.0.0', release.payload, release.shim, target); }
  ];
  for (let index = 0; index < cases.length; index += 1) {
    const temporary = path.join(fixtureRoot, `case-${index}`); await fs.mkdir(temporary);
    const env = testEnvironment(temporary); await fs.mkdir(env.TEMP, { recursive: true });
    const bytes = payload('1.0.0'); const release = { payload: bytes, shim, manifest: manifest('1.0.0', bytes, shim, target) };
    cases[index](release);
    const served = await fixtureServer(t, new Map([['1.0.0', release]]), target);
    const rendered = await renderedInstaller(temporary, served.origin);
    const result = await runPowerShell(rendered, ['-Version', '1.0.0', '-Yes'], env);
    assert.notEqual(result.status, 0, `${index}\n${result.stdout}\n${result.stderr}`);
    await assert.rejects(fs.lstat(path.join(env.LOCALAPPDATA, 'claudexctl', 'current.json')), { code: 'ENOENT' });
    assert.equal(`${result.stdout}${result.stderr}`.includes('OAuth'), false);
  }
});

test('a first install refuses pre-existing launcher identity material instead of adopting it', async (t) => {
  if (process.platform !== 'win32' || spawnSync(csc, ['/nologo', '/?'], { encoding: 'utf8' }).status !== 0) {
    return t.skip('Native Windows bootstrap proof requires the inbox .NET C# compiler.');
  }
  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'claudex-bootstrap-windows-foreign-key-'));
  t.after(() => fs.rm(temporary, { recursive: true, force: true }));
  const env = testEnvironment(temporary); await fs.mkdir(env.TEMP, { recursive: true });
  const shim = await buildFixtureShim(temporary); const target = process.arch === 'arm64' ? 'windows-arm64' : 'windows-x64';
  const bytes = payload('1.0.0'); const release = { payload: bytes, shim, manifest: manifest('1.0.0', bytes, shim, target) };
  const served = await fixtureServer(t, new Map([['1.0.0', release]]), target);
  const rendered = await renderedInstaller(temporary, served.origin);
  const managerRoot = path.join(env.LOCALAPPDATA, 'claudexctl');
  await fs.mkdir(path.join(managerRoot, 'bin'), { recursive: true });
  await fs.writeFile(path.join(managerRoot, 'bin', 'claudex-launcher.key'), Buffer.alloc(32, 0x5a));
  const result = await runPowerShell(rendered, ['-Version', '1.0.0', '-Yes'], env);
  assert.notEqual(result.status, 0, result.stderr);
  await assert.rejects(fs.lstat(path.join(managerRoot, 'current.json')), { code: 'ENOENT' });
});
