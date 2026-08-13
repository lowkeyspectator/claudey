import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

import {
  buildManagerPackage, validateProjectReleaseManifest
} from '../../scripts/package.mjs';
import { buildSpdxDocument } from '../../scripts/sbom.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const REVISION = 'a'.repeat(40);

function tarEntries(archive) {
  const tar = zlib.gunzipSync(archive);
  const entries = [];
  for (let offset = 0; offset + 512 <= tar.length;) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const text = (start, length) => header.subarray(start, start + length).toString('utf8').replace(/\0.*$/u, '');
    const octal = (start, length) => Number.parseInt(text(start, length).trim() || '0', 8);
    const name = text(0, 100);
    const size = octal(124, 12);
    entries.push({ name, mode: octal(100, 8), size, mtime: octal(136, 12),
      bytes: tar.subarray(offset + 512, offset + 512 + size) });
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  return entries;
}

test('manager payload is byte-deterministic, sorted, timestamp-free, and contains only declared runtime files', async (t) => {
  const first = await buildManagerPackage({ root, managerVersion: '1.0.0', sourceRevision: REVISION });
  const second = await buildManagerPackage({ root, managerVersion: '1.0.0', sourceRevision: REVISION });
  assert.deepEqual(first.archiveBytes, second.archiveBytes);
  assert.deepEqual(first.payloadDescriptor, second.payloadDescriptor);
  const entries = tarEntries(first.archiveBytes);
  const names = entries.map(({ name }) => name);
  assert.deepEqual(names, [...names].sort());
  assert.equal(entries.every(({ mtime }) => mtime === 0), true);
  assert.equal(first.archiveBytes[9], 255);
  for (const required of ['.claude-plugin/marketplace.json', 'LICENSE', 'package.json', 'bin/claudex',
    'bin/claude-agy', 'bin/claudexctl', 'bin/claudexctl.js', 'plugins/cursor-agent/.mcp.json',
    'scripts/windows/archive-helper.ps1', 'src/cli/main.js']) assert.equal(names.includes(required), true, required);
  assert.equal(names.some((name) => /^(?:docs|test|schemas|\.superpowers|\.git)(?:\/|$)/u.test(name)), false);
  assert.equal(names.some((name) => name === 'node_modules' || name.startsWith('node_modules/')), false);
  assert.deepEqual(first.inventory.map(({ path }) => path), names);
  assert.deepEqual(first.payloadDescriptor.artifact, {
    name: 'claudex-manager-1.0.0.tar.gz',
    sha256: crypto.createHash('sha256').update(first.archiveBytes).digest('hex'), size: first.archiveBytes.length
  });
  const packagedJson = JSON.parse(entries.find(({ name }) => name === 'package.json').bytes.toString('utf8'));
  assert.equal(packagedJson.type, 'module');
  assert.equal(packagedJson.dependencies, undefined);
  assert.equal(packagedJson.optionalDependencies, undefined);
  assert.equal(packagedJson.peerDependencies, undefined);
  assert.equal(entries.find(({ name }) => name === 'bin/claudexctl.js').mode, 0o755);
  assert.equal(entries.find(({ name }) => name === 'src/cli/main.js').mode, 0o644);

  const extracted = await fs.mkdtemp(path.join(os.tmpdir(), 'claudex-payload-'));
  t.after(() => fs.rm(extracted, { recursive: true, force: true }));
  for (const entry of entries) {
    const target = path.join(extracted, ...entry.name.split('/'));
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, entry.bytes, { mode: entry.mode });
  }
  const help = spawnSync(process.execPath, [path.join(extracted, 'bin/claudexctl.js'), '--help'], {
    cwd: extracted, encoding: 'utf8', env: { PATH: process.env.PATH }
  });
  assert.equal(help.status, 0, help.stderr);
  assert.match(help.stdout, /claudexctl setup/);
});

test('packager rejects undeclared runtime files, secret canaries, runtime dependencies, and hostile metadata before output', async (t) => {
  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'claudex-package-'));
  t.after(() => fs.rm(temporary, { recursive: true, force: true }));
  for (const item of ['.claude-plugin', 'bin', 'plugins', 'scripts', 'src']) {
    await fs.cp(path.join(root, item), path.join(temporary, item), { recursive: true });
  }
  await fs.copyFile(path.join(root, 'LICENSE'), path.join(temporary, 'LICENSE'));
  await fs.copyFile(path.join(root, 'package.json'), path.join(temporary, 'package.json'));

  await fs.writeFile(path.join(temporary, 'src', 'undeclared.js'), 'export default true;');
  await assert.rejects(buildManagerPackage({ root: temporary, managerVersion: '1.0.0', sourceRevision: REVISION }),
    (error) => error.code === 'PACKAGE_UNSAFE');
  await fs.rm(path.join(temporary, 'src', 'undeclared.js'));

  const mainPath = path.join(temporary, 'src', 'cli', 'main.js');
  await fs.appendFile(mainPath, '\n// task18-private-secret-canary\n');
  await assert.rejects(buildManagerPackage({ root: temporary, managerVersion: '1.0.0', sourceRevision: REVISION,
    secretCanary: 'task18-private-secret-canary' }), (error) => error.code === 'PACKAGE_UNSAFE');
  await fs.copyFile(path.join(root, 'src/cli/main.js'), mainPath);

  const packageJson = JSON.parse(await fs.readFile(path.join(temporary, 'package.json'), 'utf8'));
  packageJson.dependencies = { hostile: '1.0.0' };
  await fs.writeFile(path.join(temporary, 'package.json'), JSON.stringify(packageJson));
  await assert.rejects(buildManagerPackage({ root: temporary, managerVersion: '1.0.0', sourceRevision: REVISION }),
    (error) => error.code === 'PACKAGE_UNSAFE');
});

test('SPDX inventory and descriptors are deterministic and bind every packaged file without secrets', async () => {
  const packaged = await buildManagerPackage({ root, managerVersion: '1.0.0', sourceRevision: REVISION });
  const first = buildSpdxDocument({ managerVersion: '1.0.0', sourceRevision: REVISION, inventory: packaged.inventory });
  const second = buildSpdxDocument({ managerVersion: '1.0.0', sourceRevision: REVISION, inventory: packaged.inventory });
  assert.deepEqual(first, second);
  const document = JSON.parse(first.bytes.toString('utf8'));
  assert.equal(document.spdxVersion, 'SPDX-2.3');
  assert.equal(document.creationInfo.created, '1970-01-01T00:00:00Z');
  assert.deepEqual(document.files.map(({ fileName }) => fileName), packaged.inventory.map(({ path }) => path));
  assert.deepEqual(first.descriptor, {
    schemaVersion: 1, kind: 'manager-sbom', managerVersion: '1.0.0', sourceRevision: REVISION,
    artifact: { name: 'claudex-manager-1.0.0.spdx.json',
      sha256: crypto.createHash('sha256').update(first.bytes).digest('hex'), size: first.bytes.length }
  });
  assert.equal(first.bytes.includes(Buffer.from('task18-private-secret-canary')), false);
});

test('packaging CLI writes only the payload, payload descriptor, SBOM, and SBOM descriptor without npm install', async (t) => {
  const out = await fs.mkdtemp(path.join(os.tmpdir(), 'claudex-package-out-'));
  t.after(() => fs.rm(out, { recursive: true, force: true }));
  const child = spawnSync(process.execPath, [path.join(root, 'scripts/package.mjs'), '--root', root, '--out', out,
    '--version', '1.0.0', '--source-revision', REVISION], {
    cwd: root, encoding: 'utf8', env: { PATH: process.env.PATH, CLAUDEX_SECRET_CANARY: 'task18-cli-output-canary' }
  });
  assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout, '');
  assert.deepEqual((await fs.readdir(out)).sort(), [
    'claudex-manager-1.0.0.spdx.json', 'claudex-manager-1.0.0.spdx.json.descriptor.json',
    'claudex-manager-1.0.0.tar.gz', 'claudex-manager-1.0.0.tar.gz.json'
  ]);
  const descriptor = JSON.parse(await fs.readFile(path.join(out, 'claudex-manager-1.0.0.tar.gz.json'), 'utf8'));
  const bytes = await fs.readFile(path.join(out, descriptor.artifact.name));
  assert.equal(descriptor.sourceRevision, REVISION);
  assert.equal(descriptor.artifact.sha256, crypto.createHash('sha256').update(bytes).digest('hex'));
  assert.equal(await fs.stat(path.join(out, 'node_modules')).then(() => true, () => false), false);
});

test('schema-1 project manifest accepts the complete six-target fixture and rejects every missing, unknown, or inconsistent field', async () => {
  const valid = JSON.parse(await fs.readFile(path.join(root, 'test/fixtures/releases/project-manifest.valid.json'), 'utf8'));
  assert.deepEqual(validateProjectReleaseManifest(valid), valid);
  for (const mutate of [
    (value) => { delete value.payload.sha256; },
    (value) => { value.extra = true; },
    (value) => { delete value.targets['linux-arm64']; },
    (value) => { value.targets['darwin-arm64'].shim = 'claudex-windows-arm64.exe'; },
    (value) => { value.provenanceSubjects[0].sha256 = 'f'.repeat(64); },
    (value) => { value.managerShimCompatibilityVersion = 0; },
    (value) => { value.shims['windows-x64'].compiler.flags.push(7); },
    (value) => {
      value.shims['windows-x64'].name = 'foreign-x64.exe';
      value.targets['windows-x64'].shim = 'foreign-x64.exe';
      value.provenanceSubjects.find(({ name }) => name === 'claudex-windows-x64.exe').name = 'foreign-x64.exe';
      value.provenanceSubjects.sort((left, right) => left.name.localeCompare(right.name, 'en'));
    }
  ]) {
    const candidate = structuredClone(valid); mutate(candidate);
    assert.throws(() => validateProjectReleaseManifest(candidate), (error) => error.code === 'MANIFEST_INVALID');
  }
  const schema = JSON.parse(await fs.readFile(path.join(root, 'schemas/project-release-manifest.schema.json'), 'utf8'));
  assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema');
  assert.equal(schema.additionalProperties, false);
  assert.deepEqual(schema.required, ['schemaVersion', 'managerVersion', 'sourceRevision',
    'managerShimCompatibilityVersion', 'payload', 'shims', 'targets', 'sbom', 'provenanceSubjects']);
});
