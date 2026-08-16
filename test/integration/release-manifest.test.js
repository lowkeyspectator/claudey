import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { assembleReleaseManifest } from '../../scripts/assemble-release-manifest.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const REVISION = 'a'.repeat(40);
const digest = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');

function fixture() {
  const artifacts = new Map([
    ['claudey-manager-1.0.0.tar.gz', Buffer.from('payload-artifact')],
    ['claudey-manager-1.0.0.spdx.json', Buffer.from('{"spdxVersion":"SPDX-2.3"}\n')],
    ['claudey-windows-x64.exe', Buffer.from('x64-shim-artifact')],
    ['claudey-windows-arm64.exe', Buffer.from('arm64-shim-artifact')]
  ]);
  const artifact = (name) => ({ name, sha256: digest(artifacts.get(name)), size: artifacts.get(name).length });
  return {
    artifacts,
    payloadDescriptor: { schemaVersion: 1, kind: 'manager-payload', managerVersion: '1.0.0',
      sourceRevision: REVISION, artifact: artifact('claudey-manager-1.0.0.tar.gz'), inventorySha256: 'b'.repeat(64) },
    sbomDescriptor: { schemaVersion: 1, kind: 'manager-sbom', managerVersion: '1.0.0',
      sourceRevision: REVISION, artifact: artifact('claudey-manager-1.0.0.spdx.json') },
    shimDescriptors: [
      { schemaVersion: 1, target: 'windows-x64', ...artifact('claudey-windows-x64.exe'),
        sourceRevision: REVISION,
        managerShimCompatibilityVersion: 1,
        compiler: { name: 'MSVC', version: '19.44.35211', flags: ['/O2', '/guard:cf', '/DYNAMICBASE', '/NXCOMPAT'] } },
      { schemaVersion: 1, target: 'windows-arm64', ...artifact('claudey-windows-arm64.exe'),
        sourceRevision: REVISION,
        managerShimCompatibilityVersion: 1,
        compiler: { name: 'MSVC', version: '19.44.35211', flags: ['/O2', '/guard:cf', '/DYNAMICBASE', '/NXCOMPAT'] } }
    ],
    readArtifact: async (name) => Buffer.from(artifacts.get(name))
  };
}

test('assembles a deterministic schema-1 manifest only after rehashing payload, SBOM, and both target shims', async () => {
  const f = fixture();
  const reads = [];
  const options = { ...f, readArtifact: async (name) => { reads.push(name); return f.readArtifact(name); } };
  const first = await assembleReleaseManifest(options);
  const second = await assembleReleaseManifest(f);
  assert.deepEqual(first, second);
  assert.deepEqual(reads, [...f.artifacts.keys()]);
  assert.equal(first.schemaVersion, 1);
  assert.equal(first.managerVersion, '1.0.0');
  assert.equal(first.sourceRevision, REVISION);
  assert.equal(first.managerShimCompatibilityVersion, 1);
  assert.deepEqual(Object.keys(first.targets), [
    'windows-x64', 'windows-arm64', 'darwin-x64', 'darwin-arm64', 'linux-x64', 'linux-arm64'
  ]);
  assert.deepEqual(first.provenanceSubjects.map(({ name }) => name), [...f.artifacts.keys()].sort());
  assert.equal(Object.isFrozen(first), true);
  assert.equal(Object.isFrozen(first.shims['windows-x64'].compiler.flags), true);
});

test('rejects missing, duplicate, foreign, stale, incompatible, malformed, and digest-mismatched descriptors', async () => {
  const mutations = [
    (f) => { f.shimDescriptors.pop(); },
    (f) => { f.shimDescriptors[1].target = 'windows-x64'; },
    (f) => { f.shimDescriptors[0].target = 'linux-x64'; },
    (f) => { f.shimDescriptors[0].managerShimCompatibilityVersion = 2; },
    (f) => { f.shimDescriptors[0].sourceRevision = 'c'.repeat(40); },
    (f) => { const bytes = f.artifacts.get(f.shimDescriptors[0].name);
      f.shimDescriptors[0].name = 'foreign-x64.exe'; f.artifacts.set('foreign-x64.exe', bytes); },
    (f) => { f.sbomDescriptor.sourceRevision = 'c'.repeat(40); },
    (f) => { f.payloadDescriptor.managerVersion = '1.0.1'; },
    (f) => { f.payloadDescriptor.extra = true; },
    (f) => { f.shimDescriptors[0].compiler.flags.push('/O2'); },
    (f) => { f.artifacts.set('claudey-windows-arm64.exe', Buffer.from('changed')); },
    (f) => { f.readArtifact = async () => Buffer.from('foreign'); }
  ];
  for (const mutate of mutations) {
    const f = fixture(); mutate(f);
    await assert.rejects(assembleReleaseManifest(f), (error) => error.code === 'MANIFEST_INVALID');
  }
});

test('CLI consumes descriptor files and real artifacts, then fresh-process validates before atomic publication', async (t) => {
  const f = fixture();
  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'claudey-release-manifest-'));
  t.after(() => fs.rm(temporary, { recursive: true, force: true }));
  const artifactsRoot = path.join(temporary, 'artifacts');
  await fs.mkdir(artifactsRoot);
  for (const [name, bytes] of f.artifacts) await fs.writeFile(path.join(artifactsRoot, name), bytes);
  const inputs = [
    ['payload.json', f.payloadDescriptor], ['sbom.json', f.sbomDescriptor],
    ['x64.json', f.shimDescriptors[0]], ['arm64.json', f.shimDescriptors[1]]
  ];
  for (const [name, value] of inputs) await fs.writeFile(path.join(temporary, name), `${JSON.stringify(value)}\n`);
  const output = path.join(temporary, 'project-manifest.json');
  const child = spawnSync(process.execPath, [path.join(root, 'scripts/assemble-release-manifest.mjs'),
    '--payload-descriptor', path.join(temporary, 'payload.json'), '--sbom-descriptor', path.join(temporary, 'sbom.json'),
    '--shim-x64-descriptor', path.join(temporary, 'x64.json'), '--shim-arm64-descriptor', path.join(temporary, 'arm64.json'),
    '--artifacts', artifactsRoot, '--out', output], { cwd: root, encoding: 'utf8' });
  assert.equal(child.status, 0, child.stderr);
  const manifest = JSON.parse(await fs.readFile(output, 'utf8'));
  assert.equal(manifest.sourceRevision, REVISION);
  const validate = spawnSync(process.execPath, [path.join(root, 'scripts/assemble-release-manifest.mjs'),
    '--validate', output], { cwd: root, encoding: 'utf8' });
  assert.equal(validate.status, 0, validate.stderr);
});
