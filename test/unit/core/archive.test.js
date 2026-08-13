import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { ARCHIVE_LIMITS, validateArchive } from '../../../src/core/archive.js';
import {
  buildGzip, buildTar, buildTarGz, buildZip, paxRecord, validTarEntries, validZipEntries
} from '../../support/archive-fixtures.js';

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

async function archiveFixture(t, bytes, kind, expectedExecutable, options = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'claudexctl-archive-unit-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const archivePath = path.join(root, kind === 'zip' ? 'fixture.zip' : 'fixture.tar.gz');
  await fs.writeFile(archivePath, bytes, { mode: 0o600 });
  const stats = await fs.stat(archivePath);
  return {
    descriptor: Object.freeze({
      path: archivePath,
      name: path.basename(archivePath),
      bytes: bytes.length,
      sha256: sha256(bytes),
      kind
    }),
    expectedExecutable,
    adapter: {
      targetPlatform: options.targetPlatform ?? (kind === 'zip' ? 'win32' : 'linux'),
      stagingRoot: root,
      archiveIdentity: { dev: stats.dev, ino: stats.ino },
      ...options.adapter
    }
  };
}

async function validateBytes(t, bytes, kind, expectedExecutable, options = {}) {
  const fixture = await archiveFixture(t, bytes, kind, expectedExecutable, options);
  return validateArchive(fixture.descriptor, fixture.expectedExecutable, options.limits, fixture.adapter);
}

function unsafe(error) {
  return error?.code === 'ARCHIVE_UNSAFE' && !String(error.message).includes(process.env.CLAUDEX_SECRET_CANARY ?? '\0never');
}

test('accepts valid ZIP and TAR.GZ metadata into sorted deeply immutable plans without extraction', async (t) => {
  for (const [bytes, kind, executable] of [
    [buildZip(validZipEntries), 'zip', 'CLIProxyAPI.exe'],
    [buildTarGz(validTarEntries), 'tar.gz', 'CLIProxyAPI']
  ]) {
    const plan = await validateBytes(t, bytes, kind, executable);
    assert.equal(plan.kind, kind);
    assert.equal(plan.expectedExecutable, executable);
    assert.deepEqual(plan.entries.map((entry) => entry.path), ['README.txt', 'bin', `bin/${executable}`]);
    assert.equal(plan.candidate.path, `bin/${executable}`);
    assert.equal(Object.isFrozen(plan), true);
    assert.equal(Object.isFrozen(plan.entries), true);
    assert.equal(Object.isFrozen(plan.entries[0]), true);
    assert.throws(() => plan.entries.push({}));
    assert.throws(() => { plan.candidate.path = 'elsewhere'; });
  }
});

test('rehashes and rechecks the verified Task 5 descriptor before parsing', async (t) => {
  const bytes = buildZip(validZipEntries);
  const fixture = await archiveFixture(t, bytes, 'zip', 'CLIProxyAPI.exe');
  await fs.writeFile(fixture.descriptor.path, Buffer.from('replacement'));
  await assert.rejects(
    () => validateArchive(fixture.descriptor, fixture.expectedExecutable, undefined, fixture.adapter),
    unsafe
  );
});

test('requires exactly one case-sensitive regular expected executable', async (t) => {
  const variants = [
    [],
    [{ name: 'CLIProxyAPI.EXE', content: 'candidate' }],
    [{ name: 'CLIProxyAPI.exe/', directory: true }],
    [{ name: 'CLIProxyAPI.exe', content: 'a' }, { name: 'CLIProxyAPI.exe', content: 'b' }]
  ];
  for (const entries of variants) {
    await assert.rejects(() => validateBytes(t, buildZip(entries), 'zip', 'CLIProxyAPI.exe'), unsafe);
  }
});

test('rejects traversal, absolute, drive, UNC, controls, aliases, and invalid file slashes in both formats', async (t) => {
  const hostile = [
    '../escape', 'a/../../escape', '..', 'a/..', '/absolute', '\\absolute', '//server/share',
    '\\\\server\\share', 'C:\\absolute', 'C:/absolute', 'C:relative', 'a//b', 'a/./b',
    'a\u0000b', 'a\rb', 'a\nb', 'a\tb', '', `${'a'.repeat(256)}/x`, 'file/'
  ];
  for (const name of hostile) {
    const zipEntry = { name, content: 'x', directory: name.endsWith('/') && name !== 'file/' };
    await assert.rejects(() => validateBytes(t, buildZip([zipEntry, { name: 'CLIProxyAPI.exe', content: 'ok' }]), 'zip', 'CLIProxyAPI.exe'), unsafe, `ZIP ${JSON.stringify(name)}`);
    const tarEntry = { name, content: 'x', directory: name.endsWith('/') && name !== 'file/' };
    await assert.rejects(() => validateBytes(t, buildTarGz([tarEntry, { name: 'CLIProxyAPI', content: 'ok' }]), 'tar.gz', 'CLIProxyAPI'), unsafe, `TAR ${JSON.stringify(name)}`);
  }
});

test('rejects separator, NFC, case, Windows trailing-dot, and type collisions for the target platform', async (t) => {
  const collisions = [
    ['a/b', 'a\\b'],
    ['caf\u00e9', 'cafe\u0301'],
    ['A/file', 'a/file'],
    ['dir/name', 'dir/name.'],
    ['same', 'same'],
    ['node', 'node/']
  ];
  for (const [left, right] of collisions) {
    const entries = [
      { name: left, content: 'a' },
      { name: right, content: right.endsWith('/') ? '' : 'b', directory: right.endsWith('/') },
      { name: 'CLIProxyAPI.exe', content: 'ok' }
    ];
    await assert.rejects(() => validateBytes(t, buildZip(entries), 'zip', 'CLIProxyAPI.exe'), unsafe, `${left} / ${right}`);
  }
});

test('rejects ZIP central/local disagreement, critical flags, unsupported methods, special types, overlaps, and malformed directory', async (t) => {
  const hostileEntries = [
    { name: 'CLIProxyAPI.exe', localName: 'different.exe', content: 'x' },
    { name: 'CLIProxyAPI.exe', flags: 1, content: 'x' },
    { name: 'CLIProxyAPI.exe', flags: 0x20, content: 'x' },
    { name: 'CLIProxyAPI.exe', method: 12, compressed: Buffer.from('x'), content: 'x' },
    { name: 'CLIProxyAPI.exe', externalAttributes: 0xa1ff0000, content: 'x' },
    { name: 'CLIProxyAPI.exe', localOffset: 1, content: 'x' },
    { name: 'dir', directory: true }
  ];
  for (const entry of hostileEntries) {
    await assert.rejects(() => validateBytes(t, buildZip([entry]), 'zip', 'CLIProxyAPI.exe'), unsafe);
  }
  for (const bytes of [
    buildZip(validZipEntries).subarray(0, -1),
    buildZip(validZipEntries, { centralOffset: 0xffffffff }),
    buildZip(validZipEntries, { trailing: 'garbage' })
  ]) await assert.rejects(() => validateBytes(t, bytes, 'zip', 'CLIProxyAPI.exe'), unsafe);
});

test('rejects ZIP64 sentinels and declared payload metadata outside the archive', async (t) => {
  const zip64 = buildZip([{ name: 'CLIProxyAPI.exe', content: 'x', size: 0xffffffff }]);
  const outside = buildZip([{ name: 'CLIProxyAPI.exe', content: 'x', compressedSize: 100 }]);
  await assert.rejects(() => validateBytes(t, zip64, 'zip', 'CLIProxyAPI.exe'), unsafe);
  await assert.rejects(() => validateBytes(t, outside, 'zip', 'CLIProxyAPI.exe'), unsafe);
});

test('rejects invalid GZIP framing/trailer, TAR truncation/checksum/end markers, and trailing members', async (t) => {
  const tar = buildTar(validTarEntries);
  const invalid = [
    Buffer.from('not-gzip'),
    buildGzip(tar, { method: 7 }),
    buildGzip(tar, { crc: 1 }),
    buildGzip(tar, { size: 1 }),
    buildGzip(tar, { trailing: 'x' }),
    buildGzip(buildTar(validTarEntries, { missingEnd: true })),
    buildGzip(buildTar([{ name: 'CLIProxyAPI', content: 'x', badChecksum: true }]))
  ];
  for (const bytes of invalid) await assert.rejects(() => validateBytes(t, bytes, 'tar.gz', 'CLIProxyAPI'), unsafe);
});

test('rejects TAR links, devices, FIFO, sparse, socket, global/PAX unknown, and malformed numeric fields', async (t) => {
  for (const type of ['1', '2', '3', '4', '6', '7', 'S', 'V', 'g', '9']) {
    await assert.rejects(
      () => validateBytes(t, buildTarGz([{ name: 'CLIProxyAPI', content: '', type }]), 'tar.gz', 'CLIProxyAPI'),
      unsafe,
      `type ${type}`
    );
  }
  const malformed = buildTar([{ name: 'CLIProxyAPI', content: 'x' }]);
  malformed.fill(0xff, 124, 136);
  await assert.rejects(() => validateBytes(t, buildGzip(malformed), 'tar.gz', 'CLIProxyAPI'), unsafe);
});

test('accepts only bounded PAX path and size records and reapplies path safety after overrides', async (t) => {
  const validPath = `long/${'a'.repeat(90)}/CLIProxyAPI`;
  const valid = buildTarGz([
    { name: 'PaxHeader', type: 'x', content: paxRecord('path', validPath) },
    { name: 'placeholder', content: 'candidate', mode: 0o755 }
  ]);
  const plan = await validateBytes(t, valid, 'tar.gz', 'CLIProxyAPI');
  assert.equal(plan.candidate.path, validPath);

  const hostile = [
    paxRecord('path', '../CLIProxyAPI'),
    paxRecord('linkpath', 'outside'),
    Buffer.from('9 path=x\n'),
    Buffer.concat([paxRecord('path', 'CLIProxyAPI'), paxRecord('path', 'other')]),
    paxRecord('GNU.sparse.map', '0,1')
  ];
  for (const content of hostile) {
    const bytes = buildTarGz([{ name: 'PaxHeader', type: 'x', content }, { name: 'placeholder', content: 'candidate' }]);
    await assert.rejects(() => validateBytes(t, bytes, 'tar.gz', 'CLIProxyAPI'), unsafe);
  }
});

test('enforces checked count, expanded, per-entry, compressed, and ratio boundaries', async (t) => {
  const entries = [{ name: 'CLIProxyAPI.exe', content: '1234' }, { name: 'data', content: '12' }];
  const bytes = buildZip(entries);
  const base = { archiveBytes: bytes.length, entries: 2, expandedBytes: 6, entryBytes: 4, expansionRatio: 4 };
  await validateBytes(t, bytes, 'zip', 'CLIProxyAPI.exe', { limits: base });
  for (const limits of [
    { ...base, archiveBytes: bytes.length - 1 },
    { ...base, entries: 1 },
    { ...base, expandedBytes: 5 },
    { ...base, entryBytes: 3 },
    { ...base, expandedBytes: Number.NaN },
    { ...base, entryBytes: -1 },
    { ...base, entries: Number.MAX_SAFE_INTEGER + 1 }
  ]) await assert.rejects(() => validateBytes(t, bytes, 'zip', 'CLIProxyAPI.exe', { limits }), unsafe);
  const ratioBytes = buildZip([{ name: 'CLIProxyAPI.exe', content: 'x'.repeat(200), method: 8 }]);
  await assert.rejects(() => validateBytes(t, ratioBytes, 'zip', 'CLIProxyAPI.exe', {
    limits: { ...base, archiveBytes: ratioBytes.length, entries: 1, expandedBytes: 200, entryBytes: 200, expansionRatio: 1 }
  }), unsafe);
});

test('publishes the exact fixed limits', () => {
  assert.deepEqual(ARCHIVE_LIMITS, {
    archiveBytes: 268435456,
    entries: 2048,
    expandedBytes: 536870912,
    entryBytes: 268435456,
    expansionRatio: 100,
    extractionDeadlineMs: 120000,
    outputBytes: 65536,
    pathBytes: 4096,
    componentBytes: 255
  });
});
