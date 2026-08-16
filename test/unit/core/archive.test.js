import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { ARCHIVE_LIMITS, testArchiveLimitPolicy, validateArchive } from '../../../src/core/archive.js';
import {
  buildGzip, buildTar, buildTarGz, buildZip, paxRecord, validTarEntries, validZipEntries
} from '../../support/archive-fixtures.js';

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

async function archiveFixture(t, bytes, kind, expectedExecutable, options = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'claudeyctl-archive-unit-'));
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
  return error?.code === 'ARCHIVE_UNSAFE' && !String(error.message).includes(process.env.CLAUDEY_SECRET_CANARY ?? '\0never');
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
  const descriptor = buildZip([{ name: 'CLIProxyAPI.exe', flags: 0x808, localFlags: 0x808, content: 'x' }]);
  const inconsistentDescriptor = buildZip([{ name: 'CLIProxyAPI.exe', flags: 0x808, localFlags: 0x808, content: 'x', compressedSize: 0 }]);
  await assert.rejects(() => validateBytes(t, zip64, 'zip', 'CLIProxyAPI.exe'), unsafe);
  await assert.rejects(() => validateBytes(t, outside, 'zip', 'CLIProxyAPI.exe'), unsafe);
  await assert.rejects(() => validateBytes(t, descriptor, 'zip', 'CLIProxyAPI.exe'), unsafe);
  await assert.rejects(() => validateBytes(t, inconsistentDescriptor, 'zip', 'CLIProxyAPI.exe'), unsafe);
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
  const paxSize = buildTarGz([
    { name: 'PaxHeader', type: 'x', content: paxRecord('size', '9') },
    { name: 'CLIProxyAPI', content: 'candidate', mode: 0o755 }
  ]);
  assert.equal((await validateBytes(t, paxSize, 'tar.gz', 'CLIProxyAPI')).candidate.size, 9);
  const paxDisagreement = buildTarGz([
    { name: 'PaxHeader', type: 'x', content: paxRecord('size', '8') },
    { name: 'CLIProxyAPI', content: 'candidate', mode: 0o755 }
  ]);
  await assert.rejects(() => validateBytes(t, paxDisagreement, 'tar.gz', 'CLIProxyAPI'), unsafe);
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
test('fixed production ceilings cannot be raised by caller overrides', async (t) => {
  const bytes = buildZip(validZipEntries);
  for (const [key, value] of Object.entries(ARCHIVE_LIMITS)) {
    await assert.rejects(() => validateBytes(t, bytes, 'zip', 'CLIProxyAPI.exe', {
      limits: { [key]: value + 1 }
    }), unsafe, key);
  }
});

test('checks exact numeric boundaries through a metadata-only internal seam', () => {
  assert.deepEqual(testArchiveLimitPolicy([{ size: 268435456 }, { size: 268435456 }], 5368710), {
    entryCount: 2, expandedBytes: 536870912
  });
  for (const input of [
    { entries: Array.from({ length: 2049 }, () => ({ size: 0 })), compressed: 1 },
    { entries: [{ size: 268435457 }], compressed: 268435457 },
    { entries: [{ size: 268435456 }, { size: 268435456 }, { size: 1 }], compressed: 5368710 },
    { entries: [{ size: 101 }], compressed: 1 },
    { entries: [{ size: 1 }], compressed: 0 },
    { entries: [{ size: Number.MAX_SAFE_INTEGER }], compressed: 1 }
  ]) assert.throws(() => testArchiveLimitPolicy(input.entries, input.compressed), unsafe);
  assert.doesNotThrow(() => testArchiveLimitPolicy(Array.from({ length: 2048 }, () => ({ size: 0 })), 1));
  assert.doesNotThrow(() => testArchiveLimitPolicy([{ size: 100 }], 1));
  assert.doesNotThrow(() => testArchiveLimitPolicy([{ size: 0 }], 1, undefined, 268435456));
  assert.throws(() => testArchiveLimitPolicy([{ size: 0 }], 1, undefined, 268435457), unsafe);
});

test('verified descriptor path enforces compressed ceiling at exact and plus one without allocation', async (t) => {
  const bytes = buildZip(validZipEntries);
  const fixture = await archiveFixture(t, bytes, 'zip', 'CLIProxyAPI.exe');
  const archiveStats = await fs.lstat(fixture.descriptor.path);
  let archiveReads = 0;
  const fsApi = {
    ...fs,
    lstat: async (target, options) => target === fixture.descriptor.path
      ? new Proxy(archiveStats, { get: (value, key) => key === 'size' ? ARCHIVE_LIMITS.archiveBytes : Reflect.get(value, key, value) })
      : fs.lstat(target, options),
    readFile: async (target, ...args) => {
      if (target === fixture.descriptor.path) archiveReads += 1;
      return fs.readFile(target, ...args);
    }
  };
  const exact = Object.freeze({ ...fixture.descriptor, bytes: ARCHIVE_LIMITS.archiveBytes });
  await assert.rejects(
    () => validateArchive(exact, fixture.expectedExecutable, undefined, { ...fixture.adapter, fsApi }),
    unsafe
  );
  assert.equal(archiveReads, 1);

  archiveReads = 0;
  const over = Object.freeze({ ...fixture.descriptor, bytes: ARCHIVE_LIMITS.archiveBytes + 1 });
  await assert.rejects(
    () => validateArchive(over, fixture.expectedExecutable, undefined, { ...fixture.adapter, fsApi }),
    unsafe
  );
  assert.equal(archiveReads, 0);
});
test('TAR entry ceiling counts PAX metadata headers at exact 2048 and rejects 2049', async (t) => {
  const paxAndCandidate = [
    { name: 'PaxHeader', type: 'x', content: paxRecord('path', 'bin/CLIProxyAPI') },
    { name: 'placeholder', content: 'candidate', mode: 0o755 }
  ];
  const filler = (count) => Array.from({ length: count }, (_, index) => ({ name: `data/${index}`, content: '' }));
  const exact = buildTarGz([...paxAndCandidate, ...filler(2046)]);
  const plan = await validateBytes(t, exact, 'tar.gz', 'CLIProxyAPI');
  assert.equal(plan.entries.length, 2047);
  const over = buildTarGz([...paxAndCandidate, ...filler(2047)]);
  await assert.rejects(() => validateBytes(t, over, 'tar.gz', 'CLIProxyAPI'), unsafe);
});
test('validates the complete supported ustar header and refuses hidden link metadata', async (t) => {
  for (const hostile of [
    { name: 'CLIProxyAPI', content: 'candidate', mode: 0o755, magic: 'bad\0\0\0' },
    { name: 'CLIProxyAPI', content: 'candidate', mode: 0o755, version: '99' },
    { name: 'CLIProxyAPI', content: 'candidate', mode: 0o755, linkName: 'outside' },
    { name: 'CLIProxyAPI', content: 'candidate', mode: 0o755, userName: 'owner' }
  ]) await assert.rejects(() => validateBytes(t, buildTarGz([hostile]), 'tar.gz', 'CLIProxyAPI'), unsafe);
});

test('parses PAX record lengths as bytes and canonicalizes multibyte collisions', async (t) => {
  const multibyte = buildTarGz([
    { name: 'PaxHeader', type: 'x', content: paxRecord('path', 'd\u00edr/CLIProxyAPI') },
    { name: 'placeholder', content: 'candidate', mode: 0o755 }
  ]);
  assert.equal((await validateBytes(t, multibyte, 'tar.gz', 'CLIProxyAPI')).candidate.path, 'd\u00edr/CLIProxyAPI');
  const collision = buildTarGz([
    { name: 'PaxHeader', type: 'x', content: paxRecord('path', '\u03a3/CLIProxyAPI') },
    { name: 'placeholder', content: 'candidate', mode: 0o755 },
    { name: '\u03c3/CLIProxyAPI', content: 'x', mode: 0o755 }
  ]);
  await assert.rejects(() => validateBytes(t, collision, 'tar.gz', 'CLIProxyAPI', { targetPlatform: 'win32' }), unsafe);
});

test('ZIP DOS attributes use a strict allowlist for files and directories', async (t) => {
  for (const entry of [
    { name: 'CLIProxyAPI.exe', content: 'candidate', versionMadeBy: 20, externalAttributes: 0x400 },
    { name: 'dir/', directory: true, versionMadeBy: 20, externalAttributes: 0x410 },
    { name: 'CLIProxyAPI.exe', content: 'candidate', versionMadeBy: 20, externalAttributes: 0x420 },
    { name: 'CLIProxyAPI.exe', content: 'candidate', versionMadeBy: 0x031e, externalAttributes: 0x81a40400 },
    { name: 'dir/', directory: true, versionMadeBy: 0x031e, externalAttributes: 0x41ed0410 }
  ]) await assert.rejects(() => validateBytes(t, buildZip([entry]), 'zip', 'CLIProxyAPI.exe'), unsafe);
});

test('plan destinations remain relative until bound to the exact extraction directory', async (t) => {
  const plan = await validateBytes(t, buildTarGz(validTarEntries), 'tar.gz', 'CLIProxyAPI');
  assert.equal(plan.entries.every((entry) => !Object.hasOwn(entry, 'destination')), true);
});
