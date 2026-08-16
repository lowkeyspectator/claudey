import assert from 'node:assert/strict';
import test from 'node:test';

import {
  canonicalManifestBytes,
  createInstallationSecrets,
  deriveApprovalKey,
  loadOrCreateInstallationSecrets,
  planOwnedRemoval,
  removeVerifiedOwnedFile,
  verifyManifest,
  writeManifest
} from '../../../src/core/manifest.js';
import { Secret } from '../../../src/core/secrets.js';

const ROOTS = Object.freeze({
  managerRoot: 'C:\\Users\\Casey\\AppData\\Local\\claudexctl',
  stateRoot: 'C:\\Users\\Casey\\AppData\\Local\\claudexctl\\state',
  userBinRoot: 'C:\\Users\\Casey\\AppData\\Local\\claudexctl\\bin',
  ownedPluginRoots: ['C:\\Users\\Casey\\AppData\\Local\\claudexctl\\plugins']
});
const FILE_HASH = 'a'.repeat(64);
const CANONICAL = '{"files":[{"relativePath":"releases/7.2.130/CLIProxyAPI.exe","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","type":"file"}],"installationId":"11111111-1111-4111-8111-111111111111","managedRoots":{"managerRoot":"C:\\\\Users\\\\Casey\\\\AppData\\\\Local\\\\claudexctl","ownedPluginRoots":["C:\\\\Users\\\\Casey\\\\AppData\\\\Local\\\\claudexctl\\\\plugins"],"stateRoot":"C:\\\\Users\\\\Casey\\\\AppData\\\\Local\\\\claudexctl\\\\state","userBinRoot":"C:\\\\Users\\\\Casey\\\\AppData\\\\Local\\\\claudexctl\\\\bin"},"platform":{"family":"windows","runtimeArch":"x64"},"schemaVersion":1}';
const HMAC = 'CgHxuFvgsUpkHZ-jPqd-S28pNY7r7R535lzgSZ332co';

function unsignedManifest(overrides = {}) {
  return {
    schemaVersion: 1,
    installationId: '11111111-1111-4111-8111-111111111111',
    platform: { family: 'windows', runtimeArch: 'x64' },
    managedRoots: { ...ROOTS, ownedPluginRoots: [...ROOTS.ownedPluginRoots] },
    files: [{ relativePath: 'releases/7.2.130/CLIProxyAPI.exe', type: 'file', sha256: FILE_HASH }],
    ...overrides
  };
}

function signedManifest(overrides = {}) {
  return { ...unsignedManifest(overrides), hmac: HMAC };
}

function key(byte = 0x22) {
  return Secret.fromBytes(Buffer.alloc(32, byte));
}

test('creates independent 32-byte bearer and manifest secrets from two RNG calls', () => {
  const outputs = [Buffer.alloc(32, 0x11), Buffer.alloc(32, 0x22)];
  const requested = [];
  const secrets = createInstallationSecrets((size) => {
    requested.push(size);
    return outputs.shift();
  });
  assert.deepEqual(requested, [32, 32]);
  assert.equal(secrets.bearerToken.withValue((bytes) => Buffer.from(bytes).toString('base64url')),
    'ERERERERERERERERERERERERERERERERERERERERERE');
  assert.deepEqual(secrets.manifestKey.withValue((bytes) => Buffer.from(bytes)), Buffer.alloc(32, 0x22));
  assert.notEqual(secrets.bearerToken, secrets.manifestKey);
});

test('fails before persistence for short or repeated RNG output', async () => {
  assert.throws(() => createInstallationSecrets(() => Buffer.alloc(31, 0x11)),
    (error) => error?.code === 'SAFETY_REFUSAL');
  assert.throws(() => createInstallationSecrets(() => Buffer.alloc(32, 0x11)),
    (error) => error?.code === 'SAFETY_REFUSAL');
  let writes = 0;
  await assert.rejects(() => loadOrCreateInstallationSecrets({
    readExisting: async () => null,
    persistCreated: async () => { writes += 1; }
  }, { randomBytes: () => Buffer.alloc(31) }), (error) => error?.code === 'SAFETY_REFUSAL');
  assert.equal(writes, 0);
});

test('preserves existing protected secrets byte-identically without rotating', async () => {
  const existing = { bearerToken: key(0x41), manifestKey: key(0x42) };
  let rngCalls = 0;
  let writes = 0;
  const loaded = await loadOrCreateInstallationSecrets({
    readExisting: async () => existing,
    persistCreated: async () => { writes += 1; }
  }, { randomBytes: () => { rngCalls += 1; return Buffer.alloc(32); } });
  assert.equal(loaded, existing);
  assert.equal(rngCalls, 0);
  assert.equal(writes, 0);
});

test('canonical manifest bytes are recursively sorted and HMAC verifies only with the manifest key', () => {
  const manifest = signedManifest();
  assert.equal(canonicalManifestBytes(manifest).toString('utf8'), CANONICAL);
  assert.equal(verifyManifest(manifest, key(), { fixedPaths: ROOTS }), manifest);
  assert.throws(() => verifyManifest(signedManifest(), key(0x11), { fixedPaths: ROOTS }),
    (error) => error?.code === 'SAFETY_REFUSAL');
  const approval = deriveApprovalKey(key());
  assert.equal(approval.withValue((bytes) => Buffer.from(bytes).toString('base64url')),
    'pWeNpmY61IFYy39qZfUZjEHONcDmtT-n6gPoTqdaCMw');
  assert.notEqual(approval.withValue((bytes) => Buffer.from(bytes).toString('hex')), Buffer.alloc(32, 0x22).toString('hex'));
});

test('uses timing-safe comparison only after decoded MAC lengths match', () => {
  let comparisons = 0;
  const cryptoApi = {
    timingSafeEqual(left, right) {
      comparisons += 1;
      return Buffer.from(left).equals(right);
    }
  };
  assert.throws(() => verifyManifest({ ...signedManifest(), hmac: 'AA' }, key(), { fixedPaths: ROOTS, cryptoApi }),
    (error) => error?.code === 'SAFETY_REFUSAL');
  assert.equal(comparisons, 0);
  assert.throws(() => verifyManifest({ ...signedManifest(), hmac: `${HMAC.slice(0, -1)}A` }, key(), { fixedPaths: ROOTS, cryptoApi }),
    (error) => error?.code === 'SAFETY_REFUSAL');
  assert.equal(comparisons, 1);
});

test('refuses unknown fields, invalid IDs, unsafe file ownership, OAuth entries, and foreign fixed roots', () => {
  const badFiles = [
    { relativePath: '../escape', type: 'file', sha256: FILE_HASH },
    { relativePath: 'C:\\escape', type: 'file', sha256: FILE_HASH },
    { relativePath: 'auth/oauth.json', type: 'file', sha256: FILE_HASH },
    { relativePath: 'safe', type: 'file', sha256: 'A'.repeat(64) },
    { relativePath: 'safe', type: 'file', sha256: FILE_HASH, extra: true }
  ];
  const cases = [
    { ...signedManifest(), extra: true },
    signedManifest({ installationId: 'not-a-uuid' }),
    ...badFiles.map((file) => signedManifest({ files: [file] })),
    signedManifest({ files: [badFiles[0], badFiles[0]] }),
    signedManifest({ managedRoots: { ...ROOTS, managerRoot: 'D:\\foreign' } })
  ];
  for (const manifest of cases) {
    assert.throws(() => verifyManifest(manifest, key(), { fixedPaths: ROOTS }),
      (error) => error?.code === 'SAFETY_REFUSAL');
  }
});

test('writes only authenticated inventory through atomic replacement without secret canaries', async () => {
  const writes = [];
  const tokenCanary = 'TASK4_BEARER_CANARY';
  const keyCanary = Buffer.from('TASK4_MANIFEST_KEY_CANARY_123456').subarray(0, 32);
  await writeManifest(unsignedManifest(), Secret.fromBytes(keyCanary), { ...ROOTS }, {
    assertLockHeld: async () => undefined,
    atomicReplace: async (request) => { writes.push(request); return 'manifest'; }
  });
  assert.equal(writes.length, 1);
  assert.equal(writes[0].root, ROOTS.stateRoot);
  assert.equal(writes[0].mode, 0o600);
  const serialized = writes[0].bytes.toString('utf8');
  assert.equal(serialized.endsWith('\n'), true);
  assert.equal(serialized.includes(tokenCanary), false);
  assert.equal(serialized.includes(keyCanary.toString('utf8')), false);
  assert.deepEqual(Object.keys(JSON.parse(serialized)).sort(),
    ['files', 'hmac', 'installationId', 'managedRoots', 'platform', 'schemaVersion']);
});

test('rejects exact protected directory segments with minimal fixed paths without substring matching', async () => {
  for (const relativePath of ['auth/account.json', 'oauth/account.json', 'config/settings.json']) {
    let writes = 0;
    await assert.rejects(() => writeManifest(unsignedManifest({
      files: [{ relativePath, type: 'file', sha256: FILE_HASH }]
    }), key(), ROOTS, {
      assertLockHeld: async () => undefined,
      atomicReplace: async () => { writes += 1; }
    }), (error) => error?.code === 'SAFETY_REFUSAL', relativePath);
    assert.equal(writes, 0, relativePath);
  }

  const admitted = await writeManifest(unsignedManifest({ files: [
    { relativePath: 'releases/authentication-helper.exe', type: 'file', sha256: FILE_HASH },
    { relativePath: 'releases/oauth2-support.dll', type: 'file', sha256: 'b'.repeat(64) },
    { relativePath: 'releases/configuration-guide.txt', type: 'file', sha256: 'c'.repeat(64) }
  ] }), key(), ROOTS, {
    assertLockHeld: async () => undefined,
    atomicReplace: async () => undefined
  });
  assert.equal(admitted.files.length, 3);
});
test('rejects adapter-protected roots and credential filenames without banning ordinary release files', async () => {
  const protectedPaths = {
    ...ROOTS,
    configRoot: 'C:\\Users\\Casey\\AppData\\Local\\claudexctl\\settings',
    authRoot: 'C:\\Users\\Casey\\AppData\\Local\\claudexctl\\credentials',
    protectedRoots: ['C:\\Users\\Casey\\AppData\\Local\\claudexctl\\private-state']
  };
  const unsafePaths = [
    'settings/user.json',
    'credentials/account.json',
    'private-state/pending.json',
    'releases/7.2.130/config.yaml',
    'releases/7.2.130/oauth-token.json'
  ];
  for (const relativePath of unsafePaths) {
    let writes = 0;
    await assert.rejects(() => writeManifest(unsignedManifest({
      files: [{ relativePath, type: 'file', sha256: FILE_HASH }]
    }), key(), protectedPaths, {
      assertLockHeld: async () => undefined,
      atomicReplace: async () => { writes += 1; }
    }), (error) => error?.code === 'SAFETY_REFUSAL', relativePath);
    assert.equal(writes, 0, relativePath);
  }

  const admitted = await writeManifest(unsignedManifest({ files: [
    { relativePath: 'releases/7.2.130/config-helper.exe', type: 'file', sha256: FILE_HASH },
    { relativePath: 'releases/7.2.130/oauth-support.dll', type: 'file', sha256: 'b'.repeat(64) }
  ] }), key(), protectedPaths, {
    assertLockHeld: async () => undefined,
    atomicReplace: async () => undefined
  });
  assert.equal(admitted.files.length, 2);
});
test('plans removal only for authenticated unchanged files and preserves modified or missing files', async () => {
  const manifest = verifyManifest(signedManifest(), key(), { fixedPaths: ROOTS });
  const states = [
    { exists: true, canonicalPath: 'C:\\Users\\Casey\\AppData\\Local\\claudexctl\\releases\\7.2.130\\CLIProxyAPI.exe', type: 'file', sha256: FILE_HASH },
    { exists: true, canonicalPath: 'C:\\Users\\Casey\\AppData\\Local\\claudexctl\\releases\\7.2.130\\CLIProxyAPI.exe', type: 'file', sha256: 'b'.repeat(64) },
    { exists: false }
  ];
  const expected = [
    { action: 'remove', reason: 'unchanged' },
    { action: 'preserve', reason: 'modified' },
    { action: 'preserve', reason: 'missing' }
  ];
  for (let index = 0; index < states.length; index += 1) {
    const plan = await planOwnedRemoval(manifest, ROOTS, {
      platform: 'win32',
      inspectCandidate: async () => states[index]
    });
    assert.equal(plan.length, 1);
    assert.equal(plan[0].action, expected[index].action);
    assert.equal(plan[0].reason, expected[index].reason);
  }
});

test('owned-file removal rechecks the planned target under lock and never unlinks a swapped file', async () => {
  const manifest = verifyManifest(signedManifest(), key(), { fixedPaths: ROOTS });
  const unchanged = {
    exists: true,
    canonicalPath: 'C:\\Users\\Casey\\AppData\\Local\\claudexctl\\releases\\7.2.130\\CLIProxyAPI.exe',
    type: 'file',
    sha256: FILE_HASH
  };
  const plan = await planOwnedRemoval(manifest, ROOTS, {
    platform: 'win32', inspectCandidate: async () => unchanged
  });
  assert.equal(plan[0].action, 'remove');

  for (const changed of [
    { ...unchanged, sha256: 'b'.repeat(64) },
    { ...unchanged, type: 'directory' },
    { ...unchanged, canonicalPath: 'C:\\Users\\Casey\\AppData\\Local\\claudexctl\\foreign.exe' }
  ]) {
    const unlinked = [];
    const result = await removeVerifiedOwnedFile(
      manifest,
      'releases/7.2.130/CLIProxyAPI.exe',
      ROOTS,
      {
        platform: 'win32',
        assertLockHeld: async () => undefined,
        inspectCandidate: async () => changed,
        unlink: async (target) => { unlinked.push(target); }
      }
    );
    assert.deepEqual(result, { action: 'preserve', reason: 'modified', path: unchanged.canonicalPath });
    assert.deepEqual(unlinked, []);
  }

  let linkUnlinks = 0;
  await assert.rejects(() => removeVerifiedOwnedFile(
    manifest,
    'releases/7.2.130/CLIProxyAPI.exe',
    ROOTS,
    {
      platform: 'win32',
      assertLockHeld: async () => undefined,
      inspectCandidate: async () => { throw Object.assign(new Error('link swap'), { code: 'SAFETY_REFUSAL' }); },
      unlink: async () => { linkUnlinks += 1; }
    }
  ), (error) => error?.code === 'SAFETY_REFUSAL');
  assert.equal(linkUnlinks, 0);

  const removed = [];
  const result = await removeVerifiedOwnedFile(
    manifest,
    'releases/7.2.130/CLIProxyAPI.exe',
    ROOTS,
    {
      platform: 'win32',
      assertLockHeld: async () => undefined,
      inspectCandidate: async () => unchanged,
      unlink: async (target) => { removed.push(target); }
    }
  );
  assert.deepEqual(result, { action: 'removed', reason: 'unchanged', path: unchanged.canonicalPath });
  assert.deepEqual(removed, [unchanged.canonicalPath]);
});
test('refuses unauthenticated inventories and propagates a live link-swap safety refusal', async () => {
  await assert.rejects(() => planOwnedRemoval(signedManifest(), ROOTS, {
    platform: 'win32', inspectCandidate: async () => ({ exists: false })
  }), (error) => error?.code === 'SAFETY_REFUSAL');
  const manifest = verifyManifest(signedManifest(), key(), { fixedPaths: ROOTS });
  await assert.rejects(() => planOwnedRemoval(manifest, ROOTS, {
    platform: 'win32',
    inspectCandidate: async () => {
      const error = new Error('link swapped');
      error.code = 'SAFETY_REFUSAL';
      throw error;
    }
  }), (error) => error?.code === 'SAFETY_REFUSAL');
});
