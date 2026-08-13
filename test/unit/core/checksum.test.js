import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

import { ClaudexError } from '../../../src/core/errors.js';
import { parseChecksumManifest, verifySha256 } from '../../../src/core/checksum.js';
import { downloadVerifiedRelease, resolveReleaseAsset } from '../../../src/core/release.js';
import { createReleaseHttp } from '../../support/release-server.js';

const RELEASE_ORIGIN = 'https://github.com/router-for-me/CLIProxyAPI/releases/download/v7.2.130';
const CHECKSUM_URL = `${RELEASE_ORIGIN}/checksums.txt`;
const HELLO_DIGEST = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';

function assetDescriptor({ size = 5 } = {}) {
  const resolved = resolveReleaseAsset({
    version: '7.2.130',
    platform: { platform: 'win32', arch: 'x64' }
  });
  return {
    ...resolved,
    size
  };
}

function releaseDescriptor(asset) {
  return {
    version: '7.2.130',
    tag: 'v7.2.130',
    asset,
    checksumAsset: Object.freeze({
      name: 'checksums.txt',
      url: CHECKSUM_URL,
      size: 1_024,
      kind: 'checksum',
      contentType: 'text/plain'
    })
  };
}

async function temporaryStaging(t) {
  const root = await mkdtemp(join(tmpdir(), 'claudex-release-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

function expectsIntegrityFailure(error) {
  return error instanceof ClaudexError && error.code === 'CHECKSUM_MISMATCH';
}

test('parses exactly one lowercase or uppercase SHA-256 record for the selected basename', () => {
  const asset = assetDescriptor();
  const lowercase = `${HELLO_DIGEST}  ${asset.name}\n`;
  const uppercase = `${HELLO_DIGEST.toUpperCase()} *${asset.name}\r\n`;

  assert.equal(parseChecksumManifest(lowercase, asset.name), HELLO_DIGEST);
  assert.equal(parseChecksumManifest(uppercase, asset.name), HELLO_DIGEST);
  assert.deepEqual(verifySha256(Buffer.from('hello'), HELLO_DIGEST, asset.name), {
    assetName: asset.name,
    bytes: 5,
    sha256: HELLO_DIGEST
  });
});

test('rejects absent, duplicate, malformed, and path-bearing checksum rows without leaking manifest text', () => {
  const asset = assetDescriptor();
  const cases = [
    `${HELLO_DIGEST}  CLIProxyAPI_7.2.130_windows_aarch64.zip\n`,
    `${HELLO_DIGEST}  ${asset.name}\n${HELLO_DIGEST}  ${asset.name}\n`,
    `not-a-digest  ${asset.name}\n`,
    `${HELLO_DIGEST}  ../${asset.name}\n`,
    `${HELLO_DIGEST}  ${asset.name}\u0000canary\n`
  ];

  for (const manifest of cases) {
    assert.throws(
      () => parseChecksumManifest(manifest, asset.name),
      (error) => {
        assert.ok(expectsIntegrityFailure(error));
        assert.doesNotMatch(`${error.message} ${JSON.stringify(error.details)}`, /canary|not-a-digest/i);
        return true;
      }
    );
  }
});

test('downloads the checksum before the archive and atomically publishes only a verified archive', async (t) => {
  const root = await temporaryStaging(t);
  const asset = assetDescriptor();
  const release = releaseDescriptor(asset);
  const http = createReleaseHttp({ routes: new Map([
    [CHECKSUM_URL, { headers: { 'content-length': `${HELLO_DIGEST.length + asset.name.length + 3}` }, chunks: [`${HELLO_DIGEST}  ${asset.name}\n`] }],
    [asset.url, { headers: { 'content-length': '5' }, chunks: ['hello'] }]
  ]) });
  const target = resolve(root, asset.name);
  await writeFile(target, 'previous-release');

  const verified = await downloadVerifiedRelease(release, asset, root, { http });

  assert.deepEqual(http.requests.map((request) => request.url), [CHECKSUM_URL, asset.url]);
  assert.equal(verified.path, target);
  assert.equal(verified.name, asset.name);
  assert.equal(verified.bytes, 5);
  assert.equal(verified.sha256, HELLO_DIGEST);
  assert.equal(Object.isFrozen(verified), true);
  assert.deepEqual(await readFile(target), Buffer.from('hello'));
  assert.deepEqual((await readdir(root)).filter((name) => name.endsWith('.part')), []);
});

test('rejects a digest mismatch, preserves the prior final archive, and removes only its owned partial file', async (t) => {
  const root = await temporaryStaging(t);
  const asset = assetDescriptor({ size: 6 });
  const release = releaseDescriptor(asset);
  const http = createReleaseHttp({ routes: new Map([
    [CHECKSUM_URL, { chunks: [`${HELLO_DIGEST}  ${asset.name}\n`] }],
    [asset.url, { headers: { 'content-length': '6' }, chunks: ['hello!'] }]
  ]) });
  const target = resolve(root, asset.name);
  await writeFile(target, 'known-good');
  await writeFile(join(root, 'unrelated.part'), 'preserve');

  await assert.rejects(
    () => downloadVerifiedRelease(release, asset, root, { http }),
    expectsIntegrityFailure
  );

  assert.deepEqual(await readFile(target), Buffer.from('known-good'));
  assert.deepEqual(await readFile(join(root, 'unrelated.part')), Buffer.from('preserve'));
  assert.deepEqual((await readdir(root)).filter((name) => name.startsWith(`.${asset.name}.`) && name.endsWith('.part')), []);
});

test('fails checksum parsing or a bounded archive stream before an unverified file is promoted', async (t) => {
  const root = await temporaryStaging(t);
  const asset = assetDescriptor();
  const release = releaseDescriptor(asset);
  const malformedHttp = createReleaseHttp({ routes: new Map([
    [CHECKSUM_URL, { chunks: ['malformed checksum\n'] }],
    [asset.url, { chunks: ['hello'] }]
  ]) });

  await assert.rejects(
    () => downloadVerifiedRelease(release, asset, root, { http: malformedHttp }),
    expectsIntegrityFailure
  );
  assert.deepEqual(malformedHttp.requests.map((request) => request.url), [CHECKSUM_URL]);

  const boundedHttp = createReleaseHttp({ routes: new Map([
    [CHECKSUM_URL, { chunks: [`${HELLO_DIGEST}  ${asset.name}\n`] }],
    [asset.url, { chunks: ['hello', '!'] }]
  ]) });
  await assert.rejects(
    () => downloadVerifiedRelease(release, asset, root, { http: boundedHttp, limits: { archiveBytes: 5 } }),
    (error) => error instanceof ClaudexError && error.code === 'NETWORK_FAILURE'
  );
  assert.deepEqual((await readdir(root)).filter((name) => name.endsWith('.part')), []);
});
