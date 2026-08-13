import assert from 'node:assert/strict';
import test from 'node:test';

import { ClaudexError } from '../../../src/core/errors.js';
import {
  fetchOfficialResponse,
  readResponseBytes,
  resolveRelease,
  resolveReleaseAsset
} from '../../../src/core/release.js';
import { createReleaseHttp, releaseAsset, releaseRecord } from '../../support/release-server.js';

const API_ORIGIN = 'https://api.github.com';
const RELEASE_ORIGIN = 'https://github.com/router-for-me/CLIProxyAPI/releases/download';
const TAG_URL = `${API_ORIGIN}/repos/router-for-me/CLIProxyAPI/releases/tags/v7.2.130`;
const LIST_URL = `${API_ORIGIN}/repos/router-for-me/CLIProxyAPI/releases?per_page=100&page=1`;
const DIGEST_URL = `${RELEASE_ORIGIN}/v7.2.130/checksums.txt`;

function archiveUrl(name) {
  return `${RELEASE_ORIGIN}/v7.2.130/${name}`;
}

function stableRelease({ tag = 'v7.2.130', assets } = {}) {
  return releaseRecord({
    tag,
    assets: assets ?? [
      releaseAsset({
        name: 'CLIProxyAPI_7.2.130_windows_amd64.zip',
        url: archiveUrl('CLIProxyAPI_7.2.130_windows_amd64.zip'),
        contentType: 'application/zip'
      }),
      releaseAsset({ name: 'checksums.txt', url: DIGEST_URL, size: 100, contentType: 'text/plain' })
    ]
  });
}

test('maps every supported runtime target to its exact official archive filename', () => {
  const cases = [
    [{ platform: 'win32', arch: 'x64' }, 'CLIProxyAPI_7.2.130_windows_amd64.zip', 'zip'],
    [{ platform: 'win32', arch: 'arm64' }, 'CLIProxyAPI_7.2.130_windows_aarch64.zip', 'zip'],
    [{ platform: 'darwin', arch: 'x64' }, 'CLIProxyAPI_7.2.130_darwin_amd64.tar.gz', 'tar.gz'],
    [{ platform: 'darwin', arch: 'arm64' }, 'CLIProxyAPI_7.2.130_darwin_aarch64.tar.gz', 'tar.gz'],
    [{ platform: 'linux', arch: 'x64' }, 'CLIProxyAPI_7.2.130_linux_amd64.tar.gz', 'tar.gz'],
    [{ platform: 'linux', arch: 'arm64' }, 'CLIProxyAPI_7.2.130_linux_aarch64.tar.gz', 'tar.gz']
  ];

  for (const [platform, name, kind] of cases) {
    assert.deepEqual(resolveReleaseAsset({ version: 'v7.2.130', platform }), {
      version: '7.2.130',
      tag: 'v7.2.130',
      name,
      url: archiveUrl(name),
      kind,
      platform
    });
  }
});

test('resolves an explicit baseline release from the exact tag endpoint', async () => {
  const http = createReleaseHttp({ routes: new Map([[TAG_URL, { chunks: [JSON.stringify(stableRelease())] }]]) });

  const release = await resolveRelease({
    requestedVersion: '7.2.130',
    platform: { platform: 'win32', arch: 'x64' },
    http
  });

  assert.equal(http.requests.length, 1);
  assert.equal(http.requests[0].url, TAG_URL);
  assert.equal(http.requests[0].deadlineMs, 30_000);
  assert.equal(release.version, '7.2.130');
  assert.equal(release.tag, 'v7.2.130');
  assert.equal(release.asset.name, 'CLIProxyAPI_7.2.130_windows_amd64.zip');
  assert.equal(release.checksumAsset.url, DIGEST_URL);
  assert.equal(Object.hasOwn(release, 'assets'), false);
});

test('rejects malformed or below-baseline explicit versions before any HTTP request', async () => {
  const invalid = ['', '7.2', 'v7.2.130.1', 'v7.2.130-rc.1', ' 7.2.130', '7.2.129'];

  for (const requestedVersion of invalid) {
    const http = createReleaseHttp();
    await assert.rejects(
      () => resolveRelease({ requestedVersion, platform: { platform: 'win32', arch: 'x64' }, http }),
      (error) => error instanceof ClaudexError && ['USAGE_ERROR', 'PREREQUISITE_MISSING'].includes(error.code)
    );
    assert.equal(http.requests.length, 0, requestedVersion);
  }
});

test('rejects draft, prerelease, and malformed explicit release metadata', async () => {
  const fixtures = [
    releaseRecord({ draft: true }),
    releaseRecord({ prerelease: true }),
    { tag_name: 'v7.2.130', draft: false, prerelease: false, assets: 'not-an-array' }
  ];

  for (const fixture of fixtures) {
    const http = createReleaseHttp({ routes: new Map([[TAG_URL, { chunks: [JSON.stringify(fixture)] }]]) });
    await assert.rejects(
      () => resolveRelease({ requestedVersion: 'v7.2.130', platform: { platform: 'win32', arch: 'x64' }, http }),
      (error) => error instanceof ClaudexError && error.code === 'NETWORK_FAILURE'
    );
  }
});

test('selects the highest stable semver across paged release metadata', async () => {
  const pageTwo = `${API_ORIGIN}/repos/router-for-me/CLIProxyAPI/releases?per_page=100&page=2`;
  const http = createReleaseHttp({ routes: new Map([
    [LIST_URL, {
      headers: { link: `<${pageTwo}>; rel="next"` },
      chunks: [JSON.stringify([
        releaseRecord({ tag: 'v7.2.129' }),
        releaseRecord({ tag: 'v9.0.0', draft: true }),
        releaseRecord({ tag: 'v8.0.0-rc.1', prerelease: true })
      ])]
    }],
    [pageTwo, { chunks: [JSON.stringify([stableRelease()])] }]
  ]) });

  const release = await resolveRelease({ platform: { platform: 'win32', arch: 'x64' }, http });

  assert.equal(release.tag, 'v7.2.130');
  assert.deepEqual(http.requests.map((request) => request.url), [LIST_URL, pageTwo]);
});

test('rejects duplicate stable versions and unsafe release assets', async () => {
  const duplicate = createReleaseHttp({ routes: new Map([[LIST_URL, { chunks: [JSON.stringify([stableRelease(), stableRelease()])] }]]) });
  await assert.rejects(
    () => resolveRelease({ platform: { platform: 'win32', arch: 'x64' }, http: duplicate }),
    (error) => error instanceof ClaudexError && error.code === 'NETWORK_FAILURE'
  );

  const unsafe = stableRelease({ assets: [
    releaseAsset({
      name: 'CLIProxyAPI_7.2.130_windows_amd64.zip',
      url: 'https://evil.example/CLIProxyAPI_7.2.130_windows_amd64.zip',
      contentType: 'application/zip'
    }),
    releaseAsset({ name: 'checksums.txt', url: DIGEST_URL, contentType: 'text/plain' })
  ] });
  const http = createReleaseHttp({ routes: new Map([[TAG_URL, { chunks: [JSON.stringify(unsafe)] }]]) });
  await assert.rejects(
    () => resolveRelease({ requestedVersion: '7.2.130', platform: { platform: 'win32', arch: 'x64' }, http }),
    (error) => error instanceof ClaudexError && error.code === 'NETWORK_FAILURE'
  );
});

test('rejects a release asset URL that carries a query token', async () => {
  const archiveName = 'CLIProxyAPI_7.2.130_windows_amd64.zip';
  const release = stableRelease({ assets: [
    releaseAsset({
      name: archiveName,
      url: `${archiveUrl(archiveName)}?token=opaque`,
      contentType: 'application/zip'
    }),
    releaseAsset({ name: 'checksums.txt', url: DIGEST_URL, contentType: 'text/plain' })
  ] });
  const http = createReleaseHttp({ routes: new Map([[TAG_URL, { chunks: [JSON.stringify(release)] }]]) });

  await assert.rejects(
    () => resolveRelease({ requestedVersion: '7.2.130', platform: { platform: 'win32', arch: 'x64' }, http }),
    (error) => error instanceof ClaudexError && error.code === 'NETWORK_FAILURE'
  );
});
test('rejects a same-target _no-plugin archive even when the exact archive exists', async () => {
  const noPluginName = 'CLIProxyAPI_7.2.130_windows_amd64_no-plugin.zip';
  const release = stableRelease({ assets: [
    releaseAsset({
      name: 'CLIProxyAPI_7.2.130_windows_amd64.zip',
      url: archiveUrl('CLIProxyAPI_7.2.130_windows_amd64.zip'),
      contentType: 'application/zip'
    }),
    releaseAsset({ name: noPluginName, url: archiveUrl(noPluginName), contentType: 'application/zip' }),
    releaseAsset({ name: 'checksums.txt', url: DIGEST_URL, contentType: 'text/plain' })
  ] });
  const http = createReleaseHttp({ routes: new Map([[TAG_URL, { chunks: [JSON.stringify(release)] }]]) });

  await assert.rejects(
    () => resolveRelease({ requestedVersion: '7.2.130', platform: { platform: 'win32', arch: 'x64' }, http }),
    (error) => error instanceof ClaudexError && error.code === 'NETWORK_FAILURE'
  );
});
test('revalidates metadata and download redirects against purpose-specific official hosts', async () => {
  const metadataRedirect = `${API_ORIGIN}/repos/router-for-me/CLIProxyAPI/releases/tags/v7.2.130?redirected=1`;
  const metadataHttp = createReleaseHttp({ routes: new Map([
    [TAG_URL, { status: 302, headers: { location: metadataRedirect } }],
    [metadataRedirect, { chunks: [JSON.stringify(stableRelease())] }]
  ]) });
  const response = await fetchOfficialResponse({
    http: metadataHttp,
    url: TAG_URL,
    purpose: 'metadata',
    deadlineMs: 30_000
  });
  assert.equal(response.status, 200);
  assert.deepEqual(metadataHttp.requests.map((request) => request.url), [TAG_URL, metadataRedirect]);

  const badRedirectHttp = createReleaseHttp({ routes: new Map([[TAG_URL, {
    status: 302,
    headers: { location: 'https://github.com/router-for-me/CLIProxyAPI/releases/tags/v7.2.130' }
  }]]) });
  await assert.rejects(
    () => fetchOfficialResponse({ http: badRedirectHttp, url: TAG_URL, purpose: 'metadata', deadlineMs: 30_000 }),
    (error) => error instanceof ClaudexError && error.code === 'NETWORK_FAILURE'
  );

  const downloadRedirectHttp = createReleaseHttp({ routes: new Map([
    ['https://github.com/example/archive.zip', { status: 302, headers: { location: 'https://objects.githubusercontent.com/archive.zip?signature=opaque' } }],
    ['https://objects.githubusercontent.com/archive.zip?signature=opaque', { chunks: ['hello'] }]
  ]) });
  const downloadResponse = await fetchOfficialResponse({
    http: downloadRedirectHttp,
    url: 'https://github.com/example/archive.zip',
    purpose: 'download',
    deadlineMs: 120_000
  });
  assert.deepEqual(await readResponseBytes(downloadResponse, { limit: 5 }), Buffer.from('hello'));
});

test('rejects a response returned after its request deadline', async () => {
  const http = createReleaseHttp({ routes: new Map([[TAG_URL, { waitForAbort: true, chunks: ['late'] }]]) });

  await assert.rejects(
    () => fetchOfficialResponse({ http, url: TAG_URL, purpose: 'metadata', deadlineMs: 20 }),
    (error) => error instanceof ClaudexError && error.code === 'NETWORK_FAILURE'
  );
  assert.deepEqual(http.aborts, [TAG_URL]);
});
test('bounds streamed bytes before accepting an oversized response', async () => {
  await assert.rejects(
    () => readResponseBytes({ status: 200, headers: { 'content-length': '6' }, body: (async function* () { yield Buffer.from('hello!'); })() }, { limit: 5 }),
    (error) => error instanceof ClaudexError && error.code === 'NETWORK_FAILURE'
  );
  await assert.rejects(
    () => readResponseBytes({ status: 200, headers: {}, body: (async function* () { yield Buffer.from('hello'); yield Buffer.from('!'); })() }, { limit: 5 }),
    (error) => error instanceof ClaudexError && error.code === 'NETWORK_FAILURE'
  );
});
