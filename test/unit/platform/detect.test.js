import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { resolveReleaseAsset } from '../../../src/platform/asset-map.js';
import { detectPlatform } from '../../../src/platform/detect.js';
import { parseOsRelease } from '../../../src/platform/linux.js';

const fixtureRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../fixtures/platform');
const fixtures = JSON.parse(await fs.readFile(path.join(fixtureRoot, 'detect.json'), 'utf8'));

test('normalizes every supported native platform without inspecting the host', () => {
  for (const { id, input, expected } of fixtures.supported) {
    assert.deepEqual(detectPlatform(input), expected, id);
  }
});

test('refuses unsupported operating systems, releases, distributions, libc families, and runtime architectures', () => {
  for (const { id, input } of fixtures.unsupported) {
    assert.throws(() => detectPlatform(input), (error) => error.code === 'PLATFORM_UNSUPPORTED', id);
  }
});

test('selects the runtime architecture asset even when native architecture differs under emulation', () => {
  const fixture = fixtures.supported.find(({ id }) => id === 'wsl-runtime-native-mismatch');
  const platform = detectPlatform(fixture.input);
  const asset = resolveReleaseAsset({ version: '7.2.130', platform });
  assert.equal(asset.runtimeArch, 'x64');
  assert.equal(asset.archiveName, 'CLIProxyAPI_7.2.130_linux_amd64.tar.gz');
});

test('parses structured os-release fixture text without guessing unavailable fields', async () => {
  const ubuntu = await fs.readFile(path.join(fixtureRoot, 'os-release', 'ubuntu-20'), 'utf8');
  const debian = await fs.readFile(path.join(fixtureRoot, 'os-release', 'debian-10'), 'utf8');
  assert.deepEqual(parseOsRelease(ubuntu), { ID: 'ubuntu', VERSION_ID: '20.04' });
  assert.deepEqual(parseOsRelease(debian), { ID: 'debian', VERSION_ID: '10' });
  assert.deepEqual(parseOsRelease('ID=ubuntu\nBROKEN\n'), { ID: 'ubuntu' });
});
