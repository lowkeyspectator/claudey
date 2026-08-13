import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { resolveReleaseAsset } from '../../../src/platform/asset-map.js';

const fixturesPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../fixtures/platform/assets.json');
const fixtures = JSON.parse(await fs.readFile(fixturesPath, 'utf8'));

test('maps every supported runtime platform and architecture to its exact standard release asset', () => {
  for (const { input, expected } of fixtures.valid) {
    const asset = resolveReleaseAsset(input);
    assert.deepEqual(asset, expected, `${input.platform.runtimePlatform}/${input.platform.runtimeArch}`);
    assert.equal(asset.archiveName.includes('_no-plugin'), false);
    assert.equal(asset.runtimeArch, input.platform.runtimeArch);
  }
});

test('refuses malformed versions and unsupported runtime platform combinations before selecting an asset', () => {
  for (const input of fixtures.invalid) {
    assert.throws(
      () => resolveReleaseAsset(input),
      (error) => error.code === 'PLATFORM_UNSUPPORTED',
      `${input.version} ${input.platform.runtimePlatform}/${input.platform.runtimeArch}`
    );
  }
});
