import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { PRODUCT_LEAF } from '../../../src/core/identity.js';
import { getLegacyManagedPathSets, getManagedPaths } from '../../../src/core/paths.js';
import { getManagedPaths as getManagedPathsFromPlatform, getPlatformAdapter } from '../../../src/platform/index.js';

const fixturesPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../fixtures/platform/paths.json');
const fixtures = JSON.parse(await fs.readFile(fixturesPath, 'utf8'));

test('derives exact per-user Windows, macOS, Linux, and WSL managed roots without creating them', () => {
  for (const { id, platform, env, safety, expected } of fixtures.valid) {
    assert.deepEqual(getManagedPaths(platform, env, safety), expected, id);
    assert.deepEqual(getManagedPathsFromPlatform(platform, env, safety), expected, `${id} public adapter`);
  }
});

test('refuses WSL roots on Windows mounts and unsafe home or XDG roots', () => {
  for (const { id, platform, env, safety = {} } of fixtures.unsafe) {
    assert.throws(() => getManagedPaths(platform, env, safety), (error) => error.code === 'SAFETY_REFUSAL', id);
  }
  assert.throws(
    () => getManagedPaths({ family: 'linux' }, { HOME: '/home/casey' }, { inspectPath: () => ({ isReparsePoint: true }) }),
    (error) => error.code === 'SAFETY_REFUSAL'
  );
});

test('requires WSL mount metadata and refuses a custom Windows mount root', () => {
  const platform = { family: 'linux', isWsl: true };
  assert.throws(
    () => getManagedPaths(platform, { HOME: '/home/casey' }),
    (error) => error.code === 'SAFETY_REFUSAL'
  );
  assert.throws(
    () => getManagedPaths(
      platform,
      { HOME: '/home/casey', XDG_STATE_HOME: '/windows-share/casey/state' },
      { mountTable: [{ mountPoint: '/windows-share', source: 'D:' }] }
    ),
    (error) => error.code === 'SAFETY_REFUSAL'
  );
});

test('derives previous branded siblings without changing the current product leaf', () => {
  assert.equal(PRODUCT_LEAF, 'claudeyctl');
  const current = getManagedPaths(
    { family: 'windows' },
    { LOCALAPPDATA: 'C:\\Users\\Casey\\AppData\\Local', APPDATA: 'C:\\Users\\Casey\\AppData\\Roaming' }
  );
  const legacy = getLegacyManagedPathSets(
    { family: 'windows' },
    { LOCALAPPDATA: 'C:\\Users\\Casey\\AppData\\Local', APPDATA: 'C:\\Users\\Casey\\AppData\\Roaming' }
  );
  assert.deepEqual(legacy.map(({ leaf }) => leaf), ['claudexctl', 'claudex', 'claudey']);
  assert.equal(current.managerRoot, 'C:\\Users\\Casey\\AppData\\Local\\claudeyctl');
  assert.equal(legacy[0].paths.managerRoot, 'C:\\Users\\Casey\\AppData\\Local\\claudexctl');
  assert.equal(legacy[0].paths.configRoot, 'C:\\Users\\Casey\\AppData\\Roaming\\claudexctl');
  assert.equal(legacy[2].paths.managerRoot, 'C:\\Users\\Casey\\AppData\\Local\\claudey');
});

test('selects a family adapter only for a detected supported family', () => {
  assert.equal(getPlatformAdapter({ family: 'windows' }).family, 'windows');
  assert.equal(getPlatformAdapter({ family: 'macos' }).family, 'macos');
  assert.equal(getPlatformAdapter({ family: 'linux' }).family, 'linux');
  assert.throws(() => getPlatformAdapter({ family: 'freebsd' }), (error) => error.code === 'PLATFORM_UNSUPPORTED');
});
