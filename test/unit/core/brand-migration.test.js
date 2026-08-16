import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  applyBrandMigration,
  classifyOwnedLauncher,
  inspectFromListing,
  migrateLegacyBrand,
  planBrandMigration,
  relocatableRoots,
  renderWindowsCmdLauncher,
  replaceRootPrefix,
  retirePathEntries,
  rewriteLauncherText
} from '../../../src/core/brand-migration.js';
import { getLegacyManagedPathSets, getManagedPaths } from '../../../src/core/paths.js';

const WIN_ENV = Object.freeze({
  LOCALAPPDATA: 'C:\\Users\\Casey\\AppData\\Local',
  APPDATA: 'C:\\Users\\Casey\\AppData\\Roaming',
  USERPROFILE: 'C:\\Users\\Casey'
});

function windowsSets() {
  return {
    current: getManagedPaths({ family: 'windows' }, WIN_ENV),
    candidates: getLegacyManagedPathSets({ family: 'windows' }, WIN_ENV)
  };
}

function inspectMap(entries) {
  return Object.fromEntries(Object.entries(entries).map(([target, value]) => [target, inspectFromListing(value)]));
}

function installedDir() {
  return {
    exists: true,
    kind: 'directory',
    entries: [{ name: 'installation.json', kind: 'file' }],
    files: { 'installation.json': true }
  };
}

function vacantDir() {
  return {
    exists: true,
    kind: 'directory',
    entries: [{ name: 'releases', kind: 'directory', empty: true }],
    files: {}
  };
}

test('relocatable Windows roots exclude children and keep the roaming config sibling', () => {
  const { current } = windowsSets();
  assert.deepEqual(relocatableRoots(current, 'windows'), [current.managerRoot, current.configRoot]);
});

test('plans a claudexctl to claudeyctl relocation and refuses collisions', () => {
  const { current, candidates } = windowsSets();
  const claudex = candidates.find(({ leaf }) => leaf === 'claudexctl');
  const inspections = inspectMap({
    [current.managerRoot]: { exists: false },
    [current.configRoot]: { exists: false },
    [claudex.paths.managerRoot]: installedDir(),
    [claudex.paths.configRoot]: installedDir(),
    ...Object.fromEntries(candidates.filter(({ leaf }) => leaf !== 'claudexctl').flatMap(({ paths }) => [
      [paths.managerRoot, { exists: false }],
      [paths.configRoot, { exists: false }]
    ]))
  });
  const plan = planBrandMigration({
    family: 'windows',
    current,
    candidates,
    inspections,
    launchers: [
      {
        path: 'C:\\Users\\Casey\\.local\\bin\\claudey.cmd',
        name: 'claudey.cmd',
        text: 'node C:\\repo\\bin\\claudexctl.js launcher claudey %*'
      },
      {
        path: `${claudex.paths.userBinRoot}\\claudey.cmd`,
        name: 'claudey.cmd',
        text: 'node C:\\repo\\bin\\claudexctl.js launcher claudey %*'
      }
    ],
    unofficialLauncherDirectory: 'C:\\Users\\Casey\\.local\\bin'
  });
  assert.equal(plan.kind, 'migrate');
  assert.equal(plan.leaf, 'claudexctl');
  assert.deepEqual(plan.moves, [
    { from: claudex.paths.managerRoot, to: current.managerRoot },
    { from: claudex.paths.configRoot, to: current.configRoot }
  ]);
  assert.ok(plan.retireLaunchers.includes('C:\\Users\\Casey\\.local\\bin\\claudey.cmd'));
  assert.ok(plan.rewriteLaunchers.includes(`${claudex.paths.userBinRoot}\\claudey.cmd`));

  assert.throws(() => planBrandMigration({
    family: 'windows',
    current,
    candidates,
    inspections: inspectMap({
      [current.managerRoot]: installedDir(),
      [current.configRoot]: installedDir(),
      [claudex.paths.managerRoot]: installedDir(),
      [claudex.paths.configRoot]: installedDir(),
      ...Object.fromEntries(candidates.filter(({ leaf }) => leaf !== 'claudexctl').flatMap(({ paths }) => [
        [paths.managerRoot, { exists: false }],
        [paths.configRoot, { exists: false }]
      ]))
    })
  }), (error) => error.code === 'SAFETY_REFUSAL');
});

test('removes a vacant current scaffold before renaming the legacy root', () => {
  const { current, candidates } = windowsSets();
  const claudex = candidates.find(({ leaf }) => leaf === 'claudexctl');
  const inspections = inspectMap({
    [current.managerRoot]: vacantDir(),
    [current.configRoot]: { exists: false },
    [claudex.paths.managerRoot]: installedDir(),
    [claudex.paths.configRoot]: installedDir(),
    ...Object.fromEntries(candidates.filter(({ leaf }) => leaf !== 'claudexctl').flatMap(({ paths }) => [
      [paths.managerRoot, { exists: false }],
      [paths.configRoot, { exists: false }]
    ]))
  });
  const plan = planBrandMigration({ family: 'windows', current, candidates, inspections });
  assert.deepEqual(plan.removals, [current.managerRoot]);
  assert.equal(plan.moves[0].from, claudex.paths.managerRoot);
});

test('rewrites owned launcher text and path prefixes without inventing a claudexctl.js alias', () => {
  assert.equal(
    rewriteLauncherText('"C:\\\\node.exe" "C:\\\\repo\\\\bin\\\\claudexctl.js" launcher claudex %*'),
    '"C:\\\\node.exe" "C:\\\\repo\\\\bin\\\\claudeyctl.js" launcher claudey %*'
  );
  assert.equal(
    replaceRootPrefix(
      'C:\\Users\\Casey\\AppData\\Local\\claudexctl\\releases\\7.2.133\\cli-proxy-api.exe',
      'C:\\Users\\Casey\\AppData\\Local\\claudexctl',
      'C:\\Users\\Casey\\AppData\\Local\\claudeyctl',
      'windows'
    ),
    'C:\\Users\\Casey\\AppData\\Local\\claudeyctl\\releases\\7.2.133\\cli-proxy-api.exe'
  );
  assert.equal(classifyOwnedLauncher('claude.exe', 'anything'), 'keep');
  assert.equal(classifyOwnedLauncher('claudex.cmd', 'node claudexctl.js'), 'delete');
  assert.equal(classifyOwnedLauncher('claudey.cmd', 'node claudexctl.js launcher claudey'), 'rewrite');
  assert.equal(classifyOwnedLauncher('claudey.cmd', 'node claudexctl.js', { unofficial: true }), 'delete');
  assert.equal(
    renderWindowsCmdLauncher('C:\\node.exe', 'C:\\repo\\bin\\claudeyctl.js', ['launcher', 'claudey']),
    '@echo off\nsetlocal\n"C:\\node.exe" "C:\\repo\\bin\\claudeyctl.js" launcher claudey %*\n'
  );
});

test('PATH retirement drops only leftover brand bins and keeps empty segments', () => {
  const retired = retirePathEntries(
    'C:\\Windows;;C:\\Users\\Casey\\AppData\\Local\\claudexctl\\bin;C:\\Tools;',
    ['C:\\Users\\Casey\\AppData\\Local\\claudexctl\\bin', 'C:\\Users\\Casey\\AppData\\Local\\claudey\\bin'],
    'windows'
  );
  assert.equal(retired.after, 'C:\\Windows;;C:\\Tools;');
  assert.equal(retired.changed, true);
});

test('applyBrandMigration renames roots, rewrites identities, and rolls back on failure', async () => {
  const { current, candidates } = windowsSets();
  const claudex = candidates.find(({ leaf }) => leaf === 'claudexctl');
  const inspections = inspectMap({
    [current.managerRoot]: { exists: false },
    [current.configRoot]: { exists: false },
    [claudex.paths.managerRoot]: installedDir(),
    [claudex.paths.configRoot]: installedDir(),
    ...Object.fromEntries(candidates.filter(({ leaf }) => leaf !== 'claudexctl').flatMap(({ paths }) => [
      [paths.managerRoot, { exists: false }],
      [paths.configRoot, { exists: false }]
    ]))
  });
  const plan = planBrandMigration({ family: 'windows', current, candidates, inspections });
  const fsState = new Map([
    [claudex.paths.managerRoot, 'manager'],
    [claudex.paths.configRoot, 'config'],
    [`${claudex.paths.configRoot}\\installation.json`, JSON.stringify({
      schemaVersion: 1, installationId: 'id', port: 8317,
      executable: `${claudex.paths.managerRoot}\\releases\\7.2.133\\cli-proxy-api.exe`
    })],
    [`${claudex.paths.configRoot}\\token`, Buffer.alloc(32, 7)],
    [`${claudex.paths.configRoot}\\config.yaml`, 'auth-dir: old\n']
  ]);
  const renamed = [];
  await applyBrandMigration(plan, {
    rename: async (from, to) => {
      renamed.push([from, to]);
      fsState.set(to, fsState.get(from));
      fsState.delete(from);
    },
    readFile: async (target, encoding) => {
      const lookup = [
        target,
        target.replace(current.configRoot, claudex.paths.configRoot),
        target.replace(current.managerRoot, claudex.paths.managerRoot)
      ];
      let value;
      for (const key of lookup) {
        if (fsState.has(key)) { value = fsState.get(key); break; }
      }
      if (value === undefined) {
        const error = new Error('missing');
        error.code = 'ENOENT';
        throw error;
      }
      if (encoding === 'utf8') return Buffer.isBuffer(value) ? value.toString('utf8') : value;
      return Buffer.isBuffer(value) ? value : Buffer.from(String(value));
    },
    writeFile: async (target, contents) => { fsState.set(target, contents); }
  });
  assert.deepEqual(renamed, plan.moves.map(({ from, to }) => [from, to]));
  const installation = JSON.parse(fsState.get(plan.rewriteInstallation).toString());
  assert.equal(installation.executable, `${current.managerRoot}\\releases\\7.2.133\\cli-proxy-api.exe`);
  assert.match(fsState.get(plan.rewriteConfig).toString(), /claudeyctl\\\\auth/u);

  const failing = planBrandMigration({ family: 'windows', current, candidates, inspections });
  const rolled = [];
  await assert.rejects(applyBrandMigration(failing, {
    rename: async (from, to) => {
      rolled.push([from, to]);
      if (rolled.length === 2) throw new Error('disk full');
    }
  }), (error) => error.code === 'SAFETY_REFUSAL');
  assert.deepEqual(rolled[2], [failing.moves[0].to, failing.moves[0].from]);
});

test('migrateLegacyBrand relocates a real leftover Windows-style install on disk', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'claudey-brand-'));
  const local = path.join(root, 'Local');
  const roaming = path.join(root, 'Roaming');
  const legacyManager = path.join(local, 'claudexctl');
  const legacyConfig = path.join(roaming, 'claudexctl');
  const currentManager = path.join(local, 'claudeyctl');
  const currentConfig = path.join(roaming, 'claudeyctl');
  await fs.mkdir(path.join(legacyManager, 'releases', '7.2.133'), { recursive: true });
  await fs.writeFile(path.join(legacyManager, 'releases', '7.2.133', 'cli-proxy-api.exe'), 'exe');
  await fs.mkdir(path.join(legacyConfig, 'auth'), { recursive: true });
  await fs.writeFile(path.join(legacyConfig, 'auth', 'codex.json'), '{"type":"codex"}');
  await fs.writeFile(path.join(legacyConfig, 'token'), Buffer.alloc(32, 9));
  await fs.writeFile(path.join(legacyConfig, 'installation.json'), `${JSON.stringify({
    schemaVersion: 1,
    installationId: '11111111-1111-4111-8111-111111111111',
    port: 8317,
    version: '7.2.133',
    executable: path.join(legacyManager, 'releases', '7.2.133', 'cli-proxy-api.exe')
  }, null, 2)}\n`);
  const unofficial = path.join(root, 'home', '.local', 'bin');
  await fs.mkdir(unofficial, { recursive: true });
  await fs.writeFile(path.join(unofficial, 'claudey.cmd'), 'node C:\\repo\\bin\\claudexctl.js launcher claudey %*\n');
  await fs.writeFile(path.join(unofficial, 'claude.exe'), 'keep-me');

  const result = await migrateLegacyBrand({
    LOCALAPPDATA: local,
    APPDATA: roaming,
    USERPROFILE: path.join(root, 'home')
  }, {
    noPath: true,
    adapter: {
      lstat: (target) => fs.lstat(target),
      readdir: (target, options) => fs.readdir(target, options),
      readFile: (target, encoding) => fs.readFile(target, encoding),
      writeFile: (target, contents) => fs.writeFile(target, contents),
      rename: (from, to) => fs.rename(from, to),
      unlink: (target) => fs.unlink(target),
      removeVacant: (target) => fs.rm(target, { recursive: true }),
      stopGateway: async () => {}
    }
  });
  assert.equal(result.kind, 'migrate');
  assert.equal(result.leaf, 'claudexctl');
  await assert.rejects(fs.lstat(legacyManager), { code: 'ENOENT' });
  await assert.rejects(fs.lstat(path.join(unofficial, 'claudey.cmd')), { code: 'ENOENT' });
  assert.equal(await fs.readFile(path.join(unofficial, 'claude.exe'), 'utf8'), 'keep-me');
  const installation = JSON.parse(await fs.readFile(path.join(currentConfig, 'installation.json'), 'utf8'));
  assert.equal(installation.executable, path.join(currentManager, 'releases', '7.2.133', 'cli-proxy-api.exe'));
  assert.match(await fs.readFile(path.join(currentConfig, 'config.yaml'), 'utf8'), /auth-dir:/u);
  await fs.rm(root, { recursive: true, force: true });
});
