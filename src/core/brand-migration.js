import { spawnSync } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';

import { buildGatewayConfig } from './config.js';
import { ClaudeyError } from './errors.js';
import {
  LAUNCHER_NAMES,
  LEGACY_LAUNCHER_NAMES,
  STALE_LAUNCHER_EXTENSIONS
} from './identity.js';
import { getLegacyManagedPathSets, getManagedPaths } from './paths.js';
import { Secret } from './secrets.js';

const PLANS = new WeakSet();
const INSTALL_FILES = Object.freeze(['installation.json', 'token', 'current.json']);
const SCAFFOLD_DIRS = Object.freeze(['releases', 'state', 'bin', 'launchers', 'staging', 'auth', 'plugins']);
const POWERSHELL = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
const WINDOWS_LAUNCHER_DIR = Object.freeze(['.local', 'bin']);

function safety(message = 'Brand migration could not be completed safely.') {
  return new ClaudeyError('SAFETY_REFUSAL', message);
}

function freeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

function branded(value) {
  freeze(value);
  PLANS.add(value);
  return value;
}

function familyOf(platform) {
  if (platform === 'windows' || platform === 'win32') return 'windows';
  if (platform === 'macos' || platform === 'darwin') return 'macos';
  if (platform === 'linux') return 'linux';
  throw safety('Brand migration is unavailable for this platform.');
}

function pathApiFor(family) {
  return family === 'windows' ? path.win32 : path.posix;
}

function samePath(left, right, family) {
  const pathApi = pathApiFor(family);
  const a = pathApi.normalize(left);
  const b = pathApi.normalize(right);
  return family === 'windows' ? a.toLowerCase() === b.toLowerCase() : a === b;
}

function isStrictChild(parent, child, family) {
  const pathApi = pathApiFor(family);
  const relative = pathApi.relative(parent, child);
  const compare = family === 'windows' ? relative.toLowerCase() : relative;
  return compare !== '' && compare !== '..' && !compare.startsWith(`..${pathApi.sep}`) && !pathApi.isAbsolute(relative);
}

export function relocatableRoots(paths, family) {
  const unique = [];
  for (const root of [paths.managerRoot, paths.configRoot, paths.stateRoot]) {
    if (unique.some((item) => samePath(item, root, family))) continue;
    unique.push(root);
  }
  return unique.filter((root) => !unique.some((other) => !samePath(other, root, family) && isStrictChild(other, root, family)));
}

function requiredInspection(inspections, target) {
  const value = inspections?.[target];
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw safety();
  if (!['missing', 'directory', 'file', 'reparse'].includes(value.kind)
    || typeof value.exists !== 'boolean' || typeof value.vacant !== 'boolean' || typeof value.installed !== 'boolean') {
    throw safety();
  }
  if (value.kind === 'reparse') throw safety('Managed roots cannot resolve through links or reparse points.');
  return value;
}

function setInstalled(paths, inspections) {
  const config = requiredInspection(inspections, paths.configRoot);
  const manager = requiredInspection(inspections, paths.managerRoot);
  return config.installed === true || manager.installed === true;
}

export function replaceRootPrefix(value, fromRoot, toRoot, family) {
  if (typeof value !== 'string' || value.length === 0) return value;
  const pathApi = pathApiFor(family);
  const normalize = (input) => {
    const unified = family === 'windows' ? input.replaceAll('/', '\\') : input;
    const normalized = pathApi.normalize(unified);
    return family === 'windows' ? normalized.toLowerCase() : normalized;
  };
  const valueNorm = normalize(value);
  const fromNorm = normalize(fromRoot);
  if (valueNorm === fromNorm) return toRoot;
  const sep = family === 'windows' ? '\\' : '/';
  if (!valueNorm.startsWith(`${fromNorm}${sep}`)) return value;
  const suffix = value.slice(fromRoot.length).replace(/^[\\/]/u, '');
  return suffix.length === 0 ? toRoot : pathApi.join(toRoot, suffix);
}

export function rewriteLauncherText(text) {
  if (typeof text !== 'string') throw safety();
  return text
    .replaceAll('claudexctl.js', 'claudeyctl.js')
    .replaceAll('claudex.js', 'claudeyctl.js')
    .replace(/(launcher(?:\s+|['"]\s*))claudex\b/gu, '$1claudey');
}

const CMD_INVOCATION = /"([^"\r\n]+)"\s+"([^"\r\n]+claudeyctl\.js)"/u;

export function renderWindowsCmdLauncher(nodePath, managerPath, profileArgs) {
  if (typeof nodePath !== 'string' || typeof managerPath !== 'string') throw safety();
  const prefix = `@echo off\nsetlocal\n"${nodePath}" "${managerPath}"`;
  if (!Array.isArray(profileArgs) || profileArgs.length === 0) return `${prefix} %*\n`;
  return `${prefix} ${profileArgs.join(' ')} %*\n`;
}

export function launcherIdentity(name) {
  if (typeof name !== 'string' || name.length === 0 || name.includes('\0') || name.includes('/') || name.includes('\\')) {
    return null;
  }
  const lower = name.toLowerCase();
  if (lower.endsWith('.exe')) return null;
  for (const extension of STALE_LAUNCHER_EXTENSIONS) {
    if (extension && lower.endsWith(extension)) {
      return lower.slice(0, -extension.length);
    }
  }
  return lower;
}

export function classifyOwnedLauncher(name, text, { unofficial = false } = {}) {
  const base = launcherIdentity(name);
  if (!base) return 'keep';
  const known = new Set([...LAUNCHER_NAMES, ...LEGACY_LAUNCHER_NAMES]);
  if (!known.has(base)) return 'keep';
  if (LEGACY_LAUNCHER_NAMES.includes(base) || unofficial) return 'delete';
  if (typeof text === 'string' && /claudexctl\.js|claudex\.js|(?:launcher\s+)claudex\b/u.test(text)) return 'rewrite';
  return 'keep';
}

export function retirePathEntries(pathValue, retireDirectories, family) {
  if (typeof pathValue !== 'string') throw safety();
  const delimiter = family === 'windows' ? ';' : ':';
  const pathApi = pathApiFor(family);
  const retired = new Set(retireDirectories.map((entry) => {
    const normalized = pathApi.normalize(entry).replace(/[\\/]+$/u, '');
    return family === 'windows' ? normalized.toLowerCase() : normalized;
  }));
  const entries = pathValue.split(delimiter);
  const kept = [];
  let dropped = false;
  for (const entry of entries) {
    if (entry.length === 0) {
      kept.push(entry);
      continue;
    }
    const normalized = pathApi.normalize(entry).replace(/[\\/]+$/u, '');
    const key = family === 'windows' ? normalized.toLowerCase() : normalized;
    if (retired.has(key)) {
      dropped = true;
      continue;
    }
    kept.push(entry);
  }
  const after = kept.join(delimiter);
  return freeze({ before: pathValue, after, changed: dropped || after !== pathValue });
}

export function planBrandMigration({
  family, current, candidates, inspections, launchers = [], unofficialLauncherDirectory
}) {
  if (!current || typeof current !== 'object' || !Array.isArray(candidates) || !inspections || typeof inspections !== 'object') {
    throw safety();
  }
  const usedFamily = familyOf(family);

  for (const root of relocatableRoots(current, usedFamily)) requiredInspection(inspections, root);
  const currentInstalled = setInstalled(current, inspections);
  const installedCandidates = [];
  for (const candidate of candidates) {
    if (!candidate || typeof candidate !== 'object' || typeof candidate.leaf !== 'string' || !candidate.paths) throw safety();
    for (const root of relocatableRoots(candidate.paths, usedFamily)) requiredInspection(inspections, root);
    if (setInstalled(candidate.paths, inspections)) installedCandidates.push(candidate);
  }
  if (currentInstalled && installedCandidates.length > 0) {
    throw safety('Legacy and current Claudey roots both contain an installation.');
  }
  if (installedCandidates.length > 1) throw safety('Multiple legacy Claudey roots contain an installation.');

  const selected = currentInstalled ? null : installedCandidates[0] ?? null;
  const moves = [];
  const removals = [];
  if (selected) {
    const currentRoots = relocatableRoots(current, usedFamily);
    const legacyRoots = relocatableRoots(selected.paths, usedFamily);
    if (currentRoots.length !== legacyRoots.length) throw safety();
    for (let index = 0; index < currentRoots.length; index += 1) {
      const from = legacyRoots[index];
      const to = currentRoots[index];
      if (samePath(from, to, usedFamily)) continue;
      const source = requiredInspection(inspections, from);
      const target = requiredInspection(inspections, to);
      if (source.kind === 'missing' || source.installed !== true) continue;
      if (source.kind !== 'directory') throw safety();
      if (target.kind === 'directory' && target.installed) throw safety();
      if (target.exists && !target.vacant && target.kind !== 'missing') {
        throw safety('The current Claudey root is not vacant for brand migration.');
      }
      if (target.exists && target.vacant) removals.push(to);
      moves.push({ from, to });
    }
  }

  const replacements = [];
  const sources = selected ? [selected] : candidates;
  for (const candidate of sources) {
    for (const role of ['managerRoot', 'configRoot', 'stateRoot', 'authRoot']) {
      if (!samePath(candidate.paths[role], current[role], usedFamily)) {
        replacements.push({ from: candidate.paths[role], to: current[role] });
      }
    }
  }

  const retireLaunchers = [];
  const rewriteLaunchers = [];
  for (const file of launchers) {
    if (!file || typeof file !== 'object' || typeof file.path !== 'string') throw safety();
    const unofficial = unofficialLauncherDirectory
      ? samePath(pathApiFor(usedFamily).dirname(file.path), unofficialLauncherDirectory, usedFamily)
        && usedFamily === 'windows'
      : false;
    const action = classifyOwnedLauncher(file.name, file.text, { unofficial });
    if (action === 'delete') retireLaunchers.push(file.path);
    else if (action === 'rewrite') rewriteLaunchers.push(file.path);
  }

  const retirePathDirectories = candidates
    .map((candidate) => candidate.paths.userBinRoot)
    .filter((root) => !samePath(root, current.userBinRoot, usedFamily));

  const changed = moves.length > 0 || removals.length > 0 || rewriteLaunchers.length > 0 || retireLaunchers.length > 0;
  return branded({
    schemaVersion: 1,
    kind: selected && moves.length > 0 ? 'migrate' : 'none',
    changed,
    leaf: selected?.leaf ?? null,
    family: usedFamily,
    current,
    moves,
    removals,
    replacements,
    rewriteLaunchers,
    retireLaunchers,
    retirePathDirectories,
    currentBin: current.userBinRoot,
    rewriteInstallation: pathApiFor(usedFamily).join(current.configRoot, 'installation.json'),
    rewriteConfig: pathApiFor(usedFamily).join(current.configRoot, 'config.yaml'),
    tokenFile: pathApiFor(usedFamily).join(current.configRoot, 'token')
  });
}

function assertPlan(plan) {
  if (!PLANS.has(plan)) throw safety('Brand migration requires a trusted plan.');
  return plan;
}

export async function applyBrandMigration(plan, adapter = {}) {
  assertPlan(plan);
  const family = plan.family;
  const completed = [];
  try {
    if (typeof adapter.stopGateway === 'function') {
      for (const move of plan.moves) await adapter.stopGateway(move.from);
    }
    for (const target of plan.removals) {
      if (typeof adapter.removeVacant !== 'function') throw safety();
      await adapter.removeVacant(target);
    }
    for (const move of plan.moves) {
      if (typeof adapter.rename !== 'function') throw safety();
      await adapter.rename(move.from, move.to);
      completed.push(move);
    }
  } catch (error) {
    if (typeof adapter.rename === 'function') {
      for (const move of completed.reverse()) {
        try { await adapter.rename(move.to, move.from); } catch { /* rollback is best-effort */ }
      }
    }
    if (error?.code === 'SAFETY_REFUSAL') throw error;
    throw safety();
  }

  if (typeof adapter.readFile === 'function' && typeof adapter.writeFile === 'function') {
    await rewriteInstallationRecord(plan, adapter, family);
    await rewriteGatewayConfigRecord(plan, adapter, family);
    for (const target of plan.rewriteLaunchers) {
      const relocated = relocatePlannedPath(target, plan);
      let text;
      try { text = await adapter.readFile(relocated, 'utf8'); } catch { continue; }
      if (typeof text !== 'string') continue;
      const next = rewriteLauncherText(text);
      if (next !== text) await adapter.writeFile(relocated, next);
    }
  }
  if (typeof adapter.unlink === 'function') {
    for (const target of plan.retireLaunchers) {
      try { await adapter.unlink(relocatePlannedPath(target, plan)); } catch { /* missing stale launcher is a success */ }
    }
  }
  await ensureWindowsCmdSiblings(plan, adapter);
  return freeze({ action: plan.kind, changed: plan.changed, leaf: plan.leaf });
}

async function ensureWindowsCmdSiblings(plan, adapter) {
  if (plan.family !== 'windows' || typeof adapter.readFile !== 'function' || typeof adapter.writeFile !== 'function') return;
  const pathApi = path.win32;
  const samples = [];
  for (const name of ['claudey.cmd', 'claude-agy.cmd', 'claude-grok.cmd', 'claude-codex.cmd', 'claudeyctl.cmd']) {
    try { samples.push(await adapter.readFile(pathApi.join(plan.currentBin, name), 'utf8')); } catch { /* try next */ }
  }
  const source = samples.map((text) => rewriteLauncherText(text)).find((text) => CMD_INVOCATION.test(text));
  if (!source) return;
  const match = source.match(CMD_INVOCATION);
  if (!match) return;
  const nodePath = match[1];
  const managerPath = match[2];
  const profiles = [
    ['claudeyctl.cmd', []],
    ['claudey.cmd', []],
    ['claude-codex.cmd', ['launcher', 'claude-codex']],
    ['claude-agy.cmd', ['launcher', 'claude-agy']],
    ['claude-grok.cmd', ['launcher', 'claude-grok']]
  ];
  for (const [name, args] of profiles) {
    const target = pathApi.join(plan.currentBin, name);
    let existing = null;
    try { existing = await adapter.readFile(target, 'utf8'); } catch { existing = null; }
    const next = renderWindowsCmdLauncher(nodePath, managerPath, args);
    if (existing !== next) await adapter.writeFile(target, next);
  }
}

function relocatePlannedPath(target, plan) {
  let result = target;
  for (const { from, to } of plan.moves) result = replaceRootPrefix(result, from, to, plan.family);
  return result;
}

async function rewriteInstallationRecord(plan, adapter, family) {
  let raw;
  try { raw = await adapter.readFile(plan.rewriteInstallation, 'utf8'); } catch { return; }
  let record;
  try { record = JSON.parse(raw); } catch { return; }
  if (!record || typeof record !== 'object' || typeof record.executable !== 'string') return;
  let executable = record.executable;
  for (const { from, to } of plan.replacements) executable = replaceRootPrefix(executable, from, to, family);
  if (executable === record.executable) return;
  await adapter.writeFile(plan.rewriteInstallation, `${JSON.stringify({ ...record, executable }, null, 2)}\n`);
}

async function rewriteGatewayConfigRecord(plan, adapter, family) {
  let tokenBytes;
  try { tokenBytes = await adapter.readFile(plan.tokenFile); } catch { return; }
  if (!Buffer.isBuffer(tokenBytes) || tokenBytes.length !== 32) return;
  let port = 8317;
  try {
    const record = JSON.parse(await adapter.readFile(plan.rewriteInstallation, 'utf8'));
    if (Number.isSafeInteger(record?.port)) port = record.port;
  } catch { /* keep default managed port */ }
  const token = Secret.fromBytes(tokenBytes);
  const authDir = plan.replacements.reduce((value, { from, to }) => replaceRootPrefix(value, from, to, family),
    plan.current.authRoot);
  await adapter.writeFile(plan.rewriteConfig, buildGatewayConfig({ port, authDir, token }));
}

export function inspectFromListing({ exists = false, kind = 'missing', entries = [], files = {} } = {}) {
  if (!exists) return freeze({ exists: false, kind: 'missing', vacant: true, installed: false });
  if (kind === 'reparse' || kind === 'file') {
    return freeze({ exists: true, kind, vacant: false, installed: false });
  }
  const installed = INSTALL_FILES.some((name) => files[name])
    || (Array.isArray(files.auth) && files.auth.some((name) => name.endsWith('.json')))
    || (Array.isArray(files.releases) && files.releases.length > 0);
  const vacant = !installed && entries.every((entry) => entry.kind === 'directory' && SCAFFOLD_DIRS.includes(entry.name)
    && (entry.empty !== false));
  return freeze({ exists: true, kind: 'directory', vacant, installed });
}

async function inspectPath(target, fsApi) {
  let metadata;
  try { metadata = await fsApi.lstat(target); } catch (error) {
    if (error?.code === 'ENOENT') return inspectFromListing();
    throw safety();
  }
  if (metadata.isSymbolicLink?.() || metadata.isSymbolicLink === true) {
    return inspectFromListing({ exists: true, kind: 'reparse' });
  }
  if (!metadata.isDirectory()) return inspectFromListing({ exists: true, kind: 'file' });
  let entries;
  try { entries = await fsApi.readdir(target, { withFileTypes: true }); } catch { throw safety(); }
  const files = {};
  const listing = [];
  for (const entry of entries) {
    const name = entry.name;
    listing.push({
      name,
      kind: entry.isDirectory() ? 'directory' : 'file',
      empty: entry.isDirectory() ? (await fsApi.readdir(path.join(target, name))).length === 0 : undefined
    });
    if (entry.isFile() && INSTALL_FILES.includes(name)) files[name] = true;
    if (entry.isDirectory() && name === 'auth') {
      try { files.auth = await fsApi.readdir(path.join(target, name)); } catch { files.auth = []; }
    }
    if (entry.isDirectory() && name === 'releases') {
      try { files.releases = await fsApi.readdir(path.join(target, name)); } catch { files.releases = []; }
    }
  }
  return inspectFromListing({ exists: true, kind: 'directory', entries: listing, files });
}

async function collectLauncherSnapshots(directories, fsApi, pathApi) {
  const launchers = [];
  for (const directory of directories) {
    let names;
    try { names = await fsApi.readdir(directory); } catch { continue; }
    for (const name of names) {
      const target = pathApi.join(directory, name);
      let metadata;
      try { metadata = await fsApi.lstat(target); } catch { continue; }
      if (!metadata.isFile() || metadata.isSymbolicLink?.()) continue;
      let text = '';
      try { text = await fsApi.readFile(target, 'utf8'); } catch { text = ''; }
      launchers.push({ path: target, name, text });
    }
  }
  return launchers;
}

function readWindowsUserPath() {
  const result = spawnSync(POWERSHELL, [
    '-NoProfile', '-NonInteractive', '-Command',
    '[Environment]::GetEnvironmentVariable("Path","User")'
  ], { encoding: 'utf8', windowsHide: true, timeout: 15_000 });
  if (result.status !== 0) throw safety('The user PATH could not be read.');
  return (result.stdout ?? '').replace(/\r?\n$/u, '');
}

function writeWindowsUserPath(value) {
  const result = spawnSync(POWERSHELL, [
    '-NoProfile', '-NonInteractive', '-Command',
    '[Environment]::SetEnvironmentVariable("Path",$env:CLDY_PATH_VALUE,"User")'
  ], {
    encoding: 'utf8',
    windowsHide: true,
    timeout: 15_000,
    env: { ...process.env, CLDY_PATH_VALUE: value }
  });
  if (result.status !== 0) throw safety('The user PATH could not be updated.');
}

function updateProcessPath(plan, family) {
  const delimiter = family === 'windows' ? ';' : ':';
  const current = process.env.PATH ?? '';
  const retired = retirePathEntries(current, plan.retirePathDirectories, family);
  const pathApi = pathApiFor(family);
  const expected = family === 'windows'
    ? pathApi.normalize(plan.currentBin).replace(/[\\/]+$/u, '').toLowerCase()
    : pathApi.normalize(plan.currentBin).replace(/\/+$/u, '');
  const entries = retired.after.split(delimiter);
  const present = entries.some((entry) => {
    if (entry.length === 0) return false;
    const normalized = pathApi.normalize(entry).replace(/[\\/]+$/u, '');
    return (family === 'windows' ? normalized.toLowerCase() : normalized) === expected;
  });
  process.env.PATH = present ? retired.after : `${plan.currentBin}${delimiter}${retired.after}`;
}

async function createProductionAdapter() {
  return {
    async lstat(target) { return fs.lstat(target); },
    async readdir(target, options) { return fs.readdir(target, options); },
    async readFile(target, encoding) { return fs.readFile(target, encoding); },
    async writeFile(target, contents) {
      if (typeof contents === 'string' || Buffer.isBuffer(contents)) {
        await fs.writeFile(target, contents);
        return;
      }
      throw safety();
    },
    async rename(from, to) { await fs.rename(from, to); },
    async unlink(target) { await fs.unlink(target); },
    async removeVacant(target) { await fs.rm(target, { recursive: true, force: false }); },
    async stopGateway(root) {
      const pidPath = path.join(root, 'state', 'gateway.pid');
      let text;
      try { text = (await fs.readFile(pidPath, 'utf8')).trim(); } catch { return; }
      const pid = Number(text);
      if (!Number.isSafeInteger(pid) || pid <= 0) return;
      try { process.kill(pid, 'SIGTERM'); } catch { return; }
      for (let attempt = 0; attempt < 20; attempt += 1) {
        try { process.kill(pid, 0); } catch { return; }
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      try { process.kill(pid, 'SIGKILL'); } catch { /* already gone */ }
    }
  };
}

export async function migrateLegacyBrand(environment = process.env, overrides = {}) {
  const familyName = process.platform === 'win32' ? 'windows' : process.platform === 'darwin' ? 'macos' : 'linux';
  let current;
  let candidates;
  try {
    current = getManagedPaths(familyName, environment, overrides.safety ?? {});
    candidates = getLegacyManagedPathSets(familyName, environment, overrides.safety ?? {});
  } catch {
    return freeze({ schemaVersion: 1, kind: 'none', changed: false });
  }
  const adapter = overrides.adapter ?? await createProductionAdapter();
  const fsApi = {
    lstat: adapter.lstat.bind(adapter),
    readdir: adapter.readdir.bind(adapter),
    readFile: adapter.readFile.bind(adapter)
  };
  const pathApi = pathApiFor(familyName);
  const inspections = {};
  const roots = new Set();
  for (const paths of [current, ...candidates.map((item) => item.paths)]) {
    for (const root of relocatableRoots(paths, familyName)) roots.add(root);
  }
  for (const root of roots) inspections[root] = await inspectPath(root, fsApi);

  const unofficial = familyName === 'windows' && environment.USERPROFILE
    ? path.win32.join(environment.USERPROFILE, ...WINDOWS_LAUNCHER_DIR)
    : null;
  const launcherDirs = [
    current.userBinRoot,
    ...candidates.map((item) => item.paths.userBinRoot),
    ...(unofficial ? [unofficial] : [])
  ];
  const uniqueDirs = launcherDirs.filter((directory, index, all) => {
    return all.findIndex((item) => samePath(item, directory, familyName)) === index;
  });
  const launchers = await collectLauncherSnapshots(uniqueDirs, fsApi, pathApi);
  const plan = planBrandMigration({
    family: familyName, current, candidates, inspections, launchers, unofficialLauncherDirectory: unofficial
  });
  const result = await applyBrandMigration(plan, adapter);
  if (overrides.noPath !== true) {
    if (familyName === 'windows') {
      const before = typeof overrides.readUserPath === 'function' ? await overrides.readUserPath() : readWindowsUserPath();
      const retired = retirePathEntries(before, plan.retirePathDirectories, familyName);
      const delimiter = ';';
      const expected = path.win32.normalize(plan.currentBin).replace(/[\\/]+$/u, '').toLowerCase();
      const entries = retired.after === '' ? [] : retired.after.split(delimiter);
      const present = entries.some((entry) => path.win32.normalize(entry).replace(/[\\/]+$/u, '').toLowerCase() === expected);
      const after = present ? retired.after : (retired.after ? `${retired.after}${delimiter}${plan.currentBin}` : plan.currentBin);
      if (after !== before) {
        if (typeof overrides.writeUserPath === 'function') await overrides.writeUserPath(after);
        else writeWindowsUserPath(after);
      }
    }
    updateProcessPath(plan, familyName);
  }
  return freeze({ ...result, kind: plan.kind, leaf: plan.leaf, changed: plan.changed || result.changed });
}
