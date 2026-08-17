import { spawn, spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import process from 'node:process';
import { setTimeout as delay } from 'node:timers/promises';

import { migrateLegacyBrand } from '../core/brand-migration.js';
import { requestGatewayModels } from '../core/gateway-client.js';
import { providerOwns } from '../providers/catalog.js';
import { attachUsage, collectProviderUsage } from '../providers/usage.js';
import { ClaudeyError } from '../core/errors.js';
import { createOfficialHttpsClient } from '../core/http.js';
import { getManagedPaths } from '../core/paths.js';
import { atomicReplace } from '../core/permissions.js';
import { downloadVerifiedRelease, resolveRelease } from '../core/release.js';
import { Secret } from '../core/secrets.js';
import { buildGatewayConfig, GATEWAY_CONFIG_CHILD } from '../core/config.js';
import { probeAuthCapabilities } from '../providers/auth.js';
import { buildManagedOAuthAliases } from '../providers/oauth-aliases.js';
import { createDefaultExecutableAdapter, resolveVerifiedExecutable } from '../core/executable.js';
import { defaultClaudeCandidates } from './launchers/claude-codex.js';

const INSTALLATION_CHILD = 'installation.json';
const TOKEN_CHILD = 'token';
const PID_CHILD = 'gateway.pid';

function failure(code, message, options) {
  return new ClaudeyError(code, message, options);
}

function notInstalled() {
  return failure('NOT_INSTALLED', 'Claudey is not installed.', { hint: 'Run claudey setup.' });
}

function pathApi() {
  return process.platform === 'win32' ? path.win32 : path.posix;
}

function managedPaths(environment = process.env) {
  const family = process.platform === 'win32' ? 'windows' : process.platform === 'darwin' ? 'macos' : 'linux';
  return getManagedPaths(family, environment);
}

function installationFile(paths) {
  return pathApi().join(paths.configRoot, INSTALLATION_CHILD);
}

function tokenFile(paths) {
  return pathApi().join(paths.configRoot, TOKEN_CHILD);
}

function configFile(paths) {
  return pathApi().join(paths.configRoot, 'config.yaml');
}

function pidFile(paths) {
  return pathApi().join(paths.stateRoot, PID_CHILD);
}

async function readJson(pathname) {
  try {
    return JSON.parse(await fs.readFile(pathname, 'utf8'));
  } catch {
    return null;
  }
}

export async function loadInstallation(environment = process.env) {
  const paths = managedPaths(environment);
  const record = await readJson(installationFile(paths));
  if (!record || record.schemaVersion !== 1 || !Number.isSafeInteger(record.port)
    || typeof record.executable !== 'string' || typeof record.installationId !== 'string') {
    throw notInstalled();
  }
  let tokenBytes;
  try { tokenBytes = await fs.readFile(tokenFile(paths)); } catch { throw notInstalled(); }
  if (!Buffer.isBuffer(tokenBytes) || tokenBytes.length !== 32) throw notInstalled();
  return {
    paths,
    installationId: record.installationId,
    port: record.port,
    version: record.version,
    executable: record.executable,
    token: Secret.fromBytes(tokenBytes)
  };
}

async function pathExists(pathname) {
  try {
    await fs.access(pathname);
    return true;
  } catch {
    return false;
  }
}

async function portFree(port) {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.unref();
    server.once('error', () => resolve(false));
    server.listen(port, '127.0.0.1', () => {
      server.close(() => resolve(true));
    });
  });
}

async function modelsReady(port, token) {
  try {
    await requestGatewayModels({
      host: '127.0.0.1',
      port,
      token,
      allowPreAuthEmpty: true
    });
    return true;
  } catch {
    return false;
  }
}

function providerFromAuthType(type) {
  if (type === 'codex') return 'codex';
  if (type === 'antigravity') return 'antigravity';
  if (type === 'xai' || type === 'grok') return 'grok';
  return null;
}

async function expectedAuthProviders(authDir) {
  if (typeof authDir !== 'string' || authDir.length < 2) return [];
  let names;
  try { names = await fs.readdir(authDir); } catch { return []; }
  const found = new Set();
  for (const name of names) {
    if (!name.endsWith('.json')) continue;
    try {
      const parsed = JSON.parse(await fs.readFile(path.join(authDir, name), 'utf8'));
      const provider = providerFromAuthType(parsed?.type);
      if (provider) found.add(provider);
    } catch { /* unreadable auth files are ignored for readiness */ }
  }
  return [...found];
}

function catalogCoversProviders(catalog, providers) {
  return providers.every((provider) => Array.isArray(catalog?.data)
    && catalog.data.some((model) => providerOwns(provider, model?.owned_by)));
}

async function waitForAuthModels(installed) {
  const expected = await expectedAuthProviders(installed.paths.authRoot);
  for (let attempt = 0; attempt < 40; attempt += 1) {
    try {
      const catalog = await requestGatewayModels({
        host: '127.0.0.1',
        port: installed.port,
        token: installed.token,
        allowPreAuthEmpty: true
      });
      if (expected.length === 0 || catalogCoversProviders(catalog, expected)) return true;
    } catch { /* gateway is still registering provider catalogs */ }
    await delay(250);
  }
  return modelsReady(installed.port, installed.token);
}

export async function syncManagedOAuthAliases({
  paths,
  port,
  token,
  models,
  fsApi = fs,
  atomicReplace: replace = atomicReplace
}) {
  const oauthModelAlias = buildManagedOAuthAliases(models);
  const bytes = buildGatewayConfig({
    port,
    authDir: paths.authRoot,
    token,
    oauthModelAlias
  });
  await replace({
    root: paths.configRoot,
    child: GATEWAY_CONFIG_CHILD,
    bytes,
    mode: 0o600
  }, { fsApi });
  return Object.freeze({ synced: true, oauthModelAlias });
}

export async function waitForManagedAliases({
  host = '127.0.0.1',
  port,
  token,
  aliases,
  requestModels = requestGatewayModels,
  timeoutMs = 8_000,
  delayMs = 100
}) {
  const expected = new Set();
  for (const entries of Object.values(aliases ?? {})) {
    for (const entry of entries) expected.add(entry.alias);
  }
  if (expected.size === 0) return true;
  const deadline = Date.now() + timeoutMs;
  while (Date.now() <= deadline) {
    try {
      const catalog = await requestModels({ host, port, token, allowPreAuthEmpty: true });
      const present = new Set((catalog?.data ?? []).map((model) => model?.id).filter(Boolean));
      if ([...expected].every((alias) => present.has(alias))) return true;
    } catch { /* gateway is still loading managed aliases */ }
    await delay(delayMs);
  }
  return false;
}

async function readPid(paths) {
  try {
    const text = (await fs.readFile(pidFile(paths), 'utf8')).trim();
    const pid = Number(text);
    return Number.isSafeInteger(pid) && pid > 0 ? pid : null;
  } catch {
    return null;
  }
}

function processAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function startGatewayProcess(installed) {
  if (await modelsReady(installed.port, installed.token)) {
    await waitForAuthModels(installed);
    return;
  }
  const pid = await readPid(installed.paths);
  if (pid && processAlive(pid) && await modelsReady(installed.port, installed.token)) {
    await waitForAuthModels(installed);
    return;
  }
  if (!(await portFree(installed.port)) && !(await modelsReady(installed.port, installed.token))) {
    throw failure('PORT_IN_USE', 'The managed gateway port is occupied by an unrelated listener.');
  }
  const child = spawn(installed.executable, ['--config', configFile(installed.paths)], {
    cwd: installed.paths.configRoot,
    detached: true,
    stdio: 'ignore',
    windowsHide: true,
    shell: false
  });
  child.unref();
  if (Number.isSafeInteger(child.pid) && child.pid > 0) {
    await fs.mkdir(installed.paths.stateRoot, { recursive: true, mode: 0o700 });
    await fs.writeFile(pidFile(installed.paths), `${child.pid}\n`, { mode: 0o600 });
  }
  if (await waitForAuthModels(installed)) return;
  throw failure('GATEWAY_UNHEALTHY', 'The managed gateway did not become healthy.');
}

async function stopGatewayProcess(environment = process.env) {
  const paths = managedPaths(environment);
  const pid = await readPid(paths);
  if (!pid) return { operation: 'stop', state: 'already-stopped' };
  if (processAlive(pid)) {
    try { process.kill(pid, 'SIGTERM'); } catch { /* already gone */ }
    for (let attempt = 0; attempt < 20 && processAlive(pid); attempt += 1) await delay(100);
    if (processAlive(pid)) {
      try { process.kill(pid, 'SIGKILL'); } catch { /* already gone */ }
    }
  }
  try { await fs.unlink(pidFile(paths)); } catch { /* missing pid file is a stop */ }
  return { operation: 'stop', state: 'stopped' };
}

export async function inspectCallbackPort({ port }) {
  return { state: await portFree(port) ? 'free' : 'busy', port };
}

function createLauncherContext(environment) {
  return {
    isTTY: Boolean(process.stdin?.isTTY && process.stdout?.isTTY),
    cwd: process.cwd(),
    baseEnvironment: environment,
    sessionSettingsDir: pathApi().join(managedPaths(environment).configRoot, 'claude-session'),
    sessionAuthDir: managedPaths(environment).authRoot,
    ensureGateway: async () => {
      const installed = await loadInstallation(environment);
      await startGatewayProcess(installed);
      return { host: '127.0.0.1', port: installed.port, token: installed.token };
    },
    syncOAuthAliases: async ({ models }) => {
      const installed = await loadInstallation(environment);
      return syncManagedOAuthAliases({
        paths: installed.paths,
        port: installed.port,
        token: installed.token,
        models
      });
    },
    waitForAliasReady: async ({ gateway, aliases }) => waitForManagedAliases({
      host: gateway.host,
      port: gateway.port,
      token: gateway.token,
      aliases
    }),
    selectModel: async ({ models }) => models[0]?.id
  };
}

function createGatewayQueryContext(environment) {
  const cursor = createCursorQueryContext(environment);
  const context = {
    host: '127.0.0.1',
    port: 8317,
    token: Secret.fromBytes(Buffer.alloc(32, 1)),
    requestModels: requestGatewayModels,
    modelReadyWaitMs: 8_000,
    cursor,
    verifyCursorPrerequisite: (...args) => cursor.verifyCursorPrerequisite(...args),
    listCursorModels: (...args) => cursor.listCursorModels(...args),
    async ensureHealthy() {
      const installed = await loadInstallation(environment);
      await startGatewayProcess(installed);
      context.host = '127.0.0.1';
      context.port = installed.port;
      context.token = installed.token;
      return { state: 'healthy' };
    },
    async attachUsage(result) {
      const collected = await collectProviderUsage({
        authDir: managedPaths(environment).authRoot,
        environment
      });
      return attachUsage(result, collected);
    }
  };
  return context;
}

function createAuthContext(environment) {
  return {
    isTTY: Boolean(process.stdin?.isTTY && process.stdout?.isTTY),
    environment,
    inspectCallbackPort,
    warn: (message) => {
      try { process.stderr.write(`${message}\n`); } catch { /* warning is best-effort */ }
    }
  };
}

function runAuthProbe({ executablePath, args, timeoutMs = 3_000, maxStdoutBytes = 16_384, maxStderrBytes = 16_384 }) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(executablePath, args, { shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    } catch {
      resolve({ code: -1, stdout: '', stderr: '', cleanupConfirmed: true });
      return;
    }
    let stdout = Buffer.alloc(0);
    let stderr = Buffer.alloc(0);
    const finish = (code) => {
      clearTimeout(timer);
      resolve({
        code,
        stdout: stdout.toString('utf8'),
        stderr: stderr.toString('utf8'),
        cleanupConfirmed: true
      });
    };
    child.stdout.on('data', (chunk) => {
      stdout = Buffer.concat([stdout, chunk]).subarray(0, maxStdoutBytes);
    });
    child.stderr.on('data', (chunk) => {
      stderr = Buffer.concat([stderr, chunk]).subarray(0, maxStderrBytes);
    });
    child.once('error', () => finish(-1));
    child.once('close', (code) => finish(code ?? -1));
    const timer = setTimeout(() => {
      try { child.kill(); } catch { /* already exited */ }
    }, timeoutMs);
  });
}

export async function prepareAuthContext(environment = process.env) {
  const installed = await loadInstallation(environment);
  const adapter = createDefaultExecutableAdapter();
  const cliProxy = await resolveVerifiedExecutable({
    command: 'cliproxyapi',
    platform: process.platform,
    candidates: [{ path: installed.executable }],
    adapter
  });
  return {
    isTTY: Boolean(process.stdin?.isTTY && process.stdout?.isTTY),
    environment,
    configPath: configFile(installed.paths),
    cwd: installed.paths.configRoot,
    capabilities: await probeAuthCapabilities({ cliProxy, run: runAuthProbe }),
    inspectCallbackPort,
    warn: (message) => {
      try { process.stderr.write(`${message}\n`); } catch { /* warning is best-effort */ }
    }
  };
}

async function extractArchive(archivePath, destination) {
  await fs.mkdir(destination, { recursive: true, mode: 0o755 });
  const tar = process.platform === 'win32' ? 'tar.exe' : 'tar';
  await new Promise((resolve, reject) => {
    const child = spawn(tar, ['-xf', archivePath, '-C', destination], { shell: false, windowsHide: true });
    child.once('error', reject);
    child.once('exit', (code) => {
      if (code === 0) resolve();
      else reject(failure('ARCHIVE_UNSAFE', 'The downloaded release archive could not be extracted.'));
    });
  });
}

async function findExtractedExecutable(root) {
  const wanted = process.platform === 'win32'
    ? new Set(['CLIProxyAPI.exe', 'cli-proxy-api.exe', 'cliproxyapi.exe'])
    : new Set(['CLIProxyAPI', 'cli-proxy-api', 'cliproxyapi']);
  const stack = [root];
  while (stack.length > 0) {
    const current = stack.pop();
    let entries;
    try { entries = await fs.readdir(current, { withFileTypes: true }); } catch { continue; }
    for (const entry of entries) {
      const next = path.join(current, entry.name);
      if (entry.isDirectory()) stack.push(next);
      else if (wanted.has(entry.name)) return next;
    }
  }
  throw failure('ARCHIVE_UNSAFE', 'The downloaded release did not contain the gateway executable.');
}

export async function runProductionSetup(options = {}, environment = process.env) {
  const migrated = await migrateLegacyBrand(environment, { noPath: options.noPath === true });
  try {
    const existing = await loadInstallation(environment);
    if (options.noStart !== true) await startGatewayProcess(existing);
    return Object.freeze({
      schemaVersion: 1,
      operation: 'setup',
      version: existing.version,
      port: existing.port,
      started: options.noStart !== true,
      changed: migrated.changed === true,
      launchers: Object.freeze(['claudey', 'claudeyctl', 'claude-codex', 'claude-agy', 'claude-grok'])
    });
  } catch (error) {
    if (error?.code !== 'NOT_INSTALLED') throw error;
  }

  const paths = managedPaths(environment);
  const port = options.port ?? 8317;
  const platform = {
    runtimePlatform: process.platform,
    runtimeArch: process.arch,
    platform: process.platform,
    arch: process.arch
  };
  await fs.mkdir(paths.configRoot, { recursive: true, mode: 0o700 });
  await fs.mkdir(paths.authRoot, { recursive: true, mode: 0o700 });
  await fs.mkdir(paths.releaseRoot, { recursive: true, mode: 0o755 });
  await fs.mkdir(paths.stateRoot, { recursive: true, mode: 0o700 });
  await fs.mkdir(paths.userBinRoot, { recursive: true, mode: 0o755 });

  const http = createOfficialHttpsClient();
  let requestedVersion = options.version;
  if (requestedVersion === undefined) {
    const latest = await http.get('https://api.github.com/repos/router-for-me/CLIProxyAPI/releases/latest', {
      deadlineMs: 30_000
    });
    if (latest.status !== 200) {
      throw failure('NETWORK_FAILURE', 'The latest CLIProxyAPI release could not be resolved.');
    }
    const chunks = [];
    for await (const chunk of latest.body) chunks.push(chunk);
    let payload;
    try { payload = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
    catch { throw failure('NETWORK_FAILURE', 'The latest CLIProxyAPI release metadata was not valid JSON.'); }
    const tag = typeof payload?.tag_name === 'string' ? payload.tag_name : '';
    requestedVersion = tag.startsWith('v') ? tag.slice(1) : tag;
  }
  const release = await resolveRelease({
    requestedVersion,
    platform,
    http
  });
  const downloaded = await downloadVerifiedRelease(release, release.asset, path.join(paths.stateRoot, 'staging'), { http });
  const extractRoot = path.join(paths.releaseRoot, release.version);
  await extractArchive(downloaded.path, extractRoot);
  const executable = await findExtractedExecutable(extractRoot);

  const tokenBytes = crypto.randomBytes(32);
  const token = Secret.fromBytes(tokenBytes);
  const installationId = crypto.randomUUID();
  await fs.writeFile(tokenFile(paths), tokenBytes, { mode: 0o600 });
  await fs.writeFile(configFile(paths), buildGatewayConfig({
    port,
    authDir: paths.authRoot,
    token
  }), { mode: 0o600 });
  await fs.writeFile(installationFile(paths), `${JSON.stringify({
    schemaVersion: 1,
    installationId,
    port,
    version: release.version,
    executable
  }, null, 2)}\n`, { mode: 0o600 });

  if (options.noStart !== true) {
    await startGatewayProcess({ paths, port, executable, token, installationId, version: release.version });
  }

  return Object.freeze({
    schemaVersion: 1,
    operation: 'setup',
    version: release.version,
    port,
    started: options.noStart !== true,
    launchers: Object.freeze(['claudey', 'claudeyctl', 'claude-codex', 'claude-agy', 'claude-grok'])
  });
}

export async function runProductionLifecycle(command, options = {}, environment = process.env) {
  if (command === 'stop') return stopGatewayProcess(environment);
  const installed = await loadInstallation(environment);
  if (command === 'status') {
    const healthy = await modelsReady(installed.port, installed.token);
    return { operation: 'status', state: healthy ? 'healthy' : 'stopped' };
  }
  if (command === 'restart') await stopGatewayProcess(environment);
  await startGatewayProcess(installed);
  return { operation: command === 'restart' ? 'restart' : 'start', state: options.foreground ? 'foreground' : 'started' };
}

function createCursorQueryContext(environment = process.env) {
  const run = (args) => {
    if (process.platform === 'win32' && environment.LOCALAPPDATA) {
      return spawnSync('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', [
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
        path.join(environment.LOCALAPPDATA, 'cursor-agent', 'cursor-agent.ps1'),
        ...args
      ], { encoding: 'utf8', windowsHide: true, timeout: 12_000, shell: false });
    }
    return spawnSync('cursor-agent', args, {
      encoding: 'utf8', windowsHide: true, timeout: 12_000, shell: false
    });
  };
  return {
    async verifyCursorPrerequisite() {
      try {
        const result = run(['status', '--format', 'json']);
        if (result.status !== 0 || typeof result.stdout !== 'string') return false;
        const parsed = JSON.parse(result.stdout);
        return parsed?.isAuthenticated === true;
      } catch { return false; }
    },
    async listCursorModels() {
      const result = run(['models']);
      if (result.status !== 0 || typeof result.stdout !== 'string') {
        throw new ClaudeyError('CAPABILITY_UNSUPPORTED', 'The live Cursor model catalog is unavailable.');
      }
      const models = [];
      for (const line of result.stdout.split(/\r?\n/u)) {
        const match = /^([A-Za-z0-9][A-Za-z0-9._:/-]{0,255})\s+-\s+/u.exec(line.trim());
        if (match) models.push(match[1]);
      }
      if (models.length === 0) {
        throw new ClaudeyError('CAPABILITY_UNSUPPORTED', 'The live Cursor model catalog is unavailable.');
      }
      return { models };
    }
  };
}

export function createProductionContainer(environment = process.env) {
  let launcher;
  let models;
  let auth;
  let cursor;
  const getLauncher = () => {
    if (!launcher) launcher = createLauncherContext(environment);
    return launcher;
  };
  return {
    contexts: {
      get claudey() { return getLauncher(); },
      get claudeyctl() { return getLauncher(); },
      get 'claude-codex'() { return getLauncher(); },
      get 'claude-agy'() { return getLauncher(); },
      get 'claude-grok'() { return getLauncher(); },
      get models() { return models ??= createGatewayQueryContext(environment); },
      get auth() { return auth ??= createAuthContext(environment); },
      get cursor() { return cursor ??= createCursorQueryContext(environment); },
      setup: { production: true },
      lifecycle: { production: true },
      status: { production: true }
    }
  };
}

export async function resolveClaudeExecutable(environment = process.env, options = {}) {
  const adapter = options.adapter ?? createDefaultExecutableAdapter();
  const candidates = options.candidates ?? defaultClaudeCandidates(process.platform, environment);
  for (const candidate of candidates) {
    try {
      const resolved = await resolveVerifiedExecutable({
        command: 'claude',
        platform: process.platform,
        candidates: [candidate],
        adapter
      });
      if (resolved) return resolved;
    } catch {
      continue;
    }
  }
  throw failure('PREREQUISITE_MISSING', 'A verified Claude Code executable is required.');
}
