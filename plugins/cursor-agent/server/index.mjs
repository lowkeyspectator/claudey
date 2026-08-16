import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const ALLOWED_ENVIRONMENT = new Set([
  'PATH', 'HOME', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA', 'SystemRoot', 'WINDIR',
  'TMP', 'TEMP', 'TMPDIR', 'LANG', 'LC_ALL', 'TERM', 'COLORTERM'
]);

function refusal() {
  const error = new Error('The Claudey Cursor plugin bootstrap is unsafe.');
  error.code = 'SAFETY_REFUSAL';
  return error;
}

function record(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null));
}

function exact(value, keys) {
  return record(value) && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}

function family(value) { return typeof value === 'string' && /^[A-Za-z]:\\/u.test(value) ? path.win32 : path.posix; }

function safeAbsolute(value, pathApi) {
  if (typeof value !== 'string' || value.length === 0 || /[\u0000\r\n]/u.test(value)
    || !pathApi.isAbsolute(value) || pathApi.normalize(value) !== value || value === pathApi.parse(value).root) throw refusal();
  return value;
}

function contained(root, child, pathApi) {
  const relative = pathApi.relative(root, child);
  return relative !== '' && relative !== '..' && !relative.startsWith(`..${pathApi.sep}`) && !pathApi.isAbsolute(relative);
}

function minimalEnvironment(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw refusal();
  const result = {};
  for (const key of ALLOWED_ENVIRONMENT) {
    if (typeof value[key] === 'string' && value[key].length <= 32_768 && !value[key].includes('\0')) result[key] = value[key];
  }
  result.CLAUDE_CODE_SUBPROCESS_ENV_SCRUB = '1';
  return Object.freeze(result);
}

export function buildManagerInvocation({
  nodePath, managerPath, managerRoot, installationId, pluginRoot, sourceRoot, ambientEnvironment
} = {}) {
  try {
    const pathApi = family(managerRoot);
    const root = safeAbsolute(managerRoot, pathApi);
    const manager = safeAbsolute(managerPath, pathApi);
    const node = safeAbsolute(nodePath, pathApi);
    safeAbsolute(pluginRoot, pathApi);
    if (!contained(root, manager, pathApi) || !UUID.test(installationId)) throw refusal();
    const args = [manager, 'cursor', 'mcp-serve'];
    if (sourceRoot !== undefined) args.push('--source-root', safeAbsolute(sourceRoot, pathApi));
    args.push('--installation-id', installationId, '--manager-root', root);
    return Object.freeze({
      executable: node, args: Object.freeze(args), cwd: root,
      env: minimalEnvironment(ambientEnvironment), stdio: 'inherit', shell: false
    });
  } catch { throw refusal(); }
}

function checkedManager(value) {
  if (!exact(value, ['nodePath', 'managerPath', 'managerRoot', 'installationId']) || !UUID.test(value.installationId)) throw refusal();
  return Object.freeze({ ...value });
}

function safeSourceState(value) {
  try {
    if (!exact(value, ['safe', 'canonicalPath', 'gitRoot', 'isLink', 'isJunction', 'isReparsePoint'])
      || value.safe !== true || value.isLink !== false || value.isJunction !== false || value.isReparsePoint !== false
      || typeof value.canonicalPath !== 'string' || value.canonicalPath !== value.gitRoot) return undefined;
    const pathApi = family(value.gitRoot);
    return safeAbsolute(value.gitRoot, pathApi);
  } catch { return undefined; }
}

export async function runPluginForwarder({
  cwd, pluginRoot, ambientEnvironment, inspectSourceRoot, discoverManager, revalidateManager, spawnManager
} = {}) {
  if (typeof inspectSourceRoot !== 'function' || typeof discoverManager !== 'function'
    || typeof revalidateManager !== 'function' || typeof spawnManager !== 'function') throw refusal();
  let sourceRoot;
  try { sourceRoot = safeSourceState(await inspectSourceRoot(cwd)); } catch { sourceRoot = undefined; }
  let manager;
  try { manager = checkedManager(await discoverManager()); } catch { throw refusal(); }
  const invocation = buildManagerInvocation({ ...manager, pluginRoot, sourceRoot, ambientEnvironment });
  let current = false;
  try { current = await revalidateManager(Object.freeze({ manager, pluginRoot })) === true; } catch { current = false; }
  if (!current) throw refusal();
  let result;
  try { result = await spawnManager(invocation); } catch { throw refusal(); }
  if (!exact(result, ['code', 'signal']) || !Number.isSafeInteger(result.code) || result.code < 0 || result.code > 255
    || result.signal !== null && typeof result.signal !== 'string') throw refusal();
  return Object.freeze({ code: result.code, signal: result.signal });
}

async function linkFreeCanonical(candidate) {
  try {
    const pathApi = family(candidate);
    const normalized = safeAbsolute(pathApi.resolve(candidate), pathApi);
    const canonical = await fs.realpath(normalized);
    const equivalent = pathApi === path.win32 ? canonical.toLowerCase() === normalized.toLowerCase() : canonical === normalized;
    if (!equivalent) return null;
    const parsed = pathApi.parse(normalized);
    let current = parsed.root;
    for (const part of normalized.slice(parsed.root.length).split(pathApi.sep).filter(Boolean)) {
      current = pathApi.join(current, part);
      if ((await fs.lstat(current)).isSymbolicLink()) return null;
    }
    let root = normalized;
    while (root !== pathApi.parse(root).root) {
      try {
        const git = await fs.lstat(pathApi.join(root, '.git'));
        if (!git.isSymbolicLink() && (git.isDirectory() || git.isFile())) return {
          safe: true, canonicalPath: root, gitRoot: root, isLink: false, isJunction: false, isReparsePoint: false
        };
      } catch { /* continue upward */ }
      root = pathApi.dirname(root);
    }
    return null;
  } catch { return null; }
}

async function defaultManager(pluginRoot) {
  const raw = JSON.parse(await fs.readFile(path.join(pluginRoot, '.claudey-owner.json'), 'utf8'));
  if (!exact(raw, ['schemaVersion', 'managerPath', 'managerRoot', 'installationId']) || raw.schemaVersion !== 1) throw refusal();
  return { nodePath: process.execPath, managerPath: raw.managerPath, managerRoot: raw.managerRoot,
    installationId: raw.installationId };
}

async function linkFreeExact(candidate, expectedKind) {
  const pathApi = family(candidate);
  const normalized = safeAbsolute(candidate, pathApi);
  const parsed = pathApi.parse(normalized);
  let current = parsed.root;
  for (const part of normalized.slice(parsed.root.length).split(pathApi.sep).filter(Boolean)) {
    current = pathApi.join(current, part);
    const metadata = await fs.lstat(current);
    if (metadata.isSymbolicLink()) return false;
  }
  const leaf = await fs.lstat(normalized);
  if (expectedKind === 'directory' ? !leaf.isDirectory() : !leaf.isFile()) return false;
  const canonical = await fs.realpath(normalized);
  return pathApi === path.win32 ? canonical.toLowerCase() === normalized.toLowerCase() : canonical === normalized;
}

async function defaultRevalidate(proof) {
  try {
    if (!exact(proof, ['manager', 'pluginRoot'])) return false;
    const manager = checkedManager(proof.manager);
    const pathApi = family(manager.managerRoot);
    safeAbsolute(proof.pluginRoot, pathApi);
    if (!contained(manager.managerRoot, manager.managerPath, pathApi)) return false;
    return await linkFreeExact(manager.managerRoot, 'directory')
      && await linkFreeExact(manager.managerPath, 'file')
      && await linkFreeExact(proof.pluginRoot, 'directory');
  } catch { return false; }
}

function defaultSpawn(invocation) {
  return new Promise((resolve, reject) => {
    const child = spawn(invocation.executable, invocation.args, {
      cwd: invocation.cwd, env: invocation.env, stdio: invocation.stdio, shell: invocation.shell
    });
    child.once('error', reject);
    child.once('close', (code, signal) => resolve({ code: code ?? 1, signal: signal ?? null }));
  });
}

async function main() {
  const pluginRoot = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
  const result = await runPluginForwarder({
    cwd: process.cwd(), pluginRoot, ambientEnvironment: process.env,
    inspectSourceRoot: linkFreeCanonical,
    discoverManager: () => defaultManager(pluginRoot),
    revalidateManager: defaultRevalidate,
    spawnManager: defaultSpawn
  });
  process.exitCode = result.code;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch(() => {
    process.stderr.write('error[SAFETY_REFUSAL]: The Claudey Cursor plugin could not start safely.\n');
    process.exitCode = 7;
  });
}
