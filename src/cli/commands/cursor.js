import path from 'node:path';

import { ClaudeyError } from '../../core/errors.js';
import { verifyManifest } from '../../core/manifest.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const APPROVAL = /^[A-Za-z0-9_-]{43}$/u;
const MODEL = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const GLOBAL_OPTIONS = new Set(['json', 'noColor', 'verbose', 'nonInteractive']);

function error(code, message) { return new ClaudeyError(code, message); }
function safety() { return error('SAFETY_REFUSAL', 'The Cursor management operation could not be completed safely.'); }
function usage(message = 'The Cursor command arguments are invalid.') { return error('USAGE_ERROR', message); }
function collision() { return error('MCP_OWNERSHIP_COLLISION', 'The Cursor plugin name or marketplace is owned by another installation.'); }
function interaction() { return error('INTERACTION_REQUIRED', 'Explicit confirmation is required for this Cursor operation.'); }
function prerequisite() { return error('PREREQUISITE_MISSING', 'A verified Cursor Agent installation is required.'); }

function record(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exact(value, keys) {
  return record(value) && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}

function freeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

function checkedOptions(raw, allowed, types = {}) {
  try {
    if (!record(raw)) throw usage();
    for (const key of Object.keys(raw)) {
      if (!allowed.includes(key) && !GLOBAL_OPTIONS.has(key)) throw usage();
      const type = types[key] ?? (GLOBAL_OPTIONS.has(key) ? 'boolean' : undefined);
      if (type === 'boolean' && typeof raw[key] !== 'boolean') throw usage();
      if (type === 'scope' && !['user', 'local'].includes(raw[key])) throw usage();
      if (type === 'path' && (typeof raw[key] !== 'string' || raw[key].length === 0 || /[\u0000\r\n]/u.test(raw[key]))) throw usage();
      if (type === 'approval' && (typeof raw[key] !== 'string' || !APPROVAL.test(raw[key]))) throw usage();
    }
    return raw;
  } catch (caught) {
    try { if (caught?.code === 'USAGE_ERROR') throw caught; } catch (inner) { throw inner; }
    throw safety();
  }
}

function requireFunction(context, name) {
  let value;
  try { value = context?.[name]; } catch { throw safety(); }
  if (typeof value !== 'function') throw safety();
  return value;
}

function checkedContext(context) {
  try {
    if (!record(context) || !UUID.test(context.installationId)
      || typeof context.managerRoot !== 'string' || typeof context.marketplaceRoot !== 'string'
      || typeof context.currentProject !== 'string' || !['windows', 'win32', 'linux', 'macos', 'darwin'].includes(context.platform)) throw safety();
    return context;
  } catch { throw safety(); }
}

function checkedRegistration(value, installationId) {
  if (!exact(value, ['marketplace', 'plugin', 'ownerInstallationId'])
    || !['absent', 'owned', 'foreign'].includes(value.marketplace)
    || !['absent', 'owned', 'foreign'].includes(value.plugin)
    || value.ownerInstallationId !== null && !UUID.test(value.ownerInstallationId)
    || (value.marketplace === 'owned' || value.plugin === 'owned') && value.ownerInstallationId !== installationId
    || value.marketplace === 'absent' && value.plugin === 'owned') throw safety();
  if (value.marketplace === 'foreign' || value.plugin === 'foreign') throw collision();
  return value;
}

async function pluginState(context, scope) {
  let value;
  try { value = await requireFunction(context, 'inspectPluginRegistration')({ scope }); }
  catch (caught) {
    try { if (caught?.code === 'MCP_OWNERSHIP_COLLISION') throw caught; } catch (inner) { throw inner; }
    throw safety();
  }
  return checkedRegistration(value, context.installationId);
}

async function runPlugin(context, args) {
  try { await requireFunction(context, 'runClaudePlugin')(freeze([...args])); }
  catch { throw safety(); }
}

async function writeWrites(context, enabled) {
  try {
    await context.writesStore.write(freeze({ schemaVersion: 1, installationId: context.installationId, enabled }));
  } catch { throw safety(); }
}

async function readWrites(context) {
  let value;
  try { value = await context.writesStore.read(); } catch { throw safety(); }
  if (!exact(value, ['schemaVersion', 'installationId', 'enabled']) || value.schemaVersion !== 1
    || value.installationId !== context.installationId || typeof value.enabled !== 'boolean') throw safety();
  return value;
}

async function clearApprovals(context) {
  try {
    const result = await context.approvalService.cleanup();
    if (!exact(result, ['action']) || result.action !== 'cleared') throw safety();
  } catch { throw safety(); }
}

async function enable(options, context) {
  const scope = options.scope;
  if (!scope) throw usage('cursor enable requires a scope.');
  const state = await pluginState(context, scope);
  const alreadyEnabled = state.marketplace === 'owned' && state.plugin === 'owned';
  if (!alreadyEnabled) {
    if (state.marketplace === 'absent') {
      await runPlugin(context, ['plugin', 'marketplace', 'add', context.marketplaceRoot, '--scope', scope]);
    }
    if (state.plugin === 'absent') {
      await runPlugin(context, ['plugin', 'install', 'cursor-agent@claudey', '--scope', scope]);
    }
    try { await requireFunction(context, 'writePluginOwnership')({ scope, installationId: context.installationId,
      managerRoot: context.managerRoot, marketplaceRoot: context.marketplaceRoot }); } catch { throw safety(); }
  }
  if (scope === 'local') {
    try { await context.registry.add({ path: context.currentProject, scope: 'local',
      currentProject: context.currentProject, confirmed: true }); } catch { throw safety(); }
  }
  return freeze(alreadyEnabled ? { action: 'preserved', reason: 'already-enabled', scope } : { action: 'enabled', scope });
}

async function disable(options, context) {
  const scope = options.scope;
  if (!scope) throw usage('cursor disable requires a scope.');
  const state = await pluginState(context, scope);
  const alreadyDisabled = state.marketplace === 'absent' && state.plugin === 'absent';
  if (!alreadyDisabled) {
    if (state.plugin === 'owned') {
      await runPlugin(context, ['plugin', 'uninstall', 'cursor-agent@claudey', '--scope', scope, '--yes']);
    }
    if (state.marketplace === 'owned') {
      await runPlugin(context, ['plugin', 'marketplace', 'remove', 'claudey', '--scope', scope]);
    }
    try { await requireFunction(context, 'removePluginOwnership')({ scope, installationId: context.installationId }); }
    catch { throw safety(); }
  }
  await writeWrites(context, false);
  await clearApprovals(context);
  return freeze(alreadyDisabled ? { action: 'preserved', reason: 'already-disabled', scope } : { action: 'disabled', scope });
}

function checkedInstaller(value, platform) {
  try {
    if (!exact(value, ['finalUrl', 'sha256', 'path']) || !/^[0-9a-f]{64}$/u.test(value.sha256)) throw safety();
    const url = new URL(value.finalUrl);
    if (url.protocol !== 'https:' || url.username || url.password || url.hash
      || !(url.hostname === 'cursor.com' || url.hostname.endsWith('.cursor.com'))) throw safety();
    const pathApi = platform === 'windows' || platform === 'win32' ? path.win32 : path.posix;
    if (typeof value.path !== 'string' || !pathApi.isAbsolute(value.path) || pathApi.normalize(value.path) !== value.path
      || value.path === pathApi.parse(value.path).root) throw safety();
    return freeze({ finalUrl: url.href, sha256: value.sha256, path: value.path });
  } catch { throw safety(); }
}

async function install(options, context) {
  if (options.nonInteractive === true && options.yes !== true) throw interaction();
  let available = false;
  try { available = await requireFunction(context, 'cursorAvailable')() === true; } catch { throw safety(); }
  if (available) return freeze({ action: 'preserved', reason: 'already-installed' });
  const url = context.platform === 'windows' || context.platform === 'win32'
    ? 'https://cursor.com/install?win32=true' : 'https://cursor.com/install';
  let descriptor;
  try { descriptor = checkedInstaller(await requireFunction(context, 'downloadCursorInstaller')({
    url, maxBytes: 268_435_456, allowedHttpsHosts: ['cursor.com', 'www.cursor.com', 'download.cursor.com']
  }), context.platform); } catch { throw safety(); }
  const display = freeze({
    warning: 'Cursor publishes no stable detached checksum for this installer; verify the final Cursor-owned URL and SHA-256 before execution.',
    finalUrl: descriptor.finalUrl, sha256: descriptor.sha256,
    yes: options.yes === true, nonInteractive: options.nonInteractive === true
  });
  let confirmed = false;
  try { confirmed = await requireFunction(context, 'confirmCursorInstaller')(display) === true; } catch { throw safety(); }
  if (!confirmed) throw interaction();
  try { await requireFunction(context, 'executeCursorInstaller')(descriptor); } catch { throw safety(); }
  let verified = false;
  try { verified = await requireFunction(context, 'verifyCursorPrerequisite')() === true; } catch { throw safety(); }
  if (!verified) throw prerequisite();
  return freeze({ action: 'installed', sha256: descriptor.sha256, finalUrl: descriptor.finalUrl });
}

async function requireCursor(context) {
  let verified = false;
  try { verified = await requireFunction(context, 'verifyCursorPrerequisite')() === true; } catch { throw safety(); }
  if (!verified) throw prerequisite();
}

async function login(options, context) {
  if (options.nonInteractive === true) throw interaction();
  await requireCursor(context);
  let result;
  try { result = await requireFunction(context, 'runCursorLogin')(); } catch { throw safety(); }
  if (!exact(result, ['code', 'signal']) || result.code !== 0 || result.signal !== null) throw error('AUTH_REQUIRED', 'Cursor Agent login did not complete.');
  return freeze({ action: 'authenticated' });
}

async function repo(command, options, context) {
  const action = command[2];
  if (action === 'list') {
    let repositories;
    try { repositories = await context.registry.list(); } catch { throw safety(); }
    if (!Array.isArray(repositories)) throw safety();
    return freeze({ repositories: [...repositories] });
  }
  const target = options.path ?? context.currentProject;
  if (action === 'add') {
    const scope = options.path === undefined ? 'local' : 'user';
    try { return freeze(await context.registry.add({ path: target, scope, currentProject: context.currentProject,
      confirmed: options.yes === true })); } catch (caught) {
      try { if (caught?.code === 'INTERACTION_REQUIRED') throw caught; } catch (inner) { throw inner; }
      throw safety();
    }
  }
  if (action === 'remove') {
    let confirmed = options.yes === true;
    if (!confirmed && options.path === undefined) {
      let repositories;
      try { repositories = await context.registry.list(); } catch { throw safety(); }
      if (!Array.isArray(repositories) || repositories.length > 1_024
        || repositories.some((entry) => !exact(entry, ['root', 'scope']) || typeof entry.root !== 'string'
          || !['local', 'user'].includes(entry.scope))) throw safety();
      const same = context.platform === 'windows' || context.platform === 'win32'
        ? (left, right) => left.toLowerCase() === right.toLowerCase() : (left, right) => left === right;
      confirmed = repositories.some((entry) => entry.scope === 'local' && same(entry.root, context.currentProject));
    }
    try { return freeze(await context.registry.remove({ path: target, confirmed })); }
    catch (caught) {
      try { if (caught?.code === 'INTERACTION_REQUIRED') throw caught; } catch (inner) { throw inner; }
      throw safety();
    }
  }
  throw usage();
}

async function writes(command, options, context) {
  const action = command[2];
  if (action === 'enable') {
    if (options.yes !== true) throw interaction();
    if ((await readWrites(context)).enabled) return freeze({ action: 'preserved', reason: 'already-enabled' });
    await writeWrites(context, true);
    return freeze({ action: 'enabled' });
  }
  if (action === 'disable') {
    await writeWrites(context, false);
    await clearApprovals(context);
    return freeze({ action: 'disabled' });
  }
  throw usage();
}

async function approve(options, context) {
  try {
    return freeze(await context.approvalService.approve(options.approvalId, {
      isTTY: context.isTTY === true, confirm: requireFunction(context, 'confirmApproval')
    }));
  } catch (caught) {
    let code;
    try { code = caught?.code; } catch { code = undefined; }
    if (['APPROVAL_INVALID', 'INTERACTION_REQUIRED'].includes(code)) {
      throw error(code, code === 'INTERACTION_REQUIRED' ? 'Cursor approval requires an interactive terminal.'
        : 'The Cursor approval is invalid, expired, declined, or already consumed.');
    }
    throw safety();
  }
}

export async function runCursorCommand(command, rawOptions = {}, rawContext = {}) {
  const context = checkedContext(rawContext);
  if (!Array.isArray(command) || command[0] !== 'cursor') throw usage();
  const action = command[1];
  if (action === 'enable' || action === 'disable') {
    if (command.length !== 2) throw usage();
    const options = checkedOptions(rawOptions, ['scope'], { scope: 'scope' });
    return action === 'enable' ? enable(options, context) : disable(options, context);
  }
  if (action === 'install') {
    if (command.length !== 2) throw usage();
    return install(checkedOptions(rawOptions, ['yes'], { yes: 'boolean' }), context);
  }
  if (action === 'login') {
    if (command.length !== 2) throw usage();
    const options = checkedOptions(rawOptions, []);
    return login(options, context);
  }
  if (action === 'repo') {
    if (command.length !== 3 || !['add', 'list', 'remove'].includes(command[2])) throw usage();
    return repo(command, checkedOptions(rawOptions, ['path', 'yes'], { path: 'path', yes: 'boolean' }), context);
  }
  if (action === 'writes') {
    if (command.length !== 3 || !['enable', 'disable'].includes(command[2])) throw usage();
    return writes(command, checkedOptions(rawOptions, command[2] === 'enable' ? ['yes'] : [], { yes: 'boolean' }), context);
  }
  if (action === 'approve') {
    if (command.length !== 2) throw usage();
    return approve(checkedOptions(rawOptions, ['approvalId'], { approvalId: 'approval' }), context);
  }
  throw usage();
}

function checkedModels(value) {
  if (!exact(value, ['models']) || !Array.isArray(value.models) || value.models.length === 0 || value.models.length > 1_024) throw safety();
  const seen = new Set();
  const models = value.models.map((model) => {
    if (typeof model !== 'string' || !MODEL.test(model) || seen.has(model)) throw safety();
    seen.add(model); return model;
  });
  return freeze(models.sort((left, right) => left.localeCompare(right)));
}

export async function runCursorModelsCommand(context) {
  await requireCursor(context);
  let models;
  try { models = checkedModels(await requireFunction(context, 'listCursorModels')()); } catch { throw safety(); }
  return freeze({ provider: 'cursor', models });
}

export function createCursorMcpToolExecutor({
  resolveSourceRepository, listCursorModels, resolveRepository, readonlyService, worktreeService, defaultBaseRef
} = {}) {
  if (typeof resolveSourceRepository !== 'function' || typeof listCursorModels !== 'function'
    || typeof resolveRepository !== 'function' || !readonlyService || typeof readonlyService.ask !== 'function'
    || typeof readonlyService.plan !== 'function' || !worktreeService || typeof worktreeService.run !== 'function'
    || typeof defaultBaseRef !== 'string') throw safety();
  return async ({ name, arguments: args, signal } = {}) => {
    if (!signal || typeof signal.addEventListener !== 'function') throw safety();
    const models = checkedModels(await listCursorModels());
    if (name === 'cursor_models') return freeze({ models });
    const model = args.model ?? models[0];
    if (!models.includes(model)) throw error('MODEL_NOT_FOUND', 'The requested Cursor model is unavailable.');
    if (name === 'cursor_ask' || name === 'cursor_plan') {
      let sourceRepository;
      try { sourceRepository = await resolveSourceRepository(); } catch { throw safety(); }
      if (!sourceRepository) throw safety();
      if (!record(sourceRepository)) throw safety();
      const input = { repository: sourceRepository, prompt: args.prompt, model,
        ...(Object.hasOwn(args, 'paths') ? { paths: [...args.paths] } : {}) };
      return readonlyService[name === 'cursor_ask' ? 'ask' : 'plan'](freeze(input), { signal });
    }
    if (name === 'cursor_worktree_run') {
      let repository;
      try { repository = await resolveRepository(args.repo); } catch { throw safety(); }
      if (!record(repository)) throw safety();
      return worktreeService.run(freeze({ repository, prompt: args.prompt, model,
        baseRef: args.baseRef ?? defaultBaseRef,
        ...(Object.hasOwn(args, 'approvalId') ? { approvalId: args.approvalId } : {}) }), { signal });
    }
    throw safety();
  };
}

function safeRoot(value) {
  const pathApi = typeof value === 'string' && /^[A-Za-z]:\\/u.test(value) ? path.win32 : path.posix;
  return typeof value === 'string' && pathApi.isAbsolute(value) && pathApi.normalize(value) === value
    && value !== pathApi.parse(value).root && !/[\u0000\r\n]/u.test(value);
}

export async function runCursorMcpServe(rawOptions, context = {}) {
  try {
    if (!exact(rawOptions, Object.hasOwn(rawOptions ?? {}, 'sourceRoot')
      ? ['installationId', 'managerRoot', 'sourceRoot'] : ['installationId', 'managerRoot'])
      || !UUID.test(rawOptions.installationId) || !safeRoot(rawOptions.managerRoot)
      || Object.hasOwn(rawOptions, 'sourceRoot') && !safeRoot(rawOptions.sourceRoot)
      || typeof context.readManifest !== 'function' || typeof context.revalidateMcpPaths !== 'function'
      || typeof context.createServer !== 'function' || typeof context.serveMcp !== 'function') throw safety();
    const manifest = verifyManifest(await context.readManifest(), context.manifestKey, { fixedPaths: context.fixedPaths });
    const family = manifest.platform.family === 'windows' ? 'windows' : 'posix';
    const sameRoot = family === 'windows'
      ? manifest.managedRoots.managerRoot.toLowerCase() === rawOptions.managerRoot.toLowerCase()
      : manifest.managedRoots.managerRoot === rawOptions.managerRoot;
    if (manifest.installationId !== rawOptions.installationId || !sameRoot) throw safety();
    const proof = freeze({ manifest, managerRoot: rawOptions.managerRoot,
      pluginRoots: [...manifest.managedRoots.ownedPluginRoots] });
    const revalidateStartup = async () => {
      try { return await context.revalidateMcpPaths(proof) === true; } catch { return false; }
    };
    if (!await revalidateStartup()) throw safety();
    const server = await context.createServer(freeze({ manifest, revalidateStartup,
      ...(Object.hasOwn(rawOptions, 'sourceRoot') ? { sourceRoot: rawOptions.sourceRoot } : {}) }));
    const result = await context.serveMcp(server);
    if (!exact(result, ['action']) || result.action !== 'closed') throw safety();
    return freeze({ action: 'closed' });
  } catch { throw safety(); }
}
