import path from 'node:path';

import { ClaudeyError } from './errors.js';

const PLANS = new WeakSet();
const BEGIN = '# >>> claudeyctl PATH >>>';
const END = '# <<< claudeyctl PATH <<<';

function safety(message = 'PATH mutation could not be completed safely.') {
  return new ClaudeyError('SAFETY_REFUSAL', message);
}

function safeString(value, label, { empty = false, multiline = false } = {}) {
  if (typeof value !== 'string' || (!empty && value.length === 0)
    || value.includes('\0') || value.includes('\r') || !multiline && value.includes('\n')) throw safety(`${label} is invalid.`);
  return value;
}

function checkedOptions(value) {
  const allowed = new Set(['platform', 'binDirectory', 'noPath', 'currentShellPath', 'userPath', 'profilePath', 'profileText']);
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw safety();
    const keys = Object.keys(value);
    if (keys.some((key) => !allowed.has(key))) throw safety();
    const result = {};
    for (const key of keys) result[key] = value[key];
    return result;
  } catch (caught) {
    try { if (caught?.code === 'SAFETY_REFUSAL') throw caught; } catch { /* sanitize below */ }
    throw safety();
  }
}

function family(platform) {
  if (platform === 'windows' || platform === 'win32') return 'windows';
  if (platform === 'linux' || platform === 'darwin' || platform === 'macos') return 'posix';
  throw safety('PATH mutation is unavailable for this platform.');
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

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
  }
  return value;
}

function pathEntries(value, delimiter) {
  return safeString(value ?? '', 'PATH', { empty: true }).split(delimiter).filter((entry) => entry.length > 0);
}

function normalizeEntry(value, kind) {
  return kind === 'windows' ? path.win32.normalize(value).replace(/[\\/]+$/u, '').toLowerCase() : path.posix.normalize(value).replace(/\/+$/u, '');
}

function visible(currentShellPath, binDirectory, kind) {
  const delimiter = kind === 'windows' ? ';' : ':';
  const expected = normalizeEntry(binDirectory, kind);
  return pathEntries(currentShellPath ?? '', delimiter).some((entry) => normalizeEntry(entry, kind) === expected);
}

function launcher(binDirectory, kind) {
  return kind === 'windows' ? path.win32.join(binDirectory, 'claudeyctl.exe') : path.posix.join(binDirectory, 'claudeyctl');
}

function remediation(binDirectory, kind, shellVisible, changed) {
  return freeze({ restartShell: changed && !shellVisible, absoluteLauncher: launcher(binDirectory, kind) });
}

function shellDoubleQuoted(value) {
  return value.replaceAll('\\', '\\\\').replaceAll('"', '\\"').replaceAll('$', '\\$').replaceAll('`', '\\`');
}

function ownedBlock(binDirectory) {
  return `${BEGIN}\nexport PATH="${shellDoubleQuoted(binDirectory)}:$PATH"\n${END}\n`;
}

function occurrences(text, needle) {
  let count = 0;
  let offset = 0;
  while ((offset = text.indexOf(needle, offset)) !== -1) { count += 1; offset += needle.length; }
  return count;
}

export function planPathMutation(options = {}) {
  options = checkedOptions(options);
  let platform;
  let binDirectory;
  let noPath;
  let currentShellPath;
  try {
    ({ platform, binDirectory, noPath = false, currentShellPath = '' } = options);
  } catch { throw safety(); }
  if (Object.hasOwn(options, 'noPath') && typeof options.noPath !== 'boolean') throw safety('noPath must be Boolean.');
  if (Object.hasOwn(options, 'currentShellPath') && typeof options.currentShellPath !== 'string') throw safety();
  const kind = family(platform);
  const pathApi = kind === 'windows' ? path.win32 : path.posix;
  safeString(binDirectory, 'Bin directory');
  if (!pathApi.isAbsolute(binDirectory) || pathApi.normalize(binDirectory) === pathApi.parse(binDirectory).root) {
    throw safety('Bin directory must be a safe absolute non-root path.');
  }
  const shellVisible = visible(currentShellPath, binDirectory, kind);
  if (noPath) return branded({
    schemaVersion: 1, kind: 'none', changed: false, binDirectory, shellVisible,
    remediation: { restartShell: false, absoluteLauncher: launcher(binDirectory, kind) }
  });

  if (kind === 'windows') {
    if (Object.hasOwn(options, 'userPath') && typeof options.userPath !== 'string') throw safety();
    const before = safeString(options.userPath ?? '', 'User PATH', { empty: true });
    const expected = normalizeEntry(binDirectory, kind);
    const entries = before === '' ? [] : before.split(';');
    const afterEntries = [];
    let kept = false;
    for (const entry of entries) {
      if (normalizeEntry(entry, kind) === expected) {
        if (kept) continue;
        kept = true;
      }
      afterEntries.push(entry);
    }
    if (!kept) afterEntries.push(binDirectory);
    const after = afterEntries.join(';');
    const changed = after !== before;
    return branded({
      schemaVersion: 1, kind: 'windows-user-path', changed, binDirectory, before, after,
      owned: changed, shellVisible, remediation: remediation(binDirectory, kind, shellVisible, changed)
    });
  }

  const profilePath = safeString(options.profilePath, 'Profile path');
  if (!path.posix.isAbsolute(profilePath)) throw safety('Profile path must be absolute.');
  if (Object.hasOwn(options, 'profileText') && typeof options.profileText !== 'string') throw safety();
  const before = safeString(options.profileText ?? '', 'Profile text', { empty: true, multiline: true });
  const beginCount = occurrences(before, BEGIN);
  const endCount = occurrences(before, END);
  if (beginCount !== endCount || beginCount > 1) throw safety('The Claudey PATH marker block is ambiguous.');
  const block = ownedBlock(binDirectory);
  if (beginCount === 1) {
    const blockOffset = before.indexOf(block);
    if (blockOffset < 0 || blockOffset > 0 && before[blockOffset - 1] !== '\n') {
      throw safety('The Claudey PATH marker block was modified.');
    }
    return branded({
      schemaVersion: 1, kind: 'posix-profile-block', changed: false, binDirectory, profilePath,
      before, after: before, block, owned: false, shellVisible,
      remediation: remediation(binDirectory, kind, shellVisible, false)
    });
  }
  const separator = before.length > 0 && !before.endsWith('\n') ? '\n' : '';
  const after = `${before}${separator}${block}`;
  return branded({
    schemaVersion: 1, kind: 'posix-profile-block', changed: true, binDirectory, profilePath,
    before, after, block, owned: true, shellVisible,
    remediation: remediation(binDirectory, kind, shellVisible, true)
  });
}

export function loadPathMutationRecord(record, expected = {}) {
  try {
    if (!record || typeof record !== 'object' || Array.isArray(record)) throw safety();
    const binDirectory = safeString(expected.binDirectory, 'Expected bin directory');
    if (record.binDirectory !== binDirectory || typeof record.shellVisible !== 'boolean') throw safety();
    let platform;
    if (path.win32.isAbsolute(binDirectory) && !path.posix.isAbsolute(binDirectory)) platform = 'win32';
    else if (path.posix.isAbsolute(binDirectory)) platform = 'linux';
    else throw safety();
    const common = { platform, binDirectory, currentShellPath: record.shellVisible ? binDirectory : '' };
    let rebuilt;
    if (record.kind === 'none') rebuilt = planPathMutation({ ...common, noPath: true });
    else if (record.kind === 'windows-user-path') {
      rebuilt = planPathMutation({ ...common, userPath: safeString(record.before, 'Recorded PATH', { empty: true }) });
    } else if (record.kind === 'posix-profile-block') {
      const profilePath = safeString(expected.profilePath, 'Expected profile path');
      if (record.profilePath !== profilePath) throw safety();
      rebuilt = planPathMutation({
        ...common, profilePath, profileText: safeString(record.before, 'Recorded profile', { empty: true, multiline: true })
      });
    } else throw safety();
    if (JSON.stringify(stable(record)) !== JSON.stringify(stable(rebuilt))) throw safety();
    return rebuilt;
  } catch (caught) {
    if (caught?.code === 'SAFETY_REFUSAL') throw caught;
    throw safety();
  }
}

export async function applyPathMutation(plan, adapter = {}) {
  if (!PLANS.has(plan)) throw safety('PATH mutation requires a trusted plan.');
  if (!plan.changed) return { action: 'preserved', reason: 'not-owned' };
  if (plan.kind === 'windows-user-path') {
    if (typeof adapter.writeUserPath !== 'function') throw safety();
    await adapter.writeUserPath(plan.after);
  } else if (plan.kind === 'posix-profile-block') {
    if (typeof adapter.writeProfile !== 'function') throw safety();
    await adapter.writeProfile(plan.profilePath, plan.after);
  } else throw safety();
  return { action: 'applied', reason: 'owned-change' };
}

export async function restorePathMutation(plan, adapter = {}) {
  if (!PLANS.has(plan)) throw safety('PATH restoration requires a trusted plan.');
  if (!plan.changed || plan.owned !== true) return { action: 'preserved', reason: 'not-owned' };
  if (plan.kind === 'windows-user-path') {
    if (typeof adapter.readUserPath !== 'function' || typeof adapter.writeUserPath !== 'function') throw safety();
    const current = await adapter.readUserPath();
    if (current !== plan.after) return { action: 'preserved', reason: 'modified' };
    await adapter.writeUserPath(plan.before);
    return { action: 'restored', reason: 'owned-change' };
  }
  if (plan.kind === 'posix-profile-block') {
    if (typeof adapter.readProfile !== 'function' || typeof adapter.writeProfile !== 'function') throw safety();
    const current = await adapter.readProfile(plan.profilePath);
    if (typeof current !== 'string' || occurrences(current, plan.block) !== 1
      || occurrences(current, BEGIN) !== 1 || occurrences(current, END) !== 1) {
      return { action: 'preserved', reason: 'modified' };
    }
    await adapter.writeProfile(plan.profilePath, current.replace(plan.block, ''));
    return { action: 'restored', reason: 'owned-change' };
  }
  throw safety();
}
