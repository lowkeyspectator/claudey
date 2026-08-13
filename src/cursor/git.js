import path from 'node:path';

import { ClaudexError } from '../core/errors.js';

const OID = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u;
const REF = /^refs\/(?:heads|tags)\/[A-Za-z0-9][A-Za-z0-9._/-]{0,1023}$/u;
const BRANCH = /^claudex\/cursor-[a-z0-9][a-z0-9-]{0,63}$/u;
const FINGERPRINT_KEYS = ['files', 'head', 'index', 'tree'];

function safety() {
  return new ClaudexError('SAFETY_REFUSAL', 'The Cursor Git operation could not be completed safely.');
}

function safeAbsolute(value, pathApi) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0') || value.includes('\r') || value.includes('\n')
    || !pathApi.isAbsolute(value) || pathApi.normalize(value) !== value || value === pathApi.parse(value).root) throw safety();
  return value;
}

function fingerprint(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).sort().join(',') !== [...FINGERPRINT_KEYS].sort().join(',')
    || FINGERPRINT_KEYS.some((key) => typeof value[key] !== 'string' || value[key].length === 0 || value[key].includes('\0'))) throw safety();
  return Object.freeze(Object.fromEntries(FINGERPRINT_KEYS.map((key) => [key, value[key]])));
}

function same(left, right) { return FINGERPRINT_KEYS.every((key) => left[key] === right[key]); }

export function createSafeCursorGit({ repositoryRoot, revalidateRepository, captureCallerState, runGit } = {}) {
  const pathApi = typeof repositoryRoot === 'string' && /^[A-Za-z]:\\/u.test(repositoryRoot) ? path.win32 : path.posix;
  const root = safeAbsolute(repositoryRoot, pathApi);
  if (typeof revalidateRepository !== 'function' || typeof captureCallerState !== 'function' || typeof runGit !== 'function') throw safety();
  const nullDevice = pathApi === path.win32 ? 'NUL' : '/dev/null';
  const env = Object.freeze({
    GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: nullDevice, GIT_CONFIG_COUNT: '2',
    GIT_CONFIG_KEY_0: 'core.hooksPath', GIT_CONFIG_VALUE_0: nullDevice,
    GIT_CONFIG_KEY_1: 'core.fsmonitor', GIT_CONFIG_VALUE_1: 'false'
  });
  const invoke = async (args, { allowOutput = true, allowStderr = false } = {}) => {
    if (await revalidateRepository(root) !== true) throw safety();
    let result;
    try {
      result = await runGit(Object.freeze({ cwd: root, args: Object.freeze([...args]), env, nullDevice, shell: false,
        timeoutMs: 30_000, maxStdoutBytes: 1_048_576, maxStderrBytes: 16_384 }));
    } catch { throw safety(); }
    if (!result || result.code !== 0 || typeof result.stdout !== 'string' || typeof result.stderr !== 'string'
      || !allowStderr && result.stderr !== '' || Buffer.byteLength(result.stdout, 'utf8') > 1_048_576
      || Buffer.byteLength(result.stderr, 'utf8') > 16_384 || !allowOutput && result.stdout !== '') throw safety();
    return result.stdout;
  };
  const listRefs = async () => {
    const output = await invoke(['for-each-ref', '--format=%(refname)%00%(objectname)%00%(objecttype)', 'refs/heads', 'refs/tags']);
    if (output.length === 0 || !output.endsWith('\n')) throw safety();
    const seen = new Set();
    const refs = output.slice(0, -1).split('\n').map((line) => {
      const fields = line.split('\0');
      if (fields.length !== 3 || !REF.test(fields[0]) || !OID.test(fields[1]) || !['commit', 'tag'].includes(fields[2])
        || seen.has(fields[0])) throw safety();
      seen.add(fields[0]);
      return Object.freeze({ ref: fields[0], objectId: fields[1], objectType: fields[2] });
    }).sort((left, right) => left.ref.localeCompare(right.ref));
    return Object.freeze(refs);
  };
  return Object.freeze({
    listRefs,
    async resolveBase(value) {
      if (typeof value !== 'string') throw safety();
      if (!OID.test(value)) {
        if (!REF.test(value) || !(await listRefs()).some(({ ref }) => ref === value)) throw safety();
      }
      const output = await invoke(['rev-parse', '--verify', `${value}^{commit}`]);
      if (!/^([0-9a-f]{40}|[0-9a-f]{64})\n$/u.test(output)) throw safety();
      return output.slice(0, -1);
    },
    async addWorktree({ branch, path: worktreePath, commit } = {}) {
      if (!BRANCH.test(branch) || !OID.test(commit)) throw safety();
      const destination = safeAbsolute(worktreePath, pathApi);
      const before = fingerprint(await captureCallerState(root));
      let caught;
      try { await invoke(['worktree', 'add', '-b', branch, '--', destination, commit], { allowStderr: true }); }
      catch { caught = safety(); }
      let after;
      try { after = fingerprint(await captureCallerState(root)); } catch { caught = safety(); }
      if (after && !same(before, after)) caught = safety();
      if (caught) throw caught;
      return Object.freeze({ action: 'created', branch, path: destination, commit });
    }
  });
}
