import path from 'node:path';

import { ClaudexError } from '../core/errors.js';
import { isRegisteredCursorRepository } from './registry.js';
import { createCursorRunScope } from './runner.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const REF_OR_OID = /^(?:refs\/(?:heads|tags)\/[A-Za-z0-9][A-Za-z0-9._/-]{0,1023}|[0-9a-f]{40}|[0-9a-f]{64})$/u;
const MODEL = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const APPROVAL = /^[A-Za-z0-9_-]{1,128}$/u;

function failure(code = 'SAFETY_REFUSAL', details = {}) {
  const messages = {
    CAPABILITY_UNSUPPORTED: 'Cursor worktree delegation is disabled or unavailable.',
    APPROVAL_INVALID: 'The Cursor worktree approval is invalid, expired, or already consumed.',
    SAFETY_REFUSAL: 'The Cursor worktree delegation could not be completed safely.'
  };
  return new ClaudexError(code, messages[code] ?? messages.SAFETY_REFUSAL, { details });
}

function freeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

function checkedInput(value) {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw failure();
    const keys = Object.keys(value).sort().join(',');
    if (!['baseRef,model,prompt,repository', 'approvalId,baseRef,model,prompt,repository'].includes(keys)
      || !isRegisteredCursorRepository(value.repository) || typeof value.prompt !== 'string'
      || value.prompt.length === 0 || Buffer.byteLength(value.prompt, 'utf8') > 32_768 || value.prompt.includes('\0')
      || !MODEL.test(value.model) || !REF_OR_OID.test(value.baseRef)
      || Object.hasOwn(value, 'approvalId') && !APPROVAL.test(value.approvalId)) throw failure();
    return value;
  } catch { throw failure(); }
}

function checkedCollected(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).sort().join(',') !== 'diff,sharedMetadata,status'
    || typeof value.status !== 'string' || Buffer.byteLength(value.status, 'utf8') > 1_048_576
    || !value.diff || Object.keys(value.diff).sort().join(',') !== 'deletions,files,insertions'
    || !['files', 'insertions', 'deletions'].every((key) => Number.isSafeInteger(value.diff[key]) && value.diff[key] >= 0)
    || !value.sharedMetadata || Object.keys(value.sharedMetadata).sort().join(',') !== 'branchCreated,worktreeRegistered'
    || typeof value.sharedMetadata.branchCreated !== 'boolean' || typeof value.sharedMetadata.worktreeRegistered !== 'boolean') throw failure();
  return value;
}

function exact(value, keys) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...keys].sort().join(','));
}

function checkedApprovalRequest(value) {
  if (!exact(value, ['code', 'approvalId', 'expiresAt']) || value.code !== 'APPROVAL_REQUIRED'
    || !APPROVAL.test(value.approvalId) || !Number.isSafeInteger(value.expiresAt) || value.expiresAt < 0) throw failure();
  return value;
}

function checkedConsumed(value, approvalId) {
  if (!exact(value, ['action', 'approvalId']) || value.action !== 'consumed' || value.approvalId !== approvalId) throw failure();
}

function checkedCreated(value, expected) {
  if (!exact(value, ['action', 'branch', 'path', 'commit']) || value.action !== 'created'
    || value.branch !== expected.branch || value.path !== expected.path || value.commit !== expected.commit) throw failure();
}

export function createCursorWorktreeService({
  installationId, writesEnabled, platform, worktreeRoot, approvalService, git, runner, randomId,
  assertWorktreeNoLinks, collectResult, runContext = {}
} = {}) {
  const pathApi = platform === 'win32' || platform === 'windows' ? path.win32
    : platform === 'linux' || platform === 'darwin' || platform === 'macos' ? path.posix : null;
  if (!UUID.test(installationId) || typeof writesEnabled !== 'boolean' || !pathApi || typeof worktreeRoot !== 'string'
    || !pathApi.isAbsolute(worktreeRoot) || pathApi.normalize(worktreeRoot) !== worktreeRoot
    || worktreeRoot === pathApi.parse(worktreeRoot).root
    || !approvalService || typeof approvalService.request !== 'function' || typeof approvalService.consume !== 'function'
    || !git || typeof git.resolveBase !== 'function' || typeof git.addWorktree !== 'function'
    || !runner || typeof runner.run !== 'function' || typeof randomId !== 'function'
    || typeof assertWorktreeNoLinks !== 'function' || typeof collectResult !== 'function'
    || !runContext || typeof runContext !== 'object' || Array.isArray(runContext)) throw failure();
  const context = freeze({ ...runContext });
  return freeze({
    async run(rawInput) {
      if (!writesEnabled) throw failure('CAPABILITY_UNSUPPORTED');
      const input = checkedInput(rawInput);
      let baseCommit;
      try { baseCommit = await git.resolveBase(input.baseRef); } catch { throw failure(); }
      if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u.test(baseCommit)) throw failure();
      const binding = freeze({
        repository: input.repository.root, prompt: input.prompt, model: input.model,
        baseCommit, installationId
      });
      if (!Object.hasOwn(input, 'approvalId')) {
        try { return freeze(checkedApprovalRequest(await approvalService.request(binding))); } catch { throw failure(); }
      }
      let id;
      try { id = randomId(); } catch { throw failure(); }
      if (typeof id !== 'string' || !/^[a-z0-9][a-z0-9-]{2,63}$/u.test(id)) throw failure();
      const branch = `claudex/cursor-${id}`;
      const worktreePath = pathApi.join(worktreeRoot, id);
      const retainedDetails = freeze({ retained: true, path: worktreePath, branch, baseCommit });
      try { checkedConsumed(await approvalService.consume(input.approvalId, binding), input.approvalId); } catch (error) {
        let code;
        try { code = error?.code; } catch { /* sanitize */ }
        throw failure(code === 'APPROVAL_INVALID' ? 'APPROVAL_INVALID' : 'SAFETY_REFUSAL');
      }
      const creation = { branch, path: worktreePath, commit: baseCommit };
      try { checkedCreated(await git.addWorktree(creation), creation); }
      catch { throw failure('SAFETY_REFUSAL', retainedDetails); }
      let linksSafe = false;
      try { linksSafe = await assertWorktreeNoLinks(worktreePath) === true; } catch { linksSafe = false; }
      if (!linksSafe) throw failure('SAFETY_REFUSAL', retainedDetails);
      const scope = createCursorRunScope({ kind: 'worktree', cwd: worktreePath, platform });
      let delegated;
      let state = 'retained';
      try {
        delegated = await runner.run({ ...context, mode: 'worktree', prompt: input.prompt, model: input.model, scope });
      } catch { state = 'retained-failed'; }
      let collected;
      try { collected = checkedCollected(await collectResult(worktreePath)); }
      catch { throw failure('SAFETY_REFUSAL', retainedDetails); }
      return freeze({
        state, path: worktreePath, branch, baseCommit, status: collected.status, diff: collected.diff,
        sharedMetadata: collected.sharedMetadata, ...(delegated === undefined ? {} : { result: delegated })
      });
    }
  });
}
