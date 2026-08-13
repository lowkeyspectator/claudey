import assert from 'node:assert/strict';
import test from 'node:test';

import { createSafeCursorGit } from '../../../src/cursor/git.js';

const ROOT = '/home/casey/project';
const COMMIT = 'a'.repeat(40);

function fixture(overrides = {}) {
  const calls = [];
  const callerState = { files: '1', index: '2', head: '3', tree: '4' };
  const git = createSafeCursorGit({
    repositoryRoot: ROOT,
    revalidateRepository: async () => true,
    captureCallerState: async () => ({ ...callerState }),
    runGit: async (request) => {
      calls.push(request);
      const key = request.args.join(' ');
      const values = {
        'for-each-ref --format=%(refname)%00%(objectname)%00%(objecttype) refs/heads refs/tags': `refs/heads/main\0${COMMIT}\0commit\nrefs/tags/v1\0${'b'.repeat(40)}\0tag\n`,
        [`rev-parse --verify refs/heads/main^{commit}`]: `${COMMIT}\n`,
        [`rev-parse --verify ${COMMIT}^{commit}`]: `${COMMIT}\n`,
        [`cat-file -t ${COMMIT}`]: 'commit\n'
      };
      return overrides[key] ?? { code: values[key] ? 0 : 2, stdout: values[key] ?? '', stderr: '' };
    }
  });
  return { git, calls };
}

test('enumerates only full local heads/tags with fixed isolated Git environment', async () => {
  const f = fixture();
  const refs = await f.git.listRefs();
  assert.deepEqual(refs.map(({ ref }) => ref), ['refs/heads/main', 'refs/tags/v1']);
  assert.deepEqual(f.calls[0].args, ['for-each-ref', '--format=%(refname)%00%(objectname)%00%(objecttype)', 'refs/heads', 'refs/tags']);
  assert.equal(f.calls[0].env.GIT_CONFIG_NOSYSTEM, '1');
  assert.equal(f.calls[0].env.GIT_CONFIG_GLOBAL, f.calls[0].nullDevice);
  assert.equal(f.calls[0].env.GIT_CONFIG_COUNT, '2');
});

test('resolves only an enumerated full ref or full object ID and peels to an exact commit', async () => {
  const f = fixture();
  assert.equal(await f.git.resolveBase('refs/heads/main'), COMMIT);
  assert.equal(await f.git.resolveBase(COMMIT), COMMIT);
  for (const hostile of ['main', 'HEAD~1', '--help', 'refs/heads/main^{tree}', 'refs/remotes/origin/main', `${COMMIT} --help`]) {
    await assert.rejects(f.git.resolveBase(hostile), (error) => error.code === 'SAFETY_REFUSAL');
  }
});

test('creates only a fixed generated worktree/branch with resolved commit after -- and no caller text', async () => {
  const f = fixture({
    [`worktree add -b claudex/cursor-abc -- /home/casey/worktrees/abc ${COMMIT}`]: {
      code: 0, stdout: 'HEAD is now at aaaaaaa fixture\n', stderr: 'Preparing worktree (new branch \'claudex/cursor-abc\')\n'
    }
  });
  await f.git.addWorktree({ branch: 'claudex/cursor-abc', path: '/home/casey/worktrees/abc', commit: COMMIT });
  const call = f.calls.at(-1);
  assert.deepEqual(call.args, ['worktree', 'add', '-b', 'claudex/cursor-abc', '--', '/home/casey/worktrees/abc', COMMIT]);
});

test('fails closed on malformed refs, non-commit objects, repository identity changes, and hostile diagnostics', async () => {
  const malformed = fixture({
    'for-each-ref --format=%(refname)%00%(objectname)%00%(objecttype) refs/heads refs/tags': { code: 0, stdout: 'refs/heads/main\n', stderr: '' }
  });
  await assert.rejects(malformed.git.listRefs(), (error) => error.code === 'SAFETY_REFUSAL');
  let runs = 0;
  const swapped = createSafeCursorGit({ repositoryRoot: ROOT, revalidateRepository: async () => false,
    captureCallerState: async () => ({ files: '1', index: '2', head: '3', tree: '4' }), runGit: async () => { runs += 1; } });
  await assert.rejects(swapped.listRefs(), (error) => error.code === 'SAFETY_REFUSAL');
  assert.equal(runs, 0);
});
