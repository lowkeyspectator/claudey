import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  buildArchiveHelperRequest,
  extractValidatedArchive,
  parseArchiveHelperResponse,
  validateArchive
} from '../../src/core/archive.js';
import { buildTarGz, buildZip, validTarEntries, validZipEntries } from '../support/archive-fixtures.js';

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

async function extractionFixture(t, kind = 'tar.gz') {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'claudexctl-archive-extraction-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await fs.chmod(root, 0o700);
  const bytes = kind === 'zip' ? buildZip(validZipEntries) : buildTarGz(validTarEntries);
  const archivePath = path.join(root, kind === 'zip' ? 'release.zip' : 'release.tar.gz');
  await fs.writeFile(archivePath, bytes, { mode: 0o600 });
  const stats = await fs.stat(archivePath);
  const targetPlatform = kind === 'zip' ? 'win32' : 'linux';
  const expectedExecutable = kind === 'zip' ? 'CLIProxyAPI.exe' : 'CLIProxyAPI';
  const descriptor = Object.freeze({
    path: archivePath, name: path.basename(archivePath), bytes: bytes.length, sha256: sha256(bytes), kind
  });
  const plan = await validateArchive(descriptor, expectedExecutable, undefined, {
    targetPlatform, stagingRoot: root, archiveIdentity: { dev: stats.dev, ino: stats.ino }
  });
  return { root, archivePath, bytes, descriptor, plan, staging: path.join(root, 'candidate') };
}

const contents = new Map([
  ['README.txt', Buffer.from('readme')],
  ['bin/CLIProxyAPI', Buffer.from('candidate')],
  ['bin/CLIProxyAPI.exe', Buffer.from('candidate')]
]);

async function materializePlan(plan, staging, { omit, unexpected, corrupt, directoryInstead, reparse } = {}) {
  for (const entry of plan.entries) {
    if (entry.path === omit) continue;
    const target = path.join(staging, ...entry.path.split('/'));
    if (entry.type === 'directory') await fs.mkdir(target, { recursive: true, mode: 0o755 });
    else {
      await fs.mkdir(path.dirname(target), { recursive: true, mode: 0o755 });
      if (entry.path === directoryInstead) {
        await fs.mkdir(target, { mode: 0o755 });
        continue;
      }
      const content = entry.path === corrupt ? Buffer.from('corrupt') : contents.get(entry.path);
      await fs.writeFile(target, content, { mode: entry.mode ?? 0o600 });
      if (entry.mode !== null) await fs.chmod(target, entry.mode);
    }
  }
  if (unexpected) await fs.writeFile(path.join(staging, unexpected), 'unexpected');
  if (reparse) return path.join(staging, ...reparse.split('/'));
  return undefined;
}

function helperEntries(plan) {
  return plan.entries.map(({ path: entryPath, type, size, sha256: hash }) => ({
    path: entryPath, type, size, sha256: hash
  }));
}

function posixAdapter(plan, action = {}) {
  return {
    targetPlatform: 'linux',
    tarPath: '/usr/bin/tar',
    verifyTarPath: async (tarPath) => {
      assert.equal(tarPath, '/usr/bin/tar');
      return tarPath;
    },
    runProcess: async (command, args, options) => {
      assert.equal(command, '/usr/bin/tar');
      assert.deepEqual(args, ['-xzf', plan.archivePath, '-C', action.staging, '--no-same-owner', '--no-same-permissions']);
      assert.deepEqual({ shell: options.shell, timeoutMs: options.timeoutMs, maxOutputBytes: options.maxOutputBytes }, {
        shell: false, timeoutMs: 120000, maxOutputBytes: 65536
      });
      if (action.error) throw action.error;
      action.reparsePath = await materializePlan(plan, action.staging, action);
      return action.result ?? { code: 0, stdout: '', stderr: '' };
    },
    fsApi: action.reparseTarget === undefined ? undefined : {
      ...fs,
      lstat: async (target) => {
        const stats = await fs.lstat(target);
        return target === action.reparseTarget ? Object.assign(stats, { isReparsePoint: true }) : stats;
      }
    },
    beforePostWalk: action.beforePostWalk
  };
}

test('extracts only through fixed absolute tar arguments and returns a frozen canonical candidate descriptor', async (t) => {
  const fixture = await extractionFixture(t);
  const action = { staging: fixture.staging };
  const candidate = await extractValidatedArchive(fixture.plan, fixture.staging, posixAdapter(fixture.plan, action));
  assert.deepEqual(candidate, {
    path: path.join(fixture.staging, 'bin', 'CLIProxyAPI'),
    size: 9,
    sha256: sha256(Buffer.from('candidate')),
    mode: 0o755
  });
  assert.equal(Object.isFrozen(candidate), true);
});

test('builds and parses a strict one-line Windows archive helper protocol', () => {
  const requestId = randomUUID();
  const request = JSON.parse(buildArchiveHelperRequest({
    requestId,
    archivePath: 'C:\\managed\\release.zip',
    destination: 'C:\\managed\\candidate',
    archiveSha256: 'a'.repeat(64),
    entries: [{ path: 'CLIProxyAPI.exe', type: 'file', size: 9, sha256: 'b'.repeat(64) }]
  }));
  assert.deepEqual(Object.keys(request).sort(), ['archivePath', 'archiveSha256', 'destination', 'entries', 'operation', 'requestId', 'schemaVersion']);
  const response = parseArchiveHelperResponse(JSON.stringify({
    ok: true,
    schemaVersion: 1,
    requestId,
    result: { canonicalDestination: 'C:\\managed\\candidate', entryCount: 1, expandedBytes: 9, entries: request.entries }
  }), { requestId });
  assert.equal(response.result.entryCount, 1);

  for (const stdout of ['', '{}\n{}', '{bad', JSON.stringify({
    ok: true, schemaVersion: 1, requestId, result: { canonicalDestination: 'C:\\managed\\candidate', entryCount: 1, expandedBytes: 9, entries: request.entries, extra: true }
  })]) assert.throws(() => parseArchiveHelperResponse(stdout, { requestId }), (error) => error?.code === 'CAPABILITY_UNSUPPORTED');
});

test('invokes only fixed System32 PowerShell and the bundled helper with a private request', async (t) => {
  const fixture = await extractionFixture(t, 'zip');
  const action = { staging: fixture.staging };
  const requestPath = path.join(fixture.root, 'private-request.json');
  let stagingProtected = false;
  const adapter = {
    targetPlatform: 'win32',
    currentUserSid: 'S-1-5-21-1',
    protectStaging: async (target) => { assert.equal(target, fixture.staging); stagingProtected = true; },
    verifyWindowsTools: async () => ({
      powershellPath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      helperPath: 'C:\\bundle\\archive-helper.ps1'
    }),
    createPrivateRequest: async (input) => {
      await fs.writeFile(requestPath, input, { mode: 0o600 });
      return { requestPath, cleanup: async () => fs.rm(requestPath) };
    },
    runProcess: async (command, args, options) => {
      assert.equal(stagingProtected, true);
      assert.equal(command, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');
      assert.deepEqual(args, ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', 'C:\\bundle\\archive-helper.ps1', '-RequestPath', requestPath]);
      assert.equal(options.shell, false);
      await materializePlan(fixture.plan, fixture.staging);
      const request = JSON.parse(await fs.readFile(requestPath, 'utf8'));
      return { code: 0, stderr: '', stdout: JSON.stringify({
        ok: true,
        schemaVersion: 1,
        requestId: request.requestId,
        result: {
          canonicalDestination: fixture.staging,
          entryCount: fixture.plan.entries.length,
          expandedBytes: fixture.plan.expandedBytes,
          entries: helperEntries(fixture.plan)
        }
      }) };
    }
  };
  const candidate = await extractValidatedArchive(fixture.plan, fixture.staging, adapter);
  assert.equal(candidate.path, path.join(fixture.staging, 'bin', 'CLIProxyAPI.exe'));
  await assert.rejects(() => fs.access(requestPath), { code: 'ENOENT' });
});

test('rejects pre-existing, linked, permissive, outside-root, and cross-device staging before extractor', async (t) => {
  const fixture = await extractionFixture(t);
  await fs.mkdir(fixture.staging);
  let called = false;
  await assert.rejects(() => extractValidatedArchive(fixture.plan, fixture.staging, {
    ...posixAdapter(fixture.plan, { staging: fixture.staging }),
    runProcess: async () => { called = true; }
  }), (error) => error?.code === 'SAFETY_REFUSAL');
  assert.equal(called, false);
  await assert.rejects(
    () => extractValidatedArchive(fixture.plan, path.join(path.dirname(fixture.root), 'outside'), posixAdapter(fixture.plan, { staging: 'unused' })),
    (error) => error?.code === 'SAFETY_REFUSAL'
  );
});

test('cleans only verified owned staging after timeout and preserves the prior installation', async (t) => {
  const fixture = await extractionFixture(t);
  const prior = path.join(fixture.root, 'active-release');
  await fs.writeFile(prior, 'prior');
  const timeout = Object.assign(new Error('timeout canary-private-path'), { code: 'CAPABILITY_UNSUPPORTED' });
  await assert.rejects(
    () => extractValidatedArchive(fixture.plan, fixture.staging, posixAdapter(fixture.plan, { staging: fixture.staging, error: timeout })),
    (error) => error?.code === 'CAPABILITY_UNSUPPORTED' && !error.message.includes('canary-private-path')
  );
  await assert.rejects(() => fs.access(fixture.staging), { code: 'ENOENT' });
  assert.equal(await fs.readFile(prior, 'utf8'), 'prior');
});

test('post-walk rejects unexpected, missing, changed-size/hash, and changed-type results and cleans staging', async (t) => {
  for (const hostile of [
    { unexpected: 'extra' },
    { omit: 'README.txt' },
    { corrupt: 'README.txt' },
    { directoryInstead: 'README.txt' }
  ]) {
    const fixture = await extractionFixture(t);
    await assert.rejects(
      () => extractValidatedArchive(fixture.plan, fixture.staging, posixAdapter(fixture.plan, { staging: fixture.staging, ...hostile })),
      (error) => error?.code === 'ARCHIVE_UNSAFE'
    );
    await assert.rejects(() => fs.access(fixture.staging), { code: 'ENOENT' });
  }
});

test('post-walk rejects a reparse/link swap and candidate substitution immediately before handoff', async (t) => {
  const fixture = await extractionFixture(t);
  const reparseAction = {
    staging: fixture.staging,
    reparseTarget: path.join(fixture.staging, 'README.txt')
  };
  await assert.rejects(
    () => extractValidatedArchive(fixture.plan, fixture.staging, posixAdapter(fixture.plan, reparseAction)),
    (error) => error?.code === 'ARCHIVE_UNSAFE'
  );
  const action = {
    staging: fixture.staging,
    beforePostWalk: async () => {
      const candidate = path.join(fixture.staging, 'bin', 'CLIProxyAPI');
      await fs.writeFile(candidate, 'substitute');
    }
  };
  await assert.rejects(
    () => extractValidatedArchive(fixture.plan, fixture.staging, posixAdapter(fixture.plan, action)),
    (error) => error?.code === 'ARCHIVE_UNSAFE'
  );
});

test('refuses helper metadata differing from the immutable plan before candidate handoff', async (t) => {
  const fixture = await extractionFixture(t, 'zip');
  const requestPath = path.join(fixture.root, 'request.json');
  await assert.rejects(() => extractValidatedArchive(fixture.plan, fixture.staging, {
    targetPlatform: 'win32', currentUserSid: 'S-1-5-21-1',
    verifyWindowsTools: async () => ({ powershellPath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', helperPath: 'C:\\bundle\\archive-helper.ps1' }),
    protectStaging: async (target) => assert.equal(target, fixture.staging),
    createPrivateRequest: async (input) => {
      await fs.writeFile(requestPath, input);
      return { requestPath, cleanup: async () => fs.rm(requestPath, { force: true }) };
    },
    runProcess: async () => {
      await materializePlan(fixture.plan, fixture.staging);
      const request = JSON.parse(await fs.readFile(requestPath, 'utf8'));
      return { code: 0, stderr: '', stdout: JSON.stringify({
        ok: true, schemaVersion: 1, requestId: request.requestId,
        result: { canonicalDestination: fixture.staging, entryCount: 0, expandedBytes: 0, entries: [] }
      }) };
    }
  }), (error) => error?.code === 'ARCHIVE_UNSAFE');
  await assert.rejects(() => fs.access(fixture.staging), { code: 'ENOENT' });
});
