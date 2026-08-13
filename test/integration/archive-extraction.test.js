import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';
import { EventEmitter } from 'node:events';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import test from 'node:test';

import { ClaudexError } from '../../src/core/errors.js';

import {
  buildArchiveHelperRequest,
  ARCHIVE_HELPER_PATH,
  testRunArchiveProcess,
  extractValidatedArchive,
  parseArchiveHelperResponse,
  revalidateExtractedCandidate,
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
  const simulatedModes = new Map();
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
    fsApi: {
      ...fs,
      chmod: async (target, mode) => {
        await fs.chmod(target, mode);
        simulatedModes.set(target, mode);
      },
      lstat: async (target, options) => {
        let stats = await fs.lstat(target, options);
        if (process.platform === 'win32') stats = new Proxy(stats, {
          get(object, property) {
            if (property === 'blocks') return Math.ceil(object.size / 512);
            if (property === 'mode' && simulatedModes.has(target)) return (object.mode & ~0o777) | simulatedModes.get(target);
            return Reflect.get(object, property, object);
          }
        });
        if (target === action.reparseTarget) stats = Object.assign(stats, { isReparsePoint: true });
        return action.lstatOverride?.(target, stats) ?? stats;
      }
    },
    beforePostWalk: action.beforePostWalk
  };
}

test('extracts only through fixed absolute tar arguments and returns a frozen canonical candidate descriptor', async (t) => {
  const fixture = await extractionFixture(t);
  const action = { staging: fixture.staging };
  const adapter = posixAdapter(fixture.plan, action);
  const candidate = await extractValidatedArchive(fixture.plan, fixture.staging, adapter);
  assert.deepEqual(candidate, {
    path: path.join(fixture.staging, 'bin', 'CLIProxyAPI'),
    size: 9,
    sha256: sha256(Buffer.from('candidate')),
    mode: 0o755,
    identity: candidate.identity
  });
  assert.deepEqual(Object.keys(candidate.identity).sort(), ['dev', 'ino']);
  assert.equal(Object.isFrozen(candidate), true);
  assert.equal(Object.isFrozen(candidate.identity), true);
  assert.equal(await revalidateExtractedCandidate(candidate, { fsApi: adapter.fsApi }), candidate);
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
    protectStaging: async (target) => { assert.equal(path.dirname(target), fixture.root); if (target === fixture.staging) stagingProtected = true; },
    verifyWindowsTools: async () => ({
      powershellPath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      helperPath: ARCHIVE_HELPER_PATH
    }),
    createPrivateRequest: async (input) => {
      await fs.writeFile(requestPath, input, { mode: 0o600 });
      return { requestPath, cleanup: async () => fs.rm(requestPath) };
    },
    runProcess: async (command, args, options) => {
      assert.equal(stagingProtected, true);
      assert.equal(command, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');
      assert.deepEqual(args.slice(0, 7), [
        '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', args[6]
      ]);
      assert.match(args[6], /^[A-Za-z0-9+/]+=*$/);
      assert.equal(options.shell, false);
      assert.equal(options.env.CLAUDEX_ARCHIVE_HELPER_PATH, ARCHIVE_HELPER_PATH);
      assert.match(options.env.CLAUDEX_ARCHIVE_HELPER_SHA256, /^[a-f0-9]{64}$/);
      assert.equal(options.env.CLAUDEX_ARCHIVE_REQUEST_PATH, requestPath);
      assert.match(options.env.CLAUDEX_ARCHIVE_REQUEST_SHA256, /^[a-f0-9]{64}$/);
      assert.match(options.env.CLAUDEX_ARCHIVE_DESTINATION_VOLUME, /^\d+$/);
      assert.match(options.env.CLAUDEX_ARCHIVE_DESTINATION_FILE_ID, /^\d+$/);      await materializePlan(fixture.plan, fixture.staging);
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

test('rejects pre-existing or outside-root staging before extractor', async (t) => {
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

test('rejects linked, permissive, and cross-device staging before extractor', async (t) => {
  for (const hostile of ['linked', 'permissive', 'cross-device']) {
    const fixture = await extractionFixture(t);
    let extractorCalled = false;
    const adapter = posixAdapter(fixture.plan, { staging: fixture.staging });
    const baseLstat = adapter.fsApi.lstat;
    adapter.fsApi = {
      ...adapter.fsApi,
      chmod: async (target, mode) => hostile === 'permissive' && target === fixture.staging ? undefined : fs.chmod(target, mode),
      lstat: async (target) => {
        const stats = await baseLstat(target);
        if (target !== fixture.staging) return stats;
        return new Proxy(stats, {
          get(object, property) {
            if (hostile === 'linked' && property === 'isSymbolicLink') return () => true;
            if (hostile === 'permissive' && property === 'mode') return (object.mode & ~0o777) | 0o777;
            if (hostile === 'cross-device' && property === 'dev') return object.dev + 1;
            return Reflect.get(object, property, object);
          }
        });
      }
    };
    adapter.runProcess = async () => { extractorCalled = true; return { code: 0, stdout: '', stderr: '' }; };
    await assert.rejects(
      () => extractValidatedArchive(fixture.plan, fixture.staging, adapter),
      (error) => ['SAFETY_REFUSAL', 'ARCHIVE_UNSAFE'].includes(error?.code)
    );
    assert.equal(extractorCalled, false, hostile);
  }
});
test('quarantines only verified owned staging after confirmed timeout and preserves the prior installation', async (t) => {
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

test('post-walk rejects unexpected, missing, changed-size/hash, and changed-type results and quarantines staging', async (t) => {
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

test('post-walk rejects actual hardlinks and deterministic sparse/device metadata', async (t) => {
  const hardlinkFixture = await extractionFixture(t);
  const hardlinkAction = {
    staging: hardlinkFixture.staging,
    beforePostWalk: async () => {
      const readme = path.join(hardlinkFixture.staging, 'README.txt');
      await fs.unlink(readme);
      await fs.link(path.join(hardlinkFixture.staging, 'bin', 'CLIProxyAPI'), readme);
    }
  };
  await assert.rejects(
    () => extractValidatedArchive(hardlinkFixture.plan, hardlinkFixture.staging, posixAdapter(hardlinkFixture.plan, hardlinkAction)),
    (error) => error?.code === 'ARCHIVE_UNSAFE'
  );

  for (const kind of ['sparse', 'device']) {
    const fixture = await extractionFixture(t);
    const readme = path.join(fixture.staging, 'README.txt');
    const action = {
      staging: fixture.staging,
      lstatOverride: (target, stats) => target !== readme ? stats : new Proxy(stats, {
        get(object, property) {
          if (kind === 'sparse' && property === 'blocks') return 0;
          if (kind === 'device' && property === 'isFile') return () => false;
          if (kind === 'device' && property === 'isDirectory') return () => false;
          return Reflect.get(object, property, object);
        }
      })
    };
    await assert.rejects(
      () => extractValidatedArchive(fixture.plan, fixture.staging, posixAdapter(fixture.plan, action)),
      (error) => error?.code === 'ARCHIVE_UNSAFE'
    );
  }
});
test('refuses helper metadata differing from the immutable plan before candidate handoff', async (t) => {
  const fixture = await extractionFixture(t, 'zip');
  const requestPath = path.join(fixture.root, 'request.json');
  await assert.rejects(() => extractValidatedArchive(fixture.plan, fixture.staging, {
    targetPlatform: 'win32', currentUserSid: 'S-1-5-21-1',
    verifyWindowsTools: async () => ({ powershellPath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', helperPath: ARCHIVE_HELPER_PATH }),
    protectStaging: async (target) => assert.equal(path.dirname(target), fixture.root),
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
test('refuses any Windows helper path other than the bundled archive helper', async (t) => {
  const fixture = await extractionFixture(t, 'zip');
  let spawned = false;
  await assert.rejects(() => extractValidatedArchive(fixture.plan, fixture.staging, {
    targetPlatform: 'win32',
    currentUserSid: 'S-1-5-21-1',
    protectStaging: async () => {},
    verifyWindowsTools: async () => ({
      powershellPath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      helperPath: 'C:\\other\\archive-helper.ps1'
    }),
    runProcess: async () => { spawned = true; }
  }), (error) => error?.code === 'CAPABILITY_UNSUPPORTED');
  assert.equal(spawned, false);
});

test('rechecks helper request and archive identities immediately before Windows spawn', async (t) => {
  for (const swapped of ['helper', 'archive', 'request']) {
    const fixture = await extractionFixture(t, 'zip');
    const requestPath = path.join(fixture.root, 'request-' + swapped + '.json');
    let spawned = false;
    let helperSwapped = false;
    await assert.rejects(() => extractValidatedArchive(fixture.plan, fixture.staging, {
      targetPlatform: 'win32',
      fsApi: {
        ...fs,
        realpath: async (target) => helperSwapped && target === ARCHIVE_HELPER_PATH ? target + '.foreign' : fs.realpath(target)
      },
      currentUserSid: 'S-1-5-21-1',
      protectStaging: async () => {},
      verifyWindowsTools: async () => ({
        powershellPath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        helperPath: ARCHIVE_HELPER_PATH
      }),
      createPrivateRequest: async (input) => {
        await fs.writeFile(requestPath, input);
        const stats = await fs.lstat(requestPath);
        return {
          requestPath,
          identity: { dev: stats.dev, ino: stats.ino },
          cleanup: async () => fs.rm(requestPath, { force: true })
        };
      },
      beforeExtractorSpawn: async () => {
        if (swapped === 'helper') {
          helperSwapped = true;
          return;
        }
        const target = swapped === 'archive' ? fixture.archivePath : requestPath;
        await fs.rename(target, target + '.owned');
        await fs.writeFile(target, 'foreign');
      },
      runProcess: async () => { spawned = true; }
    }), (error) => ['ARCHIVE_UNSAFE', 'SAFETY_REFUSAL', 'CAPABILITY_UNSUPPORTED'].includes(error?.code));
    assert.equal(spawned, false);
    if (swapped !== 'helper') {
      const foreign = swapped === 'archive' ? fixture.archivePath : requestPath;
      assert.equal(await fs.readFile(foreign, 'utf8'), 'foreign');
    }
  }
});

test('last launch seam pins tools, request digest, and destination before Windows spawn', async (t) => {
  for (const swapped of ['powershell', 'helper', 'helper-bytes', 'request-bytes', 'destination']) {
    const fixture = await extractionFixture(t, 'zip');
    const requestPath = path.join(fixture.root, 'last-seam-' + swapped + '.json');
    let seamReached = false;
    let spawned = false;
    let powershellSwapped = false;
    let helperSwapped = false;
    let helperBytesChanged = false;
    let requestId;
    let foreignMarker;
    const fsApi = {
      ...fs,
      readFile: async (target, ...args) => helperBytesChanged && target === ARCHIVE_HELPER_PATH
        ? Buffer.from('foreign helper')
        : fs.readFile(target, ...args),
      realpath: async (target) => {
        if (powershellSwapped && target === 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe') return target + '.foreign';
        if (helperSwapped && target === ARCHIVE_HELPER_PATH) return target + '.foreign';
        return fs.realpath(target);
      }
    };
    await assert.rejects(() => extractValidatedArchive(fixture.plan, fixture.staging, {
      targetPlatform: 'win32', fsApi, currentUserSid: 'S-1-5-21-1', protectStaging: async () => {},
      verifyWindowsTools: async () => ({
        powershellPath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        helperPath: ARCHIVE_HELPER_PATH
      }),
      createPrivateRequest: async (input) => {
        requestId = JSON.parse(input).requestId;
        await fs.writeFile(requestPath, input);
        return { requestPath, cleanup: async () => fs.rm(requestPath, { force: true }) };
      },
      beforeLaunchIdentityValidation: async () => {
        if (swapped === 'powershell') { seamReached = true; powershellSwapped = true; }
        if (swapped === 'helper') { seamReached = true; helperSwapped = true; }
      },
      afterLaunchIdentityPinBeforeProcessCreate: async () => {
        if (!['helper-bytes', 'request-bytes', 'destination'].includes(swapped)) return;
        seamReached = true;
        if (swapped === 'helper-bytes') helperBytesChanged = true;
        if (swapped === 'request-bytes') await fs.writeFile(requestPath, '{"changed":true}');
        if (swapped === 'destination') {
          await fs.rename(fixture.staging, fixture.staging + '.owned');
          await fs.mkdir(fixture.staging, { mode: 0o700 });
          foreignMarker = path.join(fixture.staging, 'foreign-marker');
          await fs.writeFile(foreignMarker, 'foreign');
        }
      },
      runProcess: async (command, args, options) => {
        spawned = true;
        assert.equal(args[5], '-EncodedCommand');
        const expectedDigest = options.env.CLAUDEX_ARCHIVE_REQUEST_SHA256;
        const actualDigest = sha256(await fs.readFile(requestPath));
        const actualHelperDigest = sha256(await fsApi.readFile(ARCHIVE_HELPER_PATH));
        const destinationStats = await fs.lstat(fixture.staging, { bigint: true });
        const destinationMatches = String(destinationStats.dev) === options.env.CLAUDEX_ARCHIVE_DESTINATION_VOLUME
          && String(destinationStats.ino) === options.env.CLAUDEX_ARCHIVE_DESTINATION_FILE_ID;
        if (actualDigest !== expectedDigest || actualHelperDigest !== options.env.CLAUDEX_ARCHIVE_HELPER_SHA256
          || !destinationMatches) return { code: 1, stderr: '', stdout: JSON.stringify({
          ok: false, schemaVersion: 1, requestId, code: 'SAFETY_REFUSAL', message: 'Archive extraction was refused.'
        }) };
        await materializePlan(fixture.plan, fixture.staging);
        return { code: 0, stderr: '', stdout: JSON.stringify({
          ok: true, schemaVersion: 1, requestId,
          result: { canonicalDestination: fixture.staging, entryCount: fixture.plan.entries.length,
            expandedBytes: fixture.plan.expandedBytes, entries: helperEntries(fixture.plan) }
        }) };
      }
    }), (error) => ['CAPABILITY_UNSUPPORTED', 'SAFETY_REFUSAL', 'ARCHIVE_UNSAFE'].includes(error?.code));
    assert.equal(seamReached, true);
    assert.equal(spawned, ['helper-bytes', 'request-bytes', 'destination'].includes(swapped));
    if (foreignMarker) assert.equal(await fs.readFile(foreignMarker, 'utf8'), 'foreign');
  }
});
test('actual child timeout and output overflow settle within a terminal deadline', async () => {
  const started = Date.now();
  await assert.rejects(() => testRunArchiveProcess(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], {
    timeoutMs: 20, maxOutputBytes: 1024, terminationDeadlineMs: 500
  }), (error) => error?.code === 'CAPABILITY_UNSUPPORTED');
  assert.equal(Date.now() - started < 1500, true);

  await assert.rejects(() => testRunArchiveProcess(process.execPath, ['-e', 'process.stdout.write(\"x\".repeat(4096))'], {
    timeoutMs: 1000, maxOutputBytes: 64, terminationDeadlineMs: 500
  }), (error) => error?.code === 'CAPABILITY_UNSUPPORTED');
});

test('child termination deadline reports exitUnconfirmed when close never arrives', async () => {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.kill = () => true;
  await assert.rejects(() => testRunArchiveProcess('ignored', [], {
    timeoutMs: 5,
    maxOutputBytes: 64,
    terminationGraceMs: 5,
    terminationDeadlineMs: 5,
    spawnChildApi: () => child
  }), (error) => error?.code === 'CAPABILITY_UNSUPPORTED' && error.details.exitUnconfirmed === true);
});
test('unconfirmed extractor exit retains original staging and skips every cleanup hook', async (t) => {
  const fixture = await extractionFixture(t);
  let cleanupHookCalled = false;
  const unconfirmed = new ClaudexError('CAPABILITY_UNSUPPORTED', 'Extractor exit could not be confirmed.', {
    details: { exitUnconfirmed: true }
  });
  const adapter = posixAdapter(fixture.plan, { staging: fixture.staging, error: unconfirmed });
  adapter.beforeCleanupQuarantine = async () => { cleanupHookCalled = true; };
  await assert.rejects(
    () => extractValidatedArchive(fixture.plan, fixture.staging, adapter),
    (error) => error?.code === 'CAPABILITY_UNSUPPORTED' && error.details.exitUnconfirmed === true
      && error.details.stagingRetained === true
  );
  assert.equal(cleanupHookCalled, false);
  assert.equal((await fs.lstat(fixture.staging)).isDirectory(), true);
  assert.equal(await fs.readFile(fixture.archivePath).then(sha256), fixture.plan.archiveSha256);
});
test('unconfirmed Windows helper exit retains request, staging, and archive evidence', async (t) => {
  const fixture = await extractionFixture(t, 'zip');
  const requestPath = path.join(fixture.root, 'retained-request.json');
  let requestCleanupCalled = false;
  const unconfirmed = new ClaudexError('CAPABILITY_UNSUPPORTED', 'Helper exit could not be confirmed.', {
    details: { exitUnconfirmed: true }
  });
  await assert.rejects(() => extractValidatedArchive(fixture.plan, fixture.staging, {
    targetPlatform: 'win32', currentUserSid: 'S-1-5-21-1', protectStaging: async () => {},
    verifyWindowsTools: async () => ({
      powershellPath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', helperPath: ARCHIVE_HELPER_PATH
    }),
    createPrivateRequest: async (input) => {
      await fs.writeFile(requestPath, input);
      return { requestPath, cleanup: async () => { requestCleanupCalled = true; } };
    },
    runProcess: async () => { throw unconfirmed; }
  }), (error) => error?.details?.exitUnconfirmed === true && error.details.requestStorageRetained === true
    && error.details.stagingRetained === true);
  assert.equal(requestCleanupCalled, false);
  assert.equal((await fs.lstat(requestPath)).isFile(), true);
  assert.equal((await fs.lstat(fixture.staging)).isDirectory(), true);
  assert.equal(await fs.readFile(fixture.archivePath).then(sha256), fixture.plan.archiveSha256);
});
test('final handoff rechecks every entry and candidate identity after a deterministic swap', async (t) => {
  const fixture = await extractionFixture(t);
  const action = { staging: fixture.staging };
  const adapter = posixAdapter(fixture.plan, action);
  adapter.beforeFinalHandoff = async () => {
    const candidate = path.join(fixture.staging, 'bin', 'CLIProxyAPI');
    await fs.rename(candidate, candidate + '.owned');
    await fs.writeFile(candidate, 'candidate');
  };
  await assert.rejects(
    () => extractValidatedArchive(fixture.plan, fixture.staging, adapter),
    (error) => error?.code === 'ARCHIVE_UNSAFE'
  );
});

test('candidate pathname swap after handle read and immediately before return is refused', async (t) => {
  const fixture = await extractionFixture(t);
  const action = { staging: fixture.staging };
  const adapter = posixAdapter(fixture.plan, action);
  let seamReached = false;
  adapter.afterCandidateReadBeforeReturn = async ({ candidatePath }) => {
    seamReached = true;
    await fs.rename(candidatePath, candidatePath + '.owned');
    await fs.writeFile(candidatePath, 'candidate');
  };
  await assert.rejects(
    () => extractValidatedArchive(fixture.plan, fixture.staging, adapter),
    (error) => error?.code === 'ARCHIVE_UNSAFE'
  );
  assert.equal(seamReached, true);
});
test('cleanup quarantines by identity and never recursively deletes a substituted foreign directory', async (t) => {
  const fixture = await extractionFixture(t);
  const foreignMarker = path.join(fixture.staging, 'foreign-marker');
  const adapter = posixAdapter(fixture.plan, { staging: fixture.staging, error: new Error('extract failure') });
  adapter.beforeCleanupQuarantine = async () => {
    await fs.rename(fixture.staging, fixture.staging + '.owned');
    await fs.mkdir(fixture.staging);
    await fs.writeFile(foreignMarker, 'foreign');
  };
  await assert.rejects(
    () => extractValidatedArchive(fixture.plan, fixture.staging, adapter),
    (error) => error?.code === 'SAFETY_REFUSAL'
  );
  assert.equal(await fs.readFile(foreignMarker, 'utf8'), 'foreign');
});
test('cleanup retains quarantine and refuses a foreign substitution after final validation before deletion', async (t) => {
  const fixture = await extractionFixture(t);
  const adapter = posixAdapter(fixture.plan, { staging: fixture.staging, error: new Error('extract failure') });
  let foreignMarker;
  let ownedQuarantine;
  let seamReached = false;
  adapter.afterQuarantineValidationBeforeDelete = async ({ quarantine }) => {
    seamReached = true;
    ownedQuarantine = quarantine + '.owned';
    await fs.rename(quarantine, ownedQuarantine);
    await fs.mkdir(quarantine, { mode: 0o700 });
    foreignMarker = path.join(quarantine, 'foreign-marker');
    await fs.writeFile(foreignMarker, 'foreign');
  };
  await assert.rejects(
    () => extractValidatedArchive(fixture.plan, fixture.staging, adapter),
    (error) => error?.code === 'SAFETY_REFUSAL'
  );
  assert.equal(seamReached, true);
  assert.equal(await fs.readFile(foreignMarker, 'utf8'), 'foreign');
  assert.equal((await fs.lstat(ownedQuarantine)).isDirectory(), true);
});
test('production Windows bootstrap pins the bundled helper before extraction', { skip: process.platform !== 'win32' }, async (t) => {
  const fixture = await extractionFixture(t, 'zip');
  const powershell = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
  const sid = execFileSync(powershell, [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
    '[Security.Principal.WindowsIdentity]::GetCurrent().User.Value'
  ], { encoding: 'utf8' }).trim();
  const candidate = await extractValidatedArchive(fixture.plan, fixture.staging, {
    targetPlatform: 'win32', currentUserSid: sid
  });
  assert.equal(candidate.path, path.join(fixture.staging, 'bin', 'CLIProxyAPI.exe'));
  assert.equal(await revalidateExtractedCandidate(candidate), candidate);
});
test('bundled Windows helper performs a real protected-request ZIP extraction without executing the candidate', { skip: process.platform !== 'win32' }, async (t) => {
  const fixture = await extractionFixture(t, 'zip');
  const destination = fixture.staging;
  const requestDirectory = path.join(fixture.root, 'native-request');
  const requestPath = path.join(requestDirectory, 'request.json');
  await fs.mkdir(destination, { mode: 0o700 });
  await fs.mkdir(requestDirectory, { mode: 0o700 });
  const powershell = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
  const icacls = 'C:\\Windows\\System32\\icacls.exe';
  const sid = execFileSync(powershell, [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
    '[Security.Principal.WindowsIdentity]::GetCurrent().User.Value'
  ], { encoding: 'utf8' }).trim();
  execFileSync(icacls, [requestDirectory, '/inheritance:r', '/grant:r', '*' + sid + ':(OI)(CI)F', '*S-1-5-18:(OI)(CI)F', '/q']);
  const requestId = randomUUID();
  const requestInput = buildArchiveHelperRequest({
    requestId,
    archivePath: fixture.archivePath,
    destination,
    archiveSha256: fixture.plan.archiveSha256,
    entries: helperEntries(fixture.plan)
  });
  await fs.writeFile(requestPath, requestInput);
  execFileSync(icacls, [requestPath, '/inheritance:r', '/grant:r', '*' + sid + ':F', '*S-1-5-18:F', '/q']);
  const destinationStats = await fs.lstat(destination, { bigint: true });
  const result = spawnSync(powershell, [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', ARCHIVE_HELPER_PATH, '-RequestPath', requestPath,
    '-ExpectedRequestSha256', sha256(Buffer.from(requestInput)),
    '-ExpectedDestinationVolume', String(destinationStats.dev),
    '-ExpectedDestinationFileId', String(destinationStats.ino)
  ], { encoding: 'utf8' });
  assert.equal(result.stderr, '');
  assert.equal(result.status, 0, result.stdout);
  const response = parseArchiveHelperResponse(result.stdout, { requestId });
  assert.equal(response.result.entryCount, fixture.plan.entries.length);
  assert.equal(await fs.readFile(path.join(destination, 'bin', 'CLIProxyAPI.exe'), 'utf8'), 'candidate');
  const requestIdentityBefore = await fs.lstat(requestPath);
  await fs.writeFile(requestPath, requestInput + ' ');
  const requestIdentityAfter = await fs.lstat(requestPath);
  assert.deepEqual({ dev: requestIdentityAfter.dev, ino: requestIdentityAfter.ino }, {
    dev: requestIdentityBefore.dev, ino: requestIdentityBefore.ino
  });
  const refused = spawnSync(powershell, [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', ARCHIVE_HELPER_PATH, '-RequestPath', requestPath,
    '-ExpectedRequestSha256', sha256(Buffer.from(requestInput)),
    '-ExpectedDestinationVolume', String(destinationStats.dev),
    '-ExpectedDestinationFileId', String(destinationStats.ino)
  ], { encoding: 'utf8' });
  assert.equal(refused.status, 1);
  assert.equal(JSON.parse(refused.stdout).ok, false);
});
