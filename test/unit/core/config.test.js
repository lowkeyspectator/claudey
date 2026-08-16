import assert from 'node:assert/strict';
import test from 'node:test';

import { buildGatewayConfig, writeGatewayConfig } from '../../../src/core/config.js';
import { Secret } from '../../../src/core/secrets.js';

const TOKEN_TEXT = 'ERERERERERERERERERERERERERERERERERERERERERE';
const token = () => Secret.fromBytes(Buffer.alloc(32, 0x11));

function exactConfig({ port = 8317, authDir = '/home/casey/.config/claudeyctl/auth' } = {}) {
  const escapedAuthDir = JSON.stringify(authDir);
  return `host: "127.0.0.1"
port: ${port}
tls:
  enable: false
remote-management:
  allow-remote: false
  secret-key: ""
  disable-control-panel: true
auth-dir: ${escapedAuthDir}
api-keys:
  - "${TOKEN_TEXT}"
debug: false
commercial-mode: true
logging-to-file: false
usage-statistics-enabled: false
pprof:
  enable: false
plugins:
  enabled: false
ws-auth: true
`;
}

test('emits the exact restricted default gateway YAML as UTF-8 with one final LF', () => {
  const bytes = buildGatewayConfig({
    port: 8317,
    authDir: '/home/casey/.config/claudeyctl/auth',
    token: token()
  });
  assert.equal(Buffer.isBuffer(bytes), true);
  assert.equal(bytes.toString('utf8'), exactConfig());
  assert.equal(bytes.at(-1), 0x0a);
  assert.notEqual(bytes.at(-2), 0x0a);
  assert.equal(bytes.toString('utf8').includes('\r'), false);
  assert.equal(bytes.toString('utf8').split('\n').some((line) => /\s$/u.test(line)), false);
});

test('changes only the requested port digits at both accepted boundaries', () => {
  const middle = buildGatewayConfig({ port: 8317, authDir: '/private/auth', token: token() }).toString('utf8');
  for (const port of [1024, 65535]) {
    const actual = buildGatewayConfig({ port, authDir: '/private/auth', token: token() }).toString('utf8');
    assert.equal(actual, exactConfig({ port, authDir: '/private/auth' }));
    assert.equal(actual.replace(`port: ${port}`, 'port: 8317'), middle);
  }
});

test('escapes Windows paths, quotes, controls, and Unicode exactly once', () => {
  const windows = buildGatewayConfig({
    port: 8317,
    authDir: 'C:\\Users\\Casey\\AppData\\Roaming\\claudeyctl\\auth',
    token: token()
  }).toString('utf8');
  assert.equal(windows.split('\n').find((line) => line.startsWith('auth-dir:')),
    'auth-dir: "C:\\\\Users\\\\Casey\\\\AppData\\\\Roaming\\\\claudeyctl\\\\auth"');

  const custom = buildGatewayConfig({
    port: 8317,
    authDir: '/private/"quoted"/日本語\ttab',
    token: token()
  }).toString('utf8');
  assert.equal(custom.split('\n').find((line) => line.startsWith('auth-dir:')),
    'auth-dir: "/private/\\"quoted\\"/日本語\\ttab"');
  assert.equal(Buffer.from(custom, 'utf8').toString('utf8'), custom);
});

test('rejects invalid ports and non-opaque tokens before any write', async () => {
  const invalid = [1023, 65536, 0, 1.5, '8317', ' 8317 '];
  for (const port of invalid) {
    assert.throws(() => buildGatewayConfig({ port, authDir: '/private/auth', token: token() }),
      (error) => error?.code === 'USAGE_ERROR');
  }
  assert.throws(() => buildGatewayConfig({ port: 8317, authDir: '/private/auth', token: TOKEN_TEXT }),
    (error) => error?.code === 'SAFETY_REFUSAL');

  let writes = 0;
  await assert.rejects(() => writeGatewayConfig({ port: 1023, authDir: '/private/auth', token: token() }, {
    configRoot: '/private/config'
  }, { assertLockHeld: async () => undefined, atomicReplace: async () => { writes += 1; } }), (error) => error?.code === 'USAGE_ERROR');
  assert.equal(writes, 0);
});

test('delegates protected same-root atomic replacement and preserves prior state on injected failure', async () => {
  let prior = Buffer.from('prior-complete-config\n');
  const calls = [];
  await assert.rejects(() => writeGatewayConfig({
    port: 8317, authDir: '/private/auth', token: token()
  }, { configRoot: '/private/config' }, {
    assertLockHeld: async () => undefined,
    atomicReplace: async (request) => {
      calls.push(request);
      const error = new Error('injected fsync failure');
      error.code = 'EIO';
      throw error;
    }
  }), (error) => error?.code === 'EIO');
  assert.equal(prior.toString('utf8'), 'prior-complete-config\n');
  assert.equal(calls.length, 1);
  assert.deepEqual({ root: calls[0].root, child: calls[0].child, mode: calls[0].mode },
    { root: '/private/config', child: 'config.yaml', mode: 0o600 });
  assert.equal(calls[0].bytes.toString('utf8'), exactConfig({ authDir: '/private/auth' }));
  prior = calls[0].bytes;
  assert.equal(prior.at(-1), 0x0a);
});

test('gateway configuration is the only generated artifact carrying token or port literals', () => {
  const secretCanary = Secret.fromBytes(Buffer.from('TASK4_BEARER_CANARY_123456789012'));
  const config = buildGatewayConfig({ port: 54321, authDir: '/private/auth', token: secretCanary }).toString('utf8');
  const launcher = '#!/bin/sh\nexec /fixed/node /fixed/manager "$@"\n';
  assert.equal(config.includes('54321'), true);
  assert.equal(config.includes('TASK4_BEARER_CANARY_123456789012'), false);
  assert.equal(launcher.includes('54321'), false);
  assert.equal(launcher.includes('TASK4_BEARER_CANARY_123456789012'), false);
});
