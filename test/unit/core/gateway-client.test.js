import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import test from 'node:test';

import { requestGatewayModels } from '../../../src/core/gateway-client.js';
import { Secret } from '../../../src/core/secrets.js';
import { startFakeGateway } from '../../support/fake-gateway.js';

const TOKEN_BYTES = Buffer.alloc(32, 7);
const TOKEN_TEXT = TOKEN_BYTES.toString('base64url');

function secret(bytes = TOKEN_BYTES) {
  return Secret.fromBytes(bytes);
}

async function fixture(t, options = {}) {
  const gateway = await startFakeGateway({ token: TOKEN_TEXT, ...options });
  t.after(() => gateway.close());
  return gateway;
}

test('returns a strict authenticated catalog only from the exact IPv4 loopback target', async (t) => {
  const gateway = await fixture(t);
  const result = await requestGatewayModels({ host: '127.0.0.1', port: gateway.port, token: secret() });
  assert.deepEqual(result, {
    object: 'list',
    data: [{ id: 'gpt-fixture', object: 'model', created: 1, owned_by: 'codex' }]
  });
  for (const host of ['localhost', '::1', '0.0.0.0', '127.0.0.2', '192.0.2.1']) {
    await assert.rejects(
      requestGatewayModels({ host, port: gateway.port, token: secret() }),
      (error) => error.code === 'GATEWAY_UNHEALTHY'
    );
  }
});

test('fails closed when the bearer is missing, malformed, or wrong', async (t) => {
  const gateway = await fixture(t);
  for (const token of [undefined, 'plain-text', secret(Buffer.alloc(32, 8)), secret(Buffer.alloc(31, 7))]) {
    await assert.rejects(
      requestGatewayModels({ host: gateway.host, port: gateway.port, token }),
      (error) => error.code === 'GATEWAY_UNHEALTHY'
    );
  }
});

test('accepts an authenticated empty setup catalog only when pre-auth emptiness is explicit', async (t) => {
  const gateway = await fixture(t, { catalog: { object: 'list', data: [] } });
  assert.deepEqual(
    await requestGatewayModels({ host: gateway.host, port: gateway.port, token: secret(), allowPreAuthEmpty: true }),
    { object: 'list', data: [] }
  );
  await assert.rejects(
    requestGatewayModels({ host: gateway.host, port: gateway.port, token: secret() }),
    (error) => error.code === 'GATEWAY_UNHEALTHY'
  );
});

test('rejects unknown catalog keys, duplicate models, and ambiguous provider ownership', async (t) => {
  const invalidCatalogs = [
    { object: 'list', data: [], extra: true },
    { object: 'list', data: [{ id: 'x', object: 'model', created: 1, owned_by: 'other' }] },
    { object: 'list', data: [
      { id: 'x', object: 'model', created: 1, owned_by: 'codex' },
      { id: 'x', object: 'model', created: 2, owned_by: 'antigravity' }
    ] },
    { object: 'list', data: [{ id: 'x', object: 'model', created: 1, owned_by: 'codex', provider: 'antigravity' }] }
  ];
  for (const catalog of invalidCatalogs) {
    const gateway = await fixture(t, { catalog });
    await assert.rejects(
      requestGatewayModels({ host: gateway.host, port: gateway.port, token: secret(), allowPreAuthEmpty: true }),
      (error) => error.code === 'GATEWAY_UNHEALTHY'
    );
  }
});

test('rejects redirects, non-JSON success, malformed JSON, non-200 status, and oversized bodies', async (t) => {
  const cases = [
    { redirect: 'http://127.0.0.1/elsewhere' },
    { rawBody: '<html></html>', contentType: 'text/html' },
    { rawBody: '{', contentType: 'application/json' },
    { status: 503, rawBody: '{"error":"no"}' },
    { rawBody: 'x'.repeat(16_385), contentType: 'application/json' }
  ];
  for (const options of cases) {
    const gateway = await fixture(t, options);
    await assert.rejects(
      requestGatewayModels({ host: gateway.host, port: gateway.port, token: secret(), maxResponseBytes: 16_384 }),
      (error) => error.code === 'GATEWAY_UNHEALTHY'
    );
  }
});

test('enforces request deadlines and caller cancellation', async (t) => {
  const gateway = await fixture(t, { delayMs: 200 });
  await assert.rejects(
    requestGatewayModels({ host: gateway.host, port: gateway.port, token: secret(), timeoutMs: 20 }),
    (error) => error.code === 'GATEWAY_UNHEALTHY'
  );
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(
    requestGatewayModels({ host: gateway.host, port: gateway.port, token: secret(), signal: controller.signal }),
    (error) => error.code === 'GATEWAY_UNHEALTHY'
  );
});

test('maps transport failure to a redacted error without exposing the bearer', async () => {
  const canaryBytes = Buffer.alloc(32, 9);
  const canaryText = canaryBytes.toString('base64url');
  let capturedAuthorization;
  await assert.rejects(
    requestGatewayModels({
      host: '127.0.0.1', port: 65534, token: secret(canaryBytes),
      request: (_options, callback) => {
        capturedAuthorization = _options.headers.authorization;
        const error = new Error(`transport ${canaryText}`);
        return {
          once(name, handler) { if (name === 'error') queueMicrotask(() => handler(error)); return this; },
          setTimeout() { return this; },
          destroy() {},
          end() {}
        };
      }
    }),
    (error) => {
      const serialized = JSON.stringify({ code: error.code, message: error.message, details: error.details });
      return error.code === 'GATEWAY_UNHEALTHY' && !serialized.includes(canaryText);
    }
  );
  assert.equal(capturedAuthorization, `Bearer ${canaryText}`);
});

test('destroys a hostile response and request immediately after readiness refusal', async () => {
  const incoming = new EventEmitter();
  incoming.statusCode = 503;
  incoming.headers = { 'content-type': 'application/json' };
  incoming.destroyed = false;
  incoming.resume = () => {};
  incoming.destroy = () => { incoming.destroyed = true; };
  let clientDestroyed = false;
  await assert.rejects(requestGatewayModels({
    host: '127.0.0.1', port: 8317, token: secret(),
    request: (_options, callback) => {
      const client = new EventEmitter();
      client.setTimeout = () => client;
      client.destroy = () => { clientDestroyed = true; };
      client.end = () => queueMicrotask(() => callback(incoming));
      return client;
    }
  }), (error) => error.code === 'GATEWAY_UNHEALTHY');
  assert.equal(incoming.destroyed, true);
  assert.equal(clientDestroyed, true);
});
