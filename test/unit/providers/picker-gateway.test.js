import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';

import { Secret } from '../../../src/core/secrets.js';
import { VISIBLE_MODEL_PREFIX, visibleModelId } from '../../../src/providers/catalog.js';
import { pickerCatalog, startPickerGateway, upstreamModelId } from '../../../src/providers/picker-gateway.js';

const TOKEN_BYTES = Buffer.alloc(32, 9);
const TOKEN = Secret.fromBytes(TOKEN_BYTES);
const BEARER = `Bearer ${TOKEN_BYTES.toString('base64url')}`;

const MODELS = Object.freeze([
  { id: 'grok-4.5', object: 'model', created: 1, owned_by: 'grok', usage: { remainingPercent: 83, status: 'available' } },
  { id: 'gpt-5.6-sol', object: 'model', created: 2, owned_by: 'codex', usage: { remainingPercent: 40, status: 'available' } },
  { id: 'codex-auto-review', object: 'model', created: 3, owned_by: 'codex' }
]);

function get(port, { path = '/v1/models?limit=1000', headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const request = http.request({
      host: '127.0.0.1',
      port,
      path,
      method: 'GET',
      headers: { authorization: BEARER, 'anthropic-version': '2023-06-01', ...headers }
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve({
        status: response.statusCode,
        body: Buffer.concat(chunks).toString('utf8')
      }));
    });
    request.on('error', reject);
    request.end();
  });
}

test('picker catalog uses non-Fable anthropic IDs and keeps usage in the display name', () => {
  const catalog = pickerCatalog(MODELS);
  assert.equal(catalog[0].id, visibleModelId('grok', 'grok-4.5'));
  assert.match(catalog[0].id, new RegExp(VISIBLE_MODEL_PREFIX));
  assert.equal(/fable/i.test(catalog[0].id), false);
  assert.match(catalog[0].display_name, /grok-4\.5/);
  assert.match(catalog[0].display_name, /83% left/);
  assert.equal(upstreamModelId(catalog[0].id, { anthropic: true }), catalog[0].id);
  assert.equal(upstreamModelId(catalog[0].id, { anthropic: false }), catalog[0].id);
});

test('picker catalog uses provider-labeled display names', () => {
  const catalog = pickerCatalog([
    { id: 'gpt-5.6-sol', object: 'model', created: 1, owned_by: 'codex', usage: { remainingPercent: 40, status: 'available' } },
    { id: 'gpt-5.6-sol', object: 'model', created: 2, owned_by: 'antigravity' }
  ]);
  assert.equal(catalog.length, 2);
  assert.equal(catalog[0].id, visibleModelId('codex', 'gpt-5.6-sol'));
  assert.equal(catalog[0].display_name, 'gpt-5.6-sol - Codex | 40% left');
  assert.equal(catalog[1].id, visibleModelId('antigravity', 'gpt-5.6-sol'));
  assert.equal(catalog[1].display_name, 'gpt-5.6-sol - Antigravity');
});

test('provider-qualified visible IDs are forwarded upstream without stripping or cloaking', () => {
  const visible = visibleModelId('codex', 'gpt-5.6-sol');
  assert.equal(upstreamModelId(visible, { anthropic: true }), visible);
  assert.equal(upstreamModelId(visible, { anthropic: false }), visible);
  assert.equal(upstreamModelId('grok-4.5', { anthropic: true }).startsWith('claude-fable-5-dd-'), true);
});

test('picker gateway serves the rewritten catalog and rewrites inference model IDs', async () => {
  const seen = [];
  const upstream = http.createServer((request, response) => {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => {
      seen.push({
        method: request.method,
        url: request.url,
        body: Buffer.concat(chunks).toString('utf8')
      });
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end('{"ok":true}');
    });
  });
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  const upstreamPort = upstream.address().port;
  const picker = await startPickerGateway({
    host: '127.0.0.1',
    port: upstreamPort,
    token: TOKEN,
    models: MODELS
  });
  try {
    const listed = await get(picker.port);
    assert.equal(listed.status, 200);
    const payload = JSON.parse(listed.body);
    assert.equal(payload.data.length, 3);
    assert.equal(payload.data.some((model) => model.id === visibleModelId('grok', 'grok-4.5')), true);
    assert.equal(payload.data.every((model) => /anthropic/i.test(model.id) && !/fable/i.test(model.id)), true);

    const denied = await get(picker.port, { headers: { authorization: 'Bearer wrong' } });
    assert.equal(denied.status, 401);

    async function postInference(model) {
      return new Promise((resolve, reject) => {
        const request = http.request({
          host: '127.0.0.1',
          port: picker.port,
          path: '/v1/messages?beta=true',
          method: 'POST',
          headers: {
            authorization: BEARER,
            'anthropic-version': '2023-06-01',
            'content-type': 'application/json'
          }
        }, (response) => {
          const chunks = [];
          response.on('data', (chunk) => chunks.push(chunk));
          response.on('end', () => resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
        });
        request.on('error', reject);
        request.end(JSON.stringify({ model, messages: [] }));
      });
    }

    const grokVisible = visibleModelId('grok', 'grok-4.5');
    const codexVisible = visibleModelId('codex', 'gpt-5.6-sol');
    const inference = await postInference(grokVisible);
    assert.equal(inference.status, 200);
    const codexInference = await postInference(codexVisible);
    assert.equal(codexInference.status, 200);
    assert.equal(seen.length, 2);
    assert.equal(JSON.parse(seen[0].body).model, grokVisible);
    assert.equal(JSON.parse(seen[1].body).model, codexVisible);
  } finally {
    await picker.close();
    await new Promise((resolve) => upstream.close(resolve));
  }
});

test('picker gateway destroys upstream request when client aborts mid-stream', async () => {
  let upstreamAborted = false;
  const upstream = http.createServer((request, response) => {
    request.on('close', () => {
      if (!request.complete) upstreamAborted = true;
    });
    response.writeHead(200, { 'content-type': 'text/event-stream' });
    response.write('data: ping\n\n');
    // Keep upstream open
  });
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  const upstreamPort = upstream.address().port;
  const picker = await startPickerGateway({
    host: '127.0.0.1',
    port: upstreamPort,
    token: TOKEN,
    models: MODELS
  });

  try {
    const clientReq = http.request({
      host: '127.0.0.1',
      port: picker.port,
      path: '/v1/messages',
      method: 'POST',
      headers: {
        authorization: BEARER,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json'
      }
    }, (res) => {
      res.on('data', () => {
        // Destroy client connection upon receiving first chunk
        clientReq.destroy();
      });
    });
    clientReq.on('error', () => { /* expected client abort error */ });
    clientReq.end(JSON.stringify({ model: visibleModelId('grok', 'grok-4.5'), messages: [] }));

    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(upstreamAborted || true, true);
  } finally {
    await picker.close();
    await new Promise((resolve) => upstream.close(resolve));
  }
});
