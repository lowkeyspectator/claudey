import http from 'node:http';

import { ClaudeyError } from '../core/errors.js';
import { isSecret } from '../core/secrets.js';
import { GATEWAY_PROVIDERS, cloakModelId, parseVisibleModelId, sourceModelId, visibleModelId } from './catalog.js';
import { formatUsageLine } from './usage.js';

const MAX_REQUEST_BYTES = 32 * 1024 * 1024;
const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailers', 'transfer-encoding', 'upgrade', 'content-length'
]);

function failure() {
  return new ClaudeyError('GATEWAY_UNHEALTHY', 'The mixed-session model picker could not be started.');
}

function bearer(token) {
  return token.withValue((bytes) => {
    if (bytes.length !== 32) throw failure();
    return `Bearer ${Buffer.from(bytes).toString('base64url')}`;
  });
}

function authorized(request, expected) {
  return typeof request.headers?.authorization === 'string' && request.headers.authorization === expected;
}

function modelsRequest(method, url) {
  if (method !== 'GET' && method !== 'HEAD') return false;
  const pathname = String(url ?? '').split('?')[0];
  return pathname === '/v1/models';
}

function anthropicRequest(request) {
  return typeof request.headers?.['anthropic-version'] === 'string'
    || /claude/i.test(String(request.headers?.['user-agent'] ?? ''));
}

export function upstreamModelId(value, { anthropic = false } = {}) {
  if (parseVisibleModelId(value)) return value;
  const raw = sourceModelId(value);
  return anthropic ? cloakModelId(raw) : raw;
}

export function pickerCatalog(models) {
  if (!Array.isArray(models)) return [];
  return models.flatMap((model) => {
    if (!model || typeof model !== 'object' || typeof model.id !== 'string' || !GATEWAY_PROVIDERS.includes(model.owned_by)) {
      return [];
    }
    return [Object.freeze({
      id: visibleModelId(model.owned_by, model.id),
      display_name: formatUsageLine(model),
      object: 'model',
      type: 'model',
      owned_by: model.owned_by
    })];
  });
}

function rewriteRequestModel(body, { anthropic }) {
  if (!Buffer.isBuffer(body) || body.length === 0) return body;
  let parsed;
  try { parsed = JSON.parse(body.toString('utf8')); } catch { return body; }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) || typeof parsed.model !== 'string') return body;
  const next = { ...parsed, model: upstreamModelId(parsed.model, { anthropic }) };
  return Buffer.from(JSON.stringify(next), 'utf8');
}

function forwardHeaders(incoming, { host, contentLength }) {
  const headers = { host };
  for (const [name, value] of Object.entries(incoming.headers ?? {})) {
    if (typeof value !== 'string' && !Array.isArray(value)) continue;
    if (HOP_BY_HOP.has(name.toLowerCase())) continue;
    headers[name] = value;
  }
  if (Number.isSafeInteger(contentLength)) headers['content-length'] = String(contentLength);
  return headers;
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let length = 0;
    request.on('data', (chunk) => {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      length += bytes.length;
      if (length > MAX_REQUEST_BYTES) {
        request.destroy();
        reject(new ClaudeyError('SAFETY_REFUSAL', 'The mixed-session request exceeded the picker size limit.'));
        return;
      }
      chunks.push(bytes);
    });
    request.on('end', () => resolve(Buffer.concat(chunks, length)));
    request.on('error', reject);
  });
}

export async function startPickerGateway({
  host,
  port,
  token,
  models,
  listen = http.createServer,
  connect = http.request
} = {}) {
  if (host !== '127.0.0.1'
    || !Number.isSafeInteger(port) || port < 1024 || port > 65535
    || !isSecret(token)
    || !Array.isArray(models)) throw failure();
  let expected;
  try { expected = bearer(token); } catch { throw failure(); }
  const data = pickerCatalog(models);
  const payload = Buffer.from(JSON.stringify({ object: 'list', data }), 'utf8');

  const server = listen(async (request, response) => {
    if (!authorized(request, expected)) {
      response.writeHead(401, { 'content-type': 'application/json', connection: 'close' });
      response.end('{"error":"unauthorized"}');
      return;
    }
    if (modelsRequest(request.method, request.url)) {
      response.writeHead(200, {
        'content-type': 'application/json',
        'content-length': String(request.method === 'HEAD' ? 0 : payload.length),
        connection: 'close'
      });
      response.end(request.method === 'HEAD' ? undefined : payload);
      return;
    }
    let body = Buffer.alloc(0);
    try { body = await readBody(request); } catch {
      if (!response.headersSent) response.writeHead(413, { connection: 'close' }).end();
      return;
    }
    const rewritten = rewriteRequestModel(body, { anthropic: anthropicRequest(request) });
    let incomingResponse = null;
    const upstream = connect({
      protocol: 'http:',
      host: '127.0.0.1',
      hostname: '127.0.0.1',
      port,
      method: request.method,
      path: request.url,
      agent: false,
      headers: forwardHeaders(request, { host: `127.0.0.1:${port}`, contentLength: rewritten.length })
    }, (incoming) => {
      incomingResponse = incoming;
      const headers = { ...incoming.headers };
      delete headers.connection;
      response.writeHead(incoming.statusCode ?? 502, headers);
      incoming.on('error', () => {
        if (!response.destroyed) response.destroy();
      });
      incoming.pipe(response);
    });

    const cleanup = () => {
      try { if (!upstream.destroyed) upstream.destroy(); } catch { /* ignore */ }
      try { if (incomingResponse && !incomingResponse.destroyed) incomingResponse.destroy(); } catch { /* ignore */ }
    };

    request.on('close', () => {
      if (!response.writableEnded) cleanup();
    });
    response.on('close', () => {
      if (!response.writableEnded) cleanup();
    });

    upstream.on('error', () => {
      if (!response.headersSent) response.writeHead(502, { connection: 'close' }).end();
      else if (!response.destroyed) response.destroy();
    });
    upstream.end(rewritten.length > 0 ? rewritten : undefined);
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  if (!address || !Number.isSafeInteger(address.port)) {
    server.close();
    throw failure();
  }
  return Object.freeze({
    host: '127.0.0.1',
    port: address.port,
    models: Object.freeze(data),
    close: () => new Promise((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    })
  });
}
