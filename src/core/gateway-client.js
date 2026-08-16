import http from 'node:http';

import { ClaudeyError } from './errors.js';
import { isSecret } from './secrets.js';
import { validateAuthenticatedModelCatalog } from '../providers/capabilities.js';

const DEFAULT_TIMEOUT_MS = 3_000;
const DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024;

function unhealthy() {
  return new ClaudeyError('GATEWAY_UNHEALTHY', 'The managed gateway did not provide authenticated readiness.');
}

function checkedInteger(value, minimum, maximum) {
  return Number.isSafeInteger(value) && value >= minimum && value <= maximum;
}

function assertRequestOptions({ host, port, token, timeoutMs, maxResponseBytes, allowPreAuthEmpty, signal, request }) {
  if (host !== '127.0.0.1'
    || !checkedInteger(port, 1024, 65535)
    || !isSecret(token)
    || !checkedInteger(timeoutMs, 1, 120_000)
    || !checkedInteger(maxResponseBytes, 1, 1024 * 1024)
    || typeof allowPreAuthEmpty !== 'boolean'
    || (signal !== undefined && (!signal || typeof signal.addEventListener !== 'function'))
    || typeof request !== 'function') {
    throw unhealthy();
  }
}

function bearerHeader(token) {
  try {
    return token.withValue((bytes) => {
      if (bytes.length !== 32) throw unhealthy();
      return `Bearer ${Buffer.from(bytes).toString('base64url')}`;
    });
  } catch {
    throw unhealthy();
  }
}

function strictCatalog(bytes, allowPreAuthEmpty) {
  let decoded;
  let value;
  try {
    decoded = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    value = JSON.parse(decoded);
  } catch {
    throw unhealthy();
  }
  if (!validateAuthenticatedModelCatalog(value, { allowPreAuthEmpty })) throw unhealthy();
  return value;
}

export async function requestGatewayModels({
  host,
  port,
  token,
  allowPreAuthEmpty = false,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
  signal,
  request = http.request
} = {}) {
  assertRequestOptions({ host, port, token, timeoutMs, maxResponseBytes, allowPreAuthEmpty, signal, request });
  if (signal?.aborted) throw unhealthy();
  const authorization = bearerHeader(token);

  return new Promise((resolve, reject) => {
    let settled = false;
    let response;
    let timer;
    const fail = () => {
      try { response?.destroy(); } catch { /* response is already closed */ }
      try { client?.destroy(); } catch { /* request is already closed */ }
      finish(undefined, unhealthy());
    };
    const onAbort = () => {
      try { response?.destroy(); } catch { /* response is already closed */ }
      try { client?.destroy(); } catch { /* request is already closed */ }
      fail();
    };
    const finish = (value, error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      if (error) reject(error); else resolve(value);
    };
    let client;
    try {
      client = request({
        protocol: 'http:',
        host: '127.0.0.1',
        hostname: '127.0.0.1',
        port,
        method: 'GET',
        path: '/v1/models',
        agent: false,
        headers: { accept: 'application/json', authorization, connection: 'close' }
      }, (incoming) => {
        response = incoming;
        const contentType = incoming.headers?.['content-type'];
        const contentLength = Number(incoming.headers?.['content-length']);
        if (incoming.statusCode !== 200
          || typeof contentType !== 'string'
          || !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(contentType)
          || (Number.isFinite(contentLength) && contentLength > maxResponseBytes)) {
          fail();
          return;
        }
        const chunks = [];
        let length = 0;
        incoming.on('data', (chunk) => {
          if (settled) return;
          const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          length += bytes.length;
          if (length > maxResponseBytes) {
            incoming.destroy();
            fail();
            return;
          }
          chunks.push(bytes);
        });
        incoming.once('aborted', fail);
        incoming.once('error', fail);
        incoming.once('end', () => {
          if (settled) return;
          try { finish(strictCatalog(Buffer.concat(chunks, length), allowPreAuthEmpty)); }
          catch { fail(); }
        });
      });
      client.once('error', fail);
      client.setTimeout?.(timeoutMs, onAbort);
      timer = setTimeout(onAbort, timeoutMs);
      timer.unref?.();
      signal?.addEventListener('abort', onAbort, { once: true });
      client.end();
    } catch {
      fail();
    }
  });
}
