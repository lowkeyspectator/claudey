import { ClaudexError } from '../core/errors.js';
import {
  MCP_PROTOCOL_VERSION, buildCursorToolDescriptors, validateCursorToolArguments
} from './mcp-schema.js';

const FORBIDDEN_ENVIRONMENT = new Set([
  'ANTHROPIC_BASE_URL', 'ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'GOOGLE_API_KEY',
  'GOOGLE_APPLICATION_CREDENTIALS', 'GITHUB_TOKEN', 'GH_TOKEN', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY',
  'AZURE_CLIENT_SECRET', 'CURSOR_API_KEY'
]);
const MAX_STRUCTURED_BYTES = 480_000;
const PUBLIC_CODES = new Set([
  'SAFETY_REFUSAL', 'CAPABILITY_UNSUPPORTED', 'AUTH_REQUIRED', 'MODEL_NOT_FOUND', 'APPROVAL_REQUIRED', 'APPROVAL_INVALID'
]);

function safety(message = 'The Cursor MCP server refused an unsafe operation.') {
  return new ClaudexError('SAFETY_REFUSAL', message);
}

function record(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exact(value, allowed, required = allowed) {
  if (!record(value)) return false;
  const keys = Object.keys(value);
  return keys.every((key) => allowed.includes(key)) && required.every((key) => Object.hasOwn(value, key));
}

function validId(value) {
  return Number.isSafeInteger(value) || typeof value === 'string' && value.length > 0
    && value.length <= 128 && !/[\u0000-\u001f\u007f]/u.test(value);
}

function response(id, result) { return { jsonrpc: '2.0', id, result }; }
function protocolError(id, code, message) { return { jsonrpc: '2.0', id, error: { code, message } }; }

export function assertCursorMcpEnvironment(environment) {
  try {
    if (!environment || typeof environment !== 'object' || Array.isArray(environment)
      || environment.CLAUDE_CODE_SUBPROCESS_ENV_SCRUB !== '1') throw safety();
    for (const name of Object.keys(environment)) {
      if (FORBIDDEN_ENVIRONMENT.has(name)
        || /^CLAUDE_(?:SESSION|AUTH|OAUTH|TOKEN|CODE_(?!SUBPROCESS_ENV_SCRUB$))/u.test(name)
        || /^CLIPROXY(?:API)?_/u.test(name) || /^CLI_PROXY(?:_API)?_/u.test(name)) throw safety();
    }
    return Object.freeze({ scrubbed: true });
  } catch { throw safety('The Cursor MCP server requires a verified scrubbed environment.'); }
}

function initializeParams(value) {
  return exact(value, ['protocolVersion', 'capabilities', 'clientInfo'])
    && value.protocolVersion === MCP_PROTOCOL_VERSION && record(value.capabilities)
    && exact(value.clientInfo, ['name', 'version'])
    && typeof value.clientInfo.name === 'string' && value.clientInfo.name.length > 0 && value.clientInfo.name.length <= 128
    && typeof value.clientInfo.version === 'string' && value.clientInfo.version.length > 0 && value.clientInfo.version.length <= 64;
}

function publicError(error) {
  let code;
  try { code = error?.code; } catch { code = undefined; }
  if (!PUBLIC_CODES.has(code)) code = 'SAFETY_REFUSAL';
  const messages = {
    SAFETY_REFUSAL: 'The Cursor MCP tool refused an unsafe operation.',
    CAPABILITY_UNSUPPORTED: 'Cursor Agent cannot perform this operation.',
    AUTH_REQUIRED: 'Cursor Agent authentication is required.',
    MODEL_NOT_FOUND: 'The requested Cursor model is unavailable.',
    APPROVAL_REQUIRED: 'A separate Cursor write approval is required.',
    APPROVAL_INVALID: 'The Cursor write approval is invalid, expired, or already consumed.'
  };
  return { code, message: messages[code] };
}

function jsonClone(value) {
  try {
    if (!record(value)) throw safety();
    const serialized = JSON.stringify(value);
    if (Buffer.byteLength(serialized, 'utf8') > MAX_STRUCTURED_BYTES) throw safety();
    return { value: JSON.parse(serialized), serialized };
  } catch { throw safety(); }
}

function toolSuccess(value) {
  const cloned = jsonClone(value);
  const structuredContent = { ok: true, value: cloned.value };
  return { content: [{ type: 'text', text: JSON.stringify(structuredContent) }], structuredContent };
}

function toolFailure(error) {
  const failure = publicError(error);
  const structuredContent = { ok: false, error: failure };
  return { content: [{ type: 'text', text: JSON.stringify(structuredContent) }], structuredContent, isError: true };
}

function abortRace(signal) {
  return new Promise((resolve, reject) => {
    if (signal.aborted) reject(Object.assign(new Error('cancelled'), { cancelled: true }));
    else signal.addEventListener('abort', () => reject(Object.assign(new Error('cancelled'), { cancelled: true })), { once: true });
  });
}

export function createCursorMcpServer({
  environment, capabilities, writesEnabled, worktreeSafetyReady, revalidateStartup, executeTool
} = {}) {
  assertCursorMcpEnvironment(environment);
  const tools = buildCursorToolDescriptors({ capabilities, writesEnabled, worktreeSafetyReady });
  if (typeof revalidateStartup !== 'function' || typeof executeTool !== 'function') throw safety();
  const names = new Set(tools.map(({ name }) => name));
  const active = new Map();
  let initializeReceived = false;
  let initialized = false;
  let closed = false;

  const close = async () => {
    if (!closed) {
      closed = true;
      for (const controller of active.values()) controller.abort();
    }
    return Object.freeze({ action: 'closed' });
  };

  const handleNotification = (message) => {
    if (message.method === 'notifications/initialized') {
      if (initializeReceived && (!Object.hasOwn(message, 'params') || exact(message.params, []))) initialized = true;
    } else if (message.method === 'notifications/cancelled'
      && exact(message.params, ['requestId'], ['requestId']) && validId(message.params.requestId)) {
      active.get(`${typeof message.params.requestId}:${message.params.requestId}`)?.abort();
    }
    return null;
  };

  const handle = async (message) => {
    try {
      if (!record(message) || message.jsonrpc !== '2.0' || typeof message.method !== 'string'
        || Object.keys(message).some((key) => !['jsonrpc', 'id', 'method', 'params'].includes(key))) {
        return protocolError(null, -32600, 'Invalid Request');
      }
      const isNotification = !Object.hasOwn(message, 'id');
      if (isNotification) return handleNotification(message);
      if (!validId(message.id)) return protocolError(null, -32600, 'Invalid Request');
      const { id } = message;
      if (closed) return protocolError(id, -32603, 'Cursor MCP server is closed.');

      if (message.method === 'initialize') {
        if (initializeReceived || !initializeParams(message.params)) return protocolError(id, -32602, 'Invalid params');
        initializeReceived = true;
        return response(id, {
          protocolVersion: MCP_PROTOCOL_VERSION, capabilities: { tools: { listChanged: false } },
          serverInfo: { name: 'claudex-cursor', version: '1.0.0' }
        });
      }
      if (!initialized) return protocolError(id, -32002, 'Cursor MCP server is not initialized.');
      if (message.method === 'ping') {
        if (Object.hasOwn(message, 'params') && !exact(message.params, [])) return protocolError(id, -32602, 'Invalid params');
        return response(id, {});
      }
      if (message.method === 'tools/list') {
        if (Object.hasOwn(message, 'params') && !exact(message.params, [])) return protocolError(id, -32602, 'Invalid params');
        let safe = false;
        try { safe = await revalidateStartup() === true; } catch { safe = false; }
        if (!safe) return protocolError(id, -32603, 'Cursor MCP startup identity is unsafe.');
        return response(id, { tools });
      }
      if (message.method !== 'tools/call') return protocolError(id, -32601, 'Method not found');
      if (!exact(message.params, ['name', 'arguments']) || typeof message.params.name !== 'string'
        || !names.has(message.params.name)) return protocolError(id, -32602, 'Invalid params');
      let args;
      try { args = validateCursorToolArguments(message.params.name, message.params.arguments); }
      catch { return protocolError(id, -32602, 'Invalid params'); }
      const key = `${typeof id}:${id}`;
      if (active.has(key)) return protocolError(id, -32600, 'Duplicate active request id.');
      const controller = new AbortController();
      active.set(key, controller);
      try {
        let safe = false;
        try { safe = await Promise.race([revalidateStartup(), abortRace(controller.signal)]) === true; }
        catch (error) { if (error?.cancelled) return protocolError(id, -32800, 'Request cancelled.'); }
        if (!safe) return protocolError(id, -32603, 'Cursor MCP startup identity is unsafe.');
        try {
          const value = await Promise.race([
            executeTool(Object.freeze({ name: message.params.name, arguments: args, signal: controller.signal })),
            abortRace(controller.signal)
          ]);
          return response(id, toolSuccess(value));
        } catch (error) {
          if (error?.cancelled || controller.signal.aborted) return protocolError(id, -32800, 'Request cancelled.');
          return response(id, toolFailure(error));
        }
      } finally { active.delete(key); }
    } catch {
      const id = record(message) && validId(message.id) ? message.id : null;
      return protocolError(id, -32603, 'Cursor MCP internal error.');
    }
  };

  return Object.freeze({ handle, close });
}

function parseError() { return protocolError(null, -32700, 'Parse error'); }

export async function serveCursorMcpStdio({
  server, input, output, maxRequestBytes = 65_536, maxOutputBytes = 1_048_576, shutdownGraceMs = 50
} = {}) {
  if (!server || typeof server.handle !== 'function' || typeof server.close !== 'function'
    || !input || typeof input[Symbol.asyncIterator] !== 'function' || !output || typeof output.write !== 'function'
    || !Number.isSafeInteger(maxRequestBytes) || maxRequestBytes < 256 || maxRequestBytes > 1_048_576
    || !Number.isSafeInteger(maxOutputBytes) || maxOutputBytes < 256 || maxOutputBytes > 2_097_152
    || !Number.isSafeInteger(shutdownGraceMs) || shutdownGraceMs < 0 || shutdownGraceMs > 1_000) throw safety();
  const pending = new Set();
  let writes = Promise.resolve();
  let buffer = Buffer.alloc(0);
  let discarding = false;

  const queueResponse = (value) => {
    let serialized = `${JSON.stringify(value)}\n`;
    if (Buffer.byteLength(serialized, 'utf8') > maxOutputBytes) {
      const id = validId(value?.id) ? value.id : null;
      serialized = `${JSON.stringify(protocolError(id, -32603, 'Cursor MCP response exceeded its output limit.'))}\n`;
    }
    writes = writes.then(() => new Promise((resolve, reject) => {
      try { output.write(serialized, 'utf8', (error) => error ? reject(error) : resolve()); }
      catch (error) { reject(error); }
    }));
    return writes;
  };

  const schedule = (line) => {
    let task;
    task = (async () => {
      if (line.length > maxRequestBytes) { await queueResponse(parseError()); return; }
      let text;
      try { text = new TextDecoder('utf-8', { fatal: true }).decode(line); }
      catch { await queueResponse(parseError()); return; }
      let message;
      try { message = JSON.parse(text); }
      catch { await queueResponse(parseError()); return; }
      const result = await server.handle(message);
      if (result !== null) await queueResponse(result);
    })().catch(async () => { await queueResponse(protocolError(null, -32603, 'Cursor MCP transport error.')); })
      .finally(() => pending.delete(task));
    pending.add(task);
  };

  try {
    for await (const rawChunk of input) {
      let chunk = Buffer.isBuffer(rawChunk) ? rawChunk : Buffer.from(rawChunk);
      while (chunk.length > 0) {
        const newline = chunk.indexOf(0x0a);
        if (discarding) {
          if (newline === -1) { chunk = Buffer.alloc(0); continue; }
          discarding = false;
          chunk = chunk.subarray(newline + 1);
          continue;
        }
        if (newline === -1) {
          if (buffer.length + chunk.length > maxRequestBytes) {
            buffer = Buffer.alloc(0); discarding = true; schedule(Buffer.alloc(maxRequestBytes + 1));
          } else buffer = Buffer.concat([buffer, chunk]);
          chunk = Buffer.alloc(0);
          continue;
        }
        const line = Buffer.concat([buffer, chunk.subarray(0, newline)]);
        buffer = Buffer.alloc(0);
        schedule(line.length > 0 && line.at(-1) === 0x0d ? line.subarray(0, -1) : line);
        chunk = chunk.subarray(newline + 1);
      }
    }
    if (!discarding && buffer.length > 0) schedule(buffer);
    if (pending.size > 0) {
      await Promise.race([
        Promise.allSettled([...pending]),
        new Promise((resolve) => setTimeout(resolve, shutdownGraceMs))
      ]);
    }
    await server.close();
    if (pending.size > 0) await Promise.allSettled([...pending]);
    await writes;
  } finally {
    await server.close();
  }
  if (typeof output.end === 'function') await new Promise((resolve) => output.end(resolve));
  return Object.freeze({ action: 'closed' });
}
