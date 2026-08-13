import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const DEFAULT_CATALOG = Object.freeze({
  object: 'list',
  data: [{ id: 'gpt-fixture', object: 'model', created: 1, owned_by: 'codex' }]
});

export async function startFakeGateway({
  token,
  catalog = DEFAULT_CATALOG,
  status = 200,
  redirect,
  delayMs = 0,
  rawBody,
  contentType = 'application/json',
  host = '127.0.0.1',
  port = 0
} = {}) {
  const server = http.createServer((request, response) => {
    const reply = () => {
      if (request.method !== 'GET' || request.url !== '/v1/models') {
        response.writeHead(404).end();
        return;
      }
      if (redirect) {
        response.writeHead(302, { location: redirect }).end();
        return;
      }
      if (request.headers.authorization !== `Bearer ${token}`) {
        response.writeHead(401, { 'content-type': 'application/json' }).end('{"error":"unauthorized"}');
        return;
      }
      const body = rawBody ?? JSON.stringify(catalog);
      response.writeHead(status, { 'content-type': contentType });
      response.end(body);
    };
    if (delayMs > 0) setTimeout(reply, delayMs).unref();
    else reply();
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, resolve);
  });
  const address = server.address();
  return {
    host,
    port: address.port,
    close: () => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()))
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const args = process.argv.slice(2);
  if (args.length === 0) process.exit(0);
  if (args.length !== 2 || args[0] !== '--config' || !path.isAbsolute(args[1])) process.exit(2);
  let config;
  try {
    const bytes = await fs.readFile(args[1]);
    if (bytes.length > 64 * 1024) process.exit(2);
    config = bytes.toString('utf8');
  } catch { process.exit(2); }
  const host = /^host: "([^"]+)"$/m.exec(config)?.[1];
  const port = Number(/^port: (\d+)$/m.exec(config)?.[1]);
  const token = /^  - "([A-Za-z0-9_-]{43})"$/m.exec(config)?.[1];
  if (host !== '127.0.0.1' || !Number.isSafeInteger(port) || port < 1024 || port > 65535 || !token) process.exit(2);
  const gateway = await startFakeGateway({ host, port, token });
  let closing = false;
  const close = async () => {
    if (closing) return;
    closing = true;
    await gateway.close();
    process.exit(0);
  };
  process.on('SIGINT', close);
  process.on('SIGTERM', close);
}
