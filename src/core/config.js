import { ClaudexError } from './errors.js';
import { atomicReplace } from './permissions.js';
import { isSecret } from './secrets.js';

export const GATEWAY_CONFIG_CHILD = 'config.yaml';

function usage(message) {
  return new ClaudexError('USAGE_ERROR', message);
}

function safety(message) {
  return new ClaudexError('SAFETY_REFUSAL', message);
}

function assertPort(port) {
  if (!Number.isInteger(port) || port < 1024 || port > 65535) {
    throw usage('Port must be an integer from 1024 through 65535.');
  }
  return port;
}

function quoteYamlString(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) {
    throw safety(`${label} must be a nonempty string without NUL bytes.`);
  }
  return JSON.stringify(value);
}

function bearerText(token) {
  if (!isSecret(token)) throw safety('Gateway bearer token must be an opaque secret.');
  return token.withValue((bytes) => {
    if (bytes.length !== 32) throw safety('Gateway bearer token must contain 32 bytes.');
    return Buffer.from(bytes).toString('base64url');
  });
}

export function buildGatewayConfig({ port = 8317, authDir, token }) {
  const checkedPort = assertPort(port);
  const quotedAuthDir = quoteYamlString(authDir, 'Gateway auth directory');
  const quotedToken = quoteYamlString(bearerText(token), 'Gateway bearer token');
  const yaml = `host: "127.0.0.1"
port: ${checkedPort}
tls:
  enable: false
remote-management:
  allow-remote: false
  secret-key: ""
  disable-control-panel: true
auth-dir: ${quotedAuthDir}
api-keys:
  - ${quotedToken}
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
  return Buffer.from(yaml, 'utf8');
}

export async function writeGatewayConfig(options, paths, deps = {}) {
  if (typeof deps.assertLockHeld !== 'function') throw safety('Configuration mutation requires the installation lock.');
  await deps.assertLockHeld();
  if (!paths || typeof paths.configRoot !== 'string') throw safety('A fixed configuration root is required.');
  const bytes = buildGatewayConfig(options);
  const replace = deps.atomicReplace ?? atomicReplace;
  await replace({
    root: paths.configRoot,
    child: GATEWAY_CONFIG_CHILD,
    bytes,
    mode: 0o600
  }, deps.atomicDeps);
  return bytes;
}
