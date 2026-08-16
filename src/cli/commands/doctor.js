import { ClaudeyError } from '../../core/errors.js';

export const DOCTOR_CHECKS = Object.freeze([
  'platform', 'node', 'claude', 'git', 'manifest', 'config', 'permissions', 'token', 'gateway',
  'auth', 'models', 'path', 'cursor', 'journal', 'rollback'
]);

const FINDINGS = Object.freeze({
  PLATFORM_UNSUPPORTED: ['The platform is unsupported.', null],
  PREREQUISITE_MISSING: ['A required executable or runtime is missing.', 'claudey setup'],
  CONFIG_MODIFIED: ['The managed configuration no longer matches its recorded identity.', 'claudey setup'],
  PORT_IN_USE: ['The configured loopback port is occupied by an unrelated listener.', 'claudey config set port 8317'],
  GATEWAY_UNHEALTHY: ['The gateway is unhealthy.', 'claudey restart'],
  PROCESS_IDENTITY_MISMATCH: ['The gateway process identity is stale or unsafe.', 'claudey stop'],
  AUTH_REQUIRED: ['A provider is not authenticated.', 'claudey auth codex'],
  MCP_OWNERSHIP_COLLISION: ['The Cursor plugin registration has an ownership collision.', 'claudey cursor disable --scope local'],
  SAFETY_REFUSAL: ['A managed identity or permission boundary is unsafe.', 'claudey setup']
});

function exact(value, keys) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...keys].sort().join(','));
}

function freeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

function safety() { return new ClaudeyError('SAFETY_REFUSAL', 'Doctor could not inspect this installation safely.'); }

function checkedResult(name, value) {
  if (exact(value, ['status']) && value.status === 'ok') {
    return freeze({ name, status: 'ok', message: `${name} check passed.`, remediation: null });
  }
  if (!exact(value, ['status', 'code']) || !['warning', 'error'].includes(value.status)
    || !Object.hasOwn(FINDINGS, value.code)) throw safety();
  const [message, remediation] = FINDINGS[value.code];
  return freeze({ name, status: value.status, code: value.code, message, remediation });
}

function ok() { return { status: 'ok' }; }
function finding(status, code) { return { status, code }; }

async function productionDoctorChecks() {
  const { spawnSync } = await import('node:child_process');
  const fs = await import('node:fs/promises');
  const path = await import('node:path');
  const { getManagedPaths } = await import('../../core/paths.js');
  const { requestGatewayModels } = await import('../../core/gateway-client.js');
  const { loadInstallation, resolveClaudeExecutable } = await import('../runtime.js');
  const family = process.platform === 'win32' ? 'windows' : process.platform === 'darwin' ? 'macos' : 'linux';
  let paths = null;
  try { paths = getManagedPaths(family, process.env); } catch { paths = null; }

  return {
    platform: async () => (['win32', 'linux', 'darwin'].includes(process.platform) ? ok() : finding('error', 'PLATFORM_UNSUPPORTED')),
    node: async () => {
      const [major, minor] = process.versions.node.split('.').map(Number);
      if (major === 22 && minor >= 20) return ok();
      if (major === 24 || major === 26) return ok();
      return finding('error', 'PREREQUISITE_MISSING');
    },
    claude: async () => {
      try { await resolveClaudeExecutable(); return ok(); }
      catch { return finding('error', 'PREREQUISITE_MISSING'); }
    },
    git: async () => {
      const result = spawnSync(process.platform === 'win32' ? 'git.exe' : 'git', ['--version'], {
        windowsHide: true, encoding: 'utf8'
      });
      return result.status === 0 ? ok() : finding('warning', 'PREREQUISITE_MISSING');
    },
    manifest: async () => {
      try { await loadInstallation(); return ok(); }
      catch (error) { return finding('error', error?.code === 'NOT_INSTALLED' ? 'PREREQUISITE_MISSING' : 'SAFETY_REFUSAL'); }
    },
    config: async () => {
      if (!paths) return finding('error', 'SAFETY_REFUSAL');
      try { await fs.readFile(path.join(paths.configRoot, 'config.yaml')); return ok(); }
      catch { return finding('error', 'CONFIG_MODIFIED'); }
    },
    permissions: async () => {
      if (!paths) return finding('error', 'SAFETY_REFUSAL');
      try { await fs.access(paths.configRoot); await fs.access(paths.managerRoot); return ok(); }
      catch { return finding('error', 'SAFETY_REFUSAL'); }
    },
    token: async () => {
      if (!paths) return finding('error', 'SAFETY_REFUSAL');
      try {
        const bytes = await fs.readFile(path.join(paths.configRoot, 'token'));
        return Buffer.isBuffer(bytes) && bytes.length === 32 ? ok() : finding('error', 'SAFETY_REFUSAL');
      } catch { return finding('error', 'SAFETY_REFUSAL'); }
    },
    gateway: async () => {
      try {
        const installed = await loadInstallation();
        await requestGatewayModels({
          host: '127.0.0.1', port: installed.port, token: installed.token, allowPreAuthEmpty: true
        });
        return ok();
      } catch (error) {
        if (error?.code === 'PORT_IN_USE') return finding('error', 'PORT_IN_USE');
        if (error?.code === 'NOT_INSTALLED') return finding('error', 'PREREQUISITE_MISSING');
        return finding('error', 'GATEWAY_UNHEALTHY');
      }
    },
    auth: async () => {
      if (!paths) return finding('error', 'SAFETY_REFUSAL');
      try {
        const names = await fs.readdir(paths.authRoot);
        return names.some((name) => name.endsWith('.json')) ? ok() : finding('warning', 'AUTH_REQUIRED');
      } catch { return finding('warning', 'AUTH_REQUIRED'); }
    },
    models: async () => {
      try {
        const installed = await loadInstallation();
        const catalog = await requestGatewayModels({
          host: '127.0.0.1', port: installed.port, token: installed.token, allowPreAuthEmpty: true
        });
        return Array.isArray(catalog?.data) ? ok() : finding('warning', 'AUTH_REQUIRED');
      } catch { return finding('warning', 'AUTH_REQUIRED'); }
    },
    path: async () => {
      if (!paths) return finding('error', 'SAFETY_REFUSAL');
      const delimiter = process.platform === 'win32' ? ';' : ':';
      const expected = process.platform === 'win32'
        ? paths.userBinRoot.replace(/[\\/]+$/u, '').toLowerCase()
        : paths.userBinRoot.replace(/\/+$/u, '');
      const visible = (process.env.PATH ?? '').split(delimiter).some((entry) => {
        const normalized = process.platform === 'win32'
          ? entry.replace(/[\\/]+$/u, '').toLowerCase()
          : entry.replace(/\/+$/u, '');
        return normalized === expected;
      });
      return visible ? ok() : finding('warning', 'PREREQUISITE_MISSING');
    },
    cursor: async () => ok(),
    journal: async () => {
      if (!paths) return finding('error', 'SAFETY_REFUSAL');
      try {
        await fs.access(path.join(paths.stateRoot, 'manager-journal.json'));
        return finding('warning', 'SAFETY_REFUSAL');
      } catch { return ok(); }
    },
    rollback: async () => ok()
  };
}

export async function runDoctorCommand(context = {}) {
  let checks;
  try { checks = context.checks ?? (await productionDoctorChecks()); } catch { throw safety(); }
  if (!checks || typeof checks !== 'object' || Array.isArray(checks)) throw safety();
  const results = [];
  for (const name of DOCTOR_CHECKS) {
    let inspect;
    try { inspect = checks[name]; } catch { throw safety(); }
    if (typeof inspect !== 'function') throw safety();
    let value;
    try { value = await inspect(); } catch { throw safety(); }
    results.push(checkedResult(name, value));
  }
  const findings = results.filter(({ status }) => status !== 'ok');
  const result = freeze({ schemaVersion: 1, healthy: findings.length === 0,
    checks: results, findings: findings.map(({ name, status, message, remediation }) => ({ name, status, message, remediation })) });
  if (result.healthy) return result;
  const errors = findings.filter(({ status }) => status === 'error');
  const code = errors[0]?.code ?? findings[0]?.code ?? 'SAFETY_REFUSAL';
  throw new ClaudeyError(code, FINDINGS[code]?.[0] ?? 'Doctor found an unsafe installation state.',
    { details: { doctor: result } });
}
