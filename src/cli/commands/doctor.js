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

export async function runDoctorCommand(context = {}) {
  let checks;
  try { checks = context.checks; } catch { throw safety(); }
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
