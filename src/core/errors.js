import { isSecret } from './secrets.js';

const exitCodes = new Map([
  ['USAGE_ERROR', 2],
  ['PLATFORM_UNSUPPORTED', 3], ['PREREQUISITE_MISSING', 3], ['CAPABILITY_UNSUPPORTED', 3], ['NOT_INSTALLED', 3],
  ['AUTH_REQUIRED', 4], ['INTERACTION_REQUIRED', 4], ['MODEL_REQUIRED', 4], ['MODEL_NOT_FOUND', 4],
  ['NETWORK_FAILURE', 5], ['CHECKSUM_MISMATCH', 5], ['ARCHIVE_UNSAFE', 5],
  ['LOCK_BUSY', 6], ['PORT_IN_USE', 6], ['GATEWAY_UNHEALTHY', 6], ['PROCESS_IDENTITY_MISMATCH', 6],
  ['CONFIG_MODIFIED', 7], ['MCP_OWNERSHIP_COLLISION', 7], ['APPROVAL_REQUIRED', 7], ['APPROVAL_INVALID', 7], ['SAFETY_REFUSAL', 7],
  ['UPDATE_ROLLED_BACK', 8], ['ROLLBACK_UNAVAILABLE', 8]
]);

function assertNoSecret(value) {
  if (isSecret(value)) {
    const error = new Error('SECRET_SERIALIZATION_REFUSED');
    error.code = 'SECRET_SERIALIZATION_REFUSED';
    throw error;
  }
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) assertNoSecret(child);
  }
}

export class ClaudeyError extends Error {
  constructor(code, message, { hint, details = {}, cause } = {}) {
    assertNoSecret(details);
    super(message, { cause });
    this.name = 'ClaudeyError';
    this.code = code;
    this.hint = hint;
    this.details = details;
  }
}

export { ClaudeyError as ClaudexError };

export function exitCodeFor(error) {
  return exitCodes.get(error?.code) ?? 2;
}
