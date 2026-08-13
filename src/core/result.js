export const SCHEMA_VERSION = 1;

export function ok(result) {
  return { ok: true, schemaVersion: SCHEMA_VERSION, result };
}

export function failEnvelope(error) {
  return {
    ok: false,
    code: error.code,
    message: error.message,
    ...(error.hint ? { hint: error.hint } : {}),
    details: error.details ?? {}
  };
}
