import { parseManagementArgs } from './parse.js';
import { ClaudexError, exitCodeFor } from '../core/errors.js';
import { emitError, emitSuccess } from './output.js';

export function main(argv = process.argv.slice(2), environment = process.env) {
  return parseManagementArgs(argv, environment);
}

function errorEnvelope(error) {
  if (error instanceof ClaudexError) return error;
  return new ClaudexError(error?.code ?? 'USAGE_ERROR', error?.message ?? 'Unexpected command failure.', {
    hint: error?.hint,
    details: error?.details ?? {}
  });
}

export function run(argv = process.argv.slice(2), environment = process.env, io = process) {
  const json = argv.includes('--json');
  try {
    const result = main(argv, environment);
    emitSuccess(result, { json: result.options.json === true }, io);
    return 0;
  } catch (error) {
    const normalized = errorEnvelope(error);
    emitError(normalized, { json }, io);
    return exitCodeFor(normalized);
  }
}
