import { ClaudexError } from '../../core/errors.js';
import { runGatewayPortChange } from '../../core/activation.js';

export async function runConfigCommand(command, options = {}, context = {}) {
  if (!Array.isArray(command) || command.length !== 3
    || command[0] !== 'config' || command[1] !== 'set' || command[2] !== 'port') {
    throw new ClaudexError('USAGE_ERROR', 'Expected config set port PORT.');
  }
  return runGatewayPortChange(options, context);
}
