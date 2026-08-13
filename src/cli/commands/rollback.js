import { runGatewayRollback } from '../../core/activation.js';

export async function runRollbackCommand(options = {}, context = {}) {
  return runGatewayRollback(options, context);
}
