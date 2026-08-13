import { checkGatewayUpdate, runGatewayInstallation } from '../../core/activation.js';

export async function runUpdateCommand(options = {}, context = {}) {
  let check;
  try { check = options?.check; }
  catch { return checkGatewayUpdate(options, context); }
  if (check === true) return checkGatewayUpdate(options, context);
  return runGatewayInstallation({ kind: 'update', options, update: true }, context);
}
