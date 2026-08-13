import { runGatewayInstallation } from '../../core/activation.js';

export async function runSetupCommand(options = {}, context = {}) {
  return runGatewayInstallation({ kind: 'setup', options, setup: true }, context);
}
