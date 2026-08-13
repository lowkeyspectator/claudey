import { runGatewayInstallation } from '../../core/activation.js';

export async function runInstallCommand(options = {}, context = {}) {
  return runGatewayInstallation({ kind: 'install', options }, context);
}
