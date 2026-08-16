import { listAllGatewayModels, listProviderModels } from '../../providers/models.js';

export async function runModelsCommand(command, context) {
  if (!Array.isArray(command) || command[0] !== 'models' || command.length > 2) {
    const error = new Error('Invalid models command.');
    error.code = 'USAGE_ERROR';
    throw error;
  }
  const provider = command[1] ?? 'all';
  const result = provider === 'all' ? await listAllGatewayModels(context) : await listProviderModels(provider, context);
  if (typeof context?.attachUsage === 'function') return context.attachUsage(result);
  return result;
}
