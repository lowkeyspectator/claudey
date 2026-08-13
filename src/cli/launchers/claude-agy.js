import { ClaudexError } from '../../core/errors.js';
import { parseLauncherArgs } from '../parse.js';
import { launchClaudeProvider } from '../../providers/claude.js';

export async function runClaudeAgy(argv, environment, context = {}) {
  const parsed = parseLauncherArgs(argv, environment);
  const launch = context.launch ?? launchClaudeProvider;
  if (typeof launch !== 'function') throw new ClaudexError('SAFETY_REFUSAL', 'Launcher orchestration is unavailable.');
  return launch({ ...context, provider: 'antigravity', parsed });
}
