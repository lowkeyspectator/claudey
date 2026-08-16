import { ClaudeyError } from '../../core/errors.js';
import { parseLauncherArgs } from '../parse.js';
import { resolveClaudeExecutable } from '../runtime.js';
import { launchClaudeProvider } from '../../providers/claude.js';

export async function runClaudeAgy(argv, environment, context = {}) {
  const parsed = parseLauncherArgs(argv, environment);
  const launch = context.launch ?? launchClaudeProvider;
  if (typeof launch !== 'function') throw new ClaudeyError('SAFETY_REFUSAL', 'Launcher orchestration is unavailable.');

  let claude = context.claude;
  if (!claude && typeof context.launch !== 'function') {
    claude = await resolveClaudeExecutable(environment, context);
  }

  const selectModel = context.selectModel ?? (async ({ models }) => models[0]?.id);

  return launch({
    isTTY: Boolean(process.stdin?.isTTY && process.stdout?.isTTY),
    cwd: process.cwd(),
    baseEnvironment: environment,
    claude,
    selectModel,
    ...context,
    provider: 'antigravity',
    parsed
  });
}
