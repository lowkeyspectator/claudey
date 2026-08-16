import { ClaudeyError } from '../../core/errors.js';
import { beginnerLaunchError, ensureLocalInstall } from '../first-run.js';
import { parseLauncherArgs } from '../parse.js';
import { resolveClaudeExecutable } from '../runtime.js';
import { launchClaudeProvider } from '../../providers/claude.js';

export async function runClaudey(argv, environment, context = {}) {
  const parsed = parseLauncherArgs(argv, environment);
  const launch = context.launch ?? launchClaudeProvider;
  if (typeof launch !== 'function') throw new ClaudeyError('SAFETY_REFUSAL', 'Launcher orchestration is unavailable.');
  if (context.skipOnboard !== true && typeof context.launch !== 'function') {
    try { await ensureLocalInstall(environment, context); }
    catch (error) { throw beginnerLaunchError(error); }
  }

  let claude = context.claude;
  if (!claude && typeof context.launch !== 'function') {
    try {
      claude = await resolveClaudeExecutable(environment, context);
    } catch (error) {
      throw beginnerLaunchError(error);
    }
  }

  const selectModel = context.selectModel ?? (async ({ models }) => models[0]?.id);

  try {
    return await launch({
      isTTY: Boolean(process.stdin?.isTTY && process.stdout?.isTTY),
      cwd: process.cwd(),
      baseEnvironment: environment,
      claude,
      selectModel,
      ...context,
      provider: 'codex',
      parsed: { ...parsed, all: true }
    });
  } catch (error) {
    throw beginnerLaunchError(error);
  }
}
