import { ClaudexError } from '../../core/errors.js';
import { createDefaultExecutableAdapter, resolveVerifiedExecutable } from '../../core/executable.js';
import { parseLauncherArgs } from '../parse.js';
import { defaultClaudeCandidates } from './claudex.js';
import { launchClaudeProvider } from '../../providers/claude.js';

export async function runClaudeAgy(argv, environment, context = {}) {
  const parsed = parseLauncherArgs(argv, environment);
  const launch = context.launch ?? launchClaudeProvider;
  if (typeof launch !== 'function') throw new ClaudexError('SAFETY_REFUSAL', 'Launcher orchestration is unavailable.');

  let claude = context.claude;
  if (!claude && typeof context.launch !== 'function') {
    const candidates = defaultClaudeCandidates(process.platform, environment);
    const adapter = context.adapter ?? createDefaultExecutableAdapter();
    for (const candidate of candidates) {
      try {
        claude = await resolveVerifiedExecutable({ command: 'claude', platform: process.platform, candidates: [candidate], adapter });
        if (claude) break;
      } catch {
        continue;
      }
    }
    if (!claude) {
      throw new ClaudexError('PREREQUISITE_MISSING', 'A verified Claude Code executable is required.');
    }
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
