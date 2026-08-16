import { ClaudeyError } from '../core/errors.js';
import { loadInstallation, runProductionSetup } from './runtime.js';

const AUTH_HINT = 'claudey auth grok\nclaudey auth antigravity\nclaudey auth codex';

function writeLine(text) {
  try { process.stderr.write(`${text}\n`); } catch { /* best-effort beginner guidance */ }
}

export async function ensureLocalInstall(environment = process.env, context = {}) {
  const load = context.loadInstallation ?? loadInstallation;
  try { return await load(environment); } catch (error) {
    if (error?.code !== 'NOT_INSTALLED') throw error;
  }
  const setup = context.runSetup ?? runProductionSetup;
  const announce = context.announce ?? writeLine;
  announce('First run: installing the local gateway. This may take a minute.');
  await setup({ yes: true }, environment);
  return load(environment);
}

export function beginnerLaunchError(error) {
  if (error?.code === 'AUTH_REQUIRED') {
    return new ClaudeyError('AUTH_REQUIRED', 'Sign in to at least one provider, then run claudey again.', {
      hint: AUTH_HINT
    });
  }
  if (error?.code === 'PREREQUISITE_MISSING') {
    return new ClaudeyError('PREREQUISITE_MISSING', 'Install Claude Code, then run claudey again.', {
      hint: 'https://claude.com/download'
    });
  }
  return error;
}

export function beginnerNextSteps() {
  return [
    'Sign in to the providers you use:',
    '  claudey auth grok',
    '  claudey auth antigravity',
    '  claudey auth codex',
    'Then start Claude Code with every signed-in model:',
    '  claudey',
    'Skip permission prompts with:',
    '  claudey --yolo'
  ].join('\n');
}
