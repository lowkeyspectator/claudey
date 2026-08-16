import { authenticateProvider } from '../../providers/auth.js';
import { prepareAuthContext } from '../runtime.js';

function hasProbedCapabilities(context) {
  return Boolean(context && typeof context.capabilities === 'object' && context.capabilities
    && !Array.isArray(context.capabilities) && typeof context.capabilities.providers === 'object');
}

async function authenticateOne(provider, options, resolved, context) {
  return authenticateProvider({
    isTTY: Boolean(process.stdin?.isTTY && process.stdout?.isTTY),
    ...resolved,
    provider,
    mode: options?.deviceCode === true ? 'device-code' : options?.noBrowser === true ? 'no-browser' : 'browser',
    callbackPort: options?.callbackPort,
    nonInteractive: options?.nonInteractive === true,
    ci: context?.ci === true
  });
}

export async function runAuthCommand(command, options, context = {}) {
  const provider = Array.isArray(command) && command.length === 2 && command[0] === 'auth' ? command[1] : undefined;
  const resolved = hasProbedCapabilities(context) ? context : await prepareAuthContext();
  if (provider === 'all') {
    const providers = [];
    for (const name of ['grok', 'antigravity', 'codex']) {
      providers.push(await authenticateOne(name, options, resolved, context));
    }
    return Object.freeze({ authenticated: true, provider: 'all', providers: Object.freeze(providers) });
  }
  return authenticateOne(provider, options, resolved, context);
}
