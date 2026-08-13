import { authenticateProvider } from '../../providers/auth.js';

export async function runAuthCommand(command, options, context) {
  const provider = Array.isArray(command) && command.length === 2 && command[0] === 'auth' ? command[1] : undefined;
  const mode = options?.deviceCode === true ? 'device-code' : options?.noBrowser === true ? 'no-browser' : 'browser';
  return authenticateProvider({
    isTTY: Boolean(process.stdin?.isTTY && process.stdout?.isTTY),
    ...context,
    provider,
    mode,
    callbackPort: options?.callbackPort,
    nonInteractive: options?.nonInteractive === true,
    ci: context?.ci === true
  });
}
