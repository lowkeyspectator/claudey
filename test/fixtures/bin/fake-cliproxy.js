import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const args = process.argv.slice(2);
if (args.length === 0) process.exit(0);
let stdin = '';
for await (const chunk of process.stdin) stdin += chunk;
await fs.appendFile(fileURLToPath(new URL('./capture.jsonl', import.meta.url)), `${JSON.stringify({ args, env: process.env, stdin })}\n`);
const command = args.join(' ');const responses = {
  '--version': 'CLIProxyAPI 7.2.130\n',
  '--help --json': '{"commands":["login","config"],"loginModes":["codex","antigravity"]}\n',
  'config probe --json': '{"explicitConfigSelection":true,"requiredKeys":["host","port","tls","remote-management","auth-dir","api-keys","debug","commercial-mode","logging-to-file","usage-statistics-enabled","pprof","plugins","ws-auth"],"commercialMode":{"requiredValue":true,"requestLoggingDisabled":true}}\n'
};
process.stdout.write(responses[command] ?? '');
process.exitCode = Object.hasOwn(responses, command) ? 0 : 2;
