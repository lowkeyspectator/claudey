import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const args = process.argv.slice(2);
if (args.length === 0) process.exit(0);
let stdin = '';
if (args[0] !== '--model' || args.includes('--print')) {
  for await (const chunk of process.stdin) stdin += chunk;
}
await fs.appendFile(fileURLToPath(new URL('./capture.jsonl', import.meta.url)), `${JSON.stringify({ args, env: process.env, stdin })}\n`);
const command = args.join(' ');const responses = {
  '--version': 'Claude Code 2.1.229\n',
  'model --help --json': '{"modelSelection":true}\n',
  'plugin --help --json': '{"plugins":true}\n',
  'mcp --help --json': '{"mcp":true}\n',
  'environment --json': '{"gatewayVariables":["ANTHROPIC_BASE_URL","ANTHROPIC_AUTH_TOKEN"]}\n'
};
if (Object.hasOwn(responses, command)) {
  process.stdout.write(responses[command]);
  process.exitCode = 0;
} else if (args[0] === '--model') {
  const exitArgument = args.find((argument) => /^--fixture-exit=(?:0|[1-9]\d{0,2})$/.test(argument));
  const requestedExit = exitArgument ? Number(exitArgument.slice('--fixture-exit='.length)) : 0;
  if (args.includes('--fixture-wait')) setInterval(() => {}, 1_000);
  else process.exitCode = requestedExit <= 255 ? requestedExit : 2;
} else process.exitCode = 2;
