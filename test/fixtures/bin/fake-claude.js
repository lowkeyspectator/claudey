import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const args = process.argv.slice(2);
if (args.length === 0) process.exit(0);
let stdin = '';
for await (const chunk of process.stdin) stdin += chunk;
await fs.appendFile(fileURLToPath(new URL('./capture.jsonl', import.meta.url)), `${JSON.stringify({ args, env: process.env, stdin })}\n`);
const command = args.join(' ');const responses = {
  '--version': 'Claude Code 2.1.229\n',
  'model --help --json': '{"modelSelection":true}\n',
  'plugin --help --json': '{"plugins":true}\n',
  'mcp --help --json': '{"mcp":true}\n',
  'environment --json': '{"gatewayVariables":["ANTHROPIC_BASE_URL","ANTHROPIC_AUTH_TOKEN"]}\n'
};
process.stdout.write(responses[command] ?? '');
process.exitCode = Object.hasOwn(responses, command) ? 0 : 2;
