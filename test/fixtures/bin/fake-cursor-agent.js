#!/usr/bin/env node
import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const args = process.argv.slice(2);
if (args.length === 0) process.exit(0);
let stdin = '';
for await (const chunk of process.stdin) stdin += chunk;
const capturePath = fileURLToPath(new URL('./capture.jsonl', import.meta.url));
const capture = { args, env: Object.fromEntries(Object.entries(process.env).sort(([left], [right]) => left.localeCompare(right))), stdin };
await fs.appendFile(capturePath, `${JSON.stringify(capture)}\n`);
const command = args.join(' ');
const responses = {
  '--version': 'Cursor Agent 1.0.0\n',
  'status --json': '{"authenticated":true}\n',
  'models --json': '{"models":[{"id":"cursor-model"}]}\n',
  '--list-models --json': '{"models":[{"id":"cursor-model"}]}\n',
  'probe json --json': '{"type":"probe","capability":"json","framing":"json-lines"}\n',
  'probe mode ask --json': '{"type":"probe","capability":"ask","supported":true}\n',
  'probe mode plan --json': '{"type":"probe","capability":"plan","supported":true}\n',
  'probe sandbox read-only --json': '{"type":"probe","capability":"sandbox","supported":true}\n'
};
if (command === 'probe stdin --json') process.stdout.write(`${JSON.stringify({ type: 'probe', capability: 'stdin', echo: stdin })}\n`);
else { process.stdout.write(responses[command] ?? ''); process.exitCode = Object.hasOwn(responses, command) ? 0 : 2; }
