#!/usr/bin/env node
const command = process.argv.slice(2).join(' ');
const responses = {
  '--version': 'Cursor Agent 1.0.0\n',
  'status --json': '{"authenticated":true}\n',
  'models --json': '{"models":[{"id":"cursor-model"}]}\n',
  'print --json --mode ask --sandbox read-only': '{"type":"result"}\n'
};
process.stdout.write(responses[command] ?? '');
process.exitCode = command === '' || Object.hasOwn(responses, command) ? 0 : 2;
