#!/usr/bin/env node
const command = process.argv.slice(2).join(' ');
const responses = {
  '--version': 'CLIProxyAPI 7.2.130\n',
  'login codex --json': '{"modes":["codex"]}\n',
  'login antigravity --json': '{"modes":["antigravity"]}\n',
  'config check --json': '{"configPath":"/private/manager/config.yaml","requiredKeys":["host","port","api-keys"]}\n',
  'models --json': '{"models":[{"id":"gpt","provider":"codex"},{"id":"gemini","provider":"antigravity"}]}\n'
};
process.stdout.write(responses[command] ?? '');
process.exitCode = command === '' || Object.hasOwn(responses, command) ? 0 : 2;
