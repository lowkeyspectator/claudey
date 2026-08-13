#!/usr/bin/env node
const command = process.argv.slice(2).join(' ');
const responses = {
  '--version': 'Claude Code 2.1.229\n',
  'model --help --json': '{"modelSelection":true}\n',
  'plugin --help --json': '{"plugins":true}\n',
  'mcp --help --json': '{"mcp":true}\n',
  'environment --json': '{"gatewayVariables":["ANTHROPIC_BASE_URL","ANTHROPIC_AUTH_TOKEN"]}\n'
};
process.stdout.write(responses[command] ?? '');
process.exitCode = command === '' || Object.hasOwn(responses, command) ? 0 : 2;
