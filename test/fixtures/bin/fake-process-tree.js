#!/usr/bin/env node
import { spawn } from 'node:child_process';

if (process.argv[2] === 'ignore-tree') {
  const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });
  process.stdout.write(`${child.pid}\n`);
  process.on('SIGTERM', () => {});
  setInterval(() => {}, 1000);
}
