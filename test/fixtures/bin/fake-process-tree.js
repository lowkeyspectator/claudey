#!/usr/bin/env node
import { spawn } from 'node:child_process';

if (process.argv[2] === 'ignore-tree') {
  const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });
  process.stdout.write(`${child.pid}\n`);
  process.on('SIGTERM', () => {});
  setInterval(() => {}, 1000);
} else if (process.argv[2] === 'hang') {
  process.stdout.write(`${process.pid}\n`);
  process.on('SIGTERM', () => {});
  setInterval(() => {}, 1000);
} else if (process.argv[2] === 'term-exits') {
  process.stdout.write(`${process.pid}\n`);
  setInterval(() => {}, 1000);
}
