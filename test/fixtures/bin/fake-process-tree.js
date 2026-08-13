#!/usr/bin/env node
import { spawn } from 'node:child_process';
import fs from 'node:fs';

if (process.argv[2] === 'ignore-tree') {
  const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });
  process.stdout.write(`${child.pid}\n`);
  process.on('SIGTERM', () => {});
  setInterval(() => {}, 1000);
} else if (process.argv[2] === 'hang') {
  process.stdout.write(`${process.pid}\n`);
  process.on('SIGTERM', () => {});
  setInterval(() => {}, 1000);
} else if (process.argv[2] === 'close-stdin') {
  process.stdin.destroy();
  process.stdout.write(`${process.pid}\n`);
  setInterval(() => {}, 1000);
} else if (process.argv[2] === 'term-exits') {
  const child = spawn(process.execPath, ['-e', 'process.on("SIGTERM",()=>{}); setInterval(() => {}, 1000)'], { stdio: 'ignore', detached: true });
  child.unref();
  fs.writeFileSync(process.argv[3], String(child.pid));
  process.stdout.write(`${process.pid}\n`);
  setInterval(() => {}, 1000);
}
