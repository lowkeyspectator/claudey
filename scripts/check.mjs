import fs from 'node:fs/promises';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const root = path.resolve(import.meta.dirname, '..');
const forbiddenNames = new Set(['claude', 'claude.exe', 'claude.cmd', 'claude.bat']);

async function files(directory) {
  const entries = await fs.readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(entries.filter((entry) => entry.isDirectory() && !['node_modules', '.git', '.superpowers'].includes(entry.name)).map((entry) => files(path.join(directory, entry.name))));
  return [...entries.filter((entry) => entry.isFile()).map((entry) => path.join(directory, entry.name)), ...nested.flat()];
}

const allFiles = await files(root);
for (const file of allFiles.filter((item) => item.endsWith('.js') || item.endsWith('.mjs'))) {
  const check = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
  if (check.status !== 0) throw new Error(`Syntax check failed: ${path.relative(root, file)}\n${check.stderr}`);
}
for (const file of allFiles.filter((item) => item.startsWith(path.join(root, 'src') + path.sep) && item.endsWith('.js'))) {
  await import(`${new URL(`file:///${file.replaceAll('\\', '/')}`).href}?check=${Date.now()}`);
}
for (const file of allFiles.filter((item) => item.endsWith('.json'))) JSON.parse(await fs.readFile(file, 'utf8'));
for (const file of allFiles.filter((item) => path.dirname(item) === path.join(root, 'bin'))) {
  if (forbiddenNames.has(path.basename(file).toLowerCase())) throw new Error(`Forbidden launcher name: ${path.basename(file)}`);
  const contents = await fs.readFile(file, 'utf8');
  if (!contents.startsWith('#!')) throw new Error(`Launcher lacks an executable header: ${path.basename(file)}`);
}
const packageJson = JSON.parse(await fs.readFile(path.join(root, 'package.json'), 'utf8'));
if (packageJson.dependencies || packageJson.optionalDependencies || packageJson.peerDependencies) throw new Error('Runtime dependencies are forbidden.');
const canary = process.env.CLAUDEY_SECRET_CANARY;
if (canary) {
  for (const file of allFiles) {
    if ((await fs.readFile(file)).includes(Buffer.from(canary))) throw new Error(`Secret canary found in ${path.relative(root, file)}.`);
  }
}
console.log('check: ok');
