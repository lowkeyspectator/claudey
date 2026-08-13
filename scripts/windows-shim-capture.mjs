import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';

const [launcher, manager] = process.argv.slice(2);
if (!launcher || !manager || !path.win32.isAbsolute(launcher) || !path.win32.isAbsolute(manager)) process.exit(2);
const values = ['', 'two words', '雪', 'a"b', 'ends slash \\', '--leading', ';&|`$()%VAR%', 'line\r\nbreak'];
const result = spawnSync(launcher, values, { encoding: 'utf8', windowsHide: true, shell: false });
assert.equal(result.status, 23, result.stderr);
const lines = result.stdout.trimEnd().split(/\r?\n/u);
assert.equal(Number(lines[0]), values.length + 2);
const decoded = lines.slice(2).map((line) => {
  const separator = line.indexOf(':');
  const length = Number(line.slice(0, separator));
  const hex = line.slice(separator + 1);
  const units = [];
  for (let index = 0; index < hex.length; index += 4) units.push(Number.parseInt(hex.slice(index, index + 4), 16));
  assert.equal(units.length, length);
  return String.fromCharCode(...units);
});
assert.deepEqual(decoded, [manager, ...values]);
