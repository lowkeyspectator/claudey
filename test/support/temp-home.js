import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

export async function createTempHome() {
  return fs.mkdtemp(path.join(os.tmpdir(), 'claudexctl-test-'));
}
