import assert from 'node:assert/strict';
import test from 'node:test';

import { buildCursorEnvironment, isCursorEnvironment } from '../../../src/cursor/env.js';

const CANARY = 'TASK13_CURSOR_SECRET_CANARY';

test('Windows Cursor environment is a minimal allowlist and excludes every provider, gateway, cloud, Claude, and Cursor key', () => {
  const parent = {
    SystemRoot: 'C:\\Windows', WINDIR: 'C:\\Windows', ComSpec: 'C:\\Windows\\System32\\cmd.exe',
    PATHEXT: '.EXE;.CMD', PATH: 'C:\\Windows\\System32', TEMP: 'C:\\Temp', TMP: 'C:\\Temp',
    USERPROFILE: 'C:\\Users\\Casey', APPDATA: 'C:\\Users\\Casey\\AppData\\Roaming',
    LOCALAPPDATA: 'C:\\Users\\Casey\\AppData\\Local', LANG: 'en_US.UTF-8',
    ANTHROPIC_BASE_URL: CANARY, ANTHROPIC_AUTH_TOKEN: CANARY, ANTHROPIC_API_KEY: CANARY,
    OPENAI_API_KEY: CANARY, GOOGLE_API_KEY: CANARY, GOOGLE_APPLICATION_CREDENTIALS: CANARY,
    GITHUB_TOKEN: CANARY, GH_TOKEN: CANARY, AWS_ACCESS_KEY_ID: CANARY, AWS_SECRET_ACCESS_KEY: CANARY,
    AZURE_CLIENT_SECRET: CANARY, CURSOR_API_KEY: CANARY, CLAUDE_CODE_SESSION_ID: CANARY,
    CLIPROXYAPI_TOKEN: CANARY, CLI_PROXY_AUTH_DIR: CANARY, UNRELATED: CANARY
  };
  const before = structuredClone(parent);
  const env = buildCursorEnvironment(parent, { platform: 'win32' });
  assert.deepEqual(parent, before);
  assert.deepEqual(env, {
    SystemRoot: parent.SystemRoot, WINDIR: parent.WINDIR, ComSpec: parent.ComSpec, PATHEXT: parent.PATHEXT,
    PATH: parent.PATH, TEMP: parent.TEMP, TMP: parent.TMP, USERPROFILE: parent.USERPROFILE,
    APPDATA: parent.APPDATA, LOCALAPPDATA: parent.LOCALAPPDATA, LANG: parent.LANG
  });
  assert.equal(JSON.stringify(env).includes(CANARY), false);
  assert.equal(Object.isFrozen(env), true);
  assert.equal(isCursorEnvironment(env), true);
});

test('POSIX environment keeps only execution, terminal, locale, and browser-login store roots', () => {
  const env = buildCursorEnvironment({
    HOME: '/home/casey', PATH: '/usr/bin:/bin', TMPDIR: '/tmp/casey', USER: 'casey', LOGNAME: 'casey',
    SHELL: '/bin/bash', TERM: 'xterm-256color', COLORTERM: 'truecolor', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8',
    XDG_CONFIG_HOME: '/home/casey/.config', XDG_DATA_HOME: '/home/casey/.local/share',
    XDG_STATE_HOME: '/home/casey/.local/state', XDG_CACHE_HOME: '/home/casey/.cache',
    SSH_AUTH_SOCK: CANARY, CURSOR_API_KEY: CANARY
  }, { platform: 'linux' });
  assert.deepEqual(Object.keys(env), [
    'HOME', 'PATH', 'TMPDIR', 'USER', 'LOGNAME', 'SHELL', 'TERM', 'COLORTERM', 'LANG', 'LC_ALL',
    'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME', 'XDG_CACHE_HOME'
  ]);
  assert.equal(JSON.stringify(env).includes(CANARY), false);
});

test('omits absent allowlisted fields and rejects malformed values, unsupported platforms, and hostile accessors', () => {
  assert.deepEqual(buildCursorEnvironment({ HOME: '/home/casey' }, { platform: 'darwin' }), { HOME: '/home/casey' });
  for (const [parent, options] of [
    [{ HOME: 'bad\0value' }, { platform: 'linux' }],
    [{ HOME: 1 }, { platform: 'linux' }],
    [{ HOME: '/home' }, { platform: 'freebsd' }]
  ]) assert.throws(() => buildCursorEnvironment(parent, options), (error) => error.code === 'SAFETY_REFUSAL');
  const hostile = new Proxy({}, { ownKeys: () => { throw new Error('private env canary'); } });
  assert.throws(() => buildCursorEnvironment(hostile, { platform: 'linux' }),
    (error) => error.code === 'SAFETY_REFUSAL' && !error.message.includes('canary'));
  assert.equal(isCursorEnvironment({ HOME: '/home/casey' }), false);
});
