import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import { buildManagerInvocation, runPluginForwarder } from '../../plugins/cursor-agent/server/index.mjs';

const ROOT = path.resolve(import.meta.dirname, '..', '..');
const UUID = '11111111-1111-4111-8111-111111111111';

test('marketplace, plugin, and MCP manifests are exact local static definitions with no installer or secret interpolation', async () => {
  const marketplace = JSON.parse(await fs.readFile(path.join(ROOT, '.claude-plugin', 'marketplace.json'), 'utf8'));
  const plugin = JSON.parse(await fs.readFile(path.join(ROOT, 'plugins', 'cursor-agent', '.claude-plugin', 'plugin.json'), 'utf8'));
  const mcp = JSON.parse(await fs.readFile(path.join(ROOT, 'plugins', 'cursor-agent', '.mcp.json'), 'utf8'));
  assert.deepEqual(marketplace, {
    name: 'claudey', owner: { name: 'Claudey' }, description: 'Constrained local Claudey integrations.',
    plugins: [{ name: 'cursor-agent', source: './plugins/cursor-agent', version: '1.0.0',
      description: 'Delegates bounded model, ask, plan, and explicitly approved worktree operations to Cursor Agent.' }]
  });
  assert.deepEqual(plugin, {
    name: 'cursor-agent', version: '1.0.0', description: 'Constrained Cursor Agent tools managed by Claudey.',
    author: { name: 'Claudey' }
  });
  assert.deepEqual(mcp, { mcpServers: { 'claudey-cursor': {
    type: 'stdio', command: 'node', args: ['${CLAUDE_PLUGIN_ROOT}/server/index.mjs'],
    env: { CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: '1' }
  } } });
  assert.equal(JSON.stringify({ marketplace, plugin, mcp }).match(/token|secret|oauth|install\?/giu), null);
});

test('wrapper passes only a no-follow link-free Git source candidate to the fixed absolute manager invocation', async () => {
  const calls = [];
  const result = await runPluginForwarder({
    cwd: '/home/casey/project/subdir', pluginRoot: '/home/casey/.claude/plugins/cache/claudex/cursor-agent/1',
    ambientEnvironment: { PATH: '/usr/bin', HOME: '/home/casey', LANG: 'en_US.UTF-8', ANTHROPIC_API_KEY: 'private-canary' },
    inspectSourceRoot: async (candidate) => {
      calls.push(['inspect-source', candidate]);
      return { safe: true, canonicalPath: '/home/casey/project', gitRoot: '/home/casey/project',
        isLink: false, isJunction: false, isReparsePoint: false };
    },
    discoverManager: async () => ({
      nodePath: '/usr/bin/node', managerPath: '/home/casey/.local/share/claudexctl/manager/index.mjs',
      managerRoot: '/home/casey/.local/share/claudexctl', installationId: UUID
    }),
    revalidateManager: async (identity) => { calls.push(['revalidate-manager', identity]); return true; },
    spawnManager: async (invocation) => { calls.push(['spawn', invocation]); return { code: 0, signal: null }; }
  });
  assert.deepEqual(result, { code: 0, signal: null });
  assert.deepEqual(calls.map(([name]) => name), ['inspect-source', 'revalidate-manager', 'spawn']);
  assert.deepEqual(calls[1][1], {
    manager: {
      nodePath: '/usr/bin/node', managerPath: '/home/casey/.local/share/claudexctl/manager/index.mjs',
      managerRoot: '/home/casey/.local/share/claudexctl', installationId: UUID
    },
    pluginRoot: '/home/casey/.claude/plugins/cache/claudex/cursor-agent/1'
  });
  assert.deepEqual(calls[2][1], {
    executable: '/usr/bin/node',
    args: ['/home/casey/.local/share/claudexctl/manager/index.mjs', 'cursor', 'mcp-serve',
      '--source-root', '/home/casey/project', '--installation-id', UUID,
      '--manager-root', '/home/casey/.local/share/claudexctl'],
    cwd: '/home/casey/.local/share/claudexctl',
    env: { PATH: '/usr/bin', HOME: '/home/casey', LANG: 'en_US.UTF-8', CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: '1' },
    stdio: 'inherit', shell: false
  });
  assert.equal(JSON.stringify(calls[2][1]).includes('private-canary'), false);
});

test('missing, non-Git, unregistered, linked, or reparse startup CWD omits source root but still permits models', async () => {
  for (const state of [
    null,
    { safe: false },
    { safe: true, canonicalPath: '/tmp/not-git', gitRoot: null, isLink: false, isJunction: false, isReparsePoint: false },
    { safe: true, canonicalPath: '/tmp/repo', gitRoot: '/tmp/repo', isLink: true, isJunction: false, isReparsePoint: false },
    { safe: true, canonicalPath: '/tmp/repo', gitRoot: '/tmp/repo', isLink: false, isJunction: false, isReparsePoint: true }
  ]) {
    let invocation;
    await runPluginForwarder({
      cwd: '/tmp/repo', pluginRoot: '/home/casey/plugin', ambientEnvironment: { PATH: '/usr/bin' },
      inspectSourceRoot: async () => state,
      discoverManager: async () => ({ nodePath: '/usr/bin/node', managerPath: '/home/casey/manager/index.mjs',
        managerRoot: '/home/casey/manager', installationId: UUID }),
      revalidateManager: async () => true,
      spawnManager: async (value) => { invocation = value; return { code: 0, signal: null }; }
    });
    assert.equal(invocation.args.includes('--source-root'), false);
    assert.equal(invocation.args.includes('cursor'), true);
    assert.equal(invocation.args.includes('mcp-serve'), true);
  }
});

test('fixed invocation rejects relative or foreign paths, hostile identities, and final manager swaps before child creation', async () => {
  assert.throws(() => buildManagerInvocation({
    nodePath: 'node', managerPath: '/home/casey/manager/index.mjs', managerRoot: '/home/casey/manager',
    installationId: UUID, pluginRoot: '/home/casey/plugin', ambientEnvironment: {}
  }), (error) => error.code === 'SAFETY_REFUSAL');
  let spawned = false;
  await assert.rejects(runPluginForwarder({
    cwd: '/tmp', pluginRoot: '/home/casey/plugin', ambientEnvironment: { PATH: '/usr/bin' },
    inspectSourceRoot: async () => null,
    discoverManager: async () => ({ nodePath: '/usr/bin/node', managerPath: '/home/casey/manager/index.mjs',
      managerRoot: '/home/casey/manager', installationId: UUID }),
    revalidateManager: async () => false,
    spawnManager: async () => { spawned = true; }
  }), (error) => error.code === 'SAFETY_REFUSAL');
  assert.equal(spawned, false);
});
