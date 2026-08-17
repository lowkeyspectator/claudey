import assert from 'node:assert/strict';
import test from 'node:test';

import { visibleModelId } from '../../../src/providers/catalog.js';
import { buildManagedOAuthAliases, oauthAliasChannel } from '../../../src/providers/oauth-aliases.js';

test('builds provider-scoped OAuth aliases from the live mixed catalog', () => {
  assert.equal(oauthAliasChannel('codex'), 'codex');
  assert.equal(oauthAliasChannel('antigravity'), 'antigravity');
  assert.equal(oauthAliasChannel('grok'), 'xai');

  const aliases = buildManagedOAuthAliases([
    { id: 'gpt-5.6-sol', owned_by: 'codex' },
    { id: 'gpt-5.6-sol', owned_by: 'antigravity' },
    { id: 'grok-4.5', owned_by: 'grok' }
  ]);

  assert.deepEqual(aliases.codex, [{
    name: 'gpt-5.6-sol',
    alias: visibleModelId('codex', 'gpt-5.6-sol'),
    displayName: 'gpt-5.6-sol — Codex',
    forceMapping: true
  }]);
  assert.equal(aliases.antigravity[0].alias, visibleModelId('antigravity', 'gpt-5.6-sol'));
  assert.equal(aliases.xai[0].alias, visibleModelId('grok', 'grok-4.5'));
  assert.equal(aliases.xai[0].displayName, 'grok-4.5 — Grok');
});
