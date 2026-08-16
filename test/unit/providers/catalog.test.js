import assert from 'node:assert/strict';
import test from 'node:test';

import {
  ANTHROPIC_CLOAK_PREFIX,
  GATEWAY_PROVIDERS,
  VISIBLE_MODEL_PREFIX,
  cloakModelId,
  isAnthropicNativeId,
  isGatewayProvider,
  isSafeOwnedBy,
  parseVisibleModelId,
  providerOwns,
  sameModelId,
  sourceModelId,
  uncloakModelId,
  visibleModelId
} from '../../../src/providers/catalog.js';

test('gateway providers are the live Claude Code harness backends', () => {
  assert.deepEqual(GATEWAY_PROVIDERS, ['codex', 'antigravity', 'grok']);
  assert.equal(isGatewayProvider('grok'), true);
  assert.equal(isGatewayProvider('cursor'), false);
});

test('maps CLIProxyAPI ownership metadata onto launcher providers without name heuristics', () => {
  assert.equal(providerOwns('codex', 'codex'), true);
  assert.equal(providerOwns('codex', 'openai'), true);
  assert.equal(providerOwns('codex', 'xai'), false);
  assert.equal(providerOwns('antigravity', 'antigravity'), true);
  assert.equal(providerOwns('antigravity', 'google'), true);
  assert.equal(providerOwns('grok', 'xai'), true);
  assert.equal(providerOwns('grok', 'grok'), true);
  assert.equal(providerOwns('grok', 'openai'), false);
  assert.equal(isSafeOwnedBy('xai'), true);
  assert.equal(isSafeOwnedBy(''), false);
});

test('cloaks non-Claude IDs the way CLIProxyAPI presents them to Claude Code', () => {
  assert.equal(cloakModelId('grok-4.5'), `${ANTHROPIC_CLOAK_PREFIX}5.4-korg`);
  assert.equal(cloakModelId('gpt-5.6-sol'), `${ANTHROPIC_CLOAK_PREFIX}los-6.5-tpg`);
  assert.equal(uncloakModelId(`${ANTHROPIC_CLOAK_PREFIX}5.4-korg`), 'grok-4.5');
  assert.equal(cloakModelId('claude-sonnet-4-6'), 'claude-sonnet-4-6');
  assert.equal(isAnthropicNativeId('claude-sonnet-4-6'), true);
  assert.equal(isAnthropicNativeId('gpt-5.6-sol'), false);
  assert.equal(sameModelId('grok-4.5', `${ANTHROPIC_CLOAK_PREFIX}5.4-korg`), true);
  assert.equal(sameModelId('grok-4.5', cloakModelId('grok-4.5')), true);
  assert.equal(sameModelId('grok-4.5', 'gpt-5.6-sol'), false);
  assert.equal(visibleModelId('grok', 'grok-4.5'), `${VISIBLE_MODEL_PREFIX}grok-grok-4.5`);
  assert.equal(parseVisibleModelId(`${VISIBLE_MODEL_PREFIX}grok-grok-4.5`).id, 'grok-4.5');
  assert.equal(sourceModelId(`${VISIBLE_MODEL_PREFIX}codex-gpt-5.6-sol`), 'gpt-5.6-sol');
  assert.equal(sameModelId(`${VISIBLE_MODEL_PREFIX}grok-grok-4.5`, 'grok-4.5'), true);
  assert.equal(sameModelId(`${VISIBLE_MODEL_PREFIX}grok-grok-4.5`, `${ANTHROPIC_CLOAK_PREFIX}5.4-korg`), true);
  assert.match(visibleModelId('grok', 'grok-4.5'), /anthropic/i);
  assert.equal(/fable/i.test(visibleModelId('grok', 'grok-4.5')), false);
});
