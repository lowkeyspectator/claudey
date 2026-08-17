import { isGatewayProvider, visibleModelId } from './catalog.js';
import { providerTitle } from './usage.js';

export function oauthAliasChannel(provider) {
  if (provider === 'codex') return 'codex';
  if (provider === 'antigravity') return 'antigravity';
  if (provider === 'grok') return 'xai';
  return null;
}

export function buildManagedOAuthAliases(models) {
  const result = Object.create(null);
  if (!Array.isArray(models)) return result;
  for (const model of models) {
    if (!model || typeof model.id !== 'string' || !isGatewayProvider(model.owned_by)) continue;
    const channel = oauthAliasChannel(model.owned_by);
    const title = providerTitle(model.owned_by);
    if (!channel || !title) continue;
    const entry = Object.freeze({
      name: model.id,
      alias: visibleModelId(model.owned_by, model.id),
      displayName: `${model.id} — ${title}`,
      forceMapping: true
    });
    if (!result[channel]) result[channel] = [];
    if (result[channel].some((existing) => existing.alias === entry.alias)) continue;
    result[channel].push(entry);
  }
  for (const channel of Object.keys(result)) Object.freeze(result[channel]);
  return Object.freeze(result);
}
