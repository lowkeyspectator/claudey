import { isGatewayProvider, parseVisibleModelId, visibleModelId } from './catalog.js';
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
    if (!model || typeof model.id !== 'string') continue;
    const visible = parseVisibleModelId(model.id);
    const provider = visible?.provider ?? model.owned_by;
    const rawId = visible?.id ?? model.id;
    if (!isGatewayProvider(provider)) continue;
    const channel = oauthAliasChannel(provider);
    const title = providerTitle(provider);
    if (!channel || !title) continue;
    const entry = Object.freeze({
      name: rawId,
      alias: visibleModelId(provider, rawId),
      displayName: `${rawId} - ${title}`,
      forceMapping: true
    });
    if (!result[channel]) result[channel] = [];
    if (result[channel].some((existing) => existing.alias === entry.alias)) continue;
    result[channel].push(entry);
  }
  for (const channel of Object.keys(result)) Object.freeze(result[channel]);
  return Object.freeze(result);
}
