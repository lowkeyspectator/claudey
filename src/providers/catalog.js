import { ClaudeyError } from '../core/errors.js';

export const GATEWAY_PROVIDERS = Object.freeze(['codex', 'antigravity', 'grok']);

export const ANTHROPIC_CLOAK_PREFIX = 'claude-fable-5-dd-';

const OWNERSHIP = Object.freeze({
  codex: Object.freeze(['codex', 'openai']),
  antigravity: Object.freeze(['antigravity', 'google']),
  grok: Object.freeze(['grok', 'xai'])
});

const OWNED_BY_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;

export function isGatewayProvider(provider) {
  return GATEWAY_PROVIDERS.includes(provider);
}

export function ownedByAliases(provider) {
  return OWNERSHIP[provider] ?? Object.freeze([]);
}

export function providerOwns(provider, ownedBy) {
  return ownedByAliases(provider).includes(ownedBy);
}

export function isSafeOwnedBy(value) {
  return typeof value === 'string' && OWNED_BY_PATTERN.test(value);
}

export function isAnthropicNativeId(value) {
  return typeof value === 'string' && /claude|anthropic/i.test(value);
}

export function cloakModelId(value) {
  if (typeof value !== 'string' || value.length === 0) return value;
  if (value.startsWith(ANTHROPIC_CLOAK_PREFIX) || isAnthropicNativeId(value)) return value;
  return `${ANTHROPIC_CLOAK_PREFIX}${[...value].reverse().join('')}`;
}

export function uncloakModelId(value) {
  if (typeof value !== 'string' || !value.startsWith(ANTHROPIC_CLOAK_PREFIX)) return value;
  return [...value.slice(ANTHROPIC_CLOAK_PREFIX.length)].reverse().join('');
}

export const VISIBLE_MODEL_PREFIX = 'anthropic-cdx-';

export function visibleModelId(provider, rawId) {
  if (!isGatewayProvider(provider) || typeof rawId !== 'string' || rawId.length === 0) return rawId;
  if (rawId.startsWith(VISIBLE_MODEL_PREFIX)) return rawId;
  return `${VISIBLE_MODEL_PREFIX}${provider}-${uncloakModelId(rawId)}`;
}

export function parseVisibleModelId(value) {
  if (typeof value !== 'string' || !value.startsWith(VISIBLE_MODEL_PREFIX)) return null;
  const rest = value.slice(VISIBLE_MODEL_PREFIX.length);
  const provider = [...GATEWAY_PROVIDERS].sort((left, right) => right.length - left.length)
    .find((name) => rest.startsWith(`${name}-`));
  if (!provider) return null;
  const id = rest.slice(provider.length + 1);
  return id.length > 0 ? Object.freeze({ provider, id }) : null;
}

export function sourceModelId(value) {
  if (typeof value !== 'string') return value;
  return parseVisibleModelId(value)?.id ?? uncloakModelId(value);
}

export function sameModelId(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  if (left === right) return true;
  const sourceLeft = sourceModelId(left);
  const sourceRight = sourceModelId(right);
  return sourceLeft === sourceRight || cloakModelId(sourceLeft) === cloakModelId(sourceRight);
}

export function resolveMixedCatalogModel(catalog, requested) {
  if (!Array.isArray(catalog) || typeof requested !== 'string' || requested.length === 0) {
    throw new ClaudeyError('MODEL_NOT_FOUND', `"${requested}" is not available.`, {
      details: { model: requested }
    });
  }

  const parsed = parseVisibleModelId(requested);
  if (parsed) {
    const match = catalog.find((model) => model?.owned_by === parsed.provider && sameModelId(model.id, parsed.id));
    if (!match) {
      throw new ClaudeyError('MODEL_NOT_FOUND', `"${requested}" is not available.`, {
        details: { model: requested, provider: parsed.provider }
      });
    }
    return match;
  }

  const matches = catalog.filter((model) => sameModelId(model?.id, requested));
  if (matches.length === 1) return matches[0];
  if (matches.length > 1) {
    const alternatives = matches.map((model) => visibleModelId(model.owned_by, model.id));
    throw new ClaudeyError(
      'MODEL_AMBIGUOUS',
      `"${requested}" is available from multiple providers.`,
      {
        hint: `Use one of: ${alternatives.join(', ')}`,
        details: { model: requested, alternatives }
      }
    );
  }
  throw new ClaudeyError('MODEL_NOT_FOUND', `"${requested}" is not available.`, {
    details: { model: requested }
  });
}
