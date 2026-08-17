# Provider-Labeled Model Selection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make mixed `claudey` model selection show `model — Provider` labels and guarantee that choosing a duplicate model routes to the selected provider.

**Architecture:** Keep every authenticated `(provider, model ID)` pair in the mixed catalog, label options with provider titles, sync provider-qualified `oauth-model-alias` entries into the managed CLIProxyAPI config, and stop the picker gateway from stripping those aliases before upstream routing.

**Tech Stack:** Node.js ESM, Node standard library only, `node:test`, existing Claudey provider/catalog/picker/config modules.

## Global Constraints

- Follow `docs/superpowers/specs/2026-08-16-provider-labeled-model-selection-design.md` exactly.
- Never invent models; aliases and labels come only from authenticated live catalogs.
- Visible IDs stay `anthropic-cdx-<provider>-<rawId>`.
- Display format is `<raw-model-id> — <ProviderTitle>` plus optional ` · <usage>`.
- Provider titles: `codex` → `Codex`, `antigravity` → `Antigravity`, `grok` → `Grok`.
- Provider-qualified aliases must be forwarded upstream unchanged (no strip, no Anthropic cloak).
- Single-provider launchers keep raw model IDs and current spawn behavior.
- Ambiguous raw `--model` in mixed mode fails closed with provider-qualified alternatives.
- No npm runtime dependencies; use existing Claudey error/result patterns.
- TDD: write the failing test first, observe the failure, implement the minimum, re-run, commit.

## File map

| File | Responsibility |
|---|---|
| `src/providers/usage.js` | Provider titles and `formatUsageLine` including `model — Provider`. |
| `src/providers/catalog.js` | OAuth channel mapping helpers live beside resolve helpers as needed; mixed catalog resolve/ambiguity. |
| `src/core/errors.js` | Public `MODEL_AMBIGUOUS` exit mapping. |
| `src/core/config.js` | Render managed `oauth-model-alias` into gateway YAML. |
| `src/providers/oauth-aliases.js` | Build managed alias records from live models. |
| `src/providers/picker-gateway.js` | Preserve provider-qualified aliases on rewrite; use labeled display names. |
| `src/providers/claude.js` | Keep `(provider,id)` pairs; resolve with ambiguity; sync aliases; announce labels. |
| `src/cli/runtime.js` | Config rewrite and alias readiness helpers used by mixed launch. |
| Matching `test/unit/...` files | Focused coverage for each behavior. |

---

### Task 1: Provider-labeled display lines

**Files:**
- Modify: `src/providers/usage.js`
- Test: `test/unit/providers/usage.test.js`

**Interfaces:**
- Produces: `providerTitle(provider) → string|null`
- Produces: `formatUsageLine(model)` returns `id — Provider` and appends usage with ` · ` when present

- [ ] **Step 1: Write the failing test**

Add to `test/unit/providers/usage.test.js`:

```js
import { formatUsageLine, providerTitle } from '../../../src/providers/usage.js';

test('labels models with provider titles and keeps usage after the provider', () => {
  assert.equal(providerTitle('codex'), 'Codex');
  assert.equal(providerTitle('antigravity'), 'Antigravity');
  assert.equal(providerTitle('grok'), 'Grok');
  assert.equal(providerTitle('cursor'), null);

  assert.equal(
    formatUsageLine({ id: 'gpt-5.6-sol', owned_by: 'codex', usage: { remainingPercent: 40, status: 'available' } }),
    'gpt-5.6-sol — Codex · 40% left'
  );
  assert.equal(
    formatUsageLine({ id: 'gpt-5.6-sol', owned_by: 'antigravity' }),
    'gpt-5.6-sol — Antigravity'
  );
  assert.equal(
    formatUsageLine({ id: 'grok-4.5', owned_by: 'grok', usage: { remainingPercent: 83, status: 'available' } }),
    'grok-4.5 — Grok · 83% left'
  );
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/unit/providers/usage.test.js`

Expected: FAIL because `providerTitle` is not exported and current `formatUsageLine` returns `gpt-5.6-sol · 40% left` without a provider.

- [ ] **Step 3: Write minimal implementation**

In `src/providers/usage.js`:

```js
export function providerTitle(provider) {
  if (provider === 'codex') return 'Codex';
  if (provider === 'antigravity') return 'Antigravity';
  if (provider === 'grok') return 'Grok';
  return null;
}

export function formatUsageLine(model) {
  const usage = model?.usage;
  const title = providerTitle(model?.owned_by);
  const base = typeof model?.id === 'string'
    ? (title ? `${model.id} — ${title}` : model.id)
    : '';
  if (!usage) return base;
  const parts = [base];
  if (Number.isFinite(usage.remainingPercent)) parts.push(`${usage.remainingPercent}% left`);
  else if (usage.window) parts.push(String(usage.window));
  if (usage.status && usage.status !== 'available' && usage.status !== 'unknown') parts.push(usage.status);
  return parts.join(' · ');
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test test/unit/providers/usage.test.js`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/providers/usage.js test/unit/providers/usage.test.js
git commit -m "$(cat <<'EOF'
feat: label mixed model options with provider titles

EOF
)"
```

---

### Task 2: Mixed catalog resolve and ambiguity error

**Files:**
- Modify: `src/core/errors.js`
- Modify: `src/providers/catalog.js`
- Test: `test/unit/providers/catalog.test.js`

**Interfaces:**
- Produces: `MODEL_AMBIGUOUS` public code with exit class `4`
- Produces: `resolveMixedCatalogModel(catalog, requested) → model | throws ClaudeyError`
- Consumes: `visibleModelId`, `parseVisibleModelId`, `sameModelId`

- [ ] **Step 1: Write the failing test**

Add to `test/unit/providers/catalog.test.js`:

```js
import { ClaudeyError } from '../../../src/core/errors.js';
import { resolveMixedCatalogModel, visibleModelId } from '../../../src/providers/catalog.js';

test('mixed resolve keeps provider-qualified matches and rejects ambiguous raw IDs', () => {
  const catalog = [
    { id: 'gpt-5.6-sol', object: 'model', created: 1, owned_by: 'codex' },
    { id: 'gpt-5.6-sol', object: 'model', created: 2, owned_by: 'antigravity' },
    { id: 'grok-4.5', object: 'model', created: 3, owned_by: 'grok' }
  ];

  assert.equal(
    resolveMixedCatalogModel(catalog, visibleModelId('antigravity', 'gpt-5.6-sol')).owned_by,
    'antigravity'
  );
  assert.equal(resolveMixedCatalogModel(catalog, 'grok-4.5').owned_by, 'grok');

  assert.throws(
    () => resolveMixedCatalogModel(catalog, 'gpt-5.6-sol'),
    (error) => error instanceof ClaudeyError
      && error.code === 'MODEL_AMBIGUOUS'
      && error.details.model === 'gpt-5.6-sol'
      && error.details.alternatives.includes(visibleModelId('codex', 'gpt-5.6-sol'))
      && error.details.alternatives.includes(visibleModelId('antigravity', 'gpt-5.6-sol'))
  );
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/unit/providers/catalog.test.js`

Expected: FAIL because `resolveMixedCatalogModel` is missing and `MODEL_AMBIGUOUS` is unmapped.

- [ ] **Step 3: Write minimal implementation**

In `src/core/errors.js`, add `['MODEL_AMBIGUOUS', 4]` next to `MODEL_NOT_FOUND`.

In `src/providers/catalog.js`:

```js
import { ClaudeyError } from '../core/errors.js';

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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test test/unit/providers/catalog.test.js`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/core/errors.js src/providers/catalog.js test/unit/providers/catalog.test.js
git commit -m "$(cat <<'EOF'
feat: resolve mixed models with provider ambiguity checks

EOF
)"
```

---

### Task 3: Managed OAuth alias records and config YAML

**Files:**
- Create: `src/providers/oauth-aliases.js`
- Modify: `src/core/config.js`
- Test: `test/unit/providers/oauth-aliases.test.js`
- Test: `test/unit/core/config.test.js`

**Interfaces:**
- Produces: `oauthAliasChannel(provider) → 'codex'|'antigravity'|'xai'|null`
- Produces: `buildManagedOAuthAliases(models) → { [channel]: Array<{name, alias, displayName, forceMapping}> }`
- Produces: `buildGatewayConfig({ port, authDir, token, oauthModelAlias? })` appends `oauth-model-alias` YAML when provided

- [ ] **Step 1: Write the failing tests**

Create `test/unit/providers/oauth-aliases.test.js`:

```js
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
```

Add to `test/unit/core/config.test.js`:

```js
test('renders managed oauth-model-alias entries into gateway config YAML', () => {
  const bytes = buildGatewayConfig({
    port: 8317,
    authDir: '/private/auth',
    token: token(),
    oauthModelAlias: {
      codex: [{
        name: 'gpt-5.6-sol',
        alias: 'anthropic-cdx-codex-gpt-5.6-sol',
        displayName: 'gpt-5.6-sol — Codex',
        forceMapping: true
      }],
      xai: [{
        name: 'grok-4.5',
        alias: 'anthropic-cdx-grok-grok-4.5',
        displayName: 'grok-4.5 — Grok',
        forceMapping: true
      }]
    }
  }).toString('utf8');

  assert.match(bytes, /oauth-model-alias:/u);
  assert.match(bytes, /codex:/u);
  assert.match(bytes, /name: "gpt-5\.6-sol"/u);
  assert.match(bytes, /alias: "anthropic-cdx-codex-gpt-5\.6-sol"/u);
  assert.match(bytes, /display-name: "gpt-5\.6-sol — Codex"/u);
  assert.match(bytes, /force-mapping: true/u);
  assert.match(bytes, /xai:/u);
  assert.match(bytes, /alias: "anthropic-cdx-grok-grok-4\.5"/u);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
node --test test/unit/providers/oauth-aliases.test.js test/unit/core/config.test.js
```

Expected: FAIL on missing module / missing oauth YAML.

- [ ] **Step 3: Write minimal implementation**

Create `src/providers/oauth-aliases.js`:

```js
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
```

Update `src/core/config.js` `buildGatewayConfig` to accept optional `oauthModelAlias` and append:

```yaml
oauth-model-alias:
  codex:
    - name: "..."
      alias: "..."
      display-name: "..."
      force-mapping: true
```

Validate each channel/name/alias/displayName as nonempty safe strings before quoting with the existing `quoteYamlString` helper. Omit the block when `oauthModelAlias` is omitted or empty.

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
node --test test/unit/providers/oauth-aliases.test.js test/unit/core/config.test.js
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/providers/oauth-aliases.js src/core/config.js \
  test/unit/providers/oauth-aliases.test.js test/unit/core/config.test.js
git commit -m "$(cat <<'EOF'
feat: generate managed oauth-model-alias config for mixed routing

EOF
)"
```

---

### Task 4: Picker preserves provider-qualified aliases and labeled names

**Files:**
- Modify: `src/providers/picker-gateway.js`
- Test: `test/unit/providers/picker-gateway.test.js`

**Interfaces:**
- Consumes: `formatUsageLine` (now provider-labeled), `parseVisibleModelId`
- Produces: `upstreamModelId(value, { anthropic })` returns the visible alias unchanged when parseable; otherwise keeps prior cloak/raw behavior

- [ ] **Step 1: Write the failing tests**

Update/add in `test/unit/providers/picker-gateway.test.js`:

```js
test('picker catalog uses provider-labeled display names', () => {
  const catalog = pickerCatalog([
    { id: 'gpt-5.6-sol', object: 'model', created: 1, owned_by: 'codex', usage: { remainingPercent: 40, status: 'available' } },
    { id: 'gpt-5.6-sol', object: 'model', created: 2, owned_by: 'antigravity' }
  ]);
  assert.equal(catalog.length, 2);
  assert.equal(catalog[0].id, visibleModelId('codex', 'gpt-5.6-sol'));
  assert.equal(catalog[0].display_name, 'gpt-5.6-sol — Codex · 40% left');
  assert.equal(catalog[1].id, visibleModelId('antigravity', 'gpt-5.6-sol'));
  assert.equal(catalog[1].display_name, 'gpt-5.6-sol — Antigravity');
});

test('provider-qualified visible IDs are forwarded upstream without stripping or cloaking', () => {
  const visible = visibleModelId('codex', 'gpt-5.6-sol');
  assert.equal(upstreamModelId(visible, { anthropic: true }), visible);
  assert.equal(upstreamModelId(visible, { anthropic: false }), visible);
  assert.equal(upstreamModelId('grok-4.5', { anthropic: true }).startsWith('claude-fable-5-dd-'), true);
});
```

Also extend the existing gateway proxy test so a request body with `model: visibleModelId('codex', 'gpt-5.6-sol')` reaches upstream with that exact model string.

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/unit/providers/picker-gateway.test.js`

Expected: FAIL because `upstreamModelId` still strips/cloaks visible IDs.

- [ ] **Step 3: Write minimal implementation**

In `src/providers/picker-gateway.js`:

```js
export function upstreamModelId(value, { anthropic = false } = {}) {
  if (parseVisibleModelId(value)) return value;
  const raw = sourceModelId(value);
  return anthropic ? cloakModelId(raw) : raw;
}
```

`pickerCatalog` already uses `formatUsageLine(model)`; after Task 1 that is enough for labels. Ensure duplicate `(owned_by, id)` rows are both emitted (no dedupe here).

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test test/unit/providers/picker-gateway.test.js`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/providers/picker-gateway.js test/unit/providers/picker-gateway.test.js
git commit -m "$(cat <<'EOF'
fix: forward provider-qualified picker model aliases upstream

EOF
)"
```

---

### Task 5: Keep duplicate providers in the mixed launch catalog

**Files:**
- Modify: `src/providers/claude.js`
- Test: `test/unit/providers/claude.test.js`

**Interfaces:**
- Consumes: `resolveMixedCatalogModel`, `formatUsageLine`
- Produces: mixed merge keyed by `${owned_by}\0${id}`; announcements use provider-labeled lines

- [ ] **Step 1: Write the failing test**

Add to `test/unit/providers/claude.test.js`:

```js
test('mixed session keeps duplicate raw model IDs from different providers', async () => {
  const announced = [];
  const startPicker = async ({ models }) => {
    assert.equal(models.filter((model) => model.id === 'gpt-5.6-sol').length, 2);
    assert.deepEqual(
      models.filter((model) => model.id === 'gpt-5.6-sol').map((model) => model.owned_by).sort(),
      ['antigravity', 'codex']
    );
    return {
      host: '127.0.0.1',
      port: 19_001,
      close: async () => {}
    };
  };

  await launchClaudeProvider({
    ...await baseLaunch({
      parsed: { model: visibleModelId('antigravity', 'gpt-5.6-sol'), select: false, all: true, claudeArgs: [], nonInteractive: true },
      listModels: async (name) => {
        if (name === 'codex') {
          return { provider: name, status: 'available', models: [
            { id: 'gpt-5.6-sol', object: 'model', created: 1, owned_by: 'codex' }
          ] };
        }
        if (name === 'antigravity') {
          return { provider: name, status: 'available', models: [
            { id: 'gpt-5.6-sol', object: 'model', created: 2, owned_by: 'antigravity' }
          ] };
        }
        return { provider: name, status: 'available', models: [
          { id: 'grok-4.5', object: 'model', created: 3, owned_by: 'grok' }
        ] };
      },
      startPicker,
      announce: (text) => announced.push(text),
      syncOAuthAliases: async () => ({ synced: true, oauthModelAlias: {} }),
      waitForAliasReady: async () => true
    })
  });

  assert.match(announced.join('\n'), /gpt-5\.6-sol — Codex/u);
  assert.match(announced.join('\n'), /gpt-5\.6-sol — Antigravity/u);
});
```

Adapt fixture helpers already used in that file so the new optional hooks default safely in older tests.

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/unit/providers/claude.test.js`

Expected: FAIL because the merge `seen` set still drops the second `gpt-5.6-sol`.

- [ ] **Step 3: Write minimal implementation**

In `src/providers/claude.js` mixed merge:

```js
const seen = new Set();
for (const name of GATEWAY_PROVIDERS) {
  // ...
  for (const model of models) {
    const key = `${model.owned_by}\0${model.id}`;
    if (seen.has(key)) continue;
    seen.add(key);
    merged.push(model);
  }
}
```

Replace `resolveCatalogModel(catalog, selected)` in mixed mode with `resolveMixedCatalogModel(catalog, selected)`.

Use `formatUsageLine(model)` in the announcement loop.

Accept optional `syncOAuthAliases` / `waitForAliasReady` context hooks for Task 6; if absent in this task, no-op defaults are fine so this test can pass without real config I/O.

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test test/unit/providers/claude.test.js`

Expected: PASS for the new test; existing single-provider tests still PASS.

- [ ] **Step 5: Commit**

```bash
git add src/providers/claude.js test/unit/providers/claude.test.js
git commit -m "$(cat <<'EOF'
fix: keep cross-provider duplicate models in mixed sessions

EOF
)"
```

---

### Task 6: Sync aliases on mixed launch and wait for readiness

**Files:**
- Modify: `src/providers/claude.js`
- Modify: `src/cli/runtime.js`
- Test: `test/unit/providers/claude.test.js`
- Test: `test/unit/cli/runtime-oauth-aliases.test.js`

**Interfaces:**
- Produces: `syncManagedOAuthAliases({ paths, port, token, models })`
- Produces: `waitForManagedAliases({ host, port, token, aliases, requestModels, timeoutMs })`
- Consumes: `buildManagedOAuthAliases`, `buildGatewayConfig`, installation token/paths

- [ ] **Step 1: Write the failing tests**

```js
test('mixed launch syncs oauth aliases before starting the picker', async () => {
  const synced = [];
  await launchClaudeProvider({
    ...await baseLaunch({
      parsed: { model: visibleModelId('codex', 'gpt-5.6-sol'), select: false, all: true, claudeArgs: [], nonInteractive: true },
      listModels: async (name) => ({
        provider: name,
        status: 'available',
        models: name === 'codex'
          ? [{ id: 'gpt-5.6-sol', object: 'model', created: 1, owned_by: 'codex' }]
          : []
      }),
      syncOAuthAliases: async ({ models }) => {
        synced.push(models.map((model) => `${model.owned_by}:${model.id}`));
        return { synced: true, oauthModelAlias: {} };
      },
      waitForAliasReady: async () => true,
      startPicker: async () => ({ host: '127.0.0.1', port: 19_002, close: async () => {} })
    })
  });
  assert.deepEqual(synced, [['codex:gpt-5.6-sol']]);
});

test('mixed launch fails closed when alias readiness never arrives', async () => {
  await assert.rejects(
    () => launchClaudeProvider({
      ...await baseLaunch({
        parsed: { model: visibleModelId('codex', 'gpt-5.6-sol'), select: false, all: true, claudeArgs: [], nonInteractive: true },
        listModels: async (name) => ({
          provider: name,
          status: 'available',
          models: name === 'codex'
            ? [{ id: 'gpt-5.6-sol', object: 'model', created: 1, owned_by: 'codex' }]
            : []
        }),
        syncOAuthAliases: async () => ({ synced: true, oauthModelAlias: {} }),
        waitForAliasReady: async () => false,
        startPicker: async () => {
          throw new Error('picker must not start');
        }
      })
    }),
    (error) => error.code === 'GATEWAY_UNHEALTHY'
  );
});
```

Create `test/unit/cli/runtime-oauth-aliases.test.js` asserting the runtime helper writes config bytes containing `oauth-model-alias` and treats readiness as “every expected alias appears in `/v1/models`”.

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test test/unit/providers/claude.test.js`

Expected: FAIL until launch calls sync/readiness hooks before `startPicker`.

- [ ] **Step 3: Write minimal implementation**

In `src/cli/runtime.js`:

```js
export async function syncManagedOAuthAliases({ paths, port, token, models, fsApi = fs }) {
  const oauthModelAlias = buildManagedOAuthAliases(models);
  const bytes = buildGatewayConfig({
    port,
    authDir: paths.authRoot,
    token,
    oauthModelAlias
  });
  await fsApi.writeFile(path.join(paths.configRoot, 'config.yaml'), bytes, { mode: 0o600 });
  return Object.freeze({ synced: true, oauthModelAlias });
}

export async function waitForManagedAliases({
  host = '127.0.0.1',
  port,
  token,
  aliases,
  requestModels = requestGatewayModels,
  timeoutMs = 8_000,
  delayMs = 100
}) {
  const expected = new Set();
  for (const entries of Object.values(aliases ?? {})) {
    for (const entry of entries) expected.add(entry.alias);
  }
  if (expected.size === 0) return true;
  const deadline = Date.now() + timeoutMs;
  while (Date.now() <= deadline) {
    try {
      const catalog = await requestModels({ host, port, token, allowPreAuthEmpty: true });
      const present = new Set((catalog?.data ?? []).map((model) => model?.id).filter(Boolean));
      if ([...expected].every((alias) => present.has(alias))) return true;
    } catch { /* keep polling */ }
    await delay(delayMs);
  }
  return false;
}
```

In `launchClaudeProvider` mixed branch, after building `catalog`/`decorated` and before `startPicker`:

```js
const sync = syncOAuthAliases ?? defaultSync;
const wait = waitForAliasReady ?? defaultWait;
const aliasResult = await sync({ models: decorated, gateway });
if (await wait({ gateway, aliases: aliasResult.oauthModelAlias }) !== true) {
  throw unhealthy();
}
```

Wire production defaults through the launcher context in `createProductionContainer` / `createLauncherContext` so real `claudey` launches sync aliases.

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
node --test test/unit/providers/claude.test.js test/unit/providers/picker-gateway.test.js test/unit/providers/catalog.test.js test/unit/providers/usage.test.js test/unit/core/config.test.js test/unit/cli/runtime-oauth-aliases.test.js
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/providers/claude.js src/cli/runtime.js test/unit/providers/claude.test.js test/unit/cli/runtime-oauth-aliases.test.js
git commit -m "$(cat <<'EOF'
feat: sync provider oauth aliases before mixed Claude launch

EOF
)"
```

---

### Task 7: Ambiguous raw `--model` rejection in mixed launcher

**Files:**
- Modify: `src/providers/claude.js` (if not fully done in Task 5)
- Modify: `src/cli/first-run.js` only if needed to avoid remapping `MODEL_AMBIGUOUS`
- Test: `test/unit/providers/claude.test.js`

**Interfaces:**
- Consumes: `resolveMixedCatalogModel`
- Produces: mixed `--model shared` throws `MODEL_AMBIGUOUS`; unique raw IDs still launch

- [ ] **Step 1: Write the failing test**

```js
test('mixed --model rejects ambiguous raw IDs and accepts unique raw IDs', async () => {
  const listModels = async (name) => {
    if (name === 'codex') {
      return { provider: name, status: 'available', models: [
        { id: 'shared-model', object: 'model', created: 1, owned_by: 'codex' },
        { id: 'only-codex', object: 'model', created: 2, owned_by: 'codex' }
      ] };
    }
    if (name === 'antigravity') {
      return { provider: name, status: 'available', models: [
        { id: 'shared-model', object: 'model', created: 3, owned_by: 'antigravity' }
      ] };
    }
    return { provider: name, status: 'available', models: [] };
  };

  await assert.rejects(
    () => launchClaudeProvider({
      ...await baseLaunch({
        parsed: { model: 'shared-model', select: false, all: true, claudeArgs: [], nonInteractive: true },
        listModels,
        syncOAuthAliases: async () => ({ synced: true, oauthModelAlias: {} }),
        waitForAliasReady: async () => true
      })
    }),
    (error) => error.code === 'MODEL_AMBIGUOUS'
  );

  const result = await launchClaudeProvider({
    ...await baseLaunch({
      parsed: { model: 'only-codex', select: false, all: true, claudeArgs: [], nonInteractive: true },
      listModels,
      syncOAuthAliases: async () => ({ synced: true, oauthModelAlias: {} }),
      waitForAliasReady: async () => true,
      startPicker: async () => ({ host: '127.0.0.1', port: 19_003, close: async () => {} })
    })
  });
  assert.equal(result.provider, 'codex');
  assert.equal(result.model, 'only-codex');
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/unit/providers/claude.test.js`

Expected: FAIL if mixed path still uses raw `sameModelId` first-match.

- [ ] **Step 3: Write minimal implementation**

Ensure mixed selection uses:

```js
const matched = resolveMixedCatalogModel(catalog, selected);
```

and that `beginnerLaunchError` / public CLI mapping leave `MODEL_AMBIGUOUS` visible (no remap to `SAFETY_REFUSAL`).

- [ ] **Step 4: Run focused suites**

Run:

```bash
node --test \
  test/unit/providers/claude.test.js \
  test/unit/providers/picker-gateway.test.js \
  test/unit/providers/catalog.test.js \
  test/unit/providers/usage.test.js \
  test/unit/providers/oauth-aliases.test.js \
  test/unit/core/config.test.js \
  test/unit/cli/runtime-oauth-aliases.test.js
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/providers/claude.js test/unit/providers/claude.test.js src/cli/first-run.js
git commit -m "$(cat <<'EOF'
fix: reject ambiguous raw model IDs in mixed claudey sessions

EOF
)"
```

---

### Task 8: Spec coverage self-check and docs touch

**Files:**
- Modify: `README.md` only if the public model-selection blurb still claims unlabeled `/model` rows
- Verify: `docs/superpowers/specs/2026-08-16-provider-labeled-model-selection-design.md`

- [ ] **Step 1: Map spec requirements to tasks**

Confirm each of these is covered by Tasks 1–7:

1. Duplicate raw IDs kept → Task 5
2. `model — Provider` labels → Task 1/4
3. Provider routing via oauth aliases → Tasks 3/4/6
4. Ambiguous raw `--model` → Task 7
5. Single-provider unchanged → Task 5/7 regression tests
6. Hot-reload readiness fail-closed → Task 6

- [ ] **Step 2: Update README mixed-session sentence if needed**

If README still says rows are labeled only with model id/capacity, change it to mention provider:

```text
Each row is labeled with the live model id, provider, and remaining capacity when that is known.
```

- [ ] **Step 3: Run the focused regression set once more**

Run the same `node --test` command from Task 7 Step 4.

Expected: PASS

- [ ] **Step 4: Commit docs if changed**

```bash
git add README.md
git commit -m "$(cat <<'EOF'
docs: note provider labels in mixed model selection

EOF
)"
```

---

## Spec coverage checklist

| Spec requirement | Task |
|---|---|
| Display `model — Provider` (+ usage) | 1, 4 |
| Keep `(provider, id)` pairs | 5 |
| Provider-qualified visible IDs unchanged | 4, 5 |
| Managed `oauth-model-alias` generation | 3 |
| Config YAML render | 3 |
| Forward aliases without strip/cloak | 4 |
| Sync + readiness before picker | 6 |
| Ambiguous raw `--model` refusal | 2, 7 |
| Unique raw `--model` still works | 7 |
| Single-provider launchers unchanged | 5, 7 |
| Announcement lists provider-labeled duplicates | 5 |
| Fail closed on alias readiness timeout | 6 |

## Placeholder / consistency review

- No TBD/TODO steps remain.
- Function names are stable across tasks: `providerTitle`, `formatUsageLine`, `resolveMixedCatalogModel`, `oauthAliasChannel`, `buildManagedOAuthAliases`, `upstreamModelId`, `syncManagedOAuthAliases`, `waitForManagedAliases`.
- Grok OAuth channel is consistently `xai`.
- Visible alias format remains `anthropic-cdx-<provider>-<rawId>` from existing `visibleModelId`.
