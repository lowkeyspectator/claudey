# Provider-Labeled Model Selection

Date: 2026-08-16

Status: Approved design

## 1. Summary

In mixed `claudey` sessions, Claude Code’s `/model` menu must show which service each model comes from, and selecting an option must guarantee that provider. Today the mixed catalog drops duplicate raw model IDs before provider-qualified picker IDs are created, so the same upstream name from two authenticated providers can collapse into a single ambiguous entry.

This change keeps every authenticated `(provider, model ID)` pair, labels options as `model-name — Provider` (with usage details after the label), and routes each selection through a provider-specific CLIProxyAPI OAuth alias that Claudey manages and hot-reloads.

## 2. Goals

1. Show provider identity in every mixed-session model option.
2. Keep duplicate raw model IDs when different providers expose them.
3. Guarantee that choosing `model — Provider` routes inference to that provider.
4. Preserve existing usage decoration in the option label.
5. Keep single-provider launchers (`claude-codex`, `claude-agy`, `claude-grok`) unchanged in behavior.
6. Fail closed on ambiguous raw `--model` values when more than one provider owns that ID.

## 3. Non-goals

- Changing Cursor model listing or Cursor MCP tools.
- Reworking single-provider catalogs beyond ambiguous `--model` rejection in mixed mode.
- Shipping a static model catalog or provider-name heuristics.
- Depending on unofficial CLIProxyAPI forks or undocumented display-prefix flags.
- Changing Claude Code’s own `/model` UI chrome beyond the catalog fields Claudey already supplies (`id`, `display_name`, `owned_by`).

## 4. Current behavior and defect

Relevant code:

- `src/providers/claude.js` merges provider catalogs with a `seen` set keyed only by raw `model.id`, discarding later providers for the same ID.
- `src/providers/picker-gateway.js` already builds provider-qualified visible IDs via `visibleModelId(owned_by, id)` and puts usage into `display_name` through `formatUsageLine`.
- `src/providers/catalog.js` already encodes `anthropic-cdx-<provider>-<rawId>` and can parse it back.
- `picker-gateway` rewrites request models with `upstreamModelId`, which strips the visible prefix and returns the raw ID (cloaked for Anthropic). The upstream gateway then resolves that raw ID without Claudey’s provider choice.

Result: labels can look similar across providers, duplicates are dropped early, and even a provider-qualified visible ID is reduced to an ambiguous raw upstream name before CLIProxyAPI routes it.

## 5. UX contract

### 5.1 Display format

Each mixed-session option uses:

```text
<raw-model-id> — <ProviderTitle> · <usage-if-present>
```

Examples:

- `gpt-5.6-sol — Codex · 40% left`
- `gpt-5.6-sol — Antigravity · 12% left`
- `grok-4.5 — Grok · 83% left`

Provider titles:

| Provider key | Title |
|---|---|
| `codex` | `Codex` |
| `antigravity` | `Antigravity` |
| `grok` | `Grok` |

Usage continues to come from `formatUsageLine` / attached usage metadata. If usage is unavailable, omit the usage suffix and keep `model — Provider`.

### 5.2 Selection surfaces

Applies to:

- Claude Code `/model` catalog served by the mixed-session picker gateway.
- Launch-time announcement listing models by provider.
- Mixed-session `claudey --model ...` resolution.

Does not change the interactive `selectModel` hook’s required return value shape (still a model ID string), but the available IDs become provider-qualified when duplicates exist.

## 6. Routing contract

### 6.1 Provider-qualified visible IDs

Keep the existing visible ID scheme:

```text
anthropic-cdx-<provider>-<rawId>
```

These remain the Claude-facing model IDs in mixed mode.

### 6.2 Upstream alias pinning

For each live authenticated model, Claudey ensures a CLIProxyAPI OAuth alias for that provider’s channel:

```yaml
oauth-model-alias:
  codex:
    - name: "gpt-5.6-sol"
      alias: "anthropic-cdx-codex-gpt-5.6-sol"
      display-name: "gpt-5.6-sol — Codex"
      force-mapping: true
  antigravity:
    - name: "gpt-5.6-sol"
      alias: "anthropic-cdx-antigravity-gpt-5.6-sol"
      display-name: "gpt-5.6-sol — Antigravity"
      force-mapping: true
  xai: # or grok channel key as supported by the installed CLIProxyAPI
    - name: "grok-4.5"
      alias: "anthropic-cdx-grok-grok-4.5"
      display-name: "grok-4.5 — Grok"
      force-mapping: true
```

Rules:

1. Alias equals the Claude-facing visible ID.
2. `name` equals the provider’s exact live upstream model ID.
3. Claudey never invents models; aliases are generated only from the authenticated live catalog.
4. Channel names follow CLIProxyAPI’s supported OAuth channels for the installed binary (`codex`, `antigravity`, `xai`/`grok` as detected).
5. Alias generation is idempotent and replaces Claudey-managed alias entries; it does not delete unrelated user aliases outside Claudey’s managed prefix/marker.

### 6.3 Picker rewrite change

In mixed mode, when the request model is a parseable provider-qualified visible ID, the picker gateway must forward that exact alias to CLIProxyAPI. It must not:

- strip the visible prefix down to the raw source ID, or
- apply Anthropic cloaking to the alias

because the alias registered in `oauth-model-alias` is the client-visible ID Claudey generated. Cloaking or stripping would make the upstream lookup miss the provider-scoped alias and reintroduce ambiguity.

If the request model is not provider-qualified, existing rewrite/cloak behavior remains, subject to the ambiguity rule in §7.

### 6.4 Config update and hot reload

Claudey writes the managed alias block into the existing managed `config.yaml` and relies on CLIProxyAPI’s config watcher hot reload. Launch waits until the picker catalog reflects the expected provider-qualified aliases (or fails closed with a remediation) rather than racing a stale upstream catalog.

Setup / restart paths that rebuild gateway config must preserve or regenerate the managed alias block.

## 7. Ambiguity and matching rules

1. Mixed catalog identity key is `(owned_by, id)`, not `id` alone.
2. `sameModelId` / catalog lookup for mixed mode must prefer provider-qualified matches.
3. If the user passes a raw `--model <id>` and exactly one authenticated provider owns that ID, accept it and route through that provider’s qualified alias.
4. If two or more authenticated providers own that raw ID, reject with `MODEL_NOT_FOUND` or a dedicated `MODEL_AMBIGUOUS` public error, listing the provider-qualified alternatives.
5. Selecting a provider-qualified ID always pins that provider.

## 8. Architecture

### 8.1 Components

| Unit | Responsibility |
|---|---|
| Mixed catalog merge in `claude.js` | Keep all `(provider, id)` pairs; stop raw-ID dedupe. |
| Display formatter (usage or catalog helper) | Build `model — Provider` (+ usage) strings. |
| Managed alias sync | Diff live catalog against managed `oauth-model-alias` entries and update `config.yaml`. |
| Picker catalog | Continue emitting visible IDs; use the new display format. |
| Picker request rewrite | Forward provider-qualified aliases instead of stripping them. |
| Model resolution | Provider-aware matching and ambiguity refusal. |

### 8.2 Data flow

```text
auth providers → live models by provider
  → merge on (provider, id)
  → sync oauth-model-alias into managed config.yaml
  → wait for upstream readiness
  → decorate usage
  → pickerCatalog(display_name = "id — Provider · usage")
  → Claude /model shows labeled options
  → user selects anthropic-cdx-<provider>-<id>
  → picker forwards alias to CLIProxyAPI
  → CLIProxyAPI resolves alias to that provider’s upstream model
```

## 9. Error handling

- Alias sync failure: fail closed before launching Claude; do not start a mixed session with ambiguous routing.
- Hot-reload readiness timeout: fail with `GATEWAY_UNHEALTHY` (or equivalent public code) and remediation to restart/setup.
- Ambiguous raw model: public error with provider-qualified alternatives in details/hint.
- Unauthenticated providers: omit their models; do not invent placeholders.
- Partial provider success: unchanged — mixed session continues with authenticated providers only.

## 10. Testing

Required unit/integration coverage:

1. Duplicate raw IDs from two providers both appear with distinct display names and visible IDs.
2. Selecting each duplicate routes through the matching provider alias (request body model assertion).
3. Raw `--model` unique across providers still works.
4. Raw `--model` shared by two providers is rejected as ambiguous.
5. Display format includes provider title and preserves usage when present.
6. Alias sync writes expected `oauth-model-alias` entries for the live catalog.
7. Picker no longer strips provider-qualified IDs before upstream.
8. Single-provider launchers still pin and spawn with raw provider model IDs as today.
9. Launch announcement lists duplicates under each provider section.

## 11. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Installed CLIProxyAPI channel key differs (`xai` vs `grok`) | Probe/map from existing ownership aliases; fail closed if unsupported. |
| Hot reload lag | Explicit readiness wait on expected aliases before Claude spawn. |
| User-edited `oauth-model-alias` conflicts | Manage only Claudey visible-prefix aliases; leave foreign aliases untouched. |
| Claude Code ignores `display_name` | Still keep distinct visible IDs so options remain distinguishable even if only IDs render. |
| Alias explosion over time | Rebuild managed alias set from current live catalog each mixed launch/sync. |

## 12. Rollout

No migration flag. Existing installs pick up the behavior on next mixed `claudey` launch after the code update. Managed config gains/refreshes the alias block automatically. No change to uninstall ownership rules beyond existing managed `config.yaml` handling.
