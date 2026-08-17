# Usage labels and the mixed model picker

This guide covers how Claudey decorates `/model` options with remaining quota, how to verify each provider segment, and what is intentionally **not** in the mixed gateway picker (Cursor Composer).

Related design notes:

- [Provider-labeled model selection](superpowers/specs/2026-08-16-provider-labeled-model-selection-design.md)
- [Provider usage and picker hardening (2026-08-17)](superpowers/specs/2026-08-17-provider-usage-and-picker-hardening-design.md)

## Segments at a glance

| Segment | Where models come from | Where usage comes from | Shows in mixed `claudey` `/model`? |
|---|---|---|---|
| Codex | CLIProxy gateway | ChatGPT WHAM usage API | Yes |
| Antigravity | CLIProxy gateway | Google Cloud Code quota APIs | Yes |
| Grok | CLIProxy gateway | xAI CLI-proxy billing (`format=credits`) | Yes |
| Cursor (Composer, etc.) | Cursor Agent catalog | Cursor dashboard period usage | **No** — use `claudey models cursor` / Cursor commands |

Mixed sessions only forward inference through the local CLIProxyAPI gateway. Cursor Composer uses Cursor’s own auth and runtime, so it cannot be selected from the same gateway-backed `/model` list without a separate dual-routing design.

## Label format

Picker / `claudey models` labels look like:

```text
<raw-model-id> - <Provider> | <usage>
```

Examples:

```text
gpt-5.6-sol - Codex | 40% left
gemini-3-flash - Antigravity | 61%/7d · 100%/5h
grok-4.6 - Grok | 100% left
```

Rules implemented in `src/providers/usage.js` → `formatUsageLine`:

- Provider title comes after the model id (`Codex`, `Antigravity`, `Grok`).
- If Antigravity supplies both weekly and 5-hour windows, show compact dual usage: `61%/7d · 100%/5h`.
- Otherwise prefer a single `N% left` when remaining percent is known.
- Do **not** treat model context length (`500000 ctx`) as usage.

## Auth and paths

On macOS, managed state lives under Application Support with product leaf `claudeyctl`:

```text
~/Library/Application Support/claudeyctl/auth/     # OAuth JSON (codex / antigravity / xai)
~/Library/Application Support/claudeyctl/config.yaml
```

`claudey models …` and mixed-session usage decoration read that `auth` directory. Cursor usage reads the Cursor app token from Cursor’s `state.vscdb` (separate from CLIProxy auth).

---

## Segment A — Antigravity

### Behavior

1. Collect quota with `User-Agent: antigravity` (required; without it Google often returns `403 SUBSCRIPTION_REQUIRED`).
2. Prefer `POST …/v1internal:retrieveUserQuotaSummary` across sandbox/daily/prod Cloud Code hosts.
3. Map summary **pools** onto catalog models:
   - Gemini family → Gemini pool
   - Claude / GPT family → “3p” (Claude and GPT) pool
4. Show both weekly (`7d`) and five-hour (`5h`) remaining fractions when present.
5. If summary fails, fall back to per-model `retrieveUserQuota` (still with the Antigravity user-agent).

### Verify

```text
claudey auth antigravity
claudey models antigravity --json
claudey
# then open /model and confirm Gemini / Claude / GPT lines show %/7d · %/5h (not "unavailable")
```

Healthy JSON usage looks like `status: "available"` with numeric `remainingPercent` and optional `windows`.

### Common failure

| Symptom | Cause | Fix |
|---|---|---|
| Every Antigravity model `unavailable` | Quota call missing Antigravity user-agent or empty buckets | Update to a build that includes the 2026-08-17 usage fix; re-auth if `project_id` is missing |
| Provider catalog `available` but usage `unavailable` | Usage fetch failed while gateway listing succeeded | Check network; confirm auth JSON has `project_id` |

---

## Segment B — Grok

### Behavior

1. `GET https://cli-chat-proxy.grok.com/v1/billing?format=credits` with bearer token and `x-xai-token-auth: xai-grok-cli`.
2. Remaining percent from `creditUsagePercent` when present.
3. Else `onDemandUsed / onDemandCap` when the cap is positive.
4. Else, if a parseable `currentPeriod` exists and percent fields are omitted, treat **used = 0%** → **100% left** (xAI/CodexBar convention for proto3-omitted zero).
5. Attach that remaining percent to catalog models; keep window as the billing period (`7d` / `30d`), never context length.

### Verify

```text
claudey auth grok
claudey models grok --json
claudey
# /model should show "N% left", not "7d" alone or "500000 ctx"
```

### Common failure

| Symptom | Cause | Fix |
|---|---|---|
| `grok-… \| 7d` or `\| 500000 ctx` | Remaining percent was null; ctx leaked into the usage window | Use the 2026-08-17 Grok usage fix |
| `unavailable` | Auth missing or billing request failed | Re-run `claudey auth grok` |

---

## Segment C — Codex

### Behavior

Uses ChatGPT WHAM usage (`primary_window` / additional rate limits). Labels typically show `N% left` and may include named extra windows for specific model families.

### Verify

```text
claudey auth codex
claudey models codex --json
```

---

## Segment D — Cursor / Composer (not in mixed `/model`)

### What works today

```text
claudey models cursor --json
claudey cursor login   # when Cursor integration is enabled
```

Composer and other Cursor models appear here with Cursor period usage (auto / API buckets). They are **not** injected into the mixed Claude Code `/model` menu.

### Why mixed `/model` cannot host Composer “the same way”

| | Gateway (Codex / Antigravity / Grok) | Cursor Composer |
|---|---|---|
| Catalog | CLIProxy `/v1/models` | Cursor Agent model list |
| Inference | Claude Code → picker gateway → CLIProxy → provider | Cursor Agent / Cursor APIs |
| Auth | `claudeyctl/auth/*.json` | Cursor `state.vscdb` access token |

Mixed sessions also write session `availableModels` with `enforceAvailableModels: true` for **gateway** IDs only (`src/providers/claude.js`). That keeps Claude Code from selecting non-gateway IDs that would fail against CLIProxy.

Putting Composer into the same menu without dual routing would either hide it (current) or show it and break when Claude sent the request to the gateway.

A future design would need: Cursor entries in the picker catalog **and** picker-gateway routing of those IDs to Cursor (plus clear provider labels). That is out of scope for the usage fixes documented here.

---

## Mixed session end-to-end checklist

1. Authenticate the providers you care about: `claudey auth grok`, `claudey auth antigravity`, `claudey auth codex`.
2. Confirm catalogs + usage: `claudey models all --json` (or per-provider).
3. Launch: `claudey` or `claudey --yolo`.
4. Open `/model`:
   - Each option is `id - Provider | usage`.
   - Duplicate raw IDs from different providers both appear (provider-qualified routing).
   - Antigravity shows dual windows when summary quota is available.
   - Grok shows percent remaining, not context size.
5. For Composer / Cursor-only models, use `claudey models cursor` and Cursor integration commands — not mixed `/model`.

## Implementation map

| Concern | Primary file |
|---|---|
| Collect + format usage | `src/providers/usage.js` |
| Mixed launch, session `availableModels`, host-managed env | `src/providers/claude.js` |
| Picker catalog `display_name` | `src/providers/picker-gateway.js` |
| Provider-qualified IDs / aliases | `src/providers/catalog.js`, `src/providers/oauth-aliases.js` |
| Unit coverage | `test/unit/providers/usage.test.js`, `claude.test.js`, `picker-gateway.test.js` |

## Related launcher hardening (same change set)

These are not usage-label changes but ship alongside them:

- macOS/Linux `safeCwd` no longer takes the Windows path branch (fixes false `SAFETY_REFUSAL` on POSIX cwd).
- Claude executable resolution follows symlinks to a canonical candidate.
- Release download accepts GitHub’s `application/x-gtar` content type for CLIProxyAPI tarballs.
- Mixed session sets `CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST=1` so `~/.claude/settings.json` cannot overwrite launcher base URL / auth.
