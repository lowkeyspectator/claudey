# Provider Usage and Picker Hardening

Date: 2026-08-17

Status: Implemented

## 1. Summary

Mixed `claudey` sessions list live gateway models with provider labels and usage. Two usage collectors were broken in practice:

1. **Antigravity** — every model showed `unavailable` because `retrieveUserQuota` without `User-Agent: antigravity` returned `403 SUBSCRIPTION_REQUIRED`.
2. **Grok** — models showed `7d` or `500000 ctx` instead of remaining percent because unified-billing responses omit `creditUsagePercent` when used percent is zero, and context length was incorrectly stored as the usage `window`.

This change fixes those collectors, documents verification per provider segment, and records why **Cursor Composer** cannot appear in the same gateway-backed `/model` menu without a separate dual-routing design.

## 2. Goals

1. Antigravity models show real remaining quota (prefer summary pools with weekly + 5h).
2. Grok models show remaining percent (including the omitted-percent ⇒ 0% used case).
3. Never present context length as quota.
4. Keep Codex / Cursor usage paths working.
5. Document segment boundaries and Composer non-goals clearly for operators.

## 3. Non-goals

- Routing Cursor Composer (or any Cursor model) through the mixed CLIProxy picker.
- Changing CLIProxyAPI upstream behavior.
- Scraping grok.com browser cookies or implementing full gRPC-web protobuf parsing (REST credits path is sufficient when period-omission ⇒ 0% used).
- Altering single-provider launcher UX beyond shared usage helpers.

## 4. Defects and evidence

### 4.1 Antigravity

- Auth JSON included `project_id`.
- `POST https://daily-cloudcode-pa.googleapis.com/v1internal:retrieveUserQuota` **without** `User-Agent: antigravity` → HTTP 403 `SUBSCRIPTION_REQUIRED`.
- Same call **with** `User-Agent: antigravity` → 200 and per-model buckets.
- `retrieveUserQuotaSummary` (sandbox/daily/prod) returns Gemini vs Claude/GPT pools with `remainingFraction` for `weekly` and `5h`.

### 4.2 Grok

- Live `GET …/v1/billing?format=credits` returned `currentPeriod` + `isUnifiedBillingUser` but **no** `creditUsagePercent`.
- Collector left `remainingPercent: null` and stuffed `context_length` into `window`, so labels became `grok-4.6 - Grok | 500000 ctx`.
- CodexBar / xAI convention: parseable current period with omitted percent ⇒ **0% used**.

### 4.3 Composer

- `claudey models cursor` lists Composer with Cursor usage successfully.
- Mixed picker (`picker-gateway.js`) only accepts `GATEWAY_PROVIDERS` and forwards to CLIProxy.
- Session settings set `enforceAvailableModels: true` to gateway IDs only.

## 5. Design

### 5.1 Antigravity collector

1. Always send `user-agent: antigravity`.
2. Try `retrieveUserQuotaSummary` on:
   - `daily-cloudcode-pa.sandbox.googleapis.com`
   - `daily-cloudcode-pa.googleapis.com`
   - `cloudcode-pa.googleapis.com`
3. Build pool extras named `gemini`, `claude`, `gpt` with dual `windows` (`7d`, `5h`).
4. `usageForModel` matchExtra associates catalog ids via includes/family matching.
5. `formatUsageLine` renders dual windows as `61%/7d · 100%/5h`.
6. Fallback: `retrieveUserQuota` per-model buckets if summary yields nothing.

### 5.2 Grok collector

1. Send `x-xai-token-auth: xai-grok-cli` on CLI-proxy calls.
2. Resolve used percent: explicit `creditUsagePercent` → on-demand ratio → **0** when `currentPeriod` is present.
3. Convert to remaining with existing `remainingFromUsedPercent`.
4. Model extras inherit remaining percent and period window only (no ctx window).

### 5.3 Composer boundary

Documented only. Future dual-routing would be a new design (picker catalog + non-CLIProxy upstream for Cursor-owned ids).

### 5.4 Adjacent hardening in the same delivery

- POSIX `safeCwd` gated on `process.platform === 'win32'`.
- Claude binary resolution expands symlink candidates.
- Release tarball content-types include `application/x-gtar`.
- `CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST=1` on child env and session settings.

## 6. Tests

- `test/unit/providers/usage.test.js`
  - Antigravity summary + user-agent
  - Antigravity per-model fallback
  - Dual-window label formatting
  - Grok omitted `creditUsagePercent` ⇒ 100% left; no ctx in label
- Existing Claude / picker-gateway tests updated for label separators and `availableModels`.

## 7. Operator instructions

See [Usage labels and the mixed model picker](../../usage-and-model-picker.md) for per-segment verify commands and failure tables.

## 8. Acceptance

- [x] Antigravity live usage shows pool percents, not `unavailable`.
- [x] Grok live usage shows `% left`, not ctx / bare `7d`.
- [x] Unit tests for both collectors pass.
- [x] Composer gap documented; not falsely advertised in mixed `/model`.
- [x] README + troubleshooting point at the usage guide.
