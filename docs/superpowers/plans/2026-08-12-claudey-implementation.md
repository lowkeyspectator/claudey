# Claudey Cross-Platform Gateway and Cursor Bridge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a zero-runtime-dependency, per-user `claudeyctl` manager that safely installs and operates CLIProxyAPI for Codex and Antigravity, launches Claude Code through live-selected models, and optionally exposes Cursor Agent through constrained Claude Code MCP tools on six native OS/architecture targets.

**Architecture:** A dependency-injected ESM Node.js core owns contracts, secure state, verified releases, lifecycle, provider discovery, and launch orchestration. Platform adapters exclusively own OS-specific paths, permissions, archives, processes, and PATH mutation. Cursor is a separately gated bridge using authenticated manager identity, read-only snapshots by default, and approval-bound Git worktrees for writes. Thin POSIX scripts and reproducibly built Windows native shims forward arguments without reconstructing shell commands.

**Tech Stack:** Node.js 22.20.0+ on an upstream-supported release line, ESM, Node standard library only at runtime, `node:test`, PowerShell 5.1+ helpers on Windows, system `tar` on POSIX, CMake/MSVC for Windows launcher builds, GitHub Actions.

## Global Constraints

- Preserve every invariant and acceptance criterion in `docs/superpowers/specs/2026-08-12-claudey-cross-platform-design.md`; stop and revise the spec when an upstream capability contradicts it.
- Do not install or replace a command named `claude`. Install only `claudey`, `claudeyctl`, `claude-codex`, `claude-agy`, and `claude-grok`; proxy variables exist only in the launched Claude child.
- Use no npm runtime dependencies. All subprocess calls use an absolute verified executable, discrete argument array, `shell: false`, bounded I/O, and a timeout.
- Bind CLIProxyAPI exactly to `127.0.0.1`; require a generated 256-bit bearer token; use a different 256-bit secret for manifest HMAC and approval-key derivation.
- Never log, serialize, back up outside the protected root, or forward gateway tokens, manifest secrets, OAuth content, or credential canaries.
- Accept only `win32`, `darwin`, or detected glibc Ubuntu/Debian `linux`, with `x64` or `arm64`. WSL is an independent Linux installation. Unsupported targets fail before a persistent write.
- Map release assets exactly: `windows_amd64.zip`, `windows_aarch64.zip`, `darwin_amd64.tar.gz`, `darwin_aarch64.tar.gz`, `linux_amd64.tar.gz`, and `linux_aarch64.tar.gz`, with prefix `CLIProxyAPI_<version-without-v>_`; never select `_no-plugin`.
- Enforce archive limits: 256 MiB compressed, 2,048 entries, 512 MiB expanded total, 256 MiB per entry, 100:1 expansion ratio, and a two-minute extraction deadline. Reject traversal, links, reparse points, devices, duplicate executable entries, and post-extraction escapes.
- Make every mutation transactional and lock-protected. Validate canonical containment and absence of links/reparse points immediately before each write, rename, restore, or delete. Uninstall only authenticated-manifest entries within fixed managed roots.
- Verify a gateway by authenticated `GET /v1/models`, process identity, configured host/port, executable/config canonical paths, installation UUID, start time, and nonce. Never adopt or signal an unrelated PID/listener.
- Discover model catalogs live. Filter gateway models by exact `owned_by`; validate a chosen model before starting Claude or Cursor; ship no fallback catalog.
- Cursor ask/plan operate on disposable snapshots and are untrusted output. Cursor write delegation is absent by default and requires persistent opt-in plus a new interactive, five-minute, single-use approval bound to exact repository, base commit, normalized prompt digest, model, and installation UUID.
- Cursor children receive a minimal allowlisted environment with gateway, Anthropic, OpenAI, Google, GitHub, cloud, Claude-session, and `CURSOR_API_KEY` values removed. MCP refuses all tools unless the Claude subprocess scrub contract is present and independently verified.
- JSON mode emits exactly one schema-versioned success or error envelope on stdout. Human progress goes to stderr. Public error codes and exit classes in the spec are stable.
- Every production behavior starts with a focused test that is run and observed failing for the intended reason. Implement only enough to pass, then run the focused tests and the relevant aggregate suite with pristine output.
- Parallel implementers use distinct Git worktrees and disjoint ownership. Shared contract/router files are changed only by the integration controller. Every packet is committed, receives task-scoped spec/quality review, and is re-reviewed after fixes before integration.
- A fixture or fake is never reported as a live upstream test. Authenticated browser/model/inference checks remain opt-in, redact secrets, enforce caps, and report unavailable credentials or capabilities honestly.

## Public contracts fixed before parallel work

```js
// src/core/errors.js
export class ClaudeyError extends Error {
  constructor(code, message, { hint, details = {}, cause } = {})
}
export function exitCodeFor(error) {}

// src/core/result.js
export const ok = (result) => ({ ok: true, schemaVersion: 1, result });
export const failEnvelope = (error) => ({
  ok: false, code: error.code, message: error.message,
  ...(error.hint ? { hint: error.hint } : {}), details: error.details ?? {}
});

// src/platform/index.js
export async function detectPlatform(deps) {}
export function getManagedPaths(platform, env) {}
export function getPlatformAdapter(platform, deps) {}

// src/core/release.js and src/core/archive.js
export function resolveReleaseAsset({ version, platform }) {}
export async function resolveRelease({ requestedVersion, http }) {}
export async function downloadVerifiedRelease(release, asset, stagingRoot, deps) {}
export async function validateArchive(archivePath, kind, limits, adapter) {}
export async function extractValidatedArchive(plan, stagingDir, adapter) {}

// src/core/manifest.js and src/core/config.js
export async function loadVerifiedManifest(paths, secret, deps) {}
export async function writeManifest(manifest, secret, paths, deps) {}
export function planOwnedRemoval(manifest, paths, options) {}
export function buildGatewayConfig({ port, authDir, token }) {}

// src/core/lifecycle.js
export async function ensureGatewayHealthy(ctx) {}
export async function startOwnedGateway(ctx, { foreground = false } = {}) {}
export async function stopOwnedGateway(ctx) {}
export async function verifyOwnedProcess(runtimeRecord, adapter) {}

// src/providers/models.js and src/providers/claude.js
export async function listProviderModels(provider, ctx) {}
export async function assertLiveModel(provider, modelId, ctx) {}
export async function launchClaude({ provider, model, claudeArgs }, ctx) {}

// src/cursor/service.js
export async function resolveCursorExecutable(env, paths, deps) {}
export async function probeCursorCapabilities(executable, deps) {}
export async function listCursorModels(executable, capabilities, deps) {}
export async function runCursor({ executable, cwd, mode, model, prompt, env, limits }, deps) {}
export function normalizePromptForApproval(prompt) {}
export async function createSnapshot({ root, paths, limits }, deps) {}
export async function createApproval(binding, deps) {}
export async function consumeApproval(approvalId, expectedBinding, deps) {}
export async function createDelegatedWorktree({ repository, baseCommit, runId }, deps) {}
export async function runCursorMcpServer({ sourceRoot, installationId, managerRoot }, deps) {}
```

Cursor boundaries use these stable schema-1 records and reject unknown fields:

```js
// Canonical paths are absolute, link-free strings revalidated at use time.
const RegisteredRoot = {
  schemaVersion: 1, installationId, canonicalPath, gitCommonDir,
  scope: 'user' /* or 'local' */, registeredAt
};

const DisposableSnapshot = {
  snapshotId, canonicalRoot, sourceRoot, fileCount, totalBytes,
  sourceFingerprint, dispose: async () => {}
};

const ApprovalBinding = {
  schemaVersion: 1, approvalId, installationId,
  repositoryCanonicalPath, baseCommit, model,
  normalizedPromptSha256, expiresAt
};

const WorktreeRequest = {
  repositoryCanonicalPath, baseRef: null, model, prompt, approvalId: null
};

const WorktreeResult = {
  canonicalPath, branch, baseCommit, porcelain,
  diff: { files, insertions, deletions, truncated }, sharedMetadata
};

const McpToolRequest = {
  jsonrpc: '2.0', id: 1, method: 'tools/call',
  params: { name: 'cursor_ask', arguments: { prompt, model, paths: [] } }
};
```

`normalizePromptForApproval` requires a JavaScript string with no NUL, encodes its exact scalar sequence as UTF-8, and performs no Unicode or newline normalization. The same function produces the stored digest and the consumption-time digest, so changing CRLF/LF, spacing, or normalization form invalidates an approval.

## Command contract matrix

Task 1 parser fixtures enumerate these exact forms; later command tasks bind behavior to them. Global `--json`, `--no-color`, `--verbose`, and `--non-interactive` may appear before or after a management subcommand but never after a launcher delimiter. `CI=true` implies noninteractive. `--yes` confirms only predictable local mutation, never OAuth or Cursor per-run approval.

| Command | Accepted command-specific options/operands |
|---|---|
| `setup` | `--version VERSION`, `--port PORT`, `--with-cursor`, `--no-start`, `--no-path`, `--yes` |
| `install` | `--version VERSION`, `--port PORT`, `--yes` |
| `auth codex` | mutually exclusive `--device-code` / `--no-browser`, `--callback-port PORT` |
| `auth antigravity` | `--no-browser`, `--callback-port PORT` |
| `start` | `--foreground` |
| `stop`, `restart` | no command-specific options |
| `status`, `doctor` | optional global `--json` |
| `update` | mutually exclusive `--check` / `--version VERSION`, `--yes` only for mutation |
| `rollback` | `--version VERSION`, `--yes` |
| `models` | optional `codex`, `antigravity`, `cursor`, or `all`; optional global `--json` |
| `config set port` | `PORT`, `--yes` |
| `cursor enable`, `cursor disable` | `--scope user` or `--scope local` |
| `cursor install` | `--yes` |
| `cursor login` | no command-specific options |
| `cursor repo add`, `cursor repo remove` | optional `PATH` |
| `cursor repo list` | no command-specific options |
| `cursor writes enable` | required `--yes` |
| `cursor writes disable` | no command-specific options |
| `cursor approve` | required `APPROVAL_ID`; interactive TTY confirmation only |
| `uninstall` | `--dry-run`, `--purge-auth`, `--yes` |
| `claudey`, `claude-codex`, `claude-agy`, `claude-grok` | mutually exclusive `--model MODEL` / `--select` / `--yolo`; Claude args only after `--` |

## Windows helper protocol contract

Each helper accepts a single versioned JSON request file path and writes exactly one invariant-culture UTF-8 JSON object to stdout; stderr is diagnostic only and cannot drive safety decisions. The Node caller resolves fixed system `powershell.exe`, passes `-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File <bundled-absolute-script> -RequestPath <private-absolute-json>`, caps output, applies a two-minute timeout, validates schema/unknown fields, and maps missing/malformed/localized output to `PREREQUISITE_MISSING` or `CAPABILITY_UNSUPPORTED`.

| Helper | Request operation | Required response identity |
|---|---|---|
| `security-helper.ps1` | `applyDacl`, `inspectDacl`, `inspectReparse` | canonical path, owner SID, protected flag, normalized ACEs, reparse flag/tag |
| `archive-helper.ps1` | `inspectZip`, `extractZip` | archive/staging canonical paths, entry metadata/count/bytes, elapsed milliseconds |
| `process-helper.ps1` | `inspectProcess`, `listDescendants`, `signalProcess` | PID, creation time, executable path, parent PID/tree, action outcome |

## Installed launcher artifact matrix

| Source artifact | Installed name | Platform | Ownership/hash/version rule |
|---|---|---|---|
| `bin/claudeyctl.js` | manager entry under versioned manager payload | all | manifest-owned, payload SHA-256 and manager version |
| `bin/claudeyctl`, `bin/claudey`, `bin/claude-codex`, `bin/claude-agy`, `bin/claude-grok` templates | same basenames in user bin | macOS/Linux/WSL | rendered only with fixed absolute Node/manager paths; manifest-owned and hashed |
| one native shim binary from `native/windows-shim` | `claudeyctl.exe`, `claudey.exe`, `claude-codex.exe`, `claude-agy.exe`, `claude-grok.exe` | Windows x64/ARM64 | identical target-specific bytes copied under five names; project-release hash, capture self-test, manager compatibility version |

Launchers read current managed config/port at runtime through the manager entry. No launcher bakes in port `8317` or a bearer token.

The integration controller owns changes to `package.json`, `src/core/schema.js`, `src/platform/index.js`, `src/cli/main.js`, and shared test-support contracts after Task 1.

---

### Task 1: Repository foundation, public contracts, and test harness

**Dependencies:** None. This is the serial root task.

**Files:**

- Create: `package.json`, `.gitignore`, `LICENSE`
- Create: `bin/claudeyctl.js`
- Create: `src/core/errors.js`, `src/core/result.js`, `src/core/secrets.js`, `src/core/schema.js`, `src/core/limits.js`
- Create: `src/cli/parse.js`, `src/cli/output.js`, `src/cli/main.js`
- Create: `scripts/check.mjs`
- Create: `test/unit/core/errors.test.js`, `test/unit/core/secrets.test.js`, `test/unit/cli/parse.test.js`, `test/unit/cli/output.test.js`
- Create: `test/support/{clock,http,spawner,terminal,temp-home,canary}.js`

- [ ] Write parser table tests for every row and option in the Command contract matrix, including mutual exclusions, missing operands, duplicate options, global-flag placement, `CI=true`, `--yes` limitations, launcher delimiters, integer port range `1024..65535`, normalized versions `7.2.130`/`v7.2.130`, and unknown option rejection.
- [ ] Run `node --test test/unit/cli/parse.test.js`; record RED as a missing-module failure. Implement only the table-driven management/launcher parsers and re-run it GREEN.
- [ ] Write tests for the exact schema-1 success/error envelopes, every documented error-to-exit mapping, one-stdout-envelope JSON discipline, and `Secret` refusal from JSON, inspection, string coercion, structured clone, and error details. Add prompt-normalization tests proving exact UTF-8 preservation and digest changes for CRLF/LF, whitespace, and Unicode normalization forms.

```js
test('Secret cannot cross serialization boundaries', () => {
  const secret = Secret.fromBytes(Buffer.alloc(32, 0x5a));
  assert.throws(() => JSON.stringify({ secret }), /SECRET_SERIALIZATION_REFUSED/);
  assert.throws(() => String(secret), /SECRET_ACCESS_REFUSED/);
  assert.equal(secret.withValue((value) => value.length), 32);
});

test('launcher requires a delimiter before Claude arguments', () => {
  assert.throws(
    () => parseLauncherArgs(['--model', 'gpt-test', '--verbose']),
    (error) => error.code === 'USAGE_ERROR'
  );
  assert.deepEqual(parseLauncherArgs(['--model', 'gpt-test', '--', '--verbose']), {
    model: 'gpt-test', select: false, claudeArgs: ['--verbose']
  });
});
```

- [ ] Run `node --test test/unit/core/errors.test.js test/unit/core/secrets.test.js test/unit/cli/output.test.js`; record RED as missing-module failures.
- [ ] Implement the remaining contracts above. `Secret` stores bytes in a private field, exposes only callback-scoped access, wipes owned buffers when disposed, and throws stable safety errors for serialization/coercion/inspection.
- [ ] Add `package.json` with `"type": "module"`, `"engines": { "node": ">=22.20.0" }`, no `dependencies`, and scripts `check`, `test`, `test:unit`, `test:integration`, `test:e2e:fixtures`, and `test:e2e:live`. `scripts/check.mjs` verifies syntax/imports, executable headers, JSON files, forbidden runtime dependencies, forbidden launcher names, and secret canary absence without rewriting files.
- [ ] Re-run the focused command, then `npm.cmd run check` and `npm.cmd test`; record GREEN and commit `feat: establish claudey contracts and test harness`.

### Task 2: Platform support detection, managed paths, and asset mapping

**Dependencies:** Task 1. **Parallel wave A; owns only the files below.**

**Files:**

- Create: `src/platform/detect.js`, `src/platform/asset-map.js`, `src/platform/linux.js`, `src/platform/macos.js`, `src/platform/windows.js`, `src/platform/index.js`, `src/core/paths.js`
- Create: `test/unit/platform/detect.test.js`, `test/unit/platform/asset-map.test.js`, `test/unit/platform/paths.test.js`
- Create: `test/fixtures/platform/*.json`, `test/fixtures/platform/os-release/*`

- [ ] Add and RED-run `asset-map.test.js` for the exact names `CLIProxyAPI_7.2.130_windows_amd64.zip`, `CLIProxyAPI_7.2.130_windows_aarch64.zip`, `CLIProxyAPI_7.2.130_darwin_amd64.tar.gz`, `CLIProxyAPI_7.2.130_darwin_aarch64.tar.gz`, `CLIProxyAPI_7.2.130_linux_amd64.tar.gz`, and `CLIProxyAPI_7.2.130_linux_aarch64.tar.gz`, leading-`v` normalization, `_no-plugin` exclusion, and unsupported combinations. Implement only `resolveReleaseAsset`; re-run GREEN.
- [ ] Add and RED-run `detect.test.js` for runtime/native mismatch reporting, Windows 10 1809+, macOS 13+, Ubuntu 20.04+/Debian 10+ glibc, musl/unknown distro refusal, WSL identity, and runtime-architecture selection. Implement only pure platform detection; re-run GREEN.
- [ ] Add and RED-run `paths.test.js` with exact roots: Windows `%LOCALAPPDATA%\\claudeyctl` manager/state/bin and `%APPDATA%\\claudeyctl` config/auth; macOS `~/Library/Application Support/claudeyctl` manager/config/auth/state and `~/.local/bin`; Linux/WSL XDG data/config/state fallbacks plus `~/.local/bin`. Assert WSL never selects mounted Windows state. Implement only path derivation; re-run GREEN.
- [ ] Re-run focused tests and `npm.cmd test`; commit `feat: detect supported platforms and release assets`.

### Task 3: Canonical filesystem, permissions, lock, and mutation primitives

**Dependencies:** Task 1. **Parallel wave A.**

**Files:**

- Create: `src/core/fs-safe.js`, `src/core/permissions.js`, `src/core/lock.js`
- Create: `src/platform/posix.js`, `src/platform/windows-helpers.js`
- Create: `scripts/windows/security-helper.ps1`
- Create: `test/unit/core/fs-safe.test.js`, `test/unit/core/permissions.test.js`, `test/unit/core/lock.test.js`
- Create: `test/integration/permissions-native.test.js`

- [ ] RED-run `fs-safe.test.js` for `..`, absolute child input, drive switching, UNC, NUL/CR/LF, symlink/junction/reparse, case-folding, link swap, and root/home/repository denial. Implement `canonicalize`, `lstatNoFollow`, containment, and immediate mutation recheck; re-run GREEN.
- [ ] RED-run `permissions.test.js` for atomic writes, POSIX `0700`/`0600`/`0755`, and the exact Windows helper JSON/DACL/reparse contract. Implement `assertProtected`, `atomicReplace`, and the helper adapter; re-run GREEN.
- [ ] RED-run `lock.test.js` for contention, installation/process owner identity, malformed records, and injected-clock stale-lock recovery/refusal. Implement the `openExclusive` lock lifecycle; re-run GREEN.
- [ ] Re-run focused and full tests; commit `feat: add safe filesystem and installation lock primitives`.

### Task 4: Authenticated manifest, deterministic gateway config, journal, and transactions

**Dependencies:** Tasks 1 and 2. **Parallel wave A after Task 2 API is fixed.**

**Files:**

- Create: `src/core/manifest.js`, `src/core/config.js`, `src/core/journal.js`, `src/core/transaction.js`
- Create: `test/unit/core/manifest.test.js`, `test/unit/core/config.test.js`, `test/unit/core/journal.test.js`, `test/unit/core/transaction.test.js`

- [ ] RED-run `manifest.test.js` for 32-byte independent secrets, token preservation, constant-time HMAC verification, schema/UUID/file-hash ownership, fixed roots, OAuth exclusion, modified-file preservation, and canary absence. Implement manifest read/write/removal planning; re-run GREEN.
- [ ] Assert the serialized config is exactly:

```yaml
host: "127.0.0.1"
port: 8317
tls:
  enable: false
remote-management:
  allow-remote: false
  secret-key: ""
  disable-control-panel: true
auth-dir: "<escaped protected path>"
api-keys:
  - "<local bearer token>"
debug: false
commercial-mode: true
logging-to-file: false
usage-statistics-enabled: false
pprof:
  enable: false
plugins:
  enabled: false
ws-auth: true
```

- [ ] Add deterministic config fixtures for ports `1024`, `8317`, and `65535`, platform-specific auth-path escaping, and invalid ports. Assert only the requested port line differs and no launcher contains a port or secret.
- [ ] RED-run `config.test.js` for the exact/default/boundary/custom configs above. Implement deterministic restricted YAML emission (not a general YAML parser); re-run GREEN.
- [ ] RED-run `journal.test.js` and `transaction.test.js` for journal phases, interrupted recovery, reverse restoration order, committed cleanup, and injected failures. Implement the journal state machine and transaction checkpoints; re-run GREEN. Manifest authentication and canonical roots are both required before removal planning.
- [ ] Re-run focused and full tests; commit `feat: authenticate managed state and transactions`.

### Task 5: Release resolution, HTTPS policy, and checksum verification

**Dependencies:** Tasks 1 and 2. **Parallel wave A.**

**Files:**

- Create: `src/core/release.js`, `src/core/checksum.js`
- Create: `test/unit/core/release.test.js`, `test/unit/core/checksum.test.js`
- Create: `test/support/release-server.js`, `test/fixtures/releases/*`

- [ ] RED-run `release.test.js` for explicit/latest non-prerelease resolution, baseline `7.2.130`, exact URLs, HTTPS official-host allowlist, bounded revalidated redirects, byte caps, deadlines, abort, and partial cleanup. Implement injectable streaming `Http` and release descriptors; re-run GREEN.
- [ ] RED-run `checksum.test.js` for exact filename, exactly one 64-hex digest, upper/lower hex, mismatch before extraction, and secret-safe errors. Implement checksum parsing/SHA-256 verification; re-run GREEN. Never execute or extract unverified bytes.
- [ ] Re-run focused and full tests; commit `feat: verify official CLIProxyAPI releases`.

### Task 6: Archive preflight and safe native extraction

**Dependencies:** Tasks 2, 3, and 5. **Parallel wave B.**

**Files:**

- Create: `src/core/archive.js`, `scripts/windows/archive-helper.ps1`
- Create: `test/unit/core/archive.test.js`, `test/integration/archive-extraction.test.js`
- Create: `test/fixtures/archives/*`, `test/support/archive-fixtures.js`

- [ ] RED-run `archive.test.js` with valid ZIP/TAR.GZ plus absolute/traversal, separators, Unicode collision, symlink/hard-link/reparse/device/FIFO/sparse, duplicate/missing executable, malformed header, size disagreement, and every numeric limit. Implement streaming ZIP central/local-header and TAR/PAX preflight producing an immutable plan; re-run GREEN.
- [ ] RED-run `archive-extraction.test.js` for helper/schema refusal, private same-filesystem staging, timeout, link swap, post-walk escape/type/duplicate checks, and candidate identity. Implement extraction through only the fixed PowerShell helper or absolute system `tar`, then mandatory post-walk; re-run GREEN.
- [ ] Re-run focused and full tests; commit `feat: preflight and safely extract release archives`.

### Task 7: Prerequisites, executable identity, and upstream capability probes

**Dependencies:** Task 1. **Parallel wave B.**

**Files:**

- Create: `src/core/prerequisites.js`, `src/core/executable.js`, `src/providers/capabilities.js`
- Create: `test/unit/core/prerequisites.test.js`, `test/unit/core/executable.test.js`, `test/unit/providers/capabilities.test.js`
- Create: `test/fixtures/bin/fake-cliproxy.js`, `test/fixtures/bin/fake-claude.js`, `test/fixtures/bin/fake-cursor-agent.js`

- [ ] RED-run `prerequisites.test.js` for Node `22.20.0` floor/supported-line policy, system `tar`, Git, and strict PowerShell helper protocol. Implement prerequisite policy only; re-run GREEN.
- [ ] RED-run `executable.test.js` for native precedence, known npm-shim structural resolution, absolute identities, hostile PATH, and unknown `.cmd`/`.bat`/`.ps1` rejection. Implement `resolveVerifiedExecutable` separately from version parsing; re-run GREEN.
- [ ] RED-run `capabilities.test.js` for Claude `2.1.229`, CLIProxyAPI `7.2.130`, exact login/config/version/model and Claude model/plugin/MCP/environment capabilities, fixed argv, strict output, and timeout. Implement probes returning per-capability results; re-run GREEN.
- [ ] Re-run focused and full tests; commit `feat: probe required upstream capabilities`.

### Task 8: Gateway client, process identity, port ownership, and lifecycle

**Dependencies:** Tasks 3, 4, and 7. **Parallel wave B.**

**Files:**

- Create: `src/core/gateway-client.js`, `src/core/process.js`, `src/core/port.js`, `src/core/lifecycle.js`
- Create: `scripts/windows/process-helper.ps1`
- Create: `test/unit/core/gateway-client.test.js`, `test/unit/core/process.test.js`, `test/unit/core/port.test.js`, `test/unit/core/lifecycle.test.js`
- Create: `test/integration/gateway-lifecycle.test.js`, `test/support/fake-gateway.js`

- [ ] Test bearer-required `/v1/models`, wrong-token rejection, empty pre-auth catalog, invalid schema, non-loopback configuration, occupied listener, owned listener, start twice/stop twice, startup timeout, child early exit, stale PID, forged record, PID reuse, executable/config mismatch, inaccessible identity data, unrelated descendants, exact process-tree termination, and no lingering child after cancellation.
- [ ] Use this complete runtime record:

```js
{
  schemaVersion: 1,
  installationId,
  instanceId,
  pid,
  processGroupId,
  processStartTime,
  executableCanonicalPath,
  configCanonicalPath,
  version,
  host: '127.0.0.1',
  port,
  nonce,
  readinessIdentity,
  lastSuccessfulReadinessAt
}
```

- [ ] RED-run `gateway-client.test.js` for authenticated schema/readiness cases; implement only the bounded loopback client; re-run GREEN.
- [ ] RED-run `process.test.js` and `port.test.js` for PID/start/executable/config/process-group/listener identity and reuse/collision cases; implement only identity/port comparison; re-run GREEN.
- [ ] RED-run `lifecycle.test.js` and `gateway-lifecycle.test.js` for start/stop/restart/foreground/readiness/timeout/idempotency. Implement atomic runtime records and bounded graceful then forced termination of only the verified tree; re-run GREEN. Missing identity information refuses signaling with `PROCESS_IDENTITY_MISMATCH`.
- [ ] Re-run focused and full tests; commit `feat: manage only an authenticated owned gateway`.

### Task 9: Install, setup, activation, update, rollback, and port reconfiguration

**Dependencies:** Tasks 2 through 8, 11, and 12. Task 12 supplies `stageLaunchers(...)`. **Serial integration task after launcher artifacts exist.**

**Files:**

- Create: `src/core/activation.js`
- Create: `src/cli/commands/install.js`, `src/cli/commands/setup.js`, `src/cli/commands/update.js`, `src/cli/commands/rollback.js`, `src/cli/commands/config.js`, `src/cli/commands/lifecycle.js`
- Create: `test/integration/install.test.js`, `test/integration/setup.test.js`, `test/integration/update-rollback.test.js`, `test/integration/config-port.test.js`

- [ ] Test the exact transaction: lock, preflight, release resolution, verified download, safe extraction, candidate capability probe, token/UUID preserve-or-create, config/launcher stage, atomic active pointer, PATH intent, optional plugin intent, prior running-state capture, authenticated start/readiness, manifest commit, journal commit, lock release.
- [ ] Inject failures after download, extraction, candidate probe, config stage, activation, spawn, and readiness. Assert old binary/config/token/active pointer/running state are restored; candidate readiness failure reports `UPDATE_ROLLED_BACK`; one rollback point is retained and consumed exactly once; a repeated default rollback returns `ROLLBACK_UNAVAILABLE`, exit 8, without mutation.
- [ ] Test `install` does not alter PATH, authenticate, start a stopped gateway, or change Cursor; `setup` is idempotent, adds one PATH intent, and starts unless `--no-start`; `update --check` is read-only and exit 0; port changes preserve previous running/stopped state and reject occupied ports before config mutation.
- [ ] RED-run `install.test.js` and `setup.test.js`; implement install/setup transaction composition only; re-run GREEN.
- [ ] RED-run `update-rollback.test.js`; implement update and single-use rollback checkpoints only; re-run GREEN.
- [ ] RED-run `config-port.test.js`; implement port reconfiguration only; re-run GREEN. Command modules use injected services and do not import raw filesystem/network/process globals.
- [ ] Re-run focused and full tests; commit `feat: transact gateway installation and rollback`.

### Task 10: PATH mutation and ownership-safe uninstall

**Dependencies:** Tasks 3, 4, 8, and 9. **Parallel wave C.**

**Files:**

- Create: `src/core/path-mutation.js`, `src/cli/commands/uninstall.js`
- Create: `test/unit/core/path-mutation.test.js`, `test/integration/uninstall.test.js`

- [ ] RED-run `path-mutation.test.js` for Windows per-user case-insensitive dedup/exact restoration, POSIX marker blocks, `--no-path`, and current-shell remediation. Implement adapter-based plan/apply/restore; re-run GREEN.
- [ ] RED-run `uninstall.test.js` for authenticated manifest, out-of-root refusal, changed/OAuth/unlisted/dirty-worktree/unknown-plugin preservation, dry-run reasons, purge confirmations/root denial, interruption recovery, and repeat no-op. Implement removal planning and identity-verified stop with immediate target recheck; re-run GREEN.
- [ ] Re-run focused and full tests; commit `feat: reverse PATH and uninstall owned files safely`.

### Task 11: Provider authentication and live model discovery

**Dependencies:** Tasks 7 and 8. **Parallel wave C.**

**Files:**

- Create: `src/providers/auth.js`, `src/providers/models.js`
- Create: `src/cli/commands/auth.js`, `src/cli/commands/models.js`
- Create: `test/unit/providers/auth.test.js`, `test/unit/providers/models.test.js`
- Create: `test/integration/auth.test.js`, `test/integration/models.test.js`

- [ ] RED-run auth unit/integration files for fixed Codex browser/device/no-browser and Antigravity browser/no-browser argv after probes, callback validation, no secret argv, CI/noninteractive/TTY refusal, exit/signal relay, and no simulated success. Implement auth descriptors/orchestration; re-run GREEN.
- [ ] RED-run model unit/integration files for response schema, exact `owned_by`, no heuristics, dedupe/sort, pre-spawn rejection, auth distinction, no fallback, and partial `all`. Implement authenticated filtering/assertion for gateway providers; re-run GREEN. Cursor routing waits for Task 16.
- [ ] Re-run focused and full tests; commit `feat: authenticate providers and discover live models`.

### Task 12: Claude Code launcher orchestration and POSIX launchers

**Dependencies:** Tasks 1, 7, 8, and 11. **Parallel wave C.**

**Files:**

- Create: `src/providers/claude.js`, `src/cli/launchers/claudey.js`, `src/cli/launchers/claude-codex.js`, `src/cli/launchers/claude-agy.js`, `src/cli/launchers/claude-grok.js`
- Create: `bin/claudey`, `bin/claude-codex`, `bin/claude-agy`, `bin/claude-grok`, `bin/claudeyctl`
- Create: `test/unit/providers/claude.test.js`, `test/unit/cli/launchers.test.js`, `test/integration/claude-launcher.test.js`
- Extend: `test/fixtures/bin/fake-claude.js`

- [ ] Test interactive live selector, noninteractive `MODEL_REQUIRED`, noninteractive `--select` refusal, live provider/model validation before Claude spawn, rejection of forwarded `--model`, `--model=`, aliases, and conflicting environment. Preserve discrete arguments for empty string, spaces, Unicode, quotes, backslashes, leading dashes, semicolon, ampersand, pipe, backticks, `$()`, `%VAR%`, CR, and LF.
- [ ] Assert ambient `ANTHROPIC_BASE_URL`, `ANTHROPIC_AUTH_TOKEN`, and `ANTHROPIC_API_KEY` are removed/replaced, all other documented sensitive overrides are scrubbed, and the child receives the safe parent allowlist plus:

```text
ANTHROPIC_BASE_URL=http://127.0.0.1:<managed port>
ANTHROPIC_AUTH_TOKEN=<local bearer token>
CLAUDE_CODE_SUBAGENT_MODEL=<selected model>
CLAUDE_CODE_ALWAYS_ENABLE_EFFORT=1
CLAUDE_CODE_MAX_TOOL_USE_CONCURRENCY=3
CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1
ENABLE_TOOL_SEARCH=false
```

- [ ] Test the selected model is passed to Claude as discrete `--model <id>` arguments in addition to `CLAUDE_CODE_SUBAGENT_MODEL`; test stdio inheritance, stdin flow, signal forwarding, exact child exit code, gateway start-if-needed, parent environment byte-for-byte unchanged before/after, and normal `claude` capture with no project proxy variables.
- [ ] RED-run unit launcher/provider tests for selection, conflicts, child argv/environment, and injection cases. Implement launch orchestration only; re-run GREEN.
- [ ] RED-run integration capture tests for stdio/signals/exit/parent isolation and POSIX templates. Implement templates containing only fixed shebang/absolute installed paths/profile/`"$@"`; re-run GREEN.
- [ ] Re-run focused and full tests; commit `feat: launch Claude through child-scoped provider routing`.

### Task 13: Cursor executable identity, capability probes, models, environment, and runner

**Dependencies:** Tasks 1 and 7. **Parallel wave C; Cursor slice begins here.**

**Files:**

- Create: `src/cursor/executable.js`, `src/cursor/capabilities.js`, `src/cursor/models.js`, `src/cursor/env.js`, `src/cursor/runner.js`
- Create: `test/unit/cursor/executable.test.js`, `test/unit/cursor/capabilities.test.js`, `test/unit/cursor/models.test.js`, `test/unit/cursor/env.test.js`, `test/unit/cursor/runner.test.js`
- Extend: `test/fixtures/bin/fake-cursor-agent.js`

- [ ] RED-run `executable.test.js` for `cursor-agent` precedence, positively identified `agent`, fallback locations, native/known-shim resolution, hostile PATH, and unrelated aliases. Implement Cursor identity resolution; re-run GREEN.
- [ ] RED-run `capabilities.test.js` and `models.test.js` for login/status, current/fallback model command, JSON/stdin/ask/plan/sandbox/worktree probes, per-tool degradation, malformed/empty/duplicate output, sort, and pre-run model rejection. Implement probes/live catalog; re-run GREEN.
- [ ] RED-run `env.test.js` for the explicit forbidden-variable list and minimal allowlist. Implement scrubbed environment; re-run GREEN.
- [ ] RED-run `runner.test.js` for stdin-only prompts, caps/concurrency/timeouts, verified descendant cleanup, canaries, and refusal of arbitrary executable/flags/env/cwd. Implement injected `mode: 'ask' | 'plan' | 'worktree'` runner; re-run GREEN.
- [ ] Re-run focused and full tests; commit `feat: verify and constrain Cursor Agent execution`.

### Task 14: Cursor repository registry and immutable read-only snapshots

**Dependencies:** Tasks 3, 4, and 13. **Parallel wave D.**

**Files:**

- Create: `src/cursor/registry.js`, `src/cursor/snapshot.js`, `src/cursor/service.js`
- Create: `test/unit/cursor/registry.test.js`, `test/unit/cursor/snapshot.test.js`, `test/integration/cursor-readonly.test.js`
- Create: `test/fixtures/git-repos/*`, `test/fixtures/secret-files/*`

- [ ] RED-run `registry.test.js` for canonical Git roots, ownership/scopes/local exemption and home/root/bare/unresolved/link denial. Implement registry add/list/remove; re-run GREEN.
- [ ] RED-run `snapshot.test.js` for tracked/default and explicit untracked selection, `.git`/managed/secret/link/device/outside-root denial, all limits/timeouts, and owned cleanup. Implement same-filesystem snapshot creation; re-run GREEN.
- [ ] RED-run `cursor-readonly.test.js` with aggressive fake writes and before/after files/index/HEAD/branch/refs/untracked fingerprints. Implement ask/plan service and untrusted bounded results; re-run GREEN. Any ambiguous identity produces `SAFETY_REFUSAL`.
- [ ] Re-run focused and full tests; commit `feat: isolate Cursor ask and plan in snapshots`.

### Task 15: Encrypted approvals, safe Git plumbing, and Cursor worktree delegation

**Dependencies:** Tasks 4, 13, and 14. **Parallel wave D.**

**Files:**

- Create: `src/cursor/approval.js`, `src/cursor/git.js`, `src/cursor/worktree.js`
- Create: `test/unit/cursor/approval.test.js`, `test/unit/cursor/git.test.js`, `test/integration/cursor-worktree.test.js`

- [ ] Test random 256-bit approval IDs, five-minute expiry under injected clock, domain-separated key derivation from manifest secret, AES-256-GCM encrypted exact-UTF-8 prompt, authenticated binding metadata, prompt/repo/model/base/installation swaps, one-time atomic consumption/race, replay, disable/uninstall cleanup, ciphertext/backups/logs without canary plaintext, and refusal of approval from non-TTY or `--yes`.
- [ ] Test `cursor approve` presents canonical repository, exact model or `(default)`, resolved base commit, safely escaped bounded prompt preview, full SHA-256 prompt digest, expiry, and installation identity before an explicit TTY confirmation. It persists/logs no plaintext. CRLF/LF, whitespace, or Unicode-normalization changes cannot consume the approval.
- [ ] Test full local-ref/tag enumeration, exact enumerated full ref or full 40/64-hex commit input only, peel-to-commit, `--` terminators, revision injection, options disguised as refs, non-commit objects, links/shared unsafe roots, fixed generated branch/worktree, malicious Git hooks/config isolation, and caller checkout/index/HEAD/tree invariance. After `git worktree add` and immediately before Cursor spawn, `assertWorktreeNoLinks` rejects any symlink, junction, or reparse entry that Git materialized, retains the worktree, and reports only safe metadata.
- [ ] First write request must return `APPROVAL_REQUIRED` and create neither worktree nor branch. Second request consumes an exact approved binding immediately before creation. Cursor failure retains and reports the worktree. The tool never commit/merge/push/copy-back/delete operations; result contains path, branch, base commit, porcelain status, bounded diff metadata, and shared Git metadata created.
- [ ] RED-run `approval.test.js` for cryptography, binding/display/confirmation, expiry, atomic consumption, cleanup, and canaries. Implement approval store/TTY approval; re-run GREEN.
- [ ] RED-run `git.test.js` for refs/commits/injection/hooks/fixed commands and caller invariance. Implement safe Git plumbing; re-run GREEN.
- [ ] RED-run `cursor-worktree.test.js` for two-call approval, post-materialization link scan, run/failure/result/retention, and forbidden operations. Implement writes-disabled setting and worktree orchestration; re-run GREEN.
- [ ] Re-run focused and full tests; commit `feat: gate Cursor writes with bound one-time approvals`.

### Task 16: Cursor MCP server, plugin marketplace, and manager commands

**Dependencies:** Tasks 1, 9, 10, 11, 13, 14, and 15. **Serial Cursor integration task.**

**Files:**

- Create: `src/cursor/mcp-schema.js`, `src/cursor/mcp-server.js`, `src/cli/commands/cursor.js`
- Create: `.claude-plugin/marketplace.json`
- Create: `plugins/cursor-agent/.claude-plugin/plugin.json`, `plugins/cursor-agent/.mcp.json`, `plugins/cursor-agent/server/index.mjs`
- Create: `test/unit/cursor/mcp-schema.test.js`, `test/unit/cursor/mcp-server.test.js`
- Create: `test/integration/cursor-plugin.test.js`, `test/integration/cursor-cli.test.js`

- [ ] Test JSON-RPC 2.0 initialize, notifications, `tools/list`, `tools/call`, parse/schema/unknown-method errors, newline-delimited stdio framing, request/output caps, cancellation, deterministic shutdown, and exactly one response per request. Reject unknown tool fields.
- [ ] Dynamically advertise `cursor_models` only with verified Cursor identity, login, and model-list capability; `cursor_ask` with model list + stdin + JSON + ask and any required available sandbox capability; `cursor_plan` with model list + stdin + JSON + genuine plan and any required available sandbox capability; `cursor_worktree_run` only with persistent opt-in, identity/login/live-model/stdin/JSON/worktree mode, selected-model validation, and Git/approval/worktree safety capabilities. Test each missing capability independently and prove no prompt fallback to argv.
- [ ] The `cursor_worktree_run` descriptor must mark write/destructive behavior and required user interaction using the protocol-version-supported MCP annotations/meta. Assert the emitted descriptor exactly and keep out-of-band approval authoritative even after Claude permission.
- [ ] At server startup require `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1`, explicit absence of `ANTHROPIC_BASE_URL`, `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_API_KEY`, `GOOGLE_APPLICATION_CREDENTIALS`, `GITHUB_TOKEN`, `GH_TOKEN`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AZURE_CLIENT_SECRET`, Claude session variables, CLIProxyAPI credential/path variables, and `CURSOR_API_KEY`; also require authenticated manager manifest/installation UUID and non-link manager/plugin paths. These gates apply to all tools. Canonical current-project/registered-root validation applies per ask/plan/worktree call, not to `cursor_models`.
- [ ] Test the plugin wrapper attempts a no-follow, link-free canonicalization of startup `process.cwd()` without accepting MCP caller input. On success it passes optional `--source-root <canonical-candidate>`; on missing/non-Git/unregistered/link/reparse CWD it omits the candidate but still starts so `cursor_models` works. The manager rejects absent, changed, non-Git, unsafe, or unregistered candidates only when ask/plan/worktree is called. Cover models plus rejected repository tools in the same non-Git session.
- [ ] The wrapper spawns `<absolute-node> <absolute-manager> cursor mcp-serve [--source-root <canonical-candidate>] --installation-id <uuid> --manager-root <verified-manager-root>` with inherited stdio and `shell: false`. Before `tools/list`, the hidden command requires `installationId === verifiedManifest.installationId` and no-follow `canonical(managerRoot) === verifiedManifest.managerRoot`, revalidates the root immediately before use, and rejects a forged UUID, foreign root, link swap, or mismatched manifest. The wrapper never resolves `claudeyctl` through PATH or puts prompt/model in argv.
- [ ] Test manager commands `cursor enable/disable/install/login/repo add|list|remove/writes enable|disable/approve`, plugin UUID ownership collision, user/local idempotency, repeated disable exit-0 behavior, missing prerequisite behavior, explicit Cursor installer warning/confirmation, `models cursor` without gateway start, and use of Claude plugin commands rather than hand-editing Claude settings.
- [ ] RED-run MCP schema/server unit tests for framing, methods, errors, dynamic descriptors, annotations, scrub/identity gates, and repository-independent models. Implement protocol server only; re-run GREEN.
- [ ] RED-run `cursor-plugin.test.js` for wrapper source-root/manifest/path behavior and ownership-safe plugin enable/disable. Implement manifests/forwarder only; re-run GREEN.
- [ ] RED-run `cursor-cli.test.js` for all Cursor commands, approval UX, idempotency, installer warning, and `models cursor`. Implement manager orchestration; re-run GREEN. Results use MCP content plus `structuredContent` and stable project codes.
- [ ] Re-run focused and full tests; commit `feat: expose constrained Cursor tools to Claude Code`.

### Task 17: Doctor, status, command router, and command-level acceptance

**Dependencies:** Tasks 9 through 16. **Serial integration task.**

**Files:**

- Create: `src/cli/commands/status.js`, `src/cli/commands/doctor.js`
- Modify: `src/cli/main.js`, `bin/claudeyctl.js`
- Create: `test/integration/doctor.test.js`, `test/integration/status.test.js`, `test/integration/acceptance-core.test.js`, `test/integration/acceptance-cursor.test.js`

- [ ] Re-run the complete Task 1 command-contract matrix through the wired router and test help text, exact exit classes, JSON single-envelope output, stderr progress, idempotent no-ops, and unknown command/option schemas.
- [ ] Test healthy `status`/`doctor` exit 0 and unhealthy states return their mapped nonzero exit with valid JSON/human output; `update --check` exits 0 for current or update-available; `models all` succeeds only when at least one provider succeeds and reports every provider outcome; zero successful providers returns the mapped error.
- [ ] Doctor must remain read-only while checking supported platform/runtime/native architecture, executable identities/versions, manifest/UUID/hashes, config/bind/auth/permissions, token entropy metadata, process/port/readiness, auth presence without content, model schemas/ownership, PATH, Cursor registration/login/capabilities/write state/pending worktrees, journal, and retained rollback. Test corrupt/unsafe/stale/colliding/missing states and exact remediation commands.
- [ ] Snapshot every injected mutator call in doctor tests and assert zero calls. Run the four focused files; record RED.
- [ ] Wire the router through a dependency container. No command module imports another command or raw environment/global I/O.
- [ ] Re-run focused and full tests; commit `feat: complete management CLI and diagnostics`.

### Task 18: Deterministic manager payload and project release-manifest schema

**Dependencies:** Tasks 1 through 17. **Parallel wave E.**

**Files:**

- Create: `scripts/package.mjs`, `scripts/sbom.mjs`, `schemas/project-release-manifest.schema.json`
- Create: `test/integration/package.test.js`, `test/fixtures/releases/project-manifest.valid.json`

- [ ] RED-run `package.test.js` for a sorted, timestamp-independent manager archive that contains only runtime source, fixed launchers, plugin payload, and license; rejects docs/review/SDD artifacts, undeclared files, secrets, and runtime dependencies; and installs without `npm install`. Documentation is distributed through the repository/release page, not the installed runtime payload.
- [ ] Define and test a schema-1 project manifest with manager version/source revision, payload artifact name/SHA-256/size, x64 and ARM64 shim artifact names/SHA-256/sizes/compiler identities, manager-shim compatibility version, six-target mapping, SBOM name/hash, and provenance subject digests. Unknown/missing fields fail closed. This task creates the schema and payload descriptor only; Task 21 assembles the final manifest after shim artifacts exist.
- [ ] Generate a deterministic SPDX JSON SBOM and descriptor for the payload's source/runtime inventory. Implement payload packaging, SBOM, and descriptor generation; re-run GREEN and `npm.cmd test`, then commit `build: package deterministic manager payloads`.

### Task 19: POSIX launchers and `install.sh`

**Dependencies:** Tasks 12, 18, and 21. **Parallel wave E after the complete manifest.**

**Files:**

- Create: `install.sh`
- Create: `test/integration/bootstrap-posix.test.js`

- [ ] RED-run the POSIX bootstrap test for fixed `--version`, `--yes`, `--no-path`, and `--rollback-manager` parsing; Node floor/supported-line validation; no root; HTTPS project payload/manifest/hash verification; private staging; capture self-test; atomic manager pointer; one previous manager; exact `setup` argv; no OAuth; and no `npm install`.
- [ ] Fix version semantics in tests: bootstrap `--version` selects the manager payload release; after activation, `claudeyctl setup --version` selects the CLIProxyAPI release. Bootstrap never forwards its manager version as the gateway version.
- [ ] Test actual POSIX launcher argument preservation and ShellCheck when available. Implement `install.sh` and rendered launchers with static absolute paths and `"$@"`; re-run GREEN and commit `feat: bootstrap verified POSIX payloads`.

### Task 20: Windows native quoting, launcher shim, and architecture builds

**Dependencies:** Tasks 12 and 18. **Parallel wave E.**

**Files:**

- Create: `native/windows-shim/CMakeLists.txt`, `native/windows-shim/src/main.c`, `native/windows-shim/src/quote.c`, `native/windows-shim/src/quote.h`, `native/windows-shim/test/capture-child.c`
- Create: `scripts/build-windows-shim.ps1`, `test/integration/windows-shim.test.js`

- [ ] RED-run portable quote-vector tests and native capture tests for empty arguments, spaces, Unicode, embedded quotes, every backslash-before-quote/end run, leading dashes, metacharacters, CR/LF, `%VAR%`, and `$()`.
- [ ] Implement one wide-character shim whose basename selects only the three fixed profiles, reads authenticated fixed install metadata, quotes with the documented Microsoft algorithm, calls `CreateProcessW`, and relays stdio/console events/exit status without `cmd.exe`, `.cmd`, `%*`, generated PowerShell, or user-selected executable text.
- [ ] Build x64 on `windows-latest` and ARM64 on `windows-11-arm`, record compiler/flags, run capture-child proof on each, and upload immutable per-architecture artifacts. A local compiler absence may skip only the local native execution test; both CI builds are mandatory. Re-run GREEN and commit `feat: build native Windows launchers`.

### Task 21: Assemble and verify the complete project release manifest

**Dependencies:** Tasks 18 and 20. **Serial artifact join.**

**Files:**

- Create: `scripts/assemble-release-manifest.mjs`, `test/integration/release-manifest.test.js`

- [ ] RED-run `release-manifest.test.js` with payload and both native-shim descriptors. Require real file rehash/size checks, compiler identity, manager-shim compatibility, exact six-target mapping, source revision, SBOM descriptor, and provenance subject digests; reject missing/duplicate/foreign/stale descriptors and any digest mismatch.
- [ ] Implement final schema-1 project-manifest assembly only after both architecture artifacts exist. `provenanceSubjects` enumerates the exact artifact digests Task 25 must attest; it is not an attestation-file digest, so no circular build input exists. The manifest is deterministic, contains no signing secret, and is revalidated by a fresh process before bootstrap consumption. Re-run GREEN and commit `build: assemble verified project release manifest`.

### Task 22: `install.ps1`, manager activation, and manager rollback

**Dependencies:** Tasks 18, 20, and 21. **Parallel wave E after the complete manifest.**

**Files:**

- Create: `install.ps1`, `test/integration/bootstrap-windows.test.js`

- [ ] RED-run PowerShell bootstrap tests for the fixed `-Version`, `-Yes`, `-NoPath`, and `-RollbackManager` schema; Node/PowerShell prerequisites; non-admin operation; project manifest/payload/target-shim verification; private staging; manager/shim compatibility; capture self-test; atomic pointer; exact setup argv array splatting; no OAuth; and interrupted-update restoration.
- [ ] Fix version semantics exactly as Task 19: `-Version` is manager payload version, while a later `claudeyctl setup --version` is CLIProxyAPI version. `-RollbackManager` consumes the retained manager pointer without touching gateway rollback.
- [ ] Implement, exercise under Windows PowerShell 5.1 and current PowerShell in CI, re-run GREEN, and commit `feat: bootstrap and roll back Windows manager payloads`.

### Task 23: Six-target native CI and upstream compatibility workflow

**Dependencies:** Tasks 18 through 22. **Parallel wave F.**

**Files:**

- Create: `ci/node-lanes.json`, `scripts/check-node-lanes.mjs`, `.github/workflows/ci.yml`, `.github/workflows/upstream-compatibility.yml`
- Create: `test/unit/workflows/ci-contracts.test.js`

- [ ] Check in lanes `{ "floor": "22.20.0", "lts": "24.19.0", "current": "26.7.0", "verifiedAt": "2026-08-12", "source": "https://nodejs.org/dist/index.json" }`. RED-run contract tests and fixture-index tests for a deliberate reviewed update path. `scripts/check-node-lanes.mjs --online` compares configured LTS/current to official release data and exits nonzero when stale; scheduled checks report drift without rewriting, while every release invokes the online check as a blocking gate.
- [ ] Require blocking `windows-latest`, `windows-11-arm`, `macos-15-intel`, `macos-15`, `ubuntu-24.04`, and `ubuntu-24.04-arm`, each across all three lanes, with no `continue-on-error`. Windows runs PowerShell 5.1/current; matching Linux jobs run Ubuntu 20.04 and Debian 10 native-architecture baselines; every job runs checks, unit/integration/fixture E2E, bootstrap, native permissions/processes, hostile arguments/paths, failure injection, and canary scan.
- [ ] Pin third-party Actions to immutable commit SHAs, default permissions to read-only, grant no secrets to fork jobs, set bounded artifact retention, and keep ARM preview labels blocking. Implement workflows, validate syntax/contracts, and commit `ci: test all advertised native targets`.

### Task 24: Operations, security, and manual release-validation contracts

**Dependencies:** Tasks 1, 17, 21, and 23. **Parallel wave F before Task 25.**

**Files:**

- Create: `README.md`, `docs/security.md`, `docs/troubleshooting.md`, `SECURITY.md`
- Create: `docs/validation/README.md`, `docs/validation/release-smoke-checklist.md`, `schemas/validation-report.schema.json`, `scripts/e2e-validate-report.mjs`
- Create: `test/unit/docs/contracts.test.js`

- [ ] RED-run doc/report tests requiring every public command/support row/asset suffix and all warnings: normal `claude` isolation, explicit OAuth/Cursor installs, provider terms, third-party trust, loopback/auth, integrity/provenance limits, Cursor same-user non-sandbox, WSL separation/ports, execution policy, upstream drift, dynamic entitlements, redaction, recovery, rollback, and uninstall.
- [ ] Require one structured report per Windows 10 1809 x64, Windows 11 ARM64, macOS 13 Intel, macOS 13 Apple silicon, WSL, and each current native target. Each binds to report-schema version, release tag/version, manager payload digest, relevant shim digest, CLIProxyAPI version/hash, UTC timestamp/max-age policy, OS/version/architectures, Node/Claude/Cursor versions+hashes, clean bootstrap/repeat/update/rollback/uninstall, supported Codex browser/device/no-browser flows, supported Antigravity browser/no-browser flows, bounded inference through `claudey` and `claude-agy`, Cursor login/models/ask/plan/approved disposable-worktree, loopback/auth, permissions, source/index/HEAD hashes, cleanup, and canary result.
- [ ] Report outcomes are `passed`, `failed`, `unavailable`, `not-run`, or `not-applicable`. `not-applicable` is accepted only when the recorded installed-capability probe proves that optional auth mode absent; `unavailable`/`not-run` never count as pass. The validator rejects stale or different-release digests/tags. Missing required baseline/auth evidence blocks release or requires narrowing support. Verify GitHub private vulnerability reporting is enabled/linkable before using it in `SECURITY.md`; otherwise publication is blocked.
- [ ] Implement docs/schema/validator, re-run GREEN, and commit `docs: define safe operations and release evidence`.

### Task 25: Release DAG, SBOM, checksums, and provenance

**Dependencies:** Tasks 21 through 24. **Serial release gate after validation contracts.**

**Files:**

- Create: `.github/workflows/release.yml`, `scripts/verify-release-artifacts.mjs`
- Create: `test/unit/workflows/release-contracts.test.js`

- [ ] RED-run contract tests for this DAG: online Node-lane freshness gate; x64/ARM64 shim build+capture proof; immutable artifact upload; six-target/three-Node tests consuming verified artifacts; packaging re-download and rehash; project manifest/SBOM/provenance generation; package/bootstrap smoke; release-bound validation-report gates; publish only after every dependency succeeds.
- [ ] Require SHA-pinned Actions, least privilege, release-content write and OIDC/attestation permissions only in the publish/provenance jobs, bounded retention, no secrets on forks, digest equality between manifest/checksum/SBOM/provenance subjects, and verification of the produced attestation result rather than YAML text alone.
- [ ] Implement and validate workflow/contracts, then commit `ci: gate releases on hashes provenance and evidence`.

### Task 26: Adversarial packaged fixture E2E

**Dependencies:** Tasks 1 through 25. **Parallel wave G.**

**Files:**

- Create: `test/e2e/fixture-install-lifecycle.test.js`, `test/e2e/fixture-provider-launch.test.js`, `test/e2e/fixture-cursor.test.js`, `test/e2e/secret-canary.test.js`

- [ ] RED-run packaged isolated-home install/repeat/auth-argv/all-fake-model-selection/Claude-relay/update/failed-readiness rollback/explicit rollback/doctor/dry-uninstall/uninstall/repeat-uninstall/auth-purge tests. Implement only composition/test-support gaps and re-run GREEN.
- [ ] RED-run Cursor packaged E2E for models/ask/plan/approval/worktree, source/index/HEAD invariance, and retained worktree; implement only composition gaps and re-run GREEN.
- [ ] Add hostile path/argv, unrelated listener/PID, traversal/link/reparse archive, modified file, forged manifest, kill-point, oversized I/O, approval race, and recursive output/capture/backup/snapshot/worktree/report/repository canary scan. Re-run `npm.cmd run check`, `npm.cmd test`, and `npm.cmd run test:e2e:fixtures`; commit `test: exercise packaged adversarial workflows`.

### Task 27: Read-only live probes and explicitly metered model tests

**Dependencies:** Tasks 17, 24, and 26. **Parallel wave G.**

**Files:**

- Create: `test/e2e/live/probe.mjs`, `test/e2e/live/infer.mjs`, `test/e2e/live/cursor.mjs`, `scripts/e2e-report.mjs`
- Create: `.github/workflows/live-e2e.yml`, `test/e2e/live-contracts.test.js`

- [ ] RED-run live-contract tests proving `--probe` does only authenticated `/v1/models` retrieval and local selection/preflight validation: it sends no prompt and starts no interactive Claude/Cursor session. Per model report fields are `listed`, `providerOwnershipValidated`, `selectionPreflightValidated`, `inferenceTested`, and `inferenceOutcome`.
- [ ] Implement exact modes:

```text
npm run test:e2e:live -- --probe
npm run test:e2e:live -- --provider codex --model <live-id> --confirm-metered
npm run test:e2e:live -- --provider antigravity --model <live-id> --confirm-metered
npm run test:e2e:live -- --cursor-probe
npm run test:e2e:live -- --cursor-ask --model <live-id> --confirm-metered
npm run test:e2e:live -- --cursor-plan --model <live-id> --confirm-metered
npm run test:e2e:live -- --all-models --confirm-metered --max-models N --max-seconds N
```

- [ ] Provider metered modes must spawn packaged `claudey --model <id> -- --print <bounded-prompt>`, `claude-codex --model <id> -- --print <bounded-prompt>`, or `claude-agy --model <id> -- --print <bounded-prompt>` and capture the launcher/Claude outcome; direct gateway inference does not satisfy the test. Metered modes require TTY confirmation distinct from `--yes`, concurrency 1, bounded prompt/output/time, and a request-count warning that cost is unknown/account-dependent. `--all-models` fails before inference when discovered count exceeds `N`; it never truncates while claiming all. Cursor write smoke still uses normal approval and a disposable repo. Missing login/capability is `AUTH_REQUIRED`/`CAPABILITY_UNSUPPORTED`, never pass or simulation.
- [ ] Generate/validate/canary-scan redacted JSON and Markdown evidence without prompts, headers, environments, browser screens, tokens, or OAuth. Re-run GREEN and commit `test: add truthful opt-in live model validation`.

### Task 28: Acceptance traceability and final local/remote validation

**Dependencies:** Tasks 1 through 27. **Final verification task.**

**Files:**

- Create: `docs/validation/acceptance-traceability.md`, `test/unit/docs/traceability.test.js`

- [ ] RED-run a traceability test requiring spec acceptance criteria 1 through 24 exactly once, each mapped to primary unit/integration/E2E files and native/manual gates. Criterion 23 explicitly maps repeated `stop`, Cursor `disable`, uninstall, and consumed default rollback.
- [ ] Implement the table and re-run GREEN. Run all fixture validation on local Windows x64 and every available read-only live probe. Authenticated/metered actions run only with existing login and their explicit confirmation; unavailable actions remain labeled unavailable.
- [ ] Trigger the six-target GitHub matrix, validate required reports, and record exact URLs/results. Do not claim ARM/macOS/Linux/older-Windows/WSL or inference coverage before matching evidence passes. Commit `test: trace acceptance and release validation`.

## Acceptance criteria traceability target

Task 28 materializes and validates this exact mapping:

| Spec criterion | Primary automated evidence | Native/manual gate |
|---:|---|---|
| 1 | `package.test.js`, `bootstrap-posix.test.js`, `bootstrap-windows.test.js` | Six CI targets consume their exact asset/shim |
| 2 | `detect.test.js`, `acceptance-core.test.js` | Unsupported target fixture proves zero writes |
| 3 | `setup.test.js`, `path-mutation.test.js`, `cursor-plugin.test.js` | Packaged repeat-setup E2E |
| 4 | `claude-launcher.test.js` | Before/after real Claude environment capture |
| 5 | `auth.test.js`, canary E2E | Supported live auth-mode report |
| 6 | `auth.test.js` | CI fixture timeout proves immediate refusal |
| 7 | `config.test.js`, `gateway-client.test.js` | Native loopback/wrong-token evidence |
| 8 | `port.test.js`, `gateway-lifecycle.test.js` | Native unrelated-listener proof |
| 9 | `process.test.js`, `gateway-lifecycle.test.js` | Native stale/forged/reused PID proof |
| 10 | `models.test.js` | Authenticated catalog/owner report |
| 11 | `models.test.js`, `claude-launcher.test.js` | Live selection preflight report |
| 12 | `claude-launcher.test.js`, `windows-shim.test.js` | Native hostile-argv capture digest |
| 13 | `checksum.test.js`, `update-rollback.test.js` | Packaged mismatch E2E |
| 14 | `update-rollback.test.js` | Packaged failed-readiness restoration E2E |
| 15 | `doctor.test.js` | Native read-only diagnostics report |
| 16 | `cursor-readonly.test.js` | Live ask/plan source/index hashes |
| 17 | `cursor/models.test.js`, `cursor-readonly.test.js` | Live Cursor catalog/pre-spawn rejection |
| 18 | `mcp-server.test.js`, `approval.test.js` | Live writes-disabled/per-call approval evidence |
| 19 | `cursor-worktree.test.js` | Approved disposable-worktree before/after hashes |
| 20 | `lifecycle.test.js`, `cursor/runner.test.js` | Native descendant cleanup proof |
| 21 | `uninstall.test.js` | Packaged default-uninstall preservation E2E |
| 22 | `uninstall.test.js` | Native canonical auth-root purge evidence |
| 23 | `lifecycle.test.js` repeated stop; `cursor-cli.test.js` repeated disable; `uninstall.test.js` repeated uninstall; `update-rollback.test.js` consumed default rollback | Packaged no-op E2E |
| 24 | `secret-canary.test.js` plus every test support canary | Recursive release/report/artifact scan |

## Parallel execution and review ledger

Use maximum available workers without sharing mutable branches. Some packets are grouped topically rather than placed in numeric dependency order; this table—not document position—is the execution order.

| Wave | Worker packets | Required base |
|---|---|---|
| Root | Task 1 | Approved spec + this plan |
| A | Tasks 2, 3, 5; then Task 4 | Task 1, plus Task 2 for Task 4 |
| B | Tasks 6, 7, 8 | Integrated prerequisites noted per task |
| Provider/launcher | Tasks 11 and 13 after Task 7; then Task 12 after Task 11 | Tasks 7-8 as declared |
| Core integration | Task 9 | Tasks 2-8, 11, and 12 reviewed and integrated |
| C | Task 10 | Task 9 |
| D | Tasks 14 and 15 | Tasks 3, 4, 13 reviewed and integrated |
| Cursor integration | Task 16 | Tasks 9-15 integrated as declared |
| CLI integration | Task 17 | All core/Cursor command services |
| E | Task 18; then Task 20; then Task 21; then Tasks 19 and 22 | Task 17 and preceding artifact dependencies |
| F | Tasks 23 and 24; then Task 25 | Complete bootstrap/package artifacts and validation schema |
| G | Task 26; then Task 27 | Complete packaged product and docs/report schema |
| Final | Task 28 | Complete reviewed branch |

For each packet, record in `.superpowers/sdd/2026-08-12-claudey-implementation/ledger.md`: task number, worktree, base SHA, implementer, RED command/evidence, GREEN command/evidence, head SHA, report path, review package, review verdict, fixes, re-review verdict, integration SHA, and follow-up concerns. Reviewers are read-only and do not trust implementer claims. Critical/Important findings or spec gaps block integration.

## Final merge gates

- [ ] Run `npm.cmd run check`, `npm.cmd test`, and `npm.cmd run test:e2e:fixtures` from a clean integration worktree; capture exact counts and exit codes.
- [ ] Run native packaging/bootstrap/shim/lifecycle tests on all six blocking GitHub runners and all three supported Node lanes; validate baseline containers and manual OS evidence or narrow the advertised support table before release.
- [ ] Run a whole-branch spec-compliance review against all 24 acceptance criteria, a security review focused on secret/path/archive/process/plugin boundaries, and a code-quality/test review. Fix and re-review every Critical/Important item.
- [ ] Verify `git status --short` is clean, package contents contain no SDD/review artifacts or secrets, generated hashes match, normal `claude` is unchanged, and the local/remote branch point is intentional.
- [ ] Push the reviewed branch to `https://github.com/ramsaijanapana/claude_code_cliProxy.git`. If repository policy permits direct integration, fast-forward `main`; otherwise open a reviewable pull request and report its exact URL and remaining external gates.
