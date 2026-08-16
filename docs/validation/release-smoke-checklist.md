# Release smoke checklist

Use this checklist separately on every target listed in the validation README. Never reuse a report after changing the tag, manifest, payload, shim, source revision, or any tested executable.

## 1. Evidence setup

- [ ] Start from a clean disposable account/environment with no ambient provider tokens.
- [ ] Record UTC `observedAt`; the report expires after 168 hours.
- [ ] Re-download and hash the project manifest, manager payload, relevant shim, CLIProxyAPI, Node, Claude Code, and Cursor Agent.
- [ ] Confirm tag, manager version, source revision, payload digest, shim digest, SBOM, checksums, and provenance subjects agree.
- [ ] Confirm private vulnerability reporting is enabled and its authenticated reporting form is linkable. Stop: publication is blocked if this cannot be proved.
- [ ] Create a unique secret canary without placing its value in the report, command line, repository, log, or artifact name.

## 2. Platform and bootstrap

- [ ] Record OS name/version, Node platform/runtime architecture, native architecture, and WSL version when applicable.
- [ ] On Windows, exercise both Windows PowerShell 5.1 and current PowerShell without weakening machine execution policy.
- [ ] Verify clean bootstrap and setup.
- [ ] Repeat bootstrap/setup and prove token, OAuth, configuration, PATH, process, and plugin idempotency.
- [ ] Verify update, candidate readiness, retained prior version, rollback, and prior running/stopped state.
- [ ] Inject an interrupted transaction and prove documented recovery without hand-editing state.

## 3. Authentication and inference

- [ ] Hash the installed CLIProxyAPI capability probe.
- [ ] Complete Codex browser auth.
- [ ] Complete Codex device-code and no-browser flows when each installed probe says supported; otherwise record only `not-applicable` with that false probe.
- [ ] Complete Antigravity browser auth and no-browser when supported under the same rule.
- [ ] Verify live provider ownership/model discovery and bounded successful inference through `claude-codex` and `claude-agy`.
- [ ] Prove the normal `claude` environment/settings remain isolated before and after both launchers.

## 4. Gateway and Cursor

- [ ] Prove the gateway listens exactly on `127.0.0.1` and missing/wrong bearer tokens fail while the correct token succeeds.
- [ ] Prove an unrelated listener is never killed or adopted.
- [ ] Verify protected config/auth/state permissions and exact gateway process identity/tree cleanup.
- [ ] Complete Cursor login, live models, ask, plan, and the separately approved disposable-worktree flow.
- [ ] Confirm default Cursor tools leave source files, index, branch, and `HEAD` byte-identical.
- [ ] Confirm the worktree flow changes only the reported worktree/shared Git metadata and performs no automatic commit, merge, push, copy-back, or deletion.
- [ ] Remember: a same-user Cursor process is not a sandbox against access to other user-readable paths.

## 5. Uninstall and secret scan

- [ ] Capture `uninstall --dry-run` canonical targets/reasons without mutation.
- [ ] Run default uninstall and confirm OAuth, modified/unlisted files, dirty repositories, and worktrees remain.
- [ ] Repeat uninstall and confirm an exit-0 no-op.
- [ ] If separately testing purge, use explicit confirmation and prove only the canonical protected auth root is removed.
- [ ] Scan repository output, process captures, logs, JSON, diagnostics, backups, snapshots, worktrees, and test artifacts for the canary; record only the evidence digest and `passed` outcome.
- [ ] Record before/after source-tree SHA-256, index SHA-256, and exact `HEAD`; all three pairs must match.

## 6. Final gate

- [ ] Every mandatory outcome is `passed`; `failed`, `unavailable`, and `not-run` block release.
- [ ] `not-applicable` appears only beside an optional auth mode whose recorded installed-capability probe is false.
- [ ] Run `scripts/e2e-validate-report.mjs` with the exact manifest and all 11 distinct reports.
- [ ] Retain bounded evidence according to release policy, without secrets.
