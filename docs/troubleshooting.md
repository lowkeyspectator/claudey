# Troubleshooting and recovery

Start with `claudey doctor` (or `claudey doctor --json`). Doctor is read-only: it reports a finding and the exact mutating command, but never repairs state itself.

## Common failures

| Code or symptom | Meaning | Safe next action |
|---|---|---|
| `PREREQUISITE_MISSING` | Node, Claude Code, Git, Cursor, PowerShell, or `tar` is absent/unverified | Install from the vendor's official instructions, start a new shell, and rerun doctor. |
| `CAPABILITY_UNSUPPORTED` | Installed upstream behavior drifted or an optional mode is absent | Update the relevant tool or use only a capability reported available. Do not force an old flag. |
| `AUTH_REQUIRED` | The selected provider has no authenticated live catalog | Run the matching interactive `claudey auth ...` command. |
| `MODEL_NOT_FOUND` | The model is not in the provider's current exact live list | Run `claudey models PROVIDER`; model availability and dynamic entitlements can change. |
| Antigravity models show `unavailable` in `/model` or `claudey models` | Quota fetch failed (historically: missing `User-Agent: antigravity` → Google 403) | Update Claudey, confirm auth JSON has `project_id`, rerun `claudey models antigravity --json`. See [usage guide](usage-and-model-picker.md#segment-a--antigravity). |
| Grok models show `7d` or `N ctx` instead of `% left` | Remaining percent missing; context length was treated as usage | Update Claudey (omitted `creditUsagePercent` with a current period means 100% left). See [usage guide](usage-and-model-picker.md#segment-b--grok). |
| Cursor Composer missing from mixed `/model` | Expected: mixed picker is gateway-only | Use `claudey models cursor`. Composer cannot run through CLIProxy without a separate dual-routing design. See [usage guide](usage-and-model-picker.md#segment-d--cursor--composer-not-in-mixed-model). |
| `PORT_IN_USE` | Another process or separate Windows/WSL installation owns the port | Stop that installation yourself or select another port with `claudey config set port PORT --yes`. |
| `PROCESS_IDENTITY_MISMATCH` | PID/listener state no longer identifies the owned process | Do not kill the PID manually. Run doctor and preserve the evidence. |
| `CHECKSUM_MISMATCH` / `ARCHIVE_UNSAFE` | Downloaded bytes or archive structure failed integrity checks | Keep the current version. Retry only from the official release after checking provenance. |
| `UPDATE_ROLLED_BACK` | Candidate readiness failed and the prior version was restored | Inspect redacted diagnostics, resolve the cause, and retry. |
| `ROLLBACK_UNAVAILABLE` | No eligible default rollback point remains | Install an explicit verified version; do not edit activation pointers. |
| leftover `claudexctl` / `Cannot find module ...\\claudexctl.js` | A pre-rebrand install or launcher still points at the old manager name | Run `claudey setup` from a new shell, or rerun the verified `install.ps1` / `install.sh`. Do not add a compatibility `claudexctl.js`. |
| `SAFETY_REFUSAL` | A path, permission, identity, approval, or secret boundary was ambiguous | Correct the reported state. Never bypass the boundary by broadening permissions. |

## Windows execution policy

An execution policy may block `install.ps1`. Do not change LocalMachine/UserPolicy, disable organization controls, or paste the bootstrap into another shell. Verify the release checksum and provenance, inspect the script, and follow your administrator's approved process. If process-scoped execution is permitted, invoke the exact verified local file from Windows PowerShell; a process-scoped choice must not persist a weaker policy.

PowerShell 5.1 and current PowerShell are separate release-validation lanes. A script parsing under one does not prove the other.

## WSL separation and port collisions

WSL is a separate installation, not a way to operate the Windows installation. Keep binaries and state in the WSL Linux filesystem. WSL 1 shares networking and WSL 2 can forward localhost, so port 8317 may already be owned across the boundary. Claudey reports but does not adopt or terminate that listener. Stop it in its own environment or select a different user port.

## Interrupted install or update

Do not delete locks, journals, staging, `current`, or `previous` pointers by hand.

1. Preserve the reported recovery path and error.
2. Run `claudey doctor`.
3. Rerun the interrupted install/update when doctor says recovery is safe.
4. If the manager itself was interrupted, rerun the exact verified bootstrap.
5. Use bootstrap `--rollback-manager`/`-RollbackManager` only for the retained verified manager rollback.

An unconfirmed child exit retains request/staging evidence. This is intentional recovery behavior, not an uninstall leak.

## Rollback

`claudey rollback --yes` consumes the default prior release once. Use `--version VERSION` only for a retained verified version. Rollback preserves configuration, token, OAuth root, launchers, and prior running/stopped state. A repeated default rollback returns `ROLLBACK_UNAVAILABLE` without mutation.

## Uninstall

Run `claudey uninstall --dry-run` first. Default uninstall preserves OAuth, modified files, unlisted data, dirty repositories, and Cursor worktrees. `--purge-auth` is irreversible and requires explicit confirmation; in noninteractive mode it also requires `--yes`. A second uninstall is an idempotent no-op.

## Upstream drift and release evidence

Scheduled compatibility checks report Node lane drift but do not rewrite reviewed configuration. New CLIProxyAPI, Claude Code, or Cursor behavior must pass installed capability probes. `unavailable` and `not-run` validation outcomes never count as pass; missing baseline or auth evidence blocks the release or requires narrowing the support table.

Diagnostics and JSON are redacted. If the exact cause is hidden, reproduce with `--verbose` only after replacing real credentials with disposable test values; never publish a token, OAuth file, private prompt, or canary.
