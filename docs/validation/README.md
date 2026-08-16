# Release validation reports

Release publication requires structured, release-bound evidence in addition to automated CI. Reports use [`schemas/validation-report.schema.json`](../../schemas/validation-report.schema.json) and are gated by `scripts/e2e-validate-report.mjs`.

## Required reports

Exactly one fresh report is required for each identifier:

1. `windows-10-1809-x64`
2. `windows-11-arm64`
3. `macos-13-x64`
4. `macos-13-arm64`
5. `wsl`
6. `current-windows-x64`
7. `current-windows-arm64`
8. `current-darwin-x64`
9. `current-darwin-arm64`
10. `current-linux-x64`
11. `current-linux-arm64`

The older desktop baselines are not implied by a latest hosted runner. WSL is manual because hosted native Linux does not prove WSL lifecycle or Windows/WSL port behavior.

## Release and tool binding

Each report records schema version 1, exact release tag/version/source revision, SHA-256 of the complete project manifest, manager payload name/hash/size, relevant Windows shim name/hash/size (or `null` on POSIX), CLIProxyAPI version/hash, UTC observation time, a 168-hour maximum-age policy, OS/version, runtime/native architectures, WSL version where applicable, and Node/Claude/Cursor versions plus executable hashes.

The validator revalidates the closed project manifest and rejects stale evidence, duplicate/missing targets, a different tag/version/revision, or any payload/shim/manifest digest mismatch. Report files must be bounded, regular, single-link files whose identity is stable while read.

## Required evidence

Every report binds evidence digests for:

- clean bootstrap, repeat bootstrap, update, rollback, dry-run uninstall, uninstall, and repeat uninstall;
- Codex browser, supported device-code, and supported no-browser flows;
- Antigravity browser and supported no-browser flows;
- bounded inference through `claude-codex` and `claude-agy`;
- Cursor login, models, ask, plan, and approved disposable-worktree operation;
- exact loopback binding, missing/wrong/correct bearer behavior, protected permissions, cleanup, and secret-canary scan;
- before/after source-tree hash, index hash, and `HEAD` revision.

Outcomes are exactly `passed`, `failed`, `unavailable`, `not-run`, `not-applicable`. Only `passed` counts. `not-applicable` is accepted solely for Codex device-code/no-browser or Antigravity no-browser when the same report records a hashed installed-capability probe with `supported: false`. `failed`, `unavailable`, and `not-run` always block publication.

## Gate invocation

Pass the exact project manifest and all 11 reports. `--now` is useful only for deterministic test/replay; release automation normally uses current UTC.

```text
node scripts/e2e-validate-report.mjs --manifest project-manifest.json --report windows-10-1809-x64.json --report windows-11-arm64.json --report macos-13-x64.json --report macos-13-arm64.json --report wsl.json --report current-windows-x64.json --report current-windows-arm64.json --report current-darwin-x64.json --report current-darwin-arm64.json --report current-linux-x64.json --report current-linux-arm64.json
```

Success prints only `validation reports: valid (11/11)`. This validates the report set; it does not override the independent private-reporting, provenance, CI, or publication gates. Failure is sanitized and exits 7.

Private vulnerability reporting is also a release prerequisite. The current repository status is not verified, so release publication remains blocked independently of otherwise valid reports.
