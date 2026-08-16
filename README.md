# Claudey

## Beginner quick start

1. Install [Claude Code](https://claude.com/download) (any current 2.1.229+ release is fine).
2. From this folder, or after install, run:

```text
claudey onboard --yes
claudey auth grok
claudey auth antigravity
claudey auth codex
claudey
```

`claudey` starts Claude Code with every signed-in provider. Use `claudey --yolo` to skip permission prompts. Newer Claude Code versions are accepted as they release; only a verified `claude` binary at or above 2.1.229 is required.

Claudey is a per-user, zero-runtime-dependency Node.js manager for running Claude Code against models exposed by a locally managed CLIProxyAPI gateway. `claudey` is the primary unified executable functioning as both an interactive Claude Code CLI proxy launcher (`claudey --yolo`, `claudey --model ...`, `claudey --select`) and as the management orchestration CLI (`claudey setup`, `claudey status`, `claudey auth`, `claudey models`, `claudey doctor`, etc.). `claudeyctl` is available as a dedicated management binary and alias. Single-provider launchers include `claude-codex` (OpenAI Codex backend), `claude-agy` (Google Antigravity backend), `claude-grok` (xAI Grok backend), and the optional Claude Code plugin delegates bounded tasks to Cursor Agent. All launchers keep the Claude Code harness — tools, Task subagents, and agent teams — on the selected live model.

The normal `claude` remains isolated: Claudey does not replace it, edit Claude settings to add proxy variables, or persist gateway credentials in the global environment. Routing variables exist only in the child launched by `claudey`, `claude-codex`, `claude-agy`, or `claude-grok`.

> **Pre-release status:** do not publish or rely on a release until all blocking CI, provenance, private security-reporting, and manual validation gates pass.

## Trust and account warning

CLIProxyAPI is a third-party executable with access to OAuth credentials and prompt traffic. It is not audited or endorsed by OpenAI, Anthropic, Google, or Cursor. Subscription OAuth through a proxy may have provider terms or account consequences. Review the upstream project and your provider terms before opting in.

OAuth is always explicit OAuth initiated by a person. Claudey never authenticates silently and refuses auth in CI or noninteractive mode. Cursor is also opt-in: `setup --with-cursor` enables integration only after a verified local Cursor Agent is available, while explicit Cursor installation is a separate command that shows the final official URL and SHA-256 before execution.

## Supported platforms and upstream assets

`VERSION` excludes the leading `v`. Standard CLIProxyAPI archives are selected; `no-plugin` archives are not.

| Platform | Minimum baseline | Node target | CLIProxyAPI asset suffix |
|---|---|---|---|
| Windows x64 | Windows 10 1809 | `win32/x64` | `_windows_amd64.zip` |
| Windows ARM64 | Windows 10 1809 ARM64 | `win32/arm64` | `_windows_aarch64.zip` |
| macOS Intel | macOS 13 | `darwin/x64` | `_darwin_amd64.tar.gz` |
| macOS Apple silicon | macOS 13 | `darwin/arm64` | `_darwin_aarch64.tar.gz` |
| Linux x64 | Ubuntu 20.04+/Debian 10+ glibc | `linux/x64` | `_linux_amd64.tar.gz` |
| Linux ARM64 | Ubuntu 20.04+/Debian 10+ glibc | `linux/arm64` | `_linux_aarch64.tar.gz` |
| WSL 1/2 | supported glibc distribution | Linux architecture | matching Linux suffix |

Musl, unrecognized distributions, other architectures, containers as an installation target, and system-wide installation are not supported. WSL is a separate installation: do not share Windows binaries, configuration, state, OAuth files, or PID records through a mounted Windows path. WSL 1 networking and WSL 2 localhost forwarding can create a port collision with the Windows gateway; Claudey refuses to adopt or kill the unrelated listener.

## Prerequisites

- Node.js 22.20.0 or newer on a currently supported Node release line.
- Claude Code 2.1.229 or newer, installed separately and verifiable by identity and capabilities.
- Windows PowerShell 5.1+ on Windows; system `tar` on macOS/Linux.
- Git only for the approved Cursor worktree tool.
- Cursor Agent only when Cursor integration is requested.

CLIProxyAPI 7.2.130 is the initial compatibility baseline. Newer upstream versions are accepted only after their installed capability probes pass. Model names and dynamic entitlements are account-specific and are always discovered live.

## Bootstrap

Download the bootstrap and the release manifest from the same release, verify the published checksums and provenance, then run one of:

```text
./install.sh [--version VERSION] [--yes] [--no-path] [--rollback-manager]
.\install.ps1 [-Version VERSION] [-Yes] [-NoPath] [-RollbackManager]
```

The scripts install only inside the current user's managed roots and then run `claudey setup`. They do not require administrator/root access and do not start OAuth. Re-running the bootstrap is the manager self-update path.

On Windows, an execution policy may block a downloaded script. Do not weaken a machine or organization policy. Inspect the script and verified release metadata, and use only an organization-approved process-scoped invocation if policy permits. See [troubleshooting](docs/troubleshooting.md).

## Public command reference

Global management flags are `--json`, `--no-color`, `--verbose`, and `--non-interactive`; `CI=true` is noninteractive.

```text
claudey onboard [--yes]
claudey setup [--version VERSION] [--port PORT] [--with-cursor] [--no-start] [--no-path] [--yes]
claudey install [--version VERSION] [--port PORT] [--yes]
claudey auth codex [--device-code | --no-browser] [--callback-port PORT]
claudey auth antigravity [--no-browser] [--callback-port PORT]
claudey auth grok [--device-code | --no-browser] [--callback-port PORT]
claudey auth all [options]
claudey start [--foreground]
claudey stop
claudey restart
claudey status [--json]
claudey update [--check | --version VERSION] [--yes]
claudey rollback [--version VERSION] [--yes]
claudey models [codex | antigravity | grok | cursor | all] [--json]
claudey doctor [--json]
claudey config set port PORT [--yes]
claudey cursor enable [--scope user | local]
claudey cursor disable [--scope user | local]
claudey cursor install [--yes]
claudey cursor login
claudey cursor repo add [PATH]
claudey cursor repo list
claudey cursor repo remove [PATH]
claudey cursor writes enable --yes
claudey cursor writes disable
claudey cursor approve APPROVAL_ID
claudey uninstall [--dry-run] [--purge-auth] [--yes]
```

Note: All management commands can also be run using the `claudeyctl` executable alias.

Launchers:

```text
claudey [--model MODEL | --select | --yolo] [-- CLAUDE_ARGS...]
claude-codex [--model MODEL | --select | --all | --yolo] [-- CLAUDE_ARGS...]
claude-agy [--model MODEL | --select | --yolo] [-- CLAUDE_ARGS...]
claude-grok [--model MODEL | --select | --yolo] [-- CLAUDE_ARGS...]
```

`claudey` starts a mixed session by default. `--yolo` enables Claude Code skip-permissions mode (`--dangerously-skip-permissions`). The delimiter is required before other Claude arguments. Values are forwarded as discrete arguments, never reconstructed as a shell command. In a noninteractive terminal, `--model` is required.

From this repository checkout on Windows, the same commands are:

```text
node bin/claudey.js setup --yes --no-path
node bin/claudey.js auth codex
node bin/claudey.js auth antigravity
node bin/claudey.js auth grok
node bin/claudey.js launcher claudey --
node bin/claudey.js launcher claude-codex --
node bin/claudey.js launcher claude-agy --
node bin/claudey.js launcher claude-grok --
```

Each launcher starts the real Claude Code harness with the selected live model pinned for the main agent, Task subagents, and haiku/sonnet/opus/fable aliases. The normal `claude` command is left unchanged.

`claudey` starts one session against every authenticated provider and fills Claude Code `/model` from a local picker catalog (utility names such as `auto-review` are omitted). Each row is labeled with the live model id and remaining capacity when that is known. Switch with `/model`. Auth each provider first so its models appear. Use `claudey --yolo` when you want skip-permissions mode.

## Authentication and model selection

`auth codex` supports browser login and only offers device-code/no-browser modes proven by the installed upstream capability probe. `auth antigravity` behaves the same for its supported browser/no-browser modes. `auth grok` uses the installed CLIProxyAPI xAI/Grok login flags (`--grok-login` when present, otherwise `--xai-login`) and offers device-code when the installed binary reports it. A callback-port collision is reported; Claudey never kills its owner.

Models come from authenticated live catalogs with exact provider ownership metadata. No catalog is bundled and no model name is guessed. Upstream drift or changed flags fail closed with a remediation. A provider may disappear from a user's dynamic entitlements at any time.

## Local gateway security

The gateway binds exactly to `127.0.0.1`; every model and inference request requires a generated bearer token. Localhost is not treated as authentication. Claudey records and revalidates process identity and refuses an unrelated listener. Tokens and OAuth data are excluded from command lines, logs, JSON, profiles, backups, and Cursor environments; provenance-based redaction is backed by secret-canary tests.

A checksum beside an artifact proves transfer integrity, not publisher identity. The release manifest, SBOM, checksum set, and provenance must agree on exact digests. Even provenance cannot make a compromised upstream binary trustworthy; it establishes how the Claudey artifacts were built.

## Cursor boundary

Cursor integration is optional. Ask and plan run against protected snapshots. Write delegation is absent until `cursor writes enable --yes`, and every run then needs a separate interactive, single-use approval bound to the exact repository, model, prompt, base commit, and installation.

A same-user process is not a sandbox. A trusted Cursor binary can still read other files accessible to the account even when its working directory is disposable. Claudey never automatically commits, merges, pushes, copies changes back, or deletes a worktree.

## Recovery, rollback, and uninstall

Install/update operations journal their phases and preserve the last verified release. On interrupted recovery, rerun the same command or `claudey doctor`; do not delete state by hand. `rollback` is transactional and the default rollback point is single-use. Manager rollback uses the bootstrap `--rollback-manager`/`-RollbackManager` option.

Start with `claudey uninstall --dry-run`. Default uninstall removes only unchanged, authenticated manifest-owned paths and preserves OAuth data, modified or unlisted files, dirty repositories, and Cursor worktrees. OAuth purge needs `--purge-auth` plus explicit confirmation. Repeated stop/disable/uninstall operations are safe no-ops.

See [security](docs/security.md), [troubleshooting](docs/troubleshooting.md), and [release validation](docs/validation/README.md).
