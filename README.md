# Claudex

Claudex is a per-user, zero-runtime-dependency Node.js manager for running Claude Code against models exposed by a locally managed CLIProxyAPI gateway. `claudex` selects live Codex models, `claude-agy` selects live Google Antigravity models, and the optional Claude Code plugin delegates bounded tasks to Cursor Agent.

The normal `claude` remains isolated: Claudex does not replace it, edit Claude settings to add proxy variables, or persist gateway credentials in the global environment. Routing variables exist only in the child launched by `claudex` or `claude-agy`.

> **Pre-release status:** do not publish or rely on a release until all blocking CI, provenance, private security-reporting, and manual validation gates pass.

## Trust and account warning

CLIProxyAPI is a third-party executable with access to OAuth credentials and prompt traffic. It is not audited or endorsed by OpenAI, Anthropic, Google, or Cursor. Subscription OAuth through a proxy may have provider terms or account consequences. Review the upstream project and your provider terms before opting in.

OAuth is always explicit OAuth initiated by a person. Claudex never authenticates silently and refuses auth in CI or noninteractive mode. Cursor is also opt-in: `setup --with-cursor` enables integration only after a verified local Cursor Agent is available, while explicit Cursor installation is a separate command that shows the final official URL and SHA-256 before execution.

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

Musl, unrecognized distributions, other architectures, containers as an installation target, and system-wide installation are not supported. WSL is a separate installation: do not share Windows binaries, configuration, state, OAuth files, or PID records through a mounted Windows path. WSL 1 networking and WSL 2 localhost forwarding can create a port collision with the Windows gateway; Claudex refuses to adopt or kill the unrelated listener.

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

The scripts install only inside the current user's managed roots and then run `claudexctl setup`. They do not require administrator/root access and do not start OAuth. Re-running the bootstrap is the manager self-update path.

On Windows, an execution policy may block a downloaded script. Do not weaken a machine or organization policy. Inspect the script and verified release metadata, and use only an organization-approved process-scoped invocation if policy permits. See [troubleshooting](docs/troubleshooting.md).

## Public command reference

Global management flags are `--json`, `--no-color`, `--verbose`, and `--non-interactive`; `CI=true` is noninteractive.

```text
claudexctl setup [--version VERSION] [--port PORT] [--with-cursor] [--no-start] [--no-path] [--yes]
claudexctl install [--version VERSION] [--port PORT] [--yes]
claudexctl auth codex [--device-code | --no-browser] [--callback-port PORT]
claudexctl auth antigravity [--no-browser] [--callback-port PORT]
claudexctl start [--foreground]
claudexctl stop
claudexctl restart
claudexctl status [--json]
claudexctl update [--check | --version VERSION] [--yes]
claudexctl rollback [--version VERSION] [--yes]
claudexctl models [codex | antigravity | cursor | all] [--json]
claudexctl doctor [--json]
claudexctl config set port PORT [--yes]
claudexctl cursor enable [--scope user | local]
claudexctl cursor disable [--scope user | local]
claudexctl cursor install [--yes]
claudexctl cursor login
claudexctl cursor repo add [PATH]
claudexctl cursor repo list
claudexctl cursor repo remove [PATH]
claudexctl cursor writes enable --yes
claudexctl cursor writes disable
claudexctl cursor approve APPROVAL_ID
claudexctl uninstall [--dry-run] [--purge-auth] [--yes]
```

Launchers:

```text
claudex [--model MODEL | --select] [-- CLAUDE_ARGS...]
claude-agy [--model MODEL | --select] [-- CLAUDE_ARGS...]
```

The delimiter is required before Claude arguments. Values are forwarded as discrete arguments, never reconstructed as a shell command. In a noninteractive terminal, `--model` is required.

## Authentication and model selection

`auth codex` supports browser login and only offers device-code/no-browser modes proven by the installed upstream capability probe. `auth antigravity` behaves the same for its supported browser/no-browser modes. A callback-port collision is reported; Claudex never kills its owner.

Models come from authenticated live catalogs with exact provider ownership metadata. No catalog is bundled and no model name is guessed. Upstream drift or changed flags fail closed with a remediation. A provider may disappear from a user's dynamic entitlements at any time.

## Local gateway security

The gateway binds exactly to `127.0.0.1`; every model and inference request requires a generated bearer token. Localhost is not treated as authentication. Claudex records and revalidates process identity and refuses an unrelated listener. Tokens and OAuth data are excluded from command lines, logs, JSON, profiles, backups, and Cursor environments; provenance-based redaction is backed by secret-canary tests.

A checksum beside an artifact proves transfer integrity, not publisher identity. The release manifest, SBOM, checksum set, and provenance must agree on exact digests. Even provenance cannot make a compromised upstream binary trustworthy; it establishes how the Claudex artifacts were built.

## Cursor boundary

Cursor integration is optional. Ask and plan run against protected snapshots. Write delegation is absent until `cursor writes enable --yes`, and every run then needs a separate interactive, single-use approval bound to the exact repository, model, prompt, base commit, and installation.

A same-user process is not a sandbox. A trusted Cursor binary can still read other files accessible to the account even when its working directory is disposable. Claudex never automatically commits, merges, pushes, copies changes back, or deletes a worktree.

## Recovery, rollback, and uninstall

Install/update operations journal their phases and preserve the last verified release. On interrupted recovery, rerun the same command or `claudexctl doctor`; do not delete state by hand. `rollback` is transactional and the default rollback point is single-use. Manager rollback uses the bootstrap `--rollback-manager`/`-RollbackManager` option.

Start with `claudexctl uninstall --dry-run`. Default uninstall removes only unchanged, authenticated manifest-owned paths and preserves OAuth data, modified or unlisted files, dirty repositories, and Cursor worktrees. OAuth purge needs `--purge-auth` plus explicit confirmation. Repeated stop/disable/uninstall operations are safe no-ops.

See [security](docs/security.md), [troubleshooting](docs/troubleshooting.md), and [release validation](docs/validation/README.md).
