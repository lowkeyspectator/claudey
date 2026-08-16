# Claudey Cross-Platform Gateway and Cursor Bridge

Date: 2026-08-12

Status: Approved architecture, written specification pending final review

Repository: https://github.com/ramsaijanapana/claude_code_cliProxy

## 1. Summary

This project provides a safe, repeatable way to use Claude Code with models available through Codex and Google Antigravity OAuth, while also exposing the models available to Cursor Agent as delegated Claude Code tools.

The implementation has three user-facing entry points:

- `claudey` runs Claude Code against the locally managed CLIProxyAPI gateway with live model selection across providers (and dedicated launchers `claude-codex`, `claude-agy`, and `claude-grok`).
- `claude-agy` runs Claude Code against the same gateway and a live-selected Antigravity model.
- The optional Claude Code plugin exposes Cursor Agent through typed MCP tools for asking, planning, model discovery, and explicitly approved worktree changes.

The normal `claude` command and the user's existing Claude configuration remain unchanged. Proxy variables and tokens exist only in the launched child process.

The implementation is a zero-runtime-dependency Node.js command named `claudeyctl`, with thin `install.ps1` and `install.sh` bootstrap scripts. It supports native Windows, macOS, Linux, and WSL as an independent Linux environment.

## 2. Context and interpretation

The two source threads demonstrate routing Claude Code through CLIProxyAPI with `ANTHROPIC_BASE_URL` and `ANTHROPIC_AUTH_TOKEN`, selecting a Codex model, and setting Claude Code effort and subagent model variables.

The request for “agy” is interpreted as the Google Antigravity provider supported by CLIProxyAPI.

Cursor is intentionally integrated differently. Cursor Agent is a coding-agent harness with model selection; it is not documented as an Anthropic-compatible model endpoint. Therefore:

- Codex and Antigravity are inference providers behind CLIProxyAPI.
- Cursor models are made available through the installed Cursor Agent CLI and exposed to Claude Code as delegated MCP tools.
- The project does not impersonate Cursor as a CLIProxyAPI provider or claim that Cursor subscription models can be called through an undocumented HTTP API.

This distinction is a correctness and account-safety boundary, not merely an implementation preference.

## 3. Goals

The first release shall:

1. Install a verified CLIProxyAPI binary for the current supported OS and architecture.
2. Configure it as a local-only, authenticated per-user service without administrator access.
3. Guide the user through explicit Codex and Antigravity authentication.
4. Discover currently available models at runtime rather than shipping a stale catalog.
5. Launch Claude Code with a selected Codex or Antigravity model without changing normal Claude Code behavior.
6. Optionally install a Claude Code plugin that delegates read-oriented work to Cursor Agent.
7. Keep Cursor write delegation disabled until the user opts in, and require a separate human approval for every write-capable run.
8. Make install, update, rollback, status, diagnostics, and uninstall idempotent and recoverable.
9. Support paths and arguments containing spaces, Unicode, quotes, leading dashes, and shell metacharacters.
10. Test the security and lifecycle invariants on all advertised native platforms.

## 4. Non-goals

The first release will not:

- Modify, replace, or alias the normal `claude` executable.
- Write proxy variables into the user's global environment or Claude settings.
- Install or authenticate Claude Code, Codex, Antigravity, or Cursor silently.
- Turn Cursor into an undocumented inference endpoint.
- Automatically commit, merge, push, delete, or apply Cursor-generated changes.
- Run CLIProxyAPI as a system service requiring administrator or root privileges.
- Manage multiple operating systems from one shared installation directory.
- Guarantee that an upstream OAuth workflow is endorsed by the subscription provider.
- Provide a hard security sandbox around a same-user Cursor process.
- Support FreeBSD, ia32, ppc64, s390x, containers, or system-wide installations in the first release.

## 5. Design principles

The implementation follows these rules:

- Local by construction: the gateway binds exactly to `127.0.0.1`.
- Authenticated by construction: model and inference requests require a generated bearer token.
- Child-scoped configuration: launcher environment changes die with the child process.
- Live catalogs: model lists come from authenticated provider tools at execution time.
- Fail closed: ambiguous providers, unsupported platforms, invalid state, and unsafe paths stop before mutation.
- Transactional mutation: downloads, config writes, activation, and rollback use staging and atomic replacement.
- Ownership-aware cleanup: only manifest-owned, canonical paths are eligible for removal.
- Least privilege: no admin access, no arbitrary Cursor command MCP tool, and no default write delegation.
- Observable behavior: human output is actionable and machine output has a stable JSON envelope.
- No shell reconstruction: user values remain typed data or discrete arguments.

## 6. Supported platforms

| Platform | Minimum baseline | Node platform/architecture | CLIProxyAPI release asset |
|---|---|---|---|
| Windows x64 | Windows 10 1809, Windows PowerShell 5.1 | `win32/x64` | `CLIProxyAPI_VERSION_windows_amd64.zip` |
| Windows ARM64 | Windows 10 1809 ARM64 | `win32/arm64` | `CLIProxyAPI_VERSION_windows_aarch64.zip` |
| macOS Intel | macOS 13 | `darwin/x64` | `CLIProxyAPI_VERSION_darwin_amd64.tar.gz` |
| macOS Apple silicon | macOS 13 | `darwin/arm64` | `CLIProxyAPI_VERSION_darwin_aarch64.tar.gz` |
| Linux x64 | glibc-based Ubuntu 20.04+ or Debian 10+ | `linux/x64` | `CLIProxyAPI_VERSION_linux_amd64.tar.gz` |
| Linux ARM64 | glibc-based Ubuntu 20.04+ or Debian 10+ | `linux/arm64` | `CLIProxyAPI_VERSION_linux_aarch64.tar.gz` |
| WSL 1 or 2 | Supported Linux distribution in WSL | `linux/x64` or `linux/arm64` | Matching Linux asset |

`VERSION` in the asset name excludes a leading `v`. Upstream asset names use `aarch64`, not `arm64`. The standard archives are selected; `no-plugin` variants are not selected.

Only `win32`, `darwin`, and a detected glibc Ubuntu/Debian `linux`, and only `x64` and `arm64`, are accepted. Linux distribution, version, and libc are read from structured OS metadata and the Node process report. Musl and unrecognized distributions fail closed until their own release assets and lifecycle behavior are tested. Unsupported combinations fail with `PLATFORM_UNSUPPORTED` before a persistent write.

WSL is a separate Linux installation and does not share Windows binaries, state, PID metadata, or configuration through a mounted Windows path. WSL 1 shares networking with Windows, and WSL 2 localhost forwarding can still produce cross-environment port collisions. Setup detects a conflicting listener normally, refuses to adopt or kill it, and explains that the Windows or WSL gateway must be stopped or assigned a user-selected alternate port.

When runtime and native architectures differ because of emulation, the runtime architecture selects the executable. Doctor reports both values and warns about the mismatch.

## 7. Prerequisites

The core requires:

- Node.js 22.20.0 or newer on a Node release line that is still supported upstream.
- Claude Code resolvable and verifiable with `claude --version` before a launcher is used.
- A working system `tar` on macOS and Linux for extraction after the Node core validates the archive headers.
- Git when the Cursor worktree tool is enabled.
- Cursor Agent only when Cursor integration is requested.

Missing prerequisites produce an exact diagnostic and an official installation link. The project never silently executes a third-party remote installer.

Cursor detection checks the unambiguous `cursor-agent` compatibility alias first, then considers the current primary command `agent` only after its version output verifies that it is Cursor Agent. A same-named executable from another product is skipped rather than treated as a fatal match. Detection also checks documented per-user fallback locations when a newly installed executable is not visible in the current shell.

On Windows, executable resolution prefers native executables. A known npm shim may be structurally resolved to its Node entry point and launched without a shell. An unrecognized `.cmd`, `.bat`, or PowerShell shim is rejected instead of placing user-controlled text into a shell command.

The first compatibility baseline is CLIProxyAPI 7.2.130 and Claude Code 2.1.229. Older explicit versions are rejected. Newer versions must pass capability probes before mutation: CLIProxyAPI must expose Codex and Antigravity login modes, explicit config selection, required config keys, an authenticated model endpoint with provider ownership metadata, and a version probe; Claude Code must expose model selection and plugin/MCP commands and be compatible with the documented gateway environment variables. Cursor Agent is beta and has no numeric stability promise, so it must pass executable-identity, login/status, live-model-list, JSON print, stdin prompt, mode, and sandbox capability probes. A missing Cursor capability disables only the affected Cursor tool and reports `CAPABILITY_UNSUPPORTED`.

Platform helpers are explicit and probed before mutation:

- Windows uses Windows PowerShell 5.1+ and .NET `System.IO.Compression` through fixed, bundled helper scripts for ZIP metadata/extraction, `icacls.exe` plus `Get-Acl` for DACL application/verification, and CIM plus PID-targeted process commands for identity and process trees.
- macOS and Linux use the system `tar`, Node permission APIs, `ps` with fixed fields, and, on Linux, `/proc` identity data when available.
- Configuration is emitted from a strict structured schema. The manager does not attempt to parse arbitrary YAML; it validates its deterministic serialization, its recorded hash, and candidate startup with the explicit config.

Helper invocations use absolute known-system paths or verified resolution, fixed scripts and flags, typed path arguments, timeouts, and output schemas. A missing, unexpected, localized, or malformed helper result fails with `PREREQUISITE_MISSING` or `CAPABILITY_UNSUPPORTED` before activation.

## 8. High-level architecture

~~~text
                         +----------------------+
                         |      claudeyctl      |
                         | install/auth/lifecycle|
                         +----------+-----------+
                                    |
                   managed config, token, process, models
                                    |
                         +----------v-----------+
                         | CLIProxyAPI on       |
                         | 127.0.0.1:<port>     |
                         +-----+-----------+----+
                               |           |
                         Codex OAuth   Antigravity OAuth

 claudey / claude-codex -------> Claude Code child
 claude-agy -------------------> Claude Code child
   child-only ANTHROPIC_BASE_URL, ANTHROPIC_AUTH_TOKEN, selected model

 Claude Code plugin -----------> local stdio MCP server
                                      |
                                      v
                               Cursor Agent CLI
                         disposable snapshot or new worktree
~~~

The Node core owns all state transitions. Bootstrap scripts only locate Node, copy or invoke the project payload, and preserve arguments.

On POSIX, launchers are fixed shell scripts that invoke one absolute Node entry point with quoted static paths and `"$@"`. On Windows, launchers are tiny native `.exe` shims built reproducibly from included source for x64 and ARM64. A single audited forwarding implementation is installed under the names `claudeyctl.exe`, `claudey.exe`, `claude-codex.exe`, `claude-agy.exe`, and `claude-grok.exe`; it uses its basename to select a fixed profile and a documented Windows quoting algorithm to call the absolute Node executable and manager entry point. No `.cmd`, `.bat`, `%*`, generated PowerShell launcher, or `cmd.exe` is used for user arguments.

The Windows shim binaries are distributed in this project's GitHub release, hashed in a project checksum manifest, verified before use, version-matched to the installed manager, and self-tested with a capture child before activation. The PowerShell bootstrap is invoked explicitly and uses array splatting only for its small fixed option schema.

No third-party npm runtime dependency is required. Node standard-library APIs are used for HTTP, crypto, filesystem, processes, locks, and tests; the narrowly scoped platform helpers in Section 7 provide the OS facilities Node lacks.

## 9. Installed data layout

Paths are resolved through one platform adapter and recorded in an installation manifest with a random installation UUID.

### Windows

| Purpose | Default |
|---|---|
| Manager, release binaries, launchers | `%LOCALAPPDATA%\claudeyctl` |
| User configuration and OAuth root | `%APPDATA%\claudeyctl` |
| Runtime state, locks, logs, staging | `%LOCALAPPDATA%\claudeyctl\state` |
| User command directory | `%LOCALAPPDATA%\claudeyctl\bin` |

### macOS

| Purpose | Default |
|---|---|
| Manager, release binaries, configuration, OAuth root | `~/Library/Application Support/claudeyctl` |
| Runtime state and logs | `~/Library/Application Support/claudeyctl/state` |
| User command directory | `~/.local/bin` |

### Linux and WSL

| Purpose | Default |
|---|---|
| Manager and release binaries | `$XDG_DATA_HOME/claudeyctl`, falling back to `~/.local/share/claudeyctl` |
| Configuration and OAuth root | `$XDG_CONFIG_HOME/claudeyctl`, falling back to `~/.config/claudeyctl` |
| Runtime state and logs | `$XDG_STATE_HOME/claudeyctl`, falling back to `~/.local/state/claudeyctl` |
| User command directory | `~/.local/bin` |

The project records every managed path, its content hash where applicable, its type, and its installation UUID. The manifest has a versioned schema and an HMAC derived from a separate protected installation secret; malformed or unauthenticated manifests are never used for deletion. Even an authenticated entry must remain within a fixed platform-managed root. OAuth artifacts are deliberately excluded from the removable-file manifest.

POSIX secret directories and files use modes `0700` and `0600`. Executables and launchers use `0755`. Windows secret paths receive a protected DACL limited to the current user and required operating-system principals, without inherited `Everyone` or ordinary `Users` access, and are rejected if they resolve through a junction or reparse point. Permission verification occurs after creation and during doctor.

## 10. Public command contract

### Bootstrap

~~~text
./install.sh [--version VERSION] [--yes] [--no-path] [--rollback-manager]
.\install.ps1 [-Version VERSION] [-Yes] [-NoPath] [-RollbackManager]
~~~

The bootstrap installs the current project payload and then invokes `claudeyctl setup`. Re-running the bootstrap is the supported manager self-update path. It never starts OAuth by surprise.

### Management

~~~text
claudeyctl setup [--version VERSION] [--port PORT] [--with-cursor] [--no-start] [--no-path] [--yes]
claudeyctl install [--version VERSION] [--port PORT] [--yes]
claudeyctl auth codex [--device-code | --no-browser] [--callback-port PORT]
claudeyctl auth antigravity [--no-browser] [--callback-port PORT]
claudeyctl start [--foreground]
claudeyctl stop
claudeyctl restart
claudeyctl status [--json]
claudeyctl update [--check | --version VERSION] [--yes]
claudeyctl rollback [--version VERSION] [--yes]
claudeyctl models [codex | antigravity | cursor | all] [--json]
claudeyctl doctor [--json]
claudeyctl config set port PORT [--yes]
claudeyctl cursor enable [--scope user | local]
claudeyctl cursor disable [--scope user | local]
claudeyctl cursor install [--yes]
claudeyctl cursor login
claudeyctl cursor repo add [PATH]
claudeyctl cursor repo list
claudeyctl cursor repo remove [PATH]
claudeyctl cursor writes enable --yes
claudeyctl cursor writes disable
claudeyctl cursor approve APPROVAL_ID
claudeyctl uninstall [--dry-run] [--purge-auth] [--yes]
~~~

Global management flags are `--json`, `--no-color`, `--verbose`, and `--non-interactive`. `CI=true` implies noninteractive behavior.

The `--yes` flag confirms predictable local mutations such as installing a verified release. It never simulates OAuth completion and cannot satisfy a per-run Cursor write approval.

`setup` is the convenience orchestration command: it installs or updates CLIProxyAPI, creates or validates managed configuration and launchers, optionally enables Cursor integration, manages PATH, and starts the gateway unless told otherwise. `install` performs only the verified CLIProxyAPI/config/launcher transaction; it does not authenticate, change Cursor registration, alter PATH, or start a stopped gateway.

The default port is 8317. `--port` and `config set port` accept only an integer from 1024 through 65535, reject an occupied address before config mutation, and update config plus prior running/stopped state transactionally. Generated launchers read the managed port at runtime; no launcher rewrite is needed.

When `setup --with-cursor` cannot find a verified Cursor Agent installation, it prompts to run the separate opt-in `cursor install` flow in an interactive terminal; noninteractive setup returns `PREREQUISITE_MISSING` with that remediation. It never treats `--with-cursor` alone as permission to execute a remote installer.

### Launchers

~~~text
claudey [--model MODEL | --select | --yolo] [-- CLAUDE_ARGS...]
claude-codex [--model MODEL | --select | --all | --yolo] [-- CLAUDE_ARGS...]
claude-agy [--model MODEL | --select | --yolo] [-- CLAUDE_ARGS...]
claude-grok [--model MODEL | --select | --yolo] [-- CLAUDE_ARGS...]
~~~

Everything after the delimiter is forwarded to Claude Code as discrete arguments. A delimiter is required when Claude arguments are present so wrapper and Claude options cannot be confused.

In an interactive terminal, omitting `--model` opens a selector populated from the live provider catalog. In a noninteractive terminal, `--model` is required and omission returns `MODEL_REQUIRED`; explicitly requesting `--select` returns `INTERACTION_REQUIRED`.

## 11. Setup behavior

Setup performs a recoverable sequence:

1. Acquire the installation lock.
2. Detect and validate OS, runtime architecture, prerequisites, paths, and current state.
3. Resolve an explicit version or the current non-prerelease CLIProxyAPI release.
4. Download the exact release checksum file and exact platform archive.
5. Verify the archive SHA-256 against one unambiguous filename entry.
6. Extract into a private same-filesystem staging directory with safe-entry validation.
7. Probe the candidate executable and record its reported version.
8. Generate or preserve the installation UUID and 256-bit local bearer token.
9. Stage and validate the minimal gateway configuration and launcher files.
10. Atomically activate the candidate and record a transaction journal.
11. Add the user bin directory to the user PATH unless `--no-path` was given and only when absent.
12. Optionally register the Cursor plugin.
13. Start the gateway unless `--no-start` was given.
14. Perform authenticated gateway readiness and endpoint-schema checks. Before provider login, an empty model catalog is valid setup state.
15. Commit the transaction and release the lock.

Authentication is always a separate explicit command because browser or device interaction may be required.

Repeated setup preserves the bearer token, OAuth files, user-owned Claude settings, current configuration, and a single PATH entry. It creates at most one managed gateway process and one owned plugin registration. Setup never requires provider authentication to complete.

## 12. Release resolution and integrity

Downloads use HTTPS and an allowlist of official GitHub release hosts. Redirects are bounded and each redirect target is revalidated.

For a release such as `v7.2.130`, the x64 Windows archive is:

~~~text
CLIProxyAPI_7.2.130_windows_amd64.zip
~~~

The checksum parser:

- Requires an exact filename match.
- Requires exactly one SHA-256 value with 64 hexadecimal characters.
- Rejects missing, duplicate, ambiguous, or path-containing entries.
- Hashes the complete archive before extraction.
- Does not execute any downloaded content before verification.

Safe extraction accepts only regular files and directories. It rejects absolute paths, drive-qualified paths, UNC paths, NUL bytes, parent traversal, symlinks, hard links, sparse files, devices, unsupported extended entry types, duplicate executable entries, and any canonical target outside staging. The Windows adapter preflights ZIP metadata and then uses the locally installed Windows PowerShell archive API; the macOS/Linux adapter preflights TAR headers and then invokes the system `tar` executable with fixed arguments. Both adapters re-walk staging before any candidate is used.

Release downloads and extraction are resource-bounded: 256 MiB maximum archive bytes, 2,048 entries, 512 MiB maximum total expanded bytes, 256 MiB maximum single entry, 100:1 maximum declared compression ratio, and a two-minute extraction deadline. Limits are constants covered by fixtures and may be raised only with documented evidence from an official release. Partial downloads and staging directories are cleaned only after canonical ownership verification.

The candidate executable is probed before activation. Activation uses an atomic pointer or rename on the same filesystem. At least one previous verified release is retained.

A checksum served beside a release proves transfer integrity only. It does not protect against an upstream publisher or GitHub account compromise. If CLIProxyAPI later publishes signed attestations, verification of those attestations becomes a release requirement.

## 13. CLIProxyAPI configuration

The manager owns a minimal generated configuration with these invariants:

~~~yaml
host: "127.0.0.1"
port: 8317
tls:
  enable: false
remote-management:
  allow-remote: false
  secret-key: ""
  disable-control-panel: true
auth-dir: "<absolute protected per-user auth path>"
api-keys:
  - "<generated 256-bit token>"
debug: false
commercial-mode: true
logging-to-file: false
usage-statistics-enabled: false
pprof:
  enable: false
plugins:
  enabled: false
ws-auth: true
~~~

The management API remains disabled. Plugin loading, request logging, in-memory usage statistics, and the control panel remain disabled. The service binds to the IPv4 loopback address rather than `localhost` to avoid ambiguous IPv6 or interface behavior. The installed upstream version must confirm the documented `commercial-mode` behavior before activation; setup fails rather than silently enabling request logging when that contract is absent.

The gateway is launched with an explicit absolute config path and a minimal inherited environment. In particular, `MANAGEMENT_PASSWORD` and any upstream configuration-override variables are removed so a user's ambient environment cannot silently enable remote management or replace the managed security settings.

The manager uses an authenticated `GET /v1/models` request for readiness. A mere open TCP port is not sufficient.

Config writes use a same-directory temporary file, restrictive permissions, schema validation, file synchronization where supported, and atomic replacement. A protected backup records the prior content hash and format version. OAuth files are never included in config backups.

If a config no longer matches its recorded managed hash, mutation commands stop with `CONFIG_MODIFIED` and provide a diff-safe remediation. They do not overwrite it silently. Corrupt backups are quarantined and never restored.

## 14. Authentication

### Codex

`claudeyctl auth codex` invokes the installed CLIProxyAPI binary with its supported Codex OAuth login mode. Browser login is the interactive default. Device-code and no-browser modes are exposed only when the installed upstream version reports support for the corresponding flag.

### Antigravity

`claudeyctl auth antigravity` invokes the supported Antigravity OAuth login mode. The no-browser and callback-port options are validated against the installed upstream help output before invocation.

Default upstream callback ports are not assumed to be free. The command checks for a collision before starting and reports the owning process when the OS permits. It never kills a process that owns a callback port.

All OAuth commands are refused immediately under `--non-interactive` or `CI=true` because browser, device-code, and no-browser URL flows still require a person to authenticate. Those flags select how an interactive user completes login; they are not unattended credential modes. An authentication prompt is never allowed to hang a CI job.

CLIProxyAPI manages provider OAuth files as opaque data in the dedicated protected per-user auth root. Claudeyctl does not parse, print, copy, back up, or commit their contents.

Authentication subprocesses receive an explicit config path, fixed working directory, restrictive file-creation policy, and a minimized environment. Ambient provider tokens and gateway override variables are removed before the upstream login executable is started.

Documentation and the first authentication run warn that CLIProxyAPI is a third-party project, is not audited or endorsed by OpenAI, Anthropic, Google, or Cursor, and that using subscription OAuth through a proxy may have terms-of-service or account consequences.

## 15. Live model discovery

No model catalog is bundled.

For Codex and Antigravity:

1. Ensure the owned gateway is healthy.
2. Request `GET /v1/models` with the local bearer token.
3. Validate the OpenAI-compatible response schema.
4. Select entries by the exact `owned_by` provider metadata returned by CLIProxyAPI.
5. Sort deterministically for human and JSON output.
6. Reject missing or ambiguous provider attribution rather than guessing from a model name.

For Cursor:

1. Resolve and verify the installed `cursor-agent` alias or a verified `agent` executable.
2. Invoke the current `agent models` command, with the documented `--list-models` compatibility fallback.
3. Parse only a recognized output shape.
4. Return a live list or a version-specific remediation; never substitute a stale web catalog.

A requested model must appear in the current live list for the selected launcher or tool. Unknown models return `MODEL_NOT_FOUND` before Claude Code or Cursor starts.

The thread's `gpt-5.6-sol` choice may be offered first when it is present in the live Codex list, but it is not assumed to exist and is not an invisible fallback.

`claudeyctl models codex` and `claudeyctl models antigravity` start an installed, stopped owned gateway and leave it running. An explicitly requested provider without an authenticated catalog returns `AUTH_REQUIRED` and exit 4. `models cursor` never starts the gateway. `models all` reports a status and model array for every provider; it exits 0 when at least one provider succeeds and marks unavailable providers in the result, or returns the highest-priority applicable nonzero exit when none succeeds.

## 16. Claude Code launcher behavior

The launch sequence is:

1. Resolve and verify the real Claude Code executable without resolving back to a project launcher.
2. Acquire the lifecycle lock and ensure the owned gateway is healthy, starting it if needed.
3. Fetch and validate the selected model against live provider metadata.
4. Construct a child environment from the user's environment while removing conflicting Anthropic gateway variables.
5. Set only child-scoped gateway and Claude Code compatibility variables.
6. Spawn Claude Code with an argument array and shell execution disabled.
7. Relay standard input, output, terminal signals, and the exact child exit status.
8. Drop token references and zero mutable buffers promptly when no longer needed.

The child environment contains:

~~~text
ANTHROPIC_BASE_URL=http://127.0.0.1:<managed port>
ANTHROPIC_AUTH_TOKEN=<local bearer token>
CLAUDE_CODE_SUBAGENT_MODEL=<selected live model>
CLAUDE_CODE_ALWAYS_ENABLE_EFFORT=1
CLAUDE_CODE_MAX_TOOL_USE_CONCURRENCY=3
CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1
ENABLE_TOOL_SEARCH=false
~~~

The selected model is also passed to Claude Code through its normal `--model` argument. A caller-supplied `--model VALUE`, `--model=VALUE`, or recognized model alias after the wrapper delimiter is rejected so there is one authoritative model. All other post-delimiter values remain untouched.

The concurrency value and `ENABLE_TOOL_SEARCH=false` match the source-thread profile and are documented by current Claude Code. Loading tools up front is intentional for a non-first-party gateway so the optional Cursor tools remain discoverable. Future configuration may expose these values, but the first release keeps a deterministic tested profile.

After the child exits, the parent process environment, shell profile, Claude settings, and ordinary `claude` behavior are unchanged. JavaScript runtime strings cannot be guaranteed to be zeroized in memory; the design minimizes their lifetime and never serializes them outside the protected config and child environment.

## 17. Gateway process lifecycle

The manager runs a per-user background process rather than a system service.

Runtime metadata contains:

- Installation UUID.
- Process ID.
- Process start time.
- Canonical executable path and release version.
- Canonical config path.
- Host and port.
- Random instance nonce.
- Readiness identity and last successful readiness time.

Start is idempotent. A healthy owned process returns success without spawning another process.

Before signaling or reusing a process, the manager verifies the complete available identity, not only the PID. A forged or stale PID file must not allow an unrelated process to be killed.

If `127.0.0.1:8317` is occupied by an unrelated process, start fails with `PORT_IN_USE` and reports available ownership details. It never authenticates to, adopts, or kills that listener.

The background process writes bounded, redacted stdout and stderr logs. Debug logging is off. Start waits for authenticated readiness and fails cleanly if the child exits or the deadline expires.

Stop requests graceful termination, waits a bounded interval, and then force-terminates only a still-verified owned process tree. Name-based `pkill`, `killall`, `taskkill` by image name, and broad process matching are forbidden.

On POSIX, the manager records a process group, revalidates executable/start-time/group identity through `/proc` or `ps`, sends `SIGTERM` to that verified group, waits, revalidates, and uses `SIGKILL` only as the bounded fallback. On Windows, fixed PowerShell/CIM helpers return JSON containing PID, parent PID, creation time, and executable path; the manager revalidates the entire descendant set, then uses only PID-targeted `taskkill /PID <verified-pid> /T` and, if needed, `/F`. Image-name targeting is never permitted. The native launcher owns console-event relay for its foreground Claude child. CI covers PID reuse, forged state, and descendant cleanup on both Windows architectures.

Status distinguishes:

- `not-installed`
- `stopped`
- `starting`
- `healthy`
- `unhealthy`
- `stale-state`
- `port-occupied`

Concurrent install, update, rollback, start, stop, config, and uninstall operations use one exclusive lock with safe stale-lock recovery.

`restart` stops and starts a healthy or unhealthy owned process and starts a stopped installation. It preserves a healthy process if pre-stop identity verification fails, and it returns `PORT_IN_USE` without signaling anything when an unrelated listener owns the configured port.

## 18. Update and rollback

`claudeyctl update` manages CLIProxyAPI within the installed manager version. Re-running the repository bootstrap updates the manager itself.

Manager self-update is also transactional. The bootstrap downloads or copies a complete versioned manager payload and, on Windows, its release-matched verified native shim; runs static load, help, version, and launcher-capture self-tests from staging; atomically switches the active-manager pointer; and retains the prior verified manager. If the first post-switch command fails, the bootstrap restores the prior pointer. `install.sh --rollback-manager` and `install.ps1 -RollbackManager` restore only that retained manager version. Bootstrap interruption is recovered from a manager-specific journal that contains no secrets.

Update follows download, checksum, safe extraction, probe, stage, activate, and readiness phases. It preserves the token, OAuth root, config, launchers, and prior running or stopped state.

If candidate readiness fails:

1. Stop only the verified candidate process tree.
2. Atomically restore the prior active-release pointer and configuration.
3. Restart the prior version only if it was running before the update.
4. Verify authenticated readiness.
5. Return `UPDATE_ROLLED_BACK` with the failed candidate diagnostics.

Rollback without a version selects the one pending previous verified release produced by the last successful install or update. A successful rollback consumes that default rollback point; repeating default rollback returns `ROLLBACK_UNAVAILABLE` with exit 8 rather than toggling versions. A supplied version may select only a locally retained and previously verified release; selecting the already active version is an exit-0 no-op. Rollback never downloads an arbitrary old binary.

The transaction journal lets the next command identify an interrupted operation and either complete activation or restore the last known-good state. It contains operation IDs, paths, hashes, and phases but no bearer token or OAuth data.

## 19. Claude Code Cursor plugin

The repository is also a Claude Code plugin marketplace:

~~~text
.claude-plugin/marketplace.json
plugins/cursor-agent/.claude-plugin/plugin.json
plugins/cursor-agent/.mcp.json
plugins/cursor-agent/server/
~~~

`claudeyctl cursor enable` registers this repository marketplace and installs the owned plugin at user or local scope by invoking supported Claude Code plugin commands. It does not edit the user's settings JSON directly.

The registration includes an ownership marker containing the repository identity and installation UUID. If an unrelated registration already uses the same name, enable fails with `MCP_OWNERSHIP_COLLISION`.

Local-scope enable also registers the canonical current Git project as an allowed Cursor source root. User-scope enable installs the tools but does not grant access to every project. `cursor repo add` explicitly registers a canonical Git project, `repo list` displays registered roots, and `repo remove` revokes a root without deleting it. Add and remove require an interactive confirmation unless they operate on the current project at local scope; `--yes` may confirm only this predictable registration mutation. Filesystem roots, home directories, bare repositories, and linked or unresolved paths are refused.

Cursor absence or authentication failure disables only Cursor tools. Codex and Antigravity launchers continue to work.

### 19.1 Optional Cursor installation

`claudeyctl cursor install` is an explicit trust-boundary operation. Native Windows downloads the official installer from `https://cursor.com/install?win32=true`; macOS, Linux, and WSL download from `https://cursor.com/install`. Redirects are restricted to Cursor-owned HTTPS hosts. The bytes are saved in private staging, capped in size, hashed with SHA-256, and shown with the final URL before execution.

Cursor does not publish a stable detached checksum for this installer, so transport security and the displayed hash do not provide the same publisher-independent verification as the CLIProxyAPI archive. Interactive confirmation is required after that warning; `--yes` is accepted only when `cursor install` itself was explicitly requested. The fixed installer is then invoked without user interpolation, and the result is accepted only after the expected `cursor-agent` or verified `agent` binary appears and passes identity, version, and capability checks. Failure preserves the rest of Claudey and gives the official manual installation command.

### 19.2 Default tools

After Cursor integration is enabled, these tools are available:

~~~text
cursor_models({})
cursor_ask({prompt, model?, paths?})
cursor_plan({prompt, model?, paths?})
~~~

`cursor_models` uses the live `models` subcommand of the verified Cursor Agent executable.

`cursor_ask` and `cursor_plan`:

- Accept typed fields only and reject unknown fields.
- Validate the optional model against the live Cursor list.
- Anchor the source root to the canonical Claude Code project root supplied when the MCP server starts; callers cannot switch roots.
- Copy only requested, contained source paths into a private disposable snapshot.
- Exclude `.git`, known secret files, managed credentials, all symbolic links, junctions, and reparse points.
- Run Cursor in ask or plan mode, print mode, JSON output, and sandbox mode when supported.
- Send the prompt through standard input, but only after the installed CLI help/capability probe confirms stdin prompt ingestion.
- Enforce input, file-count, byte-count, output, and time limits.
- Return structured results labeled as untrusted tool output.
- Delete only the verified disposable snapshot on completion.

When `paths` is omitted, the snapshot is built from eligible Git-tracked files under the registered project root, subject to the same deny rules and resource limits. Untracked files are included only when named explicitly and still pass containment and secret-name checks.

Cursor documentation states that noninteractive print mode has write and shell capabilities. Ask and plan therefore never run in the caller's checkout, even when the CLI mode claims to be read-oriented. Tests must prove that writes directed at the delegated working directory affect only the disposable snapshot and leave the registered source files and Git index byte-identical.

If stdin prompt ingestion, genuine ask mode, or genuine plan mode is missing, the corresponding tool is not advertised. The server never falls back to putting a private prompt in a process argument or emulating plan mode with prompt text.

### 19.3 Optional worktree tool

Write delegation is absent from the advertised tool list until the user runs:

~~~text
claudeyctl cursor writes enable --yes
~~~

The enabled tool is:

~~~text
cursor_worktree_run({
  repo,
  prompt,
  model?,
  baseRef?,
  approvalId?
})
~~~

Every invocation uses a newly created Git worktree and uniquely named branch. The caller's working-tree files, index, checked-out branch, and `HEAD` are never changed. Creating the delegated branch and worktree intentionally updates shared Git refs and worktree metadata; those exact changes are reported and retained for the user to inspect.

The requested repository must equal a canonical project root explicitly registered by the user. Filesystem roots, the user's home directory, bare repositories, and arbitrary caller-selected paths are refused. Existing outward-pointing links in the materialized worktree cause the run to fail before Cursor starts.

An optional `baseRef` is either an exact full ref selected from server-enumerated local branches/tags or a full hexadecimal commit object ID. The server resolves it to a commit object ID with safe Git plumbing before worktree creation and passes only that resolved object ID as a discrete argument after option termination. Caller text is never concatenated into a Git revision expression.

A Boolean field is not sufficient proof of human approval. The per-call flow is:

1. An initial tool call validates the exact repository, prompt hash, model, and base reference and returns `APPROVAL_REQUIRED` plus a 256-bit random approval ID that expires after five minutes.
2. The user runs `claudeyctl cursor approve APPROVAL_ID` in an interactive terminal.
3. The approval command displays the bound repository, model, base reference, a safely escaped bounded prompt preview, and the full prompt digest and requires an explicit confirmation. It refuses non-TTY input and has no `--yes` mode.
4. A repeated MCP call presents the approval ID.
5. The server consumes the single-use approval only if every bound field matches and the approval has not expired.

Pending approvals live only in the protected state directory. The normalized prompt is encrypted with authenticated encryption under a domain-separated key derived from the protected installation secret; bound metadata is authenticated, and plaintext is never logged or backed up. The record is removed on consumption, expiry, plugin disable, or uninstall.

The tool also carries destructive and user-interaction metadata so Claude Code displays an additional permission boundary. The out-of-band, single-use approval remains authoritative even when a client has permissive MCP settings.

The server creates the worktree itself, chooses the branch name, fixes the working directory, constructs all flags, and provides a minimal environment. The caller cannot supply an executable, arbitrary flags, a working directory, environment variables, or a Git command.

The result includes the worktree path, branch, base commit, porcelain status, diff metadata, and the shared Git metadata it created. The tool never commits, merges, pushes, copies changes back, deletes the worktree, or changes the caller's files, index, checked-out branch, or `HEAD`.

## 20. Cursor subprocess security

The MCP server resolves an absolute, identity-verified Cursor Agent executable and invokes it without a general-purpose shell. On Windows, a required trusted launcher is handled only through a fixed compatibility path; the prompt never appears in the command string and model identifiers use a strict allowlist.

The Cursor child receives a minimal environment required for process execution, terminal behavior, and Cursor authentication. It explicitly excludes:

- `ANTHROPIC_BASE_URL`
- `ANTHROPIC_AUTH_TOKEN`
- `ANTHROPIC_API_KEY`
- OpenAI and Google provider credentials
- CLIProxyAPI tokens and OAuth paths
- GitHub tokens
- Unrelated cloud credentials
- Claude Code session variables

`CURSOR_API_KEY` is removed as well. The first release supports Cursor's browser-login credential store and does not pass an API key through Claude Code or the MCP server.

Claude Code's documented `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1` strips Anthropic and cloud credentials from stdio MCP servers. On startup, the Cursor MCP server independently checks that gateway and provider credential variables are absent and refuses all tools with `SAFETY_REFUSAL` if the scrub contract is not in effect. Its own Cursor children apply a second explicit environment allowlist.

Cancellation or timeout terminates the verified Cursor process tree. Limits apply to prompt size, selected input paths, total snapshot bytes, output bytes, duration, and simultaneous runs.

A disposable snapshot or Git worktree protects the caller's checkout from ordinary working-directory writes. It is not a hard sandbox against a malicious or compromised same-user process, which may enumerate and access other user-readable files, including the original checkout. The project does not claim protection against that threat; the documentation requires users to trust the installed Cursor binary and states this limitation prominently.

## 21. Filesystem and argument safety

Every managed root is canonicalized at discovery and rechecked immediately before a write, rename, extraction, restoration, or deletion.

Managed path components reject:

- Parent traversal.
- Absolute input where a relative path is required.
- Drive changes and UNC paths.
- NUL bytes and line breaks.
- Symlinks, junctions, and reparse points.
- Canonical targets outside the declared root.
- Link swaps detected between validation and mutation.

User values are never interpolated into PowerShell source, POSIX shell source, environment assignment text, Git revision expressions, or a constructed command line. Subprocess APIs receive an absolute executable and argument array with shell execution disabled.

Forwarded Claude arguments stay separate after the delimiter. Tests cover semicolons, ampersands, pipes, quotes, backticks, command substitution syntax, percent expansion syntax, CR/LF, spaces, Unicode, and leading dashes.

## 22. Secret handling

The local bearer token and separate manifest-authentication key are generated with a cryptographic random-number generator and each contain at least 256 bits of entropy.

Tokens, the manifest-authentication key, and OAuth data never appear in:

- Repository files.
- Process arguments.
- Global environment variables.
- Shell profiles.
- Human or JSON logs.
- Test snapshots.
- Error details.
- Cursor child environments.
- General configuration backups outside the protected config area.

Log redaction is based on sensitive field provenance in addition to pattern matching. Secret-bearing values are represented by opaque secret types so accidental serialization fails tests.

Tests place unique canaries in stub tokens and OAuth files, then scan repository output, process captures, backups, logs, exceptions, Cursor environments, and test artifacts.

## 23. PATH behavior

Setup uses a per-user bin directory, adds it to the user PATH by default, and never writes a system PATH. `--no-path` disables that mutation consistently in the bootstrap and `setup`.

PATH modification is:

- Optional through `--no-path`.
- Idempotent.
- Case-insensitively deduplicated on Windows.
- Marker-owned in POSIX shell profile blocks when a profile change is necessary.
- Recorded with its previous state for rollback.
- Limited to the `claudeyctl` bin directory.

No file named `claude` is installed. Only `claudey`, `claudeyctl`, `claude-codex`, `claude-agy`, and `claude-grok` are installed.

If a current shell cannot see a newly added directory, setup prints the exact safe action needed to start a new shell or invoke the absolute launcher.

## 24. Uninstall

Default uninstall:

1. Acquires the installation lock.
2. Verifies and stops only the owned gateway process.
3. Removes unchanged manifest-owned manager files, binaries, launchers, runtime state, and owned plugin registration.
4. Restores only the exact PATH or profile change made by setup.
5. Preserves OAuth data, user-modified managed files, Cursor worktrees, dirty repositories, and unlisted files.
6. Reports every preserved path.

A valid manifest cannot expand the fixed deletion roots. Uninstall rejects a manifest path outside the recorded manager, state, user-bin, or owned plugin roots even if other metadata appears valid.

`--dry-run` lists canonical targets and reasons without mutation.

OAuth removal requires `--purge-auth` plus explicit confirmation. In noninteractive mode it additionally requires `--yes`. Purge is still restricted to the recorded protected auth root and refuses a filesystem root, home directory, repository root, unresolved path, link, junction, or reparse target.

Uninstall is idempotent. A second invocation succeeds without broadening its deletion scope.

## 25. Errors and machine-readable output

Human errors use:

~~~text
error[MODEL_NOT_FOUND]: "gpt-x" is not available for provider "codex".
next: Run claudeyctl models codex.
~~~

JSON errors use:

~~~json
{
  "ok": false,
  "code": "MODEL_NOT_FOUND",
  "message": "The requested model is not currently available.",
  "hint": "Run claudeyctl models codex.",
  "details": {}
}
~~~

JSON success uses:

~~~json
{
  "ok": true,
  "schemaVersion": 1,
  "result": {}
}
~~~

Global flags may appear before or after the subcommand but never after the launcher delimiter. Under `--json`, exactly one success or error envelope is written to stdout; progress and diagnostics go to stderr. Errors still use their documented nonzero exit. `status` and `doctor` return exit 0 only when the installation or checks are healthy; their nonhealthy state remains present in the JSON result or error details. `update --check` returns exit 0 whether current or update-available and expresses that state in `result`. `models all` follows the partial-success rule in Section 15.

Stable exit classes are:

| Exit | Meaning |
|---|---|
| 0 | Success or idempotent no-op |
| 2 | Usage or schema error |
| 3 | Missing or unsupported prerequisite |
| 4 | Authentication or interaction required |
| 5 | Network, release, or integrity failure |
| 6 | Lifecycle, lock, readiness, or port failure |
| 7 | Confirmation, ownership, or safety policy refusal |
| 8 | Rollback unavailable or rollback failure |

Symbolic codes used by public behavior and acceptance tests are stable within schema version 1. They include `USAGE_ERROR`, `PLATFORM_UNSUPPORTED`, `PREREQUISITE_MISSING`, `CAPABILITY_UNSUPPORTED`, `NOT_INSTALLED`, `AUTH_REQUIRED`, `INTERACTION_REQUIRED`, `MODEL_REQUIRED`, `MODEL_NOT_FOUND`, `NETWORK_FAILURE`, `CHECKSUM_MISMATCH`, `ARCHIVE_UNSAFE`, `LOCK_BUSY`, `PORT_IN_USE`, `GATEWAY_UNHEALTHY`, `PROCESS_IDENTITY_MISMATCH`, `CONFIG_MODIFIED`, `MCP_OWNERSHIP_COLLISION`, `APPROVAL_REQUIRED`, `APPROVAL_INVALID`, `SAFETY_REFUSAL`, `UPDATE_ROLLED_BACK`, and `ROLLBACK_UNAVAILABLE`.

Status, models, and doctor JSON outputs include a `schemaVersion` field. Human progress goes to stderr when JSON is requested so stdout remains parseable.

## 26. Diagnostics

Doctor is read-only and checks:

- Supported OS and runtime/native architecture.
- Node, Claude Code, Git, and optional Cursor versions.
- Resolved absolute executable identities.
- Install manifest and UUID consistency.
- Managed hashes and ownership collisions.
- Config schema, bind address, API authentication, and protected permissions.
- Token entropy metadata without revealing the token.
- Gateway PID identity, port ownership, readiness, and stale state.
- Auth presence by provider without reading credential contents.
- Live model endpoint schema and provider attribution.
- PATH visibility and duplicate entries.
- Cursor MCP registration, login status, models, write setting, and pending worktrees.
- Transaction journal and retained rollback release.

Doctor never repairs state. It prints the exact mutating command that would address a finding.

## 27. Test strategy

The project uses Node's built-in test runner and test doubles for network, filesystem, process, Claude Code, CLIProxyAPI, Cursor Agent, Git, and OAuth interactions.

### Unit tests

- Platform and asset mapping for all supported and unsupported combinations.
- Version normalization and exact checksum parsing.
- Archive entry validation.
- Canonical containment and link/reparse rejection.
- YAML and JSON generation, schema checks, and secret-safe serialization.
- Argument parsing, delimiter handling, and model conflict detection.
- Environment construction and credential scrubbing.
- Error envelopes and exit-code mapping.
- Manifest ownership and uninstall target calculation.
- Approval challenge binding, expiration, and one-time consumption.

### Integration tests

- Clean install with a fixture release server.
- Generated-config probe proving loopback binding, authenticated model access, disabled management/control-panel routes, disabled plugins, and disabled request/usage logging.
- Repeat install and setup idempotency.
- Start twice, stop twice, stale PID, forged PID, PID reuse, and unrelated port listener.
- Auth flag construction and noninteractive refusal.
- Authenticated live models with correct provider filtering.
- Claude launcher stdin/stdout/signal/exit-code relay.
- Spaces, Unicode, shell metacharacters, and hostile argument payloads.
- Checksum mismatch, traversal archive, link archive, corrupt config, interrupted transaction, readiness failure, automatic rollback, and rollback unavailability.
- Plugin ownership collision and repeated enable/disable.
- Cursor snapshot immutability under attempted writes.
- Cursor live-model validation, timeout, output cap, and descendant cleanup.
- Worktree isolation and per-call out-of-band approval.
- Default uninstall preservation, dry run, explicit credential purge, forged manifest, and repeated uninstall.
- Secret-canary scanning across all outputs and artifacts.

### End-to-end smoke tests

Tests with real upstream services are opt-in because they require provider accounts and browser interaction. They are never required for pull requests and never consume a contributor's credentials automatically.

Release candidates require manual authenticated smoke evidence for:

- Codex browser OAuth.
- Codex device-code or no-browser flow when supported.
- Antigravity browser OAuth.
- Antigravity no-browser flow when supported.
- Claude Code inference through each provider.
- Cursor login, live model discovery, ask, plan, and approved worktree delegation.

## 28. CI matrix and gates

Advertised native targets are blocking jobs:

| Target | GitHub runner |
|---|---|
| Windows x64 | `windows-latest` |
| Windows ARM64 | `windows-11-arm` |
| macOS Intel | `macos-15-intel` |
| macOS Apple silicon | `macos-15` |
| Linux x64 | `ubuntu-24.04` |
| Linux ARM64 | `ubuntu-24.04-arm` |

Every native runner tests the Node 22.20.0 compatibility floor, current Node LTS, and current Node. End-of-life and unsupported odd-numbered lines are rejected even when their numeric version is higher. Both Windows jobs exercise Windows PowerShell 5.1 and current PowerShell. Linux x64 and ARM64 jobs add container smoke tests for the Ubuntu 20.04 and Debian 10 baselines at the matching architecture. WSL remains a documented manual smoke test because hosted WSL coverage is not equivalent to a native Linux job.

Latest hosted runners do not prove older desktop operating-system baselines. A release therefore also requires recorded manual or self-hosted smoke results on Windows 10 1809 x64, Windows 11 ARM64, macOS 13 Intel, and macOS 13 Apple silicon. If a baseline cannot be exercised for a release, the support table is raised to the oldest environment actually tested before publication.

Every matrix job runs:

- Formatting and static checks.
- Unit and integration tests.
- Bootstrap syntax checks.
- Platform-specific permission and process tests.
- Hostile path and argument fixtures.
- Transaction failure injection.
- Secret-canary scanning.
- Install, repeat install, update, rollback, dry-run uninstall, uninstall, and repeat uninstall.

A release is blocked by any advertised-platform failure, secret scan hit, unsafe archive result, lifecycle identity failure, source-checkout mutation by default Cursor tools, or missing provenance/checksum metadata.

## 29. Packaging and repository structure

The planned repository shape is:

~~~text
.
|-- .claude-plugin/
|   +-- marketplace.json
|-- .github/
|   +-- workflows/
|-- bin/
|   |-- claudey
|   |-- claude-codex
|   |-- claude-agy
|   |-- claude-grok
|   +-- claudeyctl
|-- docs/
|   |-- security.md
|   |-- troubleshooting.md
|   +-- superpowers/
|       |-- plans/
|       +-- specs/
|-- plugins/
|   +-- cursor-agent/
|       |-- .claude-plugin/plugin.json
|       |-- .mcp.json
|       +-- server/
|-- src/
|   |-- cli/
|   |-- core/
|   |-- platform/
|   |-- providers/
|   +-- cursor/
|-- test/
|   |-- fixtures/
|   |-- integration/
|   +-- unit/
|-- install.ps1
|-- install.sh
|-- package.json
|-- LICENSE
+-- README.md
~~~

Generated launchers remain thin. Business rules live in independently testable Node modules.

## 30. Acceptance criteria

The first release is accepted only when all of the following are demonstrated:

1. A clean install succeeds on Windows x64/ARM64, macOS x64/ARM64, and Linux x64/ARM64 using the exact verified upstream asset.
2. Unsupported platforms stop before persistent mutation.
3. Repeated setup preserves the token, OAuth, config, PATH, and one owned process/plugin entry.
4. Normal `claude` receives no project proxy variables before or after a launcher run.
5. Codex and Antigravity auth invoke supported upstream flags and never leak credential contents.
6. CI browser auth fails immediately with `INTERACTION_REQUIRED` rather than hanging.
7. The gateway listens only on `127.0.0.1` and rejects a missing or wrong bearer token.
8. An unrelated process on the selected port is reported and never killed or adopted.
9. Forged and stale PID state cannot cause an unrelated process to be signaled.
10. Models are fetched live, filtered by exact provider ownership, and never inferred from names or a bundled list.
11. A selected unknown or cross-provider model is rejected before Claude starts.
12. Launcher arguments preserve spaces, Unicode, quotes, metacharacters, leading dashes, and child exit status without command injection.
13. Update rejects a checksum mismatch before extraction and preserves the running installation.
14. Failed candidate readiness restores the prior release, config, and running state.
15. Doctor finds corrupt config, unsafe permissions, stale state, port collision, missing auth, missing tools, and plugin ownership collision without mutation.
16. Default Cursor ask and plan leave the caller's checkout and index byte-identical when the Cursor test double writes within the delegated working directory.
17. Cursor models are discovered live and invalid IDs fail before an agent run.
18. The Cursor worktree tool is absent by default and requires both persistent opt-in and a unique interactive approval for each exact invocation.
19. A Cursor worktree run changes only its new working-tree files plus the reported shared branch/worktree metadata; it never changes the caller's files, index, checked-out branch, or `HEAD`, and never commits, merges, pushes, copies, or deletes automatically.
20. Timeouts leave no owned CLIProxyAPI or Cursor descendants.
21. Default uninstall preserves OAuth, modified files, dirty worktrees, and unlisted data.
22. Purge removes only the canonical recorded auth root after explicit confirmation.
23. Repeated `stop`, Cursor `disable`, and uninstall are exit-0 no-ops that preserve already-stopped, already-disabled, or already-uninstalled state. A repeated default rollback after its rollback point was consumed returns `ROLLBACK_UNAVAILABLE`, exit 8, and makes no change.
24. Logs, JSON output, test artifacts, snapshots, command lines, and Cursor environments contain no token or OAuth canary.

## 31. Known risks and limitations

- CLIProxyAPI is a third-party executable with broad access to provider OAuth credentials and prompt traffic.
- A release checksum hosted by the same publisher does not establish publisher identity.
- Provider terms and OAuth behavior can change without notice.
- Claude Code, CLIProxyAPI, and Cursor Agent are independently versioned; compatibility probes and clear failures are required.
- Cursor Agent is currently described as beta and its noninteractive mode has powerful filesystem and command capabilities.
- A same-user process cannot be fully isolated by a disposable directory or Git worktree alone.
- Model availability, model names, and subscription entitlements are dynamic and account-specific.
- Native ARM hosted runner availability can change; the project must not advertise an untested platform if its blocking coverage is removed.

These risks are documented in the README and security guide and surfaced before the relevant opt-in.

## 32. Source references

Research was checked on 2026-08-12. Implementation must revalidate version-sensitive command flags against the installed executable.

- Source thread by Theo: https://x.com/theo/status/2076114415368482854
- Follow-up thread: https://x.com/thsottiaux/status/2076119366647894371
- CLIProxyAPI repository: https://github.com/router-for-me/CLIProxyAPI
- CLIProxyAPI example configuration: https://github.com/router-for-me/CLIProxyAPI/blob/main/config.example.yaml
- CLIProxyAPI management and provider documentation: https://help.router-for.me
- Claude Code environment variables: https://code.claude.com/docs/en/env-vars
- Claude Code LLM gateway configuration: https://docs.anthropic.com/en/docs/claude-code/llm-gateway
- Claude Code MCP documentation: https://code.claude.com/docs/en/mcp
- Claude Code plugin marketplaces: https://code.claude.com/docs/en/plugin-marketplaces
- OpenAI Codex CLI: https://github.com/openai/codex
- Cursor CLI documentation: https://cursor.com/docs
- Cursor CLI model-list announcement: https://cursor.com/changelog/cli-jan-08-2026
- Cursor Agent CLI safety notice: https://cursor.com/blog/cli
- Node.js release status: https://nodejs.org/en/about/previous-releases

## 33. Implementation boundary

This document defines the approved product behavior and safety invariants. The implementation plan must break it into independently verifiable slices and preserve every acceptance criterion. If upstream behavior contradicts an assumption in this specification, implementation stops at that boundary, records evidence, and revises the spec before weakening a safety rule or pretending compatibility.
