# Claudey

**Run Claude Code on Codex, Antigravity, and Grok — one harness, one `/model` menu, live quota on every row.**

Claudey is a per-user manager that keeps the full Claude Code experience (tools, Task subagents, agent teams) while routing inference through a **local CLIProxyAPI gateway** on your machine. Sign in to the providers you use, run `claudey`, and switch models inside Claude Code without touching global Claude settings.

> **Pre-release:** do not rely on this for production until CI, provenance, security reporting, and manual validation gates all pass.

---

## Why Claudey

| You want… | Claudey gives you… |
|---|---|
| One Claude Code workflow across OpenAI, Google, and xAI | Mixed `claudey` session with provider-labeled `/model` options |
| Remaining quota visible before you pick a model | Live usage on picker rows (`61%/7d · 100%/5h`, `100% left`, etc.) |
| Your normal `claude` command untouched | Gateway env only on the child process Claudey launches |
| Fail-closed safety | Verified binaries, localhost-only gateway, explicit OAuth, no silent auth |

**Who it’s for:** developers who already use Claude Code and want subscription-backed Codex, Antigravity, or Grok models in the same session — without maintaining separate proxy env vars by hand.

**Who it’s not for:** system-wide installs, containers as the install target, or routing Cursor Composer through the same gateway picker (see [Model segments](#model-segments) below).

---

## Get started

**Prerequisites:** [Claude Code](https://claude.com/download) 2.1.229+, Node.js 22.20+.

### 1. Install

From a [verified release](docs/validation/README.md):

```text
./install.sh --yes          # macOS / Linux
.\install.ps1 -Yes          # Windows
```

Or from this checkout:

```text
claudey onboard --yes
```

### 2. Sign in to providers

```text
claudey auth grok
claudey auth antigravity
claudey auth codex
```

OAuth is always interactive — never silent, never in CI.

### 3. Launch

```text
claudey              # mixed session — all signed-in gateway providers
claudey --yolo       # same, with skip-permissions mode
claudey --select     # pick a model before launch
```

Inside Claude Code, use **`/model`** to switch. Each option looks like:

```text
gemini-3-flash - Antigravity | 61%/7d · 100%/5h
grok-4.6 - Grok | 100% left
gpt-5.6-sol - Codex | 40% left
```

Verify catalogs and usage anytime:

```text
claudey models all --json
claudey doctor
```

---

## Model segments

Mixed `/model` is **gateway-backed only**. Cursor Composer lives on a separate path.

| Segment | Example models | Usage in `/model` | How to verify |
|---|---|---|---|
| **Codex** | `gpt-5.6-sol`, `gpt-5.3-codex-spark` | `% left`, named extra windows | `claudey models codex --json` |
| **Antigravity** | `gemini-3-flash`, `claude-sonnet-4-6` | Dual pool: `%/7d · %/5h` | `claudey models antigravity --json` |
| **Grok** | `grok-4.6`, `grok-4.5` | `% left` (weekly period) | `claudey models grok --json` |
| **Cursor / Composer** | `composer-2.5`, `composer-2.5-fast` | *Not in mixed `/model`* | `claudey models cursor --json` |

**Composer note:** Cursor models use Cursor auth and Cursor’s runtime. They appear under `claudey models cursor`, not in the gateway mixed picker, because mixed sessions forward inference to CLIProxy — not to Cursor Agent. Full explanation: [Usage labels and the mixed model picker](docs/usage-and-model-picker.md#segment-d--cursor--composer-not-in-mixed-model).

**Duplicate model names across providers:** mixed sessions keep both (e.g. same id from Codex and Antigravity) with provider labels and provider-qualified routing — see [provider-labeled selection design](docs/superpowers/specs/2026-08-16-provider-labeled-model-selection-design.md).

---

## How it works

```text
You → claudey → Claude Code (tools, subagents, /model)
                    ↓
              picker gateway (localhost)
                    ↓
              CLIProxyAPI (127.0.0.1, bearer token)
                    ↓
         Codex · Antigravity · Grok  (OAuth per provider)
```

- **`claudey`** — mixed launcher + management CLI (`setup`, `auth`, `models`, `doctor`, …).
- **`claudeyctl`** — same management commands, dedicated binary alias.
- **`claude-codex`**, **`claude-agy`**, **`claude-grok`** — single-provider Claude Code launchers.
- **Optional Cursor plugin** — bounded delegation to Cursor Agent (separate from gateway `/model`).

Models are always discovered **live** from authenticated catalogs — nothing is bundled or guessed.

---

## Launchers

```text
claudey [--model MODEL | --select | --yolo] [-- CLAUDE_ARGS...]
claude-codex [--model MODEL | --select | --all | --yolo] [-- CLAUDE_ARGS...]
claude-agy   [--model MODEL | --select | --yolo] [-- CLAUDE_ARGS...]
claude-grok  [--model MODEL | --select | --yolo] [-- CLAUDE_ARGS...]
```

- **`--yolo`** — Claude Code skip-permissions mode (`--dangerously-skip-permissions`).
- Use **`--`** before forwarding arbitrary Claude arguments (noninteractive mode requires **`--model`**).
- Checkout dev entrypoint: `node bin/claudey.js launcher claudey --`

---

## Platforms

| Platform | Minimum | Notes |
|---|---|---|
| macOS 13+ (Intel / Apple silicon) | Node 22.20+, Claude Code 2.1.229+ | Managed state under `~/Library/Application Support/claudeyctl/` |
| Windows 10 1809+ (x64 / ARM64) | PowerShell 5.1+ | See [troubleshooting](docs/troubleshooting.md) for execution policy |
| Linux x64 / ARM64 (glibc) | Ubuntu 20.04+ / Debian 10+ | No musl, no system-wide install |
| WSL 1/2 | Separate install from Windows | Do not share OAuth/state across the boundary |

CLIProxyAPI compatibility is probed at install time; newer upstream versions are accepted only after capability checks pass.

---

## Trust and security

CLIProxyAPI is a **third-party** local proxy with access to OAuth credentials and prompt traffic. It is not audited or endorsed by OpenAI, Anthropic, Google, or xAI. Subscription OAuth through a proxy may have provider terms implications — review upstream CLIProxyAPI and your provider terms before opting in.

Claudey’s defaults:

- Gateway binds **`127.0.0.1` only**; bearer token required on every request.
- OAuth tokens stay out of logs, JSON, and command lines.
- Cursor write delegation is **off** until you explicitly enable it with per-run approval.

Details: [Security](docs/security.md) · [Cursor boundary](#cursor-optional) below.

---

## Cursor (optional)

Cursor integration is opt-in (`claudey setup --with-cursor`). Ask/plan use protected snapshots; writes require `claudey cursor writes enable --yes` and a single-use approval per run.

```text
claudey cursor login
claudey models cursor --json
```

Cursor never auto-commits, merges, or pushes on your behalf.

---

## Common commands

Management (also available as `claudeyctl`):

```text
claudey setup | start | stop | status | update | rollback | doctor
claudey auth {codex|antigravity|grok|all} [options]
claudey models {codex|antigravity|grok|cursor|all} [--json]
claudey config set port PORT --yes
claudey uninstall [--dry-run] [--purge-auth] [--yes]
```

Global flags: `--json`, `--no-color`, `--verbose`, `--non-interactive` (`CI=true` forces noninteractive).

Full command list and Windows checkout equivalents remain in git history and [troubleshooting](docs/troubleshooting.md).

---

## Documentation

| Topic | Doc |
|---|---|
| Usage labels, per-provider verify steps, failure tables | [docs/usage-and-model-picker.md](docs/usage-and-model-picker.md) |
| Antigravity / Grok usage fixes (2026-08-17) | [docs/superpowers/specs/2026-08-17-provider-usage-and-picker-hardening-design.md](docs/superpowers/specs/2026-08-17-provider-usage-and-picker-hardening-design.md) |
| Provider-labeled mixed selection | [docs/superpowers/specs/2026-08-16-provider-labeled-model-selection-design.md](docs/superpowers/specs/2026-08-16-provider-labeled-model-selection-design.md) |
| Errors, recovery, rollback | [docs/troubleshooting.md](docs/troubleshooting.md) |
| Security model | [docs/security.md](docs/security.md) |
| Release validation | [docs/validation/README.md](docs/validation/README.md) |

---

## Recovery

Interrupted install or odd gateway state:

```text
claudey doctor
```

Do not delete locks, journals, or OAuth files by hand. Rollback: `claudey rollback --yes`. Uninstall preview: `claudey uninstall --dry-run`.
