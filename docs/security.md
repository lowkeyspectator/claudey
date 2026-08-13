# Security model

Claudex is designed to fail closed at executable, filesystem, process, archive, network, and release boundaries. It reduces accidental exposure and confused-deputy behavior; it does not turn all same-user tools into a hard sandbox.

## Trust boundaries

- CLIProxyAPI is a third-party binary with access to provider OAuth material and prompt traffic. It is not endorsed by OpenAI, Anthropic, Google, Cursor, or Anthropic.
- Provider terms can change. Subscription OAuth routed through a proxy may have account consequences. Authentication is an explicit OAuth action and never runs during setup, CI, or a noninteractive command.
- Cursor installation is a separate explicit Cursor installation operation. Cursor Agent is beta, must pass live capability/identity probes, and is trusted code running as the current user.
- A same-user process is not a sandbox. Snapshots and worktrees protect the caller's checkout from ordinary working-directory writes, not from malicious reads or writes elsewhere in the account.

## Gateway and credential boundary

The managed gateway listens only on `127.0.0.1`, and every API request requires the per-installation bearer token. Loopback reduces network exposure but is not authentication. The process identity, complete descendant tree, PID start identity, listener ownership, and authenticated health response are checked before adoption or termination.

The bearer token, manifest-authentication key, and OAuth files are kept under protected per-user roots. They never belong in arguments, global environment, shell profiles, repository files, general backups, logs, JSON, diagnostics, snapshots, or Cursor child environments. Secret values use opaque types and provenance-based redaction; release tests scan for unique canaries.

WSL is a separate installation. Do not place WSL state in `/mnt/c` or reuse Windows tokens, OAuth files, binaries, configuration, or PID metadata. WSL and Windows localhost forwarding may produce a port collision. Assign one installation a different port; never adopt or kill the other environment's process.

## Release integrity and provenance limits

Downloaded archives are bounded, preflighted, safely extracted, re-walked, hashed, and matched to the closed release manifest. A checksum detects changed transfer bytes. A checksum published by the same compromised account does not establish publisher identity. The release SBOM and provenance subjects must match the manifest and checksum set exactly, and the produced attestation must be independently verified.

Provenance describes the Claudex build. It does not attest that CLIProxyAPI, Claude Code, Cursor Agent, Node.js, or provider services are harmless. Upstream drift, dynamic entitlements, and provider behavior remain external risks and are checked again at runtime.

## Filesystem and process safety

Managed paths are canonical, bounded to fixed roots, and revalidated before mutation. Links, junctions, reparse points, hard links, cross-device surprises, unsafe ownership/permissions, and identity swaps fail closed. Cleanup targets only authenticated, unchanged, installation-owned paths. Unconfirmed process termination or ambiguous storage identity retains evidence for recovery instead of guessing.

Cursor subprocesses receive a minimal allowlisted environment without gateway/provider/GitHub/cloud credentials. Cancellation and timeouts use bounded process-tree cleanup. Approval for a write-capable worktree is encrypted at rest, expires, and is single-use.

## Reporting vulnerabilities

The repository policy is defined in [`SECURITY.md`](../SECURITY.md). Do not place secrets, OAuth files, tokens, private prompts, or exploit details in a public issue.

As of 2026-08-13, private vulnerability reporting could not be independently verified from the public repository metadata. Publication is blocked until a maintainer enables it and verifies the authenticated reporting form. The unverified form URL is intentionally not advertised.
