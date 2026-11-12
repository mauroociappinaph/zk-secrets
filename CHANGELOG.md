# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `zks run [--policy FILE] [--only A,B] [--agent LABEL] -- <command> [args...]`: runs one command with the selected variables as environment variables of that child process only. The dialog opens on every run (Deny / Approve, never Always allow) and shows the executable, its full arguments, the working directory and each variable name with its source. Generated variables are skipped unless named, and naming one is a usage error. zks exits with the command's own exit code and forwards `SIGINT`, `SIGTERM` and `SIGHUP`. Each run is audited per variable (`action: "run"`), never with values or arguments.

## [0.2.0] - 2026-11-12

### Added

- Security hardening:
  - `sudo ./install.sh --system`: a root-owned, read-only install under `/usr/local/libexec/zks`, with an ownership check in `zks doctor`.
  - `gh`, `op`, `docker` and ego-browser are pinned by path and binary sha256 in `tools.json`. A changed binary is refused.
  - Both `npm ci` runs of `install.sh` are isolated from the user's npm config, cache and logs.
  - CycloneDX SBOM (`npm run sbom`, `sbom.cdx.json` in the install), `npm run deps:check` (exact versions, lockfile in sync, `npm audit`) and `npm audit signatures` in CI.
- `zks capture --isolated`: the secret step runs in a space zks opens in a separate ego-browser profile (`zks config set capture-profile`), without the agent's session, and closes afterwards.
- Sources:
  - `generate` formats `uuid`, `jwt-secret`, `password`, `rsa-private-key` and `ed25519-private-key`.
  - `template` (`${NAME}`, `${NAME:url}`) and `public-key`, both derived in memory in the same apply.
- `zks rotate NAME`: writes a new value of a generated variable and its derived variables to their targets. It always asks first and does not revoke the old value.
- `zks inventory`: shows which variable is in which destination and how old it is (audit metadata only).
- `plan` effects per provider (`effect` per operation and an `effects` summary).
- `zks doctor --fix`: repairs the modes of the zks config and state files and lists what it cannot fix.
- New destinations: `netlify`, `docker-swarm` (unix socket only), `compose` secret files and `dotenv` (`.env*` files, mode 600).

### Changed

- The `dotenv` **source** now decodes `\\`, `\"`, `\$`, `\n` and `\r` inside double-quoted values, the same escapes the `dotenv` destination writes. A double-quoted value that held one of these sequences literally now resolves to a different value.

## [0.1.0] - 2026-11-04

### Added

- The `zks` CLI with `init`, `validate`, `plan`, `apply`, `auth`, `audit`, `config` and `doctor`. The agent edits a policy of names, targets and sources; zks resolves values itself and never prints, logs or accepts them on the command line or in the policy.
- Sources: 1Password (`op`), macOS Keychain, a hidden prompt dialog, a local CSPRNG generator (`generate`) and dotenv files. Literal values are allowed only for non-sensitive variables.
- Native macOS approval dialog listing every write with its real destination. Denial, timeout or no GUI writes nothing and is audited as `denied`.
- Destinations: Vercel, AWS SSM Parameter Store, AWS Secrets Manager, GitHub Actions secrets and variables (REST API, sealed-box encryption), Railway and Supabase.
- Trusted destinations (Deny / Approve once / Always allow) in an HMAC-signed trust store, with `zks trust list|remove`.
- `zks capture read|fill`: zks's own ego-browser script reads web-issued tokens into the Keychain or fills a generated or stored password into one password input. zks provider tokens are captured only from pinned provider origins.
- Metadata-only audit log: append-only SQLite with a SHA-256 hash chain, a Keychain anchor, `zks audit list|verify|sync` and an optional HMAC-signed Google Sheets mirror.
- Hardening: zks ignores the caller's environment (`env -i`), ignores AWS `endpoint_url` and `gh` host config, rejects prototype keys and bounds the dialog size.
- `install.sh` and `uninstall.sh`, a global agent skill (`skill/SKILL.md`), a `~/AGENTS.md` rule, architecture and agent-flow docs, and CI.

[Unreleased]: https://github.com/mauroociappinaph/zk-secrets/compare/main...develop
[0.2.0]: https://github.com/mauroociappinaph/zk-secrets/compare/79a2cf4...3dc166c
[0.1.0]: https://github.com/mauroociappinaph/zk-secrets/commits/79a2cf4
