# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.2.x | yes |
| < 0.2 | no |

Fixes land on `develop` and ship in the next 0.2.x release.

## Reporting a vulnerability

Report vulnerabilities privately. **Do not open a public issue, discussion or pull request for a vulnerability.**

- Use GitHub private vulnerability reporting: [Report a vulnerability](https://github.com/mauroociappinaph/zk-secrets/security/advisories/new) (repository **Security** tab → **Advisories** → **Report a vulnerability**).
- Include the zks version (`zks --version`), macOS and node versions, the install mode (user or `--system`), the steps to reproduce and what an attacker gains.
- Never include a real secret value, a real provider token or audit records with real project or variable names. Use throwaway values.

You will get an acknowledgement within **7 days**. The maintainer then confirms or rejects the report, agrees a fix and disclosure date with you, and publishes a GitHub Security Advisory with credit (unless you prefer not to be named).

## Scope

In scope: anything that lets an agent or another process

- obtain a secret value through zks: through its argv, environment, stdout, stderr, temp files, the audit log, the dialog, an error message, a `zks capture` script or a provider write zks makes to a destination other than the one shown;
- bypass the approval dialog or the trusted-destination check: a write to a new destination, a `zks rotate` or `zks run` without the dialog, a dialog that hides or misstates a write, or a forged trust entry accepted without the HMAC key;
- tamper with the audit log without `zks audit verify` detecting it.

Out of scope: the limits zks already documents as limits, above all what an agent running as the **same macOS user** can do (read Keychain items with `/usr/bin/security`, edit `~/.aws/config` or `~/.config/gh`, replace Homebrew binaries, rewrite the local audit log in a tamper-evident way). They are described in the threat model in [docs/architecture.md](./docs/architecture.md) and in the "Honest limits" part of [README.md](./README.md#what-is-guaranteed-and-what-is-not). They are not vulnerabilities; a way around one of zks's checks that does **not** rely on them is.

Also out of scope: the providers' own access rules after a write (who can read an SSM SecureString, a Railway variable), and vulnerabilities in `gh`, `op`, `docker`, ego-browser or the providers themselves (report those to their vendors).
