# zks — zero-knowledge secrets for AI agents

`zks` is a macOS CLI that writes secrets and env vars to Vercel, AWS SSM Parameter Store, AWS Secrets Manager, GitHub Actions, Railway and Supabase **without the agent ever seeing a value**. The agent edits a policy file with names, targets and *sources* (1Password, Keychain, hidden dialog, generator, dotenv file). zks resolves each value itself, shows you one native approval dialog, writes straight to the provider, and records metadata only in a hash-chained audit log.

## What is guaranteed, and what is not

**Guaranteed by design**

- Secret values never appear in zks argv, environment, stdout, stderr, temp files or the audit log. Output is JSON metadata; any echoed secret is scrubbed.
- zks rejects secret values on the command line (`--value`, `--secret`, `--token`, `--password`) and in the policy (`value` is only allowed when `sensitive: false`).
- Nothing is written until you click **Approve** in a macOS dialog. Denial, timeout or no GUI writes nothing and is audited as `denied`.
- Provider tokens live in the macOS Keychain; AWS uses your existing SSO or profile credentials.

**Honest limits**

- Values transit the zks process memory briefly: read, send, zero. zks zeroes its buffers and disables core dumps, but it cannot stop the OS from paging memory to swap, and the short-lived JavaScript strings sent to provider APIs cannot be zeroed.
- An agent running as the **same macOS user** has the same file and Keychain access as you:
  - the install integrity check (`zks doctor`) is **tamper-evident, not tamper-proof**: it detects a modified install, it cannot prevent one;
  - Keychain items can be read with `security find-generic-password -w` by the same user unless their ACL restricts it. The skill and `~/AGENTS.md` rule forbid this; they cannot enforce it.
- After the write, the provider's own access rules apply. Vercel `sensitive` variables and GitHub secrets cannot be read back; SSM SecureString and Secrets Manager values can be read by any principal with decrypt/read permission; Railway variables stay readable by every member of the Railway project.
- The Google Sheets audit is a **mirror**. The source of truth is the local log (`zks audit verify`) and the providers' own audit logs.

## Quick start

```sh
./install.sh                     # macOS, node >= 22.18; builds, tests and installs ~/.local/bin/zks
zks auth set vercel              # hidden dialog; repeat for railway and supabase as needed
aws sso login                    # AWS uses your SSO/profile credentials
gh auth login                    # GitHub uses the gh CLI session
cd my-app && zks init --project my-app
$EDITOR zks.policy.json          # names, targets, sources — never values
zks validate && zks plan
zks apply --only STRIPE_SECRET_KEY --target vercel-prod
```

A full six-provider policy lives in [`zks.policy.example.json`](./zks.policy.example.json).

## Commands

```text
zks init [--policy FILE] [--project NAME]   Create a zks.policy.json template
zks validate [--policy FILE]                Check the policy
zks plan [--policy FILE] [--only A,B] [--target t1,t2]
                                            List the writes apply would make (no network)
zks apply [--policy FILE] [--only A,B] [--target t1,t2] [--agent LABEL]
                                            Ask for approval, then write values to providers
zks auth status                             Show which provider tokens are in the Keychain
zks auth set <vercel|railway|supabase|sheets-hmac>
                                            Store a token through a hidden dialog
zks auth delete <vercel|railway|supabase|sheets-hmac>
zks audit list [--limit N] [--project P]    Show audit records (metadata only)
zks audit verify                            Check the audit hash chain
zks audit sync                              Push pending audit records to Google Sheets
zks config show
zks config set sheets-webhook <url>         Apps Script /exec URL for the audit mirror
zks config unset sheets-webhook
zks doctor                                  Check tools, tokens, audit and install integrity
zks --version | zks help
```

## Providers

| `provider` | Writes | Credentials | Required fields | Optional fields |
|---|---|---|---|---|
| `vercel` | project env var, type `sensitive` or `plain` | `zks auth set vercel` | `projectId`, `environments` | `teamId`, `gitBranch` |
| `aws-ssm` | parameter `<prefix><NAME>`, `SecureString` or `String` | AWS SSO / profile, optional `roleArn` | `region`, `prefix` (`/a/b/`) | `profile`, `roleArn`, `kmsKeyId` |
| `aws-sm` | secret `<prefix><NAME>` (new version or create) | AWS SSO / profile, optional `roleArn` | `region`, `prefix` (`a/b/`) | `profile`, `roleArn`, `kmsKeyId` |
| `github` | Actions secret (sensitive) or variable (plain) | `gh auth login` | `repo` | `environment` |
| `railway` | service or shared variable | `zks auth set railway` | `projectId`, `environmentId` | `serviceId`, `tokenType`, `skipDeploys` |
| `supabase` | Edge Functions secret | `zks auth set supabase` | `projectRef` (20 lowercase alphanumerics) | — |

Rules: Vercel sensitive variables cannot target `development`; Supabase rejects names starting with `SUPABASE_`.

## Sources

| `source.kind` | Where the value comes from | Use when |
|---|---|---|
| `op` | `op read <ref>` (1Password CLI) | the value is in 1Password; the `op://` reference is not secret |
| `keychain` | macOS Keychain item `service`/`account` | the value is already in the Keychain |
| `prompt` | hidden macOS dialog | the human types or pastes it |
| `generate` | local CSPRNG, `bytes` 16–512, `base64url` or `hex` | a new random key; **rotates on every apply** |
| `dotenv` | a dotenv file read by zks (`path`, optional `key`) | migrating an existing `.env` file |
| *(none)* `value` | literal in the policy | only `sensitive: false` env vars |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ok |
| 1 | a write or check failed |
| 2 | usage or policy error |
| 3 | not approved (denied, timed out or no GUI) |

## Audit

Every apply appends one record per variable × target to `~/.local/state/zks/audit.db` (SQLite, append-only triggers, SHA-256 hash chain): time, human, agent, project, provider, target, environment, variable name, sensitive flag, source kind, result, provider version, error code. There is no field for a value or a hash of a value.

- `zks audit list` — read records.
- `zks audit verify` — check the chain.
- `zks audit sync` — push to the optional Google Sheets mirror; setup in [docs/apps-script](./docs/apps-script/README.md).

## Uninstall

```sh
./uninstall.sh
```

Removes the launcher, `~/.local/libexec/zks`, the skill and the `~/AGENTS.md` block. Keeps the audit log, `~/.config/zks` and the Keychain tokens, and prints where they are.

## Development

```sh
npm ci
npm run check    # typecheck + tests
npm run build    # dist/
```

CI runs the same steps on every push and pull request to `main` and `develop`.

## Docs

- [Architecture, trust boundaries and threat model](./docs/architecture.md)
- [Agent flow and source decision table](./docs/agent-flow.md)
- [Google Sheets audit mirror](./docs/apps-script/README.md)
- [Agent skill](./skill/SKILL.md)
