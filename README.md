# zks — zero-knowledge secrets for AI agents

`zks` is a macOS CLI that writes secrets and env vars to Vercel, AWS SSM Parameter Store, AWS Secrets Manager, GitHub Actions, Railway and Supabase **without the agent ever seeing a value**. The agent edits a policy file with names, targets and *sources* (1Password, Keychain, hidden dialog, generator, dotenv file). zks resolves each value itself, shows you one native approval dialog (or none, for a destination you already chose "Always allow" for), writes straight to the provider, and records metadata only in a hash-chained audit log. With `zks capture`, the agent also obtains web-issued tokens and API keys itself in ego-browser without seeing them: zks's own browser script moves the value between the page and the Keychain.

## What is guaranteed, and what is not

**Guaranteed by design**

- Secret values never appear in zks argv, environment, stdout, stderr, temp files or the audit log. Output is JSON metadata; any echoed secret is scrubbed.
- zks rejects secret values on the command line (`--value`, `--secret`, `--token`, `--password`) and in the policy (`value` is only allowed when `sensitive: false`). Any `source` requires `sensitive: true`, so a resolved value can never go out as a readable plain variable.
- Nothing is written to a new destination until you click **Approve once** or **Always allow** in a macOS dialog. The dialog lists every write with its real destination (Vercel project/team, AWS region/name/role/profile/KMS key, GitHub repo/environment, Railway ids, Supabase project, the absolute path of a dotenv file), marks writes to a destination you have not trusted yet with `[NEW destination]`, and is never truncated: at most 20 writes, 300 characters per line and 6000 in total per apply (`too_many_operations` / `dialog_too_long` otherwise). Denial, timeout or no GUI writes nothing and is audited as `denied`. See [Trusted destinations](#trusted-destinations).
- zks ignores the caller's environment: the launcher runs node through `env -i` with only `HOME`, `USER`, `LOGNAME`, `LANG`, a fixed `PATH` and the agent label, and zks empties `process.env` again before loading anything else. Variables such as `AWS_ENDPOINT_URL`, `HTTPS_PROXY`, `NODE_EXTRA_CA_CERTS`, `GH_HOST` or `XDG_CONFIG_HOME` cannot redirect a write, and `endpoint_url` in `~/.aws/config` is ignored.
- GitHub writes go from zks straight to `https://api.github.com` (secrets sealed with the repository's libsodium public key). The `gh` CLI is only asked for your login token (`gh auth token --hostname github.com`), so its config (hosts, `http_unix_socket`) cannot redirect a write.
- Provider tokens live in the macOS Keychain; AWS uses your existing SSO or profile credentials.
- `zks capture` reads a token from a web page (or fills a password into one) inside a script zks builds and pipes to `ego-browser nodejs`; the value goes straight between the page and `/usr/bin/security`, and zks prints only its length. zks provider tokens (`zks/vercel`, `zks/railway`, `zks/supabase`, `zks/sheets-hmac`) are only captured from their pinned provider origin. See [Web token capture](#web-token-capture).
- zks never looks `ego-browser`, `gh` or `op` up on `PATH`: `install.sh` records their real paths in the read-only install (`tools.json`, covered by the integrity digest).

**Honest limits**

- Values transit the zks process memory briefly: read, send, zero. zks zeroes its buffers and disables core dumps, but it cannot stop the OS from paging memory to swap, and the short-lived JavaScript strings sent to provider APIs cannot be zeroed.
- An agent running as the **same macOS user** has the same file and Keychain access as you:
  - the install integrity check (`zks doctor`) is **tamper-evident, not tamper-proof**: it detects a modified install, it cannot prevent one;
  - Keychain items (provider tokens, the audit anchor) can be read with `/usr/bin/security find-generic-password -w` by any process of the same user. The skill and `~/AGENTS.md` rule forbid this; they cannot enforce it. For a hard boundary, run the agent as a dedicated macOS user;
  - it can edit the files zks trusts after `env -i`: `~/.aws/config` (`credential_process`), `~/.config/gh` (the login token zks reads) and the Homebrew binaries on the fixed `PATH` (`/opt/homebrew/bin/gh`, `op`);
  - it can read the `trust-hmac` Keychain item and forge `~/.config/zks/trust.json`, so trusted destinations stop a confused or prompt-injected agent, not a same-user agent that attacks zks itself.
- The agent field of the audit log (`actorAgent`) is a **self-declared label** (`--agent`, `PI_SESSION_ID`, `AI_AGENT`); zks cannot authenticate who asked.
- The local hash chain, the Keychain anchor (`audit-head`) and the Sheet mirror make tampering with the audit log **evident, not impossible**.
- After the write, the provider's own access rules apply. Vercel `sensitive` variables and GitHub secrets cannot be read back; SSM SecureString and Secrets Manager values can be read by any principal with decrypt/read permission; Railway variables stay readable by every member of the Railway project.
- `zks capture` trusts the same-user agent to follow the skill: while a page shows a revealed token, or after a fill while the password field holds the value, the agent's own ego-browser session could read it. zks shrinks that window (it clicks the reveal itself, blanks the element, leaves the page on `about:blank` after every reveal click, and fills only password inputs), it cannot close it. The ego-browser runtime holds the value in memory while the script runs.
- The first capture into a `zks/*` token (`zks/vercel`, `zks/railway`, `zks/supabase`, `zks/sheets-hmac`) needs no approval: only replacing an existing one does. The pinned origin limits it to the provider's own site, so an agent can only store a token that site issued to your logged-in session; a same-user agent could still store a token of its choosing there (same-user limit).
- `fill --from` decides "same origin, no dialog" from the local audit log, which a same-user process can rewrite (tamper-evident through `zks audit verify`, not tamper-proof).
- `tools.json` stores real paths, which include version directories (Homebrew `Cellar`/`Caskroom`, ego's `Versions/<n>`): after upgrading `gh`, `op` or ego-browser, rerun `./install.sh`, or zks reports the tool unavailable.
- The Google Sheets audit is a **mirror**. The source of truth is the local log (`zks audit verify`) and the providers' own audit logs.

## Quick start

```sh
./install.sh                     # macOS, node >= 22.18; builds, tests and installs ~/.local/bin/zks
# Tokens: your agent creates them on the provider site and runs `zks capture` (no copy-paste).
# Without an agent: zks auth set vercel|railway|supabase (hidden dialog).
aws sso login                    # AWS uses your SSO/profile credentials
gh auth login                    # GitHub: zks reads this session's token and calls the API itself
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
zks capture read --space ID --page LABEL --selector CSS --store SERVICE/ACCOUNT [--click SELECTOR] [--origin ORIGIN]
                                            In an ego-browser page: click, read the token element
                                            into the Keychain, blank it (value never shown)
zks capture fill --space ID --page LABEL --selector CSS (--store SERVICE/ACCOUNT --generate BYTES
                 | --from SERVICE/ACCOUNT) --origin ORIGIN
                                            Fill a new random (16-128 bytes) or a stored password
                                            into one password input of an ego-browser page; --from
                                            into another origin than the item came from asks first
zks audit list [--limit N] [--project P]    Show audit records (metadata only)
zks audit verify                            Check the audit hash chain
zks audit sync                              Push pending audit records to Google Sheets
zks trust list                              Show trusted destinations (writes there need no dialog)
zks trust remove <key>                      Stop trusting a destination (no dialog needed)
zks config show
zks config set sheets-webhook <url>         Apps Script /exec URL for the audit mirror
zks config unset sheets-webhook
zks doctor                                  Check tools, tokens, audit and install integrity
zks --version | zks help
```

## Providers

| `provider` | Writes | Credentials | Required fields | Optional fields |
|---|---|---|---|---|
| `vercel` | project env var, type `sensitive` or `plain` | `zks/vercel` (`zks capture` or `zks auth set vercel`) | `projectId`, `environments` | `teamId`, `gitBranch` |
| `aws-ssm` | parameter `<prefix><NAME>`, `SecureString` or `String` | AWS SSO / profile, optional `roleArn` | `region`, `prefix` (`/a/b/`, at most 200 characters) | `profile`, `roleArn`, `kmsKeyId` |
| `aws-sm` | secret `<prefix><NAME>` (new version or create) | AWS SSO / profile, optional `roleArn` | `region`, `prefix` (`a/b/`, at most 200 characters) | `profile`, `roleArn`, `kmsKeyId` |
| `github` | Actions secret (sensitive, sealed-box encrypted) or variable (plain), through `api.github.com` | `gh auth login` (zks reads the token with `gh auth token`) | `repo` (at most 100 characters) | `environment` |
| `railway` | service or shared variable | `zks/railway` (`zks capture` or `zks auth set railway`) | `projectId`, `environmentId` | `serviceId`, `tokenType`, `skipDeploys` |
| `supabase` | Edge Functions secret | `zks/supabase` (`zks capture` or `zks auth set supabase`) | `projectRef` (20 lowercase alphanumerics) | — |

Rules: Vercel sensitive variables cannot target `development`; Supabase rejects names starting with `SUPABASE_`. Variable names `__proto__`, `constructor` and `prototype` (any case) are reserved.

## Sources

| `source.kind` | Where the value comes from | Use when |
|---|---|---|
| `op` | `op read <ref>` (1Password CLI) | the value is in 1Password; the `op://` reference is not secret |
| `keychain` | macOS Keychain item `service`/`account` | the value is already in the Keychain |
| `prompt` | hidden macOS dialog | the human types or pastes it |
| `generate` | local CSPRNG, `bytes` 16–512, `base64url` or `hex` | a new random key; **rotates on every apply** |
| `dotenv` | a dotenv file read by zks (`path`, optional `key`) | migrating an existing `.env` file |
| *(none)* `value` | literal in the policy | only `sensitive: false` env vars |

Source rules:

- Every `source` needs `"sensitive": true`. Only a literal `value` can be non-sensitive.
- `keychain`: `service` and `account` match `^[A-Za-z0-9_.-]{1,128}$`; the service `zks` (in any case) is reserved for zks's own tokens.
- `dotenv`: `path` is a relative `.env*` file inside the project (for example `.env.production` or `apps/web/.env.local`): ASCII, no `..`, no absolute path, at most 200 characters. `plan` and the dialog show it resolved to an absolute path; zks reads the resolved real path it checked.
- `op`: `ref` is `op://` followed by printable ASCII without spaces, at most 200 characters.

Each command refuses options it does not use (`option --X is not valid for <command>`, exit 2).

## Trusted destinations

The first write to a destination opens the dialog with three buttons: **Deny** (default), **Approve once** and **Always allow**. "Always allow" trusts each `[NEW destination]` of that apply, from any project, from then on; an apply whose destinations are all trusted opens no dialog and is audited with `approval: "trusted"`.

| Destination key | Trusts |
|---|---|
| `github:<owner>` | every repository of that GitHub owner (lower case) |
| `vercel:team:<teamId>` or `vercel:personal` | every project of that Vercel team, or of the personal account (no `teamId`) |
| `aws:<profile or default>:<roleArn or no-role>:<region>` | SSM and Secrets Manager writes with that profile, role and region |
| `railway:<projectId>` | that Railway project |
| `supabase:<projectRef>` | that Supabase project |

Keys trusted before this format (`vercel:<teamId>`) no longer match any write; `zks trust list` describes them as an old Vercel key format and `zks trust remove <key>` drops them. The keys live in `~/.config/zks/trust.json` (mode `600`), signed with HMAC-SHA256 by a key in the Keychain item `zks`/`trust-hmac`. A file that is unparsable or whose signature does not match trusts nothing: every write asks again and `apply` and `doctor` report `trust: "invalid"`. `zks trust list` shows the keys; `zks trust remove <key>` drops one without a dialog.

## Web token capture

The agent drives the non-secret steps in an ego-browser TaskSpace (open the token page, fill the token name and expiry), then hands the secret step to zks:

```sh
zks capture read --space 7 --page p1 --click "loc=role:button[name='Create']" \
  --selector "[role=dialog] input[readonly]" --store zks/vercel --origin https://vercel.com
zks capture fill --space 7 --page p1 --selector "#password" --store indec/password --generate 24 \
  --origin https://api.indec.gob.ar
zks capture fill --space 7 --page p1 --selector "#password" --from indec/password --origin https://api.indec.gob.ar
```

- zks builds the script itself (every input embedded only through `JSON.stringify`) and pipes it to `ego-browser nodejs`. The script checks the page origin (`--origin`), optionally clicks `--click` (any ego selector), waits up to 15 s for `--selector` (plain CSS, exactly one element) to hold a value, takes `value` (inputs, textareas) or the trimmed text, blanks the element (`""` or `[captured by zks]`), stores it with `/usr/bin/security -i` (on stdin, hex) and navigates the page to `about:blank`. Once a `--click` ran (or was attempted), the page goes to `about:blank` on every outcome, including `not_found`, `origin_mismatch`, `keychain_failed` and errors.
- `fill` always needs `--origin`. `fill --generate BYTES` (16–128) makes a base64url password in zks, stores it, and the script reads it back inside ego (`security find-generic-password -w`, kept in memory). `fill --from SERVICE/ACCOUNT` fills an existing item. The script then runs one `page.evaluate` in the page's main frame that re-checks `document.location.origin`, requires `--selector` to match exactly one `<input type="password">` (otherwise `not_password_field`, nothing filled), sets it with the native value setter and fires `input` and `change`. It never uses `page.fill`, so it never reaches into iframes. The value never appears in the script, argv or output.
- `fill --from` runs without a dialog only into the origin the item was last captured or generated from (the latest applied `capture-read` or `capture-generate` audit record of that item). Any other origin, or an item with no such record, asks "Fill <service>/<account> into <origin>?"; denial exits 3, is audited `denied` and runs nothing. An approved fill does not make the next one silent.
- The script prints one line, `ZKS_RESULT {"ok":true,"length":N}` or `{"ok":false,"code":...}`; zks reads only that line and never relays any other ego output.
- Output: `{ok, command: "capture", mode: "read"|"fill", store, origin, length, auditId, mirror}`. Errors (exit 1): `origin_mismatch` (nothing stored or filled), `not_found`, `not_password_field`, `keychain_failed`, `browser_failed`. Usage errors exit 2 and never echo a value.
- One-time codes that are not secrets worth keeping (an e-mail verification code) are not captured: the agent types them with normal ego actions.
- Service `zks` (any case) is reserved: only `zks/vercel` (`--origin https://vercel.com`), `zks/railway` (`https://railway.com`), `zks/supabase` (`https://supabase.com`) and `zks/sheets-hmac` (`https://script.google.com`) can be captured, only with `read` and only from that origin. `fill` never uses service `zks`.
- Replacing an existing Keychain item (`read`, `fill --generate`) opens an approval dialog first; denial exits 3 and runs nothing. The first capture into a new item, `zks/*` included, needs no approval (see [What is guaranteed, and what is not](#what-is-guaranteed-and-what-is-not)).
- Every capture is audited: `provider: "keychain"`, `action: "capture"`, `target: "<service>/<account>"`, `environment: <origin>`, `sourceKind: capture-read|capture-generate|capture-from`, result `applied`, `failed` or `denied`. Like `apply`, every capture then pushes pending records to the Sheets mirror (best effort) and reports it in `mirror`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ok |
| 1 | a write or check failed |
| 2 | usage or policy error |
| 3 | not approved (denied, timed out or no GUI) |

## Audit

Every apply appends one record per variable × target to `~/.local/state/zks/audit.db` (SQLite, append-only triggers, SHA-256 hash chain): time, human, agent, project, provider, target, environment, variable name, sensitive flag, source kind, result, provider version, error code, approval mode (`dialog` or `trusted`). There is no field for a value or a hash of a value.

- `zks audit list` — read records.
- `zks audit verify` — check the chain, and check it against the anchor (record count and last hash) that every apply stores in the Keychain item `zks`/`audit-head`; a deleted tail fails with `brokenAt: "truncated"`.
- `zks audit sync` — push to the optional Google Sheets mirror; setup in [docs/apps-script](./docs/apps-script/README.md). `zks config set|unset sheets-webhook` asks for your approval in a dialog.

## Uninstall

```sh
./uninstall.sh
```

Removes the launcher, `~/.local/libexec/zks` (with `tools.json`), the skill and the `~/AGENTS.md` block. Keeps the audit log, `~/.config/zks`, the Keychain tokens and any item `zks capture` stored under another service, and prints where they are.

## Development

```sh
npm ci
npm run check    # typecheck + tests
npm run build    # dist/
npm run deps:check   # exact versions, v3 lockfile in sync, no high/critical npm audit finding
npm run sbom         # CycloneDX SBOM of the production dependencies on stdout
```

CI runs the same steps on every push and pull request to `main` and `develop`, plus `deps:check --strict` (an unreachable registry fails), `npm audit signatures` and an `sbom` artifact.

### Supply chain

- Every dependency in `package.json` is an exact version and `.npmrc` sets `save-exact=true`; `deps:check` fails on a range, a tag, a URL or a lockfile that disagrees with `package.json`.
- `install.sh` runs `deps:check` before building (an offline registry only warns) and writes `sbom.cdx.json` into the read-only install, so the integrity digest covers it.
- socket.dev is not wired in: it needs an account and an API token; `npm audit` plus `npm audit signatures` cover known advisories and registry signatures.

## Docs

- [Architecture, trust boundaries and threat model](./docs/architecture.md)
- [Agent flow and source decision table](./docs/agent-flow.md)
- [Google Sheets audit mirror](./docs/apps-script/README.md)
- [Agent skill](./skill/SKILL.md)
