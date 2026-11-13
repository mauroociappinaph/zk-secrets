# zks — secrets for AI agents that never see them

`zks` is a macOS CLI that writes secrets and env vars to Vercel, AWS SSM Parameter Store, AWS Secrets Manager, GitHub Actions, Railway, Supabase, Netlify, Docker Swarm, Compose secret files and local `.env` files **without the agent ever seeing a value**. The agent edits a policy file with names, targets and *sources* (1Password, Keychain, hidden dialog, generator, dotenv file). zks resolves each value itself, shows you one native approval dialog (or none, for a destination you already chose "Always allow" for), writes straight to the provider, and records metadata only in a hash-chained audit log. With `zks capture`, the agent also obtains web-issued tokens and API keys itself in ego-browser without seeing them: zks's own browser script moves the value between the page and the Keychain.

## What is guaranteed, and what is not

**Guaranteed by design**

- Secret values never appear in zks argv, environment, stdout, stderr, temp files or the audit log. Output is JSON metadata; any echoed secret is scrubbed. File destinations (`compose`, `dotenv`) are written through a mode-600 file in the destination directory that is renamed into place: that file is the destination, and it is removed if the write fails.
- zks rejects secret values on the command line (`--value`, `--secret`, `--token`, `--password`) and in the policy (`value` is only allowed when `sensitive: false`). Any `source` requires `sensitive: true`, so a resolved value can never go out as a readable plain variable.
- Nothing is written to a new destination until you click **Approve once** or **Always allow** in a macOS dialog. The dialog lists every write with its real destination (Vercel project/team, AWS region/name/role/profile/KMS key, GitHub repo/environment, Railway ids, Supabase project, Netlify account/site/context, docker host and secret name, the absolute path of a Compose secret file, the absolute path of a dotenv file), marks writes to a destination you have not trusted yet with `[NEW destination]`, and is never truncated: at most 20 writes, 300 characters per line and 6000 in total per apply (`too_many_operations` / `dialog_too_long` otherwise). Denial, timeout or no GUI writes nothing and is audited as `denied`. See [Trusted destinations](#trusted-destinations).
- zks ignores the caller's environment: the launcher runs node through `env -i` with only `HOME`, `USER`, `LOGNAME`, `LANG`, a fixed `PATH` and the agent label, and zks empties `process.env` again before loading anything else. Variables such as `AWS_ENDPOINT_URL`, `HTTPS_PROXY`, `NODE_EXTRA_CA_CERTS`, `GH_HOST` or `XDG_CONFIG_HOME` cannot redirect a write, and `endpoint_url` in `~/.aws/config` is ignored.
- GitHub writes go from zks straight to `https://api.github.com` (secrets sealed with the repository's libsodium public key). The `gh` CLI is only asked for your login token (`gh auth token --hostname github.com`), so its config (hosts, `http_unix_socket`) cannot redirect a write.
- Provider tokens live in the macOS Keychain; AWS uses your existing SSO or profile credentials.
- `zks capture` reads a token from a web page (or fills a password into one) inside a script zks builds and pipes to `ego-browser nodejs`; the value goes straight between the page and `/usr/bin/security`, and zks prints only its length. zks provider tokens (`zks/vercel`, `zks/railway`, `zks/supabase`, `zks/netlify`, `zks/sheets-hmac`) are only captured from their pinned provider origin. See [Web token capture](#web-token-capture).
- zks never looks `ego-browser`, `gh`, `op` or `docker` up on `PATH`: `install.sh` records `docker` only when it finds it on the fixed system path (`/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin`) and records their real paths and the sha256 of each binary in the read-only install (`tools.json`, covered by the integrity digest). zks runs a tool only while its binary still has that hash; a changed binary is refused with a stderr warning (`zks: gh changed since install (sha256 mismatch); rerun ./install.sh to pin the new binary`), the command reports the tool unavailable, and `zks doctor` shows `tools.pins.<tool>: "changed"`.

**Honest limits**

- Values transit the zks process memory briefly: read, send, zero. zks zeroes its buffers and disables core dumps, but it cannot stop the OS from paging memory to swap, and the short-lived JavaScript strings sent to provider APIs cannot be zeroed.
- An agent running as the **same macOS user** has the same file and Keychain access as you:
  - with the default user install, the install integrity check (`zks doctor`) is **tamper-evident, not tamper-proof**: it detects a modified install, it cannot prevent one. `sudo ./install.sh --system` makes the app, its node, the launcher and the manifest root-owned and read-only, so the user cannot modify them (see [System install](#system-install)); a same-user agent can still put another `zks` earlier on `PATH`, so agents should call `/usr/local/libexec/zks/bin/zks`;
  - Keychain items (provider tokens, the audit anchor) can be read with `/usr/bin/security find-generic-password -w` by any process of the same user. The skill and `~/AGENTS.md` rule forbid this; they cannot enforce it. For a hard boundary, run the agent as a dedicated macOS user;
  - it can edit the files zks trusts after `env -i`: `~/.aws/config` (`credential_process`), `~/.config/gh` (the login token zks reads) and the Homebrew binaries on the fixed `PATH` (`/opt/homebrew/bin/gh`, `op`);
  - it can read the `trust-hmac` Keychain item and forge `~/.config/zks/trust.json`, so trusted destinations stop a confused or prompt-injected agent, not a same-user agent that attacks zks itself.
- The agent field of the audit log (`actorAgent`) is a **self-declared label** (`--agent`, `PI_SESSION_ID`, `AI_AGENT`); zks cannot authenticate who asked.
- The local hash chain, the Keychain anchor (`audit-head`) and the Sheet mirror make tampering with the audit log **evident, not impossible**.
- After the write, the provider's own access rules apply. Vercel `sensitive` variables and GitHub secrets cannot be read back; SSM SecureString and Secrets Manager values can be read by any principal with decrypt/read permission; Railway variables stay readable by every member of the Railway project.
- `zks capture` trusts the same-user agent to follow the skill: while a page shows a revealed token, or after a fill while the password field holds the value, the agent's own ego-browser session could read it. zks shrinks that window (it clicks the reveal itself, blanks the element, leaves the page on `about:blank` after every reveal click, and fills only password inputs), it cannot close it. The ego-browser runtime holds the value in memory while the script runs.
- The first capture into a `zks/*` token (`zks/vercel`, `zks/railway`, `zks/supabase`, `zks/netlify`, `zks/sheets-hmac`) needs no approval: only replacing an existing one does. The pinned origin limits it to the provider's own site, so an agent can only store a token that site issued to your logged-in session; a same-user agent could still store a token of its choosing there (same-user limit).
- File destinations (`compose`, `dotenv`) are plaintext files the same-user agent can read once written. Prefer **Approve once** over **Always allow** for them: a standing trust on a local `.env` would let a prompt-injected agent route any secret it can name into that file without a dialog and read it back.
- `fill --from` decides "same origin, no dialog" from the local audit log, which a same-user process can rewrite (tamper-evident through `zks audit verify`, not tamper-proof).
- `tools.json` pins each tool by path and sha256: after upgrading `gh`, `op`, `docker` or ego-browser, rerun `./install.sh`, or zks refuses the changed binary and reports the tool unavailable (`zks doctor`: `"changed"`). The hash is checked once per zks process before the first run of each tool; a binary swapped between that check and the run is not caught (same-user limit).
- `zks run` hands the values to the command it starts: that process and everything it spawns can read, print or send them. See [Run](#run).
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

A policy using every provider lives in [`zks.policy.example.json`](./zks.policy.example.json).

## What 0.2.0 to 0.7.0 add

| Area | Feature | Where to read |
| --- | --- | --- |
| Hardening | `sudo ./install.sh --system` root-owned install; `gh`, `op`, `docker`, ego-browser pinned by sha256; both `npm ci` runs isolated from your npm config; SBOM and `npm audit` on every install and in CI | [System install](#system-install), [Supply chain](#supply-chain) |
| Capture | `--isolated`: the browser script runs in a separate ego-browser profile without the agent's session | [Isolated capture](#isolated-capture---isolated) |
| Sources | `generate` formats (`uuid`, `jwt-secret`, `password`, `rsa-private-key`, `ed25519-private-key`), `template` (`${NAME}`, `${NAME:url}`) and `public-key` derived in memory | [Sources](#sources) |
| Lifecycle | `zks rotate NAME`, `zks inventory`, `plan` effects per provider, `zks doctor --fix` | [Rotate](#rotate), [Inventory](#inventory), [Plan effects](#plan-effects), [Doctor --fix](#doctor---fix) |
| Destinations | `netlify`, `docker-swarm` (unix socket only), `compose` secret files, `dotenv` (`.env*` files, mode 600) | [Providers](#providers) |
| Run (0.3.0) | `zks run -- <command>`: the selected secrets exist only in that child process; dialog every time | [Run](#run) |
| Login (0.3.0) | `zks capture login` with recipes (`hostgator`, `cpanel`): the agent's browser logs in with a Keychain password it never sees | [Login](#login-capture-login) |
| Clipboard (0.4.0) | `{"kind":"clipboard"}` source (to any destination, GitHub Actions included) and `zks capture clipboard --store SERVICE/ACCOUNT`; always asks, even for trusted destinations; the clipboard is cleared after reading only if unchanged | [Sources](#sources), [Clipboard capture](#clipboard-capture) |
| File (0.5.0) | `zks capture file --store SERVICE/ACCOUNT PATH`: a downloaded key file (Google `.json`, Apple `.p8`) from `~/Downloads` or the project into the Keychain, then the file is deleted; always asks; never deleted on failure | [File capture](#file-capture) |
| Where (0.7.0) | `zks where NAME`: every project file that names a key (workflows, Compose, Dockerfile, Railway, Vercel, Netlify, dotenv files, other CI, scripts, code), split into places zks manages, places it does not know and consumers; paths and line numbers only, never a line | [Where](#where) |

Planned next (not built yet): capture recipes per provider (`zks capture recipe vercel-token`), a Playwright/Chrome capture backend, capture inside modals and shadow DOM, a `zks mcp` stdio server so any agent can call `plan`/`apply`/`capture` without a shell, and `zks init --detect` that drafts the policy from `.env.example`, `vercel.json` and `railway.toml`. Tracked in [`odd/tasks/zks-v2.md`](./odd/tasks/zks-v2.md).

## Commands

```text
zks init [--policy FILE] [--project NAME]   Create a zks.policy.json template
zks validate [--policy FILE]                Check the policy
zks plan [--policy FILE] [--only A,B] [--target t1,t2]
                                            List the writes apply would make (no network)
zks apply [--policy FILE] [--only A,B] [--target t1,t2] [--agent LABEL]
                                            Ask for approval, then write values to providers
zks rotate NAME [--target t1,t2] [--policy FILE]
                                            Write a NEW value of a generated variable to its targets
                                            and its derived variables; always asks (no revocation)
zks run [--policy FILE] [--only A,B] [--agent LABEL] -- <command> [args...]
                                            Run one command with the variables as its env vars only;
                                            always asks (shows command, args, dir, names); exits
                                            with the command's code and prints nothing of its own
zks inventory [--project P] [--policy FILE] [--older-than <N>d]
                                            Which variable is in which destination and how old
                                            (audit log metadata, no network); --older-than keeps
                                            writes older than N days (1-3650) and never-written ones
zks where NAME [--policy FILE]              Every project file that names NAME: managed, unmanaged
                                            and consumers (paths and line numbers, never a line)
zks auth status                             Show which provider tokens are in the Keychain
zks auth set <vercel|railway|supabase|netlify|sheets-hmac>
                                            Store a token through a hidden dialog
zks auth delete <vercel|railway|supabase|netlify|sheets-hmac>
zks capture read --space ID --page LABEL --selector CSS --store SERVICE/ACCOUNT [--click SELECTOR] [--origin ORIGIN]
                                            In an ego-browser page: click, read the token element
                                            into the Keychain, blank it (value never shown)
zks capture fill --space ID --page LABEL --selector CSS (--store SERVICE/ACCOUNT --generate BYTES
                 | --from SERVICE/ACCOUNT) --origin ORIGIN
                                            Fill a new random (16-128 bytes) or a stored password
                                            into one password input of an ego-browser page; --from
                                            into another origin than the item came from asks first
zks capture read --isolated --url URL --selector CSS --store SERVICE/ACCOUNT [--click SELECTOR] --origin ORIGIN
zks capture fill --isolated --url URL --selector CSS (--store SERVICE/ACCOUNT --generate BYTES
                 | --from SERVICE/ACCOUNT) --origin ORIGIN
                                            Same, in a space zks opens itself in the capture-profile
                                            (not the agent's session) at URL, closed afterwards
zks capture login --origin ORIGIN --url URL --user USERNAME --user-selector CSS --password-selector CSS
                  --submit-selector SELECTOR --from SERVICE/ACCOUNT [--success-selector CSS] [--recipe NAME]
                  [--agent LABEL] (--isolated | --space ID --page LABEL)
                                            Log the browser into a site with a stored password
                                            (never shown); always asks first
zks capture clipboard --store SERVICE/ACCOUNT
                                            Store the macOS clipboard in a Keychain item, then clear it
                                            if unchanged; always asks first
zks capture file --store SERVICE/ACCOUNT PATH
                                            Store a downloaded key file (~/Downloads or the project)
                                            in a Keychain item, then delete it; always asks first
zks capture recipes                         List login recipes (hostgator, cpanel)
zks audit list [--limit N] [--project P]    Show audit records (metadata only)
zks audit verify                            Check the audit hash chain
zks audit sync                              Push pending audit records to Google Sheets
zks trust list                              Show trusted destinations (writes there need no dialog)
zks trust remove <key>                      Stop trusting a destination (no dialog needed)
zks config show
zks config set sheets-webhook <url>         Apps Script /exec URL for the audit mirror
zks config unset sheets-webhook
zks config set capture-profile <profileId>  Separate ego-browser profile for capture --isolated
zks config unset capture-profile
zks doctor [--fix]                          Check tools, tokens, audit and install integrity;
                                            --fix creates/chmods ~/.config/zks, ~/.local/state/zks
                                            (700) and their files (600) and lists what it cannot fix
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
| `netlify` | account (or site) env var for one deploy context, `is_secret` when sensitive | `zks/netlify` (`zks capture` or `zks auth set netlify`) | `accountId`, `context` (`all`, `production`, `deploy-preview`, `branch-deploy`, `dev`) | `siteId` |
| `docker-swarm` | Swarm secret `NAME` (`docker secret create NAME -`, value on stdin) | the docker CLI pinned in `tools.json`, talking only to `host` | — | `host` (`unix:///path` to a real socket, passed as `docker --host`; no `ssh://`; docker contexts and `~/.docker/config.json` are ignored), `replace` |
| `compose` | file `<dir>/<NAME>` (mode `600`, `dir` `700`) for Compose `secrets: <name>: file:` | — | `dir` (relative to the current directory, or absolute) | — |
| `dotenv` | `NAME="value"` in a local `.env*` file (mode `600`), other lines kept | — | `path` (relative to the current directory, or absolute; file name `.env*`) | — |

Rules: Vercel sensitive variables cannot target `development`; Supabase rejects names starting with `SUPABASE_`. Netlify: a missing variable is created; an existing one gets the value for `context`; a sensitive value is refused (`netlify_not_secret`, nothing written) when the existing variable is not secret. Docker Swarm secrets are immutable: an existing one fails with `secret_exists` unless the target sets `replace: true`, which runs `docker secret rm` then `create` (a secret still used by a service cannot be removed: `docker_failed`); without docker in `tools.json` the write fails with `docker_unavailable`. A `unix://` host must point to a real socket, not a symlink: zks lstats the path before running docker and refuses a symlink, a missing path or a non-socket with `docker_host_invalid` (nothing runs); on Docker Desktop `/var/run/docker.sock` is a symlink, so use the real socket path, e.g. the one `docker context inspect` shows under your home (`unix:///Users/you/.docker/run/docker.sock`). `ssh://` hosts are not accepted because docker resolves them through your ssh client config, which a same-user agent can edit; `tcp://` hosts are not accepted because the sink has no TLS certificates and the value would travel as plain HTTP. Limit: a socket under your home is still replaceable by a same-user agent (same-user limit as the `node` and `npm` files noted in [System install](#system-install)). Docker secret names must start and end with a letter or digit. `compose` refuses a `dir` or file that is a symlink (`symlink_refused`) and an existing `dir` others can access (`insecure_dir`, run `chmod 700`); it never changes an existing directory's mode. `dotenv` replaces the first definition of `NAME` in place (keeping `export`, and a quoted value spanning several lines as a whole), drops later definitions, appends it when missing, and rewrites the file atomically (mode-600 file in the same directory, renamed into place); it escapes `\`, `"`, newline, carriage return and `$` (`\\`, `\"`, `\n`, `\r`, `\$`, as shells, python-dotenv, Compose and dotenv-expand read them; the zks `dotenv` source decodes the same five escapes inside double quotes), keeps every other line byte for byte with its own line ending, refuses a symlinked file (`symlink_refused`), refuses a file that is not UTF-8 text (`file_not_utf8`, nothing written) and does not create missing directories (`file_write_failed`). It is a different thing from the `dotenv` source, which keeps its relative-only rule. Variable names `__proto__`, `constructor` and `prototype` (any case) are reserved.

## Sources

| `source.kind` | Where the value comes from | Use when |
|---|---|---|
| `op` | `op read <ref>` (1Password CLI) | the value is in 1Password; the `op://` reference is not secret |
| `keychain` | macOS Keychain item `service`/`account` | the value is already in the Keychain |
| `prompt` | hidden macOS dialog | the human types or pastes it |
| `clipboard` | macOS clipboard (`/usr/bin/pbpaste`), one trailing newline dropped, then cleared with `/usr/bin/pbcopy` if unchanged | the human already copied the value; one variable per policy; always asks |
| `generate` | local CSPRNG; `format` (below), default `random` with `bytes` 16–512, `base64url` or `hex` | a new key, password or keypair; **rotates on every apply** |
| `dotenv` | a dotenv file read by zks (`path`, optional `key`) | migrating an existing `.env` file |
| `public-key` | SPKI PEM public key of another variable's generated private key (`of`) | publishing the verifying half of a keypair |
| `template` | built in memory from other variables (`template`) | `DATABASE_URL` from user, password and host |
| *(none)* `value` | literal in the policy | only `sensitive: false` env vars |

`generate` formats:

| `format` | Value | Options |
|---|---|---|
| `random` (default) | `bytes` random bytes in `encoding` | `bytes` 16–512 (32), `encoding` `base64url`\|`hex` |
| `uuid` | UUID v4 | — |
| `jwt-secret` | 64 random bytes, base64url (an HS256/HS512 key) | — |
| `password` | at least one character of each enabled class, characters chosen uniformly (rejection sampling) | `length` 12–128 (32); `lower`, `upper`, `digits`, `symbols` booleans (all `true`), at least one enabled; symbols are `!#$%&()*+,-./:;<=>?@[]^_{\|}~` |
| `rsa-private-key` | PKCS#8 PEM | `bits` 2048\|3072\|4096 (3072) |
| `ed25519-private-key` | PKCS#8 PEM | — |

An option another format does not use is an `invalid_policy` issue (`variables.X.source.length: is not valid for format "uuid"`).

```json
"SESSION_SECRET": { "sensitive": true, "source": { "kind": "generate", "format": "jwt-secret" }, "targets": ["vercel-prod"] },
"DB_PASSWORD":    { "sensitive": true, "source": { "kind": "generate", "format": "password", "length": 40, "symbols": false }, "targets": ["railway-prod"] },
"SIGNING_KEY":     { "sensitive": true,  "source": { "kind": "generate", "format": "ed25519-private-key" }, "targets": ["ssm-prod"] },
"SIGNING_KEY_PUB": { "sensitive": false, "source": { "kind": "public-key", "of": "SIGNING_KEY" }, "targets": ["vercel-prod"] },
"DATABASE_URL": {
  "sensitive": true,
  "source": { "kind": "template", "template": "postgres://${DB_USER}:${DB_PASSWORD:url}@${DB_HOST}/app" },
  "targets": ["vercel-prod"]
}
```

`clipboard` is read at `apply` (or `run`) time, after the approval dialog and never at `plan`; an empty clipboard is `source_missing` (`the clipboard is empty`) and nothing is written. An `apply` or `rotate` whose writes use a clipboard value, directly or through a `template` or `public-key`, always opens the approval dialog, even when every destination is trusted ("Always allow" never skips it); the dialog adds `Reads the clipboard: <names>`. The clipboard is cleared only if it still holds the value zks read: zks reads it again, compares in constant time and calls pbcopy only when it is unchanged, so something you copied in between is left alone. `apply` clears it only once every write succeeded and reports `clipboardCleared` (`false` after a failed write, so a retry still finds the value, or when the clipboard changed: clear it yourself if you give up); `run` clears it as soon as it is read. It works with every destination; for GitHub Actions the value is sealed with the repository public key like any other source:

```json
"targets":   { "gh": { "provider": "github", "repo": "acme/web" } },
"variables": { "API_KEY": { "sensitive": true, "source": { "kind": "clipboard" }, "targets": ["gh"] } }
```

Derived values (`public-key`, `template`) are computed in memory during the same `apply` as the values they use: every variable is resolved once, dependencies first, so `DB_PASSWORD` above is generated once and the same bytes reach both its own target and `DATABASE_URL`. `plan` and the dialog show `generate password(40)`, `public-key of SIGNING_KEY` and `template(DB_USER, DB_PASSWORD, DB_HOST)`, never values.

Source rules:

- Every `source` needs `"sensitive": true`, except `public-key`, which may be `"sensitive": false`. Only a literal `value` or a `public-key` can be non-sensitive.
- `public-key`: `of` names a variable whose source is `generate` with format `rsa-private-key` or `ed25519-private-key`.
- `template`: 1–2000 characters; `${NAME}` inserts NAME's value as is, `${NAME:url}` percent-encodes it (`encodeURIComponent`), `$${` is a literal `${`. It must reference at least one variable; an unknown variable, a reference to itself or a cycle (`A -> B -> A`) is an `invalid_policy` issue.
- A selection (`--only`, `--target`) that writes a derived variable must also write every generated variable it is derived from, otherwise zks would write a value derived from a key or password stored nowhere (`selection: DATABASE_URL uses DB_PASSWORD, a generated value this selection does not write; select it too`, exit 2). Non-generated dependencies (Keychain, 1Password, literals) are read even when not selected.
- `keychain`: `service` and `account` match `^[A-Za-z0-9_.-]{1,128}$`; the service `zks` (in any case) is reserved for zks's own tokens.
- `dotenv`: `path` is a relative `.env*` file inside the project (for example `.env.production` or `apps/web/.env.local`): ASCII, no `..`, no absolute path, at most 200 characters. `plan` and the dialog show it resolved to an absolute path; zks reads the resolved real path it checked.
- `op`: `ref` is `op://` followed by printable ASCII without spaces, at most 200 characters.

Each command refuses options it does not use (`option --X is not valid for <command>`, exit 2).

## Trusted destinations

The first write to a destination opens the dialog with three buttons: **Deny** (default), **Approve once** and **Always allow**. "Always allow" trusts each `[NEW destination]` of that apply, from any project, from then on; an apply whose destinations are all trusted opens no dialog and is audited with `approval: "trusted"`, unless it reads the clipboard (a clipboard value always asks).

| Destination key | Trusts |
|---|---|
| `github:<owner>` | every repository of that GitHub owner (lower case) |
| `vercel:team:<teamId>` or `vercel:personal` | every project of that Vercel team, or of the personal account (no `teamId`) |
| `aws:<profile or default>:<roleArn or no-role>:<region>` | SSM and Secrets Manager writes with that profile, role and region |
| `railway:<projectId>` | that Railway project |
| `supabase:<projectRef>` | that Supabase project |
| `netlify:<accountId>` | every site of that Netlify account |
| `docker-swarm:<host>` | the swarm daemon at that unix socket |
| `compose:<absolute dir>` | that Compose secrets directory |
| `dotenv:<absolute path>` | that one `.env` file |

Keys trusted before this format (`vercel:<teamId>`) no longer match any write; `zks trust list` describes them as an old Vercel key format and `zks trust remove <key>` drops them. The keys live in `~/.config/zks/trust.json` (mode `600`), signed with HMAC-SHA256 by a key in the Keychain item `zks`/`trust-hmac`. A file that is unparsable or whose signature does not match trusts nothing: every write asks again and `apply` and `doctor` report `trust: "invalid"`. `zks trust list` shows the keys; `zks trust remove <key>` drops one without a dialog.

## Rotate

`zks rotate NAME [--target t1,t2]` writes a NEW value of a variable with a `generate` source to every one of its targets (or the `--target` subset, which must be targets of NAME) and, in the same apply, rewrites the variables derived from it (`template` and `public-key` sources referencing it) with the new value. The approval dialog always opens, even when every destination is trusted (`approval: "dialog"`); it starts with `Rotate NAME: a NEW value replaces the current one...` and lists every write. Records are audited with `action: "rotate"`; a denial writes nothing and is audited `denied` (exit 3). The old value is not revoked at any provider.

- A variable without a `generate` source (op, keychain, prompt, dotenv, template, public-key or a literal) is refused with `not_rotatable` (exit 2): nothing is resolved or written, and each of its targets is audited `failed` with that code.
- A derived variable that also uses another generated value is refused the same way (`AB also uses B, another generated value; rotating A alone would replace it too`).
- With `--target`, every derived variable must have all its targets inside the selection; otherwise the rotation is refused with `dependents_outside_selection` (exit 2): nothing is resolved or written, every write it would have made is audited `failed` with that code, and `error.dependents` lists `{dependent, targets}` for the targets outside the selection. Rerun without `--target`, or include those targets (they must be targets of NAME too).
- The output is the `apply` output plus `rotated` (NAME) and `dependents` (the derived variables written).

## Run

`zks run [--policy FILE] [--only A,B] [--agent LABEL] -- <command> [args...]` runs one command that needs secrets without the agent reading `.env` files or pulling values:

```sh
zks run --only DATABASE_URL,STRIPE_SECRET_KEY -- pnpm test
```

- zks resolves the selected variables (every variable of the policy, or the `--only` names) with the same sources as `apply`, in memory, and starts the command with them as environment variables of that child process only. No value is written to disk, printed, passed as an argument or put in zks's own environment; zks zeroes its buffers once the child has started (the child's environment copy is the child's).
- The approval dialog opens on **every** run, with **Deny** and **Approve** only: the command is chosen by the agent, so there is no trusted destination and no **Always allow** (same rule as `zks rotate`). It shows the absolute path of the executable, its arguments in full (more than 300 characters is refused with `arguments_too_long`, exit 2, before the dialog; nothing is cut), the working directory and each variable name with its source. Values are resolved only after approval: a denial, a timeout or no GUI reads no secret, runs nothing, exits 3 and is audited `denied`.
- Generated variables are skipped unless named: without `--only` they are not injected, and a `generate` variable, or a `template`/`public-key` derived from one, named in `--only` is a usage error (exit 2) before the dialog: `run cannot inject generated values; they exist only at their destinations (NAME, ...)`. zks would otherwise create a new value that matches none of its destinations.
- The child gets `HOME`, `USER`, `LOGNAME`, `LANG`, `PATH=<cwd>/node_modules/.bin:<the fixed system PATH>` and the injected variables, nothing else from your shell. A bare command name is looked up on that `PATH`, a relative path against the current directory; anything that is not an executable file is `command_not_found` (exit 1) before any dialog. stdin, stdout and stderr are the command's own.
- On success zks prints nothing of its own on stdout and exits with the command's own exit code (`128 + N` when signal N killed it), so the exit code alone does not tell a denial apart: the command itself may exit 3. A denial is recognised by the `not_approved` JSON on stdout (exit 3). Other errors print the usual JSON error: `command_not_found`, a source error such as `source_missing`, or `run_failed` when the command cannot be started (exit 1); usage errors such as a missing `--`, `--target`, an unknown or generated `--only` name, or `arguments_too_long` (exit 2).
- The audit anchor and mirror are updated after the command exits; if one fails, zks writes one line `zks: audit anchor/mirror: <message>` to stderr and still exits with the command's code.
- Every run appends one record per injected variable: `action: "run"`, `provider: "run"`, `target` the executable's absolute path, result `applied`, `denied` or `failed`. Never a value and never the arguments. `zks inventory` skips these records: it is about stored destinations.
- `SIGINT`, `SIGTERM` and `SIGHUP` sent to zks are forwarded to the command; zks itself exits only after the command does. Ctrl-C in a terminal also reaches the command through its process group.

**Honest limit:** the child process holds the values. An agent that runs `zks run -- printenv` (or a script that prints or uploads its environment) sees them; that is why the dialog shows the full command every time and never offers to trust it. Read the command before approving, prefer wrapping single commands (`pnpm test`, `pnpm prisma migrate deploy`), and never wrap a whole agent session or an interactive shell.

## Inventory

`zks inventory [--project P] [--policy FILE] [--older-than <N>d]` reads only the local audit log (no network, no values) and the policy. For each variable × destination it prints `{variable, provider, target, environment, lastWrittenAt, ageDays, writes, status, renew}`: the latest applied `set` or `rotate` record, its age in whole days and how many applied writes there were. `status` is `written`, `never_written` (in the policy, never written: `lastWrittenAt` and `ageDays` are `null`, `writes` 0) or `not_in_policy` (written before, no longer in the policy). Denied and failed writes, captures and `zks run` records do not count.

`--older-than <N>d` (N a whole number of days from 1 to 3650, e.g. `--older-than 90d`) lists only what is due for rotation: entries whose last applied write is strictly more than N days old, plus `never_written` entries (unknown age). The output then adds `olderThanDays: N`; names, destinations and dates only, never a value. Any other form is a usage error (exit 2). Without the option every entry is listed and there is no `olderThanDays`.

Every entry of a policy variable (with or without `--older-than`) ends with `renew`, how to replace its value (metadata only, never a value):

- `generate`: `{"how":"rotate","command":"zks rotate NAME"}`. A `template` or `public-key` derived from generated variables names the first in policy order and lists the others in `also`; one derived from no generated variable lists the sources it reads in `from` (`{variable, source, step}`), or is `how: "edit"` when they are all literals.
- `keychain`, `op`, `dotenv`, `prompt`, `clipboard`: `{"how":"source","source":KIND,"step":...,"then":"zks apply --only NAME"}`.
- literal values: `{"how":"edit","step":"change the value in the policy","then":"zks apply --only NAME"}`.
- `not_in_policy` entries, and every entry without a policy to compare with, have no `renew`.

zks never revokes the old value at the provider: every `rotate` and `source` hint adds `"revoke":"delete the old value at the provider yourself"`.

```json
{
  "variable": "STRIPE_SECRET_KEY", "provider": "vercel", "target": "web", "environment": "production",
  "lastWrittenAt": "2026-08-01T08:00:00.000Z", "ageDays": 104, "writes": 1, "status": "written",
  "renew": {
    "how": "source",
    "source": "keychain",
    "step": "replace the Keychain item stripe/secret with a new value from the provider (zks capture read or zks capture file)",
    "then": "zks apply --only STRIPE_SECRET_KEY",
    "revoke": "delete the old value at the provider yourself"
  }
}
```

The project is `--project` or the policy's `project`. With `--project` and no policy file in the directory, or a policy of another project, the audit entries are listed without a comparison (`policy: null`, every entry `written`).

## Where

`zks where NAME [--policy FILE]` answers "which places use this key" before a rotation or a renew, so none is left with the old value. It searches the project for **the name only**, never a value, and prints paths, line numbers and kinds; never a line of text (a dotenv line holds the value). Read-only: no dialog, no audit record, no network.

- `NAME` must match the policy variable-name rule (`^[A-Za-z_][A-Za-z0-9_]{0,127}$`, otherwise exit 2 without echoing it); it need not be in the policy.
- Files: `git ls-files --cached --others --exclude-standard` when the current directory is in a Git work tree (tracked and untracked, `.gitignore` respected), otherwise a walk of the current directory. Always skipped: `node_modules`, `.git`, `dist` and `build` directories, symlinks, files over 1 MiB, binary files (a NUL byte) and the policy file itself. At most 20,000 files; beyond that `truncated` is `true`.
- Matches are whole words (`[A-Za-z0-9_]` boundaries): `STRIPE_KEY` does not match `STRIPE_KEY_ID` or `MY_STRIPE_KEY`. A line counts once.
- `kind` of each file: `github-workflow` (`.github/workflows/*.yml|yaml`), `compose` (`*compose*.yml|yaml`), `dockerfile` (`Dockerfile`, `Dockerfile.*`, `*.dockerfile`), `railway` (`railway.toml|json`), `vercel` (`vercel.json`), `netlify` (`netlify.toml`), `dotenv` (the file names a `dotenv` target accepts), `ci-other` (`.gitlab-ci.yml`, `bitbucket-pipelines.yml`, `azure-pipelines.yml`, `.travis.yml`, `.drone.yml`, `Jenkinsfile`, `.circleci/`, `.buildkite/`), `script` (`*.sh`, `Makefile`, `package.json`), `code` (anything else).
- `managed`: a policy target of NAME writes that place: `github-workflow` ↔ a `github` target, `compose` and `dockerfile` ↔ `compose` or `docker-swarm`, `railway`, `vercel` and `netlify` ↔ the same provider, `dotenv` ↔ a `dotenv` target with that exact path. Dotenv templates (`*.example`, `*.sample`, `*.template`) only document the name: managed as soon as NAME is in the policy.
- `unmanaged`: every other place (a `ci-other` file always is): **a place that uses this key and zks does not know**. Update it by hand or add a target, then rotate.
- `consumers`: `code` and `script` references, which read the key at run time rather than store it.

```json
{
  "ok": true, "name": "DB_PASSWORD", "inPolicy": true,
  "targets": [{ "target": "web", "provider": "vercel" }],
  "managed": [{ "path": "vercel.json", "line": 4, "kind": "vercel" }],
  "unmanaged": [{ "path": "backup/docker-compose.yml", "line": 12, "kind": "compose" }],
  "consumers": [{ "path": "src/db.ts", "line": 3, "kind": "code" }],
  "scanned": 214, "truncated": false
}
```

Exit 0 on every completed scan: unmanaged entries are a finding, not an error. Only files in the project are searched; a provider, server or backup job configured outside the repository is not, so tell the human to check those too.

## Plan effects

Every `plan` operation carries `effect`, and `effects` groups the operations by effect (`{effect, operations, targets}`). zks never redeploys anything.

| Provider | `effect` |
|---|---|
| vercel | `applies on the next deployment; redeploy to use it now` |
| railway | `Railway redeploys the service` (`applies on the next Railway deploy (skipDeploys)` with `skipDeploys: true`) |
| github | `used by the next workflow run` |
| aws-ssm, aws-sm | `consumers read it on their next fetch` |
| supabase | `Edge Functions use it on their next invocation` |
| netlify | `applies on the next Netlify build or deploy` |
| docker-swarm | `update services to use the new secret` |
| compose | `restart the Compose stack to use it` |
| dotenv | `restart processes that read the file` |

## Doctor --fix

`zks doctor --fix` repairs only file modes, then prints the usual doctor report plus `fixed` (the equivalent shell command of each change) and `notFixable`:

- creates `~/.config/zks` and `~/.local/state/zks` with mode `700` (and chmods them to `700`);
- chmods `config.json`, `trust.json`, `audit.db`, `audit.db-wal` and `audit.db-shm` to `600`.

It never follows a symlink (reported in `notFixable` as `symlink`) and never touches the install, `integrity.json`, trust content, the audit chain or the Keychain. Those appear in `notFixable` as `{check, status, command}`: a modified install or a changed tool pin → `./install.sh` (`sudo ./install.sh --system` for a system install), `trust: "invalid"` → re-trust in the next apply, a broken audit chain → `zks audit verify`, a missing token → `zks auth set <provider>`. `zks doctor` without `--fix` changes nothing.

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
- Output: `{ok, command: "capture", mode: "read"|"fill", store, origin, length, auditId, mirror}`. Errors (exit 1): `origin_mismatch` (nothing stored or filled), `not_found`, `not_password_field`, `keychain_failed`, `browser_failed`, `restore_failed`. Usage errors exit 2 and never echo a value.
- One-time codes that are not secrets worth keeping (an e-mail verification code) are not captured: the agent types them with normal ego actions.
- Service `zks` (any case) is reserved: only `zks/vercel` (`--origin https://vercel.com`), `zks/railway` (`https://railway.com`), `zks/supabase` (`https://supabase.com`), `zks/netlify` (`https://app.netlify.com`) and `zks/sheets-hmac` (`https://script.google.com`) can be captured, only with `read` and only from that origin. `fill` never uses service `zks`.
- Replacing an existing Keychain item (`read`, `fill --generate`) opens an approval dialog first; denial exits 3 and runs nothing. After approval zks reads the old value into memory (never output, audited or put in the script); if the capture then does not end ok (any error code, isolated refusals included, or a thrown error), zks writes the old value back after the script returns and the error output adds `restored: true`. If that write-back fails the error is `restore_failed` (exit 1, audited). The in-memory copy is zeroed in every case; on success the new value stays. The first capture into a new item, `zks/*` included, needs no approval (see [What is guaranteed, and what is not](#what-is-guaranteed-and-what-is-not)).

### Clipboard capture

```sh
zks capture clipboard --store stripe/api-key
```

- Always asks before the clipboard is read: a new item opens `zks: store the clipboard` (`Store the clipboard in the Keychain item SERVICE/ACCOUNT?`), an existing item the replace dialog (one dialog either way). Denial exits 3 with `not_approved`, reads nothing and is audited `denied`.
- Stores the macOS clipboard (`/usr/bin/pbpaste`, one trailing `\n` or `\r\n` dropped) in the Keychain item, then clears the clipboard with `/usr/bin/pbcopy` only if it still holds the value read (re-read and compared in constant time). The clipboard is cleared only after the item is stored, so a failed write leaves it there to retry.
- Output: `{ok, command: "capture", mode: "clipboard", store, length, clipboardCleared, auditId, mirror}`, never the value. `clipboardCleared: false` means the clipboard changed since the read (left alone) or pbcopy failed: clear it yourself if needed.
- A failed write to an existing item puts the old value back (`restored: true`).
- Errors (exit 1): `clipboard_empty`, `clipboard_unavailable`, `keychain_failed`, `restore_failed`. Service `zks` is refused (exit 2): provider tokens use `zks auth set` or `capture read` from their pinned origin.
- Audited as `sourceKind: "capture-clipboard"` with no origin, so a later `fill --from` of that item always asks.

### File capture

```sh
zks capture file --store gcp/deploy-sa ~/Downloads/my-project-1234-abcd.json
```

For keys a site hands over as a download (a Google service-account `.json`, an Apple `.p8`): zks stores the file in the Keychain without the agent opening it, and deletes it.

- PATH (relative to the current directory or absolute) must be inside `~/Downloads` or the current directory, compared after resolving symlinks of its parent directory (so `..` or a symlinked directory cannot leave them). The current directory counts only when it is strictly inside your home directory (never `~` itself or `/`), and no directory between your home (or the root) and the file may start with `.` (`.ssh`, `.aws`, `.git`...), even when you run it from inside one, so the command cannot reach your dotfiles. A file with more than one hard link is refused too. The file itself must be a regular file, not a symlink, 1 to 65536 bytes. Anything else is `file_invalid` (exit 1) before any dialog, with nothing read or deleted; a missing file is `file_not_found`. Messages may name the path, never the contents.
- Always asks before the file is read: a new item opens `zks: store a file` (`Store the file <path> (<size> bytes) in the Keychain item SERVICE/ACCOUNT?`, `zks deletes the file afterwards`), an existing item the replace dialog naming the same path and size (one dialog either way). Denial exits 3 with `not_approved`, reads nothing, keeps the file and is audited `denied`.
- The file is opened with `O_NOFOLLOW` and must still be the file the dialog named (same inode and size). Its bytes are stored exactly as read, trailing newline included; a file that is not UTF-8 text is `file_invalid` and kept (the Keychain write takes text). The read buffer is zeroed afterwards.
- Only after the item is stored is the file deleted. A failed write keeps the file and puts an existing item's old value back (`restored: true`), or reports `restore_failed`.
- Output: `{ok, command: "capture", mode: "file", store, length, fileDeleted, auditId, mirror}`, never the contents. `fileDeleted: false` (still exit 0) means the delete failed or the path changed after the read: delete the file yourself.
- Errors (exit 1): `file_invalid`, `file_not_found`, `keychain_failed`, `restore_failed`. Service `zks` is refused (exit 2), and so is a path whose dialog line would exceed 300 characters (`dialog_too_long`, exit 2, before the dialog).
- Audited as `sourceKind: "capture-file"`, `provider: "keychain"`, with no path and no origin, so a later `fill --from` of that item always asks.

### Isolated capture (`--isolated`)

By default the secret step runs in the agent's own TaskSpace, so the agent's ego session could look at the page while the token is on it. `--isolated` closes that window: zks opens its own space in a separate ego-browser profile that holds only your provider logins, does the secret step there, and closes the space.

One-time setup (the human, once):

1. In Ego Lite, create a separate profile (for example `zks-capture`), not the default one the agent uses.
2. Open that profile once and log in to each provider you capture from (Vercel, Railway, Supabase, Google Apps Script, API sites). The sessions stay in that profile.
3. Tell zks its id, the `id` that ego-browser's `profiles()` lists for it (`echo 'console.log(JSON.stringify(await profiles()))' | ego-browser nodejs`): `zks config set capture-profile zks-capture`. The change opens an approval dialog; so does `zks config unset capture-profile`. `zks config show` shows it.

```sh
zks capture read --isolated --url https://vercel.com/account/settings/tokens --click "text=Create" \
  --selector "[role=dialog] input[readonly]" --store zks/vercel --origin https://vercel.com
```

- `--isolated` replaces `--space`/`--page` (combining them is a usage error) and needs `--url` (http or https, at most 1000 printable ASCII characters) and `--origin`; the URL must be on that origin.
- Inside the ego script, zks checks `profiles()`: the configured id must be listed (else `isolated_profile_missing`) and must not be the default profile (`isDefault` must be `false`, else `isolated_profile_not_isolated`). It then creates the space `zks-capture-<16 random hex>` with `taskSpace(name, { profileId })`, opens a page, goes to `--url` and requires the page to land on `--origin`; a redirect to a login page or anywhere else is `login_required` (log in once in that profile, then retry). Then the usual `read` or `fill` steps run, and the space is always closed with `task.finish({ keep: [] })` in a `finally`, on success and on every failure.
- No profile configured (or an invalid id in `config.json`) is `isolated_profile_unset`, before any dialog, Keychain write or browser step. All four errors exit 1 and are audited `failed`; nothing is read or filled. A refused isolated `fill --generate` removes the item zks had just created for it; an existing item replaced after approval gets its old value back (`restored: true`).
- Output adds `isolated: true`. A replacement dialog says `New value: read from <origin> (isolated ego-browser profile <id>)`.
- Honest limit: the agent never gets the space id and never drives that space, but it runs as the same macOS user. While the capture runs, a same-user agent can still list and claim the space by id through ego-browser, or edit `config.json` to point at another non-default profile. `--isolated` narrows the window; a hard boundary still needs a dedicated macOS user for the agent.

### Login (`capture login`)

Logs the agent's browser into a website (a hosting panel, a dashboard) with a password stored in the Keychain, which the agent never sees. The username (an e-mail or login name) is not a secret and is passed as a plain flag:

```sh
zks capture login --recipe hostgator --user me@example.com --from hostgator/password --isolated
zks capture login --origin https://host.example.com:2083 --recipe cpanel --user me --from cpanel/password \
  --space 7 --page p1
zks capture login --origin https://app.example.com --url https://app.example.com/login --user me@example.com \
  --user-selector "#email" --password-selector "#password" --submit-selector "button[type=submit]" \
  --success-selector "[data-test=dashboard]" --from example/password --space 7 --page p1
```

- The approval dialog opens on **every** login (no Always allow, no trust): it names the origin, the page, the username, the Keychain item and what happens ("typed into the password field, then the form is submitted"), where the item was captured from, and the browser (TaskSpace/page or the isolated profile). Denial exits 3, is audited `denied` and reads nothing. A dialog line over 300 characters is `dialog_too_long` (exit 2): shorten `--url`, `--user` or the `--from` item name.
- The script (same guarantees as `fill --from`): goes to `--url` (on `--origin`; a pinned `zks` item is never used, any other origin is allowed because you approve it), checks the origin, sets the user field (exactly one non-password input) to the username, then fills the password field through fill's path (one `<input type="password">`, Keychain read inside ego, typed through the keyboard, never in the script, argv, env, output or audit), clicks `--submit-selector` and waits up to 15 s for the page to settle. A failure before the submit blanks the password field and leaves the page on `about:blank`. A pending result with the password field still on the page (the click did not submit, or the form came back) blanks that field before zks reports; the page itself stays.
- Result, exit 0: `{ok: true, command: "capture", mode: "login", origin, from, loggedIn, finalOrigin, pending?, auditId, mirror}`. `loggedIn` is true when `--success-selector` is given and found (it wins over captcha and code-input detection), or, without it, when the password field is gone and no one-time-code input or captcha shows. A captcha frame or code input counts only if it appeared after the submit or the page changed (another URL, or the password field is gone); one already on the login page (an invisible reCAPTCHA, a phone field) does not. Otherwise `loggedIn: false` with `pending`: `captcha` (an iframe whose host contains `captcha`, or a `/recaptcha/` frame), `2fa` (an `input` of type `tel` or `number`, or `autocomplete="one-time-code"`) or `unknown` (the password field is still there on the same page after 15 s: wrong password, or the page did not react). Pending is not an error: the human finishes the 2FA or captcha in the browser. With `--isolated`, a pending login keeps its page open in the capture profile (`task.finish({ keep: [page] })`) and the output adds `space` (`zks-capture-<hex>`) and `page`, so the human finishes the challenge there; a logged-in or failed isolated login closes the space as before. Give `--success-selector` when the logged-in page has number or phone inputs, or they read as `2fa`.
- Leaving `--origin` during the flow (a login wall on another origin, an SSO hop) is `login_redirected` (exit 1) with `finalOrigin` (the origin only, never the path). Other errors as `fill`: `not_found` (item, user field or submit), `not_password_field`, `keychain_failed`, `browser_failed`, `isolated_profile_*`.
- Recipes: `--recipe NAME` fills the flags you did not give; explicit flags win. `zks capture recipes` lists them as JSON. `hostgator` (`https://portal.hostgator.com/login`, `input[name=email]`, `input[name=password]`, `button[type=submit]`); `cpanel` (your own host, so it needs `--origin`; `--url` defaults to `<origin>/`; `#user`, `#pass`, `#login_submit`). Both are `verified: false`: the selectors come from public documentation and are confirmed on the first real run; if one does not match, pass that flag explicitly.
- Audit: `provider: "capture"`, `action: "capture"`, `sourceKind: "capture-login"`, `target: <origin>`, `variableName: "<service>/<account>"`, result `applied` (the form was submitted, logged in or pending), `denied` or `failed`. The username is not recorded.
- Honest limit: the logged-in session then lives in that browser profile, and an agent driving the profile can use it. Prefer `--isolated` (the session stays in the capture profile, not the agent's; the space is closed afterwards, except the page of a pending login, which stays open for the human to finish the 2FA or captcha in that profile) and log out when done. The username appears in the dialog and in the script piped to ego.

- Every capture is audited: `provider: "keychain"`, `action: "capture"`, `target: "<service>/<account>"`, `environment: <origin>`, `sourceKind: capture-read|capture-generate|capture-from`, result `applied`, `failed` or `denied` (a login is recorded as above). Like `apply`, every capture then pushes pending records to the Sheets mirror (best effort) and reports it in `mirror`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ok |
| 1 | a write or check failed |
| 2 | usage or policy error |
| 3 | not approved (denied, timed out or no GUI) |

`zks run` exits with the command's own exit code (`128 + N` when signal N killed it) once the command started; the codes above apply before that.

## Audit

Every apply and rotate appends one record per variable × target (`action: "set"` or `"rotate"`), and every `zks run` one per injected variable (`action: "run"`, see [Run](#run)), to `~/.local/state/zks/audit.db` (SQLite, append-only triggers, SHA-256 hash chain): time, human, agent, project, provider, target, environment, variable name, sensitive flag, source kind, result, provider version, error code, approval mode (`dialog` or `trusted`). There is no field for a value or a hash of a value.

- `zks audit list` — read records.
- `zks audit verify` — check the chain, and check it against the anchor (record count and last hash) that every apply stores in the Keychain item `zks`/`audit-head`; a deleted tail fails with `brokenAt: "truncated"`.
- `zks audit sync` — push to the optional Google Sheets mirror; setup in [docs/apps-script](./docs/apps-script/README.md). `zks config set|unset sheets-webhook` asks for your approval in a dialog.

## System install

```sh
./install.sh --system --dry-run   # print the layout, write nothing
sudo ./install.sh --system        # once, from your own account
```

| Path | Owner, mode |
|---|---|
| `/usr/local/libexec/zks/<version>/` (app, production `node_modules`, `tools.json`, `sbom.cdx.json`, and its own copy of `node`) | `root:wheel`, read-only |
| `/usr/local/libexec/zks/bin/zks` (launcher) | `root:wheel`, `555` |
| `/usr/local/libexec/zks/integrity.json` | `root:wheel`, `444` |
| `/etc/paths.d/zks` (puts the launcher on `PATH` for new shells) | `root:wheel`, `644` |

The build, the skill and the `~/AGENTS.md` block still run and write as you (`$SUDO_USER`), never as root. One step runs as root: the production `npm ci` inside the root-owned app. Both the build `npm ci` (as you, in the repository) and the production one run isolated from your npm config, cache and logs (in user and system installs alike): under `env -i` with a private `HOME`, cache, logs and empty global npmrc and no user npmrc, using the same checked node. It still executes your own `node` and `npm` files and npm's bundled `npmrc`, which your user can modify (same-user limit: install from a trusted state). The launcher is not written to `/usr/local/bin` because Homebrew often makes that directory user-owned; the install refuses to proceed when `/usr`, `/usr/local`, `/usr/local/libexec` or the zks prefix is not root-owned or is group/other-writable. The user-level launcher `~/.local/bin/zks` is removed so it cannot shadow the system one. `zks doctor` reports `install.mode: "system"` and an `ownership` check of the whole prefix (every entry root-owned, not group/other-writable, no symlink); a failed check turns `install.status` into `"ownership"`. Remove it with `sudo ./uninstall.sh --system`.

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

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](./CONTRIBUTING.md) before you start. In short:

- Open an issue first for any change in behaviour. Then fork, branch from `develop` and open the pull request against `develop`. `main` and `develop` are protected: a merge needs a pull request, a review by the maintainer and a green CI `check`.
- Conventional Commits with a DCO sign-off (`git commit -s`). Tests first (RED, then GREEN), one test per rule. Tests, docs and code of one behaviour go in the same commit. Keep a pull request to about 400 changed lines.
- Never let a secret value reach argv, the environment, stdout, stderr, temp files or the audit log, and never write to a new destination without the approval dialog. A change to `src/sinks`, `src/gate`, `src/capture`, `src/platform` or `install.sh` explains its impact on the [threat model](./docs/architecture.md).
- Follow the [Code of Conduct](./CODE_OF_CONDUCT.md). Report vulnerabilities privately as [SECURITY.md](./SECURITY.md) describes, never in a public issue.

Changes are listed in [CHANGELOG.md](./CHANGELOG.md).

## Docs

- [Architecture, trust boundaries and threat model](./docs/architecture.md)
- [Agent flow and source decision table](./docs/agent-flow.md)
- [Google Sheets audit mirror](./docs/apps-script/README.md)
- [Agent skill](./skill/SKILL.md)

## License

Licensed under the [Apache License, Version 2.0](./LICENSE). See [NOTICE](./NOTICE).

Copyright 2026 Mauro Ciappina
