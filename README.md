# zks — zero-knowledge secrets for AI agents

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
- `fill --from` decides "same origin, no dialog" from the local audit log, which a same-user process can rewrite (tamper-evident through `zks audit verify`, not tamper-proof).
- `tools.json` pins each tool by path and sha256: after upgrading `gh`, `op`, `docker` or ego-browser, rerun `./install.sh`, or zks refuses the changed binary and reports the tool unavailable (`zks doctor`: `"changed"`). The hash is checked once per zks process before the first run of each tool; a binary swapped between that check and the run is not caught (same-user limit).
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
zks inventory [--project P] [--policy FILE] Which variable is in which destination and how old
                                            (audit log metadata, no network)
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
| `docker-swarm` | Swarm secret `NAME` (`docker secret create NAME -`, value on stdin) | the docker CLI pinned in `tools.json`, talking only to `host` | — | `host` (`unix:///path` to a real socket or `tcp://host:port`, passed as `docker --host`; no `ssh://`; docker contexts and `~/.docker/config.json` are ignored), `replace` |
| `compose` | file `<dir>/<NAME>` (mode `600`, `dir` `700`) for Compose `secrets: <name>: file:` | — | `dir` (relative to the current directory, or absolute) | — |
| `dotenv` | `NAME="value"` in a local `.env*` file (mode `600`), other lines kept | — | `path` (relative to the current directory, or absolute; file name `.env*`) | — |

Rules: Vercel sensitive variables cannot target `development`; Supabase rejects names starting with `SUPABASE_`. Netlify: a missing variable is created; an existing one gets the value for `context`; a sensitive value is refused (`netlify_not_secret`, nothing written) when the existing variable is not secret. Docker Swarm secrets are immutable: an existing one fails with `secret_exists` unless the target sets `replace: true`, which runs `docker secret rm` then `create` (a secret still used by a service cannot be removed: `docker_failed`); without docker in `tools.json` the write fails with `docker_unavailable`. A `unix://` host must point to a real socket, not a symlink: zks lstats the path before running docker and refuses a symlink, a missing path or a non-socket with `docker_host_invalid` (nothing runs); on Docker Desktop `/var/run/docker.sock` is a symlink, so use the real socket path, e.g. the one `docker context inspect` shows under your home (`unix:///Users/you/.docker/run/docker.sock`). `ssh://` hosts are not accepted because docker resolves them through your ssh client config, which a same-user agent can edit; `tcp://` hosts need a port and have no local check. Limit: a socket under your home is still replaceable by a same-user agent (same-user limit as the `node` and `npm` files noted in [System install](#system-install)). Docker secret names must start and end with a letter or digit. `compose` refuses a `dir` or file that is a symlink (`symlink_refused`) and an existing `dir` others can access (`insecure_dir`, run `chmod 700`); it never changes an existing directory's mode. `dotenv` replaces the first definition of `NAME` in place (keeping `export`, and a quoted value spanning several lines as a whole), drops later definitions, appends it when missing, and rewrites the file atomically (mode-600 file in the same directory, renamed into place); it escapes `\`, `"`, newline, carriage return and `$` (`\\`, `\"`, `\n`, `\r`, `\$`, as shells, python-dotenv, Compose and dotenv-expand read them; the zks `dotenv` source decodes the same five escapes inside double quotes), keeps every other line byte for byte with its own line ending, refuses a symlinked file (`symlink_refused`), refuses a file that is not UTF-8 text (`file_not_utf8`, nothing written) and does not create missing directories (`file_write_failed`). It is a different thing from the `dotenv` source, which keeps its relative-only rule. Variable names `__proto__`, `constructor` and `prototype` (any case) are reserved.

## Sources

| `source.kind` | Where the value comes from | Use when |
|---|---|---|
| `op` | `op read <ref>` (1Password CLI) | the value is in 1Password; the `op://` reference is not secret |
| `keychain` | macOS Keychain item `service`/`account` | the value is already in the Keychain |
| `prompt` | hidden macOS dialog | the human types or pastes it |
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

The first write to a destination opens the dialog with three buttons: **Deny** (default), **Approve once** and **Always allow**. "Always allow" trusts each `[NEW destination]` of that apply, from any project, from then on; an apply whose destinations are all trusted opens no dialog and is audited with `approval: "trusted"`.

| Destination key | Trusts |
|---|---|
| `github:<owner>` | every repository of that GitHub owner (lower case) |
| `vercel:team:<teamId>` or `vercel:personal` | every project of that Vercel team, or of the personal account (no `teamId`) |
| `aws:<profile or default>:<roleArn or no-role>:<region>` | SSM and Secrets Manager writes with that profile, role and region |
| `railway:<projectId>` | that Railway project |
| `supabase:<projectRef>` | that Supabase project |
| `netlify:<accountId>` | every site of that Netlify account |
| `docker-swarm:<host>` | the swarm daemon at that endpoint (`unix:///path` or `tcp://host:port`) |
| `compose:<absolute dir>` | that Compose secrets directory |
| `dotenv:<absolute path>` | that one `.env` file |

Keys trusted before this format (`vercel:<teamId>`) no longer match any write; `zks trust list` describes them as an old Vercel key format and `zks trust remove <key>` drops them. The keys live in `~/.config/zks/trust.json` (mode `600`), signed with HMAC-SHA256 by a key in the Keychain item `zks`/`trust-hmac`. A file that is unparsable or whose signature does not match trusts nothing: every write asks again and `apply` and `doctor` report `trust: "invalid"`. `zks trust list` shows the keys; `zks trust remove <key>` drops one without a dialog.

## Rotate

`zks rotate NAME [--target t1,t2]` writes a NEW value of a variable with a `generate` source to every one of its targets (or the `--target` subset, which must be targets of NAME) and, in the same apply, rewrites the variables derived from it (`template` and `public-key` sources referencing it) with the new value. The approval dialog always opens, even when every destination is trusted (`approval: "dialog"`); it starts with `Rotate NAME: a NEW value replaces the current one...` and lists every write. Records are audited with `action: "rotate"`; a denial writes nothing and is audited `denied` (exit 3). The old value is not revoked at any provider.

- A variable without a `generate` source (op, keychain, prompt, dotenv, template, public-key or a literal) is refused with `not_rotatable` (exit 2): nothing is resolved or written, and each of its targets is audited `failed` with that code.
- A derived variable that also uses another generated value is refused the same way (`AB also uses B, another generated value; rotating A alone would replace it too`).
- With `--target`, every derived variable must have all its targets inside the selection; otherwise the rotation is refused with `dependents_outside_selection` (exit 2): nothing is resolved or written, every write it would have made is audited `failed` with that code, and `error.dependents` lists `{dependent, targets}` for the targets outside the selection. Rerun without `--target`, or include those targets (they must be targets of NAME too).
- The output is the `apply` output plus `rotated` (NAME) and `dependents` (the derived variables written).

## Inventory

`zks inventory [--project P] [--policy FILE]` reads only the local audit log (no network, no values) and the policy. For each variable × destination it prints `{variable, provider, target, environment, lastWrittenAt, ageDays, writes, status}`: the latest applied `set` or `rotate` record, its age in whole days and how many applied writes there were. `status` is `written`, `never_written` (in the policy, never written: `lastWrittenAt` and `ageDays` are `null`, `writes` 0) or `not_in_policy` (written before, no longer in the policy). Denied and failed writes and captures do not count.

The project is `--project` or the policy's `project`. With `--project` and no policy file in the directory, or a policy of another project, the audit entries are listed without a comparison (`policy: null`, every entry `written`).

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

- Every capture is audited: `provider: "keychain"`, `action: "capture"`, `target: "<service>/<account>"`, `environment: <origin>`, `sourceKind: capture-read|capture-generate|capture-from`, result `applied`, `failed` or `denied`. Like `apply`, every capture then pushes pending records to the Sheets mirror (best effort) and reports it in `mirror`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ok |
| 1 | a write or check failed |
| 2 | usage or policy error |
| 3 | not approved (denied, timed out or no GUI) |

## Audit

Every apply and rotate appends one record per variable × target (`action: "set"` or `"rotate"`) to `~/.local/state/zks/audit.db` (SQLite, append-only triggers, SHA-256 hash chain): time, human, agent, project, provider, target, environment, variable name, sensitive flag, source kind, result, provider version, error code, approval mode (`dialog` or `trusted`). There is no field for a value or a hash of a value.

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

The build, the skill and the `~/AGENTS.md` block still run and write as you (`$SUDO_USER`), never as root. One step runs as root: the production `npm ci` inside the root-owned app, under `env -i` with a private `HOME`, cache, logs and empty global npmrc and no user npmrc, using the same checked node. It still executes your own `node` and `npm` files and npm's bundled `npmrc`, which your user can modify (same-user limit: install from a trusted state). The launcher is not written to `/usr/local/bin` because Homebrew often makes that directory user-owned; the install refuses to proceed when `/usr`, `/usr/local`, `/usr/local/libexec` or the zks prefix is not root-owned or is group/other-writable. The user-level launcher `~/.local/bin/zks` is removed so it cannot shadow the system one. `zks doctor` reports `install.mode: "system"` and an `ownership` check of the whole prefix (every entry root-owned, not group/other-writable, no symlink); a failed check turns `install.status` into `"ownership"`. Remove it with `sudo ./uninstall.sh --system`.

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
