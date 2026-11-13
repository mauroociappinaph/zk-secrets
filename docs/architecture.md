# zks architecture

zks splits the work between an **untrusted planner** (the AI agent, which only edits names, targets and sources, and drives the non-secret browser steps) and a **trusted executor** (the installed `zks` binary, which resolves values and writes them after a human approves the write or has trusted its destination, and runs its own ego-browser script for the secret step of a web capture). The agent's view is metadata only.

## Components

```text
 ┌──────────────────────────── agent context (untrusted) ─────────────────────────────┐
 │  AI agent ──edits──▶ zks.policy.json (names, targets, sources; no secret values)    │
 │      │                                                                             │
 │      └──runs── ~/.local/bin/zks <cmd> ──▶ JSON metadata on stdout (scrubbed)        │
 └──────┼─────────────────────────────────────────────────────────────────────────────┘
        ▼
 ┌──────────────────────── zks process (trusted, read-only install) ───────────────────┐
 │  launcher: ulimit -c 0, env -i (HOME USER LOGNAME LANG PATH=SAFE_PATH label)       │
 │  cli.ts ── empties process.env again, then loads main.ts                            │
 │  run.ts ── parseArgs (rejects --value/--secret/--token/--password, -x, extra args)  │
 │    ├─ policy/validate.ts   untrusted JSON → Policy, every issue listed               │
 │    ├─ gate/dialog.ts       osascript approval + hidden prompt (human only)           │
 │    ├─ policy/trust.ts      trusted destinations, HMAC-signed trust.json              │
 │    ├─ sources/resolve.ts   op │ keychain │ prompt │ generate │ dotenv │ literal       │
 │                            public-key │ template (derived, one resolver per apply)    │
 │    ├─ secret/*             SecretBuffer (never rendered) + Redactor (scrub output)   │
 │    ├─ sinks/*              vercel │ aws-ssm │ aws-sm │ github │ railway │ supabase   │
 │    ├─ audit/store.ts       SQLite append-only, SHA-256 hash chain                    │
 │    ├─ audit/mirror.ts      HMAC-signed push to Apps Script (optional)                │
 │    ├─ capture/script.ts    builds the ego-browser script, parses its one marker line │
 │    ├─ capture/run.ts       pipes the script to `ego-browser nodejs` (absolute path)  │
 │    └─ platform/*           exec (no shell, fixed env), keychain, integrity, paths,   │
 │                            tools (tools.json: ego-browser, gh, op paths + sha256)   │
 └──────┬──────────────┬───────────────┬──────────────────┬───────────────────────────┘
        ▼              ▼               ▼                  ▼
  1Password CLI   macOS Keychain   Provider APIs        ~/.local/state/zks/audit.db
  (op read)       (service "zks"   (GitHub REST with    └─▶ Google Sheet (mirror)
                   = tokens)        `gh auth token`),
                                    AWS SDK
```

Files on disk:

| Path | Content | Mode |
|---|---|---|
| `~/.local/libexec/zks/<version>/` | `dist/`, `bin/`, `package.json`, production `node_modules`, `tools.json` (paths and binary sha256 pins of `ego-browser`, `gh`, `op` resolved at install time, `null` when missing; covered by the integrity digest) | read-only (`a-w`) |
| `~/.local/bin/zks` | launcher: `ulimit -c 0`, then `/usr/bin/env -i HOME=… USER=… LOGNAME=… LANG=en_US.UTF-8 PATH=<SAFE_PATH> ZKS_AGENT_LABEL=… <node> <install>/dist/cli.js "$@"`; node's real path and your home are fixed at install time | `555` |
| `~/.config/zks/integrity.json` | `{version, root, digest, files}` of the install | `600` in `700` dir |
| `~/.config/zks/config.json` | Sheets webhook URL; `capture.profileId` (ego-browser profile for `capture --isolated`) | `600` |
| `~/.config/zks/trust.json` | trusted destination keys with `addedAt`/`addedBy`, HMAC-SHA256 `mac` | `600` in `700` dir |
| `~/.local/state/zks/audit.db` | audit log | owner only (umask `077`) |
| Keychain service `zks` | `vercel`, `railway`, `supabase`, `sheets-hmac` tokens (stored by `zks capture` or `zks auth set`); `audit-head` anchor (`<count>:<hash>`); `trust-hmac` key that signs `trust.json` | Keychain ACL |
| Other Keychain services | items `zks capture` stored (`<service>/<account>`), for policies' `keychain` sources or local tools | Keychain ACL |

## Trust boundaries

| Boundary | Crosses it | Never crosses it |
|---|---|---|
| Agent ↔ zks | argv (commands, names, target keys, policy path), stdout JSON metadata | secret values, provider tokens |
| zks ↔ human | approval dialog text (name → real destination, secret/plain, source description with the absolute dotenv path, target key, `[NEW destination]`; printable ASCII only) and its answer (Deny / Approve once / Always allow); hidden prompt input | values echoed back on screen |
| zks ↔ sources | `op read` stdout, `security` stdout, dotenv file bytes | argv carrying a value |
| zks ↔ providers | HTTPS body with the value (GitHub secrets as a libsodium sealed box); token in an HTTP header; `gh auth token` stdout (the GitHub token) | values in URLs, argv or env |
| zks ↔ audit | metadata only | values or hashes of values |
| zks ↔ ego-browser | the capture script on stdin (space id, page label, selectors, origin, Keychain service/account, all JSON-encoded); one `ZKS_RESULT` line back with `ok`, `length` or an error code | values: the script moves them page → `security -i` (stdin, hex) or `security find-generic-password` stdout → one main-frame `page.evaluate` that sets a password input, inside the ego runtime |
| zks ↔ isolated ego profile (`--isolated`) | the same script, plus `{profileId, url, name}`; zks creates the space `zks-capture-<hex>` in the configured non-default profile and finishes it with `keep: []`, except a `capture login` left pending (2FA/captcha), which keeps its page open and reports the space name so the human can finish there | the agent's session: the agent never drives that space |
| agent ↔ ego-browser | the non-secret steps: navigation, forms, token names, expiry, scope, one-time e-mail verification codes (typed with normal ego actions) | pages while they show a secret or after a fill (the skill forbids snapshot, screenshot or evaluate then; zks clicks the reveal itself) |

The policy file is written by the agent and is **not trusted**: it is validated field by field, and the human approval dialog is the gate that decides whether anything is written.

## Apply data flow

0. The launcher starts node with an empty environment plus `HOME`, `USER`, `LOGNAME`, `LANG`, `PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin` and `ZKS_AGENT_LABEL`. `cli.ts` empties `process.env` again (keeping only those five keys, with `HOME` from `os.userInfo()`) before it loads the rest of zks or the AWS SDK. Child processes get exactly the same five keys.
1. `zks apply` parses argv; secret-carrying flags, short options, options `apply` does not use and extra arguments are rejected (exit 2, the argument is not echoed).
2. Reads `zks.policy.json`, validates it (exit 2 with every issue), expands variables × targets, filtered by `--only` and `--target`. More than 20 writes are refused with `too_many_operations` (exit 2) before any dialog or audit.
3. Loads `~/.config/zks/trust.json` and checks its HMAC with the Keychain key `zks`/`trust-hmac`; an unparsable or badly signed file counts as empty and the output says `trust: "invalid"`. Each write gets a destination key (`github:<owner>`, `vercel:team:<teamId>` or `vercel:personal`, `aws:<profile>:<role>:<region>`, `railway:<project>`, `supabase:<ref>`). The dialog text is built; a line over 300 characters or a text over 6000 is refused with `dialog_too_long` (exit 2) before any dialog or audit.
4. Opens the audit store.
5. Every destination trusted: no dialog, records get `approval: "trusted"`. Otherwise one macOS dialog lists every write: `- NAME -> <destination> [secret|plain; source] (target <key>)`, ending with `[NEW destination]` when its key is not trusted, for example `aws-ssm us-east-1 /app/prod/NAME role arn:… kms alias/app`. Every character outside printable ASCII is shown as `?`. Buttons: **Deny** (default and cancel), **Approve once**, **Always allow**; it times out after 180 s. "Always allow" adds the new keys to `trust.json` (re-signed) before writing.
6. Not approved (deny, timeout, no GUI): appends a `denied` record per operation, stores the audit anchor, syncs the mirror, exits 3. Nothing is resolved or written.
7. Approved or trusted: for each variable, resolves the value once into a `SecretBuffer`; sensitive values are registered with the `Redactor`. A dotenv file is read at the real path that was checked to be inside the project.
8. For each target of that variable, the sink writes the value in an HTTPS body using the provider credential (Keychain token, AWS credential chain with `endpoint_url` from `~/.aws/config` ignored, or the `gh auth token` of your GitHub login sent to `api.github.com` directly; GitHub secrets are sealed with the repository public key first). Each outcome is appended to the audit log as `applied` or `failed` with the provider version or error code. If the audit append fails after a successful write, zks stops and exits 1 with `audit_failed`; the write is not reported as failed.
9. The buffer is zeroed (`dispose`); provider tokens are zeroed after each request.
10. The audit head (`<count>:<hash>`) is stored in the Keychain item `zks`/`audit-head`; `zks audit verify` and `zks doctor` check the chain against it. The mirror pushes pending records to the Sheet (failures stay pending locally).
11. stdout gets JSON results (with `approval` and, after "Always allow", `trusted`), passed through `Redactor.scrub`; exit 0 if every write applied, else 1.

`zks plan` adds a fixed `effect` text per operation (what the human must redeploy or restart; zks triggers nothing) and an `effects` summary. `zks rotate NAME` runs steps 2-11 on the operations of one `generate` variable and its derived variables, with two differences: the dialog always opens (trust never skips it) and records carry `action: "rotate"`; other variables are refused with `not_rotatable` before anything is resolved. `zks inventory` only reads the audit store (latest applied `set`/`rotate` per provider × target × variable) and the policy; it makes no network call. `--older-than <N>d` keeps only entries last written more than N days ago, plus entries with no known write. `zks doctor --fix` only changes the modes of `~/.config/zks`, `~/.local/state/zks` (700) and their `config.json`, `trust.json`, `audit.db*` (600), through `O_NOFOLLOW` descriptors; integrity, trust content, the audit chain and the Keychain stay as they are and are listed as `notFixable` with the command to run.

## Capture data flow

1. The agent opens the provider or site page in one ego-browser TaskSpace and does every non-secret step (log in with the user's session, fill the token name and expiry). It stops before the click that reveals a value.
2. `zks capture read|fill` validates every option (space id, page label, selectors as printable ASCII up to 300 characters, `SERVICE/ACCOUNT`, `--origin` as an https or loopback origin, mandatory for `fill`). Service `zks` (any case) is limited to `read` of `vercel`, `railway`, `supabase` and `sheets-hmac` from their pinned origin. Errors exit 2 without echoing a value.
3. zks resolves `ego-browser` from `tools.json` (a development checkout looks on SAFE_PATH only); missing → `browser_failed`.
4. `read` and `fill --generate` over an existing Keychain item ask "Replace the Keychain item <service>/<account>?" with the origin; denial exits 3 and runs nothing. `fill --from` needs the item to exist (`not_found`); it runs without a dialog only when `--origin` equals the origin of the item's latest applied `capture-read` or `capture-generate` audit record (`AuditStore.lastCaptureOrigin`). Otherwise it asks "Fill <service>/<account> into <origin>? It was captured from <origin or unknown>."; denial exits 3, is audited `denied` and runs nothing.
5. `fill --generate`: zks generates base64url random bytes and stores them with `security -i` before the browser step.
6. zks builds the script (inputs only through `JSON.stringify`) and runs `ego-browser nodejs` with it on stdin, a fixed environment and a 60 s timeout. Inside ego, the script resumes the TaskSpace and page, checks `new URL(page.url()).origin` against `--origin`, then:
   - `read`: clicks `--click`, waits up to 15 s for `--selector` to match one element with a value, checks the origin again, takes the value and blanks the element in one `page.evaluate`, stores it with `security -i` (`add-generic-password -U … -X <hex>` on stdin) and navigates the page to `about:blank`. Once the click was attempted, `about:blank` runs in a `finally`, so every failure path leaves the page too;
   - `fill`: waits for `--selector`, reads the item with `security find-generic-password -w` (stdout kept in memory, zeroed), then runs one `page.evaluate` in the main frame with the value as its argument: it checks `document.location.origin === --origin` (else `origin_mismatch`), requires exactly one match that is an `HTMLInputElement` with `type === "password"` (else `not_password_field`), sets it with the native `HTMLInputElement.prototype` value setter and dispatches bubbling `input` and `change` events. It never calls `page.fill`, which could reach cross-origin iframes.
7. The script prints one line, `ZKS_RESULT {"ok":true,"length":N}` or `{"ok":false,"code":"origin_mismatch|not_found|not_password_field|keychain_failed|browser_failed"}`; any thrown error becomes `browser_failed` without its message. ego prints it on stderr; zks reads exactly one marker line from stdout and stderr, zeroes both and relays nothing else.
8. `--isolated` (instead of `--space`/`--page`, with mandatory `--url` on `--origin`): zks reads `capture.profileId` from `config.json` (unset or invalid → `isolated_profile_unset`, before any dialog or Keychain write) and embeds `isolated: {profileId, url, name: "zks-capture-<16 hex>"}` in the script. Inside ego the script calls `profiles()`: the id must be listed (`isolated_profile_missing`) with `isDefault === false` (`isolated_profile_not_isolated`); then `taskSpace(name, { profileId })`, `task.page("zks")`, `page.goto(url)`; a page that is not on `--origin` after landing is `login_required`. Then step 6 runs on that page, and `task.finish({ keep: [] })` runs in a `finally` (`keep: [page]` only for a pending `capture login`). A refused isolated `fill --generate` removes the item zks created for it in step 5. Output adds `isolated: true`.
9. zks appends an audit record (`provider: "keychain"`, `action: "capture"`, `target: "<service>/<account>"`, `environment: <origin>`, `sourceKind: capture-read|capture-generate|capture-from`), stores the audit anchor, pushes pending records to the Sheets mirror (best effort, like `apply`) and prints `{ok, command, mode, store, origin, length, auditId, mirror}`.

## Threat model

| Vector | Mitigation | Residual risk |
|---|---|---|
| argv (`ps`, shell history, agent transcript) | No flag accepts a value; `--value`/`--secret`/`--token`/`--password` are rejected; the only child process that receives a value gets it on stdin (`security -i`); `gh` is only run as `gh auth token` | `op read <ref>` puts the reference (not the value) in argv |
| Environment variables (`AWS_ENDPOINT_URL`, `HTTPS_PROXY`, `NODE_EXTRA_CA_CERTS`, `GH_HOST`, `XDG_*`, `OP_*`, `PATH`, `HOME`) | Launcher runs node through `env -i` with only `HOME`, `USER`, `LOGNAME`, `LANG`, `PATH=SAFE_PATH` (`/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin`) and the agent label, with node's path fixed at install; `cli.ts` empties `process.env` again; children get the same five keys; zks paths use `os.userInfo().homedir`; values are never put in env | A same-user agent can still edit what zks reads after that: `~/.aws/config` (`credential_process`; `endpoint_url` is ignored), the token in `~/.config/gh`, binaries in `/opt/homebrew/bin`. 1Password `OP_SESSION_*` is no longer forwarded (use the desktop app integration) |
| stdout / stderr | JSON metadata only; every output passes `Redactor.scrub` (raw, JSON-escaped, URL-encoded, base64, base64url, hex forms); child stderr is never forwarded | Values shorter than 4 characters are not scrubbed (they are not secrets worth the name) |
| Provider error echo | Errors are reduced to status codes and short identifiers (`safeCode`); messages are scrubbed and truncated to 300 chars | A provider could encode a value in an unknown form; still scrubbed for the known forms |
| Temp files | zks writes no temp files; values stay in memory | — |
| Core dumps | Launcher runs `ulimit -c 0` | A privileged debugger can still attach |
| Swap / memory | Buffers are zeroed after use; values live for one apply | OS paging and immutable JavaScript strings during the HTTPS request cannot be zeroed |
| Prompt injection (policy text, repo files, provider output) | The agent never receives values to leak; the approval dialog shows exactly what will be written: every write, its real destination ids, secret/plain and source, never truncated (max 20 writes), printable ASCII only; skill and `~/AGENTS.md` rule forbid reading secrets | A tricked agent can still propose a bad policy; the human must read the dialog |
| Binary tampering | Install is read-only; `zks doctor` compares a SHA-256 tree digest with `integrity.json` | Tamper-evident, not tamper-proof: a same-user process can `chmod` and rewrite both |
| Policy tampering | Policy is untrusted input: strict validation (own keys only, strict id patterns), literal values only for `sensitive: false`, every `source` except `public-key` forced to `sensitive: true`, `template` references checked for unknown names and cycles, Keychain service `zks` reserved, dotenv paths limited to relative `.env*` files inside the project (symlinks resolved; the checked real path is the one read), `op://` refs limited to printable ASCII, identifiers length-capped so the dialog is never truncated; the approval dialog is the gate | Human approves a list they did not read |
| Trust store tampering | `trust.json` is HMAC-SHA256 signed with a Keychain key; unparsable, unsigned or mismatched files trust nothing and are reported `trust: "invalid"`; `zks trust remove` only reduces trust | A same-user process can read `trust-hmac` and forge the file; "Always allow" on one GitHub repo trusts its whole owner |
| Audit tampering | `BEFORE UPDATE/DELETE` triggers, SHA-256 hash chain (`zks audit verify`), Keychain anchor `zks`/`audit-head` that detects a deleted tail, off-machine Sheet mirror with a `chainOk` column, provider audit logs; `zks config set/unset sheets-webhook` needs approval | Tamper-evident, not impossible: a same-user process can rewrite the SQLite file and the anchor; the mirror and provider logs reveal it |
| Actor identity | `actorHuman` comes from the OS user database | `actorAgent` is a self-declared label (`--agent`, `ZKS_AGENT_LABEL` from `PI_SESSION_ID`/`AI_AGENT`); zks cannot authenticate it |
| Capture script integrity | zks builds the whole script itself from a fixed body; every input is validated and enters only through `JSON.stringify` (a selector with quotes, backticks or `${}` stays a string); `ego-browser` runs from the real path recorded at install, never a `PATH` lookup; only the one `ZKS_RESULT` line is parsed, strictly (`ok` + integer `length`, or `ok` + a known code); errors inside the script are reported as codes, never messages | A same-user process can replace the ego-browser app or its runtime, which then sees every value the script handles; `tools.json` is tamper-evident through `zks doctor`, not tamper-proof |
| ego runtime memory | The value lives only inside the ego `nodejs` process for one script: read from the page, sent to `security` on stdin as hex (buffer zeroed), or read from `security` stdout (zeroed) and passed as the argument of one `page.evaluate` that sets a password input | JavaScript strings in the ego runtime and the page's own memory cannot be zeroed; the browser profile may keep form data per its own settings |
| Revealed page | zks performs the reveal click itself, takes and blanks the element in one `page.evaluate` (`value = ""`, `textContent = "[captured by zks]"`) and navigates the page to `about:blank`, in a `finally` once the reveal click was attempted, so a failure never leaves the token on screen | The agent's own ego session can still read a revealed page or a filled password field if it ignores the skill (same-user limit); a site may keep the token elsewhere in its DOM, history or clipboard buttons |
| Agent session sees the revealed token | `--isolated` runs the secret step in a space zks creates in a separate, non-default ego-browser profile (checked with `profiles()` inside the script), lands on `--url` only if it stays on `--origin`, and always finishes the space with `keep: []`; the agent never gets the space id | Same-user limit: while the capture runs, an agent can still list and claim the space by id through ego-browser, or edit `config.json` to name another non-default profile; without `--isolated` the step runs in the agent's own TaskSpace |
| Phishing or redirected page | `--origin` is checked before the click and again before the read; `fill` requires `--origin` and re-checks `document.location.origin` in the same `page.evaluate` that sets the value, only into one main-frame password input; `fill --from` into any origin other than the one the item was captured or generated from needs approval; `zks/<provider>` tokens can only be captured with their pinned origin (`https://vercel.com`, `https://railway.com`, `https://supabase.com`, `https://script.google.com`); `fill` never uses service `zks`; replacing an existing item needs approval | Without `--origin`, any page can be read (the agent is told to always pass it); an origin is not a path, so a malicious page on the same origin is not detected, and page JavaScript on the allowed origin can read the filled field; the "same origin, no dialog" decision reads the local audit log, which a same-user process can rewrite |
| Stored secret typed into a page (`fill`) | The value never enters page JavaScript: a secret-free `evaluate` focuses the one main-frame password input of the expected origin; the origin is checked again before the Keychain read and before typing; a second secret-free check confirms focus is still on that input right before `keyboard.insertText`; afterwards a third check confirms origin, focus and length, and on any failure zks clears the active element (input, textarea or contenteditable) and the target input and navigates to `about:blank`; `fill --from` stays silent only while the item's Keychain modification time equals the one recorded by its capture | Focus can still move in the few milliseconds between the last check and typing: text typed into a focus-stealing cross-origin iframe reaches that frame's JavaScript before cleanup (needs a hostile frame on the allowed origin); the Keychain time has one-second resolution, so a same-user replacement within the capture's second stays silent; cleanup clears the active element itself, so text typed inside a shadow root or a same-origin iframe is not cleared (the page still goes to `about:blank`); in real runs with this code 1 of 7 fills ended `browser_failed` and was cleaned up (fail closed) |
| First `zks/*` capture | Only the pinned provider origin can be captured into `zks/vercel`, `zks/railway`, `zks/supabase` and `zks/sheets-hmac`; replacing an existing token needs approval | The first capture into an empty `zks/*` item needs no approval: a same-user agent could create and store a token of its choosing from the provider site the human is logged into (same-user limit, documented) |
| Token theft | Tokens in Keychain (service `zks`), read only for one request and zeroed; a policy cannot use service `zks` as a source; AWS uses short-lived SSO/role credentials with a session policy; scoped, expiring tokens recommended below | Any process of the same user can read Keychain items with `/usr/bin/security find-generic-password -w`; for a hard boundary run the agent as a dedicated macOS user |

## Least-privilege recipes

### AWS: write-only role `zks-secret-writer`

Attach this policy to a role your SSO identity can assume, and set `roleArn` on the `aws-ssm`/`aws-sm` targets. Replace the account, region and prefixes.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "WriteParameters",
      "Effect": "Allow",
      "Action": ["ssm:PutParameter", "ssm:AddTagsToResource"],
      "Resource": "arn:aws:ssm:us-east-1:123456789012:parameter/acme-shop/*"
    },
    {
      "Sid": "WriteSecrets",
      "Effect": "Allow",
      "Action": ["secretsmanager:PutSecretValue", "secretsmanager:CreateSecret", "secretsmanager:DescribeSecret"],
      "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:acme-shop/*"
    },
    {
      "Sid": "EncryptOnly",
      "Effect": "Allow",
      "Action": ["kms:Encrypt", "kms:GenerateDataKey"],
      "Resource": "arn:aws:kms:us-east-1:123456789012:key/REPLACE_ME"
    },
    {
      "Sid": "NeverRead",
      "Effect": "Deny",
      "Action": [
        "ssm:GetParameter*",
        "secretsmanager:GetSecretValue",
        "secretsmanager:BatchGetSecretValue",
        "kms:Decrypt"
      ],
      "Resource": "*"
    }
  ]
}
```

zks assumes the role for 900 seconds with this **session policy** (`sessionPolicyFor` in `src/sinks/aws-clients.ts`). The effective permissions are the intersection of the role policy and the session policy, so each session can only write under the target's prefix:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["ssm:PutParameter", "ssm:AddTagsToResource"],
      "Resource": "arn:aws:ssm:<region>:*:parameter<prefix>*"
    },
    { "Effect": "Allow", "Action": ["kms:Encrypt", "kms:GenerateDataKey"], "Resource": "*" }
  ]
}
```

For `aws-sm` the first statement is `secretsmanager:PutSecretValue`, `secretsmanager:CreateSecret`, `secretsmanager:DescribeSecret` on `arn:aws:secretsmanager:<region>:*:secret:<prefix>*`.

### Vercel

Create a token with an **expiration** and scope it to the team that owns the project (Account Settings → Tokens). The agent creates it at `vercel.com/account/settings/tokens` and stores it with `zks capture read --store zks/vercel --origin https://vercel.com` (or, by hand, `zks auth set vercel`). zks writes sensitive variables as type `sensitive`, which Vercel never returns after creation.

### GitHub

zks reads your `gh auth login` token with `gh auth token --hostname github.com` and calls `https://api.github.com` itself: secrets are sealed with the repository (or environment) public key (libsodium `crypto_box_seal`) and sent with `PUT …/secrets/<NAME>`; variables use `PATCH …/variables/<NAME>`, or `POST …/variables` when the variable does not exist yet. Prefer a login limited to the target repositories with *Secrets* and *Variables* write permission.

### Railway

Prefer a **project token** (Project Settings → Tokens) scoped to one environment, with `"tokenType": "project"` on the target. The agent captures it into `zks/railway` with `--origin https://railway.com` (or, by hand, `zks auth set railway`).

### Supabase

Create a personal access token (Account → Access Tokens), captured into `zks/supabase` with `--origin https://supabase.com` (or `zks auth set supabase`), and revoke it when no longer needed. It can manage every project you can access, so keep it in the Keychain only.

## Data model

### Policy (`zks.policy.json`)

```text
Policy
  version: 1
  project: string               ^[A-Za-z0-9._-]{1,64}$
  targets: { <key>: Target }    key ^[a-z0-9][a-z0-9-]{0,62}$
  variables: { <NAME>: Variable }  NAME ^[A-Za-z_][A-Za-z0-9_]{0,127}$, not __proto__/constructor/prototype (any case)

Target (by provider)
  vercel    projectId, environments[production|preview|development], teamId?, gitBranch?
            projectId/teamId ^[A-Za-z0-9_.-]{1,100}$; gitBranch ^[A-Za-z0-9_./-]{1,250}$ without ".."
  aws-ssm   region, prefix "/a/b/" (at most 200 characters), profile?, roleArn?, kmsKeyId?
  aws-sm    region, prefix "a/b/" (at most 200 characters),  profile?, roleArn?, kmsKeyId?
            profile ^[A-Za-z0-9_.-]{1,64}$; kmsKeyId alias/<name>, a key UUID or a KMS key/alias ARN
  github    repo "owner/name" (at most 100 characters), environment? ^[A-Za-z0-9_.-]{1,255}$
  railway   projectId, environmentId, serviceId? (each ^[A-Za-z0-9-]{1,64}$), tokenType? account|project, skipDeploys?
  supabase  projectRef [a-z0-9]{20}

Variable
  sensitive: boolean            must be true when a source other than public-key is used
  description?: string
  source?: op{ref ^op://[printable ASCII]$, at most 200 characters}
         | keychain{service,account ^[A-Za-z0-9_.-]{1,128}$; service "zks" reserved in any case}
         | prompt
         | generate{format? random (default): bytes 16..512, encoding base64url|hex
                    | uuid | jwt-secret (64 bytes base64url)
                    | password: length 12..128 (32), lower|upper|digits|symbols booleans (true), >= 1 enabled
                    | rsa-private-key: bits 2048|3072|4096 (3072), PKCS8 PEM | ed25519-private-key: PKCS8 PEM}
                    options of another format are invalid
         | dotenv{path: relative .env* file inside the project, at most 200 characters, key?}
         | public-key{of: variable with a generate rsa-/ed25519-private-key source}  SPKI PEM; may be sensitive: false
         | template{template: 1..2000 characters, ${NAME} raw, ${NAME:url} percent-encoded, $${ literal ${;
                    >= 1 reference; no unknown, self or cyclic reference}
  value?: string                only when sensitive is false; exactly one of source or value
  targets: [<target key>, ...]  non-empty; own keys of targets only
```

### Audit record

| Field | Meaning |
|---|---|
| `auditId` | ULID-style id (time + random) |
| `ts` | ISO timestamp |
| `actorHuman` | macOS user name |
| `actorAgent` | self-declared: `--agent`, else `ZKS_AGENT_LABEL` (the launcher sets `pi:<PI_SESSION_ID>` or `AI_AGENT`), else `human` |
| `project` | policy project; for a capture the Keychain service |
| `provider`, `target`, `environment` | where the write went; for a capture `keychain`, `<service>/<account>` and the page origin (`""` without `--origin`) |
| `variableName` | name only; for a capture the Keychain account |
| `action` | `set` (apply), `rotate` (rotate) or `capture` |
| `sensitive` | boolean |
| `sourceKind` | `op`, `keychain`, `prompt`, `generate`, `dotenv`, `public-key`, `template` or `literal`; for a capture `capture-read`, `capture-generate` or `capture-from` |
| `result` | `applied`, `denied` or `failed` |
| `providerVersion` | version id returned by the provider, if any |
| `errorCode` | short code, e.g. `not_approved`, `missing_token` |
| `approval` | `dialog` or `trusted` (`""` for records written before approval modes existed) |
| `prevHash`, `hash` | SHA-256 chain: `hash = sha256(prevHash + "\n" + canonicalJson(record))`; an empty `approval` is left out, so older records keep their hashes |
| `mirroredAt` | when the Sheet accepted it (the only updatable column) |
