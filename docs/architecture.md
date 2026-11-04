# zks architecture

zks splits the work between an **untrusted planner** (the AI agent, which only edits names, targets and sources) and a **trusted executor** (the installed `zks` binary, which resolves values and writes them after a human approves). The agent's view is metadata only.

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
 │    ├─ sources/resolve.ts   op │ keychain │ prompt │ generate │ dotenv │ literal       │
 │    ├─ secret/*             SecretBuffer (never rendered) + Redactor (scrub output)   │
 │    ├─ sinks/*              vercel │ aws-ssm │ aws-sm │ github │ railway │ supabase   │
 │    ├─ audit/store.ts       SQLite append-only, SHA-256 hash chain                    │
 │    ├─ audit/mirror.ts      HMAC-signed push to Apps Script (optional)                │
 │    └─ platform/*           exec (no shell, fixed env), keychain, integrity, paths    │
 └──────┬──────────────┬───────────────┬──────────────────┬───────────────────────────┘
        ▼              ▼               ▼                  ▼
  1Password CLI   macOS Keychain   Provider APIs /      ~/.local/state/zks/audit.db
  (op read)       (service "zks"   gh CLI / AWS SDK     └─▶ Google Sheet (mirror)
                   = tokens)
```

Files on disk:

| Path | Content | Mode |
|---|---|---|
| `~/.local/libexec/zks/<version>/` | `dist/`, `bin/`, `package.json`, production `node_modules` | read-only (`a-w`) |
| `~/.local/bin/zks` | launcher: `ulimit -c 0`, then `/usr/bin/env -i HOME=… USER=… LOGNAME=… LANG=en_US.UTF-8 PATH=<SAFE_PATH> ZKS_AGENT_LABEL=… <node> <install>/dist/cli.js "$@"`; node's real path and your home are fixed at install time | `555` |
| `~/.config/zks/integrity.json` | `{version, root, digest, files}` of the install | `600` in `700` dir |
| `~/.config/zks/config.json` | Sheets webhook URL | `600` |
| `~/.local/state/zks/audit.db` | audit log | owner only (umask `077`) |
| Keychain service `zks` | `vercel`, `railway`, `supabase`, `sheets-hmac` tokens; `audit-head` anchor (`<count>:<hash>`) | Keychain ACL |

## Trust boundaries

| Boundary | Crosses it | Never crosses it |
|---|---|---|
| Agent ↔ zks | argv (commands, names, target keys, policy path), stdout JSON metadata | secret values, provider tokens |
| zks ↔ human | approval dialog text (name → real destination, secret/plain, source description, target key; printable ASCII only); hidden prompt input | values echoed back on screen |
| zks ↔ sources | `op read` stdout, `security` stdout, dotenv file bytes | argv carrying a value |
| zks ↔ providers | HTTPS body or child stdin with the value; token in an HTTP header | values in URLs, argv or env |
| zks ↔ audit | metadata only | values or hashes of values |

The policy file is written by the agent and is **not trusted**: it is validated field by field, and the human approval dialog is the gate that decides whether anything is written.

## Apply data flow

0. The launcher starts node with an empty environment plus `HOME`, `USER`, `LOGNAME`, `LANG`, `PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin` and `ZKS_AGENT_LABEL`. `cli.ts` empties `process.env` again (keeping only those five keys, with `HOME` from `os.userInfo()`) before it loads the rest of zks or the AWS SDK. Child processes get exactly the same five keys.
1. `zks apply` parses argv; secret-carrying flags, short options and extra arguments are rejected (exit 2, the argument is not echoed).
2. Reads `zks.policy.json`, validates it (exit 2 with every issue), expands variables × targets, filtered by `--only` and `--target`. More than 20 writes are refused with `too_many_operations` (exit 2) before any dialog or audit.
3. Opens the audit store.
4. Shows one macOS dialog listing every write: `- NAME -> <destination> [secret|plain; source] (target <key>)`, for example `aws-ssm us-east-1 /app/prod/NAME role arn:… kms alias/app`. Every character outside printable ASCII is shown as `?`. Default button is **Deny**; it times out after 180 s.
5. Not approved (deny, timeout, no GUI): appends a `denied` record per operation, stores the audit anchor, syncs the mirror, exits 3. Nothing is resolved or written.
6. Approved: for each variable, resolves the value once into a `SecretBuffer`; sensitive values are registered with the `Redactor`.
7. For each target of that variable, the sink writes the value (HTTPS body or `gh` stdin) using the provider credential (Keychain token, AWS credential chain, `gh` session). Each outcome is appended to the audit log as `applied` or `failed` with the provider version or error code. If the audit append fails after a successful write, zks stops and exits 1 with `audit_failed`; the write is not reported as failed.
8. The buffer is zeroed (`dispose`); provider tokens are zeroed after each request.
9. The audit head (`<count>:<hash>`) is stored in the Keychain item `zks`/`audit-head`; `zks audit verify` and `zks doctor` check the chain against it. The mirror pushes pending records to the Sheet (failures stay pending locally).
10. stdout gets JSON results, passed through `Redactor.scrub`; exit 0 if every write applied, else 1.

## Threat model

| Vector | Mitigation | Residual risk |
|---|---|---|
| argv (`ps`, shell history, agent transcript) | No flag accepts a value; `--value`/`--secret`/`--token`/`--password` are rejected; child processes get values on stdin (`gh`, `security -i`) | `op read <ref>` puts the reference (not the value) in argv |
| Environment variables (`AWS_ENDPOINT_URL`, `HTTPS_PROXY`, `NODE_EXTRA_CA_CERTS`, `GH_HOST`, `XDG_*`, `OP_*`, `PATH`, `HOME`) | Launcher runs node through `env -i` with only `HOME`, `USER`, `LOGNAME`, `LANG`, `PATH=SAFE_PATH` (`/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin`) and the agent label, with node's path fixed at install; `cli.ts` empties `process.env` again; children get the same five keys; zks paths use `os.userInfo().homedir`; values are never put in env | A same-user agent can still edit what zks reads after that: `~/.aws/config`, `~/.config/gh`, binaries in `/opt/homebrew/bin`. 1Password `OP_SESSION_*` is no longer forwarded (use the desktop app integration) |
| stdout / stderr | JSON metadata only; every output passes `Redactor.scrub` (raw, JSON-escaped, URL-encoded, base64, hex forms); child stderr is never forwarded | Values shorter than 4 characters are not scrubbed (they are not secrets worth the name) |
| Provider error echo | Errors are reduced to status codes and short identifiers (`safeCode`); messages are scrubbed and truncated to 300 chars | A provider could encode a value in an unknown form; still scrubbed for the known forms |
| Temp files | zks writes no temp files; values stay in memory | — |
| Core dumps | Launcher runs `ulimit -c 0` | A privileged debugger can still attach |
| Swap / memory | Buffers are zeroed after use; values live for one apply | OS paging and immutable JavaScript strings during the HTTPS request cannot be zeroed |
| Prompt injection (policy text, repo files, provider output) | The agent never receives values to leak; the approval dialog shows exactly what will be written: every write, its real destination ids, secret/plain and source, never truncated (max 20 writes), printable ASCII only; skill and `~/AGENTS.md` rule forbid reading secrets | A tricked agent can still propose a bad policy; the human must read the dialog |
| Binary tampering | Install is read-only; `zks doctor` compares a SHA-256 tree digest with `integrity.json` | Tamper-evident, not tamper-proof: a same-user process can `chmod` and rewrite both |
| Policy tampering | Policy is untrusted input: strict validation (own keys only, strict id patterns), literal values only for `sensitive: false`, every `source` forced to `sensitive: true`, Keychain service `zks` reserved, dotenv paths limited to relative `.env*` files inside the project, `op://` refs limited to printable ASCII; the approval dialog is the gate | Human approves a list they did not read; a `.env*` file inside the project can be a symlink to a file elsewhere |
| Audit tampering | `BEFORE UPDATE/DELETE` triggers, SHA-256 hash chain (`zks audit verify`), Keychain anchor `zks`/`audit-head` that detects a deleted tail, off-machine Sheet mirror with a `chainOk` column, provider audit logs; `zks config set/unset sheets-webhook` needs approval | Tamper-evident, not impossible: a same-user process can rewrite the SQLite file and the anchor; the mirror and provider logs reveal it |
| Actor identity | `actorHuman` comes from the OS user database | `actorAgent` is a self-declared label (`--agent`, `ZKS_AGENT_LABEL` from `PI_SESSION_ID`/`AI_AGENT`); zks cannot authenticate it |
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

Create a token with an **expiration** and scope it to the team that owns the project (Account Settings → Tokens). Store it with `zks auth set vercel`. zks writes sensitive variables as type `sensitive`, which Vercel never returns after creation.

### GitHub

zks calls `gh secret set` / `gh variable set` with the value on stdin, using your `gh auth login` session. Prefer a fine-grained token limited to the target repositories with *Secrets* and *Variables* write permission.

### Railway

Prefer a **project token** (Project Settings → Tokens) scoped to one environment, with `"tokenType": "project"` on the target. Store it with `zks auth set railway`.

### Supabase

Create a personal access token (Account → Access Tokens), store it with `zks auth set supabase`, and revoke it when no longer needed. It can manage every project you can access, so keep it in the Keychain only.

## Data model

### Policy (`zks.policy.json`)

```text
Policy
  version: 1
  project: string               ^[A-Za-z0-9._-]{1,64}$
  targets: { <key>: Target }    key ^[a-z0-9][a-z0-9-]{0,62}$
  variables: { <NAME>: Variable }  NAME ^[A-Za-z_][A-Za-z0-9_]{0,127}$

Target (by provider)
  vercel    projectId, environments[production|preview|development], teamId?, gitBranch?
            projectId/teamId ^[A-Za-z0-9_.-]{1,100}$; gitBranch ^[A-Za-z0-9_./-]{1,250}$ without ".."
  aws-ssm   region, prefix "/a/b/", profile?, roleArn?, kmsKeyId?
  aws-sm    region, prefix "a/b/",  profile?, roleArn?, kmsKeyId?
            profile ^[A-Za-z0-9_.-]{1,64}$; kmsKeyId alias/<name>, a key UUID or a KMS key/alias ARN
  github    repo "owner/name", environment? ^[A-Za-z0-9_.-]{1,255}$
  railway   projectId, environmentId, serviceId? (each ^[A-Za-z0-9-]{1,64}$), tokenType? account|project, skipDeploys?
  supabase  projectRef [a-z0-9]{20}

Variable
  sensitive: boolean            must be true when a source is used
  description?: string
  source?: op{ref ^op://[printable ASCII]{1,512}$}
         | keychain{service,account ^[A-Za-z0-9_.-]{1,128}$; service "zks" reserved}
         | prompt
         | generate{bytes 16..512, encoding base64url|hex}
         | dotenv{path: relative .env* file inside the project, key?}
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
| `project` | policy project |
| `provider`, `target`, `environment` | where the write went |
| `variableName` | name only |
| `action` | `set` |
| `sensitive` | boolean |
| `sourceKind` | `op`, `keychain`, `prompt`, `generate`, `dotenv` or `literal` |
| `result` | `applied`, `denied` or `failed` |
| `providerVersion` | version id returned by the provider, if any |
| `errorCode` | short code, e.g. `not_approved`, `missing_token` |
| `prevHash`, `hash` | SHA-256 chain: `hash = sha256(prevHash + "\n" + canonicalJson(record))` |
| `mirroredAt` | when the Sheet accepted it (the only updatable column) |
