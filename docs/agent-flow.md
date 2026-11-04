# Agent flow

How an agent sets a secret with zks, step by step. The agent handles names, targets and sources; the human handles values, tokens and approval. The skill in [`skill/SKILL.md`](../skill/SKILL.md) is the instruction set agents follow.

## Sequence

```text
Human                    Agent                         zks                          Provider
  │  "set STRIPE key      │                             │                              │
  │   on Vercel + SSM"    │                             │                              │
  │──────────────────────▶│                             │                              │
  │                       │ 1. zks doctor               │                              │
  │                       │────────────────────────────▶│ install, tools, tokens,      │
  │                       │◀──── JSON (install: ok) ────│ audit chain                  │
  │                       │   not ok? stop, tell human  │                              │
  │  "op://Prod/Stripe/   │ 2. which source? ask        │                              │
  │   secret_key"         │◀─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │                              │
  │──────────────────────▶│    edit zks.policy.json     │                              │
  │                       │    (zks init if missing)    │                              │
  │                       │ 3. zks validate             │                              │
  │                       │────────────────────────────▶│ schema check                 │
  │                       │◀──── ok / issues (exit 2) ──│                              │
  │                       │ 4. zks plan --only --target │                              │
  │                       │────────────────────────────▶│ no network                   │
  │  plan list            │◀──── operations ────────────│                              │
  │◀──────────────────────│                             │                              │
  │                       │ 5. "a macOS dialog will ask │                              │
  │                       │    you to approve"          │                              │
  │                       │    zks apply --only --target│                              │
  │                       │────────────────────────────▶│                              │
  │◀════════ native dialog: NAME -> destination … [Approve / Deny] ═════│               │
  │═════════ Approve ══════════════════════════════════▶│                              │
  │                       │                             │ resolve value (op/keychain/  │
  │                       │                             │ prompt/generate/dotenv)      │
  │                       │                             │── value over HTTPS / stdin ─▶│
  │                       │                             │◀── version / status ─────────│
  │                       │                             │ audit append, zero buffer,   │
  │                       │                             │ mirror sync                  │
  │                       │◀── JSON results (exit 0/1/3)│                              │
  │  6. name, target,     │                             │                              │
  │  result, version,     │                             │                              │
  │  auditId              │                             │                              │
  │◀──────────────────────│                             │                              │

═══ = human-only channel the agent cannot read or drive.
```

Branches:

- **Exit 2** (usage or policy): the agent fixes the policy or command and repeats from step 3. `too_many_operations` means more than 20 writes: split the apply with `--only` / `--target`.
- **Exit 3** (not approved): nothing was written. The agent asks the human whether to retry; it never retries on its own.
- **Exit 1 with `missing_token`**: the agent tells the human to run `zks auth set <vercel|railway|supabase>`; the token goes through a hidden dialog, never through chat.
- **AWS credentials expired**: the human runs `aws sso login`. **GitHub failures**: the human runs `gh auth login`.
- **A secret pasted into chat**: the agent does not use it and recommends rotating it.

## Which source kind

| The human says… | Source | Policy snippet | Note |
|---|---|---|---|
| "It's in 1Password" | `op` | `{"kind":"op","ref":"op://Vault/Item/field"}` | Ask for the reference; it is not secret |
| "I'll type it" / "I have it copied" | `prompt` | `{"kind":"prompt"}` | Hidden macOS dialog during apply |
| "Make a new random key" | `generate` | `{"kind":"generate","bytes":32}` | New value on **every** apply: it rotates each time |
| "It's in my Keychain" | `keychain` | `{"kind":"keychain","service":"svc","account":"acct"}` | Item must exist; service `zks` is reserved |
| "It's in `.env.production`" | `dotenv` | `{"kind":"dotenv","path":".env.production","key":"NAME"}` | Relative `.env*` file inside the project; agent passes the path; only zks opens the file |
| "It's a public URL / log level" | literal | `"sensitive": false, "value": "info"` | Never for sensitive values |
| Not sure | ask | — | Default to `sensitive: true` and `prompt` |

Every row with a `source` needs `"sensitive": true`; zks rejects a source on a non-sensitive variable. Only a literal `value` can be `sensitive: false`.

The approval dialog and `zks plan` show each write's real destination (`destination`), for example `github acme/shop env production secret` or `aws-ssm us-east-1 /acme-shop/prod/NAME role arn:…`. `zks config set|unset sheets-webhook` also opens an approval dialog.
