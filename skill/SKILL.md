---
name: zks-secrets
description: "Trigger: secretos, variables de entorno, env vars, Vercel env, AWS SSM, Parameter Store, Secrets Manager, GitHub secrets, Railway variables, Supabase secrets, rotar clave, deploy config. Set secrets with zks, never seeing values."
---

# zks-secrets

Set secrets and env vars on Vercel, AWS SSM, AWS Secrets Manager, GitHub Actions, Railway and Supabase through the `zks` CLI. You write names, targets and sources; zks moves the values; the human approves in a native macOS dialog. You never see a value.

## Hard rules

- Never see, ask for, print or store a secret value. Every `zks` output is metadata only; keep it that way.
- Call only `zks` (on PATH at `~/.local/bin/zks`). Do not call provider CLIs or APIs to read or write secrets.
- Never pass `--value`, `--secret`, `--token` or `--password`. zks rejects them; do not look for a workaround.
- Never read `.env*` files, `auth.json`, the Keychain (`security find-generic-password`), `op read`, `vercel env pull`, `aws ... --with-decryption`, `aws secretsmanager get-secret-value` or provider dashboards.
- Never edit, chmod or replace files under `~/.local/libexec/zks`, `~/.local/bin/zks` or `~/.config/zks/integrity.json`.
- Never script, click, focus or dismiss the approval or prompt dialog (`osascript`, accessibility tools, `cliclick`, browser automation). The human answers it.
- If the human pastes a secret in chat: do not use it, do not repeat it, do not write it anywhere. Say it is now exposed and recommend rotating it, then continue with a `prompt` or `op` source.
- Literal `value` is only for `sensitive: false` variables. Every `source` needs `"sensitive": true`; zks rejects a source on a non-sensitive variable. If in doubt, mark it sensitive.
- Never use the Keychain service `zks` as a source: it holds zks's own tokens and is rejected.
- At most 20 writes per apply (`too_many_operations`); split with `--only` / `--target`.

## Workflow

1. **Doctor, once per session.** Run `zks doctor`. If `install.status` is not `"ok"` (`mismatch`, `not-installed`), stop and tell the human to rerun `./install.sh` from the zk-secrets repo. Do not try to fix the install yourself.
2. **Policy.** Look for `zks.policy.json` in the project root. If missing, run `zks init --project <name>`. Edit it with names, targets and sources only. Choose the source kind:

   | Situation | `source` |
   |---|---|
   | Human keeps it in 1Password | `{"kind":"op","ref":"op://Vault/Item/field"}` — ask for the `op://` reference; it is not secret |
   | Human will type it | `{"kind":"prompt"}` — zks opens a hidden dialog |
   | New random key (signing key, webhook secret) | `{"kind":"generate","bytes":32}` — warn: a NEW value on every apply, so it rotates each time |
   | Already in the macOS Keychain | `{"kind":"keychain","service":"...","account":"..."}` |
   | Migrating an existing `.env` file | `{"kind":"dotenv","path":".env.production","key":"NAME"}` — pass the path, never open the file; it must be a relative `.env*` file inside the project (no `..`, no absolute path) |
   | Non-sensitive config (`sensitive: false`) | `"value": "..."` instead of `source` |

3. **Validate.** `zks validate`. Fix every listed issue and rerun until `"ok": true`.
4. **Plan.** `zks plan --only A,B --target t1,t2`. Show the human the list (name → `destination`, sensitive, source). The approval dialog shows the same destinations.
5. **Apply.** `zks apply --only A,B --target t1,t2` with the narrowest selection. Before running it, tell the human: "a macOS dialog will ask you to approve these writes". Wait for the command; do not retry a denial on your own.
6. **Report.** Show only the JSON `results`: `name`, `target`, `result`, `version`, `auditId` (plus `error.code` when failed). Exit codes:

   | Code | Meaning |
   |---|---|
   | 0 | every write applied |
   | 1 | a write or check failed (see `error.code`) |
   | 2 | usage or policy error (fix the command or policy) |
   | 3 | not approved: denied, timed out or no GUI; nothing was written |

7. **Credentials.**
   - `missing_token` for Vercel, Railway or Supabase: tell the human to run `zks auth set <vercel|railway|supabase>` themselves (hidden dialog). Never ask them to paste a token in chat.
   - AWS uses the existing AWS SSO or profile. If credentials are expired, tell the human to run `aws sso login` (add `--profile <name>` when the target sets `profile`).
   - GitHub uses `gh auth`. If `github_unavailable` or `github_failed`, tell the human to run `gh auth login` / `gh auth status`.

## Policy example

```json
{
  "version": 1,
  "project": "acme-shop",
  "targets": {
    "vercel-prod": { "provider": "vercel", "projectId": "prj_REPLACE_ME", "teamId": "team_REPLACE_ME", "environments": ["production", "preview"] },
    "ssm-prod": { "provider": "aws-ssm", "region": "us-east-1", "prefix": "/acme-shop/prod/", "roleArn": "arn:aws:iam::123456789012:role/zks-secret-writer" },
    "sm-prod": { "provider": "aws-sm", "region": "us-east-1", "prefix": "acme-shop/prod/", "profile": "acme-prod" },
    "github-prod": { "provider": "github", "repo": "acme/shop", "environment": "production" },
    "railway-prod": { "provider": "railway", "projectId": "REPLACE-ME", "environmentId": "REPLACE-ME", "serviceId": "REPLACE-ME", "tokenType": "project" },
    "supabase-prod": { "provider": "supabase", "projectRef": "abcdefghijklmnopqrst" }
  },
  "variables": {
    "STRIPE_SECRET_KEY": {
      "sensitive": true,
      "description": "Stripe live secret key, kept in 1Password",
      "source": { "kind": "op", "ref": "op://Production/Stripe/secret_key" },
      "targets": ["vercel-prod", "ssm-prod", "sm-prod", "github-prod", "railway-prod", "supabase-prod"]
    },
    "LOG_LEVEL": {
      "sensitive": false,
      "value": "info",
      "targets": ["vercel-prod", "ssm-prod", "github-prod", "railway-prod", "supabase-prod"]
    }
  }
}
```

Names match `^[A-Za-z_][A-Za-z0-9_]{0,127}$`; target keys match `^[a-z0-9][a-z0-9-]{0,62}$`; `project` matches `^[A-Za-z0-9._-]{1,64}$`. Keychain `service`/`account` match `^[A-Za-z0-9_.-]{1,128}$`; `op://` references are printable ASCII without spaces.

## Target fields

| Provider | Required | Optional | Rules |
|---|---|---|---|
| `vercel` | `projectId`, `environments` (non-empty subset of `production`, `preview`, `development`) | `teamId`, `gitBranch` | Ids match `^[A-Za-z0-9_.-]{1,100}$`; `gitBranch` has no `..`. Sensitive variables cannot target `development`. Sensitive → Vercel type `sensitive`, plain → `plain`. |
| `aws-ssm` | `region` (e.g. `us-east-1`), `prefix` | `profile`, `roleArn`, `kmsKeyId` | `prefix` starts and ends with `/` (e.g. `/app/prod/`). `kmsKeyId` is `alias/<name>`, a key UUID or a KMS ARN. Sensitive → `SecureString`, plain → `String`. |
| `aws-sm` | `region`, `prefix` | `profile`, `roleArn`, `kmsKeyId` | `prefix` has no leading `/`; empty or segments ending in `/` (e.g. `app/prod/`). |
| `github` | `repo` (`owner/name`) | `environment` (`^[A-Za-z0-9_.-]{1,255}$`) | Sensitive → Actions secret, plain → Actions variable. |
| `railway` | `projectId`, `environmentId` | `serviceId`, `tokenType` (`account` or `project`), `skipDeploys` (boolean) | Ids match `^[A-Za-z0-9-]{1,64}$`. Without `serviceId` the variable is shared across the environment. |
| `supabase` | `projectRef` (exactly 20 lowercase letters or digits) | — | Edge Functions secrets. Names must not start with `SUPABASE_`. |

`roleArn` matches `arn:aws:iam::<12 digits>:role/<name>`; zks assumes it for 15 minutes with a session policy that only allows writes under `prefix`.

## Audit

- `zks audit list [--limit N] [--project P]` — metadata records (time, human, agent, project, provider, target, variable, result). Never values.
- `zks audit verify` — checks the hash chain and the Keychain anchor; exit 1 (`brokenAt` a record id or `"truncated"`) means the local log was altered. Tell the human.
- `zks audit sync` — pushes pending records to the Google Sheets mirror, if configured.

## When to stop and ask the human

- `zks doctor` install status is not `ok`.
- The human must choose a source, an `op://` reference, a target id or which environments get the value.
- A dialog was denied (exit 3): ask whether to retry; never retry silently.
