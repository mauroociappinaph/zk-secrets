---
name: zks-secrets
description: "Trigger: secretos, variables de entorno, env vars, API key, token, crear token, Vercel env, AWS SSM, Parameter Store, Secrets Manager, GitHub secrets, Railway variables, Supabase secrets, rotar clave, deploy config. Do every secrets step yourself with zks and zks capture, never seeing values."
---

# zks-secrets

Set secrets and env vars on Vercel, AWS SSM, AWS Secrets Manager, GitHub Actions, Railway and Supabase through the `zks` CLI, and obtain the tokens and API keys they need yourself with `zks capture` in ego-browser. You write names, targets, sources and browser steps; zks moves the values; the human only approves a native macOS dialog for a new destination. You never see a value.

## Do it yourself

The human does not do setup steps. Never tell them to create, copy or paste a token, open a dashboard, or run `zks auth set`, `security add-generic-password` or any other setup command. Do it with ego-browser (their logged-in sessions are authorized) and `zks capture`.

Ask the human **only** for:

- a captcha;
- 2FA, a passkey or a security key;
- a browser-owned prompt (permissions, device chooser) — call `task.handOff()`, say what to do, resume after;
- the zks approval dialog for a new destination, for replacing a Keychain item, or for filling a stored item into another origin than it came from.

### How `zks capture` keeps the value away from you

You drive the non-secret steps in one ego-browser TaskSpace (print its `spaceId` and page label). zks then runs its own `ego-browser nodejs` script on that page for the secret step:

- `zks capture read --space ID --page p1 --click <reveal button> --selector <token element> --store <service>/<account> --origin <origin>` — clicks the button, waits up to 15 s for the element to hold a value, moves it straight into the Keychain, blanks the element and navigates the page to `about:blank`.
- `zks capture fill --space ID --page p1 --selector <password input> --store <service>/<account> --generate 24 --origin <origin>` — zks generates a random password, stores it, and fills it into the input. `--from <service>/<account>` fills an existing item instead.
- `fill` only fills a password field: `--selector` must match exactly one `<input type="password">` in the page's main frame (not an iframe, a textarea or a text input), else `not_password_field` and nothing is filled.
- `fill --from` runs without a dialog only into the origin the item was captured or generated from. Any other origin (or an item zks never captured) opens "Fill <service>/<account> into <origin>?"; tell the human a dialog will ask and wait.
- `--click` takes any ego selector (CSS, `text=Create`, `loc=role:button[name='Create token']`). `--selector` must be plain CSS (it is read with `document.querySelectorAll` and must match exactly one element).
- Output is metadata: `{ok, command, mode, store, origin, length, auditId, mirror}`. Errors: `origin_mismatch`, `not_found`, `not_password_field`, `keychain_failed`, `browser_failed` (exit 1); usage errors exit 2; a denied replacement or fill exits 3.
- `--origin` (for example `https://api.example.com`) is mandatory for `fill`; always pass it for `read` too. zks checks the page is on it before clicking or reading, and again inside the fill itself.
- After a `--click`, zks leaves the page on `about:blank` whatever happens, success or failure.

### Flow A — missing provider token (`missing_token` for Vercel, Railway or Supabase)

| Provider | Token page | Store | `--origin` (pinned, mandatory) |
|---|---|---|---|
| Vercel | `https://vercel.com/account/settings/tokens` | `zks/vercel` | `https://vercel.com` |
| Railway | `https://railway.com/account/tokens` | `zks/railway` | `https://railway.com` |
| Supabase | `https://supabase.com/dashboard/account/tokens` | `zks/supabase` | `https://supabase.com` |

1. Open the token page in your TaskSpace. Take a snapshot **before** creating anything (no secret is shown yet).
2. Fill the form yourself: name `zks-<hostname>` (`hostname -s`), the shortest sensible expiry the provider offers (for example 30 or 90 days), scope limited to the team that owns the project.
3. Do not click the final create button. Run `zks capture read --space ID --page p1 --click "<create button>" --selector "<element that will show the token>" --store zks/<provider> --origin <pinned origin>`. The element usually lives in the dialog that opens, for example `[role=dialog] input[readonly]` or `[role=dialog] code`.
4. Check with `zks auth status`, then retry the apply.

### Flow B — third-party API key (a public data API, a SaaS)

1. Register in ego-browser with the user's logged-in identity (their e-mail, or "Sign in with Google" when offered).
2. Password field: `zks capture fill --space ID --page p1 --selector "#password" --store <svc>/password --generate 24 --origin <site origin>`; for a confirmation field, `zks capture fill ... --from <svc>/password --origin <site origin>` (same origin: no dialog). Log in later the same way with `--from` on the same origin. Do not snapshot, screenshot or evaluate the page after a fill: the field holds the password.
3. Verification mail: open the user's Gmail in ego-browser, open the message and click its link with `page.click`; do not print the link or the message body. If the mail holds a one-time verification code instead, it is not a secret to store: read it and type it into the site with normal ego actions (not with `zks capture`), then move on without repeating it.
4. Generate the key on the site and `zks capture read --click "<generate button>" --selector "<key element>" --store <svc>/<account> --origin <site origin>`.
5. Use it: a `{"kind":"keychain","service":"<svc>","account":"<account>"}` source in `zks.policy.json`, then `zks apply` to the trusted destinations.

### Flow C — local-only tools (an app that reads the Keychain itself)

Capture straight into the Keychain item the app expects. Example: a tool that reads `security find-generic-password -s mrm-indec -a indec -w` → register at the API site (Flow B), then `zks capture read --click "<generate>" --selector "<token>" --store mrm-indec/indec --origin https://api.indec.gob.ar`. No policy or apply is needed.

### When a capture fails

- `not_found` after the click revealed a token: do **not** snapshot or screenshot the page. Navigate it away (`page.goto` the token list), delete the orphan token by its name in the list, and retry with another `--selector`.
- `origin_mismatch`: the page is not where you expect (redirect, phishing, login wall). Snapshot it (no secret shown), fix the navigation, retry.
- `not_password_field`: nothing was filled. Snapshot the page, pick a selector for the one `<input type="password">` in the main frame, retry. Never fill a password into another kind of field.
- `browser_failed`: check the TaskSpace id and page label; do not open a new TaskSpace to recover.
- Exit 3 on a replacement or a `fill --from`: the human denied replacing an existing item or filling it into that origin. Ask before retrying.

## Hard rules

- Never see, ask for, print or store a secret value. Every `zks` output is metadata only; keep it that way.
- Never snapshot, screenshot, `page.evaluate`, `page.fetch`, read or print a page while a secret may be shown (a new token, an API key) or after a `zks capture fill` (the password field holds it). Let `zks capture --click` perform the reveal, every time. One-time e-mail verification codes are the exception: type them yourself with normal ego actions.
- Never print or read Keychain items (`security find-generic-password -w`, `security dump-keychain`). zks reads them itself.
- Call only `zks` for secret values. Do not call provider CLIs or APIs to read or write secrets.
- Never pass `--value`, `--secret`, `--token` or `--password`. zks rejects them; do not look for a workaround.
- Never read `.env*` files, `auth.json`, `op read`, `vercel env pull`, `aws ... --with-decryption`, `aws secretsmanager get-secret-value` or the secret views of provider dashboards.
- Never tell the human to run `zks auth set` or `security add-generic-password`; capture the token yourself (Flow A).
- Never edit, chmod or replace files under `~/.local/libexec/zks` (including `tools.json`), `~/.local/bin/zks` or `~/.config/zks/integrity.json`.
- Never script, click, focus or dismiss the zks approval or prompt dialog (`osascript`, accessibility tools, `cliclick`, browser automation). The human answers it.
- If the human pastes a secret in chat: do not use it, do not repeat it, do not write it anywhere. Say it is now exposed and recommend rotating it, then capture a new one yourself.
- Literal `value` is only for `sensitive: false` variables. Every `source` needs `"sensitive": true`; zks rejects a source on a non-sensitive variable. If in doubt, mark it sensitive.
- Never use the Keychain service `zks` as a source: it holds zks's own tokens and is rejected. `zks capture` writes it only for `vercel`, `railway`, `supabase` and `sheets-hmac`, from their pinned origins, and never fills from it.
- At most 20 writes per apply (`too_many_operations`), 300 characters per dialog line and 6000 per dialog (`dialog_too_long`); split with `--only` / `--target`.
- Never edit `~/.config/zks/trust.json` or read the `zks`/`trust-hmac` Keychain item. Only the human adds trust, with **Always allow** in the dialog; you may run `zks trust list` and `zks trust remove <key>`.

## Workflow

1. **Doctor, once per session.** Run `zks doctor`. If `install.status` is not `"ok"` (`mismatch`, `not-installed`), reinstall it yourself only from a clean checkout of the published code: `cd ~/dev/zk-secrets && git fetch origin && git status --porcelain` must be empty and `git rev-parse HEAD` must equal `git rev-parse origin/main`; then run `./install.sh`. Never edit the code to make doctor pass. If the checkout is not clean or HEAD differs, or status is `mismatch` right after a reinstall, stop and report it: that can mean tampering. `tools["ego-browser"]` must be `true` for `zks capture`.
2. **Policy.** Look for `zks.policy.json` in the project root. If missing, run `zks init --project <name>`. Edit it with names, targets and sources only. Choose the source kind:

   | Situation | `source` |
   |---|---|
   | The key comes from a website | capture it first (Flow B), then `{"kind":"keychain","service":"<svc>","account":"<account>"}` |
   | Human keeps it in 1Password | `{"kind":"op","ref":"op://Vault/Item/field"}` — the `op://` reference is not secret |
   | New random key (signing key, webhook secret) | `{"kind":"generate","bytes":32}` — warn: a NEW value on every apply, so it rotates each time |
   | Already in the macOS Keychain | `{"kind":"keychain","service":"...","account":"..."}` |
   | Migrating an existing `.env` file | `{"kind":"dotenv","path":".env.production","key":"NAME"}` — pass the path, never open the file; it must be a relative `.env*` file inside the project (no `..`, no absolute path) |
   | Only the human knows it and no site issues it | `{"kind":"prompt"}` — zks opens a hidden dialog |
   | Non-sensitive config (`sensitive: false`) | `"value": "..."` instead of `source` |

3. **Validate.** `zks validate`. Fix every listed issue and rerun until `"ok": true`.
4. **Plan.** `zks plan --only A,B --target t1,t2`. Show the human the list (name → `destination`, sensitive, source). The approval dialog shows the same destinations.
5. **Apply.** `zks apply --only A,B --target t1,t2` with the narrowest selection. Writes to destinations the human already trusted open no dialog (`"approval": "trusted"`). For a new destination, say "a macOS dialog will ask you to approve these writes" (Deny / Approve once / Always allow) and wait; do not retry a denial on your own. If the output has `trust: "invalid"`, tell the human the trust file was altered.
6. **Report.** Show only the JSON `results`: `name`, `target`, `result`, `version`, `auditId` (plus `error.code` when failed). Exit codes:

   | Code | Meaning |
   |---|---|
   | 0 | every write applied |
   | 1 | a write or check failed (see `error.code`) |
   | 2 | usage or policy error (fix the command or policy) |
   | 3 | not approved: denied, timed out or no GUI; nothing was written |

7. **Credentials.**
   - `missing_token` for Vercel, Railway or Supabase: Flow A. Never ask the human for the token.
   - AWS uses the existing AWS SSO or profile. If credentials are expired, run `aws sso login` (add `--profile <name>` when the target sets `profile`) yourself; the human only completes the browser sign-in or 2FA step if one appears.
   - GitHub: zks reads the `gh auth login` token with `gh auth token` and calls `api.github.com` itself. If `missing_token`, run `gh auth login --web` yourself and finish the device flow in ego-browser; `github_unavailable` means `gh` was not found at install time (install it with `brew install gh`, then reinstall zks as in step 1); `github_failed` carries the HTTP status (for example 403: the login lacks write access to the repo).

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
| `github` | `repo` (`owner/name`, at most 100 characters) | `environment` (`^[A-Za-z0-9_.-]{1,255}$`) | Sensitive → Actions secret, plain → Actions variable. |
| `railway` | `projectId`, `environmentId` | `serviceId`, `tokenType` (`account` or `project`), `skipDeploys` (boolean) | Ids match `^[A-Za-z0-9-]{1,64}$`. Without `serviceId` the variable is shared across the environment. |
| `supabase` | `projectRef` (exactly 20 lowercase letters or digits) | — | Edge Functions secrets. Names must not start with `SUPABASE_`. |

`roleArn` matches `arn:aws:iam::<12 digits>:role/<name>`; zks assumes it for 15 minutes with a session policy that only allows writes under `prefix`.

## Audit

- `zks audit list [--limit N] [--project P]` — metadata records (time, human, agent, project, provider, target, variable, result). Captures appear with `provider: "keychain"`, `action: "capture"`, `target: "<service>/<account>"` and the page origin. Never values.
- `zks audit verify` — checks the hash chain and the Keychain anchor; exit 1 (`brokenAt` a record id or `"truncated"`) means the local log was altered. Tell the human.
- `zks audit sync` — pushes pending records to the Google Sheets mirror, if configured.

## When to stop and ask the human

- A captcha, 2FA/passkey, browser-owned prompt, or a zks approval dialog is waiting (see "Do it yourself").
- `zks doctor` install status is not `ok`.
- The human must choose between real options you cannot infer: which project, team or environment gets the value, or which existing account to use.
- A dialog was denied (exit 3): ask whether to retry; never retry silently.
