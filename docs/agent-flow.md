# Agent flow

How an agent sets a secret with zks, step by step. The agent handles names, targets, sources and every browser step (creating tokens and API keys, verification mail); zks handles values; the human only approves a dialog for a new destination and solves captchas or 2FA. The skill in [`skill/SKILL.md`](../skill/SKILL.md) is the instruction set agents follow.

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
  │◀════════ native dialog: NAME -> destination … [Deny/Once/Always] ═══│               │
  │═════════ Approve once ═════════════════════════════▶│                              │
  │                       │                             │ resolve value (op/keychain/  │
  │                       │                             │ prompt/generate/dotenv)      │
  │                       │                             │── value over HTTPS ─────────▶│
  │                       │                             │◀── version / status ─────────│
  │                       │                             │ audit append, zero buffer,   │
  │                       │                             │ mirror sync                  │
  │                       │◀── JSON results (exit 0/1/3)│                              │
  │  6. name, target,     │                             │                              │
  │  result, version,     │                             │                              │
  │  auditId              │                             │                              │
  │◀──────────────────────│                             │                              │

═══ = human-only channel the agent cannot read or drive. When every destination of the apply is
already trusted ("Always allow" earlier), there is no dialog and the result says `"approval": "trusted"`.
```

Branches:

- **Exit 2** (usage or policy): the agent fixes the policy or command and repeats from step 3. `too_many_operations` means more than 20 writes: split the apply with `--only` / `--target`.
- **Exit 3** (not approved): nothing was written. The agent asks the human whether to retry; it never retries on its own.
- **Exit 1 with `missing_token`**: the agent creates the token on the provider site in ego-browser and runs `zks capture read --store zks/<provider> --origin <pinned origin>` (see [Capture sequence](#capture-sequence)), then repeats the apply. It never asks the human for the token.
- **Exit 2 with `dialog_too_long`**: a line over 300 characters or a dialog over 6000; narrow with `--only` / `--target`.
- **AWS credentials expired**: the agent runs `aws sso login`; the human only completes a sign-in or 2FA step if the browser asks. **GitHub `missing_token`**: the agent runs `gh auth login --web` and finishes it in ego-browser; zks reads that session's token with `gh auth token` and calls `api.github.com` itself.
- **`trust: "invalid"`** in the output: `~/.config/zks/trust.json` was altered or unsigned, so nothing is trusted and every write asks again. Tell the human.
- **A secret pasted into chat**: the agent does not use it and recommends rotating it.
- **A command needs secrets** (tests, a migration): the agent runs `zks run --only A,B -- <command>` instead of reading `.env` files or pulling values. The dialog opens every time and shows the command, its arguments, the directory and the names; the values go only into that command's environment, and zks exits with its exit code (a denial is the `not_approved` JSON on stdout, exit 3). Generated variables are skipped unless named, and naming one is a usage error.

## Capture sequence

How the agent gets a token from a web page without seeing it (`zks capture read`). `fill` (always with `--origin`) reads the Keychain item inside the script instead, then sets one `<input type="password">` of the main frame in a single `page.evaluate` that re-checks the origin; anything else is `not_password_field`. `fill --from` is silent only into the origin the item was captured or generated from; any other origin opens a "Fill <service>/<account> into <origin>?" dialog.

```text
Agent                      ego-browser page              zks                          macOS Keychain
  │ open token page,         │                             │                              │
  │ snapshot (no secret yet),│                             │                              │
  │ fill name/expiry/scope   │                             │                              │
  │─────────────────────────▶│                             │                              │
  │ zks capture read --space 7 --page p1 --click <create> --selector <token> --store zks/vercel --origin https://vercel.com
  │───────────────────────────────────────────────────────▶│ validate, pinned origin,     │
  │                          │                             │ replace? ═ approval dialog ═ human
  │                          │◀── own script on stdin of `ego-browser nodejs` ────────────│
  │                          │  origin check               │                              │
  │                          │  click <create> (reveal)    │                              │
  │                          │  wait for <token>, re-check origin                         │
  │                          │  take value + blank element │                              │
  │                          │  security -i (stdin, hex) ─────────────────────────────────▶│
  │                          │  goto about:blank           │                              │
  │                          │── ZKS_RESULT {"ok":true,"length":N} ─▶│ parse one line only,  │
  │                          │                             │ audit (keychain/capture)     │
  │◀──────────── {ok, command, mode, store, origin, length, auditId} ─│                    │
```

The agent never snapshots, screenshots or evaluates the page between the reveal and `about:blank`, nor after a fill, while a secret may be shown; zks does the reveal click itself. Once the click was attempted, zks sends the page to `about:blank` on every outcome, so on `not_found` after a reveal the agent reopens the token list without looking, deletes the orphan token by name and retries with another selector. One-time e-mail verification codes are not captured: the agent types them with normal ego actions.

## Login sequence

How the agent logs a browser into a website with a stored password (`zks capture login`). The username is a plain flag; the password stays in the Keychain item `--from`.

```text
Agent                      ego-browser page              zks                          macOS Keychain
  │ zks capture login --recipe hostgator --user me@example.com --from hostgator/password --isolated
  │───────────────────────────────────────────────────────▶│ validate, item exists        │
  │◀════════ native dialog every time: origin, page, user, item, browser [Deny/Approve] ═══ human
  │                          │◀── own script on stdin of `ego-browser nodejs` ────────────│
  │                          │  goto --url, origin check   │                              │
  │                          │  set user field (username)  │                              │
  │                          │  focus password, re-check origin                           │
  │                          │  security find-generic-password ───────────────────────────▶│
  │                          │  type it (keyboard), confirm│                              │
  │                          │  click submit, settle ≤ 15 s│                              │
  │                          │── ZKS_RESULT {ok, loggedIn, finalOrigin, pending?} ─▶│ audit (origin, item)
  │◀── {ok, mode: "login", origin, from, loggedIn, finalOrigin, pending?, space?, page?, auditId} ─│
```

Branches: `loggedIn: true` → continue. `pending: "2fa" | "captcha"` (exit 0) → the agent stops and the human finishes the step in the browser; with `--isolated` the page stays open in the capture profile and `space`/`page` name it. A pending result never leaves the typed password in the field, and a captcha or code input already on the login page before the submit does not count as pending. `pending: "unknown"` → the login did not go through; the agent reports it. `login_redirected` (exit 1) → the page left the origin; only `finalOrigin` is reported. Exit 3 → denied, nothing was read.

## Which source kind

| The human says… | Source | Policy snippet | Note |
|---|---|---|---|
| "It's in 1Password" | `op` | `{"kind":"op","ref":"op://Vault/Item/field"}` | Ask for the reference; it is not secret |
| "Get a key from <site>" | capture, then `keychain` | `{"kind":"keychain","service":"svc","account":"key"}` | The agent registers and runs `zks capture read --store svc/key` first |
| "The site gave me a key file" (Google `.json`, Apple `.p8`) | capture, then `keychain` | `{"kind":"keychain","service":"svc","account":"key"}` | `zks capture file --store svc/key <path>` (the file must be in `~/Downloads` or the project); it asks, stores the file and deletes it. Never open, `cat` or move the file yourself |
| "I'll type it" | `prompt` | `{"kind":"prompt"}` | Hidden macOS dialog during apply |
| "I already have it copied" | `clipboard` | `{"kind":"clipboard"}` | Read at apply; always asks, even for trusted destinations; the clipboard is cleared only if unchanged; or `zks capture clipboard --store svc/key` and then `keychain`. Never ask the human to copy it |
| "Make a new random key" | `generate` | `{"kind":"generate","bytes":32}` | New value on **every** apply: it rotates each time |
| "It's in my Keychain" | `keychain` | `{"kind":"keychain","service":"svc","account":"acct"}` | Item must exist; service `zks` is reserved |
| "It's in `.env.production`" | `dotenv` | `{"kind":"dotenv","path":".env.production","key":"NAME"}` | Relative `.env*` file inside the project; agent passes the path; only zks opens the file |
| "It's a public URL / log level" | literal | `"sensitive": false, "value": "info"` | Never for sensitive values |
| Not sure | ask | — | Default to `sensitive: true` and `prompt` |

Every row with a `source` needs `"sensitive": true`; zks rejects a source on a non-sensitive variable. Only a literal `value` can be `sensitive: false`.

The approval dialog and `zks plan` show each write's real destination (`destination`), for example `github acme/shop env production secret` or `aws-ssm us-east-1 /acme-shop/prod/NAME role arn:…`. `zks config set|unset sheets-webhook` also opens an approval dialog. The apply dialog marks writes to destinations that are not trusted yet with `[NEW destination]` and offers **Deny**, **Approve once** and **Always allow**; `zks trust list` shows what is trusted and `zks trust remove <key>` drops a destination.
