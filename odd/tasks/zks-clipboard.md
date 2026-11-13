# zks clipboard — clipboard source and `zks capture clipboard`

Feature: take a secret from the macOS clipboard, either as a policy source (so it can go to any sink, GitHub Actions included) or into the Keychain with a capture command. Branch `feat/clipboard-source` from `main`; ships as 0.4.0. The user delegated every decision (L3).

## Specs

Every spec keeps the v1 guarantees of `odd/tasks/zks.md` S1 (no value in argv, env, stdout, stderr, temp files or audit) and S5 (no write to a new destination without the native approval dialog).

- S1 — "zks no puede tomar un valor desde el portapapeles" → policy source `{"kind":"clipboard"}`. zks reads it with `/usr/bin/pbpaste` (absolute path, no shell), drops one trailing `\n` or `\r\n`, and clears the clipboard with `/usr/bin/pbcopy` (empty stdin) right after reading. Empty clipboard → `source_missing` ("the clipboard is empty"); pbpaste missing or failing → `source_unavailable` / `source_failed`. The variable must be `sensitive: true` (existing rule). Only one variable per policy may use it (validation issue), since the first read clears the clipboard. `plan` and the dialog describe it as "the clipboard (cleared after reading)".
- S2 — "y que tambien funcione en github" → a clipboard-sourced variable applies to a `github` target like any other source: sealed with the repository public key, never sent in plaintext.
- S3 — capture command chosen in L2: `zks capture clipboard --store SERVICE/ACCOUNT` stores the clipboard into the Keychain item and clears the clipboard. Replacing an existing item needs the replace dialog; a denied replace reads nothing. Service `zks` is refused (usage error; provider tokens use `zks auth set` or `capture read` with the pinned origin). Empty clipboard → `clipboard_empty`, nothing written; pbpaste failure → `clipboard_unavailable`. A failed write puts the old value back (`restored: true`). Output reports `length` and `clipboardCleared`, never the value. Audited as `provider: "keychain"`, `action: "capture"`, `sourceKind: "capture-clipboard"`; it does not count as a page capture, so a later `fill --from` of that item always asks.
- S4 — help, README, docs, skill and CHANGELOG describe S1-S3; version 0.4.0.

## Tasks

- [ ] T1 — S1, S2: clipboard source, validation, describe, tests (inline) — commit: pending
- [ ] T2 — S3: `zks capture clipboard` + tests (inline) — commit: pending
- [ ] T3 — S4: help, docs, skill, CHANGELOG, version 0.4.0 (inline) — commit: pending

## Log

- L1 (user): "Podes hacer esto:  zks no puede tomar un valor desde el portapapeles   y que tambien funcione en github ?"
- L2 (user, choice): "Ambas cosas" — the policy source and the Keychain capture command.
- L3 (user): "Toma el rol de cto y toma todas las deciciones avisame cuando actualices la version con estas mejoras"
- L4 (decision): clipboard read and cleared through fixed `/usr/bin/pbpaste` / `/usr/bin/pbcopy`, like `/usr/bin/security`; not added to `tools.json` pins (system binaries under SIP). `zks` service refused for clipboard capture. One clipboard variable per policy.
