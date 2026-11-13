# zks 0.5.0 — capture file, old-secret report, 0.4.0 follow-ups

Feature: three items the user approved for 0.5.0 (L2). Branch `feat/v0.5.0` from `main` (cd78f0e). The user delegated every decision (CTO role, L1 of `odd/tasks/zks-clipboard.md`).

## Specs

Every spec keeps the v1 guarantees of `odd/tasks/zks.md` S1 (no value in argv, env, stdout, stderr, temp files or audit) and S5 (no write to a new destination without the native approval dialog).

- S1 — "toma un archivo de clave que bajaste, como el `.json` de Google o el `.p8` de Apple, lo guarda en el Keychain sin abrirlo y **borra el archivo**." Command: `zks capture file --store SERVICE/ACCOUNT PATH`. Decisions (L3):
  - PATH (relative to cwd or absolute) must resolve inside `~/Downloads` or the current project directory (cwd), after resolving symlinks of the parent directory; the file itself must not be a symlink, must be a regular file, non-empty, at most 64 KiB; anything else is `file_invalid` (exit 1), nothing read or deleted. A missing file is `file_not_found`. Messages never echo file contents; they may echo the path.
  - Always asks first with `deps.human.approve("zks: store a file", [...])` naming the full path, its size, the store, and that the file will be deleted; an existing item uses the replace wording in the same single dialog. Denial: exit 3, `not_approved`, audited `denied`, file untouched.
  - The bytes are stored exactly as read (no newline trimming) in the Keychain item; a failed write restores the previous item value (`restored: true`) or reports `restore_failed`, and the file is NOT deleted on any failure.
  - After a successful store the file is deleted (unlink). Output `{ok, command: "capture", mode: "file", store, length, fileDeleted, auditId, mirror}`; `fileDeleted: false` when unlink failed (still exit 0).
  - Audited `provider: "keychain"`, `action: "capture"`, `sourceKind: "capture-file"`, `environment: ""` (no path in the audit). Not a page capture: a later `fill --from` asks.
  - Service `zks` refused (exit 2).
- S2 — "`zks inventory --older-than 90d`: te lista qué claves tienen más de 90 días para que las cambies. Muestra solo nombres y fechas." `--older-than <N>d` with N an integer 1-3650 (anything else exit 2); keeps only entries whose last applied write is older than N days; entries never written are kept too (unknown age). Without the flag, output is unchanged. The output adds `olderThanDays: N` when the flag is given.
- S3 — 0.4.0 review follow-ups: (a) the clipboard compare-before-clear compares raw bytes (no string round trip), so a non-UTF-8 clipboard is cleared when unchanged; (b) command-level tests for a clipboard source through `zks run` (read after approval, never on denial, cleared on read) and `zks rotate` with a trusted destination (dialog shown); (c) fix the stale comment in `src/policy/types.ts` and the `describeSource` text so it no longer claims an unconditional clear.
- S4 — help, README, docs, skill and CHANGELOG describe S1-S3; version 0.5.0.

## Tasks

- [x] T1 — S1: `zks capture file` + tests + docs (worker) — commit: 617c4df
- [x] T2 — S2, S3: inventory --older-than, clipboard follow-ups + tests + docs (worker) — commit: 2495c5f
- [ ] T3 — S4: CHANGELOG, version 0.5.0, review, PR, merge, install (parent) — commit: pending

## Log

- L1 (user): "No importa que cambios me habias propuesto para una 0.5.0 version ?"
- L2 (user): "Ok hacelo" — accepting: capture file, inventory --older-than, and the three 0.4.0 follow-ups; `init --detect` left for 0.6.0.
- L7 (verify blocker + advisory, fixed): a cwd inside a hidden directory (`cd ~/.ssh`) reached the dialog; hidden directories are now also checked from home. Files with more than one hard link are `file_invalid`.
- L4 (decision, CTO, from the T1 worker's risk report): cwd is an allowed root only when strictly inside the home directory, and a path through any hidden directory is `file_invalid`; non-UTF-8 files are `file_invalid` (binary .p12 deferred: keychain.set stores strings); dialog_too_long and control-character PATH refusals accepted.
- L3 (decision, CTO): capture file is restricted to ~/Downloads or the project directory, always asks, never deletes on failure, 64 KiB limit; so an agent cannot stash and delete arbitrary files such as ~/.ssh keys.
