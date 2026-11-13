# zks 0.6.0 — tell how to renew each old secret

Feature: `zks inventory` says, for each entry, how to replace its value. Branch `feat/v0.6.0` from `main` (bc3bcaf). The user delegated every decision (CTO role).

## Specs

- S1 — "que `inventory --older-than` te diga para cada clave **cómo cambiarla**: 'esta se rota con `zks rotate`' o 'esta hay que pedirla en stripe.com'". Every inventory entry of a policy variable gets a `renew` object (with or without `--older-than`), metadata only, never a value:
  - `generate` source: `{"how":"rotate","command":"zks rotate NAME"}`.
  - `template` or `public-key` derived (directly or transitively) from exactly one `generate` variable G: `{"how":"rotate","command":"zks rotate G"}`; derived from several, list the first in policy order and add `"also": [...]` with the others; derived from no generated variable: treat as the sources it depends on (`how: "source"`).
  - `keychain`: `{"how":"source","source":"keychain","step":"replace the Keychain item SERVICE/ACCOUNT with a new value from the provider (zks capture read or zks capture file)","then":"zks apply --only NAME"}`.
  - `op`: step "update REF in 1Password"; `dotenv`: step "update KEY in PATH"; `prompt`: step "get a new value from the provider; zks asks for it in a dialog"; `clipboard`: step "copy a new value from the provider"; each with `"then":"zks apply --only NAME"`.
  - literal values (`sensitive: false` with `value`): `{"how":"edit","step":"change the value in the policy","then":"zks apply --only NAME"}`.
  - entries `not_in_policy` (no variable in the current policy): no `renew` field.
  - zks never revokes the old value at the provider; every `renew` with `how: "source"` or `"rotate"` adds `"revoke":"delete the old value at the provider yourself"`.
- S2 — help, README `## Inventory`, skill and CHANGELOG describe S1; version 0.6.0.

## Tasks

- [x] T1 — S1, S2: renew hints + tests + docs (worker) — commit: 6f87035
- [ ] T2 — release: CHANGELOG, version, verify, PR, merge, install (parent) — commit: pending

## Log

- L2 (decision, CTO): accepted the worker's choices: a derived value with no generated dependency lists its sources in `from`; literal-only templates use `edit`; every source shape carries `source`.
- L1 (user, on "¿Te interesa?" about renew hints per key): "Dale"
