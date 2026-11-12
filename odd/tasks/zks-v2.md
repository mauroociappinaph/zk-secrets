# zks v2 — security hardening, lifecycle, new sinks, capture backends, DX

Feature: 20 items chosen by the user from the 100-item improvement list (items 3, 5, 6 dropped by the user). Delivered in five phases, one branch per phase stacked on `develop`; push and PRs are the user's decision.
Branches: `feature/zks-v2-security` (P1) → `feature/zks-v2-lifecycle` (P2) → `feature/zks-v2-sinks` (P3) → `feature/zks-v2-capture` (P4) → `feature/zks-v2-dx` (P5).

## Specs

Each spec quotes the list item the user selected by number, then the user's decision when one was taken (L2). Every spec keeps the v1 guarantees of `odd/tasks/zks.md` S1 (no value in argv, env, stdout, stderr, temp files or audit) and S5 (no write to a new destination without the native approval dialog).

### P1 — security

- S1 (item 7) — "**Integridad que no se pueda pisar**: instalar en `/usr/local/libexec/zks` como root, para que el usuario no pueda modificarlo." Decision: "install.sh --system (Recomendado)" — `install.sh --system` is prepared and tested; the user runs it once with sudo; the user-level install keeps working.
- S2 (item 8) — "**Fijar las versiones de `gh` y `op`** por hash del binario, no solo por ruta, y avisar si cambian."
- S3 (item 19) — "**Capture en un perfil de ego aislado**, sin la sesión del agente, para cerrar la ventana donde el token queda visible."
- S4 (item 98) — "**SBOM y auditoría de dependencias** (npm audit, socket.dev), con lockfile fijado."

### P2 — lifecycle

- S5 (item 46) — "**Generadores con formato**: UUID, JWT secret, par de claves RSA/Ed25519, password con reglas."
- S6 (item 47) — "**Derivados**: `DATABASE_URL` armado a partir de user, password y host, todo en memoria."
- S7 (item 51) — "★ **`zks rotate NAME`**: generar uno nuevo, escribirlo en todos los destinos y revocar el viejo en el proveedor." Decision: "Regenerar y escribir (Recomendado)" — generates a new value and writes it to all its destinations with approval; it revokes nothing at the origin provider.
- S8 (item 52) — "★ **Inventario**: `zks inventory` lista qué secreto está en qué destino y su antigüedad, solo metadata."
- S9 (item 57) — "**Plan con efectos**: mostrar qué deploys se disparan (Vercel redeploy)."
- S10 (item 81) — "**`zks doctor --fix`** para lo reparable."

### P3 — sinks

- S11 (item 28) — "**Netlify** env."
- S12 (item 40) — "**Docker / Compose** secrets."
- S13 (item 41) — "**Archivo `.env` local con permisos 600** (ya existe dotenv como fuente; sumarlo como destino con aprobación)."

### P4 — capture

- S14 (item 63) — "★ **Recetas por proveedor**: `zks capture recipe vercel-token`, con selectores conocidos mantenidos en el repo."
- S15 (item 65) — "**Soporte de Playwright/Chrome** además de ego-browser."
- S16 (item 66) — "**Leer tokens que se descargan como archivo** (JSON de service account de GCP)."
- S17 (item 67) — "**Leer tokens dentro de un modal o shadow DOM**."

### P5 — DX

- S18 (item 83) — "★ **Servidor MCP de zks**: tools `plan`, `apply` y `capture` con el mismo gate, así cualquier agente lo usa sin shell."
- S19 (item 84) — "**`zks init --detect`**: lee `.env.example`, `vercel.json` y `railway.toml` y arma el policy."

## Tasks

- T1 [S2] pin gh/op/ego-browser binaries by sha256 in tools.json; refuse and warn on change — P1 — inline — 42ccc92 — done
- T2 [S1] `install.sh --system` root-owned install under /usr/local/libexec/zks — P1 — inline — 5429b77 — done (launcher in /usr/local/libexec/zks/bin: /usr/local/bin is uid 501 here)
- T3 [S3] capture in an isolated ego-browser profile/space — P1 — worker — 73bbc31 — done (page p1 confirmed against real ego; isolated flow not run against a real second profile)
- T4 [S4] SBOM, npm audit in install/CI, pinned lockfile check — P1 — inline — 464388e — done (socket.dev skipped: needs account+token)
- T5 [S5,S6] formatted generators and derived sources — P2 — worker — e77fbb4 — done (one ~975-line commit: generators and derived sources share the resolver; selection rule for derived values added)
- T6 [S7] `zks rotate NAME` — P2 — worker — 7ae4f28 — done
- T7 [S8] `zks inventory` — P2 — worker — 7ae4f28 — done
- T8 [S9] plan effects — P2 — worker — 7ae4f28 — done
- T9 [S10] `zks doctor --fix` — P2 — worker — 7ae4f28 — done
- T10 [S11] Netlify sink — P3 — pending
- T11 [S12] Docker Swarm / Compose secret sinks — P3 — pending
- T12 [S13] dotenv file sink (mode 600) — P3 — pending
- T13 [S14] capture recipes — P4 — pending
- T14 [S15] Playwright/Chrome capture backend — P4 — pending
- T15 [S16] capture from a downloaded file — P4 — pending
- T16 [S17] capture inside modals and shadow DOM — P4 — pending
- T17 [S18] `zks mcp` stdio server — P5 — pending
- T18 [S19] `zks init --detect` — P5 — pending

## Log

- L1 (user request, verbatim): "Hace el 6 , 7 , 8 , 19 , 28  , 40 , 41 , 46, 47 , 57, 65, 66 , 67,  , 81 , 84 , 3 , 5 , 98 ,  , 51 52 83 y 63"
- L2 (user decisions): items 3, 5, 6 — "Sacar 3, 5 y 6" (no Developer ID signing identity on this Mac: 0 valid codesigning identities). Item 7 — "install.sh --system (Recomendado)". Item 51 — "Regenerar y escribir (Recomendado)". Delivery — "Por fases, rama por fase (Recomendado)": 1 security (7, 8, 19, 98) → 2 lifecycle (46, 47, 51, 52, 57, 81) → 3 sinks (28, 40, 41) → 4 capture (63, 65, 66, 67) → 5 DX (83, 84); commits of about 400 lines.
- L3 (user, verbatim): "TOma el rol de cto y decidi todo vos sin preguntarme avisame cuando este terminado. COn un resumen de las nuevas funcionalidades y para que sirven y como se usan"
- L4 (CTO design decisions under L3; workers follow these unless the code proves one impossible, then report):
  - T3: ego-browser exposes `profiles()` (here only `[{"id":"Default","isDefault":true}]`) and `taskSpace(name, { profileId })` for new spaces, `task.finish({ keep: [] })` to close. `zks config set capture-profile <profileId>` / `unset`; `zks capture read|fill --isolated --url URL ...` (excludes `--space/--page`): zks creates its own space `zks-capture-<random hex>` with that profile, goes to URL (its origin must equal `--origin`, mandatory with `--isolated`), runs the existing read/fill steps, and always `finish({ keep: [] })`. Errors: no profile configured → `isolated_profile_unset`; id not in `profiles()` → `isolated_profile_missing`; `isDefault` profile → `isolated_profile_not_isolated`; landing on another origin (login wall) → `login_required`. The user logs into providers once in that profile.
  - T5: `generate` gains `format`: `random` (today's bytes/encoding, default), `uuid` (v4), `jwt-secret` (64 bytes base64url), `password` (`length` 12-128 default 32, `lower|upper|digits|symbols` booleans default true, at least one char of each enabled class), `rsa-private-key` (`bits` 2048|3072|4096, PKCS8 PEM), `ed25519-private-key` (PKCS8 PEM). New source `{kind:"public-key", of:"VAR"}`: public PEM of another variable's private key, derived in memory; the only source allowed with `sensitive:false`. New source `{kind:"template", template:"postgres://${DB_USER}:${DB_PASSWORD:url}@${DB_HOST}/app"}`: `${NAME}` raw, `${NAME:url}` percent-encoded; references resolved once per apply in dependency order (a generated value is shared by its dependents); unknown reference or cycle → `invalid_policy`.
  - T6: `zks rotate NAME [--target t1,t2] [--policy FILE]`: only variables with a `generate` source, else `not_rotatable`; dependents (template/public-key referencing it) are rewritten in the same apply; always shows the approval dialog (trust does not skip it); audit action `rotate`. No revocation at the origin provider (L2).
  - T7: `zks inventory [--project P] [--policy FILE]`: metadata only, no network. From the audit log: latest applied record per (project, provider, target, variable) → `{variable, provider, target, environment, lastWrittenAt, ageDays, writes}`; policy entries never written → `status:"never_written"`; audit entries no longer in the policy → `status:"not_in_policy"`.
  - T8: every `plan` operation gets `effect` (vercel: applies on the next deployment, redeploy to use it now; railway: Railway redeploys the service; netlify: next build/deploy; github: next workflow run; aws-ssm/aws-sm: consumers read it on next fetch; supabase: Edge Functions on next invocation; dotenv: restart processes that read the file; docker-swarm: update services to use the new secret; compose: restart the stack) plus a `effects` summary grouped by effect. No network, no redeploy.
  - T9: `zks doctor --fix` repairs only: create `~/.config/zks` and `~/.local/state/zks` with 700; chmod `config.json`, `trust.json`, `audit.db` (+`-wal`, `-shm`) to 600. Never touches integrity, trust content, audit chain or Keychain; reports those as not fixable with the command to run. Output adds `fixed: [...]`.
  - T10: Netlify target `{provider:"netlify", accountId, siteId?, context:"all"|"production"|"deploy-preview"|"branch-deploy"|"dev"}` via `https://api.netlify.com/api/v1/accounts/{accountId}/env`, `is_secret:true` for sensitive; token in Keychain `zks/netlify`, capture pinned origin `https://app.netlify.com`.
  - T11: `docker-swarm` target: `docker secret create NAME -` (value on stdin), docker path + sha256 pinned in tools.json; existing secret → `secret_exists` unless `replace:true` (rm then create). `compose` target `{provider:"compose", dir}`: writes `<dir>/<NAME>` mode 600, dir 700, for compose `secrets: file:`; refuses symlinks; trust key is the absolute dir.
  - T12: `dotenv` target `{provider:"dotenv", path}`: upserts `KEY="value"` (escaped), preserves other lines, mode 600, atomic write via a 600 temp file in the same dir then rename; refuses symlinks; trust key is the absolute path.
  - T13: recipes in `src/capture/recipes.ts` (vercel-token, railway-token, supabase-token, netlify-token, github-token): `{origin, url, click?, selector, store}`; `zks capture recipe <name> (--isolated | --space ID --page LABEL)` and `zks capture recipes`. Selectors cannot be verified without logging in: each recipe carries `verified:false` until a real run, tested against HTML fixtures.
  - T14: backend interface in `src/capture/`; `--browser playwright` uses pinned `playwright-core` with system Chrome (`channel:"chrome"`) and a persistent profile `~/.local/state/zks/browser-profile` (700), headed, opened at `--url` (same flow as `--isolated`).
  - T15: `zks capture download --click SELECTOR --store S/A --origin O (--space/--page | --isolated --url)`: arms `waitForEvent("download")`, clicks, reads `download.path()` bytes (max 64 KiB) straight into `security -i` inside the script, then `download.delete()`; never `saveAs`.
  - T16: read/fill/blank resolve selectors through open shadow roots recursively (closes the L19 shadow-root advisory of v1); `--wait-visible` waits until the element is visible (modals opened by `--click`).
  - T17: `zks mcp`: hand-written stdio JSON-RPC 2.0 MCP server (no SDK dependency); tools `zks_plan`, `zks_apply`, `zks_capture_read`, `zks_capture_fill`, `zks_inventory`; each maps to `run([...argv], deps)` so the same gate, trust and redactor apply; input schemas have no value fields and `additionalProperties:false`.
  - T18: `zks init --detect`: reads `.env.example` names only (values never read into output), `vercel.json` → vercel target stub, `railway.toml|railway.json` → railway target stub; every variable `sensitive:true` with `{kind:"prompt"}`; refuses to overwrite an existing policy; prints what it detected.
- L5 (runtime): parent context backstop reached after T1/T2/T4; remaining tasks are delegated one worker at a time on the shared tree.
- L6 (incident, T3 worker): one run of test/isolated-capture.test.ts executed a generated capture script with the real /usr/bin/security and stored the test canary as login Keychain item app/key. Metadata (cdat 2026-11-12T15:14:11Z, created during the run) shows it did not pre-exist, so no user item was overwritten; the parent deleted it. Helper fixed by the worker to always swap in a fake security and assert the swap.
- L7 (P1 close): native assess for P1 (develop..feature/zks-v2-security, 1517 lines) returned reviewDue high_risk (install.sh, ci.yml). Native review needs the human's provider consent, which L3 does not grant; deferred to the end so the user answers once per phase candidate. P2 branched from P1.
- L8 (native review review-aa2f405c628ebf4d of P1, lenses risk+reliability): correction_required with R1-agents-symlink-root-chown (CRITICAL: --system wrote ~/AGENTS.md as root, following a user-planted symlink into a root-owned path) and R3-ownership-symlink-bin-links (CRITICAL: npm bin symlinks would make doctor report "ownership" on a correct system install). Both fixed (AGENTS update runs entirely as the user; production `npm ci --no-bin-links`). The correction capture could not be submitted: the facade loops between "intended untracked selection required" and "untracked inventory changed" while T5 work sat untracked in the tree (harness incident); the fix was committed as an ordinary commit and the lineage is left for a fresh review.
- L9 (user, verbatim): "Podes parar cuando la phase 2 este completa ?" — stop after P2 (T6-T9) is committed and reported; P3-P5 (T10-T18) stay pending.
- L10 (P2 close): T6-T9 in 7ae4f28 (one commit, ~900 lines). npm run check 233/233; smoke with the dev launcher on zks.policy.example.json: plan shows effects, inventory lists never_written entries, rotate of an unknown name is a usage error. Native review of P2 not run (stop requested in L9; RDD review needs the user's consent). Stopped here per L9; T10-T18 pending.
- L11 (independent verify mwdpvyo1-5-2cal, Risk item 2/5): no blocker reproduced; S2,S3,S5-S10 met; S1,S4 partial. Possible S1 blocker (root npm ci using the user's HOME/.npmrc/.npm) fixed: that step now runs under env -i with a private HOME, cache, logs and userconfig=/dev/null (checked: npm ci works that way, no .bin). Open advisories, not fixed: isolated fill can lose an existing item after an approved replace when the profile is refused (same pattern as v1 failed fills); rotate --target leaves dependents on other targets stale; Homebrew node dylibs under user-writable /opt/homebrew (not the case on this machine); root copies the user repo; /usr/local/bin shadowing; doctor --fix O_RDONLY on mode 0200 files; CI actions pinned by tag. Unverified: sudo HOME behaviour, real sudo install, real CI, isolated capture with a second profile.
- L12 (user, verbatim): "avisame cuando esos dos puntos esten cerrados" — read as the two open advisories of L11 the parent offered to fix: (1) a failed fill after an approved replacement loses the old Keychain value; (2) rotate --target leaves dependents on other targets stale. CTO decisions: (1) before replacing an existing item, zks reads the old value into a SecretBuffer and restores it if the capture/fill does not succeed, for isolated and non-isolated fills (zero-knowledge kept: memory only, zeroed); (2) rotate refuses with `dependents_outside_selection` (exit 2, nothing written, audited failed) when a dependent of NAME has a target outside the selected --target set, naming the dependents and their targets; rerun without --target or include them.
- L13 (verify mwdq83ew-6-jf6a of 7ff01ab): S1 unmet — B1: npm ran under whatever node SAFE_PATH found (v20 /usr/local/bin/node here, exit 127 when none); A1: global npmrc still read. Fixed: the step runs "$NODE_BIN" "<npm-cli.js realpath>" with PATH=$(dirname NODE_BIN):SAFE_PATH and an empty private globalconfig; behavioural test runs the real install.sh step against a fake node; reproduced the real step under env -i (exit 0, 0 vulnerabilities, no .bin). README documents that root still executes the user's node/npm files (same-user limit). Scratch /tmp/zv.SV2UzJ removed.
- L14 (verify mwdqv6dt-8-4ouz of d05ad76): S7 met; S3 restore logic met with fakes; U1 confirmed on the real tool by the parent with a throwaway item: `security find-generic-password -w` prints non-printable values (non-ASCII, quotes, backslash, newline) as hex, indistinguishable from a literal hex value — a v1 bug affecting every Keychain read (keychain sources, capture fill --from, and the new restore). Fixed: keychain.get and the in-script fill read parse `-g` stderr (`password: "text"` or `password: 0xHEX`), fail closed on anything else; round-trip of contraseña, abc"d\\e, deadbeef, 'a b' and 'x\ny' through the real Keychain is exact (probe item zks-probe-u1 removed). U2 (ego script still running after a client timeout) stays unverified. Verifier scratch dirs removed.
- L15 (verify mwdr437i-9-wnly of a5533ee): keychain.ts parse met against 27 real throwaway items (empty password prints 'password: ', quotes never force hex, attributes go to stdout). Blocker B1: the in-script hex regex lost its \\s inside the BODY template literal, so fill --from of any non-printable value failed closed with keychain_failed. Fixed (\\\\s in BODY) with the verifier's regression tests (hex -g fill round-trip, generated script keeps \\s) and real -g shape tests; securityG fixture corrected. 250/250.
- L16 (verify mwdra4nc-a-1bi6 of 3bac3d8): \\s fix met against 14 real throwaway items; blocker B1: a non-UTF-8 item (0x61FF) was typed as a U+FFFD string with ok. Fixed with a fatal TextDecoder (fail closed, keychain_failed) and the verifier's regression test (RED then GREEN); 251/251. Advisory left: keychain.get returns raw bytes but sinks decode values as UTF-8, so a non-UTF-8 Keychain source would be sent lossy (pre-existing v1 behaviour).
