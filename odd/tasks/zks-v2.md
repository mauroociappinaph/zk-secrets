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

- T1 [S2] pin gh/op/ego-browser binaries by sha256 in tools.json; refuse and warn on change — P1 — pending
- T2 [S1] `install.sh --system` root-owned install under /usr/local/libexec/zks — P1 — pending
- T3 [S3] capture in an isolated ego-browser profile/space — P1 — pending
- T4 [S4] SBOM, npm audit in install/CI, pinned lockfile check — P1 — pending
- T5 [S5,S6] formatted generators and derived sources — P2 — pending
- T6 [S7] `zks rotate NAME` — P2 — pending
- T7 [S8] `zks inventory` — P2 — pending
- T8 [S9] plan effects — P2 — pending
- T9 [S10] `zks doctor --fix` — P2 — pending
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
