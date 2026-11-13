# zks 0.7.0 — find every place a key lives, and check none was left behind

Feature: the user's rotation risk "olvidarse de un lugar" (L1). Branch `feat/v0.7.0` from `main` (74eaaed). The user delegated every decision (CTO role).

## Specs

Every spec keeps the v1 guarantees of `odd/tasks/zks.md` S1 (no value in argv, env, stdout, stderr, temp files or audit): both commands are read-only, metadata only, never print a matched line or a value, and open no dialog.

- S1 — "`zks where NOMBRE`: busca en el proyecto **solo el nombre** de la llave, nunca el valor, en workflows de GitHub, `docker-compose`, `railway.toml`, `vercel.json`, `.env.example`, scripts y código. Te devuelve dos listas: ✅ 'lugares que zks ya maneja' y ⚠️ '**lugares que usan esta llave y zks no conoce**'". Decisions (L3):
  - NAME must match the policy variable-name rule; it need not be in the policy (then every reference is unmanaged).
  - Files: `git ls-files --cached --others --exclude-standard` when cwd is in a Git work tree, else a walk of cwd; always skipping `node_modules`, `.git`, `dist`, `build`, symlinks, files over 1 MiB and binary files (NUL byte); at most 20,000 files. Whole-word match of NAME (`[A-Za-z0-9_]` boundaries).
  - Each reference: `{path, line, kind}` with kind one of `github-workflow` (`.github/workflows/*.y*ml`), `compose` (`*compose*.y*ml`), `dockerfile`, `railway` (`railway.toml|json`), `vercel` (`vercel.json`), `netlify` (`netlify.toml`), `dotenv` (dotenv files: names starting with `.env`), `ci-other` (other CI configs such as `.gitlab-ci.yml`, `bitbucket-pipelines.yml`, `.circleci/**`), `script` (`*.sh`, `Makefile`, `package.json`), `code` (anything else). Never the line text.
  - A reference is `managed` when a policy target of NAME covers it: `github-workflow` ↔ a `github` target; `compose`/`dockerfile` ↔ `compose` or `docker-swarm`; `railway` ↔ `railway`; `vercel` ↔ `vercel`; `netlify` ↔ `netlify`; `dotenv` ↔ a `dotenv` target with that exact path (dotenv template files whose name ends in `.example`, `.sample` or `.template` are templates: `managed: true` when NAME is in the policy at all). `code` and `script` references are consumers, reported in `consumers`, not as unmanaged destinations.
  - Output: `{ok, name, inPolicy, targets: [policy targets of NAME with provider], managed: [...refs], unmanaged: [...refs], consumers: [...refs], scanned: <files>, truncated: bool}`; exit 0 on a successful scan (unmanaged entries are a finding, not an error).
- S2 — "`zks rotate --check`: después de rotar, le pregunta a cada destino ... **la fecha de su última actualización**, nunca el valor, y te marca cuál quedó con la versión vieja." Command `zks rotate NAME --check`: no generation, no write, no dialog. For every operation the rotate would write (NAME and its derived variables), read the destination's last-modified time through the provider API (metadata only) and compare with the latest applied audit write of that operation:
  - `current` when the provider time is at or after that audit write minus 120 s; `stale` when older; `missing` when the destination has no such variable; `unknown` when the provider exposes no timestamp, there is no audit write, or the call fails (with `reason`).
  - Providers: vercel (env `updatedAt`), github (secret/variable `updated_at`), aws-ssm (`LastModifiedDate`), aws-sm (`LastChangedDate`), netlify (`updated_at` if present), dotenv and compose (file mtime). railway, supabase, docker-swarm: `unknown` unless their API gives a timestamp.
  - Output `{ok, name, checks: [{variable, target, provider, destination, status, providerTime?, lastWrite?, reason?}]}`; exit 0 when every check is `current`, 1 otherwise. Not audited (read-only); it may read provider tokens like apply does.
  - `--check` is also accepted for a non-generated variable (checks its destinations after a manual renew).
- S3 — help, README, docs, skill (agents: run `zks where NAME` before any rotation or renew and `zks rotate NAME --check` after; tell the human every unmanaged place), CHANGELOG; version 0.7.0.

## Tasks

- [ ] T1 — S1: `zks where` + tests + docs (worker) — commit: pending
- [ ] T2 — S2: `zks rotate --check` + tests + docs (worker) — commit: pending
- [ ] T3 — S3: CHANGELOG, version, verify, PR, merge, install (parent) — commit: pending

## Log

- L1 (user): "Riesgo: olvidarse de un lugar. La auditoría contó que las claves viven en seis lugares, y no tengo confirmada la lista exacta de cuáles usan estas en particular. Si queda uno con la llave vieja, esa parte deja de funcionar hasta corregirla. La candidata más probable es la copia de seguridad, que tiene su propio acceso a la base.  zks podemos crear una solucion para este problema ?"
- L2 (user choice): "Las dos (recomendado)" — `zks where NOMBRE` and `zks rotate --check`.
- L3 (decision, CTO): never print matched lines (a dotenv line holds the value); code/script references are consumers; 120 s clock tolerance; read-only, no dialog.
