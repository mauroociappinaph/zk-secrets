# zks — zero-knowledge secrets CLI + agent skill

Feature: a trusted CLI (`zks`) plus a global Gentle Shell skill that lets an agent push secrets and env vars to cloud platforms without ever seeing their values, with a metadata-only audit log.
Repo: `mauroociappinaph/zk-secrets` (private), branches `main` and `develop`.

## Specs

- S1 — Zero knowledge for the agent: "el agente jamás debe ver, procesar ni almacenar los valores en texto plano de las claves secretas". Secret values never appear in zks stdout, stderr, argv, environment, temp files or the audit store. The CLI rejects any secret value passed on the command line or in the policy.
- S2 — Injection by reference / scoped tokens: "Utilizar credenciales ya autenticadas en el sistema (CLI de Vercel / AWS SDK con roles IAM) para aplicar los secretos directamente en los proveedores de la nube." Sources: 1Password reference, macOS Keychain, hidden human prompt, local CSPRNG generation, dotenv import (read by zks only). Provider tokens live in the macOS Keychain; AWS uses the SDK credential chain with optional AssumeRole + session policy.
- S3 — All platforms, including env vars: "Debe incluir todas las plataformas incluyendo variables de entorno". Targets: Vercel, AWS SSM Parameter Store, AWS Secrets Manager, GitHub Actions (secrets and variables), Railway, Supabase. Non-sensitive env vars may carry a literal value; sensitive ones never.
- S4 — Audit: "registrando únicamente metadatos (timestamp, proyecto, nombre de la variable, usuario/agente que lo solicitó), nunca el valor del secreto." Local append-only SQLite with hash chain (`zks audit list|verify|sync`), optional Google Sheets mirror via HMAC-signed Apps Script webhook.
- S5 — Human gate: every apply shows one native approval dialog listing name → target; denial or no GUI writes nothing and is audited as `denied`.
- S6 — Works in every Gentle Shell session on its own: "Debe funcionar en todas mis sesiones de gs para que lo haga solo." Global skill at `~/.agents/skills/zks-secrets/`, installed binary at `~/.local/bin/zks`, rule in `~/AGENTS.md`.
- S7 — Repo: "Crea el repo en maurociappinaph privado con rama main y develop".
- S8 — Structure: architecture doc, secure scripts, step-by-step agent flow (`README.md`, `docs/`, `skill/SKILL.md`).

## Tasks

- T1 [S1,S2,S5] core: policy schema, SecretBuffer, scrub, output, approval gate, sources, CLI `run` — inline — commit: pending
- T2 [S3] provider sinks: vercel, aws-ssm, aws-sm, github, railway, supabase — commit: pending
- T3 [S4] audit store, verify, Sheets mirror + Apps Script — commit: pending
- T4 [S1] canary tests through `run` — commit: pending
- T5 [S6,S8] install script, skill, docs, AGENTS.md rule, CI — commit: pending
- T6 [S7] GitHub private repo, main + develop pushed — commit: pending

## Log

- L1 (user, original request): "Actúa como arquitecto de software y experto en seguridad. Quiero diseñar y programar una Agent Skill orientada a la automatización de despliegues y configuración de infraestructura (Vercel, AWS). La skill debe cumplir estrictamente con un modelo de privacidad y conocimiento cero para el agente y la máquina local: el agente jamás debe ver, procesar ni almacenar los valores en texto plano de las claves secretas. [...] Inyección por referencia o tokens con ámbito [...] Capa de auditoría (Backend / Google Sheets) [...] nunca el valor del secreto. Estructura: Define la arquitectura de la Skill, los scripts seguros necesarios (Node.js/Python) y el flujo paso a paso [...] Opción 2: Enfoque como Aplicación / CLI de Utilidad [...] Vercel, AWS Parameter Store, etc. [...] Integración opcional por detrás con Google Sheets [...]"
- L2 (user): "Decid todo vos. Debe funcionar en todas mis sesiones de gs para que lo haga solo. Debe incluir todas las plataformas incluyendo variables de entorno , etc . Crea el repo en maurociappinaph privado con rama main y develop"
- L3 (decision): GitHub account is `mauroociappinaph` (active gh login); repo `zk-secrets`. Node 22 + TypeScript, node:test, node:sqlite (no native deps). Branch flow: work on `feature/zks-core`, merge to `develop`, fast-forward `main` for v0.1.0.
