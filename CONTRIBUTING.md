# Contributing to zks

Thanks for helping. zks makes security promises, so every change has to keep them. This file explains how to propose a change and what a pull request needs before it can merge.

By taking part you agree to follow the [Code of Conduct](./CODE_OF_CONDUCT.md). **Report vulnerabilities privately** as [SECURITY.md](./SECURITY.md) describes, never in a public issue or pull request.

## How to propose a change

1. **Open an issue first** for any change in behaviour: a new command, option, source or destination, a different output or error, or a change to the dialog, trust or audit. Agree on the behaviour in the issue before you write code. Typos, docs fixes and small refactors that change no behaviour can go straight to a pull request.
2. **Fork** the repository.
3. **Branch from `develop`**, using a descriptive name such as `feat/netlify-site-scope` or `fix/dotenv-crlf`.
4. **Open the pull request against `develop`.** `main` only receives releases from `develop`.

`main` and `develop` are protected. A merge needs a pull request, an approving review and a green CI `check` job.

## Development setup

macOS is required: zks uses the macOS Keychain and native dialogs.

```sh
node --version        # >= 22.18
npm ci
npm run check         # typecheck + the full test suite
./install.sh          # builds, tests and installs ~/.local/bin/zks for a manual try
```

`npm run deps:check` and `npm run sbom` are the supply-chain checks that CI also runs. See [README.md → Development](./README.md#development).

## Rules

### Commits

- Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, with an optional scope (`fix(dotenv): ...`).
- Sign off every commit with `git commit -s`. This adds `Signed-off-by: Your Name <you@example.com>` and certifies the [Developer Certificate of Origin](https://developercertificate.org/). It is used instead of a CLA.
- Keep the tests, docs and code of one behaviour in **the same commit**, so every commit is coherent and can be reverted alone.
- Keep a pull request to roughly **400 changed lines**. Split anything larger into a stack of pull requests.
- Write code, comments, commit messages and docs in English.

### Tests first

- Write the test first and watch it fail (**RED**), then write the code that makes it pass (**GREEN**). Say in the pull request which tests were RED before your change.
- Write **one test per rule**. A test checks every observable effect of its rule (exit code, the exact JSON on stdout, stderr) through the CLI, and checks that a refused input writes nothing.
- When you change a command, option or message, update `zks help`, the README and the skill in the same commit.

### Security invariants (non-negotiable)

- **A secret value never appears** in argv, the environment, stdout, stderr, temp files or the audit log, whether in zks or in anything zks starts for its own work. This is v1 guarantee S1. Tests use canary values and assert that they do not show up.
- **Nothing is ever written to a new destination without the approval dialog** (v1 guarantee S5). A trusted destination may skip the dialog only through the existing HMAC-signed trust check, and `rotate` and `run` always ask.
- A pull request that touches `src/sinks`, `src/gate`, `src/capture`, `src/platform` or `install.sh` must include a **Threat-model impact** section: what it changes in the trust boundaries described in [docs/architecture.md](./docs/architecture.md), and an update to that document when the boundaries move.
- Do not weaken a documented guarantee to make a feature fit. Write down a new limit under "Honest limits" in the README, don't hide it.

## Reviews

- [`.github/CODEOWNERS`](./.github/CODEOWNERS) makes the maintainer ([@mauroociappinaph](https://github.com/mauroociappinaph)) the required reviewer for every path.
- The CI `check` job (typecheck, tests, `deps:check --strict`, `npm audit signatures`, build, SBOM) must be green.
- Reviews look first at the security invariants and the threat-model impact, then at tests, docs and code. Expect requests for missing tests or docs. A pull request that breaks an invariant is not merged.
- Fill in the [pull request template](./.github/PULL_REQUEST_TEMPLATE.md).

## License

Your contributions are licensed under the [Apache License 2.0](./LICENSE), the license of this project.
