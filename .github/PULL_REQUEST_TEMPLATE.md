## What / Why

<!-- What changes and why. Link the issue: "Closes #123". -->

## Rules covered

<!-- Each behaviour rule this PR adds or changes, with the test that covers it. -->

- 

## Verification

<!-- Paste the npm run check totals (for example "tests 412, pass 412, fail 0"). -->

- `npm run check`: 
- RED: <!-- the tests that failed before the change, and how -->
- GREEN: <!-- the same tests passing after it -->

## Threat-model impact

<!-- Required when touching src/sinks, src/gate, src/capture, src/platform or install.sh.
     What moves in the trust boundaries of docs/architecture.md? Write "none" otherwise. -->

## Risk

Risk: <!-- low / medium / high and why -->

## Checklist

- [ ] Commits follow Conventional Commits
- [ ] Every commit has a DCO sign-off (`git commit -s`)
- [ ] Docs, `zks help` and the skill are updated for any changed command, option or message
- [ ] No secret value in argv, env, stdout, stderr, temp files or the audit log (S1); no write to a new destination without the dialog (S5)
- [ ] Opened against `develop`, about 400 changed lines or fewer
