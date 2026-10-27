## What this changes

<!-- One or two sentences. The "why" matters more than the "what". -->

## Type

- [ ] Bug fix
- [ ] New tool / provider / capability
- [ ] Prompt or reasoning change
- [ ] Guardrail or security-relevant change
- [ ] Docs, packaging or the website
- [ ] Refactor with no behaviour change

## How it was tested

<!--
  Which model, which target (the bundled lab, a CTF box, a local VM — not someone else's
  production system), and what you observed. For prompt changes, say what changed in the
  agent's behaviour.
-->

- [ ] `make test` passes
- [ ] `make lint` passes
- [ ] New or changed behaviour has a test
- [ ] If docs changed: `make site` was run and the regenerated HTML is committed

## Guardrails

- [ ] This does not weaken scope enforcement, the destructive-command blocklist, path
      confinement or credential redaction
- [ ] If it touches `safety.py` or the prompt: I have explained the risk in the description above

## Notes for the reviewer

<!-- Anything you are unsure about, alternatives you rejected, follow-up work. -->
