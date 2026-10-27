# Contributing

Thanks for looking. redloop — published as **Panther gpt** — is a small, deliberately boring
codebase: a loop, a parser, ten tools, two provider clients and a lot of tests. Contributions that
keep it that way are the most welcome.

## Setup

```bash
git clone https://github.com/usa3492max/gpt && cd gpt
make venv                      # virtualenv with dev + docs extras
source .venv/bin/activate
redloop --help
make test                      # 226 tests, no network or API key needed
make lint                      # ruff
```

Nothing in the test suite requires Docker, a model, or internet access. Please keep it that way:
if your change needs a live endpoint, mock it with `httpx.MockTransport` (see `tests/test_llm.py`).

## Before you open a pull request

- `make test` and `make lint` pass.
- New behaviour has a test. Bug fixes have a test that fails before your fix.
- You did not add a dependency that could be avoided. The runtime dependency list is three
  packages (`httpx`, `rich`, `python-dotenv`) and we would like to keep it that short.
- If you changed `README.md`, `docs/architecture.md` or `docs/CHANGELOG.md`, run `make site` and
  commit the regenerated HTML — the published pages are generated from those files, so a doc
  change without it leaves the site stale.

## What is easy to add

**A tool.** Subclass `Tool` in `redloop/tools/`, declare `name`, `summary`, `args` and `required`,
implement `async def run(self, args, ctx) -> ToolResult`, then register it in
`redloop/tools/__init__.py`. The prompt, `--list-tools` output and parser aliases pick it up
automatically. Add the happy path, a failure path, and a guardrail case to `tests/test_tools.py`.

**A provider.** Implement `LLMClient.complete`, map HTTP errors onto the taxonomy in
`redloop/llm/base.py` (auth, rate limit, context overflow, server error), add a `ProviderPreset` to
`config.PRESETS`, and pick the branch in `llm.build_client`. Test it against
`httpx.MockTransport`, not a live API.

**A renderer.** Subscribe any callable taking an `Event` to the bus. That is the whole interface.

## Things to be careful about

- **Security-sensitive changes** — anything touching `safety.py`, the scope guard, the destructive
  blocklist, path confinement or credential redaction — need tests and a clear explanation in the
  PR. These are load-bearing.
- **The prompt is behaviour.** `prompts.py` changes alter how every model behaves. If you change
  the system prompt, say what you observed and on which model.
- **Do not weaken guardrails** to make a demo easier. If a legitimate action is being blocked,
  fix the false positive specifically rather than loosening the rule.
- **Keep the feed readable.** One action per turn is a design constraint, not an accident.

## Commits and pull requests

- Write the *why* in the commit body, not just the what.
- Keep a PR to one concern. Large mixed PRs are hard to review and hard to revert.
- Describe how you tested it, including which model and which target (a lab or CTF box, not
  somebody's production system).

## Reporting bugs and security issues

Bugs and feature requests: open an issue using the templates. Security problems: **do not** open a
public issue — follow [SECURITY.md](SECURITY.md).

## Licence

Contributions are accepted under the MIT licence, the same terms as the project.
