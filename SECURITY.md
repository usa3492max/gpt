# Security policy

redloop — published as **Panther gpt** — is an offensive-security tool. This policy covers two
different things: keeping the tool itself from being a liability, and keeping its users honest.

## Reporting a vulnerability in redloop

Use GitHub's private vulnerability reporting: **Security → Advisories → Report a vulnerability**
on <https://github.com/usa3492max/gpt/security/advisories/new>. Please do not open a public issue
for a security bug.

Include the version (`redloop --version`), a reproduction, and the impact you believe it has.
Expect an acknowledgement within a few days; this is a volunteer project, so timelines are best
effort, but anything that lets an agent escape its stated scope will be treated as urgent.

Areas we consider security-relevant:

| Area | Example of a bug we want to hear about |
|---|---|
| **Scope enforcement bypass** | A command, URL or Python snippet that reaches a host outside `--scope` without being refused |
| **Guardrail bypass** | A destructive command that slips past the blocklist (`safety.py`) and damages the container or host |
| **Prompt-injection escalation** | A malicious *target* that talks the agent into exfiltrating the API key, attacking a third party, or writing outside the run directory |
| **Path confinement** | `write_file` escaping the run directory or `/tmp` |
| **Credential handling** | An API key leaking into logs, the report, the transcript, or an error message |
| **Supply chain** | A dependency or image change that quietly adds network egress or a backdoor |

## Scope of the guarantee

The container is the security boundary. The agent runs as **root inside it on purpose**, because
raw-socket scanning, binding low ports and reading `/etc/shadow` after a simulated privilege
escalation are the job. That is not a vulnerability in itself.

What we do promise:

- Nothing is sent to a target until the operator passes `--i-am-authorized`.
- Arbitrary public hosts outside `--scope` are refused, including inside Python snippets.
- Catastrophic commands are blocked before execution.
- Every action, refusal and observation is written to the run directory so a run can be audited.

What we do **not** promise:

- That the scope guard is a sandbox. It is a guardrail: a determined model or a hostile target can
  still do something unexpected. Run it in a throwaway VM or a dedicated container host.
- That `--no-scope-check` is safe. It disables the main protection and exists for lab work only.

## Using redloop responsibly

Test only systems you own or have **explicit written permission** to test. Unauthorised access to
computer systems is a criminal offence in most jurisdictions (Computer Misuse Act, CFAA, and
equivalents elsewhere).

If you find a vulnerability with this tool, follow a responsible disclosure process with the system
owner. Do not open an issue in this repository containing another party's live vulnerability,
credentials, customer data, or flags from a platform whose rules forbid sharing them.

Reports that amount to "I ran it against a system I do not control and it worked" will be closed.

## Supported versions

The latest tagged release receives security fixes. There is one maintained line at a time.

| Version | Supported |
|---|---|
| 0.1.x | yes |
| < 0.1 | not released |
