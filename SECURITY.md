# Security Policy

Glean is a reconnaissance and intelligence-synthesis tool. That makes two
different things "security" here: vulnerabilities *in* Glean, and
responsible *use* of Glean against real infrastructure. Both are covered
below. For the full ethics rationale and threat model, see
[`docs/ETHICS.md`](docs/ETHICS.md).

## Supported versions

Glean is pre-1.0 and under active early development. There is one
supported line: the latest commit on `main`. No back-ported fixes to
older tags should be expected until a stable release policy exists.

## Reporting a vulnerability in Glean itself

If you find a security issue in Glean's own code (e.g. unsafe handling of
tool output, command injection in an adapter's invocation step, a way a
malicious scan target's response could execute code or exfiltrate data
from the machine running Glean), please report it privately rather than
opening a public issue.

- **Contact:** yulangalagoda1@gmail.com
- **Include:** affected component/adapter, a reproduction (a sanitised
  fixture is ideal — see the note on sensitive data below), and impact.
- **Response:** best-effort acknowledgement within a few days. This is a
  solo project, not a funded security team — timelines are honest, not
  contractual.

Please don't include real target infrastructure details (domains, IPs,
raw scan output) in a public report; send those privately using the
contact above.

## Responsible use (binding, not a suggestion)

Glean is built for **authorised security research only**:

- Only scan targets you own or are explicitly authorised to assess.
- Passive and active reconnaissance are kept as clearly separated
  concerns; an adapter's `method` (ADR-0002) is never ambiguous, and
  active techniques are never silently enabled by a passive-sounding
  command.
- Every finding in Glean's output carries provenance back to the tool and
  raw record that produced it, so any claim can be audited rather than
  taken on faith.

Using Glean against a target without authorisation is a misuse of the
tool, not a supported use case, regardless of what the software
technically permits it to attempt.

## Handling scan output and other sensitive data

Reconnaissance data about real infrastructure is sensitive even when the
target is your own — it's a map of exactly what an attacker would want.
Raw scan output and per-target fixtures (`eval/scans/**/raw/`,
`_private/`, `targets.txt`/`targets.md`) are git-ignored by design; see
[`docs/ETHICS.md`](docs/ETHICS.md) for the full data-governance rationale.
When filing an issue or PR, double-check that no real target data,
credentials, or API keys are included.
