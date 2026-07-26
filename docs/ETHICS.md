# Ethics, Authorisation & Threat Model

*Expands the binding ethics section in `CHARTER.md` into the full policy,
threat model, and data-governance rules for the project (roadmap
Workstreams B4, D5). This is a public document — it states the rules and
the reasoning behind them; it does not contain real target names (those
live privately, see "Data governance" below).*

## Who may run this, against what

Glean is built for **authorised security research only**:

- **Owned targets** — infrastructure the operator controls — are the
  default and preferred authorisation basis.
- **Explicitly-authorised public test targets** are acceptable when
  individually verified against a real, citable authorisation source
  (e.g. a project's own published scan-permission policy). See
  `docs/target-list-policy.md` for the full category ranking and the
  categories that are excluded even when scanning itself is technically
  permitted (e.g. third-party bug-bounty scope — in-scope-to-scan is not
  the same as in-scope-to-publish-research-about).
- **Arbitrary third-party domains are out of bounds**, full stop —
  including via fully passive tools. The charter's ethics section does
  not carve out an exception for "it's just public data"; this project
  holds itself to the literal rule rather than arguing a passive-data
  exception.

Authorisation must be decided and recorded **before** any scanning, not
justified after the fact.

## Passive vs. active reconnaissance

The adapter contract (ADR-0002 D2/D3) makes every tool declare its
`method` — `passive` or `active` — per record, not globally. This is a
design constraint, not just documentation: it means Glean's architecture
cannot silently escalate from passive lookups to active probing under a
command that looks passive. Active techniques are opt-in and visible.

## Why people-focused OSINT is out of v1

The charter scopes v1 to infrastructure/domain reconnaissance (domains,
subdomains, IPs, DNS, breach/email exposure tied to a domain, web tech)
and explicitly excludes people-focused OSINT (usernames, real names,
social graph). This isn't an oversight to fix later — it's deferred
because the abuse surface is qualitatively different: infrastructure
recon can embarrass or expose a system, but people-OSINT can enable
harassment, stalking, or doxxing of an individual who never consented to
being a research target and has no equivalent of "I own this domain" to
anchor authorisation against. If a people-OSINT domain is ever added
(roadmap, explicitly post-MVP), it needs its own authorisation model and
ethics review before a line of code is written for it — the infra-only
scoping in this version is intentional risk containment, not a
placeholder.

## Threat model: plausible misuse, and what mitigates it

This section names the ways Glean's own design could be turned toward
something it isn't meant for, and what specifically was done about each.

**1. Running it against a target without authorisation.**
Mitigation: the binding rule above, stated in `CHARTER.md`, `SECURITY.md`,
and here; no bundled target lists or "example domains" that could read as
implicit endorsement; `docs/target-list-policy.md` requires a recorded
authorisation basis before any scan, even in the project's own eval work.
This is a policy control, not a technical one — Glean cannot verify a
user's authorisation any more than `curl` can, and doesn't pretend to.

**2. Recon output about a real target leaking, even for owned domains.**
A scan result is a map of exactly what's exposed — sensitive by nature
regardless of who authorised collecting it. See "Data governance" below
for the concrete controls.

**3. The LLM synthesis step fabricating or mis-prioritising findings.**
This is the project's actual research question, not an afterthought:
dedup and prioritisation are deterministic, code-only steps (ADR-0003,
ADR-0004) — the LLM narrates a ranking it did not compute and cannot
silently reorder. The evaluation harness (ADR-0006) exists specifically
to catch and report fabrication and mis-ranking rather than assume good
behaviour, and treats a bad result as a valid, reportable outcome rather
than something to tune away.

**4. Using Glean to assemble a target list of "sensitive-looking live
hosts" as attack-prep reconnaissance.**
Glean does not add new discovery capability beyond what its underlying
FOSS tools (crt.sh, theHarvester, dnsx, etc.) already do publicly and
individually — it unifies and prioritises their output, it doesn't
introduce a new scanning technique. The same dual-use argument applies to
every tool in its adapter set already; Glean's synthesis layer doesn't
add exploitation capability, only judgment over already-public
collection. This is a real, acknowledged dual-use tension inherent to
OSINT tooling in general, not one this project claims to have solved —
it's named here rather than left unstated.

## Data governance

- Raw scan output, per-target fixtures, and the real target list are
  **git-ignored by design**: `_private/`, `raw/`, `scans/`,
  `targets.txt`/`targets.md`, and `**/live-*.json` are excluded (see
  `.gitignore`). The repo is public by default; anything that must never
  be published is excluded structurally, not by remembering to redact it
  each time.
- Fixtures committed to the public repo (golden test fixtures, worked
  examples in docs/ADRs) are either the operator's own deliberately-built
  test infrastructure (see the profile blueprint in
  `docs/target-list-policy.md`) or sanitised before commit — never an
  unredacted real scan.
- Findings docs written about real targets (e.g.
  `_private/findings/*-ground-truth-validation.md`) stay private even
  when their aggregate conclusions are published publicly (e.g.
  `docs/PILOT_findings.md`), by the same "aggregate/methodology public,
  specifics private" split used throughout this project's docs.
- API keys, secrets, and local config are excluded via `.env`, `*.key`,
  `config/*.local.*`, `**/secrets.*` in `.gitignore`.

## Reporting

- A vulnerability **in Glean's own code**: see `SECURITY.md`.
- A concern about **how this project is using or documenting a real
  target**: contact yulangalagoda1@gmail.com directly.
