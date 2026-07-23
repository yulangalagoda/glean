# Target List Policy (Roadmap Workstream D3)

*Companion to `docs/adr/0007-ground-truth-protocol.md`. This document is the public methodology: what kinds of targets are permitted, why, and the deliberate-variation blueprint for owned test domains. It intentionally contains no real domain names — those are operational specifics recorded privately (see `_private/planning/target-list.md`, git-ignored), for the same reason raw scan output stays out of the public repo: a published list of "here are my designated scan-practice domains" is itself a minor OSINT signal worth not handing out for free.*

## Why this exists

The evaluation needs a ground-truth set of **≥10 distinct scan targets** (roadmap F2) — each Glean scan targets one root domain, so this means 10 distinct domains, not 10 findings on one domain. The charter's binding ethics section requires every target be owned or explicitly cleared, decided and recorded *before* any scanning. This document is that record's methodology.

## Permitted target categories, ranked by how much of the set they can carry

1. **Domains the operator owns.** The default and majority category — cleanest authorization, no ambiguity, and the only category where infrastructure can be deliberately varied to make the ground-truth set actually informative rather than incidental.
2. **Explicitly-authorized public test targets, individually verified.** Rare and thin for this project's purposes — most public "OK to scan" targets are single hosts with no meaningful subdomain/DNS/CT-log sprawl, so they're useful for realism-check diversity but cannot carry the bulk of the set. Each one requires its own verified citation before use; the current example is `scanme.nmap.org`, sourced against the official Nmap legal-issues page (authorization: Nmap-style port scanning only, no exploits or DoS, informally capped around a dozen scans/day — [nmap.org/book/legal-issues.html](https://nmap.org/book/legal-issues.html)).
3. **Explicitly out, even when passive:** third-party bug bounty / VDP scope domains. Even where scanning itself is in-scope, most program terms don't cover publishing derived research data about the target — and publishing the ground-truth set and eval results is the entire point of this exercise. Not worth the ToS risk for something orthogonal to the scanning itself.
4. **Explicitly out:** arbitrary third-party domains, even via fully passive tools. The charter's ethics section says "targets owned or explicitly cleared" without a passive-data carve-out, and this project holds itself to that literally rather than arguing an exception for public-data-only lookups.

## Owned-domain infrastructure blueprint

A ground-truth set built from several copies of the same domain shape teaches nothing — the value is in deliberate variation that exercises different parts of the pipeline. Four profiles, designed to be genuinely low-risk on public infrastructure:

### Profile A — Sparse & clean
Apex + `www` only, correctly configured, nothing else. No exposed services beyond the site itself, no sensitive-sounding hostnames, no cert irregularities. **Tests:** that Glean doesn't hallucinate signal where none exists — the ground-truth ranking for this target should be nearly empty, and a brief that finds "priorities" here would itself be the failure being measured.

### Profile B — Sprawling with dead history
A handful (3–5) of live, legitimate subdomains, plus deliberately-created historical residue: issue a certificate for one or two additional subdomains, then let their DNS lapse while the CT log entry persists. This is the exact shape `yulan.me` turned out to have by accident — Profile B creates it on purpose. **Tests:** the `stale_no_dns` signal (ADR-0004) and dedup behavior across a live/dead mix.

### Profile C — Sensitive-named, live, genuinely harmless
Subdomains using the ADR-0004 curated sensitive-keyword list (`admin`, `staging`, `dev`, `portal`, etc.) that **do** resolve and serve a clearly-labeled static "test fixture, nothing here" page — no real login form, no real backend, no functionality of any kind. **Tests:** the true-positive case — the rubric should rank these highly (live + sensitive pattern, no liveness penalty), and a human ground-truth annotator should independently agree they warrant review, since from pure OSINT vantage a sensitive-sounding live hostname genuinely does warrant a look regardless of what's actually behind it.

### Profile D — Wildcard + multi-source corroboration
A real (intentional) wildcard DNS record resolving every subdomain to the same static harmless page. Safest profile to run — since every possible subdomain serves identical harmless content, there's nothing for even a probing scanner to find beyond the wildcard itself. **Tests:** the `wildcard_or_default` signal, and — once the domain has existed long enough to appear in multiple passive sources naturally — `multi_tool_corroboration` without any special setup.

### Hard safety rules across all profiles
- **No real vulnerable software.** If a signal needs to look "risky" (an open port, a sensitive name), the risk signal comes from OSINT-visible metadata (naming, exposure, cert age) — never from actually running outdated or exploitable software. A public IP with a genuinely vulnerable service attracts real internet background-radiation attacks and could be compromised and reused by someone else for their own purposes.
- **No real credentials, no real functionality, anywhere.** Every "sensitive-looking" surface serves static, clearly-labeled placeholder content only.
- **Stick to standard web ports (80/443, optionally 8080) for anything meant to be "exposed."** Don't fake other protocols (RDP, database ports, etc.) — there's no safe way to have something answer on those ports without it being a real, potentially-exploitable service, and it isn't needed: the signal table's `sensitive_port` case can be validated conceptually without actually running one on public infrastructure.

## Target count plan

10 total: `yulan.me` (already piloted) + `scanme.nmap.org` (verified, no setup needed) + 3–4 newly-registered owned domains across Profiles A–D, expanded further later if the roadmap's post-MVP "more targets" goal is pursued. The real domain names, once registered, are recorded in `_private/planning/target-list.md` — never in this file.
