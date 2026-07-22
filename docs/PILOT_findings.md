# Pilot Findings — bruising the ADRs against reality

*Companion to `_private/planning/PILOT_Runbook.md` (private — contains the step-by-step procedure). This document records the outcome: what survived contact with real data, what didn't, and why. Per the runbook, the pilot target is a domain the operator owns; specific hostnames and raw findings are withheld here by design — this document is public, they are not. Aggregate/methodological results only.*

**Date:** 2026-07-22
**Tools used:** crt.sh (passive, certificate transparency), theHarvester 4.11.1 (passive, sources: `crtsh,otx,duckduckgo`)
**Target:** one domain owned by the operator (authorisation basis: ownership)

## Summary

| ADR | Verdict | Notes |
|---|---|---|
| 0001 — Entity schema | **Accepted** | Frozen at v0.1.0. One open question resolved (see below). |
| 0002 — Adapter contract | Correction needed | Provenance-granularity assumption was too strong for at least one real tool. |
| 0003 — Correlation/dedup | **Accepted** | Confirmed against a real two-source overlap. |
| 0004 — Prioritisation rubric | **Accepted** (corrected) | A real gut-check failure, fixed same day and re-validated. This is the most important finding of the pilot. |
| 0005 — Brief contract | **Accepted** | Was blocked on ADR-0004; unblocked now that the ranking it renders is trustworthy. |

## ADR-0001 — Entity schema

Ten sample real records (subdomains, a wildcard, a multi-name certificate) all mapped cleanly onto the existing entity types — no schema gaps found.

**Resolved open question:** the ADR asked whether a `certificate` entity's identity could reliably use a SHA-256 fingerprint, with serial+issuer as a documented fallback. In practice, querying crt.sh's JSON API returns **no fingerprint field at all** — only issuer name and serial number, across every record checked. For any adapter built against this endpoint, serial+issuer isn't a fallback path, it's the only path. The ADR text was corrected to reflect that.

Canonicalisation rules (lowercasing, trailing-dot stripping, punycode handling) were not exercised — the real dataset happened to already be clean on all of these — so they remain unvalidated rather than confirmed. Worth revisiting once a tool that produces messier raw hostnames is piloted.

## ADR-0002 — Adapter contract

crt.sh mapped cleanly: every record carries its own row `id`, which makes a precise `raw_record_ref` trivial.

theHarvester did not. Run with three passive sources at once, its output is a single flat, already-merged list — there is no way to tell which underlying source found a given host, and no per-record locator at all. The adapter contract's requirement for a `raw_record_ref` per assertion assumed a granularity that at least one real, commonly-used tool simply doesn't provide. The contract now explicitly allows adapters to degrade to the coarsest locator the tool actually gives (e.g. a combined-sources label plus an array position), rather than requiring precision the source data can't support. This is treated as the contract being made honest, not weakened.

## ADR-0003 — Correlation & dedup

A real overlapping entity (found independently by both crt.sh and theHarvester) was hand-merged. Both tools produced the same canonical identity, so they grouped correctly under the exact-match rule; provenance union behaved as designed. On the overlapping subset measured, the before/after duplicate rate came out plausible and non-degenerate (neither 0% nor 100%), which is the sanity bound the ADR asks for.

## ADR-0004 — Prioritisation rubric (the important finding)

This is where the pilot did its job. Hand-scoring real entities against the v1 signal table surfaced a genuine gap: the `sensitive_hostname_pattern` signal fires on hostname text alone, with no signal anywhere in the table checking whether an entity is *currently live*. In the real data, an old, no-longer-resolving finding with an administratively-named hostname scored higher than genuinely live, multi-tool-corroborated infrastructure — purely because nothing tested liveness.

That is exactly the failure mode the project charter opens with: collection succeeding, judgment not — reproduced inside Glean's own scoring, not just in a third-party tool. The fix wasn't a weight tweak; it was a missing signal. A new signal, driven by a DNS-resolution tool (`dnsx` or equivalent), now fires only on *positive confirmation* that a hostname doesn't currently resolve — never merely because that tool wasn't run — and is weighted to exactly offset the hostname-pattern signal it was drowning out. This makes DNS resolution a non-optional dependency in the MVP toolset rather than a nice-to-have. Re-scored against the same real entities, the ordering now holds: the dead pattern-matching finding nets to zero and drops out of the ranked brief, the live corroborated infrastructure ranks above it. **Accepted.**

## ADR-0005 — Brief contract

The template itself reads clearly and fits the "actionable in under two minutes" bar once fed a *correct* ranking. It doesn't need changes on its own — it was downstream of ADR-0004, so it was blocked until that correction landed. With 0004 fixed and re-validated, 0005 is unblocked. **Accepted.**

## What this means for the roadmap

All five ADRs are now `Accepted` and frozen at v0.1.0 — two of them (0002, 0004) only after a real correction, which is exactly what this pilot was for. The headline result of Phase 0 is the ADR-0004 finding: **a transparent, auditable rubric can still misrank without an explicit liveness check, and that failure is invisible until you look at real data.** That's a good sign for the project's actual thesis, not a bad one — it's a concrete instance of the exact problem class the evaluation is meant to catch, caught and fixed before a single line of production code was written.
