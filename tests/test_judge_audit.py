"""Tests for the judge-reliability apparatus (ADR-0006 Q5)."""

from __future__ import annotations

import pytest

from glean_osint.evaluation import ClaimVerdict
from glean_osint.judge_audit import (
    SUPPORTED,
    UNSUPPORTED,
    AuditEntry,
    build_packet,
    interpret,
    score_packet,
)


def _entry(index: int, judge: str, human: str | None) -> AuditEntry:
    return AuditEntry(
        index=index,
        target="example.com",
        entity_id=f"subdomain:h{index}.example.com",
        claim="a claim",
        judge_verdict=judge,
        entity_facts="{}",
        human_verdict=human,
    )


def test_scoring_an_unlabelled_packet_raises_rather_than_guessing() -> None:
    """Skipping unlabelled rows would let a half-finished packet produce a
    confident-looking number over whichever claims happened to be done
    first -- exactly the quietly-wrong result this exercise exists to rule
    out. Treating them as agreement would be worse still.
    """
    with pytest.raises(ValueError, match="unlabelled entries"):
        score_packet([_entry(1, SUPPORTED, SUPPORTED), _entry(2, SUPPORTED, None)])


def test_an_invalid_label_is_rejected_by_index() -> None:
    with pytest.raises(ValueError, match=r"entries \[2\]"):
        score_packet([_entry(1, SUPPORTED, SUPPORTED), _entry(2, SUPPORTED, "maybe")])


def test_a_judge_that_over_flags_scores_low_precision() -> None:
    """The case that matters most for how `stage2_faith` should be read.
    A judge inventing problems makes published faithfulness look *worse*
    than reality -- counter-intuitive, and the reason `interpret` spells
    the direction out rather than leaving it to the reader.
    """
    result = score_packet(
        [
            _entry(1, UNSUPPORTED, SUPPORTED),  # flagged, wrongly
            _entry(2, UNSUPPORTED, SUPPORTED),  # flagged, wrongly
            _entry(3, UNSUPPORTED, UNSUPPORTED),  # flagged, rightly
            _entry(4, SUPPORTED, SUPPORTED),
        ]
    )

    assert result.flag_precision == pytest.approx(1 / 3)
    assert result.flag_recall == 1.0  # caught every real problem
    assert "understates" in interpret(result) or "dominated by judge error" in interpret(result)


def test_a_judge_that_misses_problems_scores_low_recall() -> None:
    result = score_packet(
        [
            _entry(1, SUPPORTED, UNSUPPORTED),  # missed
            _entry(2, SUPPORTED, UNSUPPORTED),  # missed
            _entry(3, UNSUPPORTED, UNSUPPORTED),  # caught
        ]
    )

    assert result.flag_precision == 1.0
    assert result.flag_recall == pytest.approx(1 / 3)


def test_precision_and_recall_are_undefined_rather_than_perfect_when_nothing_was_flagged() -> None:
    """A judge that never flags has not demonstrated precision, and a
    sample containing no real problems says nothing about recall.
    Reporting 1.0 for either would turn "unmeasured" into "flawless".
    """
    result = score_packet([_entry(1, SUPPORTED, SUPPORTED), _entry(2, SUPPORTED, SUPPORTED)])

    assert result.agreement == 1.0
    assert result.flag_precision is None
    assert result.flag_recall is None
    assert "says nothing" in interpret(result)


def test_kappa_is_none_when_chance_agreement_is_total() -> None:
    """With both raters using a single label throughout, expected agreement
    is 1.0 and kappa's denominator is zero. Returning 0.0 there would read
    as "no better than chance" when the honest answer is "this sample
    cannot measure it".
    """
    result = score_packet([_entry(1, SUPPORTED, SUPPORTED)])
    assert result.kappa is None


def test_kappa_rewards_agreement_beyond_chance() -> None:
    perfect = score_packet(
        [
            _entry(1, SUPPORTED, SUPPORTED),
            _entry(2, UNSUPPORTED, UNSUPPORTED),
        ]
    )
    assert perfect.kappa == pytest.approx(1.0)


def test_sampling_is_reproducible_from_the_seed() -> None:
    """A labelled packet that could not be regenerated would make the
    resulting reliability figure unauditable -- nobody could check which
    claims it was computed over."""
    claims = [
        (
            "example.com",
            ClaimVerdict(entity_id=f"e{i}", claim=f"c{i}", supported=i % 2 == 0, entity_facts="{}"),
        )
        for i in range(50)
    ]

    first = build_packet(claims, sample_size=10, seed=42)
    again = build_packet(claims, sample_size=10, seed=42)
    different = build_packet(claims, sample_size=10, seed=43)

    assert [e.claim for e in first] == [e.claim for e in again]
    assert [e.claim for e in first] != [e.claim for e in different]


def test_a_zero_sample_size_takes_every_claim() -> None:
    claims = [
        ("example.com", ClaimVerdict(entity_id="e", claim=f"c{i}", supported=True, entity_facts=""))
        for i in range(7)
    ]

    assert len(build_packet(claims, sample_size=0, seed=1)) == 7


def test_the_packet_carries_the_evidence_the_judge_was_shown() -> None:
    """An annotator ruling on the same claim needs the same facts, or they
    are answering a different question than the judge was."""
    claims = [
        (
            "example.com",
            ClaimVerdict(
                entity_id="subdomain:admin.example.com",
                claim="resolves to 203.0.113.1",
                supported=False,
                entity_facts='{"attributes": {"dns_resolved": true}}',
            ),
        )
    ]

    entry = build_packet(claims, sample_size=1, seed=0)[0]

    assert entry.entity_id == "subdomain:admin.example.com"
    assert entry.judge_verdict == UNSUPPORTED
    assert "dns_resolved" in entry.entity_facts
    assert entry.human_verdict is None  # never pre-filled
