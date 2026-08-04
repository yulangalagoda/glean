"""The committed evaluation fixture target (roadmap Workstream E3).

The real ground-truth set lives in `eval/scans/`, which is gitignored
because it names real domains -- so CI has nothing to evaluate against and
the harness that produces this project's headline numbers never runs on a
push. `tests/fixtures/eval/example-com/` is a safe-to-commit stand-in
(RFC 2606, synthetic captures) that lets `glean eval` run as a build-time
regression gate.

It lives here rather than under `eval/scans/` on purpose: that directory's
"everything in here is private real-domain data" rule should stay absolute,
and a `.gitignore` negation carved into it is exactly the kind of exception
that later leaks a hostname nobody meant to publish.

What these tests gate, and what they deliberately don't:

- `faithfulness` and `provenance_retention` are structural invariants of the
  pipeline (ADR-0006 D1) -- they must read 1.000 for any input whatsoever,
  so a drop is a real regression and fails the build.
- `overlap@N` / `nDCG@N` measure agreement with one annotator's ranking of a
  toy graph. They're reported for visibility but never asserted on: a
  legitimate improvement to the scoring rubric (ADR-0004) is allowed to move
  them, and a test that forbade that would make the rubric unimprovable.
"""

from __future__ import annotations

import filecmp
from pathlib import Path

import pytest

from glean_osint.cli import _evaluate_target
from glean_osint.evaluation import load_ground_truth

_FIXTURES = Path(__file__).parent / "fixtures"
_TARGET_DIR = _FIXTURES / "eval" / "example-com"

# Every raw capture in the fixture target is a byte-for-byte copy of the
# golden fixture the adapter tests already assert against.
_SHARED_CAPTURES = (
    "crtsh-example-com.json",
    "theharvester-example-com.json",
    "subfinder-example-com.jsonl",
    "dnsx-example-com.json",
    "httpx-example-com.jsonl",
)


@pytest.mark.parametrize("filename", _SHARED_CAPTURES)
def test_eval_fixture_captures_have_not_drifted_from_the_golden_fixtures(filename: str) -> None:
    """The eval target duplicates the adapter suite's golden fixtures, and
    duplicated bytes drift. `.gitattributes` already stops a checkout from
    rewriting them; nothing else stops someone editing one copy and not the
    other, which would leave the evaluation silently scoring different input
    than the adapter tests validate. Compared byte-wise (`shallow=False`),
    since size-and-mtime equality is exactly the check that would miss a
    same-length edit.
    """
    original = _FIXTURES / filename
    copy = _TARGET_DIR / "raw" / filename

    assert original.is_file(), f"golden fixture {filename} is missing"
    assert copy.is_file(), f"eval fixture capture {filename} is missing"
    assert filecmp.cmp(original, copy, shallow=False), (
        f"{filename} differs between tests/fixtures/ and the eval target -- "
        "update both copies, they are meant to be identical bytes"
    )


def test_every_ground_truth_entity_id_exists_in_the_graph() -> None:
    """A typo'd or stale `entity_id` in `ground_truth.yaml` doesn't raise --
    it just never matches, quietly dragging overlap@N down and looking like a
    prioritisation regression. ADR-0001's ids are deterministic, so a
    reference that resolves to nothing is always a mistake in the annotation,
    never a legitimate outcome.
    """
    ground_truth = load_ground_truth(_TARGET_DIR / "ground_truth.yaml")
    result = _evaluate_target(_TARGET_DIR, top_n=5)

    assert result.entities, "the fixture target produced no entities at all"
    known = {entity.id for entity in result.entities}
    unknown = [eid for eid in ground_truth.ranked_ids if eid not in known]
    assert unknown == [], f"ground truth references entities not in the graph: {unknown}"


def test_structural_metrics_are_perfect_on_the_committed_fixture() -> None:
    """The charter's two target-1.0 metrics. Both are structural: every
    finding is built directly from a real graph entity and carries that
    entity's provenance, so anything below 1.000 means the pipeline started
    inventing findings or dropping their sources -- the two failures this
    project exists to make impossible.
    """
    result = _evaluate_target(_TARGET_DIR, top_n=5)

    assert result.faithfulness.score == 1.0
    assert result.provenance_retention == 1.0
    # Not redundant with score == 1.0: a brief with zero findings scores a
    # vacuous 1.000, so assert there were real claims to support as well.
    assert result.faithfulness.total_claims > 0
    assert result.faithfulness.supported_claims == result.faithfulness.total_claims


def test_a_target_with_no_captures_is_an_error_not_a_perfect_score(tmp_path: Path) -> None:
    """The failure that made this test exist. Both headline metrics are
    ratios over a brief's findings, so a target that parsed nothing scores a
    vacuous 1.000 on each -- nothing unfaithful, nothing missing provenance,
    because there is nothing at all. CI hit precisely this: the raw captures
    were gitignored and never committed, and `glean eval` printed a flawless
    `mean faithfulness=1.000 mean provenance_retention=1.000` and exited 0.

    An empty evaluation must be reported, never scored. `run_eval` turns this
    into a per-target warning and exits non-zero if every target fails, so
    one unreadable capture degrades that target rather than the whole run.
    """
    target_dir = tmp_path / "example-com"
    (target_dir / "raw").mkdir(parents=True)  # present but empty
    (target_dir / "ground_truth.yaml").write_text(
        (_TARGET_DIR / "ground_truth.yaml").read_text(encoding="utf-8"), encoding="utf-8"
    )

    with pytest.raises(ValueError, match="no entities parsed"):
        _evaluate_target(target_dir, top_n=5)


def test_the_fixture_target_exercises_every_passive_adapter() -> None:
    """The point of a CI fixture is that a change to any adapter shows up in
    the evaluation. subfinder was the fifth adapter and went unread by
    `glean eval` entirely until `_RAW_ADAPTERS` was corrected, which is the
    failure this asserts against -- an adapter contributing nothing here
    means the harness has stopped watching it.
    """
    result = _evaluate_target(_TARGET_DIR, top_n=5)

    contributing = {prov.source_tool for entity in result.entities for prov in entity.provenance}
    assert contributing == {"crtsh", "theharvester", "subfinder", "dnsx", "httpx"}
