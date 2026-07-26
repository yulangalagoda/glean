"""No code exists yet beyond the package skeleton (see ROADMAP_Pre-Development.md,
Workstream E). This is the placeholder that keeps CI green and proves the test
runner is wired up correctly; real adapter/dedup/scoring tests replace it as
development starts."""

import re

import glean_osint


def test_version_is_set() -> None:
    assert re.match(r"^\d+\.\d+\.\d+$", glean_osint.__version__)
