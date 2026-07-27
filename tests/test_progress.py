"""Tests for the terminal progress spinner."""

from __future__ import annotations

import io
import time

from glean_osint.progress import Spinner


class _FakeTTY(io.StringIO):
    """A stream that claims to be a real terminal, unlike plain StringIO."""

    def isatty(self) -> bool:
        return True


def test_spinner_non_tty_prints_a_single_static_line() -> None:
    stream = io.StringIO()  # isatty() is False by default
    with Spinner("doing X", stream=stream):
        pass
    assert stream.getvalue() == "... doing X\n"


def test_spinner_non_tty_does_not_start_a_thread() -> None:
    stream = io.StringIO()
    with Spinner("doing X", stream=stream) as spinner:
        assert spinner._thread is None  # type: ignore[attr-defined]


def test_spinner_tty_animates_and_clears_the_line() -> None:
    stream = _FakeTTY()
    with Spinner("doing X", stream=stream):
        time.sleep(0.2)  # let at least a couple of frames render
    output = stream.getvalue()
    assert "doing X" in output
    # the line is cleared on exit -- output ends with the clearing blanks/CR
    assert output.endswith("\r")


def test_spinner_tty_thread_is_joined_on_exit() -> None:
    stream = _FakeTTY()
    with Spinner("doing X", stream=stream) as spinner:
        thread = spinner._thread  # type: ignore[attr-defined]
        assert thread is not None
        assert thread.is_alive()
    assert not thread.is_alive()


def test_spinner_does_not_raise_if_wrapped_block_raises() -> None:
    stream = io.StringIO()
    try:
        with Spinner("doing X", stream=stream):
            raise ValueError("boom")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError to propagate")
