"""Terminal progress feedback for long-running CLI operations.

Pure presentation, no business logic. A network fetch, a subprocess, or
an LLM call can easily take tens of seconds to minutes with zero output
otherwise -- indistinguishable from a hung process. This exists so a
long-running step always says what it's doing while it's doing it.
"""

from __future__ import annotations

import itertools
import sys
import threading
import time
from types import TracebackType
from typing import TextIO

_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_INTERVAL_SECONDS = 0.08


class Spinner:
    """`with Spinner("doing X..."):` shows an animated `⠋ doing X...` line
    on a real terminal for as long as the wrapped block runs, so a slow
    step never looks stuck. Falls back to a single static line (no
    animation, no carriage-return tricks) when the output stream isn't a
    real terminal -- redirected output, CI, or a captured-output test
    suite, where animation would be noise at best and broken output at
    worst.
    """

    def __init__(self, label: str, *, stream: TextIO | None = None) -> None:
        self._label = label
        self._stream: TextIO = stream if stream is not None else sys.stderr
        self._is_tty = self._stream.isatty()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def __enter__(self) -> Spinner:
        if self._is_tty:
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()
        else:
            print(f"... {self._label}", file=self._stream)
        return self

    def _spin(self) -> None:
        for frame in itertools.cycle(_FRAMES):
            if self._stop.is_set():
                return
            print(f"\r{frame} {self._label}", end="", file=self._stream, flush=True)
            time.sleep(_INTERVAL_SECONDS)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1)
            # Clear the spinner line so whatever prints next starts clean.
            print("\r" + " " * (len(self._label) + 2) + "\r", end="", file=self._stream, flush=True)


SECTION_BREAK = "=" * 60
