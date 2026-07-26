"""Shared canonicalisation rules every adapter must use (ADR-0001 D3).

Identity is only stable if every adapter canonicalises the same way before
an entity id is ever constructed — this module is the one place those
rules live, per ADR-0002's own open question 1.
"""

from __future__ import annotations


def canon_host(name: str) -> str:
    """Lowercase, strip a trailing dot, IDNA/punycode-normalise. Wildcards keep
    their leading '*.' verbatim (ADR-0001 D3/D4) — it is not stripped, and the
    rest of the name is canonicalised as usual.
    """
    name = name.strip().lower().rstrip(".")
    if name.startswith("*."):
        return "*." + _idna(name[2:])
    return _idna(name)


def _idna(host: str) -> str:
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        # Already-ASCII or malformed input the idna codec rejects (e.g. a bare
        # label) — fall back to the lowercased original rather than raising;
        # an adapter must degrade, never crash the scan (ADR-0002 D5).
        return host


def canon_email(address: str) -> str:
    """v1 lowercases the whole address, including the local part (ADR-0001 D3
    — a known simplification, may over-merge in rare case-sensitive-local-part
    setups)."""
    return address.strip().lower()
