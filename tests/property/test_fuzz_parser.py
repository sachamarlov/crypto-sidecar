"""Property-based fuzz of the ``.crypt`` header parser.

The parser must either return a valid :class:`ContainerHeader` or raise a
domain exception -- never crash on unexpected bytes. Hypothesis generates
random byte strings (empty, truncated, oversized, crafted) and feeds them
to :func:`read_header` ; any exception that is not one of the documented
``GuardiaBoxError`` subclasses fails the test.

This is a defence against the class of bugs where a malformed container
would surface as an ``IndexError`` / ``struct.error`` / ``UnicodeError``
and leak internal details on stderr.
"""

from __future__ import annotations

from io import BytesIO

from hypothesis import HealthCheck, given, settings, strategies as st

from guardiabox.core.container import read_header
from guardiabox.core.exceptions import GuardiaBoxError


@given(blob=st.binary(min_size=0, max_size=256))
@settings(max_examples=500, deadline=None, suppress_health_check=[HealthCheck.data_too_large])
def test_read_header_never_crashes_on_random_bytes(blob: bytes) -> None:
    """Any input must either parse cleanly or raise GuardiaBoxError."""
    try:
        read_header(BytesIO(blob))
    except GuardiaBoxError:
        return  # expected -- parser surfaced the malformed state
    # If we got here without raising, the header was valid.
    # We don't assert on the content: random bytes that happen to match
    # the GBOX prefix + valid version + valid kdf_id + short params are
    # technically parseable.


@given(
    valid_prefix=st.just(b"GBOX\x01\x01"),
    tail=st.binary(min_size=0, max_size=128),
)
def test_header_with_real_magic_still_bounded(valid_prefix: bytes, tail: bytes) -> None:
    """Even when the magic matches, downstream failures must still be domain errors."""
    try:
        read_header(BytesIO(valid_prefix + tail))
    except GuardiaBoxError:
        return
    # Fell through: parse succeeded. Accept -- the random tail hit a
    # coincidental valid layout.
