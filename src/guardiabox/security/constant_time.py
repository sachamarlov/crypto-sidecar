"""Constant-time byte comparison helper.

The only public symbol, :func:`equal_constant_time`, delegates to
:func:`hmac.compare_digest` — the CPython stdlib's constant-time
comparator backed by OpenSSL's ``CRYPTO_memcmp``. Code that needs to
compare tags, HMACs, hashed passwords, or any other secret-derived
bytes must route through this helper instead of ``==`` so that future
readers have a single grep target for "is this compare constant-time?".

Why not just inline ``hmac.compare_digest`` at the call site? Two
reasons:

* A single central import makes it trivial to audit every
  secret-adjacent comparison in the codebase.
* If CPython ever ships a faster primitive (e.g. a ``secrets`` helper)
  we swap it in one place instead of hunting usages.
"""

from __future__ import annotations

import hmac

__all__ = ["equal_constant_time"]


def equal_constant_time(
    a: bytes | bytearray | memoryview,
    b: bytes | bytearray | memoryview,
) -> bool:
    """Return True iff ``a`` and ``b`` are byte-equal, in constant time.

    ``hmac.compare_digest`` falls back to a Python loop when the inputs
    are of different lengths; the comparison remains constant-time with
    respect to **content** but not to **length**. That is the expected
    behaviour for MAC / tag comparison — the length is public.

    Raises:
        TypeError: If either argument is not a bytes-like object.
    """
    if not isinstance(a, (bytes, bytearray, memoryview)):
        raise TypeError(f"equal_constant_time requires bytes-like, got {type(a).__name__}")
    if not isinstance(b, (bytes, bytearray, memoryview)):
        raise TypeError(f"equal_constant_time requires bytes-like, got {type(b).__name__}")
    return hmac.compare_digest(bytes(a), bytes(b))
