"""Security-policy layer.

Wraps :mod:`guardiabox.core` primitives with policies that the rest of the
application enforces: password strength gates, lockout / backoff, key storage,
and the audit log. **Never** weaken these defaults from the UI layer.
"""
