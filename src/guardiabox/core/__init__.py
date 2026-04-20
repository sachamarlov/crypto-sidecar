"""Cryptographic and format primitives for GuardiaBox.

This package contains *pure*, side-effect-free building blocks: the AEAD
cipher, key derivation functions, the ``.crypt`` container format, and
constants. **Never import UI, persistence, or networking code from here.**
Dependencies always flow inward toward :mod:`guardiabox.core` (hexagonal
architecture).
"""
