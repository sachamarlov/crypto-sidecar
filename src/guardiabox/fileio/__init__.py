"""Safe file I/O utilities.

This package guards every disk interaction against the most common attack
classes: path traversal, symlink escape, partial writes leaving inconsistent
state, and TOCTOU races. UI / API layers must always use these helpers
instead of touching the filesystem directly.
"""
