"""GuardiaBox — local secure vault.

Public package entry point. Re-exports the version and high-level metadata.
Detailed usage lives in submodules:

* :mod:`guardiabox.core`         — crypto primitives, container format, KDFs.
* :mod:`guardiabox.fileio`       — safe path handling and atomic I/O.
* :mod:`guardiabox.security`     — password validation, keystore, audit log.
* :mod:`guardiabox.persistence`  — SQLAlchemy + SQLCipher data access.
* :mod:`guardiabox.ui`           — CLI, TUI, and Tauri sidecar adapters.
"""

from __future__ import annotations

__version__: str = "0.1.0"
__all__: list[str] = ["__version__"]
