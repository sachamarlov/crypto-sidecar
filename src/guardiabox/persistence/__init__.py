"""SQLCipher-backed persistence (SQLAlchemy 2.0 async).

The database stores: users (with their wrapped keys), per-file metadata
(filename, size, owner, KDF used, sharing tokens), and the audit log.
**Never** the plaintext content of files — that lives only in the .crypt
files on disk.
"""
