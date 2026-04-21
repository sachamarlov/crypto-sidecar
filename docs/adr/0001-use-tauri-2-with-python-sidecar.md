# 0001 — Use Tauri 2 with a Python sidecar for the desktop GUI

- Status: accepted
- Date: 2026-04-20
- Deciders: @sachamarlov, Claude Opus 4.7
- Tags: [architecture, ui, distribution]

## Context and problem statement

The academic brief mentions PyQt6 as an _example_ extension for the GUI but
does not impose it. We want the user-facing experience to look and feel like
a modern 2026 desktop product (Linear, Notion, 1Password 8, Spotify), while
keeping the cryptographic core in Python (which the brief evaluates).

## Considered options

- **A. Tauri 2 + React + Python sidecar** — modern UI via WebView2; Python
  sidecar handles all crypto/persistence; loopback HTTP between shell and
  sidecar.
- **B. PySide6 + qfluentwidgets** — pure-Python Qt with Fluent Design widgets;
  CDC-aligned; visually decent (Windows 11 native style).
- **C. Flet (Flutter)** — modern Material Design 3; sub-50 ms latency
  caveats; sits outside the Qt mention in the CDC.
- **D. Pywebview + React** — embed WebView2 from Python; simpler than Tauri
  but a smaller ecosystem and less hardened sandbox.

| Criterion                 | A (Tauri)                        | B (PySide6) | C (Flet)   | D (Pywebview) |
| ------------------------- | -------------------------------- | ----------- | ---------- | ------------- |
| Visual modernity          | ★★★★★                            | ★★★         | ★★★★       | ★★★★★         |
| Component library breadth | shadcn/Aceternity ≈ 5 000+       | ~80 Fluent  | ~300 Flet  | shadcn        |
| Distributable size        | 10–15 MiB                        | 35–45 MiB   | 50–60 MiB  | 30–40 MiB     |
| Hot reload in dev         | Vite < 50 ms                     | restart     | OK         | Vite          |
| Sandbox by default        | Strict CSP, allowlisted commands | n/a         | n/a        | weaker        |
| CDC conformance           | Python crypto via sidecar        | Strict Qt   | Outside Qt | Strict Python |
| Auto-updater              | tauri-plugin-updater             | manual      | manual     | manual        |

## Decision

Adopt **option A**. The Python sidecar is bundled with PyInstaller and
embedded into the Tauri binary. Communication is loopback HTTP plus a
per-launch session token printed to stdout.

## Consequences

**Positive**

- The UI ceiling is the entire React/Tailwind/shadcn ecosystem.
- The crypto code stays 100 % Python (CDC compliance).
- Distributable is the smallest among credible options (≈ 15 MiB shell + 25
  MiB sidecar = ~40 MiB compressed).
- Hardened by default — Tauri's allowlist + CSP eliminate the most common
  Electron-style escape vectors.

**Negative**

- Adds Rust to the toolchain (managed by the AI agent; the human user does
  not need to learn Rust).
- Two-process model requires careful IPC engineering (mitigated by ADR-0009,
  the session-token scheme).
- Slightly higher cold-start (browser process spawn) than a pure Qt window;
  acceptable per NFR-3 (≤ 1.5 s).

## References

- Tauri 2 sidecar pattern — https://v2.tauri.app/develop/sidecar/
- Tauri vs Electron 2026 — https://tech-insider.org/tauri-vs-electron-2026/
- Building production Tauri + FastAPI + PyInstaller — https://aiechoes.substack.com/p/building-production-ready-desktop
