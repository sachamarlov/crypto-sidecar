# GuardiaBox Frontend

Tauri 2 + React 19 + Vite + Tailwind v4 + shadcn/ui frontend.

## Quickstart

```bash
pnpm install
pnpm dev            # Vite only (no Tauri shell)
pnpm tauri dev      # full Tauri development (shell + Vite + sidecar)
pnpm build          # production static bundle
pnpm tauri build    # production .exe (Windows)
```

The Rust shell lives at `../src-tauri`. See `../../../../docs/DEVELOPMENT.md`
for the full setup.
