# GuardiaBox developer recipes.
# Install: `cargo install just` (or `scoop install just` / `brew install just`).
# Usage:   `just <recipe>` — for example `just dev`, `just lint`, `just test`.

# Default recipe: list all available recipes.
default:
    @just --list

# === Setup ==================================================================

# One-shot environment bootstrap.
setup: setup-python setup-frontend setup-precommit
    @echo "Environment ready."

setup-python:
    uv sync --all-extras

setup-frontend:
    pnpm --dir src/guardiabox/ui/tauri/frontend install

setup-precommit:
    uv run pre-commit install --install-hooks

# === Python =================================================================

# Run the CLI: `just cli encrypt foo.txt`.
cli *ARGS:
    uv run guardiabox {{ARGS}}

# Run the TUI.
tui:
    uv run guardiabox-tui

# Run the sidecar in the foreground (for debugging).
sidecar:
    uv run guardiabox-sidecar

# Run the test suite.
test *ARGS:
    uv run pytest {{ARGS}}

# Run only the property-based tests.
test-property:
    uv run pytest -m property

# Lint Python.
lint-py:
    uv run ruff check .
    uv run ruff format --check .
    uv run mypy src
    uv run bandit -c pyproject.toml -r src -q

# Auto-fix what can be auto-fixed.
fmt-py:
    uv run ruff check --fix .
    uv run ruff format .

# === Frontend ==============================================================

dev:
    pnpm --dir src/guardiabox/ui/tauri/frontend dev

tauri-dev:
    pnpm --dir src/guardiabox/ui/tauri/frontend tauri dev

build-frontend:
    pnpm --dir src/guardiabox/ui/tauri/frontend build

build-tauri:
    pnpm --dir src/guardiabox/ui/tauri/frontend tauri build

lint-fe:
    pnpm --dir src/guardiabox/ui/tauri/frontend lint

fmt-fe:
    pnpm --dir src/guardiabox/ui/tauri/frontend lint:fix

test-fe:
    pnpm --dir src/guardiabox/ui/tauri/frontend test

test-e2e:
    pnpm --dir src/guardiabox/ui/tauri/frontend test:e2e

# === Rust ===================================================================

lint-rs:
    cd src/guardiabox/ui/tauri/src-tauri && cargo fmt --all -- --check
    cd src/guardiabox/ui/tauri/src-tauri && cargo clippy --all-targets --all-features -- -D warnings

# === Build & distribute ====================================================

# Bundle the Python sidecar into a standalone executable.
build-sidecar:
    uv run python scripts/build_sidecar.py

# Generate placeholder Tauri icons (use until real artwork lands).
icons:
    uv run python scripts/generate_placeholder_icons.py

# === Pre-commit ============================================================

pc:
    uv run pre-commit run --all-files

# === Docs ==================================================================

docs-serve:
    uv run mkdocs serve

docs-build:
    uv run mkdocs build --strict

# === Cleanup ===============================================================

clean:
    rm -rf .pytest_cache .mypy_cache .ruff_cache .ty_cache htmlcov coverage.xml
    rm -rf src/guardiabox/ui/tauri/frontend/node_modules
    rm -rf src/guardiabox/ui/tauri/frontend/dist/assets
    rm -rf src/guardiabox/ui/tauri/src-tauri/target
    find . -type d -name "__pycache__" -prune -exec rm -rf {} +
