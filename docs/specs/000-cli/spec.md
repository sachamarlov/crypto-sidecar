# 000 — CLI (Typer)

- Status: draft
- Owner: Claude Opus 4.7 (implementation), @sachamarlov (review)
- Tracks: CDC obligation "interface utilisateur en mode console"

## Behaviour

`guardiabox` is the CLI entry point installed by the `[project.scripts]`
section of `pyproject.toml`. It exposes the canonical operations of the
vault as composable commands, suitable for both interactive use and
shell scripting.

The CDC explicitly requires a "console menu" with at least three
options (encrypt / decrypt / quit). The CLI satisfies this either via:

- direct subcommands (`guardiabox encrypt FILE`), or
- an interactive menu (`guardiabox menu`) that loops on input.

## Acceptance criteria (Gherkin)

```gherkin
Scenario: Top-level help shows every command
  When I run "guardiabox --help"
  Then the output lists at least: init, encrypt, decrypt, share, accept,
       secure-delete, user, history, sync, config, doctor, menu

Scenario: Interactive console menu (CDC compliance path)
  When I run "guardiabox menu"
  Then the screen shows numbered choices: 1 Encrypt, 2 Decrypt, 3 Quit
  And selecting "1" prompts for a path
  And selecting "3" exits with code 0

Scenario: Strict POSIX exit codes
  Given any failed operation
  When the CLI exits
  Then the exit code follows the convention
       (0 success, 1 generic error, 2 wrong password, 3 file not found,
        130 SIGINT, others per `sysexits.h`)

Scenario: Machine-readable output
  Given any read command (list, history, info)
  When invoked with `--json`
  Then stdout is valid JSON parsable by `jq`
  And human-friendly noise (colors, progress bars) is suppressed

Scenario: --quiet / --verbose toggles work consistently
  When I run any command with `--quiet`
  Then no progress bar / spinner / debug log appears on stdout
  And errors still go to stderr with the proper exit code
```

## Out of scope (future)

- `guardiabox completion bash|zsh|fish` shell completion (nice-to-have).
- TUI menu (covered in spec `000-tui`).
- Auto-update channel (`guardiabox update`) — depends on the release
  pipeline post-CDC.
