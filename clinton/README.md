# CLINTON

CLI helper for promoting local scripts to globally available commands. It drops
shims or copies into a writable directory on `PATH` and can optionally patch
your shell RC file (or user PATH on Windows) so commands are immediately
discoverable.

The tool ships inside this repository at `clinton/clinton.py` and is
self-contained—no dependencies beyond the Python standard library.

## Quick Start

```bash
# dry-run install everything discoverable in the current directory
python clinton.py --dry-run --verbose

# install a specific script with a custom command name
python clinton.py install --name greet clinton/hello.py

# preview the exported PATH line without writing anything
python clinton.py install clinton/hello.py --print-path-change

# uninstall the command (dry run keeps the files on disk)
python clinton.py uninstall greet --dry-run --verbose
```

Invoke `python clinton.py --help` (or `./clinton.py --help` on Unix after
marking it executable) to see the complete top-level usage, examples, and global
aliases.

## Commands & Flags

CLINTON exposes two subcommands. Omitting the subcommand defaults to `install`.

### `install`

```
python clinton.py install [paths|globs|bare names]
```

Recognizes `.py`, shell scripts, batch/PowerShell scripts, and any file with a
shebang. Bare names resolve against the current directory, with extensions
auto-guessed.

Key flags:

- `--source [PATH ...]` — list the files/globs explicitly (instead of scanning).
- `--name NAME` — override the command name (only valid with a single source).
- `--dry-run` — print the actions without copying or touching PATH.
- `--verbose` — show debug lines for every copy, write, or removal decision.
- `--no-path` — skip updating shell/user PATH entirely.
- `--print-path-change` — emit the would-be PATH mutation but do not apply it.
- `items` (positional) — extra script paths or bare names to install.

On Unix, CLINTON copies or wraps scripts into a writable bin directory (prefers
`~/.local/bin` or the first writable entry on `PATH`). For Python scripts lacking
a shebang, it writes a small Bash wrapper. On Windows it copies the payload into
`%LOCALAPPDATA%/any_cli/<name>` and creates `.cmd` + `.ps1` shims in a writable
directory from the current `PATH`.

### `uninstall`

```
python clinton.py uninstall <name>
```

Removes shims/payloads for the given command name and optionally prunes PATH
entries that were added during installation.

Flags:

- `--dry-run` — show the files and directories that would be deleted.
- `--verbose` — log every discovered shim/target and removal attempt.
- `--purge` — (Windows) delete `%LOCALAPPDATA%/any_cli/<name>` payload folders.
- `--keep-path` — skip removing PATH exports/shims even if they are found.

### Top-Level Aliases

Running `clinton.py` without a subcommand still accepts the install flags for
backward compatibility. For example, `python clinton.py --dry-run` is shorthand
for `python clinton.py install --dry-run`.

## Logging Style

Output follows a Nothing-inspired geometric tag system:

- `[##] done` — successful installs/uninstalls.
- `[..] info` — state changes and next steps (e.g., “open a new terminal”).
- `[::] path` — PATH-specific operations.
- `[!!] warn` / `[xx] fail` — problems or missing files.
- `[..] debug` — verbose mode diagnostics (copy/write/remove details).

This makes it easy to scan for results even when performing batch installs or
dry runs.

## Tips

- Want a quick preview of what will be installed? Run with `--dry-run` first to
  ensure only the expected scripts are touched.
- After CLINTON updates your shell RC file on Unix, open a new shell or
  `source` the file noted in the log to make the commands immediately available.
- On Windows, the PowerShell snippets the script executes require PowerShell to
  be on `PATH`. If it is missing, the tool will report that the PATH update
  could not be applied.

## Contributing

This repository collects personal utilities, but feel free to adapt CLINTON for
your own setup. The script is linted with `pylint`, and the repo retains a clean
10/10 rating—please keep it that way if you extend the functionality.
