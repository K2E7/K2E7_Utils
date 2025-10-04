# K2E7_Utils

A growing toolkit of Python command-line utilities that streamline everyday
developer workflows, automation tasks, and environment setup. Every script in
this repository is something I actually use, so the focus is on practical
features, predictable behaviour, and simple installation.

## Table of Contents

- [Overview](#overview)
- [Utilities in This Repo](#utilities-in-this-repo)
- [Quick Start](#quick-start)
- [Installing Utilities with CLINTON](#installing-utilities-with-clinton)
- [Personal Notes](#personal-notes)
- [Contributing](#contributing)

## Overview

K2E7_Utils bundles a set of cross-platform Python utilities focused on:

- **Command-line productivity** – reusable scripts for common system tasks.
- **One-command installation** – drop local tools anywhere on `PATH` without
  manual copying.
- **Safe defaults** – dry-run modes and confirmation flags designed to prevent
  accidental data loss.

Each utility lives in its own subdirectory with source code and (where helpful)
a dedicated README.

This project is relevant for:

- Python developer utilities and CLI tools
- Script installer for Linux, macOS, and Windows
- Personal automation scripts, shell productivity, and PATH management
- Cross-platform Python automation, developer experience enhancements, and
  command deployment

## Utilities in This Repo

| Utility | Description |
| --- | --- |
| [`clinton`](clinton/README.md) | Script installer that copies/wraps local tools into a writable `PATH` directory and optionally updates shell or Windows PATH entries. Ideal for promoting personal scripts to global commands without root access. |

I continue to add new scripts as they mature. Bookmark this repo or watch it to
stay updated on fresh automation helpers, shell commands, and Python utilities.

## Quick Start

```bash
git clone https://github.com/K2E7/K2E7_Utils.git
cd K2E7_Utils

# inspect available commands
python clinton/clinton.py --help

# install a utility globally (dry run first)
python clinton/clinton.py install clinton/hello.py --dry-run

# apply the installation
python clinton/clinton.py install clinton/hello.py
```

All scripts target Python 3.8+ and rely solely on the standard library.

## Installing Utilities with CLINTON

CLINTON is the heart of this repo. It provides:

- **Platform-aware installation** – Bash wrappers on Linux/macOS, CMD/PowerShell
  shims on Windows.
- **PATH management** – appends exports to `~/.bashrc`, `~/.zshrc`, or edits the
  Windows user PATH when requested.
- **Verbose dry runs** – understand exactly what will be copied, wrapped, or
  removed before committing changes.
- **Nothing-inspired logging** – geometric glyphs like `[##] done` and `[::] path`
  make terminal output easy to scan.

Refer to [`clinton/README.md`](clinton/README.md) for full documentation,
including command examples and logging conventions.

## Personal Notes

A collection of utilities I personally developed and use for my own work.

Also includes a generic installer that 'installs' said utils in the system to be
called from any directory/folder and does the intended function.

For the sake of not running it mistakenly none of the utils will execute on just
being called, one would need to add flags to make them work ( I find it useful
to add this breaker as I can subconsciously delete something useful ). Calling
the script explicitly just shows what flags it supports.

## Contributing

These are personal tools, but suggestions and issues are welcome. If you extend
the utilities, please keep `pylint` happy (the repo currently holds a 10/10
score) and document any new scripts so others can benefit from them too.
