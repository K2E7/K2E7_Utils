#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CLINTON
Install or uninstall local scripts as global commands by placing/removing shims in a
writable directory on PATH and (optionally) updating PATH.

Features:
- Supports .py, .sh/.bash/.zsh, .bat/.cmd, .ps1, and files with a shebang.
- Linux/macOS: copies script (or wraps .py without shebang) and updates shell rc file.
- Windows: copies script to %LOCALAPPDATA% and writes .cmd/.ps1 shims; can remove them.

Subcommands:
- install   (default if omitted): previous behavior
- uninstall: remove a command by name across typical locations
"""

from __future__ import annotations

import argparse
import glob
import logging
import os
import platform
import shutil
import stat
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Tuple

RECOGNIZED_EXTS = {".py", ".sh", ".bash", ".zsh", ".bat", ".cmd", ".ps1"}


LOGGER = logging.getLogger("clinton")


def configure_logging(verbose: bool) -> None:
    """Configure root logger for the CLI."""
    level = logging.DEBUG if verbose else logging.INFO
    formatter = logging.Formatter("%(message)s")

    if LOGGER.handlers:
        LOGGER.setLevel(level)
        for handler in LOGGER.handlers:
            handler.setLevel(level)
            handler.setFormatter(formatter)
        return

    handler = logging.StreamHandler()
    handler.setLevel(level)
    handler.setFormatter(formatter)
    LOGGER.addHandler(handler)
    LOGGER.setLevel(level)
    LOGGER.propagate = False


# ---------- small utils ----------


def debug(msg: str, enabled: bool) -> None:
    """Print debug logs when enabled."""
    if enabled:
        LOGGER.debug("[DEBUG] %s", msg)


def is_writable_dir(p: Path) -> bool:
    """Return True if directory is writable (creating it if needed)."""
    try:
        p.mkdir(parents=True, exist_ok=True)
        test = p / ".perm_test"
        test.write_text("ok", encoding="utf-8")
        test.unlink(missing_ok=True)
        return True
    except (OSError, PermissionError):
        return False


def ensure_executable(p: Path) -> None:
    """Mark a file executable on Unix."""
    try:
        mode = p.stat().st_mode
        p.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except (OSError, PermissionError):
        pass


def has_shebang(src: Path) -> bool:
    """Return True if file starts with #! (shebang)."""
    try:
        with src.open("rb") as f:
            return f.read(2) == b"#!"
    except (OSError, IOError):
        return False


def write_text(p: Path, text: str) -> None:
    """Write text to a file, creating parents as needed."""
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def guess_command_name(src: Path) -> str:
    """Derive command name from filename stem."""
    return src.stem


# ---------- path discovery ----------


def pick_unix_bindir() -> Path:
    """Pick a sensible bin dir for Unix: prefer ~/.local/bin or a writable PATH entry."""
    xdg = os.environ.get("XDG_BIN_HOME")
    candidates: List[Path] = []
    if xdg:
        candidates.append(Path(xdg).expanduser())
    candidates.append(Path.home() / ".local" / "bin")

    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if not entry:
            continue
        p = Path(entry).expanduser()
        if is_writable_dir(p):
            candidates.append(p)

    candidates.append(Path("/usr/local/bin"))
    for c in candidates:
        if is_writable_dir(c):
            return c
    return Path.home() / ".local" / "bin"


def pick_windows_bindir() -> Path:
    """Pick a writable directory from PATH for Windows shims; fallback to ~/bin."""
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if not entry:
            continue
        p = Path(entry).expanduser()
        if is_writable_dir(p):
            return p
    return Path.home() / "bin"


# ---------- source collection ----------


def expand_sources(args_sources: Iterable[str]) -> List[Path]:
    """Expand file/glob patterns into unique resolved Paths."""
    paths: List[Path] = []
    for pattern in args_sources:
        matches = [Path(m) for m in glob.glob(pattern)]
        if not matches:
            cand = Path(pattern)
            if cand.exists():
                matches = [cand]
        for m in matches:
            if m.is_file():
                paths.append(m.resolve())
    unique: List[Path] = []
    seen = set()
    for p in paths:
        if p not in seen:
            unique.append(p)
            seen.add(p)
    return unique


def discover_in_cwd() -> List[Path]:
    """Find recognizable scripts in the current working directory."""
    cwd = Path.cwd()
    found: List[Path] = []
    for p in cwd.iterdir():
        if p.is_file() and (p.suffix.lower() in RECOGNIZED_EXTS or has_shebang(p)):
            found.append(p.resolve())
    return found


# ---------- installers (Unix) ----------


def install_unix_py_or_wrap(
    src: Path, target: Path, *, dry_run: bool, verbose: bool
) -> str:
    """Install a .py file; if no shebang, write a tiny wrapper."""
    if src.suffix.lower() == ".py" and not has_shebang(src):
        wrapper = f'#!/usr/bin/env bash\npython3 "{src}" "$@"\n'
        if not dry_run:
            write_text(target, wrapper)
            ensure_executable(target)
        debug(f"[WRITE] Wrapper -> {target}", verbose)
        return "wrapper"
    if not dry_run:
        shutil.copy2(src, target)
        ensure_executable(target)
    debug(f"[COPY] {src} -> {target}", verbose)
    return "copy"


def install_unix(
    src: Path, name: str, *, dry_run: bool, verbose: bool
) -> Tuple[Path, str]:
    """Install a script on Unix-like OS. Returns (target_path, action)."""
    bindir = pick_unix_bindir()
    target = bindir / name
    action = install_unix_py_or_wrap(src, target, dry_run=dry_run, verbose=verbose)
    return target, action


# ---------- installers (Windows) ----------


def _windows_core_copy(
    src: Path, name: str, *, dry_run: bool, verbose: bool
) -> Tuple[Path, Path]:
    """Copy source into LOCALAPPDATA\\any_cli\\<name>\\ and return (root, dst)."""
    root = (
        Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        / "any_cli"
        / name
    )
    if not dry_run:
        root.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, root / src.name)
    debug(f"[COPY] {src} -> {root / src.name}", verbose)
    return root, root / src.name


def _win_write_cmd_ps1(
    cmd_path: Path,
    ps1_path: Path,
    contents: tuple[str, str],
    *,
    dry_run: bool,
    verbose: bool,
) -> None:
    """Write the CMD/PS1 shim pair."""
    cmd_content, ps1_content = contents
    if not dry_run:
        write_text(cmd_path, cmd_content)
        write_text(ps1_path, ps1_content)
    debug(f"[WRITE] {cmd_path}", verbose)
    debug(f"[WRITE] {ps1_path}", verbose)


def _shim_for_bat(
    dst: Path, bindir: Path, *, dry_run: bool, verbose: bool
) -> Tuple[Path, str]:
    """Create shims for .bat/.cmd targets."""
    cmd_path, ps1_path = bindir / f"{dst.stem}.cmd", bindir / f"{dst.stem}.ps1"
    _win_write_cmd_ps1(
        cmd_path,
        ps1_path,
        (
            f'@echo off\r\n"{dst}" %*\r\n',
            f'Start-Process -FilePath "{dst}" -ArgumentList $args -NoNewWindow -Wait\r\n',
        ),
        dry_run=dry_run,
        verbose=verbose,
    )
    return cmd_path, "cmd-shim"


def _shim_for_ps1(
    dst: Path, bindir: Path, *, dry_run: bool, verbose: bool
) -> Tuple[Path, str]:
    """Create shims for .ps1 targets."""
    cmd_path, ps1_path = bindir / f"{dst.stem}.cmd", bindir / f"{dst.stem}.ps1"
    if not dry_run:
        write_text(ps1_path, f'#!/usr/bin/env pwsh\r\n& "{dst}" @args\r\n')
        write_text(
            cmd_path,
            f"@echo off\r\npowershell -ExecutionPolicy Bypass "
            f'-File "{ps1_path}" %*\r\n',
        )
    debug(f"[WRITE] {ps1_path}", verbose)
    debug(f"[WRITE] {cmd_path}", verbose)
    return ps1_path, "ps1-shim"


def _shim_for_py(
    dst: Path, bindir: Path, *, dry_run: bool, verbose: bool
) -> Tuple[Path, str]:
    """Create shims for .py targets."""
    cmd_path, ps1_path = bindir / f"{dst.stem}.cmd", bindir / f"{dst.stem}.ps1"
    _win_write_cmd_ps1(
        cmd_path,
        ps1_path,
        (
            f'@echo off\r\npython "{dst}" %*\r\n',
            f'# PowerShell shim\r\npython "{dst}" $args\r\n',
        ),
        dry_run=dry_run,
        verbose=verbose,
    )
    return cmd_path, "py-shim"


def _shim_for_sh(
    dst: Path, bindir: Path, *, dry_run: bool, verbose: bool
) -> Tuple[Path, str]:
    """Create shims for POSIX shell targets."""
    cmd_path, ps1_path = bindir / f"{dst.stem}.cmd", bindir / f"{dst.stem}.ps1"
    _win_write_cmd_ps1(
        cmd_path,
        ps1_path,
        (
            f'@echo off\r\nbash "{dst}" %*\r\n',
            f'# PowerShell shim\r\nbash "{dst}" $args\r\n',
        ),
        dry_run=dry_run,
        verbose=verbose,
    )
    return cmd_path, "bash-shim"


def _shim_generic(
    dst: Path, bindir: Path, *, dry_run: bool, verbose: bool
) -> Tuple[Path, str]:
    """Fallback shim for other file types."""
    cmd_path = bindir / f"{dst.stem}.cmd"
    if not dry_run:
        write_text(
            cmd_path,
            f"@echo off\r\npowershell -ExecutionPolicy Bypass " f'-File "{dst}" %*\r\n',
        )
    debug(f"[WRITE] {cmd_path}", verbose)
    return cmd_path, "generic-shim"


def install_windows(
    src: Path, name: str, *, dry_run: bool, verbose: bool
) -> Tuple[Path, str]:
    """Install a script on Windows. Returns (shim_path, how)."""
    bindir = pick_windows_bindir()
    _, dst = _windows_core_copy(src, name, dry_run=dry_run, verbose=verbose)

    ext = src.suffix.lower()
    handlers: Dict[str, Callable[[Path, Path], Tuple[Path, str]]] = {
        ".bat": lambda d, b: _shim_for_bat(d, b, dry_run=dry_run, verbose=verbose),
        ".cmd": lambda d, b: _shim_for_bat(d, b, dry_run=dry_run, verbose=verbose),
        ".ps1": lambda d, b: _shim_for_ps1(d, b, dry_run=dry_run, verbose=verbose),
        ".py": lambda d, b: _shim_for_py(d, b, dry_run=dry_run, verbose=verbose),
        ".sh": lambda d, b: _shim_for_sh(d, b, dry_run=dry_run, verbose=verbose),
        ".bash": lambda d, b: _shim_for_sh(d, b, dry_run=dry_run, verbose=verbose),
        ".zsh": lambda d, b: _shim_for_sh(d, b, dry_run=dry_run, verbose=verbose),
    }

    creator = handlers.get(
        ext, lambda d, b: _shim_generic(d, b, dry_run=dry_run, verbose=verbose)
    )
    shim, how = creator(dst, bindir)
    return shim, how


# ---------- PATH handling ----------


def _line_to_add(bindir: Path) -> str:
    """Shell line to append to rc files."""
    return f'export PATH="{bindir}":$PATH'


def _choose_rc_file() -> Path:
    """Pick a reasonable rc file based on current shell and existing files."""
    shell = os.environ.get("SHELL", "")
    home = Path.home()
    if shell.endswith("zsh"):
        return home / ".zshrc"
    if shell.endswith("bash"):
        return home / ".bashrc"
    for cand in (home / ".bashrc", home / ".zshrc"):
        if cand.exists():
            return cand
    return home / ".profile"


def add_to_path_unix(bindir: Path, *, verbose: bool) -> Tuple[bool, Path, str]:
    """Ensure bindir is in PATH by appending an export to a shell rc file."""
    target_rc = _choose_rc_file()
    target_rc.parent.mkdir(parents=True, exist_ok=True)
    line = _line_to_add(bindir)

    try:
        if target_rc.exists():
            content = target_rc.read_text(encoding="utf-8")
            if line in content:
                debug(f"[PATH] Already present in {target_rc}", verbose)
                return False, target_rc, line
    except (OSError, IOError):
        pass

    try:
        with target_rc.open("a", encoding="utf-8") as f:
            if target_rc.exists() and target_rc.stat().st_size > 0:
                f.write("\n")
            f.write("# Added by CLINTON to expose installed CLIs\n")
            f.write(line + "\n")
        debug(f"[PATH] Appended to {target_rc}: {line}", verbose)
        return True, target_rc, line
    except (OSError, IOError, PermissionError):
        return False, target_rc, line


def add_to_path_windows(bindir: Path, *, verbose: bool) -> Tuple[bool, str]:
    """Add bindir to the user PATH on Windows using PowerShell."""
    ps_script = r"""
$dir = $args[0]
$curr = [Environment]::GetEnvironmentVariable('PATH', 'User')
if ($curr -and ($curr.Split([IO.Path]::PathSeparator) -contains $dir)) {
  Write-Output 'NOCHANGE'
} else {
  $new = if ($curr) { $curr + [IO.Path]::PathSeparator + $dir } else { $dir }
  [Environment]::SetEnvironmentVariable('PATH', $new, 'User')
  Write-Output 'CHANGED'
}
""".strip()

    try:
        res = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                ps_script,
                str(bindir),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        out = (res.stdout or "").strip()
        if "CHANGED" in out:
            debug(f"[PATH] User PATH updated with {bindir}", verbose)
            return True, "CHANGED"
        if "NOCHANGE" in out:
            debug("[PATH] Already present on PATH", verbose)
            return False, "NOCHANGE"
        return False, out or "UNKNOWN"
    except (FileNotFoundError, OSError) as e:
        return False, f"PowerShell unavailable: {e}"


def remove_from_path_unix(bindir: Path, *, verbose: bool) -> bool:
    """Remove the specific export line for bindir from the rc file."""
    target_rc = _choose_rc_file()
    line = _line_to_add(bindir)
    if not target_rc.exists():
        return False

    try:
        lines = target_rc.read_text(encoding="utf-8").splitlines()
    except (OSError, IOError):
        return False

    new_lines: List[str] = []
    removed = False
    for ln in lines:
        if ln.strip() == line.strip():
            removed = True
            # If previous line is our marker comment, drop it too.
            if new_lines and new_lines[-1].strip().startswith("# Added by CLINTON"):
                new_lines.pop()
            continue
        new_lines.append(ln)

    if removed:
        try:
            target_rc.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
            debug(f"[PATH] Removed PATH entry from {target_rc}", verbose)
            return True
        except (OSError, IOError, PermissionError):
            return False
    return False


def remove_from_path_windows(bindir: Path, *, verbose: bool) -> bool:
    """Remove bindir from Windows user PATH."""
    ps_script = r"""
$dir = $args[0]
$curr = [Environment]::GetEnvironmentVariable('PATH', 'User')
if (-not $curr) { Write-Output 'NOCHANGE'; exit 0 }
$parts = $curr.Split([IO.Path]::PathSeparator) | Where-Object { $_ -ne $dir }
$new = ($parts -join [IO.Path]::PathSeparator)
[Environment]::SetEnvironmentVariable('PATH', $new, 'User')
Write-Output 'REMOVED'
""".strip()

    try:
        res = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                ps_script,
                str(bindir),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        out = (res.stdout or "").strip()
        if "REMOVED" in out:
            debug(f"[PATH] Removed {bindir} from user PATH", verbose)
            return True
    except (FileNotFoundError, OSError):
        return False
    return False


# ---------- uninstall helpers ----------


def _paths_on_path() -> List[Path]:
    """Return all existing directories from PATH."""
    result: List[Path] = []
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if entry:
            p = Path(entry).expanduser()
            if p.exists():
                result.append(p)
    return result


def find_unix_targets(name: str) -> List[Path]:
    """Find possible Unix targets for 'name' in common bin dirs and on PATH."""
    candidates: List[Path] = []
    for d in [pick_unix_bindir(), Path("/usr/local/bin")]:
        candidates.append(d / name)
    for d in _paths_on_path():
        candidates.append(d / name)
    seen, out = set(), []
    for p in candidates:
        if p.exists() and p not in seen:
            out.append(p)
            seen.add(p)
    return out


def find_windows_shims(name: str) -> List[Path]:
    """Find Windows shims named name.cmd / name.ps1 across PATH."""
    out: List[Path] = []
    for d in _paths_on_path():
        cmd = d / f"{name}.cmd"
        ps1 = d / f"{name}.ps1"
        if cmd.exists():
            out.append(cmd)
        if ps1.exists():
            out.append(ps1)
    return out


def windows_payload_dir(name: str) -> Path:
    """Return %LOCALAPPDATA%\\any_cli\\<name> directory (may not exist)."""
    return (
        Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        / "any_cli"
        / name
    )


def safe_remove(p: Path, *, verbose: bool, dry_run: bool) -> bool:
    """Remove file or directory tree safely. Returns True if removed."""
    try:
        if dry_run:
            debug(f"[RM] Would remove {p}", verbose)
            return p.exists()
        if p.is_dir():
            shutil.rmtree(p, ignore_errors=True)
            debug(f"[RM] rmtree {p}", verbose)
            return True
        if p.exists():
            p.unlink(missing_ok=True)
            debug(f"[RM] unlink {p}", verbose)
            return True
    except (OSError, PermissionError) as e:
        LOGGER.warning("⚠️  Could not remove %s: %s", p, e)
    return False


def resolve_name_in_cwd(name: str) -> Path:
    """Resolve a bare NAME to a file in CWD."""
    cwd = Path.cwd()
    cand = cwd / name
    if cand.is_file():
        return cand.resolve()
    for ext in RECOGNIZED_EXTS:
        p = cwd / f"{name}{ext}"
        if p.is_file():
            return p.resolve()
    for p in cwd.glob(f"{name}.*"):
        if p.is_file() and (p.suffix.lower() in RECOGNIZED_EXTS or has_shebang(p)):
            return p.resolve()
    raise FileNotFoundError(f"No script named '{name}' found in {cwd}")


# ---------- main orchestration ----------


def parse_args() -> argparse.Namespace:
    """Parse and return CLI arguments (with subcommands)."""
    prog = Path(__file__).name
    description = textwrap.dedent(
        f"""\
        Install or uninstall local scripts as global commands by adding shims to PATH.

        Without a subcommand this behaves like `{prog} install`.

        Examples:
          {prog} hello.py
          {prog} install --name greet scripts/hello.py
          {prog} uninstall greet
        """
    )
    epilog = f"Run `{prog} install --help` or `{prog} uninstall --help` for details."

    ap = argparse.ArgumentParser(
        prog=prog,
        description=description,
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = ap.add_subparsers(dest="cmd", metavar="command")

    # install
    ap_i = sub.add_parser(
        "install",
        help="Install one or more scripts (default command).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Install scripts into a writable bin directory and update PATH.",
    )
    ap_i.add_argument(
        "--source",
        nargs="*",
        help="Files or globs to install. " "If omitted, scan current directory.",
    )
    ap_i.add_argument("--name", help="Override command name (only for single source).")
    ap_i.add_argument(
        "--dry-run", action="store_true", help="Print actions, do not write."
    )
    ap_i.add_argument("--verbose", action="store_true", help="Verbose output.")
    ap_i.add_argument("--no-path", action="store_true", help="Do not modify PATH.")
    ap_i.add_argument(
        "--print-path-change",
        action="store_true",
        help="Print the PATH export line or intended Windows change without applying.",
    )
    ap_i.add_argument(
        "items",
        nargs="*",
        help="Positional script names/paths. Bare NAME resolves in CWD.",
    )

    # uninstall
    ap_u = sub.add_parser(
        "uninstall",
        help="Uninstall a command by name.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Remove installed shims and clean up PATH entries.",
    )
    ap_u.add_argument("name", help="Command name to uninstall (e.g., 'hello').")
    ap_u.add_argument(
        "--dry-run", action="store_true", help="Show what would be removed."
    )
    ap_u.add_argument("--verbose", action="store_true", help="Verbose output.")
    ap_u.add_argument(
        "--purge",
        action="store_true",
        help="Also remove the Windows payload dir under "
        "LOCALAPPDATA/any_cli/<name>.",
    )
    ap_u.add_argument(
        "--keep-path",
        action="store_true",
        help="Do NOT remove the PATH entry that was added on install.",
    )

    # Back-compat: if no subcommand, treat as install
    ap.add_argument("--source", nargs="*", help=argparse.SUPPRESS)
    ap.add_argument("--name", help=argparse.SUPPRESS)
    ap.add_argument("--dry-run", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--verbose", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--no-path", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--print-path-change", action="store_true", help=argparse.SUPPRESS)

    return ap.parse_args()


def collect_sources(args: argparse.Namespace) -> List[Path]:
    """Build the list of source files to install from args or CWD."""
    srcs = getattr(args, "source", None)
    items = (
        getattr(args, "items", None)
        if getattr(args, "cmd", None) == "install"
        else None
    )

    sources: List[Path] = []
    if srcs:
        sources.extend(expand_sources(srcs))

    if items:
        expanded = expand_sources(items)
        # Anything not resolved by glob/path gets resolved as bare name in CWD
        unresolved: List[str] = []
        for token in items:
            p = Path(token)
            if p.exists() or any(str(pth).endswith(token) for pth in expanded):
                continue
            unresolved.append(token)
        sources.extend(expanded)
        for token in unresolved:
            sources.append(resolve_name_in_cwd(token))

    if sources:
        uniq, seen = [], set()
        for p in sources:
            rp = p.resolve()
            if rp not in seen:
                uniq.append(rp)
                seen.add(rp)
        return uniq

    sources = discover_in_cwd()
    if not sources:
        LOGGER.error("[ERROR] No recognizable scripts in current directory.")
        sys.exit(2)
    return sources


def install_all(
    sources: List[Path], *, name_override: str | None, dry_run: bool, verbose: bool
) -> Path | None:
    """Install each source and return the last target directory used for PATH updates."""
    system = platform.system().lower()
    LOGGER.info("ℹ️  OS: %s, installing %d script(s)", system, len(sources))
    if name_override and len(sources) != 1:
        LOGGER.error(
            "[ERROR] --name can only be used when installing a single source file."
        )
        sys.exit(2)

    last_target_dir: Path | None = None
    for src in sources:
        if not src.exists():
            LOGGER.warning("⚠️  Skipping missing source: %s", src)
            continue
        name = name_override or guess_command_name(src)
        if system.startswith("win"):
            target, how = install_windows(src, name, dry_run=dry_run, verbose=verbose)
        else:
            target, how = install_unix(src, name, dry_run=dry_run, verbose=verbose)
        last_target_dir = Path(target).parent
        LOGGER.info("✅ %s -> %s (%s)", name, target, how)
    return last_target_dir


def apply_path_change(
    last_dir: Path | None,
    *,
    dry_run: bool,
    print_only: bool,
    no_path: bool,
    verbose: bool,
) -> None:
    """Apply or print PATH updates for the directory containing installed shims/binaries."""
    if dry_run or last_dir is None:
        return

    system = platform.system().lower()
    if print_only:
        if system.startswith("win"):
            LOGGER.info("[PATH] Would add: %s", last_dir)
        else:
            LOGGER.info("[PATH] Would add line: %s", _line_to_add(last_dir))
        return

    if no_path:
        return

    if system.startswith("win"):
        changed, detail = add_to_path_windows(last_dir, verbose=verbose)
        if changed:
            LOGGER.info("🔧 Added to user PATH (Windows).")
            LOGGER.info("Open a NEW terminal to use commands.")
        else:
            LOGGER.info("ℹ️  PATH not changed (%s).", detail)
            LOGGER.info("If commands aren't found, add: %s", last_dir)
    else:
        changed, rc_file, line = add_to_path_unix(last_dir, verbose=verbose)
        if changed:
            LOGGER.info("🔧 Added to PATH by editing %s.", rc_file)
            LOGGER.info("   %s", line)
            LOGGER.info("Open a NEW shell (or `source %s`) to use commands.", rc_file)
        else:
            LOGGER.info("ℹ️  PATH already included or could not be updated.")
            LOGGER.info("If commands aren't found, add this to your rc file:")
            LOGGER.info("   %s", line)


def _uninstall_windows(
    name: str, *, dry_run: bool, verbose: bool, purge: bool, keep_path: bool
) -> bool:
    """Handle uninstall flow on Windows, returning True when anything was removed."""
    removed_any = False
    candidate_bindirs: List[Path] = []

    shims = find_windows_shims(name)
    if not shims and verbose:
        LOGGER.info("ℹ️  No shims found on PATH.")
    for shim in shims:
        candidate_bindirs.append(shim.parent)
        if safe_remove(shim, verbose=verbose, dry_run=dry_run):
            LOGGER.info("🗑️  removed %s", shim)
            removed_any = True

    if purge:
        payload = windows_payload_dir(name)
        if payload.exists():
            if safe_remove(payload, verbose=verbose, dry_run=dry_run):
                LOGGER.info("🗑️  removed payload %s", payload)
                removed_any = True

    if not keep_path:
        seen: set[Path] = set()
        for bindir in candidate_bindirs:
            if bindir in seen:
                continue
            seen.add(bindir)
            if remove_from_path_windows(bindir, verbose=verbose) and not dry_run:
                LOGGER.info(
                    "🧹 Removed PATH entry for %s (Windows). Open a NEW terminal to refresh.",
                    bindir,
                )

    return removed_any


def _uninstall_unix(
    name: str, *, dry_run: bool, verbose: bool, keep_path: bool
) -> bool:
    """Handle uninstall flow on Unix-like systems."""
    removed_any = False
    candidate_bindirs: List[Path] = []

    targets = find_unix_targets(name)
    if not targets and verbose:
        LOGGER.info("ℹ️  No targets found on PATH or common dirs.")
    for target in targets:
        candidate_bindirs.append(target.parent)
        if safe_remove(target, verbose=verbose, dry_run=dry_run):
            LOGGER.info("🗑️  removed %s", target)
            removed_any = True

    if not keep_path:
        seen: set[Path] = set()
        for bindir in candidate_bindirs or [pick_unix_bindir()]:
            if bindir in seen:
                continue
            seen.add(bindir)
            if remove_from_path_unix(bindir, verbose=verbose) and not dry_run:
                LOGGER.info("🧹 Removed PATH entry from your shell rc file.")

    return removed_any


def do_uninstall(
    name: str, *, dry_run: bool, verbose: bool, purge: bool, keep_path: bool
) -> None:
    """Uninstall a command by name across common locations and clean PATH (by default)."""
    system = platform.system().lower()
    if system.startswith("win"):
        removed_any = _uninstall_windows(
            name,
            dry_run=dry_run,
            verbose=verbose,
            purge=purge,
            keep_path=keep_path,
        )
    else:
        removed_any = _uninstall_unix(
            name,
            dry_run=dry_run,
            verbose=verbose,
            keep_path=keep_path,
        )

    if not removed_any:
        LOGGER.info(
            "ℹ️  Nothing removed for '%s'. %s",
            name,
            "It may not be installed or is in a non-standard location.",
        )


def main() -> None:
    """CLI entrypoint (install by default; supports uninstall subcommand)."""
    args = parse_args()
    configure_logging(getattr(args, "verbose", False))

    if args.cmd == "uninstall":
        do_uninstall(
            args.name,
            dry_run=args.dry_run,
            verbose=args.verbose,
            purge=args.purge,
            keep_path=args.keep_path,
        )
        return

    # Default / explicit install
    name_override = getattr(args, "name", None)
    dry_run = getattr(args, "dry_run", False)
    verbose = getattr(args, "verbose", False)
    no_path = getattr(args, "no_path", False)
    print_only = getattr(args, "print_path_change", False)

    sources = collect_sources(args)
    last_dir = install_all(
        sources, name_override=name_override, dry_run=dry_run, verbose=verbose
    )
    apply_path_change(
        last_dir,
        dry_run=dry_run,
        print_only=print_only,
        no_path=no_path,
        verbose=verbose,
    )


if __name__ == "__main__":
    main()
