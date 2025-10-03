#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CLINTON
General script installer: installs one or more local scripts as global commands
by placing them into a writable directory on PATH and (optionally) updating PATH.

Features:
- Supports .py, .sh/.bash/.zsh, .bat/.cmd, .ps1, and files with a shebang.
- On Linux/macOS: copies script (or wraps .py without shebang) and updates shell rc file.
- On Windows: copies script to %LOCALAPPDATA% and writes .cmd/.ps1 shims, updates user PATH.
"""

from __future__ import annotations

import argparse
import glob
import os
import platform
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Tuple

RECOGNIZED_EXTS = {".py", ".sh", ".bash", ".zsh", ".bat", ".cmd", ".ps1"}


# ---------- small utils ----------


def debug(msg: str, enabled: bool) -> None:
    """Print debug logs when enabled."""
    if enabled:
        print(msg, flush=True)


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

    # any writable PATH entry
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
    cmd_content: str,
    ps1_content: str,
    *,
    dry_run: bool,
    verbose: bool,
) -> None:
    if not dry_run:
        write_text(cmd_path, cmd_content)
        write_text(ps1_path, ps1_content)
    debug(f"[WRITE] {cmd_path}", verbose)
    debug(f"[WRITE] {ps1_path}", verbose)


def _shim_for_bat(
    dst: Path, bindir: Path, *, dry_run: bool, verbose: bool
) -> Tuple[Path, str]:
    cmd_path, ps1_path = bindir / f"{dst.stem}.cmd", bindir / f"{dst.stem}.ps1"
    _win_write_cmd_ps1(
        cmd_path,
        ps1_path,
        f'@echo off\r\n"{dst}" %*\r\n',
        f'Start-Process -FilePath "{dst}" -ArgumentList $args -NoNewWindow -Wait\r\n',
        dry_run=dry_run,
        verbose=verbose,
    )
    return cmd_path, "cmd-shim"


def _shim_for_ps1(
    dst: Path, bindir: Path, *, dry_run: bool, verbose: bool
) -> Tuple[Path, str]:
    cmd_path, ps1_path = bindir / f"{dst.stem}.cmd", bindir / f"{dst.stem}.ps1"
    if not dry_run:
        write_text(ps1_path, f'#!/usr/bin/env pwsh\r\n& "{dst}" @args\r\n')
        write_text(
            cmd_path,
            f'@echo off\r\npowershell -ExecutionPolicy Bypass -File "{ps1_path}" %*\r\n',
        )
    debug(f"[WRITE] {ps1_path}", verbose)
    debug(f"[WRITE] {cmd_path}", verbose)
    return ps1_path, "ps1-shim"


def _shim_for_py(
    dst: Path, bindir: Path, *, dry_run: bool, verbose: bool
) -> Tuple[Path, str]:
    cmd_path, ps1_path = bindir / f"{dst.stem}.cmd", bindir / f"{dst.stem}.ps1"
    _win_write_cmd_ps1(
        cmd_path,
        ps1_path,
        f'@echo off\r\npython "{dst}" %*\r\n',
        f'# PowerShell shim\r\npython "{dst}" $args\r\n',
        dry_run=dry_run,
        verbose=verbose,
    )
    return cmd_path, "py-shim"


def _shim_for_sh(
    dst: Path, bindir: Path, *, dry_run: bool, verbose: bool
) -> Tuple[Path, str]:
    cmd_path, ps1_path = bindir / f"{dst.stem}.cmd", bindir / f"{dst.stem}.ps1"
    _win_write_cmd_ps1(
        cmd_path,
        ps1_path,
        f'@echo off\r\nbash "{dst}" %*\r\n',
        f'# PowerShell shim\r\nbash "{dst}" $args\r\n',
        dry_run=dry_run,
        verbose=verbose,
    )
    return cmd_path, "bash-shim"


def _shim_generic(
    dst: Path, bindir: Path, *, dry_run: bool, verbose: bool
) -> Tuple[Path, str]:
    cmd_path = bindir / f"{dst.stem}.cmd"
    if not dry_run:
        write_text(
            cmd_path,
            f'@echo off\r\npowershell -ExecutionPolicy Bypass -File "{dst}" %*\r\n',
        )
    debug(f"[WRITE] {cmd_path}", verbose)
    return cmd_path, "generic-shim"


def install_windows(
    src: Path, name: str, *, dry_run: bool, verbose: bool
) -> Tuple[Path, str]:
    """Install a script on Windows. Returns (shim_path, how)."""
    bindir = pick_windows_bindir()
    root, dst = _windows_core_copy(src, name, dry_run=dry_run, verbose=verbose)

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
    shell = os.environ.get("SHELL", "")
    home = Path.home()
    if shell.endswith("zsh"):
        return home / ".zshrc"
    if shell.endswith("bash"):
        return home / ".bashrc"
    # prefer existing; else .profile
    for cand in (home / ".bashrc", home / ".zshrc"):
        if cand.exists():
            return cand
    return home / ".profile"


def add_to_path_unix(bindir: Path, *, verbose: bool) -> Tuple[bool, Path, str]:
    """
    Ensure bindir is in PATH by appending an export to a shell rc file.
    Returns (changed, file_path, line_added).
    """
    target_rc = _choose_rc_file()
    target_rc.parent.mkdir(parents=True, exist_ok=True)
    line = _line_to_add(bindir)

    existing = ""
    try:
        if target_rc.exists():
            existing = target_rc.read_text(encoding="utf-8")
    except (OSError, IOError):
        existing = ""

    if line in existing:
        debug(f"[PATH] Already present in {target_rc}", verbose)
        return False, target_rc, line

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
    """
    Add bindir to the **user** PATH on Windows using PowerShell.
    Returns (changed, explanation).
    """
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


# ---------- main orchestration ----------


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Install one or more local scripts as global commands."
    )
    ap.add_argument(
        "--source",
        nargs="*",
        help="Files or globs to install. If omitted, scan current directory.",
    )
    ap.add_argument("--name", help="Override command name (only for single source).")
    ap.add_argument(
        "--dry-run", action="store_true", help="Print actions, do not write."
    )
    ap.add_argument("--verbose", action="store_true", help="Verbose output.")
    ap.add_argument(
        "--no-path",
        action="store_true",
        help="Do not attempt to modify PATH; just install files.",
    )
    ap.add_argument(
        "--print-path-change",
        action="store_true",
        help="Print the PATH export line or intended Windows change without applying.",
    )
    return ap.parse_args()


def collect_sources(args: argparse.Namespace) -> List[Path]:
    if args.source:
        sources = expand_sources(args.source)
        if not sources:
            print("[ERROR] No matching files for --source.", file=sys.stderr)
            sys.exit(2)
        return sources
    sources = discover_in_cwd()
    if not sources:
        print("[ERROR] No recognizable scripts in current directory.", file=sys.stderr)
        sys.exit(2)
    return sources


def install_all(
    sources: List[Path], *, name_override: str | None, dry_run: bool, verbose: bool
) -> Path | None:
    system = platform.system().lower()
    print(f"[INFO] OS: {system}, installing {len(sources)} script(s)")
    if name_override and len(sources) != 1:
        print(
            "[ERROR] --name can only be used when installing a single source file.",
            file=sys.stderr,
        )
        sys.exit(2)

    last_target_dir: Path | None = None
    for src in sources:
        if not src.exists():
            print(f"[SKIP] Missing: {src}", file=sys.stderr)
            continue
        name = name_override or guess_command_name(src)
        if system.startswith("win"):
            target, how = install_windows(src, name, dry_run=dry_run, verbose=verbose)
        else:
            target, how = install_unix(src, name, dry_run=dry_run, verbose=verbose)
        last_target_dir = Path(target).parent
        print(f"✅ {name} -> {target} ({how})")
    return last_target_dir


def apply_path_change(
    last_dir: Path | None,
    *,
    dry_run: bool,
    print_only: bool,
    no_path: bool,
    verbose: bool,
) -> None:
    if dry_run or last_dir is None:
        return

    system = platform.system().lower()
    if print_only:
        if system.startswith("win"):
            print("\n[PATH] Would add:", str(last_dir))
        else:
            print("\n[PATH] Would add line:", _line_to_add(last_dir))
        return

    if no_path:
        return

    if system.startswith("win"):
        changed, detail = add_to_path_windows(last_dir, verbose=verbose)
        if changed:
            print(
                "🔧 Added to user PATH (Windows). Open a NEW terminal to use commands."
            )
        else:
            print(
                f"ℹ️  PATH not changed ({detail}). If commands aren't found, add:",
                str(last_dir),
            )
    else:
        changed, rc_file, line = add_to_path_unix(last_dir, verbose=verbose)
        if changed:
            print(
                f"🔧 Added to PATH by editing {rc_file}.\n   {line}\nOpen a NEW shell (or `source {rc_file}`) to use commands."
            )
        else:
            print(
                "ℹ️  PATH already included or could not be updated.\n"
                "If commands aren't found, add this to your rc file:\n   " + line
            )


def main() -> None:
    """CLI entrypoint."""
    args = parse_args()
    sources = collect_sources(args)
    last_dir = install_all(
        sources, name_override=args.name, dry_run=args.dry_run, verbose=args.verbose
    )
    apply_path_change(
        last_dir,
        dry_run=args.dry_run,
        print_only=args.print_path_change,
        no_path=args.no_path,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()
