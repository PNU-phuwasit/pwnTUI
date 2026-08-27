#!/usr/bin/env python3
"""
PwnTUI — a Textual-based TUI front-end for the GDB/MI debugging engine.

Backend: asyncio.subprocess running `gdb --interpreter=mi3`, parsed with the
`gdb_mi_parser` module (a self-contained fallback parser is included so this
file runs standalone).

Run:
    python3 app.py <path-to-binary> [args...]
    # or, once linked into PATH:
    pwntui <path-to-binary> [args...]

Maintenance:
    pwntui --update    upgrade textual/pwntools/rich within the major versions
                       this release is known to work with, then exit
    pwntui --repair    force-reinstall the exact versions this release was
                       integration-tested against, then exit (use when a
                       minor upgrade breaks something)
    Add --break-system-packages if your Python is distro-managed (PEP 668)
    and you accept the risk; a virtualenv is the safer route.

Requires:
    pip install textual pwntools

Terminal size:
    150x40 or larger is comfortable; 130x35 is the practical minimum. Below
    that the layout still degrades losslessly -- the stack row sheds its
    offset column, the disassembly sheds GDB's trailing address comment and
    finally wraps -- but nothing is ever silently clipped.

Keybindings (global -- the function keys are priority bindings, so they fire
no matter which panel, modal or input box currently has focus):
    F5          run                 F6   continue
    F10         step over one instruction (ni)
    F11         step into one instruction (si)
    F8          run to return of current frame (finish)

    F10/F11 are INSTRUCTION-level on purpose: source-level next/step need
    line info and fail on a stripped binary with "Cannot find bounds of
    current function". Type `next` / `step` in the console if you have DWARF
    and want source-level stepping.
    F9          toggle breakpoint on the highlighted Smart Breakpoint
    F2          open the memory viewer
    F4          interrupt a free-running target (SIGINT)
    Tab         cycle focus (Smart Breakpoints <-> console input)

    F4 works while the target is free-running or blocked in read(), from
    anywhere -- including from inside the memory viewer, which then finishes
    the read you asked for by itself.

Every action above has a function key precisely so it stays reachable while
you are typing in the console box -- the single-letter aliases below cannot
be, by design.

Single-letter shortcuts (deliberately NOT priority bindings, so they are
swallowed by the console Input while you are typing a command):
    n / s / c   step over (ni) / step into (si) / continue
    j / k       move down / up in the Smart Breakpoints list
    Enter       set (or clear) a breakpoint on the highlighted entry
    m           open the memory-viewer modal (same as F2)
    y           save the console transcript to ~/.cache/pwntui-console.txt
    i           jump to the console input     Esc  leave the console input
    q           quit

Console input box:
    <gdb command>   sent to GDB (CLI syntax auto-wrapped via -interpreter-exec),
                    e.g. "run < payload", "x/32gx $rsp", "info functions"
    -<mi command>   sent to GDB verbatim as raw MI
    !<text>         sent straight to the debuggee's own stdin (its pty),
                    e.g. "!my name" answers an interactive "Name: " prompt
                    from the target program itself -- not a GDB command.
    Up / Down       walk back through the commands you have already run

    Commands that RESUME the inferior -- run, start, continue, next, step,
    ni, si, finish, until, advance -- are rewritten to their MI spellings
    before being sent (see translate_exec_command). This is not cosmetic:
    the CLI versions execute on GDB's console interpreter, which is
    synchronous, so GDB stops reading MI entirely until the inferior stops
    again. Typing "run < payload" used to take the whole front-end offline
    for as long as the target ran -- and permanently, if the target sat
    waiting in read() for input that could no longer be delivered.
    "run < payload" keeps working exactly as written; its arguments are
    installed with `set args` first, which the startup shell honours.
"""

from __future__ import annotations

import argparse
import asyncio
import codecs
import os
import pty
import re
import subprocess
import sys
import time
import traceback
from dataclasses import dataclass, field
from typing import Optional

# --------------------------------------------------------------------------
# Dependency management (--update / --repair)
#
# This block deliberately sits ABOVE the textual/pwntools imports and uses
# nothing but the standard library. --repair exists precisely for the case
# where a dependency is broken or mis-upgraded, and a broken dependency makes
# `from textual import ...` raise at module load -- so if these flags were
# handled down in main(), --repair would crash on import in exactly the
# situation it was written to rescue. Dispatching before the heavy imports
# keeps it usable when the install is in pieces.
# --------------------------------------------------------------------------

#: Compatible-range upgrade: newest patch/minor within the major versions
#: PwnTUI is known to work with.
UPDATE_SPECS = (
    "textual>=8.2.0,<9.0.0",
    "pwntools>=4.15.0,<5.0.0",
    "rich>=15.0.0,<16.0.0",
)

#: Exact versions this release was integration-tested against. --repair pins
#: to these to undo a minor upgrade that broke something.
REPAIR_SPECS = (
    "textual==8.2.8",
    "pwntools==4.15.0",
    "rich==15.0.0",
)

#: distribution name -> importable module name (they differ for pwntools).
_DIST_MODULES = {"textual": "textual", "pwntools": "pwn", "rich": "rich"}


def _installed_versions() -> dict[str, str]:
    """Current version of each managed distribution, or "-" if absent."""
    try:
        from importlib import metadata
    except ImportError:  # pragma: no cover - Python < 3.8
        return {}
    out = {}
    for dist in _DIST_MODULES:
        try:
            out[dist] = metadata.version(dist)
        except Exception:
            out[dist] = "-"
    return out


def _in_virtualenv() -> bool:
    return sys.prefix != getattr(sys, "base_prefix", sys.prefix)


def _pip_command(specs, *, force: bool, break_system: bool) -> list[str]:
    cmd = [sys.executable, "-m", "pip", "install", "--upgrade"]
    if force:
        # --repair must overwrite an already-"satisfied" but broken install.
        cmd += ["--force-reinstall", "--no-cache-dir"]
    if break_system:
        cmd.append("--break-system-packages")
    elif not _in_virtualenv() and _externally_managed():
        # Distro-managed interpreter (Kali, Debian, Fedora...). Do NOT slip
        # --break-system-packages in silently: overriding the system package
        # manager can break OS tooling that shares site-packages. Make the
        # user opt in explicitly; _report_pip_failure explains how.
        pass
    return cmd + list(specs)


def _externally_managed() -> bool:
    """True when this interpreter is PEP 668 externally-managed."""
    import sysconfig

    for key in ("stdlib", "platstdlib"):
        path = sysconfig.get_path(key)
        if path and os.path.exists(os.path.join(path, "EXTERNALLY-MANAGED")):
            return True
    return False


def _dep_console():
    """A rich Console if rich is importable, else a tiny stdout shim.

    rich is one of the packages being repaired, so it may be the very thing
    that is broken -- this path must still work without it.
    """
    try:
        from rich.console import Console

        return Console(), True
    except Exception:
        class _Plain:
            def print(self, *args, **kwargs):
                text = " ".join(str(a) for a in args)
                print(re.sub(r"\[/?[a-z0-9_ .#]+\]", "", text))

            def status(self, *args, **kwargs):
                class _Null:
                    def __enter__(self_inner):
                        print(re.sub(r"\[/?[a-z0-9_ .#]+\]", "",
                                     str(args[0]) if args else "working..."))
                        return self_inner

                    def __exit__(self_inner, *exc):
                        return False

                return _Null()

        return _Plain(), False


def _report_pip_failure(console, result: subprocess.CompletedProcess) -> None:
    output = f"{result.stdout or ''}\n{result.stderr or ''}"
    console.print(f"[bold red]pip exited with status {result.returncode}.[/bold red]")
    tail = [ln for ln in output.splitlines() if ln.strip()][-12:]
    for line in tail:
        console.print(f"  [dim]{line}[/dim]")
    if "externally-managed-environment" in output or "EXTERNALLY-MANAGED" in output:
        console.print(
            "\n[yellow]This interpreter is managed by your distribution "
            "(PEP 668), so pip refused to modify it.[/yellow]\n"
            "Pick one:\n"
            "  [bold]1.[/bold] Use a virtualenv (recommended, cannot break the OS):\n"
            "       python3 -m venv ~/.venvs/pwntui\n"
            "       ~/.venvs/pwntui/bin/pip install "
            + " ".join(f"'{sp}'" for sp in REPAIR_SPECS)
            + "\n       ~/.venvs/pwntui/bin/python app.py <binary>\n"
            "  [bold]2.[/bold] Override the protection, accepting the risk to "
            "system packages:\n"
            "       python3 app.py --repair --break-system-packages"
        )


def _dependency_main(argv: list[str]) -> int:
    """Handle --update / --repair. Returns a process exit status."""
    repair = "--repair" in argv
    update = "--update" in argv
    break_system = "--break-system-packages" in argv

    if repair and update:
        print("pwntui: error: --update and --repair are mutually exclusive",
              file=sys.stderr)
        return 2

    specs = REPAIR_SPECS if repair else UPDATE_SPECS
    label = "Repairing" if repair else "Updating"
    console, have_rich = _dep_console()

    before = _installed_versions()
    console.print(f"[bold cyan]PwnTUI {label.lower()} dependencies[/bold cyan]")
    for dist in _DIST_MODULES:
        console.print(f"  [dim]{dist:<10}[/dim] {before.get(dist, '-')}")
    console.print("  [dim]target    [/dim] " + ", ".join(specs))
    if not _in_virtualenv():
        console.print("  [dim]note      [/dim] not running inside a virtualenv")

    cmd = _pip_command(specs, force=repair, break_system=break_system)
    try:
        with console.status(f"[bold cyan]{label} textual / pwntools / rich...",
                            spinner="dots"):
            result = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        console.print("[bold red]Could not run pip "
                      f"({sys.executable} -m pip).[/bold red]")
        return 1
    except KeyboardInterrupt:
        console.print("[yellow]Interrupted.[/yellow]")
        return 130

    if result.returncode != 0:
        _report_pip_failure(console, result)
        return result.returncode

    after = _installed_versions()
    console.print("[bold green]Done.[/bold green]")
    for dist in _DIST_MODULES:
        old_v, new_v = before.get(dist, "-"), after.get(dist, "-")
        if old_v == new_v:
            console.print(f"  [dim]{dist:<10}[/dim] {new_v} [dim](unchanged)[/dim]")
        else:
            console.print(f"  [dim]{dist:<10}[/dim] {old_v} -> [green]{new_v}[/green]")
    console.print(
        "\n[dim]Version changes only take effect in a new process; "
        "just start pwntui again.[/dim]"
    )
    return 0


# Dispatch before the heavy imports -- see the block comment above.
if __name__ == "__main__" and {"--update", "--repair"} & set(sys.argv[1:]):
    sys.exit(_dependency_main(sys.argv[1:]))

from textual import on
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.binding import Binding
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    ListItem,
    ListView,
    Label,
    RichLog,
    Static,
)
from rich.text import Text

from pwn import ELF, context as pwn_context

# --------------------------------------------------------------------------
# Backend: GDB/MI record parsing
#
# If you have the `gdb_mi_parser` module we built earlier it is used as-is;
# it must expose parse_mi_line(line: str) -> dict | None returning
#     {"type": ..., "klass": ..., "payload": ..., "token": ...}
# Otherwise the minimal fallback parser below takes over.
# --------------------------------------------------------------------------

try:
    from gdb_mi_parser import parse_mi_line as _parse_mi_line  # type: ignore
except ImportError:

    _MI_RESULT_RE = re.compile(r"^(\d*)(\^|\*|=|~|@|&)(.*)$")

    def _mi_bytes(s: str) -> bytes:
        """Recover the wire bytes behind a latin1-decoded MI line.

        _read_loop hands MI lines over decoded as latin1 precisely so this
        is lossless (latin1 maps 0x00-0xFF onto U+0000-U+00FF one for one).
        The utf-8 fallback is for callers that pass a normal unicode string.
        """
        try:
            return s.encode("latin1")
        except UnicodeEncodeError:
            return s.encode("utf-8")

    def _mi_text(s: str) -> str:
        """Decode a latin1-carried MI line as the UTF-8 it really is."""
        return _mi_bytes(s).decode("utf-8", errors="replace")

    def _mi_unescape(s: str) -> str:
        """Turn one MI C-string body into text.

        GDB does NOT escape consistently: it emits some bytes raw and
        octal-escapes others, so a single UTF-8 character arrives as a
        mixture -- GDB 17 prefixes error messages with U+274C and sends it
        as the raw bytes e2 9d 8c interleaved with escaped ef b8 8f. The
        raw halves must therefore survive as bytes all the way to here,
        which is why nothing upstream is allowed to utf-8 decode first: it
        would replace every raw byte with U+FFFD before the escapes were
        ever expanded, and there is no recovering from that.
        """
        try:
            return (
                _mi_bytes(s)
                .decode("unicode_escape")   # expands \n, \", \NNN octal
                .encode("latin1")           # back to the target's own bytes
                .decode("utf-8", errors="replace")
            )
        except (UnicodeDecodeError, UnicodeEncodeError):
            # Malformed escapes must degrade to the raw text, never raise --
            # a single weird byte from the inferior would otherwise take the
            # whole reader loop down.
            return s

    def _mi_parse_any(s: str, i: int):
        """Parse one MI value (c-string / tuple / list / bareword) at s[i:].

        Returns (value, next_index). Every branch is bounds-checked so a
        truncated or malformed record yields a partial value instead of an
        IndexError.
        """
        if i >= len(s):
            return None, i
        c = s[i]
        if c == '"':
            j = i + 1
            buf = []
            while j < len(s) and s[j] != '"':
                if s[j] == "\\" and j + 1 < len(s):
                    buf.append(s[j])
                    buf.append(s[j + 1])
                    j += 2
                else:
                    buf.append(s[j])
                    j += 1
            return _mi_unescape("".join(buf)), j + 1
        if c == "{":
            j = i + 1
            d: dict = {}
            while j < len(s) and s[j] != "}":
                key, j = _mi_read_key(s, j)
                if j < len(s) and s[j] == "=":
                    j += 1
                val, j = _mi_parse_any(s, j)
                if key:
                    d[key] = val
                if j < len(s) and s[j] == ",":
                    j += 1
                elif j < len(s) and s[j] != "}":
                    # Unparseable remainder: bail out rather than spin.
                    break
            return d, j + 1
        if c == "[":
            j = i + 1
            lst: list = []
            while j < len(s) and s[j] != "]":
                before = j
                val, j = _mi_parse_any(s, j)
                lst.append(val)
                if j < len(s) and s[j] == ",":
                    j += 1
                if j == before:  # no progress -> malformed, stop
                    break
            return lst, j + 1
        j = i
        while j < len(s) and s[j] not in ",}]":
            j += 1
        return s[i:j], j

    def _mi_read_key(s: str, i: int):
        j = i
        while j < len(s) and s[j] not in "=,}":
            j += 1
        return s[i:j], j

    def _parse_mi_line(line: str):
        line = line.rstrip("\r\n")
        # GDB's actual CLI prompt is "(gdb) " (trailing space included), so
        # an exact "(gdb)" match never fires -- strip() first, or the prompt
        # leaks into the console as if it were real output.
        if not line or line.strip() in ("(gdb)", "(gdb)"):
            return None
        m = _MI_RESULT_RE.match(line)
        if not m:
            # Not an MI record at all (GDB's own startup chatter). It came
            # in as latin1 too, so decode it the same way a C-string body
            # would be.
            return {"type": "console", "klass": "stream", "payload": _mi_text(line)}
        token, sigil, rest = m.groups()
        if sigil in ("^", "*", "="):
            parts = rest.split(",", 1)
            klass = parts[0]
            payload: object = {}
            if len(parts) > 1:
                payload, _ = _mi_parse_any("{" + parts[1] + "}", 0)
            kind = {"^": "result", "*": "exec", "=": "notify"}[sigil]
            return {"type": kind, "klass": klass, "payload": payload, "token": token}
        text, _ = _mi_parse_any(rest, 0)
        kind = {"~": "console", "@": "target", "&": "log"}[sigil]
        return {"type": kind, "klass": "stream", "payload": text}


_ERROR_LOG_PATH = os.path.join(
    os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache")),
    "pwntui-error.log",
)
_CONSOLE_DUMP_PATH = os.path.join(
    os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache")),
    "pwntui-console.txt",
)

# How long to wait for a ^done/^error reply before giving up on an
# await-ing MI command. Without this, a GDB that wedges (or dies mid
# command) leaves the awaiting coroutine hung forever and the panel that
# was refreshing simply never comes back.
MI_TIMEOUT = 10.0

# How long a cached "the inferior is running" state is trusted to suppress
# duplicate execution commands before we let one through anyway.
BUSY_STALE = 3.0

# Interactive requests (the memory viewer) use a much tighter deadline than
# the general MI_TIMEOUT. GDB stops answering ANYTHING while a step command
# that cannot complete is outstanding -- stepping over a read() that is
# waiting for input you have not sent yet is the everyday way to hit this --
# and at MI_TIMEOUT each keypress in the modal would freeze it for 10s.
MI_INTERACTIVE_TIMEOUT = 3.0

#: Registers accepted with no sigil at all ("rsp" -> "$rsp"). Deliberately a
#: short, safe list: GDB's full register list contains names like "es"/"ds"
#: that could plausibly collide with a symbol in the target.
_BARE_REGS = frozenset(
    "rax rbx rcx rdx rsi rdi rbp rsp rip "
    "eax ebx ecx edx esi edi ebp esp eip "
    "r8 r9 r10 r11 r12 r13 r14 r15 pc sp fp".split()
)

#: AT&T-style register reference, e.g. the "%rsp" the Disassembly panel shows.
_ATT_REG_RE = re.compile(r"(?<![\w$])%([A-Za-z_][A-Za-z0-9_]*)")


def normalize_mem_expr(expr: str, reg_names=()) -> str:
    """Accept the register spellings a user actually has in front of them.

    The Disassembly panel renders AT&T syntax, so the register the user is
    looking at on screen is spelled "%rsp" -- but GDB expressions want
    "$rsp", and "%rsp" comes back as an opaque "A syntax error in
    expression" that names no fix. A bare "rsp" is just as natural and fails
    even worse ("No symbol table is loaded"). Rewrite both rather than
    lecturing the user about a distinction the UI itself blurred.
    """
    known = {n for n in (reg_names or ()) if n} or set(_BARE_REGS)
    out = _ATT_REG_RE.sub(
        lambda m: "$" + m.group(1) if m.group(1) in known else m.group(0), expr
    )
    lead = re.match(r"[A-Za-z_][A-Za-z0-9_]*", out)
    if lead and lead.group(0) in _BARE_REGS:
        out = "$" + out
    return out

# Runs of whitespace inside a disassembled instruction, collapsed on render.
_WS_RUN_RE = re.compile(r"\s{2,}")

# GDB's trailing "# 0x404050 <stdout@GLIBC_2.2.5>" resolution comment.
_ADDR_COMMENT_RE = re.compile(r"\s*#\s*(0x[0-9a-fA-F]+)\s*(<[^>]*>)?\s*$")


def fit_disasm_line(line: str, width: int) -> str:
    """Shrink one disassembly row to `width` without wrapping it.

    A wrapped instruction is genuinely hard to read -- the operands end up
    on the row below, so the column stops being one-instruction-per-line and
    you lose your place while stepping. Clipping is worse still: it eats the
    branch target, the single most useful part of the row. So when a line is
    too wide, shed the least valuable part of GDB's trailing resolution
    comment first: the bare address goes, the symbol stays.
    """
    if width <= 0 or len(line) <= width:
        return line
    m = _ADDR_COMMENT_RE.search(line)
    if m:
        head, symbol = line[:m.start()], m.group(2)
        if symbol:
            candidate = f"{head} # {symbol}"
            if len(candidate) <= width:
                return candidate
        if len(head) <= width:
            return head
    return line  # still too long: wrap=True keeps it rather than losing it


def describe_corrupt_pointer(value: int, bits: int = 64) -> list[str]:
    """Explain a register that is holding payload bytes rather than an address.

    When $pc or $sp is unreadable after a smash, the number itself is the
    answer: it IS the bytes that landed on the saved return address. Showing
    it back as little-endian ASCII turns "Cannot access memory at address
    0x6161617461616173" into "that is 'saaataaa' -- byte 0x50 of your
    cyclic pattern", which is the offset the user came here to find.
    """
    size = 4 if bits == 32 else 8
    try:
        raw = value.to_bytes(size, "little")
    except (OverflowError, ValueError):
        return []
    # Trailing NULs are stripped first. The commonest real hijack overwrites
    # a return address with SIX payload bytes and leaves the top two zero --
    # which is precisely what keeps the address canonical, so it is the case
    # that actually reaches this code. Testing all eight bytes for
    # printability rejected exactly those, and the offset went unreported in
    # the situation the whole feature exists for.
    core = raw.rstrip(b"\x00")
    if len(core) < 4 or not all(32 <= b < 127 for b in core):
        return []
    text = core.decode("latin1")
    out = [f'those bytes spell "{text}" -- this is payload, not an address']
    try:
        from pwn import cyclic_find
    except Exception:
        return out
    # Both alphabet widths are reported, labelled, rather than guessed at:
    # cyclic() defaults to n=4 but everyone doing 64-bit work eventually
    # switches to cyclic(n=8), and the two produce different sequences, so
    # an unlabelled offset would be right half the time. Slicing to exactly
    # n bytes also keeps pwnlib from logging its own truncation warning.
    for n in (4, 8):
        if len(core) < n:
            continue
        try:
            offset = cyclic_find(core[:n], n=n)
        except Exception:
            continue
        # Bounded because a subsequence from an n=4 pattern also occurs
        # somewhere in the (vastly longer) n=8 one, at an offset in the tens
        # of millions. That is a coincidence, not the answer, and printing
        # it next to the real offset would make both look like guesses.
        if 0 <= offset < 0x10000:
            label = "cyclic()" if n == 4 else "cyclic(n=8)"
            out.append(f"offset {offset} (0x{offset:x}) in {label}")
    return out


#: Every C0/C1 control byte except tab and newline, plus DEL. ESC is the
#: one that matters.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def sanitize_console_text(text: str) -> str:
    """Neutralise terminal control sequences coming from the debuggee.

    rich.text.Text runs strip_control_codes(), but ESC (0x1b) is NOT in the
    set it strips -- it removes BEL and friends and passes "\x1b[2J"
    straight through to the terminal. So a target that writes ANSI to its
    own tty (any CTF binary with coloured output, and every format-string
    challenge that can be made to print arbitrary bytes) could clear the
    screen, reposition the cursor, or drop the terminal out of Textual's
    alt-screen -- from inside a pane that is supposed to be inert text.

    Controls become "." to match the convention already used by the ASCII
    column of the hexdump, so a byte the target emitted still shows up as
    something rather than silently vanishing. Tabs and newlines survive:
    GDB's own output is full of both.
    """
    return _CONTROL_RE.sub(".", text)


def _log_exception(where: str) -> None:
    """Textual runs in the terminal's alt-screen, so anything printed to
    stderr is invisible while the app is running -- write it to a file too
    so a crash/bug is diagnosable instead of just silently freezing panels."""
    try:
        os.makedirs(os.path.dirname(_ERROR_LOG_PATH), exist_ok=True)
        with open(_ERROR_LOG_PATH, "a") as f:
            f.write(f"\n--- {where} ---\n")
            traceback.print_exc(file=f)
    except Exception:
        pass


#: CLI verbs that RESUME the inferior.
#:
#: Sending any of these through -interpreter-exec makes GDB execute them on
#: the CONSOLE interpreter, which is synchronous: GDB stops reading its MI
#: input entirely until the inferior stops again. The whole front-end goes
#: deaf -- F4 cannot interrupt, the memory viewer times out, no panel
#: refreshes -- and if the target is blocked on read() waiting for input you
#: have not sent, the session is wedged for good. Their MI spellings are
#: async and leave GDB responsive, so every one of them is rewritten.
_CLI_TO_MI = {
    "continue": "-exec-continue", "cont": "-exec-continue", "c": "-exec-continue",
    "next": "-exec-next", "n": "-exec-next",
    "step": "-exec-step", "s": "-exec-step",
    "nexti": "-exec-next-instruction", "ni": "-exec-next-instruction",
    "stepi": "-exec-step-instruction", "si": "-exec-step-instruction",
    "finish": "-exec-finish", "fin": "-exec-finish",
    "until": "-exec-until", "u": "-exec-until",
    "advance": "-exec-until",
    "interrupt": "-exec-interrupt",
}

#: MI spellings that take the same trailing repeat count as their CLI twin,
#: so `next 5` keeps meaning "five times" rather than silently meaning once.
_MI_TAKES_COUNT = frozenset(
    ("-exec-next", "-exec-step", "-exec-next-instruction", "-exec-step-instruction")
)

#: MI spellings whose operand is a location, not a count.
_MI_TAKES_LOCATION = frozenset(("-exec-until",))

#: `run`/`start` spellings, handled separately because their arguments have
#: to be routed through `set args` (see translate_exec_command).
_CLI_RUN = {"run", "r", "ru"}
_CLI_START = {"start", "sta"}


def translate_exec_command(
    cmd: str,
) -> Optional[tuple[list[str], Optional[str]]]:
    """Rewrite a resuming CLI command as one or more MI commands.

    Returns (mi_commands, note) -- `note` being a warning to show the user
    when the rewrite could not carry an operand across -- or None when `cmd`
    is not an execution command at all and should be passed through to
    -interpreter-exec unchanged.

    `run < payload.bin` is the single most-typed line in a pwn session and
    MI's -exec-run takes no redirections, so its arguments are installed with
    `set args` first -- which is exactly what CLI `run` does internally, is
    honoured by the startup shell, and (crucially) does not resume anything,
    so it is safe to send through the console interpreter.
    """
    verb, _, rest = cmd.strip().partition(" ")
    rest = rest.strip()
    if verb in _CLI_RUN or verb in _CLI_START:
        mi_run = "-exec-run --start" if verb in _CLI_START else "-exec-run"
        # `set args` with an empty argument list CLEARS it, which is exactly
        # what a bare `run` after `run < payload` must not do -- GDB's own
        # `run` reuses the previous arguments. So only touch args when the
        # user actually supplied some.
        if rest:
            return (
                [f'-interpreter-exec console {_mi_quote("set args " + rest)}', mi_run],
                None,
            )
        return ([mi_run], None)

    mi = _CLI_TO_MI.get(verb)
    if mi is None:
        return None
    if not rest:
        return ([mi], None)
    if mi in _MI_TAKES_LOCATION or mi in _MI_TAKES_COUNT:
        return ([f"{mi} {rest}"], None)
    # `continue 3` sets an ignore count on the breakpoint that stopped us;
    # -exec-continue has no equivalent and quietly accepts-and-drops the
    # operand, so say so rather than letting the user believe it applied.
    return ([mi], f"note: `{verb}` takes no argument in MI -- {rest!r} ignored.")


def _mi_quote(cmd: str) -> str:
    """Quote a CLI command as a GDB/MI C-string argument.

    -interpreter-exec expects its command argument wrapped in double quotes
    with backslashes/quotes escaped C-style -- NOT shell/POSIX quoting
    (shlex.quote uses single quotes, which MI does not treat as a string
    delimiter, so the command gets mis-tokenized on whitespace).
    """
    escaped = cmd.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


# --------------------------------------------------------------------------
# Console styling
#
# NOTE: every widget that displays GDB output has markup=False and is fed
# rich.text.Text objects with explicit styles. Rich/Textual markup is never
# applied to dynamic text anywhere in this file -- see the comment on
# PwnTUI._log_console for why.
# --------------------------------------------------------------------------

S_ERROR = "bold red"
S_OK = "green"
S_INFO = "dim"
S_CMD = "bold cyan"
S_STDIN = "magenta"
S_TARGET = "white"
S_WARN = "yellow"

# Style per GDB stream channel: ~ console, & log, and the inferior's own tty.
_STREAM_STYLES = {"console": "", "log": S_INFO, "target": S_TARGET}


@dataclass
class GdbState:
    running: bool = False        # inferior exists (may be stopped)
    executing: bool = False      # inferior is currently free-running
    registers: dict[str, int] = field(default_factory=dict)
    prev_registers: dict[str, int] = field(default_factory=dict)
    disasm: list[dict] = field(default_factory=list)
    stack: list[str] = field(default_factory=list)
    current_pc: Optional[int] = None


class GdbSession:
    """Owns the `gdb --interpreter=mi3` child process and speaks MI to it."""

    def __init__(self, binary: str, args: list[str], on_event):
        self.binary = binary
        self.args = args
        self.on_event = on_event  # async callback(record: dict)
        self.proc: Optional[asyncio.subprocess.Process] = None
        self.alive = False
        self._token = 0
        self._pending: dict[str, asyncio.Future] = {}
        self._commands: dict[str, str] = {}
        self._quiet_tokens: set[str] = set()
        # Incremental, so a multi-byte character split across two reads of
        # the pty is joined back up instead of becoming two replacement
        # characters.
        self._tty_decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self._reader_task: Optional[asyncio.Task] = None
        self._pty_master: Optional[int] = None
        self._pty_slave: Optional[int] = None
        self._pty_watched = False
        # asyncio only keeps a weak reference to bare create_task() results,
        # so an in-flight handler can be garbage-collected mid-await. Hold
        # strong refs until each one finishes.
        self._tasks: set[asyncio.Task] = set()

    async def start(self) -> None:
        # Without an explicit --tty, GDB shares OUR OWN controlling terminal
        # with the debuggee by default. The target's stdout/stdin would then
        # bypass this MI pipe entirely and land on the real terminal beneath
        # Textual's alt-screen -- corrupting the TUI's rendering and giving
        # us no way to see the target's output or feed it input. Give the
        # inferior its own pty instead, which we read/write ourselves.
        self._pty_master, self._pty_slave = pty.openpty()
        slave_name = os.ttyname(self._pty_slave)
        # Non-blocking + loop.add_reader rather than a blocking os.read on a
        # worker thread: a thread parked inside read() cannot be cancelled,
        # and closing the fd underneath it does not wake it, so it would
        # still be sitting there when asyncio tried to join the default
        # executor at shutdown.
        os.set_blocking(self._pty_master, False)

        self.proc = await asyncio.create_subprocess_exec(
            "gdb",
            "--interpreter=mi3",
            "-quiet",
            f"--tty={slave_name}",
            "--args",
            self.binary,
            *self.args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        self.alive = True
        self._reader_task = asyncio.create_task(self._read_loop())
        loop = asyncio.get_running_loop()
        loop.add_reader(self._pty_master, self._on_pty_readable)
        self._pty_watched = True

    # --- plumbing ---------------------------------------------------------

    def _spawn(self, coro) -> None:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def _on_pty_readable(self) -> None:
        """The debuggee wrote to its own tty."""
        if self._pty_master is None:
            return
        try:
            data = os.read(self._pty_master, 65536)
        except BlockingIOError:
            return
        except OSError:
            # EIO here means every slave fd is gone, i.e. GDB is finished
            # with the pty. The fd stays readable forever in that state, so
            # the watch MUST be dropped or the event loop spins at 100%.
            self._stop_pty_reader()
            return
        if not data:
            self._stop_pty_reader()
            return
        self._spawn(
            self._dispatch_event(
                {
                    "type": "target",
                    "klass": "stream",
                    "payload": self._tty_decoder.decode(data),
                }
            )
        )

    def _stop_pty_reader(self) -> None:
        if not self._pty_watched or self._pty_master is None:
            return
        self._pty_watched = False
        try:
            asyncio.get_running_loop().remove_reader(self._pty_master)
        except (RuntimeError, ValueError, OSError):
            pass

    def write_stdin(self, data: bytes) -> None:
        """Send raw bytes to the debuggee's own stdin (via its pty), not to GDB."""
        if self._pty_master is not None:
            try:
                os.write(self._pty_master, data)
            except OSError:
                _log_exception("writing to inferior stdin")

    async def _read_loop(self) -> None:
        assert self.proc and self.proc.stdout
        try:
            while True:
                line = await self.proc.stdout.readline()
                if not line:
                    break
                # latin1, NOT utf-8: MI lines are a byte stream in which
                # GDB mixes raw bytes with octal escapes, and utf-8 decoding
                # here would turn every raw non-ASCII byte into U+FFFD
                # before _mi_unescape ever got to reassemble it. latin1 is
                # lossless for that, and the real decode happens per string.
                decoded = line.decode("latin1")
                try:
                    record = _parse_mi_line(decoded)
                except Exception:
                    # A malformed/unexpected line must never kill this loop --
                    # skip it and keep reading rather than going silent forever.
                    _log_exception(f"parsing MI line: {decoded!r}")
                    continue
                if record is None:
                    continue

                token = record.get("token")
                if token and record.get("type") == "result":
                    # Attach the originating command so ^error can say WHICH
                    # command failed instead of just dumping a bare message.
                    cmd = self._commands.pop(token, None)
                    if cmd:
                        record["command"] = cmd
                    if token in self._quiet_tokens:
                        self._quiet_tokens.discard(token)
                        record["quiet"] = True
                    fut = self._pending.pop(token, None)
                    if fut is not None and not fut.done():
                        fut.set_result(record)

                # Dispatch as a background task -- NEVER awaited inline here.
                # Handlers (e.g. refreshing registers/disasm/stack after a
                # *stopped event) themselves send MI commands and await their
                # replies, and those replies can only ever be delivered by
                # this very loop continuing to run. Awaiting on_event()
                # in-line would deadlock the session the first time a handler
                # does exactly that.
                self._spawn(self._dispatch_event(record))
        finally:
            self.alive = False
            self._fail_pending("GDB session ended")
            try:
                await self.on_event(
                    {"type": "session", "klass": "closed", "payload": {}}
                )
            except Exception:
                _log_exception("handling session-closed event")

    def _fail_pending(self, msg: str) -> None:
        """Resolve every outstanding await with a synthetic ^error, so that
        a GDB that died does not leave coroutines hanging forever."""
        for token, fut in list(self._pending.items()):
            self._pending.pop(token, None)
            if not fut.done():
                fut.set_result(
                    {
                        "type": "result",
                        "klass": "error",
                        "payload": {"msg": msg},
                        "token": token,
                        "command": self._commands.get(token, ""),
                    }
                )
        self._commands.clear()
        self._quiet_tokens.clear()

    async def _dispatch_event(self, record: dict) -> None:
        try:
            await self.on_event(record)
        except Exception:
            _log_exception(f"handling MI record: {record!r}")

    async def send(
        self,
        command: str,
        wait_result: bool = False,
        timeout: float = MI_TIMEOUT,
        quiet: bool = False,
    ) -> Optional[dict]:
        """Write one MI command. Returns the ^done/^error record when
        wait_result=True, else None. Never raises: a dead/closing GDB comes
        back as a synthetic ^error record (or None for fire-and-forget) so
        callers and key handlers cannot be killed by a broken pipe.

        quiet=True marks the reply as belonging to an INTERNAL command --
        one the user never typed, such as the three panel refreshes fired
        after every stop. Their failures are reported inside the pane that
        asked for them, so echoing them to the console as well produced a
        red "GDB error [-data-disassemble ...]" line on every single crash
        with a corrupted $pc, blaming the user for a command they never
        issued."""
        if not self.proc or not self.proc.stdin or not self.alive:
            err = {
                "type": "result",
                "klass": "error",
                "payload": {"msg": "GDB session is not running"},
                "command": command,
            }
            if wait_result:
                return err
            self._spawn(self._dispatch_event(err))
            return None

        self._token += 1
        token = str(self._token)
        self._commands[token] = command
        if quiet:
            self._quiet_tokens.add(token)
        fut: Optional[asyncio.Future] = None
        if wait_result:
            fut = asyncio.get_running_loop().create_future()
            self._pending[token] = fut

        try:
            self.proc.stdin.write(f"{token}{command}\n".encode())
            await self.proc.stdin.drain()
        except (BrokenPipeError, ConnectionResetError, RuntimeError, OSError) as exc:
            self.alive = False
            self._pending.pop(token, None)
            self._commands.pop(token, None)
            self._quiet_tokens.discard(token)
            err = {
                "type": "result",
                "klass": "error",
                "payload": {"msg": f"could not talk to GDB: {exc}"},
                "command": command,
            }
            if wait_result:
                return err
            self._spawn(self._dispatch_event(err))
            return None

        if fut is None:
            return None
        try:
            return await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            self._pending.pop(token, None)
            self._commands.pop(token, None)
            self._quiet_tokens.discard(token)
            return {
                "type": "result",
                "klass": "error",
                "payload": {"msg": f"timed out after {timeout:g}s"},
                "command": command,
            }

    # --- convenience MI wrappers -----------------------------------------

    async def exec_command(self, mi: str) -> Optional[dict]:
        """Send one resuming MI command and wait for its IMMEDIATE reply.

        With mi-async on, every -exec-* command answers ^running (or ^error)
        straight away, long before the inferior stops -- so awaiting the
        reply costs nothing and, unlike fire-and-forget, tells the caller
        whether the target actually started moving. That is what closes the
        window in which two fast keypresses both sailed past the "is it
        running?" guard because neither had seen a *running record yet.
        """
        return await self.send(mi, wait_result=True, timeout=MI_INTERACTIVE_TIMEOUT)

    async def run(self):
        return await self.exec_command("-exec-run")

    async def cont(self):
        return await self.exec_command("-exec-continue")

    async def step_over(self):
        # Instruction-level, NOT -exec-next. Source-level stepping needs line
        # info, so on a stripped binary -- the normal case in RE/pwn work --
        # -exec-next dies with "Cannot find bounds of current function".
        # -exec-next-instruction works off raw addresses and steps over calls.
        return await self.exec_command("-exec-next-instruction")

    async def step_into(self):
        # Same reasoning as step_over; this one descends into calls.
        return await self.exec_command("-exec-step-instruction")

    async def finish(self):
        return await self.exec_command("-exec-finish")

    async def interrupt(self):
        return await self.exec_command("-exec-interrupt")

    async def fetch_register_names(self) -> list[str]:
        """-data-list-register-names returns names ordered by register
        number; -data-list-register-values only ever gives back that numeric
        index, never the name, so we must resolve them ourselves. Blank
        entries are KEPT -- dropping them would shift every later index."""
        record = await self.send(
            "-data-list-register-names", wait_result=True, quiet=True
        )
        if not record or record.get("klass") == "error":
            return []
        names = _payload(record).get("register-names", [])
        if not isinstance(names, list):
            return []
        return [n if isinstance(n, str) else "" for n in names]

    async def refresh_registers(self):
        return await self.send(
            "-data-list-register-values x",
            wait_result=True, timeout=MI_INTERACTIVE_TIMEOUT, quiet=True,
        )

    async def refresh_disasm(self):
        # NOTE: the trailing "-- 0" (not just "0") is required by the MI
        # grammar to separate the disassembly mode from the "-s/-e" options;
        # omitting it makes GDB reject the whole command with ^error.
        #
        # "-a $pc" (function-based) also errors out with "No function
        # contains specified address" whenever $pc has landed somewhere GDB
        # can't resolve to an enclosing function -- exactly what happens
        # after a stack smash sends control flow somewhere wild, i.e.
        # precisely when you need the disassembly most. An address range
        # works regardless of symbols.
        return await self.send(
            "-data-disassemble -s $pc -e $pc+160 -- 0",
            wait_result=True, timeout=MI_INTERACTIVE_TIMEOUT, quiet=True,
        )

    async def refresh_stack(self, count: int = 128):
        return await self.send(
            f"-data-read-memory-bytes $sp {count}",
            wait_result=True, timeout=MI_INTERACTIVE_TIMEOUT, quiet=True,
        )

    async def raw(self, cmd: str) -> Optional[dict]:
        """Send a CLI command, rewriting the resuming ones to async MI.

        Returns the reply to the LAST command sent when it was an execution
        command (so the caller can update its running/stopped state), else
        None.
        """
        translated = translate_exec_command(cmd)
        if translated is None:
            await self.send(f"-interpreter-exec console {_mi_quote(cmd)}")
            return None
        mi_commands, note = translated
        if note:
            await self._dispatch_event(
                {"type": "log", "klass": "stream", "payload": note + "\n"}
            )
        record = None
        for mi in mi_commands:
            record = await self.send(
                mi, wait_result=True, timeout=MI_INTERACTIVE_TIMEOUT
            )
            if record and record.get("klass") == "error":
                break
        return record

    async def close(self):
        self.alive = False
        if self.proc and self.proc.returncode is None:
            try:
                self.proc.terminate()
                await asyncio.wait_for(self.proc.wait(), 2.0)
            except (ProcessLookupError, asyncio.TimeoutError):
                try:
                    self.proc.kill()
                except ProcessLookupError:
                    pass
            except Exception:
                _log_exception("terminating gdb")
        self._stop_pty_reader()
        if self._reader_task is not None:
            self._reader_task.cancel()
        for task in list(self._tasks):
            task.cancel()
        for fd in (self._pty_master, self._pty_slave):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        self._pty_master = self._pty_slave = None


def _payload(record: Optional[dict]) -> dict:
    """Record payloads are dicts for well-formed results but can be a bare
    string (or None) for odd/streamed ones -- normalise so callers can
    always just .get() without an isinstance dance."""
    if not record:
        return {}
    payload = record.get("payload")
    return payload if isinstance(payload, dict) else {}


def _error_message(record: Optional[dict]) -> str:
    if not record:
        return "no response from GDB"
    payload = record.get("payload")
    if isinstance(payload, dict):
        return str(payload.get("msg", "unknown error"))
    return str(payload) if payload else "unknown error"


# --------------------------------------------------------------------------
# Dangerous PLT/GOT function detection via pwntools
# --------------------------------------------------------------------------

DANGEROUS_FUNCS = {
    "system", "exec", "execve", "execl", "execlp", "execvp", "popen",
    "strcpy", "strncpy", "strcat", "sprintf", "snprintf", "vsprintf", "gets",
    "memcpy", "memmove", "read", "recv", "scanf", "fscanf", "sscanf",
    "malloc", "free", "realloc", "printf", "fprintf", "puts", "mprotect",
}


@dataclass
class BpTarget:
    """One row of the Smart Breakpoints panel.

    `location` is what actually gets handed to GDB, and it is deliberately a
    SYMBOL (e.g. "strcpy@plt"), not a raw address: for a PIE binary the
    addresses pwntools reports are unrelocated file offsets, so
    `-break-insert *0x1050` would plant a breakpoint at a bogus address that
    never fires once the loader picks a real base. GDB relocates symbol
    locations for us.
    """

    name: str          # display name, e.g. "strcpy"
    address: int       # address as seen in the ELF (unrelocated when PIE)
    location: str      # MI location argument
    kind: str          # "plt"/"sym" (breakpoint) | "got" (watchpoint)

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.name}"


def find_smart_breakpoints(elf: ELF) -> list[BpTarget]:
    """Return the interesting PLT (breakpoint) and GOT (watchpoint) targets.

    A statically linked binary -- extremely common in ROP challenges -- has
    NO PLT and NO GOT at all, so a PLT-only scan left the panel completely
    empty on exactly the targets where a function list is most useful. Fall
    back to defined function symbols in that case.
    """
    targets: list[BpTarget] = []
    seen: set[str] = set()

    for name, addr in getattr(elf, "plt", {}).items():
        base = name.split("@")[0]
        if base in DANGEROUS_FUNCS and base not in seen:
            seen.add(base)
            targets.append(BpTarget(base, addr, f"{base}@plt", "plt"))

    if not targets:
        symbols: dict[str, int] = {}
        for name, func in getattr(elf, "functions", {}).items():
            addr = getattr(func, "address", None)
            if isinstance(addr, int):
                symbols.setdefault(name, addr)
        for name, addr in getattr(elf, "symbols", {}).items():
            if isinstance(addr, int):
                symbols.setdefault(name, addr)
        for name in sorted(symbols):
            if name in DANGEROUS_FUNCS and name not in seen:
                seen.add(name)
                targets.append(BpTarget(name, symbols[name], name, "sym"))

    # A *breakpoint* on a GOT slot is meaningless -- the slot holds data, not
    # code, so execution never reaches it and the breakpoint silently never
    # fires. What you actually want while hunting GOT overwrites is a
    # watchpoint on the slot's contents.
    if not bool(getattr(elf, "pie", False)):
        for name, addr in getattr(elf, "got", {}).items():
            base = name.split("@")[0]
            if base in DANGEROUS_FUNCS:
                targets.append(
                    BpTarget(f"{base}@got", addr, f"*(void**){hex(addr)}", "got")
                )

    targets.sort(key=lambda t: (0 if t.kind in ("plt", "sym") else 1, t.name))
    return targets


# --------------------------------------------------------------------------
# Checksec badges
# --------------------------------------------------------------------------

def analyze_checksec(elf: ELF) -> dict:
    relro = getattr(elf, "relro", None)
    return {
        "pie": bool(elf.pie),
        "nx": bool(elf.nx),
        "canary": bool(elf.canary),
        "relro": relro or "None",  # pwntools: None | "Partial" | "Full"
        "arch": getattr(elf, "arch", "?"),
        "bits": getattr(elf, "bits", 0),
    }


GREEN_DOT = "\U0001F7E2"
YELLOW_DOT = "\U0001F7E1"
RED_DOT = "\U0001F534"


def build_checksec_text(info: dict) -> Text:
    """Built as a Text with explicit styles rather than a markup string:
    nothing here can ever be re-parsed as a style tag."""
    text = Text(no_wrap=True)
    for label, enabled in (
        ("PIE", info["pie"]),
        ("NX", info["nx"]),
        ("Canary", info["canary"]),
    ):
        text.append(f"{label}: ", style="bold")
        text.append(f"{GREEN_DOT if enabled else RED_DOT}    ")
    relro = info["relro"]
    dot = GREEN_DOT if relro == "Full" else YELLOW_DOT if relro == "Partial" else RED_DOT
    text.append("RELRO: ", style="bold")
    text.append(f"{dot} {relro}    ")
    text.append("Arch: ", style="bold")
    text.append(f"{info.get('arch', '?')}-{info.get('bits', 0)}")
    return text


# --------------------------------------------------------------------------
# Hexdump formatting (memory-viewer modal)
# --------------------------------------------------------------------------

def format_hexdump(base_addr: int, hex_contents: str, bits: int = 64) -> list[str]:
    """Render raw hex bytes (as returned by -data-read-memory-bytes) as a
    classic 16-bytes-per-line hex + ASCII dump.

    `bits` only sets the address column width -- padding a 32-bit target's
    0x0804a010 out to sixteen digits wastes eight columns per row and makes
    the dump harder to match against anything else on screen."""
    try:
        raw = bytes.fromhex(hex_contents)
    except ValueError:
        # Odd-length / non-hex contents: salvage what we can instead of
        # exploding on a partial read.
        usable = "".join(c for c in hex_contents if c in "0123456789abcdefABCDEF")
        raw = bytes.fromhex(usable[: len(usable) // 2 * 2])
    width = 16
    lines = []
    for i in range(0, len(raw), width):
        chunk = raw[i:i + width]
        addr = base_addr + i
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        digits = 8 if bits == 32 else 16
        lines.append(f"0x{addr:0{digits}x}  {hex_part:<47}  |{ascii_part}|")
    return lines


def format_stack_words(
    base_addr: int,
    hex_contents: str,
    marks: dict[int, str],
    width: int = 60,
    word: int = 8,
) -> list[str]:
    """Word-sized little-endian view of the stack, with $sp/$fp flagged.

    `word` is the target's pointer size in BYTES. Rendering a 32-bit target
    eight bytes at a time fuses two unrelated stack slots into one nonsense
    number -- a saved EIP and the dword above it show up as a single
    0x0804a02a0804921e -- which makes the pane useless for exactly the
    return-address hunting it exists for.

    The stack is the narrowest panel in the grid, and a fixed-width row
    (mark + address + offset + qword + ASCII = 48-57 columns depending on
    the address) ran off the right-hand edge -- RichLog clips, it does not
    warn -- so the ASCII gutter, the part that makes a wall of
    0x4141414141414141 readable, was the first thing lost.

    Rather than hand-tuned width thresholds (which drift the moment the
    format changes), each row is built in descending richness and the first
    variant that actually fits `width` wins.
    """
    try:
        raw = bytes.fromhex(hex_contents)
    except ValueError:
        return []

    word = 4 if word == 4 else 8
    vw = 2 + word * 2                      # "0x" + two hex digits per byte
    lines = []
    for i in range(0, len(raw) - (word - 1), word):
        chunk = raw[i:i + word]
        addr = base_addr + i
        value = int.from_bytes(chunk, "little")
        # The mark is followed by a space: "sp0x7fff..." read as one token
        # and the eye could not find the address boundary.
        mark = f"{marks.get(addr, '  ')} "
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        full = f"{addr:#0{vw}x}"
        # A 64-bit stack address never uses the top 16 bits, so dropping them
        # buys four columns for free. There is nothing equivalent to drop on
        # a 32-bit target.
        short = f"{addr & 0xFFFFFFFFFFFF:#014x}" if word == 8 else full
        # Ordered richest-first; the first variant that fits `width` wins.
        # The ASCII gutter is deliberately the LAST column to go: on a
        # smashed stack it is the only thing that turns a wall of
        # 0x6161617461616173 into "saaataaa", which is the offset you came
        # here to find. Everything else -- the frame offset, the leading
        # zeros of the address, even the delimiters around the ASCII --
        # is given up before it.
        # Below a certain width nothing absolute fits, but the pane is
        # anchored at $sp, so "+018" locates a slot just as precisely as
        # 0x7fffffffdad8 does and costs ten fewer columns.
        off = f"+{i:03x}"
        variants = (
            f"{mark}{full}|{off}  {value:#0{vw}x}  |{ascii_part}|",
            f"{mark}{full}  {value:#0{vw}x}  |{ascii_part}|",
            f"{mark}{short}  {value:#0{vw}x}  |{ascii_part}|",
            f"{mark}{short} {value:#0{vw}x} |{ascii_part}|",
            f"{mark}{short} {value:#0{vw}x} {ascii_part}",
            f"{mark}{off} {value:#0{vw}x} {ascii_part}",
            f"{mark}{short} {value:#0{vw}x}",
            f"{mark}{off} {value:#0{vw}x}",
            f"{mark}{off} {value:#x}",
        )
        lines.append(next((v for v in variants if len(v) <= width), variants[-1]))
    return lines


# --------------------------------------------------------------------------
# Textual UI
# --------------------------------------------------------------------------

REG_ORDER_64 = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "eflags",
]
REG_ORDER_32 = [
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip", "eflags",
]
#: Column budget for the three top panels. The disassembly floor is what
#: stops it being squeezed into an empty bordered sliver on a narrow
#: terminal; the side panels are shrunk past their comfortable size to pay
#: for it, because a cramped breakpoint list still works and a zero-width
#: disassembly pane does not.
BP_WIDTH = (14, 30)          # (hard floor, preferred cap)
REGS_WIDTH = (20, 48)
DISASM_FLOOR = 24


def panel_widths(total: int) -> tuple[int, int]:
    """(Smart Breakpoints width, registers/stack column width) for a
    terminal `total` columns wide. Disassembly takes the remainder."""
    bp_min, bp_max = BP_WIDTH
    rg_min, rg_max = REGS_WIDTH
    bp = max(bp_min, min(bp_max, total * 20 // 100))
    regs = max(rg_min, min(rg_max, total * 33 // 100))
    deficit = DISASM_FLOOR - (total - bp - regs)
    if deficit > 0:
        # Take it from the registers column first: it degrades gracefully
        # (the stack rows have a fallback ladder and the register table
        # simply clips its padding), whereas the breakpoint list starts
        # truncating symbol names almost immediately.
        take = max(0, min(deficit, regs - rg_min))
        regs -= take
        deficit -= take
        bp -= max(0, min(deficit, bp - bp_min))
    return bp, regs


PC_NAMES = ("rip", "eip", "pc")
SP_NAMES = ("rsp", "esp", "sp")
FP_NAMES = ("rbp", "ebp", "fp")

#: Registers that exist on exactly one of the two x86 register sets, used to
#: tell them apart. Note what is NOT here: "eflags". It is present on i386
#: AND on x86-64, so the obvious `any(r in regs for r in REG_ORDER_64)` test
#: matched on a 32-bit target through eflags alone -- and then filtered the
#: 64-bit order against a 32-bit register set, leaving the pane showing
#: eflags and nothing else on every single 32-bit challenge.
_ONLY_64 = ("rip", "rsp", "rax", "rbp", "r15")
_ONLY_32 = ("eip", "esp", "eax", "ebp")


class BreakpointItem(ListItem):
    """A Smart Breakpoints row that carries its own target.

    The target lives on the widget itself rather than being looked up by
    row index in a parallel list -- that mapping is what silently desyncs
    (and then silently no-ops) as soon as the list is filtered, sorted or
    re-populated.
    """

    def __init__(self, target: BpTarget) -> None:
        self.target = target
        self.bkpt_num: Optional[str] = None
        self._label = Label(self._render_text())
        super().__init__(self._label)

    def _render_text(self) -> Text:
        text = Text(no_wrap=True)
        marker = "●" if self.bkpt_num else "○"
        text.append(f"{marker} ", style=S_OK if self.bkpt_num else "dim")
        text.append(f"{self.target.name:<12}", style="bold")
        text.append(f" {self.target.address:#x}", style="cyan")
        if self.target.kind == "got":
            text.append(" w", style="dim")
        if self.bkpt_num:
            # GDB never recycles breakpoint numbers, so the id climbing on
            # every set is expected -- showing it on the row makes it obvious
            # that the row and the console line refer to the same object.
            text.append(f" #{self.bkpt_num}", style=S_OK)
        return text

    def refresh_label(self) -> None:
        self._label.update(self._render_text())


class SmartBreakpointsPanel(ListView):
    """Left panel: dangerous PLT/GOT functions."""

    BORDER_TITLE = "Smart Breakpoints"


class DisassemblyPanel(RichLog, can_focus=False):
    """Center panel: current disassembly, $pc highlighted."""

    BORDER_TITLE = "Disassembly"


class RegistersTable(DataTable, can_focus=False):
    """Top-right: registers, changed ones highlighted."""

    BORDER_TITLE = "Registers"


class StackPanel(RichLog, can_focus=False):
    """Bottom-right: stack dump."""

    BORDER_TITLE = "Stack"


class ConsolePanel(RichLog, can_focus=False):
    """Bottom: raw GDB console output.

    can_focus=False matters: RichLog is focusable by default, and because it
    is composed before the Input it used to grab the app's initial focus.
    Arrow keys then scrolled this log instead of moving the Smart
    Breakpoints cursor, and Enter went nowhere -- which is exactly what
    "the breakpoint list doesn't respond" looks like from the outside.
    """

    BORDER_TITLE = "Console"


class ConsoleInput(Input):
    """The console box, with Up/Down history.

    Input binds neither arrow, being single-line, so this costs nothing and
    saves retyping "run < payload.bin" after every one of the dozens of
    crashes a session is made of.
    """

    BINDINGS = [
        Binding("up", "history_prev", "Previous command", show=False),
        Binding("down", "history_next", "Next command", show=False),
    ]

    def _recall(self, delta: int) -> None:
        app = self.app
        history = getattr(app, "_history", None)
        if not history:
            return
        pos = max(0, min(len(history), getattr(app, "_history_pos", 0) + delta))
        app._history_pos = pos
        # One past the end is the empty "new command" slot, so Down out of
        # the history returns you to a blank box rather than sticking on the
        # newest entry.
        self.value = "" if pos >= len(history) else history[pos]
        self.cursor_position = len(self.value)

    def action_history_prev(self) -> None:
        self._recall(-1)

    def action_history_next(self) -> None:
        self._recall(1)


class CheckSecBar(Static):
    """One-line strip of checksec-style protection badges, docked under Header."""


class MemoryOutput(RichLog, can_focus=False):
    """The hexdump pane inside the memory modal.

    can_focus=False: RichLog is focusable by default, so Tab used to park
    the caret in here, where Enter and typing did nothing at all -- which
    from the outside is indistinguishable from the modal having hung.
    """


class MemoryViewerModal(ModalScreen):
    """Prompt for an address/register, then show a GDB hexdump of it."""

    DEFAULT_CSS = """
    MemoryViewerModal {
        align: center middle;
    }

    #mem-viewer-box {
        width: 90%;
        height: 90%;
        border: thick $accent;
        background: $surface;
        padding: 1 2;
    }

    #mem-addr-input { height: 3; margin-bottom: 1; }
    #mem-submit-btn { height: 3; margin-bottom: 1; width: 100%; }
    #mem-output { height: 1fr; border: round $accent; }
    """

    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="mem-viewer-box"):
            yield Label(
                "Memory Viewer -- address or register, optionally followed by a "
                "byte count.\n"
                "e.g.  $rsp  |  $rsp 512  |  0x401196  |  $rip+16    "
                "(%rsp and rsp are accepted too)"
            )
            yield Input(placeholder="address / register [count]", id="mem-addr-input")
            yield Button("Read Memory", id="mem-submit-btn", variant="primary")
            # markup=False: hexdump ASCII columns contain literal "[" and "]"
            # bytes straight out of process memory.
            yield MemoryOutput(
                id="mem-output", markup=False, highlight=False, min_width=16
            )

    _req: int = 0

    #: Expression parked because the target was running when it was asked
    #: for. Re-read automatically once the target stops (F4, a breakpoint,
    #: a crash) so interrupting from inside the modal actually answers the
    #: question instead of just clearing the way to ask it again.
    _deferred_expr: Optional[str] = None

    def on_mount(self) -> None:
        self.focus_input()

    def focus_input(self) -> None:
        try:
            self.query_one("#mem-addr-input", Input).focus()
        except Exception:
            pass

    def on_target_stopped(self) -> None:
        expr = self._deferred_expr
        self._deferred_expr = None
        if expr:
            self.run_worker(self._read_memory(expr), exclusive=True)

    # Both paths funnel into _submit(); Input.Submitted covers Enter (the
    # Input's own "enter" binding fires it), the Button covers the mouse and
    # terminals that eat Enter.
    @on(Input.Submitted, "#mem-addr-input")
    async def _on_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        await self._submit()

    @on(Button.Pressed, "#mem-submit-btn")
    async def _on_button(self, event: Button.Pressed) -> None:
        event.stop()
        await self._submit()

    async def _submit(self) -> None:
        expr = self.query_one("#mem-addr-input", Input).value.strip()
        try:
            await self._read_memory(expr)
        except Exception as exc:
            # Never let this fail silently -- whatever is wrong must show up
            # right here in the modal, not vanish into a swallowed action
            # exception with zero visible feedback.
            _log_exception("MemoryViewerModal._submit")
            self._write(f"Internal error: {exc} (see {_ERROR_LOG_PATH})", S_ERROR)

    def _write(self, line: str, style: str = "") -> None:
        try:
            self.query_one("#mem-output", MemoryOutput).write(
                Text(sanitize_console_text(line), style=style)
            )
        except Exception:
            pass

    def _notice(self, title: str, *detail: str) -> None:
        """A multi-line block, not a single thin line.

        Every "why is nothing showing?" report about this panel traced back
        to a one-line message in a tall empty pane: technically present,
        practically invisible, and never naming the next action.
        """
        self._write("", "")
        self._write(f"  {title}", S_WARN)
        for line in detail:
            self._write(f"  {line}", S_INFO)

    async def _read_memory(self, expr: str) -> None:
        if not expr:
            return

        output = self.query_one("#mem-output", MemoryOutput)
        output.clear()

        # Each submission supersedes the one before it. Without this, a slow
        # reply arriving after a newer request would clear the pane and
        # render stale bytes over the answer the user is actually looking at.
        MemoryViewerModal._req += 1
        req = MemoryViewerModal._req

        app: PwnTUI = self.app  # type: ignore[assignment]
        if not app.gdb or not app.gdb.alive:
            self._write("GDB session is not running.", S_ERROR)
            return

        needs_regs = "$" in normalize_mem_expr(expr, getattr(app, "_reg_names", ()))

        if needs_regs and not app.state.running:
            # The commonest cause of "the memory viewer shows nothing": the
            # target was never started, so there are no registers to resolve
            # $rsp/$rip against. GDB answers "No registers.", which names
            # neither the cause nor the fix.
            self._notice(
                "No process yet.",
                "$rsp and $rip only exist once the target is running.",
                "Press F5 to start it, then read again.",
                "Absolute addresses such as 0x401196 work without a process.",
            )
            return

        if needs_regs and app.state.executing:
            # Registers are unreadable while the thread runs, and a wedged
            # GDB will not answer at all -- say so instead of burning the
            # timeout on a request that cannot succeed.
            self._deferred_expr = expr
            self._notice(
                "Target is running.",
                "Registers can only be read while it is stopped.",
                "Press F4 to interrupt it -- works from right here, and this "
                "read then runs by itself.",
            )
            return

        # Allow a trailing byte count: "$rsp 512".
        count = 256
        parts = expr.rsplit(None, 1)
        if len(parts) == 2:
            try:
                count = max(16, min(4096, int(parts[1], 0)))
                expr = parts[0]
            except ValueError:
                pass

        original = expr
        expr = normalize_mem_expr(expr, getattr(app, "_reg_names", ()))
        if expr != original:
            self._write(f"reading {original}  ->  {expr}", S_INFO)
        self._write(f"reading {count} bytes at {expr} ...", S_INFO)
        record = await app.gdb.send(
            f"-data-read-memory-bytes {expr} {count}",
            wait_result=True,
            timeout=MI_INTERACTIVE_TIMEOUT,
        )
        if req != MemoryViewerModal._req:
            return  # superseded by a newer request; leave its output alone
        output.clear()
        if not record or record.get("klass") == "error":
            msg = _error_message(record)
            self._write("", "")
            self._write(f"  Could not read {expr}", S_ERROR)
            self._write(f"  GDB said: {msg}", S_INFO)
            if "No registers" in msg:
                self._write("  Press F5 to start the target first.", S_INFO)
            elif "syntax error" in msg.lower():
                self._write("  Registers are written $rsp / $rip (not %rsp).", S_INFO)
            elif "No symbol" in msg:
                self._write("  Unknown symbol -- try $rsp, $rip or an address.", S_INFO)
            return

        memory = _payload(record).get("memory", [])
        if not memory:
            self._write(f"No memory returned for {expr}.", S_WARN)
            return

        for block in memory:
            if not isinstance(block, dict):
                continue
            try:
                base = int(block.get("begin", "0x0"), 0)
            except (ValueError, TypeError):
                base = 0
            bits = app._arch_bits()
            for line in format_hexdump(base, block.get("contents", ""), bits):
                output.write(Text(line))


class PwnTUI(App):
    CSS = """
    /* Scoped to a class, NOT a bare `Screen` selector. `Screen` matches
       every subclass, modal screens included, so this 3x4 grid was also
       being applied to MemoryViewerModal -- which stuffed its 90%-sized
       box into one grid cell (18x5 on a 110-column terminal) and left the
       hexdump pane ZERO rows tall. The viewer looked like it was opening
       and then showing nothing, because there was nowhere for the bytes
       to go. */
    Screen.main-screen {
        layout: grid;
        grid-size: 3 4;
        grid-rows: 1fr 1fr 1fr auto;
        grid-columns: 1fr 2fr 1fr;
    }

    #panels-row { column-span: 3; row-span: 2; height: 100%; }

    /* These are start-up defaults only: the real widths are assigned from
       panel_widths() in on_resize. A fixed 30 plus a 48-column minimum
       added up to 78 of an 80-column terminal and left DisassemblyPanel a
       two-column sliver -- a bordered empty box with nothing in it. */
    SmartBreakpointsPanel { width: 30; border: round $accent; height: 100%; }
    DisassemblyPanel      { width: 1fr; border: round $accent; height: 100%; }
    #regs-stack-col       { width: 48; height: 100%; }
    RegistersTable        { border: round $accent; height: 1fr; }
    StackPanel            { border: round $accent; height: 1fr; }

    #console-input-row { column-span: 3; border: round $accent; height: 3; }
    #console-log       { column-span: 3; height: 100%; border: round $accent; }

    SmartBreakpointsPanel:focus { border: round $success; }
    #console-input-row:focus    { border: round $success; }

    CheckSecBar {
        dock: top;
        height: 1;
        content-align: center middle;
        background: $panel;
    }
    """

    AUTO_FOCUS = "#bp-list"

    # priority=True on the function keys: a priority binding is checked
    # BEFORE the focused widget sees the key, so F5/F8/F9/F10/F11 fire
    # identically whether the console Input, the breakpoint list or a modal
    # has focus. The single-letter shortcuts are deliberately left
    # non-priority so that typing "continue" into the console box types
    # "continue" instead of stepping the program eight times.
    BINDINGS = [
        Binding("f5", "gdb_run", "Run", priority=True),
        Binding("f6", "gdb_continue", "Continue", priority=True),
        Binding("f8", "step_out", "Step Out", priority=True),
        Binding("f9", "toggle_breakpoint", "Toggle BP", priority=True),
        Binding("f2", "open_memory_viewer", "Memory", priority=True),
        Binding("f4", "gdb_interrupt", "Interrupt", priority=True),
        Binding("f10", "step_over", "Step Over (ni)", priority=True),
        Binding("f11", "step_into", "Step Into (si)", priority=True),
        Binding("ctrl+q", "quit", "Quit", priority=True),
        Binding("n", "step_over", "Step Over (ni)", show=False),
        Binding("s", "step_into", "Step Into (si)", show=False),
        Binding("c", "gdb_continue", "Continue", show=False),
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
        Binding("enter", "toggle_breakpoint", "Set BP", show=False),
        Binding("y", "copy_console", "Save Console"),
        Binding("m", "open_memory_viewer", "Memory", show=False),
        Binding("i", "focus_input", "Console"),
        Binding("escape", "focus_panels", "Leave input", show=False),
        Binding("q", "quit", "Quit"),
    ]

    def get_default_screen(self):
        """Tag the main screen so the grid layout above applies to it alone.

        Done here rather than in on_mount so the class is present for the
        very first layout pass -- otherwise the panels flash through an
        unstyled arrangement on start-up.
        """
        screen = super().get_default_screen()
        screen.add_class("main-screen")
        return screen

    def __init__(self, binary: str, args: list[str]):
        super().__init__()
        self.binary = binary
        self.args = args
        self.gdb: Optional[GdbSession] = None
        self.state = GdbState()
        self._console_lines: list[str] = []
        self._reg_names: list[str] = []
        self._smart_bps: list[BpTarget] = []
        self._elf: Optional[ELF] = None
        # GDB emits its stream records in arbitrary chunks -- a single
        # console line routinely arrives as ~"\nProgram" followed by
        # ~" received signal SIGSEGV". Buffer per channel and only emit on a
        # real newline, or the console turns into shredded half-sentences.
        self._stream_bufs: dict[str, str] = {}
        self._flush_timer = None
        self._busy_warned = False
        self._executing_since = 0.0
        self._not_running_since = 0.0
        self._last_console_line: Optional[str] = None
        self._console_repeat = 0
        self._repeat_timer = None
        self._refresh_lock = asyncio.Lock()
        self._refresh_gen = 0
        self._exec_inflight = False
        self._history: list[str] = []
        self._history_pos = 0

    # --- composition ------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield CheckSecBar(id="checksec-bar", markup=False)
        with Horizontal(id="panels-row"):
            yield SmartBreakpointsPanel(id="bp-list")
            # markup=False everywhere below: real disassembly text (e.g.
            # "mov QWORD PTR [rbp-0x10],rax"), hexdump ASCII columns and raw
            # GDB console output ("info functions [s]") are full of square
            # brackets. With markup=True Textual parses "[rbp-0x10]" as a
            # style tag -- which at best deletes the text and at worst
            # raises MissingStyle/MarkupError and takes the app down.
            yield DisassemblyPanel(
                id="disasm", markup=False, highlight=True,
                min_width=20, auto_scroll=False, wrap=True,
            )
            with Vertical(id="regs-stack-col"):
                yield RegistersTable(id="regs", zebra_stripes=True)
                yield StackPanel(
                    id="stack", markup=False, highlight=False,
                    min_width=20, auto_scroll=False,
                )
        yield ConsolePanel(
            id="console-log", markup=False, highlight=False, wrap=True, min_width=20
        )
        yield ConsoleInput(
            placeholder="gdb command  |  -MI command  |  !text-to-target-stdin"
                        "  |  Up/Down for history",
            id="console-input-row",
        )
        yield Footer()

    async def on_mount(self) -> None:
        self.title = "PwnTUI"
        self.sub_title = self.binary
        self._apply_layout()

        regs_table = self.query_one("#regs", RegistersTable)
        regs_table.add_columns("Register", "Value")

        # --- static analysis (pwntools) ---
        try:
            pwn_context.log_level = "error"
            self._elf = ELF(self.binary, checksec=False)
            self._smart_bps = find_smart_breakpoints(self._elf)
            self.query_one("#checksec-bar", CheckSecBar).update(
                build_checksec_text(analyze_checksec(self._elf))
            )
        except Exception as exc:
            self._smart_bps = []
            if "Magic number" not in str(exc):
                # A plainly-not-an-ELF file is a user mistake with an
                # obvious message, not a defect: keep the traceback out of
                # the error log so what IS in there stays worth reading.
                _log_exception("loading ELF")
            if "Magic number" in str(exc):
                # A wrong path or a wrapper script rather than the challenge
                # binary. "Magic number does not match" names neither.
                self._log_console(
                    f"{self.binary} is not an ELF binary -- no symbols, no "
                    f"Smart Breakpoints, and GDB will not be able to run it "
                    f"either. Did you mean a different file?",
                    S_ERROR,
                )
            else:
                self._log_console(f"Failed to load ELF symbols: {exc}", S_ERROR)

        bp_list = self.query_one("#bp-list", SmartBreakpointsPanel)
        if self._smart_bps:
            await bp_list.extend(BreakpointItem(t) for t in self._smart_bps)
            # ListView starts with index=None when it is built empty, and an
            # index of None makes action_select_cursor() return immediately
            # -- Enter would do nothing at all until you first pressed an
            # arrow key. Highlight row 0 as soon as there are rows.
            bp_list.index = 0
        else:
            reason = ("(no ELF loaded)" if self._elf is None
                      else "(no PLT/GOT hits)")
            await bp_list.append(ListItem(Label(Text(reason, style=S_INFO))))

        # --- GDB ---
        self.gdb = GdbSession(self.binary, self.args, self._on_mi_event)
        try:
            await self.gdb.start()
        except (FileNotFoundError, OSError) as exc:
            self._log_console(f"Could not start gdb: {exc}", S_ERROR)
            return

        await self.gdb.send("-gdb-set mi-async on")
        await self.gdb.send("-gdb-set confirm off")
        await self.gdb.send("-gdb-set pagination off")
        self._reg_names = await self.gdb.fetch_register_names()
        self._log_console("GDB session started.", S_OK)
        self._log_console(
            "F5 run · F10 ni · F11 si · F8 finish · F6/c continue · "
            "Enter or F9 toggle breakpoint · m memory · i console · q quit",
            S_INFO,
        )

    def on_resize(self, event=None) -> None:
        # event.size, not self.size: App.size is still the PREVIOUS size
        # while this handler runs, so reading it laid the panels out one
        # resize behind and a drag-to-resize left them permanently stale.
        size = getattr(event, "size", None)
        self._apply_layout(size.width if size is not None else None)

    def _apply_layout(self, width: Optional[int] = None) -> None:
        """Re-divide the top row between the three panels for the current
        terminal width."""
        if width is None:
            width = self.size.width
        if not width:
            return
        bp, regs = panel_widths(width)
        for selector, value in (("#bp-list", bp), ("#regs-stack-col", regs)):
            try:
                self.query_one(selector).styles.width = value
            except Exception:
                pass

    async def on_unmount(self) -> None:
        for attr in ("_flush_timer", "_repeat_timer"):
            timer = getattr(self, attr, None)
            if timer is not None:
                try:
                    timer.stop()
                except Exception:
                    pass
                setattr(self, attr, None)
        if self.gdb:
            await self.gdb.close()

    # --- console output ---------------------------------------------------

    def _write_console_line(self, msg: str, style: str = "") -> None:
        """Low-level writer: one call, one or more literal lines.

        `msg` is treated as PLAIN TEXT and rendered through a rich Text with
        an explicit style -- it is never parsed as markup. That is the whole
        fix for the bracket crashes: GDB output like "x/5i $pc",
        "mov QWORD PTR [rbp-0x10],rax" or "info functions [s]" cannot be
        mistaken for a style tag if no markup parser ever touches it.
        Styling is passed out-of-band via `style`.
        """
        try:
            panel = self.query_one("#console-log", ConsolePanel)
        except Exception:
            panel = None

        # Lines are batched into one RichLog.write per run of identical
        # style. `info functions` on a static binary is 1500 lines and
        # `x/4000gx` is 500; one write() per line spent ~5x longer in
        # Textual's render path than a batched write does, and all of it
        # with the UI frozen.
        pending: list[str] = []
        pending_style = style

        def flush_batch() -> None:
            nonlocal pending
            if not pending:
                return
            text = "\n".join(pending)
            pending = []
            if panel is None:
                return
            try:
                panel.write(Text(text, style=pending_style) if pending_style else Text(text))
            except Exception:
                _log_exception("writing to console panel")

        def emit(text: str, text_style: str) -> None:
            nonlocal pending_style
            self._console_lines.append(text)
            if text_style != pending_style:
                flush_batch()
                pending_style = text_style
            pending.append(text)
            if len(pending) >= 500:
                flush_batch()

        msg = sanitize_console_text(msg)
        for line in msg.split("\n"):
            line = line.rstrip("\r")
            # Collapse consecutive identical lines. Any fire-and-forget
            # command repeated by a held-down key produces one identical
            # ^error per press ("Cannot execute this command while the
            # selected thread is running.", "The program is not being run.",
            # ...), and 40 copies of the same red line bury everything that
            # actually mattered. Doing it here rather than by modelling GDB's
            # state covers every cause and can never disable a keybinding.
            if line and line == self._last_console_line:
                self._console_repeat += 1
                # The summary is normally emitted by the next DIFFERENT
                # line -- but when the repeats are the last thing that
                # happens (you stop pressing the key), no such line ever
                # comes and the count was silently discarded: the console
                # simply showed one error where forty had occurred.
                self._schedule_repeat_flush()
                continue
            self._flush_repeat(emit)
            self._last_console_line = line
            emit(line, style)
        flush_batch()
        # Keep the in-memory transcript bounded on long fuzzing sessions.
        if len(self._console_lines) > 20000:
            del self._console_lines[:10000]

    def _flush_repeat(self, emit=None) -> None:
        if not self._console_repeat:
            return
        count = self._console_repeat
        self._console_repeat = 0
        text = f"      ... repeated {count} more times"
        if emit is not None:
            emit(text, S_INFO)
            return
        self._console_lines.append(text)
        try:
            self.query_one("#console-log", ConsolePanel).write(Text(text, style=S_INFO))
        except Exception:
            pass

    def _schedule_repeat_flush(self) -> None:
        if self._repeat_timer is not None:
            try:
                self._repeat_timer.stop()
            except Exception:
                pass
            self._repeat_timer = None
        try:
            self._repeat_timer = self.set_timer(0.5, self._flush_repeat)
        except Exception:
            self._repeat_timer = None

    def _log_console(self, msg: str, style: str = "") -> None:
        """PwnTUI's own messages. Any half-received GDB stream text is
        flushed first so the transcript keeps its true ordering."""
        self._flush_streams()
        self._write_console_line(msg, style)

    def _stream_console(self, channel: str, text: str, style: str) -> None:
        """Buffered write for GDB's ~/@/& stream records."""
        buf = self._stream_bufs.get(channel, "") + text
        if "\n" in buf:
            # Hand the whole block over in ONE call rather than looping a
            # line at a time: _write_console_line splits it itself and can
            # only batch its RichLog writes if it gets to see more than one
            # line per call. GDB delivers `info functions` in a handful of
            # multi-kilobyte chunks, so this is the difference between one
            # write per chunk and fifteen hundred of them.
            complete, _, buf = buf.rpartition("\n")
            self._write_console_line(complete, style)
        self._stream_bufs[channel] = buf
        # A prompt such as "Name: " never gets a newline, so a purely
        # newline-driven flush would leave the user staring at a blank
        # console while the target waits for input. Flush the remainder
        # shortly after the stream goes quiet.
        if buf:
            self._schedule_flush()

    def _schedule_flush(self) -> None:
        if self._flush_timer is not None:
            try:
                self._flush_timer.stop()
            except Exception:
                pass
        try:
            self._flush_timer = self.set_timer(0.15, self._flush_streams)
        except Exception:
            self._flush_timer = None
            self._flush_streams()

    def _flush_streams(self) -> None:
        if self._flush_timer is not None:
            try:
                self._flush_timer.stop()
            except Exception:
                pass
            self._flush_timer = None
        if not self._stream_bufs:
            return
        for channel, buf in list(self._stream_bufs.items()):
            if buf:
                self._write_console_line(buf, _STREAM_STYLES.get(channel, ""))
            self._stream_bufs[channel] = ""

    # --- MI event handling -------------------------------------------------

    async def _on_mi_event(self, record: dict) -> None:
        rtype = record.get("type")
        klass = record.get("klass")
        payload = record.get("payload")

        if rtype in ("console", "log", "target") and isinstance(payload, str):
            # "target" is the debuggee's own pty (its actual stdout).
            self._stream_console(rtype, payload, _STREAM_STYLES[rtype])
            return

        if rtype == "session" and klass == "closed":
            self.state.running = False
            self.state.executing = False
            self._not_running_since = time.monotonic()
            self._busy_warned = False
            self._log_console("GDB exited.", S_WARN)
            return

        if rtype == "exec":
            await self._handle_exec(klass, payload)
            return

        if rtype == "notify":
            self._handle_notify(klass, payload)
            return

        if rtype == "result":
            # THE fix for silently-dropped errors: fire-and-forget commands
            # (-exec-run, -exec-continue, -break-insert from a keypress...)
            # never had anyone awaiting their reply, so a ^error just fell on
            # the floor and the UI looked like it had ignored the keystroke.
            # Every ^error is surfaced here, tagged with the command that
            # produced it, no matter who sent it or whether anyone is waiting.
            if klass == "error":
                if record.get("quiet"):
                    # An internal panel-refresh command. Its failure is
                    # rendered inside the pane that asked for it; repeating
                    # it here as a red "GDB error [-data-disassemble ...]"
                    # blamed the user for a command they never typed, on
                    # every single crash with a corrupted $pc.
                    return
                cmd = record.get("command") or ""
                prefix = f"GDB error [{cmd}]: " if cmd else "GDB error: "
                self._log_console(prefix + _error_message(record), S_ERROR)
            return

    async def _handle_exec(self, klass: Optional[str], payload) -> None:
        data = payload if isinstance(payload, dict) else {}
        if klass == "running":
            self.state.running = True
            if not self.state.executing:
                self._executing_since = time.monotonic()
            self.state.executing = True
            return

        if klass != "stopped":
            return

        self.state.executing = False
        self._busy_warned = False
        reason = str(data.get("reason", "unknown"))

        if reason.startswith("exited"):
            # The inferior is gone. Refreshing registers/disasm/stack now
            # would fire three MI commands that can only ever answer
            # "No registers." / "No symbol \"pc\"..." -- three spurious red
            # errors in the console every single time the program ends.
            self.state.running = False
            self._not_running_since = time.monotonic()
            self.state.current_pc = None
            code = data.get("exit-code")
            if reason == "exited-normally":
                self._log_console("Process exited normally.", S_WARN)
            elif code is not None:
                self._log_console(f"Process exited with code {code}.", S_WARN)
            else:
                self._log_console(f"Process exited ({reason}).", S_WARN)
            self._clear_panels()
            return

        self.state.running = True
        if reason == "signal-received":
            name = data.get("signal-name", "?")
            meaning = data.get("signal-meaning", "")
            self._log_console(f"!! {name} ({meaning}) -- refreshing panels", S_ERROR)
        else:
            self._log_console(f"-- stopped ({reason}); refreshing panels --", S_INFO)
        await self._refresh_all()
        self._wake_memory_modal()

    def _wake_memory_modal(self) -> None:
        """Let an open memory viewer retry a read it had to park."""
        screen = self.screen_stack[-1] if self.screen_stack else None
        if isinstance(screen, MemoryViewerModal):
            try:
                screen.on_target_stopped()
            except Exception:
                _log_exception("waking the memory viewer")

    def _handle_notify(self, klass: Optional[str], payload) -> None:
        data = payload if isinstance(payload, dict) else {}
        if klass == "breakpoint-created":
            bkpt = data.get("bkpt", {})
            if isinstance(bkpt, dict):
                where = bkpt.get("at") or bkpt.get("func") or bkpt.get("addr", "?")
                self._log_console(
                    f"Breakpoint {bkpt.get('number', '?')} at {where}", S_OK
                )
        elif klass == "breakpoint-deleted":
            # GDB emits one of these per breakpoint for ANY deletion --
            # including a `delete` typed into the console. Without acting on
            # it the panel row kept its filled marker and a stale number, so
            # the next Enter tried to delete a breakpoint that no longer
            # existed and still reported "Cleared" for a no-op. (-break-delete
            # answers ^done even for a missing id, so the reply cannot detect
            # this -- the notification is the only reliable signal.)
            number = str(data.get("id", ""))
            self._clear_bp_marker(number)
            self._log_console(f"Breakpoint {number or '?'} deleted.", S_INFO)
        elif klass == "thread-group-exited":
            self.state.running = False
            self.state.executing = False
            self._not_running_since = time.monotonic()
            self._busy_warned = False

    def _clear_bp_marker(self, number: str) -> None:
        """Un-mark the Smart Breakpoints row holding this GDB breakpoint id."""
        if not number:
            return
        try:
            bp_list = self.query_one("#bp-list", SmartBreakpointsPanel)
        except Exception:
            return
        for item in bp_list.children:
            if isinstance(item, BreakpointItem) and item.bkpt_num == number:
                item.bkpt_num = None
                item.refresh_label()

    def _clear_panels(self) -> None:
        for wid, cls in (("#disasm", DisassemblyPanel), ("#stack", StackPanel)):
            try:
                self.query_one(wid, cls).clear()
            except Exception:
                pass
        try:
            self.query_one("#regs", RegistersTable).clear()
        except Exception:
            pass
        self.state.registers = {}
        self.state.prev_registers = {}
        self.state.disasm = []

    # --- panel refresh -----------------------------------------------------

    async def _refresh_all(self) -> None:
        """Repaint registers/disassembly/stack for the current stop.

        Serialised, and superseded by any newer stop. Holding F10 down
        produces stops faster than three MI round-trips can service them, so
        without this two refreshes interleaved their clear()/write() calls
        and the panes ended up holding a mix of two different program
        states -- most visibly two "->" cursors in the disassembly, pointing
        at two different instructions.
        """
        self._refresh_gen += 1
        gen = self._refresh_gen
        async with self._refresh_lock:
            if gen != self._refresh_gen:
                return  # a newer stop arrived while we waited for the lock
            try:
                await self._refresh_registers()
                if gen != self._refresh_gen:
                    return
                await self._refresh_disasm()
                if gen != self._refresh_gen:
                    return
                await self._refresh_stack()
            except Exception:
                _log_exception("refreshing panels")
                self._log_console("Panel refresh failed (see the error log).", S_ERROR)

    async def _refresh_registers(self) -> None:
        if not self.gdb:
            return
        record = await self.gdb.refresh_registers()
        if not record or record.get("klass") == "error":
            return
        values = _payload(record).get("register-values", [])
        if not isinstance(values, list):
            return

        # -data-list-register-values answers with numeric indices only, so
        # without the name table the pane cannot render a single row. The
        # table is fetched once at startup, and if THAT request failed (a
        # slow GDB, a target whose arch was not settled yet) the pane used
        # to stay blank for the rest of the session with nothing ever
        # retrying it. Re-fetch whenever it is missing or too short for the
        # indices GDB is now handing back.
        highest = -1
        for entry in values:
            if isinstance(entry, dict):
                try:
                    highest = max(highest, int(entry.get("number", -1)))
                except (ValueError, TypeError):
                    pass
        if highest >= len(self._reg_names):
            names = await self.gdb.fetch_register_names()
            if names:
                self._reg_names = names

        new_regs: dict[str, int] = {}
        # -data-list-register-values only ever returns {"number": "<idx>",
        # "value": "..."} -- never a "name" field -- so the index has to be
        # resolved against the cached -data-list-register-names order.
        for entry in values:
            if not isinstance(entry, dict):
                continue
            number = entry.get("number")
            raw = entry.get("value", "0")
            if number is None or not isinstance(raw, str):
                continue
            try:
                idx = int(number)
            except (ValueError, TypeError):
                continue
            if not (0 <= idx < len(self._reg_names)):
                continue
            name = self._reg_names[idx]
            if not name:
                continue
            try:
                new_regs[name] = int(raw, 0)
            except (ValueError, TypeError):
                continue  # vector/struct registers render as {...}: skip

        self.state.prev_registers = self.state.registers
        self.state.registers = new_regs
        self.state.current_pc = next(
            (new_regs[n] for n in PC_NAMES if n in new_regs), None
        )
        self._render_registers()

    def _arch_bits(self) -> int:
        """Pointer width of the CURRENT target, from its live register set.

        Taken from the registers rather than the ELF header because that is
        what the register/stack panes are actually rendering; the ELF is
        only the fallback for before the first stop.
        """
        regs = self.state.registers
        if any(r in regs for r in _ONLY_64):
            return 64
        if any(r in regs for r in _ONLY_32):
            return 32
        bits = getattr(self._elf, "bits", 0)
        return 32 if bits == 32 else 64

    def _reg_order(self) -> list[str]:
        regs = self.state.registers
        wanted = REG_ORDER_64 if self._arch_bits() == 64 else REG_ORDER_32
        order = [r for r in wanted if r in regs]
        # Non-x86 target (or an unexpected register set): show whatever we
        # got rather than an empty panel.
        return order or list(regs)[:24]

    def _render_registers(self) -> None:
        table = self.query_one("#regs", RegistersTable)
        table.clear()
        width = self._arch_bits() // 4
        for name in self._reg_order():
            val = self.state.registers[name]
            prev = self.state.prev_registers.get(name)
            changed = prev is not None and prev != val
            table.add_row(
                Text(name, style="bold yellow" if changed else "bold"),
                Text(f"0x{val:0{width}x}", style="red" if changed else "green"),
            )

    async def _refresh_disasm(self) -> None:
        if not self.gdb:
            return
        record = await self.gdb.refresh_disasm()
        panel = self.query_one("#disasm", DisassemblyPanel)
        if not record or record.get("klass") == "error":
            self._render_disasm_failure(panel, _error_message(record))
            self.state.disasm = []
            return
        instructions = _payload(record).get("asm_insns", [])
        self.state.disasm = [i for i in instructions if isinstance(i, dict)]
        self._render_disasm()

    def _render_disasm_failure(self, panel: "DisassemblyPanel", msg: str) -> None:
        """There is no disassembly, and WHY is the interesting part.

        The one case that matters is $pc pointing at unmapped memory: that
        is a successful control-flow hijack, the single most important
        moment in a pwn session, and it used to render as one dim line of
        GDB's own words ("Cannot access memory at address 0x6161617461616173")
        with no hint that the number was the user's own payload.
        """
        panel.clear()
        pc = self.state.current_pc
        unmapped = "cannot access memory" in msg.lower()
        if pc is not None and unmapped:
            panel.write(Text(f"$pc = {pc:#x} -- not mapped.", style=S_ERROR))
            panel.write(Text("Execution has left the program.", style=S_WARN))
            for line in describe_corrupt_pointer(pc, self._arch_bits()):
                panel.write(Text(f"  {line}", style=S_WARN))
            panel.write(Text("", style=""))
            panel.write(Text(f"GDB: {msg}", style=S_INFO))
            panel.write(
                Text("The Stack pane still works -- the return address came "
                     "from there.", style=S_INFO)
            )
        else:
            panel.write(Text(f"<no disassembly: {msg}>", style=S_WARN))

    def _render_disasm(self) -> None:
        panel = self.query_one("#disasm", DisassemblyPanel)
        panel.clear()
        pc = self.state.current_pc
        # Size the symbol column to this batch. A fixed 24-wide column left
        # 24 blank chars on every row of a symbol-less frame (anywhere in
        # stripped libc, or after control flow has been hijacked) and pushed
        # the instruction text off the panel for no reason at all.
        wheres = []
        for insn in self.state.disasm:
            func = str(insn.get("func-name", ""))
            where = f"<{func}+{insn.get('offset', '')}>" if func else ""
            wheres.append(where[:21] + "..>" if len(where) > 24 else where)
        avail = panel.content_size.width or 80
        # Cap the symbol column at a quarter of the pane. One instruction
        # resolving to a long name used to widen the gutter for the whole
        # batch, so a stripped frame with a single symbolised row rendered
        # 24 blank columns on every other line and pushed the operands out.
        wcol = min(max((len(w) for w in wheres), default=0), max(0, avail // 4))
        wheres = [w[:wcol] for w in wheres]
        for insn, where in zip(self.state.disasm, wheres):
            addr_str = str(insn.get("address", "0x0"))
            try:
                addr = int(addr_str, 0)
            except (ValueError, TypeError):
                addr = None
            body = str(insn.get("inst", ""))
            # GDB pads its output generously ("jmp    *0x2fca(%rip)        #
            # 0x404000 <strcpy@got.plt>") and prints 16-digit addresses. In a
            # three-column layout that pushed the jump target -- the single
            # most important part of the line -- past the right edge, where
            # RichLog silently cut it off. Compact the row so it fits.
            body = _WS_RUN_RE.sub(" ", body).strip()
            short_addr = f"{addr:#010x}" if addr is not None else addr_str
            line = f"{short_addr} {where:<{wcol}} {body}" if wcol else f"{short_addr} {body}"
            # 3 columns are consumed by the "-> " / "   " gutter below.
            line = fit_disasm_line(line, avail - 3)
            if pc is not None and addr == pc:
                # A Text object, not a markup string -- `body` is raw
                # disassembly and is guaranteed to contain "[...]" operands.
                panel.write(Text(f"-> {line}", style="bold reverse"))
            else:
                # A Text, like the highlighted row above: this file's rule is
                # that no dynamic string is ever handed to a renderer that
                # could reinterpret it, and disassembly operands are full of
                # brackets ("mov QWORD PTR [rbp-0x10],rax" in Intel flavour).
                panel.write(Text(f"   {line}"))
        # We disassemble forward from $pc, so the current instruction is the
        # first line written. With RichLog's default auto_scroll the panel
        # would sit at the bottom of the range and hide it.
        panel.scroll_home(animate=False)

    async def _refresh_stack(self) -> None:
        if not self.gdb:
            return
        bits = self._arch_bits()
        word = bits // 8
        regs = self.state.registers
        sp = next((regs[n] for n in SP_NAMES if n in regs), None)
        # 16 words either way, so the pane holds the same number of ROWS on
        # both architectures instead of half as many on i386.
        record = await self.gdb.refresh_stack(word * 16)
        panel = self.query_one("#stack", StackPanel)
        panel.clear()
        if not record or record.get("klass") == "error":
            msg = _error_message(record)
            if sp is not None and "cannot access memory" in msg.lower():
                panel.write(Text(f"$sp = {sp:#x} -- not mapped.", style=S_ERROR))
                for line in describe_corrupt_pointer(sp, bits):
                    panel.write(Text(f"  {line}", style=S_WARN))
                panel.write(Text(f"GDB: {msg}", style=S_INFO))
            else:
                panel.write(Text(f"<no stack: {msg}>", style=S_WARN))
            self.state.stack = []
            return
        memory = _payload(record).get("memory", [])
        if not isinstance(memory, list):
            return

        # content_size is 0 before the first layout pass; fall back to the
        # widest layout rather than locking in a degraded one.
        avail = panel.content_size.width or 60
        marks: dict[int, str] = {}
        fp = next((regs[n] for n in FP_NAMES if n in regs), None)
        if fp is not None:
            marks[fp] = "fp"
        if sp is not None:
            marks[sp] = "sp"  # sp wins if fp == sp

        lines: list[str] = []
        for block in memory:
            if not isinstance(block, dict):
                continue
            try:
                base = int(block.get("begin", "0x0"), 0)
            except (ValueError, TypeError):
                continue
            lines.extend(
                format_stack_words(
                    base, block.get("contents", ""), marks, avail, word
                )
            )
        self.state.stack = lines
        for line in lines:
            panel.write(Text(line, style="bold" if line[:2] in ("sp", "fp") else ""))
        panel.scroll_home(animate=False)

    # --- focus helpers -----------------------------------------------------

    def _busy(self) -> bool:
        """True when the inferior is free-running, so an execution command
        cannot be accepted right now.

        Holding F10 down fires one -exec-next-instruction per keypress; every one that
        lands while the target is still running comes back as "Cannot
        execute this command while the selected thread is running." -- 40
        keypresses produced 40 red console lines that buried the real
        output. Drop those at the source and say it once.

        The suppression is deliberately time-bounded. Cached state that
        says "running" can go stale (a *stopped we never saw, a follow-exec,
        a detached inferior), and a guard that trusted it unconditionally
        would silently kill F5/F6/F10/F11 for the rest of the session --
        far worse than the error flood it was added to prevent. After
        BUSY_STALE seconds the command goes through regardless and GDB's own
        answer becomes the source of truth again.
        """
        now = time.monotonic()
        if self.state.executing:
            if now - self._executing_since > BUSY_STALE:
                # Let one through and re-arm, so a genuinely stuck state
                # costs one error every BUSY_STALE seconds, not one per
                # keypress -- and never costs a dead keybinding.
                self._executing_since = now
                return False
            if not self._busy_warned:
                self._busy_warned = True
                self._log_console("Target is running -- F4 interrupts it.", S_WARN)
            return True

        if not self.state.running:
            # Same story for the other direction: once the inferior has
            # exited, every held-down F10 answered "The program is not being
            # run." Suppress the repeats, keep the first one informative.
            if now - self._not_running_since > BUSY_STALE:
                self._not_running_since = now
                return False
            if not self._busy_warned:
                self._busy_warned = True
                self._log_console("No running process -- F5 starts one.", S_WARN)
            return True

        self._busy_warned = False
        return False

    def _typing(self) -> bool:
        """True when the caret is in a text box.

        NOTE: this is deliberately NOT used to gate the action bodies. Textual
        already stops printable keys at the focused Input before any
        non-priority app binding is consulted (so typing "continue" types
        "continue" instead of stepping eight times). Guarding the actions as
        well made them unreachable by every OTHER route -- most visibly, once
        focus was in the console box there was no way at all to open the
        memory viewer, because action_open_memory_viewer() refused to run.
        Reachability is provided by the priority function keys instead.
        """
        return isinstance(self.focused, Input)

    def action_focus_input(self) -> None:
        if self._typing():
            return
        try:
            self.query_one("#console-input-row", ConsoleInput).focus()
        except Exception:
            pass

    def action_focus_panels(self) -> None:
        try:
            self.query_one("#bp-list", SmartBreakpointsPanel).focus()
        except Exception:
            pass

    # --- execution actions (function keys: always available) ---------------

    async def _exec(self, label: str, coro_factory, *, allow_stopped: bool = False):
        """Run one resuming command, once.

        `_exec_inflight` closes a race the time-based `_busy()` guard could
        not see: an execution command is only known to be running once GDB
        answers, and a held-down F10 fires the next keypress into the gap
        before that answer arrives. Both commands then passed the guard, and
        the second came back as "Cannot execute this command while the
        selected thread is running."
        """
        if not self.gdb or self._exec_inflight:
            return
        if allow_stopped:
            # -exec-run: the "no process yet" half of the guard must not
            # apply, but the "already running" half still must.
            if self.state.executing and self._busy():
                return
        elif self._busy():
            return
        self._exec_inflight = True
        try:
            self._log_console(f"$ {label}", S_CMD)
            record = await coro_factory()
            self._note_exec_reply(record)
        finally:
            self._exec_inflight = False

    def _note_exec_reply(self, record: Optional[dict]) -> None:
        """Believe GDB's ^running immediately rather than waiting for the
        *running notification to catch up."""
        if record and record.get("klass") == "running":
            self.state.running = True
            if not self.state.executing:
                self._executing_since = time.monotonic()
            self.state.executing = True

    async def action_gdb_run(self) -> None:
        # -exec-run is exempt from the "no running process" guard for the
        # obvious reason: starting one is exactly what it does.
        await self._exec("run", lambda: self.gdb.run(), allow_stopped=True)

    async def action_gdb_continue(self) -> None:
        await self._exec("continue", lambda: self.gdb.cont())

    async def action_step_over(self) -> None:
        await self._exec("ni", lambda: self.gdb.step_over())

    async def action_step_into(self) -> None:
        await self._exec("si", lambda: self.gdb.step_into())

    async def action_gdb_interrupt(self) -> None:
        """SIGINT the inferior -- the only way out of a target blocked in
        read() (or spinning) short of killing the whole session."""
        if self.gdb:
            self._log_console("$ interrupt", S_CMD)
            await self.gdb.interrupt()

    async def action_step_out(self) -> None:
        """Run to the return of the current frame (gdb `finish`).

        F8 used to be a third spelling of stepi; now that F10/F11 are both
        instruction-level it would have been an exact duplicate of F11, so it
        carries the one stepping verb that was missing instead.
        """
        await self._exec("finish", lambda: self.gdb.finish())

    # --- list navigation ---------------------------------------------------

    def _bp_list(self) -> Optional[SmartBreakpointsPanel]:
        try:
            return self.query_one("#bp-list", SmartBreakpointsPanel)
        except Exception:
            return None

    def action_cursor_down(self) -> None:
        target = self.focused if isinstance(self.focused, ListView) else self._bp_list()
        if target is not None:
            target.action_cursor_down()

    def action_cursor_up(self) -> None:
        target = self.focused if isinstance(self.focused, ListView) else self._bp_list()
        if target is not None:
            target.action_cursor_up()

    # --- breakpoints -------------------------------------------------------

    async def action_toggle_breakpoint(self) -> None:
        """Bound to both Enter and F9.

        Enter normally never reaches here -- ListView owns "enter" and turns
        it into a ListView.Selected message, handled below. This is the path
        for F9 (which works from any focus) and for the case where the list
        is not the focused widget.
        """
        bp_list = self._bp_list()
        if bp_list is None:
            return
        await self._toggle(bp_list.highlighted_child)

    @on(ListView.Selected, "#bp-list")
    async def _on_bp_list_selected(self, event: ListView.Selected) -> None:
        """Enter (or a mouse click) on a Smart Breakpoints row.

        The target is read off the selected widget itself -- event.item is
        the BreakpointItem, which carries its own name/address -- so there
        is no index arithmetic to get out of step with the list.
        """
        event.stop()
        await self._toggle(event.item)

    async def _toggle(self, item: Optional[ListItem]) -> None:
        if not isinstance(item, BreakpointItem):
            return
        if not self.gdb or not self.gdb.alive:
            self._log_console("GDB session is not running.", S_ERROR)
            return

        target = item.target
        if item.bkpt_num:
            record = await self.gdb.send(
                f"-break-delete {item.bkpt_num}", wait_result=True
            )
            if record and record.get("klass") == "error":
                self._log_console(
                    f"Could not delete breakpoint {item.bkpt_num}: "
                    f"{_error_message(record)}",
                    S_ERROR,
                )
                return
            self._log_console(f"Cleared {target.name} (bp {item.bkpt_num})", S_INFO)
            item.bkpt_num = None
            item.refresh_label()
            return

        if target.kind == "got":
            # GOT slots hold data, so watch the slot's contents; a plain
            # breakpoint there would never fire.
            command = f"-break-watch -a {target.location}"
        else:
            # -f == "pending": if the symbol is not resolvable yet (a libc
            # function before the loader has mapped libc, say) GDB keeps the
            # breakpoint pending and binds it on the shared-library load
            # instead of rejecting the command outright.
            command = f"-break-insert -f {target.location}"

        record = await self.gdb.send(command, wait_result=True)
        if not record or record.get("klass") == "error":
            self._log_console(
                f"Could not break on {target.name}: {_error_message(record)}", S_ERROR
            )
            return

        payload = _payload(record)
        bkpt = next(
            (payload[k] for k in ("bkpt", "wpt", "hw-awpt", "hw-rwpt") if k in payload),
            {},
        )
        number = bkpt.get("number") if isinstance(bkpt, dict) else None
        item.bkpt_num = str(number) if number is not None else None
        item.refresh_label()

        kindword = "Watchpoint" if target.kind == "got" else "Breakpoint"
        addr = bkpt.get("addr", hex(target.address)) if isinstance(bkpt, dict) else hex(target.address)
        self._log_console(
            f"{kindword} {item.bkpt_num or '?'} on {target.name} "
            f"({target.location} -> {addr})",
            S_OK,
        )

    # --- misc actions ------------------------------------------------------

    def action_open_memory_viewer(self) -> None:
        """F2 / m. Idempotent: pressing it again focuses the modal already on
        screen instead of pushing a second copy.

        F2 is a priority binding, so it fires from inside the modal too --
        which meant an impatient double-tap left two identical modals
        stacked, each needing its own Escape, and looked exactly like the
        Escape key being ignored."""
        screen = self.screen_stack[-1] if self.screen_stack else None
        if isinstance(screen, MemoryViewerModal):
            screen.focus_input()
            return
        self.push_screen(MemoryViewerModal())

    async def action_copy_console(self) -> None:
        """Dump the full console transcript to a file, and best-effort try
        the system clipboard too. OSC 52 (clipboard) only works if the
        terminal emulator supports it -- plenty don't (e.g. xfce4-terminal),
        and it never bridges out of a VM console to the host either. The
        file is the part that is guaranteed to work everywhere."""
        text = "\n".join(self._console_lines)
        try:
            os.makedirs(os.path.dirname(_CONSOLE_DUMP_PATH), exist_ok=True)
            with open(_CONSOLE_DUMP_PATH, "w") as f:
                f.write(text)
            self._log_console(f"Console saved to {_CONSOLE_DUMP_PATH}", S_INFO)
        except OSError as exc:
            self._log_console(f"Could not write {_CONSOLE_DUMP_PATH}: {exc}", S_ERROR)
        try:
            self.copy_to_clipboard(text)
            self._log_console(
                "Also tried the system clipboard (OSC 52) -- not every terminal "
                "supports it.",
                S_INFO,
            )
        except Exception:
            pass

    def _remember(self, cmd: str) -> None:
        """Append to the console history, de-duplicating an immediate repeat
        and resetting the cursor to the empty slot past the end."""
        if not self._history or self._history[-1] != cmd:
            self._history.append(cmd)
            if len(self._history) > 500:
                del self._history[:100]
        self._history_pos = len(self._history)

    async def action_quit(self) -> None:
        self.exit()

    # --- console input -----------------------------------------------------

    @on(Input.Submitted, "#console-input-row")
    async def _on_console_submit(self, event: Input.Submitted) -> None:
        event.stop()
        raw_value = event.value
        event.input.value = ""
        if not self.gdb:
            return

        if raw_value.startswith("!") and raw_value != "!":
            # "!" sends the rest of the line straight to the debuggee's own
            # stdin (via its pty) -- NOT to GDB. This is how you answer an
            # interactive prompt like "Name: " from the target program while
            # it is running under the debugger.
            line = raw_value[1:]
            self._remember(raw_value)
            self._log_console(f"stdin> {line}", S_STDIN)
            self.gdb.write_stdin((line + "\n").encode())
            return

        cmd = raw_value.strip()
        if not cmd:
            return
        self._remember(cmd)
        self._log_console(f"gdb> {cmd}", S_CMD)
        if cmd.startswith("-"):
            record = await self.gdb.send(
                cmd, wait_result=True, timeout=MI_INTERACTIVE_TIMEOUT
            )
            self._note_exec_reply(record)
        else:
            # CLI syntax, including shell redirection like "run < payload".
            # Resuming commands are rewritten to async MI inside raw() --
            # see translate_exec_command for why that is not optional.
            self._note_exec_reply(await self.gdb.raw(cmd))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pwntui",
        description="Textual-based TUI front-end for GDB/MI, built for pwn/exploit-dev workflows.",
        epilog=(
            "maintenance:\n"
            "  pwntui --update    upgrade textual/pwntools/rich within their tested\n"
            "                     major versions (" + ", ".join(UPDATE_SPECS) + ")\n"
            "  pwntui --repair    force-reinstall the exact versions this release was\n"
            "                     tested against (" + ", ".join(REPAIR_SPECS) + ")\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # NOTE: --update/--repair are also matched by a pre-scan of sys.argv near
    # the top of this file, so they run before textual/pwntools are imported.
    # They are declared here as well so they appear in --help and so an
    # unexpected combination is still rejected with a proper argparse error.
    parser.add_argument(
        "--update",
        action="store_true",
        help="upgrade dependencies within their tested major versions, then exit",
    )
    parser.add_argument(
        "--repair",
        action="store_true",
        help="force-reinstall the exact tested dependency versions, then exit",
    )
    parser.add_argument(
        "--break-system-packages",
        action="store_true",
        help="allow --update/--repair to modify a PEP 668 distro-managed Python "
             "(risks breaking OS tooling; prefer a virtualenv)",
    )
    parser.add_argument(
        "binary",
        nargs="?",
        help="path to the target ELF binary",
    )
    parser.add_argument(
        "args",
        nargs=argparse.REMAINDER,
        help="arguments to pass through to the target binary",
    )
    return parser


def parse_args() -> argparse.Namespace:
    return build_parser().parse_args()


def main() -> None:
    parser = build_parser()
    ns = parser.parse_args()

    # Normally unreachable: the pre-scan above already handled these and
    # exited. This is the fallback for when main() is called from an import
    # or a wrapper rather than as __main__.
    if ns.update or ns.repair:
        raise SystemExit(_dependency_main(sys.argv[1:]))

    if not ns.binary:
        parser.error("the following arguments are required: binary")

    # Resolve to an absolute path so GDB/pwntools can find the binary
    # regardless of which directory `pwntui` is invoked from.
    binary = os.path.abspath(ns.binary)
    if not os.path.isfile(binary):
        print(f"pwntui: error: no such file: {binary}", file=sys.stderr)
        raise SystemExit(1)

    PwnTUI(binary, ns.args).run()


if __name__ == "__main__":
    main()



