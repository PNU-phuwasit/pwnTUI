#!/usr/bin/env python3
"""Headless human-in-the-loop driver for PwnTUI.

Runs the REAL Textual app against the REAL gdb, presses real keys through
the Pilot, and reports anything that looks wrong: python exceptions, entries
appended to the pwntui error log, empty panes, dropped output, hangs.
"""
from __future__ import annotations

import asyncio
import os
import sys
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)
os.chdir(HERE)

import app as A  # noqa: E402
from rich.text import Text  # noqa: E402

ERRLOG = A._ERROR_LOG_PATH

FAILURES: list[str] = []
NOTES: list[str] = []


def fail(scenario: str, msg: str) -> None:
    FAILURES.append(f"[{scenario}] {msg}")
    print(f"  !! FAIL {msg}")


def note(scenario: str, msg: str) -> None:
    NOTES.append(f"[{scenario}] {msg}")
    print(f"  .. {msg}")


def errlog_size() -> int:
    try:
        return os.path.getsize(ERRLOG)
    except OSError:
        return 0


def errlog_tail(since: int) -> str:
    try:
        with open(ERRLOG) as f:
            f.seek(since)
            return f.read()
    except OSError:
        return ""


class Probe:
    """Convenience accessors over a live PwnTUI instance."""

    def __init__(self, app: "A.PwnTUI", pilot, scenario: str):
        self.app = app
        self.pilot = pilot
        self.scenario = scenario

    # --- introspection ---
    def console_text(self) -> str:
        return "\n".join(self.app._console_lines)

    def disasm_lines(self) -> list[str]:
        return self._richlog_lines("#disasm")

    def stack_lines(self) -> list[str]:
        return self._richlog_lines("#stack")

    def _richlog_lines(self, sel: str) -> list[str]:
        w = self.app.query_one(sel)
        out = []
        for strip in getattr(w, "lines", []):
            try:
                out.append("".join(seg.text for seg in strip._segments))
            except Exception:
                out.append(str(strip))
        return out

    def reg_rows(self) -> list[tuple[str, str]]:
        t = self.app.query_one("#regs")
        rows = []
        for key in t.rows:
            cells = t.get_row(key)
            rows.append(tuple(c.plain if isinstance(c, Text) else str(c) for c in cells))
        return rows

    # --- driving ---
    async def press(self, *keys, settle: float = 0.25):
        for k in keys:
            await self.pilot.press(k)
        await self.settle(settle)

    async def settle(self, seconds: float = 0.3):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            await self.pilot.pause()
            await asyncio.sleep(0.02)
        await self.pilot.pause()

    async def console(self, cmd: str, settle: float = 0.6):
        inp = self.app.query_one("#console-input-row", A.Input)
        inp.focus()
        await self.pilot.pause()
        inp.value = cmd
        await self.pilot.press("enter")
        await self.settle(settle)

    async def wait_for(self, pred, timeout: float = 8.0, what: str = "condition"):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if pred():
                return True
            await self.pilot.pause()
            await asyncio.sleep(0.05)
        note(self.scenario, f"timed out waiting for {what}")
        return False


async def drive(binary: str, scenario: str, body, size=(150, 40), args=None):
    """Boot PwnTUI on `binary`, run `body(probe)`, report anything broken."""
    print(f"\n=== {scenario}  ({os.path.basename(binary)}) ===")
    before = errlog_size()
    app = A.PwnTUI(os.path.abspath(binary), args or [])
    t0 = time.monotonic()
    try:
        async with app.run_test(headless=True, size=size) as pilot:
            probe = Probe(app, pilot, scenario)
            await probe.settle(1.5)          # let gdb boot
            await body(probe)
            await probe.settle(0.2)
    except Exception:
        fail(scenario, "python exception escaped the app:\n" + traceback.format_exc())
    elapsed = time.monotonic() - t0
    if elapsed > 240:   # generous: the harness itself sleeps a lot between steps
        fail(scenario, f"scenario took {elapsed:.0f}s -- possible hang")
    tail = errlog_tail(before)
    if tail.strip():
        fail(scenario, "pwntui-error.log grew:\n" + tail[:4000])
    return app
