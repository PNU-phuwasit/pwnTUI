#!/usr/bin/env python3
"""Drive PwnTUI through a scripted session and record it.

Writes an asciinema v2 .cast file, which render.py turns into a GIF (and
which you can also feed to `agg` or upload to asciinema.org if you prefer).

The session runs in a real pty at a fixed size with real keystrokes, so what
gets recorded is the actual program, not a mock-up. Every scene below is a
list of (bytes-to-send, seconds-to-wait-after) pairs -- the wait is what
gives the GIF its pacing, so tune those numbers, not the frame rate.

    ./record.py                 # record every scene
    ./record.py hijack          # just one
    ./record.py --list
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import pty
import struct
import subprocess
import sys
import termios
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
APP = os.path.join(REPO, "app.py")
CHALL = os.path.join(REPO, "qa", "audit")
OUT = os.path.join(HERE, "cast")

# --- key escape sequences (xterm) -------------------------------------------
ENTER, ESC, TAB = b"\r", b"\x1b", b"\t"
F2, F4, F5, F6 = b"\x1bOQ", b"\x1bOS", b"\x1b[15~", b"\x1b[17~"
F8, F9, F10, F11 = b"\x1b[19~", b"\x1b[20~", b"\x1b[21~", b"\x1b[23~"
UP, DOWN = b"\x1b[A", b"\x1b[B"
CTRL_Q = b"\x11"


def typed(text: str, cps: float = 22.0):
    """Send `text` one character at a time so the GIF shows it being typed."""
    return [(bytes([c]), 1.0 / cps) for c in text.encode()]


# --- the scenes -------------------------------------------------------------
# Keep each one short. A README GIF that runs past ~25 s does not get watched.

def scene_hijack():
    """THE headline: a crash where PwnTUI resolves the cyclic offset itself."""
    return (
        "hijack", "c1_ret2win", (110, 30),
        [(b"", 2.2), (b"i", 0.5)]
        + typed("run < p1_hijack.bin")
        + [(b"", 0.8), (ENTER, 4.5), (ESC, 3.5)],
        "A stripped 64-bit ret2win. The return address is overwritten with "
        "pattern bytes; PwnTUI names the offset without being asked.",
    )


def scene_breakpoint():
    """Smart Breakpoints -> run with redirection -> panes populate."""
    return (
        "breakpoint", "c2_nullbyte", (110, 30),
        [(b"", 2.2), (b"j", 0.5), (b"j", 0.9), (ENTER, 1.6), (b"i", 0.5)]
        + typed("run < p2_null.bin")
        + [(b"", 0.8), (ENTER, 3.5), (ESC, 2.5)],
        "Enter sets a breakpoint on a dangerous call. Every pane repaints "
        "itself on the stop.",
    )


def scene_stepping():
    """Instruction stepping on a stripped binary -- no DWARF, no complaints."""
    return (
        "stepping", "c1_ret2win", (110, 30),
        [(b"", 2.2), (ENTER, 1.4), (b"i", 0.4)]
        + typed("run < p1_win.bin")
        + [(b"", 0.6), (ENTER, 3.0), (ESC, 1.0)]
        # Slower than a real held-down key on purpose: at full speed the
        # busy guard fires ("Target is running -- F4 interrupts it") and
        # the console fills with a message about pacing rather than
        # showing the stepping itself.
        + [(F10, 0.95)] * 6
        + [(F11, 1.1), (F10, 0.95), (F10, 2.0)],
        "F10/F11 are instruction-level on purpose: source-level stepping "
        "needs line info a stripped binary does not have.",
    )


def scene_memory():
    """F2 while the target is blocked, F4 from inside it, read completes."""
    return (
        "memory", "c1_ret2win", (110, 30),
        [(b"", 2.2), (F5, 2.5), (F2, 1.2)]
        + typed("$rsp 256")
        # No trailing Escape: the payoff of this scene is the hexdump
        # filling in by itself after F4, so that is what the last frame --
        # the one that gets the long hold -- has to be showing.
        + [(b"", 0.6), (ENTER, 2.6), (F4, 4.0)],
        "The memory viewer while the target sits in read(). F4 interrupts "
        "from inside the modal and the parked read then runs by itself.",
    )


def scene_32bit():
    """A 32-bit target: register set and stack word size both follow."""
    return (
        "32bit", "c3_bof32", (110, 30),
        [(b"", 2.2), (b"i", 0.5)]
        + typed("run < p3_win.bin")
        + [(b"", 0.6), (ENTER, 4.0), (ESC, 2.5)],
        "Same tool, i386 target: eax/esp/eip, 8-digit values and 4-byte "
        "stack slots, decided from the live register set.",
    )


SCENES = {
    "hijack": scene_hijack,
    "breakpoint": scene_breakpoint,
    "stepping": scene_stepping,
    "memory": scene_memory,
    "32bit": scene_32bit,
}


def record(name: str, binary: str, size: tuple[int, int], script, caption: str) -> str:
    cols, rows = size
    target = os.path.join(CHALL, binary)
    if not os.path.exists(target):
        sys.exit(f"missing {target} -- run qa/audit/build.sh first")

    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

    events: list[tuple[float, str, str]] = []
    start = time.time()
    stop = threading.Event()

    def drain():
        while not stop.is_set():
            try:
                data = os.read(master, 65536)
            except OSError:
                break
            if not data:
                break
            events.append((time.time() - start, "o", data.decode("utf-8", "replace")))

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()

    proc = subprocess.Popen(
        [sys.executable, APP, target],
        stdin=slave, stdout=slave, stderr=slave, cwd=CHALL,
        env={**os.environ, "TERM": "xterm-256color", "COLORTERM": "truecolor"},
    )
    os.close(slave)

    # Textual needs a moment to paint its first frame before anything is sent.
    time.sleep(2.0)
    for keys, delay in script:
        if keys:
            os.write(master, keys)
        time.sleep(delay)
    # Everything after this instant is the teardown: Textual animates the
    # screen away on quit, so the last frames are a shrinking, half-drawn
    # modal. They are recorded (the process still has to exit cleanly) but
    # trimmed out below, or the GIF's final hold lands on one of them.
    script_end = time.time() - start
    os.write(master, CTRL_Q)
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    time.sleep(0.4)
    stop.set()
    try:
        os.close(master)
    except OSError:
        pass

    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, f"{name}.cast")
    header = {
        "version": 2, "width": cols, "height": rows,
        "timestamp": int(start), "env": {"TERM": "xterm-256color", "SHELL": "/bin/sh"},
        "title": f"PwnTUI -- {name}",
    }
    kept = [e for e in events if e[0] <= script_end]
    with open(path, "w") as f:
        f.write(json.dumps(header) + "\n")
        for t, kind, data in kept:
            f.write(json.dumps([round(t, 6), kind, data]) + "\n")
    events = kept
    dur = events[-1][0] if events else 0.0
    print(f"  {name:<11} {dur:5.1f}s  {len(events):5d} events  ->  {path}")
    print(f"              {caption}")
    return path


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scenes", nargs="*", default=None,
                    help="scene names to record (default: all)")
    ap.add_argument("--list", action="store_true", help="list the scenes and exit")
    ns = ap.parse_args()

    if ns.list:
        for key, fn in SCENES.items():
            print(f"  {key:<11} {fn()[4]}")
        return

    names = ns.scenes or list(SCENES)
    unknown = [n for n in names if n not in SCENES]
    if unknown:
        sys.exit(f"unknown scene(s): {', '.join(unknown)}\n"
                 f"available: {', '.join(SCENES)}")

    print("recording:")
    for name in names:
        record(*SCENES[name]())
    print("\nnow render them:  ./render.py")


if __name__ == "__main__":
    main()
