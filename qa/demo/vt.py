#!/usr/bin/env python3
"""A small VT/xterm screen emulator -- enough of one to replay a recorded
PwnTUI session into a grid of coloured cells.

Deliberately partial. It handles what Textual actually emits (absolute cursor
positioning, erases, and truecolor SGR) and silently ignores the rest, which
keeps it a few hundred lines instead of a project of its own. If a future
Textual starts using scroll regions or wide characters, this is where that
would go.
"""
from __future__ import annotations

import re

#: xterm's first 16 colours, in the Textual/most-terminals rendition.
ANSI16 = [
    (0x00, 0x00, 0x00), (0xCD, 0x00, 0x00), (0x00, 0xCD, 0x00), (0xCD, 0xCD, 0x00),
    (0x00, 0x00, 0xEE), (0xCD, 0x00, 0xCD), (0x00, 0xCD, 0xCD), (0xE5, 0xE5, 0xE5),
    (0x7F, 0x7F, 0x7F), (0xFF, 0x00, 0x00), (0x00, 0xFF, 0x00), (0xFF, 0xFF, 0x00),
    (0x5C, 0x5C, 0xFF), (0xFF, 0x00, 0xFF), (0x00, 0xFF, 0xFF), (0xFF, 0xFF, 0xFF),
]


def xterm256(n: int) -> tuple[int, int, int]:
    if n < 16:
        return ANSI16[n]
    if n < 232:
        n -= 16
        steps = (0, 95, 135, 175, 215, 255)
        return steps[n // 36 % 6], steps[n // 6 % 6], steps[n % 6]
    v = 8 + (n - 232) * 10
    return v, v, v


class Cell:
    __slots__ = ("ch", "fg", "bg", "bold")

    def __init__(self, ch=" ", fg=None, bg=None, bold=False):
        self.ch, self.fg, self.bg, self.bold = ch, fg, bg, bold

    def key(self):
        return (self.ch, self.fg, self.bg, self.bold)


_CSI = re.compile(r"\x1b\[([0-9;:?<>!]*)([@-~])")
_OSC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_ESC_SHORT = re.compile(r"\x1b[()][AB0-2]|\x1b[=>78MDEHc]")
#: A prefix that could still become a valid sequence given more bytes.
_INCOMPLETE = re.compile(r"\x1b(\[[0-9;:?<>!]*|\][^\x07\x1b]*|[()]?)\Z")


class Screen:
    def __init__(self, cols: int, rows: int, fg=(0xD0, 0xD0, 0xD0), bg=(0x0C, 0x0C, 0x0C)):
        self.cols, self.rows = cols, rows
        self.default_fg, self.default_bg = fg, bg
        self.grid = [[Cell() for _ in range(cols)] for _ in range(rows)]
        self.cx = self.cy = 0
        self._pending = ""
        self._wrap_pending = False
        self._reset_sgr()

    # --- state ---------------------------------------------------------
    def _reset_sgr(self):
        self.fg = None      # None == "use the default"
        self.bg = None
        self.bold = False
        self.reverse = False

    def _blank(self):
        return Cell(" ", None, self.bg, False)

    def clear(self):
        self.grid = [[self._blank() for _ in range(self.cols)] for _ in range(self.rows)]

    # --- the grid, resolved for rendering -------------------------------
    def snapshot(self):
        out = []
        for row in self.grid:
            line = []
            for c in row:
                fg = c.fg or self.default_fg
                bg = c.bg or self.default_bg
                line.append((c.ch, fg, bg, c.bold))
            out.append(line)
        return out

    def digest(self):
        return tuple(tuple(c.key() for c in row) for row in self.grid)

    # --- feeding --------------------------------------------------------
    def feed(self, data: str) -> None:
        # A recording is a series of write() chunks, and an escape sequence
        # can straddle two of them -- GDB flooding the console is enough to
        # make it happen. Anything left half-parsed at the end of a chunk is
        # carried over, or its digits get printed onto the screen as text
        # ("224;224;224;48;2;23;23" appearing inside a panel is exactly that
        # bug).
        data = self._pending + data
        self._pending = ""
        i, n = 0, len(data)
        while i < n:
            ch = data[i]
            if ch == "\x1b":
                for pat, handler in ((_CSI, self._csi), (_OSC, None), (_ESC_SHORT, None)):
                    m = pat.match(data, i)
                    if m:
                        if handler:
                            handler(m.group(1), m.group(2))
                        i = m.end()
                        break
                else:
                    # No complete sequence here. If this ESC is the tail of
                    # the chunk it is a split sequence -- hold it for the
                    # next feed rather than printing its digits.
                    if _INCOMPLETE.match(data, i):
                        self._pending = data[i:]
                        return
                    i += 1          # a genuinely stray ESC: drop it
                continue
            if ch == "\n":
                self.cx = 0
                self._wrap_pending = False
                self._linefeed()
            elif ch == "\r":
                self.cx = 0
                self._wrap_pending = False
            elif ch == "\b":
                self.cx = max(0, self.cx - 1)
            elif ch == "\t":
                self.cx = min(self.cols - 1, (self.cx // 8 + 1) * 8)
            elif ch >= " ":
                self._put(ch)
            i += 1

    def _linefeed(self):
        self.cy += 1
        if self.cy >= self.rows:
            self.grid.pop(0)
            self.grid.append([self._blank() for _ in range(self.cols)])
            self.cy = self.rows - 1

    def _put(self, ch: str):
        # Deferred wrap, as a real terminal does it: writing to the last
        # column leaves the cursor ON that column and only wraps when the
        # NEXT printable character arrives. Wrapping eagerly scrolled the
        # screen one line every time something was drawn into the bottom-
        # right corner, which showed up as the header sliding off the top
        # and the footer appearing twice.
        if self._wrap_pending:
            self._wrap_pending = False
            self.cx = 0
            self._linefeed()
        if 0 <= self.cy < self.rows and 0 <= self.cx < self.cols:
            fg, bg = self.fg, self.bg
            if self.reverse:
                fg, bg = bg or self.default_bg, fg or self.default_fg
            self.grid[self.cy][self.cx] = Cell(ch, fg, bg, self.bold)
        if self.cx >= self.cols - 1:
            self._wrap_pending = True
        else:
            self.cx += 1

    # --- CSI ------------------------------------------------------------
    def _csi(self, params: str, final: str):
        if params.startswith("?"):
            # DEC private mode. The only one that changes what is on screen
            # for us is the alternate buffer, which starts blank.
            if final in "hl" and "1049" in params:
                self.clear(); self.cx = self.cy = 0
            return
        nums = [int(p) if p.isdigit() else 0 for p in params.split(";")] if params else []

        def arg(idx=0, default=1):
            return nums[idx] if idx < len(nums) and nums[idx] else default

        self._wrap_pending = False
        if final in "Hf":
            self.cy = min(self.rows - 1, max(0, arg(0) - 1))
            self.cx = min(self.cols - 1, max(0, arg(1) - 1))
        elif final == "A": self.cy = max(0, self.cy - arg())
        elif final == "B": self.cy = min(self.rows - 1, self.cy + arg())
        elif final == "C": self.cx = min(self.cols - 1, self.cx + arg())
        elif final == "D": self.cx = max(0, self.cx - arg())
        elif final == "G": self.cx = min(self.cols - 1, max(0, arg() - 1))
        elif final == "d": self.cy = min(self.rows - 1, max(0, arg() - 1))
        elif final == "J":
            mode = nums[0] if nums else 0
            if mode == 2 or mode == 3:
                self.clear()
            elif mode == 0:
                for x in range(self.cx, self.cols):
                    self.grid[self.cy][x] = self._blank()
                for y in range(self.cy + 1, self.rows):
                    self.grid[y] = [self._blank() for _ in range(self.cols)]
            else:
                for y in range(0, self.cy):
                    self.grid[y] = [self._blank() for _ in range(self.cols)]
                for x in range(0, self.cx + 1):
                    self.grid[self.cy][x] = self._blank()
        elif final == "K":
            mode = nums[0] if nums else 0
            rng = (range(self.cx, self.cols) if mode == 0
                   else range(0, self.cx + 1) if mode == 1
                   else range(0, self.cols))
            for x in rng:
                self.grid[self.cy][x] = self._blank()
        elif final == "m":
            self._sgr(nums or [0])

    def _sgr(self, nums: list[int]):
        i = 0
        while i < len(nums):
            v = nums[i]
            if v == 0:
                self._reset_sgr()
            elif v == 1: self.bold = True
            elif v == 22: self.bold = False
            elif v == 7: self.reverse = True
            elif v == 27: self.reverse = False
            elif 30 <= v <= 37: self.fg = ANSI16[v - 30]
            elif 90 <= v <= 97: self.fg = ANSI16[v - 90 + 8]
            elif v == 39: self.fg = None
            elif 40 <= v <= 47: self.bg = ANSI16[v - 40]
            elif 100 <= v <= 107: self.bg = ANSI16[v - 100 + 8]
            elif v == 49: self.bg = None
            elif v in (38, 48):
                target = "fg" if v == 38 else "bg"
                if i + 1 < len(nums) and nums[i + 1] == 2 and i + 4 < len(nums):
                    setattr(self, target, (nums[i + 2], nums[i + 3], nums[i + 4]))
                    i += 4
                elif i + 1 < len(nums) and nums[i + 1] == 5 and i + 2 < len(nums):
                    setattr(self, target, xterm256(nums[i + 2]))
                    i += 2
            i += 1
