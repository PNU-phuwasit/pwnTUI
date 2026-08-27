"""Geometry assertions.

Every other suite reads what a widget CONTAINS. This one reads how big it
is -- which is how the memory viewer shipped with a zero-height output pane
while the tests that pulled hexdump lines straight out of its RichLog buffer
all passed. A widget can hold the right text and still show you nothing.
"""
import asyncio
from harness import drive, Probe, FAILURES, fail
import app as A
from textual.geometry import Region

SIZES = ((150, 40), (130, 35), (110, 30), (100, 30), (80, 24))


async def modal_geometry(p: Probe):
    for size in SIZES:
        await p.pilot.resize_terminal(*size)
        await p.settle(0.4)
        await p.pilot.press("f2")
        await p.settle(0.7)
        screen = p.app.screen
        if not isinstance(screen, A.MemoryViewerModal):
            fail("layout", f"F2 opened no modal at {size}")
            return
        box = screen.query_one("#mem-viewer-box").size
        out = screen.query_one("#mem-output").size
        inp = screen.query_one("#mem-addr-input").size
        print(f"   {size}: box={box.width}x{box.height} "
              f"output={out.width}x{out.height} input={inp.width}x{inp.height}")
        # The box should fill most of the screen, not land in a grid cell.
        if box.width < size[0] * 0.6 or box.height < size[1] * 0.5:
            fail("layout", f"memory modal is only {box.width}x{box.height} "
                           f"on a {size[0]}x{size[1]} terminal")
        if out.height < 4:
            fail("layout", f"hexdump pane is {out.height} rows tall at {size} "
                           f"-- nothing would be visible")
        if inp.width < 10:
            fail("layout", f"address input is {inp.width} columns at {size}")
        await p.pilot.press("escape")
        await p.settle(0.4)


async def main_geometry(p: Probe):
    for size in SIZES:
        await p.pilot.resize_terminal(*size)
        await p.settle(0.5)
        got = {sel: p.app.query_one(sel).size
               for sel in ("#bp-list", "#disasm", "#regs", "#stack", "#console-log")}
        desc = " ".join(f"{k.lstrip('#')}={v.width}x{v.height}" for k, v in got.items())
        print(f"   {size}: {desc}")
        for sel, sz in got.items():
            if sz.width < 8 or sz.height < 2:
                fail("layout", f"{sel} collapsed to {sz.width}x{sz.height} at {size}")
        total = got["#bp-list"].width + got["#disasm"].width + got["#regs"].width
        if total > size[0]:
            fail("layout", f"panels overflow the terminal at {size}: {total} > {size[0]}")


async def modal_shows_bytes(p: Probe):
    """The hexdump must be VISIBLE, not merely buffered."""
    await p.pilot.resize_terminal(110, 30)
    await p.pilot.press("f5")
    await p.settle(1.5)
    await p.app.gdb.send("-exec-interrupt")
    await p.settle(1.5)
    await p.pilot.press("f2")
    await p.settle(0.6)
    screen = p.app.screen
    screen.query_one("#mem-addr-input").value = "$rsp 256"
    await p.pilot.press("enter")
    await p.settle(1.5)
    out = screen.query_one("#mem-output")
    rendered = [
        "".join(seg.text for seg in strip._segments).rstrip()
        for strip in out.render_lines(Region(0, 0, out.size.width, out.size.height))
    ] if out.size.height else []
    visible = [line for line in rendered if line.strip()]
    print(f"   output pane {out.size.width}x{out.size.height}, "
          f"{len(visible)} non-blank rows actually painted")
    for line in visible[:3]:
        print("     ", line)
    if len(visible) < 3:
        fail("layout", "hexdump is buffered but not painted -- "
                       f"{len(visible)} visible rows")


async def main():
    await drive("c1_ret2win", "modal geometry", modal_geometry)
    await drive("c1_ret2win", "main geometry", main_geometry)
    await drive("c1_ret2win", "hexdump painted", modal_shows_bytes)
    print("\nFAILURES:", FAILURES or "none")
    print("RESULT:", "PASS" if not FAILURES else f"{len(FAILURES)} FAILURES")


if __name__ == "__main__":
    asyncio.run(main())
