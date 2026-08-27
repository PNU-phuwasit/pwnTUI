"""Full acceptance run: the Phase-2 human script against all five challenges,
plus one regression assertion per fix from the audit."""
import asyncio, os, time
from harness import drive, Probe, FAILURES, NOTES, fail, note
import app as A


def modal_out(app):
    m = app.screen
    return ["".join(s.text for s in st._segments) for st in m.query_one("#mem-output").lines]


async def human_session(p: Probe, payload: str, *, bits: int, bp_index: int = 0,
                        expect_win: str | None = None):
    """1. load -> Enter (smart bp) -> `run < payload` in the console
       2. spam F10 / F11
       3. crash
       4. F2 memory modal while blocked, F4 from inside it
       5. garbage input"""
    tag = p.scenario
    import time as _t
    marks = []
    def mark(label):
        marks.append((label, _t.monotonic()))
    p._mark = mark
    mark("start")

    # --- 1. smart breakpoint + run with redirection -----------------------
    bl = p.app.query_one("#bp-list")
    if p.app._smart_bps:
        bl.index = min(bp_index, len(p.app._smart_bps) - 1)
        await p.settle(0.2)
        await p.press("enter", settle=1.0)
        item = bl.highlighted_child
        if not getattr(item, "bkpt_num", None):
            fail(tag, "Enter on a Smart Breakpoint row did not set a breakpoint")
    else:
        fail(tag, "Smart Breakpoints pane is empty")

    await p.console(f"run < {payload}", settle=2.5)
    if not p.app.state.running:
        note(tag, "target not running after `run < payload`")

    mark("bp+run")
    # MI must still be alive right after a console `run` (the wedge bug)
    t0 = time.monotonic()
    rec = await p.app.gdb.send("-data-evaluate-expression 1+1", wait_result=True, timeout=3.0)
    dt = time.monotonic() - t0
    if not rec or rec.get("klass") == "error":
        fail(tag, f"GDB stopped answering MI after a console `run` ({dt:.1f}s, {rec})")

    # --- 2. aggressive stepping ------------------------------------------
    for i in range(30):
        await p.pilot.press("f11" if i % 4 == 3 else "f10")
    await p.settle(3.0)
    txt = p.console_text()
    for bad in ("Cannot find bounds of current function",
                "Cannot execute this command while"):
        if bad in txt:
            fail(tag, f"stepping produced: {bad!r}")
    d = p.disasm_lines()
    arrows = [l for l in d if l.startswith("->")]
    if p.app.state.running and len(arrows) != 1:
        fail(tag, f"disassembly shows {len(arrows)} PC cursors (expected 1)")
    if p.app.state.running and not p.reg_rows():
        fail(tag, "register pane empty while stopped")

    names = [r[0] for r in p.reg_rows()]
    if names:
        want = ("rip", "rsp") if bits == 64 else ("eip", "esp")
        missing = [w for w in want if w not in names]
        if missing:
            fail(tag, f"{bits}-bit register pane missing {missing}; has {names}")
        width = len(p.reg_rows()[0][1]) - 2
        if width != bits // 4:
            fail(tag, f"{bits}-bit values rendered {width} hex digits")

    mark("stepping")
    # --- 3. crash ---------------------------------------------------------
    await p.pilot.press("f6"); await p.settle(3.0)
    txt = p.console_text()
    if expect_win and expect_win not in txt:
        note(tag, f"expected target output {expect_win!r} not seen")
    if "SIGSEGV" in txt:
        d = p.disasm_lines()
        if not d:
            fail(tag, "disassembly pane EMPTY after SIGSEGV")
        s = p.stack_lines()
        if p.app.state.running and not s:
            fail(tag, "stack pane EMPTY after SIGSEGV")

    mark("crash")
    # --- 4. memory modal + F4 --------------------------------------------
    await p.pilot.press("f5"); await p.settle(2.0)     # restart; blocks on tty read
    await p.pilot.press("f2"); await p.settle(0.5)
    if not isinstance(p.app.screen, A.MemoryViewerModal):
        fail(tag, "F2 did not open the memory viewer")
        return
    for _ in range(3):
        await p.pilot.press("f2")          # must not stack
    await p.settle(0.3)
    depth = len(p.app.screen_stack)
    if depth != 2:
        fail(tag, f"F2 stacked modals (screen depth {depth})")

    sp = "$rsp" if bits == 64 else "$esp"
    p.app.screen.query_one("#mem-addr-input").value = sp
    await p.pilot.press("enter"); await p.settle(1.2)
    if p.app.state.executing:
        out = modal_out(p.app)
        if not any("Target is running" in l for l in out):
            note(tag, f"modal said {out[:2]} while the target was running")
        await p.pilot.press("f4"); await p.settle(3.0)
        if p.app.state.executing:
            fail(tag, "F4 from inside the memory modal did not interrupt the target")
        out = modal_out(p.app)
        if not any(l.strip().startswith("0x") and "|" in l for l in out):
            fail(tag, f"deferred memory read did not run after F4: {out[:3]}")
    if not isinstance(p.app.screen, A.MemoryViewerModal):
        fail(tag, "memory modal disappeared after F4")
    if not isinstance(p.app.focused, A.Input):
        fail(tag, f"focus left the modal input (now {type(p.app.focused).__name__})")

    mark("modal")
    # --- 5. garbage in the modal, then in the console ---------------------
    for expr in ("%rsp", "rsp", "0x1f7fe4f00", "$nosuchreg", "((((", "$rsp -5",
                 "$rsp 0", "\\x00\\x01", "[bold red]"):
        p.app.screen.query_one("#mem-addr-input").value = expr
        await p.pilot.press("enter"); await p.settle(0.7)
        if not isinstance(p.app.screen, A.MemoryViewerModal):
            fail(tag, f"modal died on input {expr!r}")
            break
    await p.pilot.press("escape"); await p.settle(0.4)
    if isinstance(p.app.screen, A.MemoryViewerModal):
        fail(tag, "Escape did not close the memory viewer")

    for cmd in ("nosuchcommand", "-nosuchmi", "x/8gx %rsp", "x/8gx 0x1f7fe4f00",
                "print $nosuchreg", "!junk", "!", "  ", "run < /nonexistent",
                "set disassembly-flavor intel", "continue"):
        await p.console(cmd, settle=0.8)
    await p.settle(1.5)
    if p.app.state.running:
        await p.app._refresh_all(); await p.settle(0.5)
        d = p.disasm_lines()
        if d and not any(c in "".join(d) for c in "[]"):
            note(tag, "intel flavour produced no bracketed operands to stress-test")

    mark("garbage")
    base = marks[0][1]
    print("   phases:", ", ".join(f"{l}={t-base:.0f}s" for l, t in marks[1:]))
    # history must have recorded them
    if "continue" not in p.app._history:
        fail(tag, "console history did not record commands")


async def c1(p): await human_session(p, "p1_win.bin", bits=64, bp_index=2)
async def c2(p): await human_session(p, "p2_null.bin", bits=64, bp_index=0)
async def c3(p): await human_session(p, "p3_win.bin", bits=32, bp_index=0)
async def c4(p): await human_session(p, "p4_win.bin", bits=64, bp_index=8)
async def c5(p): await human_session(p, "p5_fmt.bin", bits=64, bp_index=0)

async def main():
    await drive("c1_ret2win",  "C1 ret2win stripped", c1)
    await drive("c2_nullbyte", "C2 null-byte strcpy", c2)
    await drive("c3_bof32",    "C3 32-bit overflow",  c3)
    await drive("c4_static",   "C4 static monster",   c4)
    await drive("c5_fmt",      "C5 format string",    c5)
    print("\n########## FAILURES ##########")
    for f in FAILURES: print(" -", f)
    print("########## NOTES ##########")
    for n in NOTES: print(" -", n)
    print("\nRESULT:", "PASS" if not FAILURES else f"{len(FAILURES)} FAILURES")

if __name__ == "__main__":
    asyncio.run(main())
