"""Per-interaction latency: no single keypress or command may block the UI."""
import asyncio, time
from harness import drive, Probe, FAILURES, fail

BUDGET = 1.5   # seconds a single interaction may take before it feels frozen

async def timed(p, label, coro):
    t0 = time.monotonic()
    await coro
    dt = time.monotonic() - t0
    flag = "  <-- SLOW" if dt > BUDGET else ""
    print(f"   {label:<34} {dt:5.2f}s{flag}")
    if dt > BUDGET:
        fail("latency", f"{label} blocked the UI for {dt:.1f}s")
    return dt

async def body(p: Probe):
    await timed(p, "Enter (set breakpoint)", p.pilot.press("enter"))
    await p.settle(1.0)
    await timed(p, "run < payload (console)", p.app._on_console_submit(
        type("E", (), {"value": "run < p1_win.bin", "input": p.app.query_one("#console-input-row"),
                       "stop": lambda s: None})()))
    await p.settle(2.0)
    for i in range(6):
        await timed(p, f"F10 #{i}", p.pilot.press("f10"))
    await timed(p, "F11", p.pilot.press("f11"))
    await timed(p, "F8 (finish)", p.pilot.press("f8"))
    await p.settle(1.5)
    await timed(p, "F2 open modal", p.pilot.press("f2"))
    m = p.app.screen
    m.query_one("#mem-addr-input").value = "$rsp 512"
    await timed(p, "modal read $rsp 512", p.pilot.press("enter"))
    m.query_one("#mem-addr-input").value = "0x1f7fe4f00"
    await timed(p, "modal read unmapped", p.pilot.press("enter"))
    m.query_one("#mem-addr-input").value = "((((("
    await timed(p, "modal read garbage", p.pilot.press("enter"))
    await timed(p, "Escape modal", p.pilot.press("escape"))
    for cmd in ("nosuchcommand", "-nosuchmi", "x/8gx %rsp", "x/8gx 0x1f7fe4f00",
                "print $nosuchreg", "!junk", "run < /nonexistent",
                "set disassembly-flavor intel", "continue", "info functions",
                "x/2000gx $rsp-8000"):
        inp = p.app.query_one("#console-input-row")
        inp.focus(); await p.pilot.pause(); inp.value = cmd
        await timed(p, f"console {cmd!r}", p.pilot.press("enter"))
        await p.settle(0.4)
    await timed(p, "F4 interrupt", p.pilot.press("f4"))
    await timed(p, "F5 run", p.pilot.press("f5"))
    await p.settle(1.0)
    await timed(p, "F4 while blocked in read()", p.pilot.press("f4"))

async def main():
    await drive("c1_ret2win", "latency", body)
    print("\nFAILURES:", FAILURES or "none")

asyncio.run(main())
