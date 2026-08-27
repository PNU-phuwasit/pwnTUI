import asyncio, time
from harness import drive, Probe, FAILURES, fail

async def mem_ok(p: Probe):
    """Baseline: does a plain $rsp read work while STOPPED?"""
    await p.pilot.press("f5"); await p.settle(1.2)
    await p.app.gdb.send("-exec-interrupt"); await p.settle(1.5)
    print("   executing=", p.app.state.executing)
    await p.pilot.press("f2"); await p.settle(0.4)
    m = p.app.screen
    for expr in ("$rsp", "$rsp 64", "$pc", "0x401000", "$rsp+8 32", "$rip 16"):
        m.query_one("#mem-addr-input").value = expr
        await p.pilot.press("enter"); await p.settle(1.0)
        out = [ "".join(s.text for s in st._segments) for st in m.query_one("#mem-output").lines]
        ok = any(l.strip().startswith("0x") and "|" in l for l in out)
        print(f"   {expr!r:16} -> {'OK ' if ok else 'BAD'} {out[:3]}")
        if not ok: fail("mem", f"memory read of {expr!r} produced no hexdump: {out[:3]}")
    # does F10 still work from inside the modal?
    n = len(p.app._console_lines)
    await p.pilot.press("f10"); await p.settle(1.0)
    print("   F10 from modal ->", p.app._console_lines[n:n+2])

async def flood(p: Probe):
    await p.pilot.press("f5"); await p.settle(1.2)
    await p.app.gdb.send("-exec-interrupt"); await p.settle(1.5)
    for cmd, budget in (("x/4000xb $rsp-2000", 20), ("info all-registers", 20), ("info functions", 25)):
        n0 = len(p.app._console_lines); t0 = time.monotonic()
        await p.console(cmd, settle=1.0)
        await p.wait_for(lambda: not p.app.gdb._pending, timeout=budget, what=cmd)
        await p.settle(2.0)
        el = time.monotonic()-t0
        print(f"   {cmd!r}: +{len(p.app._console_lines)-n0} lines in {el:.1f}s")
        if el > budget: fail("flood", f"{cmd} took {el:.0f}s")

async def main():
    await drive("c1_ret2win", "memory read baseline", mem_ok)
    await drive("c4_static",  "console flood",        flood)
    print("\n########## FAILURES ##########")
    for f in FAILURES: print(" -", f)

asyncio.run(main())
