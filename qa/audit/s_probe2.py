import asyncio, time, os
from harness import drive, Probe, FAILURES, fail, note

async def garbage_pc(p: Probe):
    """Fully unmapped $pc and $sp -- what do the panes show?"""
    await p.pilot.press("f5"); await p.settle(1.5)
    await p.app.gdb.send("-exec-interrupt"); await p.settle(1.5)
    await p.console("set $rip=0x4141414141414141", settle=0.5)
    await p.console("set $rsp=0x4242424242424242", settle=0.5)
    await p.console("set $rbp=0x4343434343434343", settle=0.5)
    n = len(p.app._console_lines)
    await p.app._refresh_all(); await p.settle(0.5)
    print("   REGS:", [r for r in p.reg_rows() if r[0] in ("rip","rsp","rbp")])
    print("   DISASM:", p.disasm_lines())
    print("   STACK:", p.stack_lines())
    print("   console:", [l for l in p.app._console_lines[n:]])

async def flood(p: Probe):
    """Huge console flood from a format-string dump."""
    await p.pilot.press("f5"); await p.settle(1.0)
    t0 = time.monotonic()
    await p.console("x/4000gx $rsp-16000", settle=1.0)
    n0=len(p.app._console_lines)
    await p.settle(4.0)
    el = time.monotonic()-t0
    print(f"   flood: {len(p.app._console_lines)} console lines in {el:.1f}s")
    if el > 25: fail("flood","console flood took >25s")

async def repeat_flush(p: Probe):
    """Do collapsed repeats ever get reported?"""
    for _ in range(6):
        await p.pilot.press("f10")
    await p.settle(2.0)
    tail = p.app._console_lines[-6:]
    print("   tail:", tail)
    print("   pending repeat counter:", p.app._console_repeat)
    if p.app._console_repeat:
        fail("repeat", f"{p.app._console_repeat} collapsed lines never reported to the user")

async def quit_clean(p: Probe):
    """Does the app shut down cleanly with the inferior blocked in read()?"""
    await p.pilot.press("f5"); await p.settle(1.5)
    print("   executing=", p.app.state.executing)
    t0 = time.monotonic()
    await p.app.action_quit()
    await p.settle(0.5)
    print(f"   quit issued in {time.monotonic()-t0:.1f}s")

async def modal_q(p: Probe):
    """Does 'q' (or n/s/c/j/k) leak out of the modal into the app?"""
    await p.pilot.press("f2"); await p.settle(0.4)
    print("   screen:", type(p.app.screen).__name__)
    await p.pilot.press("tab"); await p.pilot.press("tab")
    print("   focus:", type(p.app.focused).__name__)
    ret = p.app._return_value
    await p.pilot.press("q"); await p.settle(0.4)
    print("   after q -> app._exit:", p.app._exit, "screen:", type(p.app.screen).__name__)
    if p.app._exit:
        fail("modal_q", "'q' inside the memory modal quit the whole application")

async def resize(p: Probe):
    """Small terminal -- do panes degrade or vanish?"""
    await p.pilot.press("f5"); await p.settle(1.0)
    await p.app.gdb.send("-exec-interrupt"); await p.settle(1.5)
    for size in ((150,40),(130,35),(100,30),(80,24),(60,20)):
        p.app._driver = p.app._driver
        try:
            await p.pilot.resize_terminal(*size)
        except Exception as e:
            print("   resize failed", e); continue
        await p.app._refresh_all(); await p.settle(0.4)
        d, s = p.disasm_lines(), p.stack_lines()
        print(f"   {size}: disasm={len(d)} stack={len(s)}  d0={d[0][:70] if d else None!r}")
        print(f"            s0={s[0][:70] if s else None!r}")
        if not d: fail("resize", f"disasm pane empty at {size}")
        if not s: fail("resize", f"stack pane empty at {size}")

async def regnames_empty(p: Probe):
    """If register-name fetch failed at boot, does the pane ever recover?"""
    p.app._reg_names = []
    await p.pilot.press("f5"); await p.settle(1.0)
    await p.app.gdb.send("-exec-interrupt"); await p.settle(1.5)
    await p.app._refresh_all(); await p.settle(0.4)
    rows = p.reg_rows()
    print("   rows with empty _reg_names:", rows[:4], "count=", len(rows))
    if not rows:
        fail("regnames", "register pane is permanently empty when the boot-time "
                         "name fetch failed; nothing ever re-fetches")

async def nullbyte(p: Probe):
    """strcpy truncation scenario end to end."""
    ok = [t for t in p.app._smart_bps if t.name == "strcpy"]
    print("   strcpy target:", ok)
    if not ok: fail("nullbyte","no strcpy smart breakpoint found")
    await p.press("enter", settle=0.8)
    await p.console("run < p2_trunc.bin", settle=3.0)
    print("   console:\n     " + "\n     ".join(p.app._console_lines[-6:]))
    await p.pilot.press("f2"); await p.settle(0.4)
    m = p.app.screen
    m.query_one("#mem-addr-input").value = "$rsi 64"
    await p.pilot.press("enter"); await p.settle(1.2)
    out = "\n".join("".join(sg.text for sg in st._segments) for st in m.query_one("#mem-output").lines)
    print("   strcpy src bytes:\n     " + out.replace("\n","\n     "))

async def main():
    await drive("c1_ret2win", "garbage pc/sp",   garbage_pc)
    await drive("c1_ret2win", "console flood",   flood)
    await drive("c1_ret2win", "repeat flush",    repeat_flush)
    await drive("c1_ret2win", "modal key leak",  modal_q)
    await drive("c1_ret2win", "resize",          resize)
    await drive("c1_ret2win", "reg names lost",  regnames_empty)
    await drive("c2_nullbyte","null-byte trap",  nullbyte)
    await drive("c1_ret2win", "quit while blocked", quit_clean)
    print("\n########## FAILURES ##########")
    for f in FAILURES: print(" -", f)

asyncio.run(main())
