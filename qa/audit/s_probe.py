"""Targeted probes for the specific defects suspected from code review."""
import asyncio, time
from harness import drive, Probe, FAILURES, NOTES, fail, note

async def p32(p: Probe):
    """32-bit: registers pane + stack layout."""
    await p.press("enter")
    await p.console("run < p3_win.bin", settle=2.5)
    rows = p.reg_rows()
    print("   reg names from gdb (first 12):", p.app._reg_names[:12])
    print("   REG ROWS:", rows)
    print("   STACK:", p.stack_lines()[:5])
    names = [r[0] for r in rows]
    for want in ("eax", "esp", "eip"):
        if want not in names:
            fail("32bit", f"register {want} missing from the pane; showing {names}")
    for r in rows:
        if len(r[1]) > 10:
            fail("32bit", f"32-bit register {r[0]} rendered 64-bit wide: {r[1]}")
            break

async def crash64(p: Probe):
    """SIGSEGV with a fully corrupted $rip."""
    await p.console("run < p1_cyclic.bin", settle=3.0)
    print("   console tail:\n     " + "\n     ".join(p.console_text().splitlines()[-8:]))
    print("   REGS:", [r for r in p.reg_rows() if r[0] in ("rip","rsp","rbp")])
    print("   DISASM:", p.disasm_lines()[:4])
    print("   STACK:", p.stack_lines()[:4])
    if not p.disasm_lines():
        fail("crash64", "disassembly pane completely EMPTY after SIGSEGV")

async def spam_step(p: Probe):
    """Aggressive F10/F11 spam -- torn panels / error flood."""
    await p.press("enter")
    await p.console("run < p1_win.bin", settle=2.0)
    t0 = time.monotonic()
    for i in range(40):
        await p.pilot.press("f10" if i % 3 else "f11")
    await p.settle(3.0)
    txt = p.console_text()
    n_cannot = txt.count("Cannot execute this command while")
    print(f"   spam took {time.monotonic()-t0:.1f}s; 'Cannot execute' errors: {n_cannot}")
    print("   console tail:\n     " + "\n     ".join(txt.splitlines()[-10:]))
    d = p.disasm_lines()
    print(f"   disasm lines={len(d)} first={d[:2]}")
    arrows = [l for l in d if l.startswith("->")]
    if len(arrows) != 1:
        fail("spam", f"disasm has {len(arrows)} '->' PC markers (expected exactly 1) "
                     f"-- concurrent refreshes tore the pane")
    if n_cannot > 3:
        fail("spam", f"{n_cannot} 'Cannot execute...' errors leaked into the console")

async def modal_stack(p: Probe):
    """Spam F2 -- do modals stack?"""
    for _ in range(5):
        await p.pilot.press("f2")
    await p.settle(0.6)
    n = len(p.app.screen_stack)
    print("   screen stack depth after 5x F2:", n, [type(s).__name__ for s in p.app.screen_stack])
    if n > 2:
        fail("modal", f"F2 stacked {n-1} modals on top of each other")
    # leak of single-letter app bindings into the modal
    await p.pilot.press("tab"); await p.pilot.press("tab")
    foc = p.app.focused
    print("   focus after 2x tab in modal:", type(foc).__name__ if foc else None)

async def modal_running(p: Probe):
    """F2 while the target is blocked in read(); then F4 from inside the modal."""
    await p.console("run", settle=1.5)     # blocks on read() from the tty
    print("   executing:", p.app.state.executing, "running:", p.app.state.running)
    await p.pilot.press("f2"); await p.settle(0.5)
    modal = p.app.screen
    inp = modal.query_one("#mem-addr-input")
    inp.value = "$rsp"
    await p.pilot.press("enter"); await p.settle(1.0)
    out = "\n".join("".join(s.text for s in strip._segments)
                    for strip in modal.query_one("#mem-output").lines)
    print("   modal output after $rsp while running:\n     " + out.replace("\n","\n     "))
    t0 = time.monotonic()
    await p.pilot.press("f4"); await p.settle(2.0)
    print(f"   F4 from modal took {time.monotonic()-t0:.1f}s; executing={p.app.state.executing}")
    print("   focus still in modal:", type(p.app.focused).__name__ if p.app.focused else None,
          "screen:", type(p.app.screen).__name__)
    if p.app.state.executing:
        fail("modal_run", "F4 from inside the memory modal did not stop the target")
    # now retry the read
    inp.value = "$rsp 64"
    await p.pilot.press("enter"); await p.settle(1.0)
    out2 = "\n".join("".join(s.text for s in strip._segments)
                     for strip in modal.query_one("#mem-output").lines)
    print("   modal output after interrupt:\n     " + out2.replace("\n","\n     ")[:600])
    if "0x" not in out2:
        fail("modal_run", "memory read still failed after interrupting")

async def bad_input(p: Probe):
    """Invalid gdb commands, typo'd registers, unmapped memory."""
    await p.console("this-is-not-a-command", settle=0.8)
    await p.console("-not-an-mi-command", settle=0.8)
    await p.console("x/32gx %rsp", settle=0.8)
    await p.console("x/8gx 0x1f7fe4f00", settle=1.0)
    await p.console("print $nosuchreg", settle=0.8)
    await p.console("!some text to stdin", settle=0.5)
    print("   console tail:\n     " + "\n     ".join(p.console_text().splitlines()[-16:]))
    # memory modal with junk
    await p.pilot.press("f2"); await p.settle(0.4)
    modal = p.app.screen
    for expr in ("%rsp", "rsp", "0x1f7fe4f00", "$nosuch", "((((", "$rsp 999999999999", ""):
        modal.query_one("#mem-addr-input").value = expr
        await p.pilot.press("enter"); await p.settle(0.8)
        out = "\n".join("".join(s.text for s in strip._segments)
                        for strip in modal.query_one("#mem-output").lines)
        print(f"   [{expr!r}] -> {out.splitlines()[:4]}")

async def static_bin(p: Probe):
    print("   smart bps:", [t.key for t in p.app._smart_bps][:20])
    if not p.app._smart_bps:
        fail("static", "Smart Breakpoints pane is EMPTY for a static binary")
    await p.press("enter", settle=1.0)
    print("   console:\n     " + "\n     ".join(p.console_text().splitlines()[-4:]))
    await p.console("run < p4_win.bin", settle=3.0)
    print("   after run:\n     " + "\n     ".join(p.console_text().splitlines()[-8:]))
    print("   disasm:", p.disasm_lines()[:3])

async def fmt_bin(p: Probe):
    await p.console("run < p5_fmt.bin", settle=3.0)
    txt = p.console_text()
    print("   console tail:\n     " + "\n     ".join(txt.splitlines()[-14:]))
    print("   disasm:", p.disasm_lines()[:3])

async def main():
    await drive("c3_bof32",   "32-bit registers/stack", p32)
    await drive("c1_ret2win", "SIGSEGV corrupted rip",  crash64)
    await drive("c1_ret2win", "F10/F11 spam",           spam_step)
    await drive("c1_ret2win", "modal stacking",         modal_stack)
    await drive("c1_ret2win", "modal while running",    modal_running)
    await drive("c2_nullbyte","bad input",              bad_input)
    await drive("c4_static",  "static binary",          static_bin)
    await drive("c5_fmt",     "format string",          fmt_bin)
    print("\n\n########## FAILURES ##########")
    for f in FAILURES: print(" -", f)
    print("########## NOTES ##########")
    for n in NOTES: print(" -", n)

asyncio.run(main())
