import asyncio, os, signal, time
from harness import drive, Probe, FAILURES, NOTES, fail, note
import app as A

async def intel_brackets(p: Probe):
    """Intel flavour puts [rbp-0x10] into every disassembly row."""
    await p.console("set disassembly-flavor intel", settle=0.5)
    await p.press("enter", settle=0.8)          # bp on first smart target
    await p.console("run < p1_win.bin", settle=2.5)
    await p.app._refresh_all(); await p.settle(0.5)
    d = p.disasm_lines()
    print("   disasm:", d[:4])
    if not any("[" in l for l in d):
        fail("intel", f"no bracketed operands rendered: {d[:3]}")
    # and through the stack ASCII + memory modal
    await p.pilot.press("f2"); await p.settle(0.4)
    p.app.screen.query_one("#mem-addr-input").value = "$rsp 256"
    await p.pilot.press("enter"); await p.settle(1.0)
    out = ["".join(s.text for s in st._segments) for st in p.app.screen.query_one("#mem-output").lines]
    print("   modal rows:", len(out))
    if not out: fail("intel", "memory modal empty")

async def giant_line(p: Probe):
    """One absurdly long console line (no newline) -- 200 KB."""
    t0 = time.monotonic()
    p.app._stream_console("console", "X" * 200_000, "")
    p.app._flush_streams()
    await p.settle(0.5)
    print(f"   200KB single line handled in {time.monotonic()-t0:.1f}s; "
          f"lines={len(p.app._console_lines)}")
    # 50k short lines
    t0 = time.monotonic()
    p.app._stream_console("console", "".join(f"line {i}\n" for i in range(20000)), "")
    await p.settle(1.0)
    print(f"   20k lines in {time.monotonic()-t0:.1f}s; kept={len(p.app._console_lines)}")
    if len(p.app._console_lines) > 20001:
        fail("giant", "console transcript is not bounded")

async def binary_tty(p: Probe):
    """Raw bytes, invalid UTF-8, ANSI and markup straight from the target's tty."""
    junk = (b"\xff\xfe\x00\x01[bold red]\x1b[2J\x1b[31mRED\x1b[0m{n}\\x %n %s\r\n"
            b"\xc3\x28\xe2\x82 partial-utf8 \xf0\x9f\x92\xa5\n")
    await p.app._on_mi_event({"type": "target", "klass": "stream",
                              "payload": junk.decode(errors="replace")})
    p.app._flush_streams(); await p.settle(0.4)
    print("   console tail:", [repr(l) for l in p.app._console_lines[-3:]])

async def gdb_dies(p: Probe):
    """Kill gdb underneath the UI. Everything must stay usable."""
    await p.pilot.press("f5"); await p.settle(1.2)
    p.app.gdb.proc.send_signal(signal.SIGKILL)
    await p.settle(2.5)
    print("   alive:", p.app.gdb.alive, "| tail:", p.app._console_lines[-2:])
    n = len(p.app._console_lines)
    for k in ("f5","f6","f10","f11","f8","f4","f9","enter"):
        await p.pilot.press(k)
    await p.settle(1.5)
    print("   keys after gdb death:", p.app._console_lines[n:n+4])
    await p.pilot.press("f2"); await p.settle(0.4)
    p.app.screen.query_one("#mem-addr-input").value = "$rsp"
    await p.pilot.press("enter"); await p.settle(1.0)
    out = ["".join(s.text for s in st._segments) for st in p.app.screen.query_one("#mem-output").lines]
    print("   modal after death:", out[:2])
    if not out: fail("gdbdead", "memory modal silently blank after gdb died")

async def restart_storm(p: Probe):
    """F5 spam -- restart storm."""
    for _ in range(12):
        await p.pilot.press("f5")
    await p.settle(4.0)
    print("   running:", p.app.state.running, "executing:", p.app.state.executing)
    print("   tail:", p.app._console_lines[-4:])
    for _ in range(12):
        await p.pilot.press("f6")
    await p.settle(3.0)
    print("   after F6 storm:", p.app.state.running, p.app._console_lines[-2:])

async def all_watchpoints(p: Probe):
    """Set every GOT watchpoint -- more than the CPU has debug registers."""
    bl = p.app.query_one("#bp-list")
    for i, t in enumerate(p.app._smart_bps):
        bl.index = i
        await p.settle(0.15)
        await p.pilot.press("f9")
        await p.settle(0.4)
    marks = [it.bkpt_num for it in bl.children if isinstance(it, A.BreakpointItem)]
    print("   bkpt numbers:", marks)
    await p.pilot.press("f5"); await p.settle(3.0)
    print("   tail:", p.app._console_lines[-4:])
    # toggle them all back off
    for i in range(len(p.app._smart_bps)):
        bl.index = i; await p.settle(0.1)
        await p.pilot.press("f9"); await p.settle(0.3)
    left = [it.bkpt_num for it in bl.children if isinstance(it, A.BreakpointItem) and it.bkpt_num]
    print("   still marked after clearing all:", left)
    if left: fail("watch", f"rows still marked after clearing: {left}")

async def focus_dance(p: Probe):
    for k in ("i","escape","tab","tab","i","escape","j","k","m","escape","y"):
        await p.pilot.press(k); await p.settle(0.25)
    print("   focus:", type(p.app.focused).__name__, "screen:", type(p.app.screen).__name__)
    print("   saved:", os.path.exists(A._CONSOLE_DUMP_PATH))
    # typing must not trigger single-letter actions
    p.app.query_one("#console-input-row").focus(); await p.settle(0.2)
    n = len(p.app._console_lines)
    for ch in "continue next stepi quit jkmy":
        await p.pilot.press(ch if ch != " " else "space")
    await p.settle(0.5)
    val = p.app.query_one("#console-input-row").value
    print("   typed into box:", repr(val))
    if p.app._exit: fail("focus", "typing in the console box quit the app")
    if val != "continue next stepi quit jkmy":
        fail("focus", f"keystrokes leaked out of the console box: {val!r}")
    if len(p.app._console_lines) != n:
        fail("focus", f"typing fired actions: {p.app._console_lines[n:]}")

async def main():
    await drive("c1_ret2win",  "intel brackets",   intel_brackets)
    await drive("c1_ret2win",  "giant console",    giant_line)
    await drive("c5_fmt",      "binary tty",       binary_tty)
    await drive("c1_ret2win",  "gdb killed",       gdb_dies)
    await drive("c1_ret2win",  "restart storm",    restart_storm)
    await drive("c2_nullbyte", "all watchpoints",  all_watchpoints)
    await drive("c1_ret2win",  "focus dance",      focus_dance)
    print("\n########## FAILURES ##########")
    for f in FAILURES: print(" -", f)
    print("RESULT:", "PASS" if not FAILURES else f"{len(FAILURES)} FAILURES")

asyncio.run(main())
