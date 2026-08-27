import asyncio, time
from harness import drive, Probe, FAILURES, fail

async def wedge_story(p: Probe):
    """The exact user story: Enter -> 'run < payload.bin' -> try to use the TUI."""
    await p.press("enter", settle=0.8)
    await p.console("run < p1_cyclic.bin", settle=0.3)   # target blocks? no, payload closes stdin
    await p.console("run", settle=1.0)                    # this one blocks on read()
    print("   executing:", p.app.state.executing)
    n = len(p.app._console_lines)
    for k in ("f10","f11","f4","f6"):
        await p.pilot.press(k)
    await p.settle(3.0)
    print("   keys while wedged produced:", p.app._console_lines[n:])
    print("   still executing:", p.app.state.executing)
    if p.app.state.executing:
        fail("wedge", "GDB is deaf after a CLI 'run' -- F4 cannot recover the session")

async def got_watch(p: Probe):
    bps = p.app.query_one("#bp-list")
    got_idx = next(i for i,t in enumerate(p.app._smart_bps) if t.kind=="got")
    bps.index = got_idx
    await p.settle(0.2)
    n = len(p.app._console_lines)
    await p.pilot.press("f9"); await p.settle(1.0)
    print("   watchpoint set:", p.app._console_lines[n:])
    await p.pilot.press("f5"); await p.settle(3.0)
    print("   after run:", p.app._console_lines[-6:])

async def del_sync(p: Probe):
    await p.press("enter", settle=0.8)
    item = p.app.query_one("#bp-list").highlighted_child
    print("   bkpt_num:", item.bkpt_num)
    await p.console("delete", settle=1.0)
    print("   after 'delete' bkpt_num:", item.bkpt_num, "| console:", p.app._console_lines[-3:])
    if item.bkpt_num:
        fail("delsync", "console 'delete' did not clear the panel marker")

async def markup_bytes(p: Probe):
    """Rich markup + ANSI bytes coming out of target memory into every pane."""
    await p.pilot.press("f5"); await p.settle(1.5)
    await p.app.gdb.send("-exec-interrupt"); await p.settle(1.5)
    await p.console("print (char*)&scratch", settle=1.0)
    await p.pilot.press("f2"); await p.settle(0.4)
    m = p.app.screen
    m.query_one("#mem-addr-input").value = "&scratch 96"
    await p.pilot.press("enter"); await p.settle(1.2)
    out = ["".join(s.text for s in st._segments) for st in m.query_one("#mem-output").lines]
    print("   memory modal with markup bytes:")
    for l in out[:7]: print("     ", repr(l))
    if not any("[bold red]" in l for l in out):
        fail("markup", "markup bytes did not survive into the hexdump ASCII column")
    await p.pilot.press("escape"); await p.settle(0.3)
    # and into the console via the target's own stdout
    p.app.gdb.write_stdin(b"[bold red]HI[/] {x} \\ %s\n")
    await p.settle(1.0)
    print("   console tail:", p.app._console_lines[-3:])

async def main():
    await drive("c1_ret2win", "CLI-run wedge story", wedge_story)
    await drive("c2_nullbyte","GOT watchpoint",      got_watch)
    await drive("c1_ret2win", "console delete sync", del_sync)
    await drive("c5_fmt",     "markup bytes",        markup_bytes)
    print("\n########## FAILURES ##########")
    for f in FAILURES: print(" -", f)

asyncio.run(main())
