import asyncio
from harness import drive, Probe, FAILURES, fail, note
import app as A

async def pie(p: Probe):
    print("   checksec pie:", A.analyze_checksec(p.app._elf))
    print("   smart bps:", [t.key for t in p.app._smart_bps])
    if any(t.kind == "got" for t in p.app._smart_bps):
        fail("pie", "GOT watchpoints offered on a PIE binary (unrelocated addresses)")
    await p.press("enter", settle=1.0)
    it = p.app.query_one("#bp-list").highlighted_child
    print("   bp set:", it.bkpt_num, "|", p.app._console_lines[-1])
    if not it.bkpt_num: fail("pie", "breakpoint on a PIE symbol failed")
    await p.console("run < p6_pie.bin", settle=3.0)
    print("   regs:", [r for r in p.reg_rows() if r[0] in ("rip","rsp")])
    print("   disasm:", p.disasm_lines()[:2])
    await p.console("continue", settle=3.0)
    print("   tail:", p.app._console_lines[-4:])
    print("   disasm after:", p.disasm_lines()[:3])

async def notelf(p: Probe):
    print("   smart bps:", p.app._smart_bps)
    print("   console:", [l for l in p.app._console_lines[:6]])
    await p.pilot.press("f5"); await p.settle(2.0)
    print("   after F5:", p.app._console_lines[-3:])
    await p.pilot.press("f2"); await p.settle(0.4)
    p.app.screen.query_one("#mem-addr-input").value = "0x400000"
    await p.pilot.press("enter"); await p.settle(1.0)
    out = ["".join(s.text for s in st._segments) for st in p.app.screen.query_one("#mem-output").lines]
    print("   modal:", out[:3])

async def withargs(p: Probe):
    await p.pilot.press("f5"); await p.settle(2.5)
    print("   console:", p.app._console_lines[-5:])

async def main():
    await drive("c6_pie",     "PIE binary",     pie)
    await drive("notanelf.sh","non-ELF target", notelf)
    await drive("c2_nullbyte","args passthru",  withargs, args=["hello", "wo rld", "[bold]"])
    print("\nFAILURES:", FAILURES or "none")

asyncio.run(main())
