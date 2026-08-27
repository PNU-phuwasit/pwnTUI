import asyncio
from harness import drive, Probe

async def body(p: Probe):
    for size in ((160,45),(150,40),(130,35),(110,32),(100,30),(90,28),(80,24)):
        await p.pilot.resize_terminal(*size)
        await p.settle(0.3)
        bp = p.app.query_one("#bp-list"); ds = p.app.query_one("#disasm")
        rg = p.app.query_one("#regs");     st = p.app.query_one("#stack")
        print(f"  {size[0]:>4}: bp={bp.content_size.width:>3} disasm={ds.content_size.width:>3} "
              f"regs={rg.content_size.width:>3} stack={st.content_size.width:>3}")

async def main():
    await drive("c1_ret2win", "pane widths", body)
asyncio.run(main())
