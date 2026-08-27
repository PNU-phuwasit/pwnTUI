"""The cyclic-offset diagnosis must fire on a REAL hijack, not just a
synthetic one. A canonical user-space address is built from six payload
bytes with the top two zero -- the case that actually reaches the pane."""
import asyncio
from harness import drive, Probe, FAILURES, fail
import app as A

def unit():
    from pwn import context, cyclic; context.log_level = "error"
    cases = [
        # (value, bits, must contain)
        (0x0000617461616173, 64, "offset 72"),     # 6-byte canonical hijack
        (0x6161617461616173, 64, "offset 72"),     # full 8-byte
        (0x62616164,         32, "offset 112"),    # 32-bit
        (0x4141414141414141, 64, None),            # printable, not in a pattern
        (0x0000000000000006, 64, ""),              # not printable -> silent
        (0x00007fffffffdad8, 64, ""),              # a real address -> silent
    ]
    for value, bits, want in cases:
        out = A.describe_corrupt_pointer(value, bits)
        text = " | ".join(out)
        print(f"   {value:#018x} ({bits}) -> {out}")
        if want == "":
            if out: fail("cyclic", f"{value:#x} should produce nothing, got {out}")
        elif want is None:
            if not out or "offset" in text:
                fail("cyclic", f"{value:#x} should decode but claim no offset, got {out}")
        elif want not in text:
            fail("cyclic", f"{value:#x} missing {want!r}, got {out}")

async def live(p: Probe):
    """End to end: the pane itself must show the offset after a real crash."""
    await p.console("run < p1_hijack.bin", settle=3.5)
    lines = p.disasm_lines()
    print("   disassembly pane:")
    for l in lines[:6]: print("     ", l)
    joined = " ".join(lines)
    if "not mapped" not in joined:
        fail("cyclic", f"no corrupt-PC diagnosis after a real hijack: {lines[:3]}")
    if "offset" not in joined:
        fail("cyclic", f"diagnosis shown but the cyclic offset is missing: {lines[:6]}")
    if "saaata" not in joined:
        fail("cyclic", f"payload bytes not decoded: {lines[:6]}")

async def main():
    print("=== describe_corrupt_pointer unit cases ===")
    unit()
    await drive("c1_ret2win", "live hijack", live)
    print("\nFAILURES:", FAILURES or "none")
    print("RESULT:", "PASS" if not FAILURES else f"{len(FAILURES)} FAILURES")

if __name__ == "__main__":
    asyncio.run(main())
