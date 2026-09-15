#!/usr/bin/env python3
"""Unit-ish probes for pwndbg-style disassembly annotations.

These avoid launching an inferior, so they still run on hosts where ptrace is
blocked. The full TUI probes cover integration when GDB can run normally.
"""
import asyncio

from harness import FAILURES, fail
import app as A


async def main():
    p = A.PwnTUI("/bin/true", [])
    p.state.registers = {
        "rax": 59,
        "rdi": 0x402004,
        "rsi": 0,
        "rdx": 0,
        "rsp": 0x7FFFFFFFE000,
        "rbp": 0x7FFFFFFFE100,
        "rip": 0x401000,
        "eflags": 0x40,
    }
    p.state.maps = [
        (0x400000, 0x405000, "r-xp", "/tmp/chal"),
        (0x7FFFFFFFD000, 0x7FFFFFFFF000, "rw-p", "[stack]"),
    ]
    p._reg_names = list(p.state.registers)
    cache, reads = {}, [10]

    cases = [
        ("ascii string", A._bytes_preview(b"/bin/sh\x00junk"),
         '"/bin/sh"'),
        ("ascii gutter", A._bytes_preview(b"\x66\x11\x40\x00\x00\x00\x00\x00"),
         "0x401166 |f.@.....|"),
        ("mov imm", await p._annotate_mov("mov", ["edi", "0x402004"], cache, reads),
         "edi => 0x402004"),
        ("mov reg", await p._annotate_mov("mov", ["rdi", "rax"], cache, reads),
         "rdi => 0x3b"),
        ("call args", await p._annotate_call("call 0x401030 <system@plt>", cache, reads),
         "system(rdi => 0x402004"),
        ("indirect call", await p._annotate_call("call rax", cache, reads),
         "call => 0x3b"),
        ("jne", p._annotate_branch("jne", "jne 0x401050 <fail>"),
         "✗ ne not taken"),
        ("je", p._annotate_branch("je", "je 0x401060 <win>"),
         "✓ e taken"),
        ("syscall", await p._annotate_syscall(cache, reads),
         "execve(rdi => 0x402004"),
    ]
    for name, got, want in cases:
        print(f"{name}: {got}")
        if want not in got:
            fail("annotations", f"{name}: wanted {want!r}, got {got!r}")

    print("RESULT:", "PASS" if not FAILURES else f"{len(FAILURES)} FAILURES")


if __name__ == "__main__":
    asyncio.run(main())
