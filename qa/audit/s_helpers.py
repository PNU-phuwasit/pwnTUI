#!/usr/bin/env python3
"""Console helper command integration probes."""
import asyncio
import re

from harness import drive, FAILURES, fail


async def helpers(p):
    await p.console("symbols --func main", settle=0.8)
    tail = p.app._console_lines[-4:]
    print("   symbols --func main:", tail)
    if not any("func main" in line and "size=" in line for line in tail):
        fail("helpers", "symbols --func main did not show a sized function row")
    await p.console("funcs main", settle=0.8)
    if not any("func main" in line for line in p.app._console_lines[-6:]):
        fail("helpers", "funcs alias did not filter to functions")
    await p.console("symbols --help", settle=0.4)
    if not any("symbols --func main" in line for line in p.app._console_lines[-8:]):
        fail("helpers", "symbols --help did not show examples")

    await p.console("symbols --plt printf", settle=0.8)
    if not any("plt printf" in line for line in p.app._console_lines[-6:]):
        fail("helpers", "symbols --plt printf did not filter to PLT rows")
    await p.console("plt printf", settle=0.8)
    if not any("plt printf" in line for line in p.app._console_lines[-6:]):
        fail("helpers", "plt alias did not filter to PLT rows")
    await p.console("symbols --got printf", settle=0.8)
    if not any("got printf" in line for line in p.app._console_lines[-6:]):
        fail("helpers", "symbols --got printf did not filter to GOT rows")
    await p.console("got printf", settle=0.8)
    if not any("got printf" in line for line in p.app._console_lines[-6:]):
        fail("helpers", "got alias did not filter to GOT rows")

    await p.console("xinfo main", settle=0.8)
    xinfo_tail = p.app._console_lines[-14:]
    print("   xinfo main:\n     " + "\n     ".join(xinfo_tail))
    for want in ("address:", "section:", "function:", "binary:", "nearby:"):
        if not any(want in line for line in xinfo_tail):
            fail("helpers", f"xinfo main missing {want}")
    if not any("symbol: main" in line for line in xinfo_tail):
        fail("helpers", "xinfo main did not show the containing symbol")

    await p.console("whereis 0x11dc", settle=0.8)
    whereis_tail = p.app._console_lines[-12:]
    if not any("symbol: main" in line for line in whereis_tail):
        fail("helpers", "whereis 0x11dc did not resolve the containing function")
    await p.console("info 0x11dc", settle=0.8)
    if not any("symbol: main" in line for line in p.app._console_lines[-12:]):
        fail("helpers", "info alias did not resolve through xinfo")

    await p.console("xinfo --help", settle=0.4)
    if not any("alias: whereis" in line for line in p.app._console_lines[-4:]):
        fail("helpers", "xinfo --help did not mention whereis")

    await p.console("set pwntui", settle=0.4)
    if not any("disasm-flavor" in line for line in p.app._console_lines[-8:]):
        fail("helpers", "set pwntui did not print current settings")
    await p.console('symbols --func "main"', settle=0.4)
    if not any("func main" in line for line in p.app._console_lines[-6:]):
        fail("helpers", "quoted command parsing did not preserve symbol argument")

    await p.console("disasm main 32", settle=0.8)
    small = p.app._console_lines[-12:]
    print("   disasm main 32:\n     " + "\n     ".join(small))
    if not any(line.startswith("disasm main: 0x") and "size=0x20" in line for line in small):
        fail("helpers", "disasm header did not show the requested byte window")

    n0 = len(p.app._console_lines)
    await p.console("disasm main --full", settle=0.8)
    full = p.app._console_lines[n0:]
    if len([line for line in full if line.startswith("  0x")]) <= 7:
        fail("helpers", "disasm --full did not expand beyond the small window")
    await p.console("disasm --help", settle=0.4)
    if not any("disasm main --full" in line for line in p.app._console_lines[-6:]):
        fail("helpers", "disasm --help did not show examples")

    await p.console("syscall execve", settle=0.4)
    if not any("rax=59" in line and "rdi=path" in line for line in p.app._console_lines[-4:]):
        fail("helpers", "syscall execve did not show amd64 convention")
    await p.console("srop execve", settle=0.4)
    if not any("frame.rax = 59" in line for line in p.app._console_lines[-8:]):
        fail("helpers", "srop execve did not show frame fields")
    await p.console("fmt offset", settle=0.4)
    if not any("0x41414141" in line for line in p.app._console_lines[-4:]):
        fail("helpers", "fmt offset did not show marker guidance")
    await p.console("fmt write 6 0x404018 0x401196", settle=0.4)
    if not any("fmt write offset=6" in line for line in p.app._console_lines[-4:]):
        fail("helpers", "fmt write did not generate a payload")
    await p.console("chain ret2system", settle=0.4)
    if not any("pop rdi" in line for line in p.app._console_lines[-8:]):
        fail("helpers", "chain ret2system did not show a skeleton")
    await p.console("chain orw", settle=0.4)
    if not any("open(path" in line for line in p.app._console_lines[-8:]):
        fail("helpers", "chain orw did not show ORW steps")
    await p.console("chain ret2dlresolve", settle=0.4)
    if not any("Ret2dlresolvePayload" in line for line in p.app._console_lines[-8:]):
        fail("helpers", "chain ret2dlresolve did not show pwntools note")
    await p.console("mitigations", settle=0.4)
    if not any("GOT overwrite" in line for line in p.app._console_lines[-8:]):
        fail("helpers", "mitigations did not explain RELRO impact")
    await p.console("seccomp", settle=0.4)
    if not any("chain orw" in line for line in p.app._console_lines[-6:]):
        fail("helpers", "seccomp did not suggest ORW")
    await p.console("one_gadget", settle=0.4)
    if not any("one_gadget:" in line for line in p.app._console_lines[-4:]):
        fail("helpers", "one_gadget did not report a usable status")
    await p.console("libc --help", settle=0.4)
    if not any("libc base" in line for line in p.app._console_lines[-8:]):
        fail("helpers", "libc --help did not show base syntax")

    await p.console("break main", settle=0.8)
    made = [line for line in p.app._console_lines[-6:] if "Breakpoint" in line and "main" in line]
    if not made:
        fail("helpers", "break main did not create a breakpoint")
    m = re.search(r"Breakpoint (\d+)", made[-1] if made else "")
    if m:
        await p.console(f"del {m.group(1)}", settle=0.8)
        if not any(f"Breakpoint {m.group(1)} deleted." in line for line in p.app._console_lines[-6:]):
            fail("helpers", "del <id> did not report success")
    else:
        fail("helpers", "could not parse breakpoint id for del <id>")

    await p.console("break *0x11dc", settle=0.8)
    if not any("Breakpoint" in line and "(*0x11dc)" in line for line in p.app._console_lines[-6:]):
        fail("helpers", "break *0x11dc did not preserve the explicit GDB location")
    await p.console("del all", settle=0.8)

    await p.console("break main", settle=0.8)
    await p.console("del all", settle=0.8)
    if not any("All breakpoints deleted." in line for line in p.app._console_lines[-6:]):
        fail("helpers", "del all did not report success")

    await p.console("clear panes", settle=0.4)
    if not any("Panes cleared." in line for line in p.app._console_lines[-3:]):
        fail("helpers", "clear panes did not report success")

    await p.console("clear all", settle=0.4)
    print("   after clear all:", p.app._console_lines)
    if p.app._console_lines != ["Console and panes cleared."]:
        fail("helpers", "clear all did not reset console transcript")


async def main():
    await drive("c6_pie", "helper commands", helpers)
    print("RESULT:", "PASS" if not FAILURES else f"{len(FAILURES)} FAILURES")


if __name__ == "__main__":
    asyncio.run(main())
