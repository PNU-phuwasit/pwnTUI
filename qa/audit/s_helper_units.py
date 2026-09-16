#!/usr/bin/env python3
"""Fast tests for pure helper utilities."""
from types import SimpleNamespace

from harness import FAILURES, fail
from pwntui_helpers import (
    DISASM_ADDRESS_WINDOW,
    disasm_range_for_target,
    elf_function_range,
    elf_nearby_symbols,
    elf_section_label,
    elf_symbol_at_or_before,
)


class FakeSection:
    def __init__(self, name, start, size):
        self.name = name
        self.header = {"sh_addr": start, "sh_size": size}


class FakeElf:
    def __init__(self):
        self.functions = {
            "main": SimpleNamespace(address=0x1000, size=0x50),
            "helper": SimpleNamespace(address=0x1080, size=0),
            "next": SimpleNamespace(address=0x10c0, size=0x20),
        }
        self.symbols = {
            "main": 0x1000,
            "helper": 0x1080,
            "global": 0x2000,
        }
        self.sections = [
            FakeSection(".text", 0x1000, 0x1000),
            FakeSection(".data", 0x2000, 0x100),
        ]


def check(name, got, want):
    print(f"   {name}: {got!r}")
    if got != want:
        fail("helper_units", f"{name}: wanted {want!r}, got {got!r}")


def main():
    elf = FakeElf()
    check("function sized", elf_function_range(elf, "main"), (0x1000, 0x50))
    check("function next-start fallback", elf_function_range(elf, "helper"), (0x1080, 0x40))
    check("function missing", elf_function_range(elf, "missing"), None)
    check(
        "disasm symbol",
        disasm_range_for_target(elf, "main"),
        ("0x1000", "0x1050", False),
    )
    check(
        "disasm address",
        disasm_range_for_target(elf, "0x1234"),
        ("0x1234", hex(0x1234 + DISASM_ADDRESS_WINDOW), False),
    )
    check("section", elf_section_label(elf, 0x1010), ".text+0x10")
    check("containing function", elf_symbol_at_or_before(elf, 0x1020), ("main", 0x1000, 0x50))
    check("symbol fallback", elf_symbol_at_or_before(elf, 0x2000), ("global", 0x2000, None))
    nearby = elf_nearby_symbols(elf, 0x1080, radius=1)
    print(f"   nearby: {nearby!r}")
    if ("helper", 0x1080) not in nearby:
        fail("helper_units", "nearby symbols did not include helper")

    print("RESULT:", "PASS" if not FAILURES else f"{len(FAILURES)} FAILURES")


if __name__ == "__main__":
    main()
