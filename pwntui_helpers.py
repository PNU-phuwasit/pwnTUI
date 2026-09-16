from __future__ import annotations

from typing import Any, Optional

DISASM_ADDRESS_WINDOW = 160
DISASM_MAX_FUNCTION_BYTES = 4096
DISASM_MAX_LINES = 400
DISASM_FULL_MAX_FUNCTION_BYTES = 65536
DISASM_FULL_MAX_LINES = 2000


def elf_function_range(elf: Any, name: str) -> Optional[tuple[int, int]]:
    """Best-effort function length for console `disasm <symbol>`."""
    func = getattr(elf, "functions", {}).get(name)
    addr = getattr(func, "address", None)
    size = getattr(func, "size", None)
    if isinstance(addr, int) and isinstance(size, int) and size > 0:
        return addr, size
    if not isinstance(addr, int):
        sym_addr = getattr(elf, "symbols", {}).get(name)
        if isinstance(sym_addr, int):
            addr = sym_addr
    if not isinstance(addr, int):
        return None

    starts: list[int] = []
    for other in getattr(elf, "functions", {}).values():
        other_addr = getattr(other, "address", None)
        if isinstance(other_addr, int) and other_addr > addr:
            starts.append(other_addr)
    if not starts:
        return None
    size = min(starts) - addr
    return (addr, size) if size > 0 else None


def disasm_range_for_target(
    elf: Any,
    target: str,
    byte_limit: Optional[int] = None,
) -> tuple[str, str, bool]:
    try:
        addr = int(target, 0)
    except ValueError:
        addr = None

    if addr is not None:
        start = hex(addr)
        size = byte_limit or DISASM_ADDRESS_WINDOW
        return start, hex(addr + size), False

    if elf is not None:
        function_range = elf_function_range(elf, target)
        if function_range:
            addr, size = function_range
            cap = byte_limit or DISASM_MAX_FUNCTION_BYTES
            capped = min(size, cap)
            return hex(addr), hex(addr + capped), size > capped

    size = byte_limit or DISASM_ADDRESS_WINDOW
    return target, f"{target}+{size}", False


def elf_section_label(elf: Any, addr: int) -> str:
    for section in getattr(elf, "sections", []):
        header = getattr(section, "header", {})
        start = header.get("sh_addr") if hasattr(header, "get") else None
        size = header.get("sh_size") if hasattr(header, "get") else None
        if isinstance(start, int) and isinstance(size, int) and size > 0:
            if start <= addr < start + size:
                return f"{getattr(section, 'name', '?')}+{addr - start:#x}"
    return ""


def elf_nearby_symbols(elf: Any, addr: int, radius: int = 3) -> list[tuple[str, int]]:
    rows: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    for name, sym_addr in getattr(elf, "symbols", {}).items():
        if not isinstance(sym_addr, int):
            continue
        key = (str(name), sym_addr)
        if key in seen:
            continue
        seen.add(key)
        rows.append((str(name), sym_addr))
    rows.sort(key=lambda row: row[1])
    if not rows:
        return []
    idx = min(range(len(rows)), key=lambda i: abs(rows[i][1] - addr))
    lo = max(0, idx - radius)
    hi = min(len(rows), idx + radius + 1)
    return rows[lo:hi]


def elf_symbol_at_or_before(elf: Any, addr: int) -> Optional[tuple[str, int, Optional[int]]]:
    best: Optional[tuple[str, int, Optional[int]]] = None
    for name, func in getattr(elf, "functions", {}).items():
        start = getattr(func, "address", None)
        if not isinstance(start, int) or start > addr:
            continue
        function_range = elf_function_range(elf, str(name))
        known_size = function_range[1] if function_range else None
        if known_size is None and addr != start:
            continue
        if known_size is not None and addr >= start + known_size:
            continue
        if best is None or start > best[1]:
            best = (str(name), start, known_size)
    if best is not None:
        return best

    for name, sym_addr in getattr(elf, "symbols", {}).items():
        if not isinstance(sym_addr, int) or sym_addr > addr:
            continue
        if best is None or sym_addr > best[1]:
            best = (str(name), sym_addr, None)
    return best
