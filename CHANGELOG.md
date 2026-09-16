# Changelog

## Unreleased

- Improved console helper workflow with filtered symbol lookup, full-function
  disassembly windows, `xinfo`/`whereis`, breakpoint deletion helpers, clear
  variants, aliases and settings display.
- Added non-heap pwn helpers for ret2libc address math, syscall/SROP notes,
  format-string payload generation and common ROP chain skeletons.
- Split ELF/disassembly helper logic into `pwntui_helpers.py` and added fast
  unit coverage alongside the existing TUI-driven audit probes.
- Updated QA documentation and badge count for the 13-suite audit run.
