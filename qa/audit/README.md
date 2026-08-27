# PwnTUI QA audit apparatus

Everything here drives the **real** `app.py` against a **real** `gdb --interpreter=mi3`
through Textual's `App.run_test()` pilot. No mocks, no stubbed MI records.

## Build the targets

    ./build.sh          # compiles c1..c6 and regenerates the payloads

## Run everything

    ./run_all.sh

## The challenges

| Binary        | Shape                                   | Exists to break |
|---------------|-----------------------------------------|-----------------|
| `c1_ret2win`  | 64-bit, no-PIE, **stripped**, `read()`  | instruction stepping without DWARF, PLT breakpoints with no symtab |
| `c2_nullbyte` | 64-bit `strcpy()`                       | NUL truncation, GOT watchpoints |
| `c3_bof32`    | **32-bit** i386 overflow                | register set + stack layout switching architecture |
| `c4_static`   | 64-bit `-static`                        | breakpoint resolution with no PLT/GOT |
| `c5_fmt`      | 64-bit format string                    | Rich markup, ANSI and raw bytes from memory into every pane |
| `c6_pie`      | 64-bit **PIE**                          | unrelocated file offsets vs runtime addresses |

## The suites

| File            | Covers |
|-----------------|--------|
| `harness.py`    | the pilot: boots PwnTUI, presses keys, watches `~/.cache/pwntui-error.log` for anything the app swallowed |
| `acceptance.py` | the full human script x 5 challenges: breakpoint, redirected run, 30 rapid steps, crash, modal + interrupt, garbage input |
| `s_probe*.py`   | one targeted regression per defect found in the audit |
| `s_cyclic.py`   | the corrupt-pointer diagnosis: unit cases plus a live hijack that must print the offset in the pane |
| `s_hostile.py`  | Intel-syntax brackets, 200 KB single line, invalid UTF-8, SIGKILL on gdb, restart storm, all watchpoints at once, focus dance |
| `s_latency.py`  | 29 individual interactions, each budgeted at 1.5 s |
| `s_pie.py`      | PIE relocation, non-ELF target, argument passthrough |
| `s_width.py`    | measured pane widths from 160 down to 80 columns |
| `s_real.py`     | real pty, real terminal, real keystrokes, clean exit |

`harness.py` treats **any growth of the pwntui error log** as a failure, which is
what catches exceptions the app deliberately swallows to keep the UI alive.
