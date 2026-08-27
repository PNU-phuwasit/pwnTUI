<div align="center">

# PwnTUI

**A Textual front-end for GDB/MI, built for the way pwn actually works.**

*Smart breakpoints on the dangerous calls. A stack pane that decodes your own cyclic pattern back into an offset. And a debugger that never stops answering you.*

[![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Build](https://img.shields.io/github/actions/workflow/status/synx/pwntui/ci.yml?branch=main)](https://github.com/synx/pwntui/actions)
[![Textual](https://img.shields.io/badge/TUI-Textual%208.x-5a2ca0)](https://github.com/Textualize/textual)
[![GDB](https://img.shields.io/badge/GDB-MI3-orange)](https://sourceware.org/gdb/)
[![QA](https://img.shields.io/badge/QA-8%20suites%20green-brightgreen)](qa/audit/README.md)

</div>

---

```text
                                           PIE: 🔴    NX: 🟢    Canary: 🔴    RELRO: 🟡 Partial    Arch: amd64-64
╭─ Smart Breakpoints ────────╮╭─ Disassembly ──────────────────────────────────────────────────────────────╮╭─ Registers ──────────────────────────────────╮
│○ printf       0x401050     ││$pc = 0x617461616173 -- not mapped.                                         ││ Register  Value                              │
│○ puts         0x401030     ││Execution has left the program.                                             ││ rax       0x0000000000000052                 │
│○ read         0x401060     ││  those bytes spell "saaata" -- this is payload, not an address             ││ rbx       0x0000000000000000                 │
│○ system       0x401040     ││  offset 72 (0x48) in cyclic()                                              ││ rcx       0x0000000000000000                 │
│○ printf@got   0x404010 w   ││                                                                            ││ rdx       0x0000000000000000                 │
│○ puts@got     0x404000 w   ││GDB: Cannot access memory at address 0x617461616173                         ││ rsi       0x00007fffffffd8f0                 │
│○ read@got     0x404018 w   ││The Stack pane still works -- the return address came from there.           │╰──────────────────────────────────────────────╯
│○ system@got   0x404008 w   ││                                                                            │╭─ Stack ──────────────────────────────────────╮
│                            ││                                                                            ││sp 0x7fffffffdaf0 0x00007fffffffdc08 .......  │
│                            ││                                                                            ││   0x7fffffffdaf8 0x00007ffff7dcdf77 w......  │
│                            ││                                                                            ││   0x7fffffffdb00 0x00007ffff7fc6000 .`.....  │
│                            ││                                                                            ││   0x7fffffffdb08 0x00000000004011d6 ..@....  │
│                            ││                                                                            ││   0x7fffffffdb10 0x00000001ffffdbf0 .......  │
│                            ││                                                                            ││                                              │
╰────────────────────────────╯╰────────────────────────────────────────────────────────────────────────────╯╰──────────────────────────────────────────────╯
╭─ Console ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│Using host libthread_db library "/usr/lib/x86_64-linux-gnu/libthread_db.so.1".                                                                            │
│Name: .                                                                                                                                                   │
│hi aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaata.                                                                        │
│                                                                                                                                                          │
│Program received signal SIGSEGV, Segmentation fault.                                                                                                      │
│0x0000617461616173 in ?? ()                                                                                                                               │
│!! SIGSEGV (Segmentation fault) -- refreshing panels                                                                                                      │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│  g   command  |  -MI command  |  !text-to-target-stdin  |  Up/Down for history                                                                           │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

<sub>A real frame. The return address was overwritten, `$pc` left the program, and the pane tells you which byte of your pattern did it.</sub>

---

## Why PwnTUI?

Raw GDB is not slow because it lacks features. It is slow because **you** are the integration layer.

You know the loop. `run < payload`. It crashes. Now type `info registers`, then `x/40gx $rsp`, then squint at `0x6161617461616173`, then open another terminal to run `cyclic_find`, then scroll back up because the register dump has already left the screen. Do that forty times an evening.

PwnTUI collapses that loop into a screen that is always already correct.

| The raw-GDB tax | What PwnTUI does |
|---|---|
| Re-typing `info registers` / `x/40gx $rsp` after every single stop | Registers, disassembly and stack repaint themselves on every stop, automatically |
| Copying a smashed `$rip` into a separate `cyclic_find` | **The offset is printed in the pane**, next to the bytes it decoded |
| Losing your place because output scrolls away | Fixed panes. Output goes to a console that does not eat your state |
| `Cannot find bounds of current function` on every stripped binary | `F10`/`F11` are instruction-level by design — stripped binaries were the assumption, not the edge case |
| Hunting the PLT by hand for `gets`, `strcpy`, `system` | Smart Breakpoints lists them on load. `Enter` to set |
| A `run` that blocks forever with no way back | Every resuming command goes out as async MI. `F4` always works |
| `[rbp-0x10]` crashing your TUI's markup parser | No dynamic text is ever parsed as markup. Anywhere. Ever |

It is a front-end, not a fork: GDB is still GDB, the console still takes every command you know, and anything PwnTUI does not wrap you can still type.

---

## Key Features

### 🎯 It finds the offset for you
When `$pc` or `$sp` lands somewhere unmapped, PwnTUI decodes the register as little-endian ASCII and looks it up in **both** cyclic alphabets — `cyclic()` and `cyclic(n=8)` — reporting whichever matches, clearly labelled. The commonest real hijack overwrites six bytes and leaves the top two zero; that case is handled explicitly.

```text
$pc = 0x617461616173 -- not mapped.
Execution has left the program.
  those bytes spell "saaata" -- this is payload, not an address
  offset 72 (0x48) in cyclic()
```

### 🧠 Smart Breakpoints
On load, the binary is scanned for the calls that actually matter — `gets`, `strcpy`, `system`, `read`, `printf`, `mprotect`, `malloc`/`free`, and the rest. PLT entries become breakpoints; **GOT slots become watchpoints**, because a breakpoint on a data slot never fires. Statically linked binaries with no PLT fall back to defined symbols, so the pane is never empty on the targets where a function list matters most. PIE symbols are handed to GDB by name, so they relocate correctly.

### ⚡ Zero freezes — async MI, end to end
CLI execution commands sent through `-interpreter-exec` run on GDB's *console* interpreter, which is **synchronous**: GDB stops reading MI entirely until the inferior stops. Typing `run < payload.bin` used to take the whole front-end offline — and permanently, if the target sat in `read()` waiting for input you could no longer send.

PwnTUI rewrites every resuming verb (`run`, `continue`, `next`, `step`, `ni`, `si`, `finish`, `until`, `advance`, `start`) to its async MI spelling before sending it. Redirections survive intact via `set args`. **No interaction in the test suite blocks the UI for more than 0.51 s.**

### 🔀 32-bit and 64-bit, seamlessly
Architecture is detected from registers that exist on exactly one of the two sets — never from `eflags`, which both have. The register pane, the value column width, the stack word size, the address width and the hexdump all follow from that one decision. Drop a 32-bit challenge on it and the stack pane shows 4-byte slots, not two i386 words fused into one nonsense qword.

### 🛡️ Hardened against your own target
Everything rendered from process memory is inert:

- No dynamic string is ever parsed as Rich/Textual markup — `[rbp-0x10]` and `[bold red]` are just bytes
- ANSI escapes from the debuggee are neutralised (`rich.Text` does **not** strip ESC — verified, then fixed)
- GDB's MI byte stream, which mixes raw bytes with octal escapes, is decoded at the byte level so nothing is mangled
- A malformed MI record can never kill the reader loop

### 🔍 Everything else you reach for
Live `checksec` badges docked at the top · a memory viewer that accepts `$rsp`, `%rsp` **and** bare `rsp` · `!text` to write straight to the debuggee's own stdin · `↑`/`↓` command history · console transcript export · a layout that reflows down to 80 columns without ever collapsing a pane.

### ✅ Aggressively QA-hardened
This is not "it worked on my machine." Six purpose-built vulnerable binaries — stripped, 32-bit, statically linked, PIE, `strcpy`-truncated and a format-string torture case — are driven through the **real** TUI against a **real** `gdb`, by a headless pilot that presses actual keys. Eleven suites, all green. The audit that produced them found and fixed 16 defects, three of which made the tool unusable on its primary workflow.

See [`qa/audit/README.md`](qa/audit/README.md).

---

## Screenshots

Every clip below is the real program, recorded by driving it through a pty
with real keystrokes — see [`qa/demo/`](qa/demo/) to regenerate or restyle them.

### The offset, without being asked

The return address is overwritten with pattern bytes. Execution leaves the program,
and the pane that would normally shrug tells you which byte of your payload did it.

![Cyclic offset resolved on a crash](qa/demo/gif/hijack.gif)

### Smart Breakpoints

<kbd>Enter</kbd> on a dangerous call, then `run < payload.bin` with the redirection
intact. Every pane repaints itself on the stop.

![Smart Breakpoints and a redirected run](qa/demo/gif/breakpoint.gif)

### The memory viewer, mid-flight

<kbd>F2</kbd> while the target sits blocked in `read()`. <kbd>F4</kbd> interrupts it
from inside the modal, and the read you already asked for completes by itself.

![Memory viewer with interrupt](qa/demo/gif/memory.gif)

<details>
<summary><b>Two more: instruction stepping on a stripped binary, and a 32-bit target</b></summary>

<br>

`F10`/`F11` step by instruction, so a binary with no DWARF is not a special case:

![Instruction stepping](qa/demo/gif/stepping.gif)

Same tool on i386 — `eax`/`esp`/`eip`, 8-digit values and 4-byte stack slots, all
decided from the live register set:

![32-bit target](qa/demo/gif/32bit.gif)

</details>

---

## Installation

### Requirements

| | |
|---|---|
| **Python** | 3.10+ (developed and tested on 3.13) |
| **GDB** | any build with `mi3` support, i.e. 8.0+ (tested against 17.2) |
| **OS** | Linux. Needs `pty` and GDB's `--tty`; not tested on macOS or WSL1 |
| **Terminal** | 150×40 is comfortable, 130×35 is the practical minimum, 80 columns still works |

### Recommended: virtualenv + a global wrapper

Kali, Debian, Ubuntu and Fedora ship a **PEP 668** externally-managed Python. Installing into it with `pip --break-system-packages` can break OS tooling that shares `site-packages`. A venv avoids the whole question, and a two-line wrapper keeps `pwntui` on your `$PATH` anyway.

```bash
# 1. clone
git clone https://github.com/synx/pwntui.git ~/tools/pwntui
cd ~/tools/pwntui

# 2. isolated environment
python3 -m venv .venv
./.venv/bin/pip install --upgrade pip
./.venv/bin/pip install "textual>=8.2,<9" "pwntools>=4.15,<5" "rich>=15,<16"

# 3. a launcher that uses the venv's interpreter, from anywhere
sudo tee /usr/local/bin/pwntui >/dev/null <<'WRAP'
#!/bin/sh
exec "$HOME/tools/pwntui/.venv/bin/python3" "$HOME/tools/pwntui/app.py" "$@"
WRAP
sudo chmod +x /usr/local/bin/pwntui
```

```bash
pwntui ./challenge          # works from any directory
```

> If you cloned somewhere other than `~/tools/pwntui`, edit the two paths in the wrapper to match.

<details>
<summary><b>Alternative: install into the system Python (not recommended)</b></summary>

```bash
pip install --break-system-packages "textual>=8.2,<9" "pwntools>=4.15,<5" "rich>=15,<16"
python3 app.py ./challenge
```

You are overriding your distribution's package manager. If something later breaks, `pwntui --repair` re-pins the exact tested versions.

</details>

### Keeping dependencies healthy

```bash
pwntui --update    # upgrade within the tested major versions
pwntui --repair    # force-reinstall the exact versions this release was tested against
```

Both run before the heavy imports, so `--repair` still works when a broken dependency is exactly what is stopping the app from starting.

---

## Usage

```bash
pwntui ./challenge                  # basic
pwntui ./challenge arg1 arg2        # with argv
```

Then, in the console box at the bottom:

```text
run < payload.bin                   # redirection works; rewritten to async MI for you
```

### Hotkeys

Function keys are **priority bindings** — they fire no matter what has focus, including while you are typing in the console or standing in a modal. The single-letter shortcuts deliberately are not, so typing `continue` types `continue` instead of stepping eight times.

| Key | Action | Notes |
|:---|:---|:---|
| <kbd>F5</kbd> | Run | `-exec-run` |
| <kbd>F6</kbd> | Continue | also <kbd>c</kbd> |
| <kbd>F8</kbd> | Step out | run to return of frame (`finish`) |
| <kbd>F10</kbd> | Step **over** | `ni` — instruction-level, works on stripped binaries |
| <kbd>F11</kbd> | Step **into** | `si` — instruction-level |
| <kbd>F9</kbd> | Toggle breakpoint | on the highlighted Smart Breakpoint row |
| <kbd>F4</kbd> | **Interrupt** | SIGINT. Works while free-running *or* blocked in `read()`, from anywhere |
| <kbd>F2</kbd> | Memory viewer | idempotent — pressing it again focuses the open modal |
| <kbd>Ctrl</kbd>+<kbd>Q</kbd> | Quit | always available |

| Key | Action |
|:---|:---|
| <kbd>Enter</kbd> | Set / clear a breakpoint on the highlighted row |
| <kbd>j</kbd> / <kbd>k</kbd> | Move down / up the Smart Breakpoints list |
| <kbd>n</kbd> / <kbd>s</kbd> / <kbd>c</kbd> | Step over / step into / continue |
| <kbd>m</kbd> | Memory viewer (same as <kbd>F2</kbd>) |
| <kbd>i</kbd> | Jump to the console input |
| <kbd>Esc</kbd> | Leave the console input · close a modal |
| <kbd>Tab</kbd> | Cycle focus |
| <kbd>y</kbd> | Save the console transcript to `~/.cache/pwntui-console.txt` |
| <kbd>q</kbd> | Quit |
| <kbd>↑</kbd> / <kbd>↓</kbd> | Command history (while in the console box) |

### Console syntax

| You type | What happens |
|:---|:---|
| `run < payload.bin` | Normal GDB CLI. Resuming verbs are rewritten to async MI automatically |
| `x/32gx $rsp` | Sent to GDB as-is |
| `-data-read-memory-bytes $sp 64` | A leading `-` sends raw MI, verbatim |
| `!my name` | Sent to the **debuggee's own stdin** — answers an interactive `Name:` prompt |

### Memory viewer

Accepts an address or register, optionally followed by a byte count:

```text
$rsp          $rsp 512          0x401196          $rip+16
%rsp          rsp                                 ← both accepted and rewritten
```

If the target is running when you ask, it says so and offers <kbd>F4</kbd> — and once you press it, **the read you asked for completes on its own**.

---

## How it works

```text
    your keystrokes
           │
           ▼
  ┌─────────────────┐   -exec-run · -exec-continue · -data-disassemble · …
  │     PwnTUI      │ ─────────────────────────────────► ┌──────────────────┐
  │    (Textual)    │                                    │       gdb        │
  │                 │ ◄───────────────────────────────── │ --interpreter=mi3│
  └─────────────────┘   ^done · ^error · *stopped · =breakpoint-created
           │                                             └────────┬─────────┘
           ▼                                                      │
  panes repaint on                                                │ --tty=/dev/pts/N
  every *stopped                                                  ▼
                                                       ┌─────────────────────┐
   its stdout  ────────────────────────────────────►   │   the debuggee,     │
   `!text` writes to its stdin  ◄───────────────────   │   on its own pty    │
                                                       └─────────────────────┘
```

The inferior gets **its own pty** rather than sharing the terminal. Without that, the target's output would bypass the MI pipe entirely and land on the real terminal underneath Textual's alt-screen, corrupting the display and leaving no way to feed it input.

Panel refreshes are serialised behind a generation counter, so a held-down <kbd>F10</kbd> producing stops faster than three MI round-trips can service them can never leave two program states interleaved in the panes.

---

## Testing

```bash
cd qa/audit
./build.sh        # compile the six challenge binaries + payloads (needs gcc-multilib for the 32-bit one)
./run_all.sh      # drive the real TUI against real gdb
```

The harness treats **any growth of `~/.cache/pwntui-error.log`** as a failure — which is what catches exceptions the app deliberately swallows to keep the UI alive.

---

## Known limitations

Stated plainly, because a tool you trust should tell you where it has not been proven:

- **One tested host**: Linux `x86_64`, `gdb 17.2`, `textual 8.2.8`, Python 3.13. Older GDB spells its errors differently and may not accept `-exec-run --start`.
- **Non-x86 targets** (ARM, MIPS) go through fallback paths that are written and reviewed but not executed against a real cross-debugger.
- **Threads and `fork()`** are not exercised. There is no thread selector, so a target that spawns threads stops on whichever one GDB selects.
- **`continue N`** cannot carry its ignore count into MI. PwnTUI applies the `continue` and tells you the count was dropped rather than silently doing something else.
- Source-level `next`/`step` still need DWARF. Type them in the console if you have it; <kbd>F10</kbd>/<kbd>F11</kbd> stay instruction-level on purpose.

---

## Contributing

Issues and PRs welcome. If you are fixing a bug, a regression probe in `qa/audit/` alongside it is the most useful thing you can bring — the existing suites are a good template, and they are all under 150 lines.

Before opening a PR:

```bash
cd qa/audit && ./run_all.sh     # should print no FAIL lines
```

---

## License

MIT — see [LICENSE](LICENSE).

<div align="center">
<sub>Built for CTFs, hardened by an adversarial QA pass, and honest about what it has not been tested on.</sub>
</div>
