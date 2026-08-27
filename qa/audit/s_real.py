"""End-to-end in a REAL pty, with the master properly drained."""
import os, pty, re, subprocess, sys, threading, time
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(os.path.dirname(HERE))

F5, F10, F2, F4, ESC, CTRLQ = b"\x1b[15~", b"\x1b[21~", b"\x1bOQ", b"\x1bOS", b"\x1b", b"\x11"

def session(binary, script, label, cols=150, rows=40):
    m, s = pty.openpty()
    import fcntl, struct, termios
    fcntl.ioctl(s, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    buf = bytearray(); stop = threading.Event()
    def rd():
        while not stop.is_set():
            try: d = os.read(m, 65536)
            except (BlockingIOError, OSError): break
            if not d: break
            buf.extend(d)
    os.set_blocking(m, True)
    th = threading.Thread(target=rd, daemon=True); th.start()
    p = subprocess.Popen([sys.executable, os.path.join(ROOT, "app.py"), os.path.join(HERE, binary)],
                         stdin=s, stdout=s, stderr=s, cwd=HERE,
                         env={**os.environ, "TERM": "xterm-256color"})
    os.close(s)
    time.sleep(4.0)
    for keys, delay in script:
        os.write(m, keys); time.sleep(delay)
    os.write(m, CTRLQ)
    t0 = time.time()
    try:
        p.wait(timeout=25); ok = f"exited rc={p.returncode} in {time.time()-t0:.1f}s"
    except subprocess.TimeoutExpired:
        p.kill(); p.wait(); ok = "!! HUNG on exit"
    stop.set()
    text = buf.decode(errors="replace")
    plain = re.sub(r"\x1b\[[0-9;?]*[A-Za-zhl]|\x1b[()][B0]|\x1b[=>]", "", text)
    print(f"  {label}: {ok}; {len(buf)} bytes rendered")
    for bad in ("Traceback", "MarkupError", "MissingStyle", "Internal error"):
        if bad in plain: print(f"    !! {bad} appeared on screen")
    os.close(m)
    return plain

out = session("c1_ret2win",
              [(b"\r", 1.0),                    # Enter: smart breakpoint
               (b"i", 0.4), (b"run < p1_cyclic.bin\r", 3.0),
               (F10, 0.5), (F10, 0.5), (F10, 0.5),
               (F2, 1.0), (b"$rsp 128\r", 1.5), (ESC, 0.6),
               (b"i", 0.4), (b"continue\r", 2.5)],
              "C1 full session")
tail = "\n".join(l.rstrip() for l in out.splitlines() if l.strip())[-2600:]
print(tail)
