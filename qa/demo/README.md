# Demo recordings

The GIFs in the top-level README are generated here, by driving the real
PwnTUI through a pty with real keystrokes. Nothing is staged or mocked; if a
pane looks wrong in a GIF, it looks wrong in the tool.

```bash
cd qa/audit && ./build.sh     # once: compile the challenge binaries
cd ../demo
./record.py                   # drive the app, write cast/*.cast
./render.py                   # turn those into gif/*.gif
```

`record.py --list` shows the scenes. Record one at a time while you tune it:

```bash
./record.py hijack && ./render.py hijack
```

## Tuning

**Pacing** lives in `record.py`. Each scene is a list of
`(bytes_to_send, seconds_to_wait_after)` pairs — change the waits, not the
frame rate. Keep a clip under ~20 s; a README GIF longer than that does not
get watched to the end.

**Appearance** lives in `render.py`:

| Flag | Default | Effect |
|---|---|---|
| `--fps` | 10 | Sampling rate. Identical consecutive screens collapse, so raising this costs less than you would expect |
| `--size` | 14 | Font size in px, which sets the output resolution |
| `--theme` | dark | `dark` or `light` |
| `--idle-cap` | 1.6 | Longest a single still frame may hold |
| `--hold` | 2.5 | Extra pause on the final frame |

GitHub renders README images inline up to 10 MB; `render.py` warns if a clip
crosses that. The usual fix is `--fps 8` or `--size 12`.

## Why not asciinema / vhs / ffmpeg?

`record.py` writes standard **asciinema v2** `.cast` files, so all of that
still works if you prefer it:

```bash
agg --theme monokai cast/hijack.cast gif/hijack.gif
asciinema upload cast/hijack.cast
```

`render.py` exists so the pipeline has no dependency beyond Pillow and a
monospace TTF — anyone who can run the test suite can regenerate the GIFs.
It also gets F-keys right, which matters here: VHS tapes cannot send
<kbd>F2</kbd>/<kbd>F4</kbd>/<kbd>F10</kbd>, and those are most of PwnTUI's
interface.

## Files

| File | Role |
|---|---|
| `record.py` | Scene definitions + the pty driver |
| `render.py` | `.cast` → GIF: frame sampling, palette, PIL rasterising |
| `vt.py` | A small VT/xterm screen emulator — enough of one to replay the recording into a grid of coloured cells |
