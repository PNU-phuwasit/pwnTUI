#!/usr/bin/env python3
"""Turn recorded .cast files into README-ready GIFs.

Self-contained: PIL and a monospace TTF are the only requirements, both of
which you already have if you can run the test suite. No ffmpeg, no Rust
toolchain, no headless browser.

    ./render.py                       # every cast in ./cast
    ./render.py hijack --fps 12
    ./render.py --theme light

If you would rather use asciinema's own renderer, the .cast files are
standard v2 and work with `agg` unchanged:

    agg --theme monokai cast/hijack.cast gif/hijack.gif
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from PIL import Image, ImageDraw, ImageFont

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vt import Screen  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
CAST = os.path.join(HERE, "cast")
GIF = os.path.join(HERE, "gif")

FONT_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/truetype/firacode/FiraCode-Regular.ttf",
    "/usr/share/fonts/truetype/noto/NotoSansMono-Regular.ttf",
    "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
    "/System/Library/Fonts/Menlo.ttc",
]
#: Emoji are a separate font on every Linux, and the checksec bar is made of
#: them -- without this the protection badges render as tofu boxes, which is
#: the one row of the UI a reader looks at first.
EMOJI_CANDIDATES = [
    "/usr/share/fonts/truetype/noto/NotoColorEmoji.ttf",
    "/usr/share/fonts/truetype/ancient-scripts/Symbola_hint.ttf",
    "/usr/share/fonts/truetype/unifont/unifont.ttf",
]

#: Last resort when no emoji font exists: keep the meaning, lose the colour.
EMOJI_FALLBACK = {"\U0001F7E2": "+", "\U0001F7E1": "~", "\U0001F534": "!"}

BOLD_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
    "/usr/share/fonts/truetype/firacode/FiraCode-Bold.ttf",
    "/usr/share/fonts/truetype/noto/NotoSansMono-Bold.ttf",
    "/usr/share/fonts/TTF/DejaVuSansMono-Bold.ttf",
]

THEMES = {
    # Backgrounds chosen to sit well on both GitHub themes.
    "dark":  {"fg": (0xD4, 0xD4, 0xD4), "bg": (0x10, 0x14, 0x17)},
    "light": {"fg": (0x24, 0x29, 0x2F), "bg": (0xFA, 0xFB, 0xFC)},
}


def pick(paths):
    for p in paths:
        if os.path.exists(p):
            return p
    return None


def load_cast(path):
    with open(path) as f:
        header = json.loads(f.readline())
        events = []
        for line in f:
            line = line.strip()
            if line:
                t, kind, data = json.loads(line)
                if kind == "o":
                    events.append((t, data))
    return header, events


def frames_from_cast(header, events, fps, idle_cap):
    """Replay the stream and snapshot the screen on a fixed clock.

    Consecutive identical screens collapse into one frame with a longer
    delay -- a TUI is mostly still, so this is the difference between a
    3 MB GIF and a 300 KB one.
    """
    screen = Screen(header["width"], header["height"],
                    fg=THEMES["dark"]["fg"], bg=THEMES["dark"]["bg"])
    step = 1.0 / fps
    end = events[-1][0] if events else 0.0
    frames, idx, t = [], 0, 0.0
    last_digest, last_snapshot = None, None
    while t <= end + step:
        while idx < len(events) and events[idx][0] <= t:
            screen.feed(events[idx][1])
            idx += 1
        digest = screen.digest()
        if digest == last_digest and frames:
            frames[-1][1] += step
        else:
            last_snapshot = screen.snapshot()
            frames.append([last_snapshot, step])
            last_digest = digest
        t += step
    for frame in frames:                     # no single frame may stall the loop
        frame[1] = min(frame[1], idle_cap)
    return _trim_blank(frames)


def _blank_frame(cells) -> bool:
    return all(glyph == " " for row in cells for glyph, _, _, _ in row)


def _trim_blank(frames):
    """Drop the empty screens at each end.

    Quitting clears the alternate buffer, so the last thing recorded is an
    empty terminal -- and since the final frame is the one that gets the
    long hold, the GIF used to end by staring at a blank rectangle for two
    and a half seconds. The lead-in is trimmed for the same reason: Textual
    takes a moment to paint its first frame.
    """
    start, end = 0, len(frames)
    while start < end and _blank_frame(frames[start][0]):
        start += 1
    while end > start and _blank_frame(frames[end - 1][0]):
        end -= 1
    return frames[start:end] or frames


#: Real emoji blocks only. An earlier "codepoint > 0x2100" test also caught
#: U+2500-257F box drawing -- which is every panel border in the UI -- and
#: handed it to a font that has no such glyphs, so the frames came out with
#: all the borders missing.
_EMOJI_RANGES = (
    (0x1F000, 0x1FAFF),   # pictographs, incl. the coloured circles
    (0x2600, 0x26FF),     # miscellaneous symbols
    (0x2700, 0x27BF),     # dingbats, incl. U+274C
    (0x2B00, 0x2BFF),     # arrows and shapes
    (0xFE00, 0xFE0F),     # variation selectors
)


def is_emoji(glyph: str) -> bool:
    cp = ord(glyph)
    return any(lo <= cp <= hi for lo, hi in _EMOJI_RANGES)


def load_emoji(size):
    """A bitmap-strike colour font can only be loaded at the size it ships
    (136 px for Noto Color Emoji); it is rendered big and scaled down."""
    path = pick(EMOJI_CANDIDATES)
    if path is None:
        return None, 1.0
    for native in (size, 109, 136):
        try:
            return ImageFont.truetype(path, native), size / native
        except OSError:
            continue
    return None, 1.0


def render_frame(cells, font, bold_font, cw, ch, pad, theme, emoji=None):
    rows, cols = len(cells), len(cells[0])
    img = Image.new("RGB", (cols * cw + pad * 2, rows * ch + pad * 2), theme["bg"])
    d = ImageDraw.Draw(img)
    for y, row in enumerate(cells):
        # Paint background runs first, so box-drawing glyphs that overhang
        # their cell are not clipped by the next cell's background.
        x = 0
        while x < cols:
            bg = row[x][2]
            run = x
            while run < cols and row[run][2] == bg:
                run += 1
            if bg != theme["bg"]:
                d.rectangle([pad + x * cw, pad + y * ch,
                             pad + run * cw - 1, pad + (y + 1) * ch - 1], fill=bg)
            x = run
        for x, (glyph, fg, bg, bold) in enumerate(row):
            if glyph == " ":
                continue
            if is_emoji(glyph):
                _draw_emoji(img, d, glyph, pad + x * cw, pad + y * ch, cw, ch,
                            fg, font, emoji)
                continue
            d.text((pad + x * cw, pad + y * ch), glyph,
                   font=bold_font if bold else font, fill=fg)
    return img


def _draw_emoji(img, d, glyph, px, py, cw, ch, fg, font, emoji):
    emoji_font, scale = emoji if emoji else (None, 1.0)
    if emoji_font is not None:
        try:
            box = emoji_font.getbbox(glyph)
            w, h = max(1, box[2] - box[0]), max(1, box[3] - box[1])
            tile = Image.new("RGBA", (w, h), (0, 0, 0, 0))
            ImageDraw.Draw(tile).text((-box[0], -box[1]), glyph,
                                      font=emoji_font, embedded_color=True)
            target = max(1, int(h * scale))
            tile = tile.resize((max(1, int(w * scale)), target), Image.LANCZOS)
            img.paste(tile, (px, py + max(0, (ch - target) // 2)), tile)
            return
        except Exception:
            pass
    d.text((px, py), EMOJI_FALLBACK.get(glyph, "?"), font=font, fill=fg)


def build(cast_path, out_path, fps, size, theme_name, idle_cap, hold):
    header, events = load_cast(cast_path)
    if not events:
        print(f"  {os.path.basename(cast_path)}: no output recorded, skipping")
        return
    theme = THEMES[theme_name]

    regular = pick(FONT_CANDIDATES)
    if regular is None:
        sys.exit("no monospace TTF found -- install fonts-dejavu-core, or edit "
                 "FONT_CANDIDATES in this file")
    font = ImageFont.truetype(regular, size)
    bold_path = pick(BOLD_CANDIDATES)
    bold_font = ImageFont.truetype(bold_path, size) if bold_path else font

    cw = round(font.getlength("M"))
    asc, desc = font.getmetrics()
    ch = asc + desc

    emoji = load_emoji(size)
    frames = frames_from_cast(header, events, fps, idle_cap)
    frames[-1][1] = max(frames[-1][1], hold)     # let the final state be read

    images, durations = [], []
    for cells, delay in frames:
        images.append(render_frame(cells, font, bold_font, cw, ch, size // 2,
                                   theme, emoji))
        durations.append(max(20, int(delay * 1000)))

    # One shared palette for the whole GIF. Per-frame adaptive palettes make
    # the colours shimmer as the quantiser re-picks them each frame.
    sample = Image.new("RGB", (images[0].width, images[0].height * min(6, len(images))))
    for n, im in enumerate(images[:: max(1, len(images) // 6)][:6]):
        sample.paste(im, (0, n * images[0].height))
    palette = sample.quantize(colors=255, method=Image.Quantize.MEDIANCUT)

    quantised = [im.quantize(palette=palette, dither=Image.Dither.NONE) for im in images]
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    quantised[0].save(
        out_path, save_all=True, append_images=quantised[1:],
        duration=durations, loop=0, optimize=True, disposal=1,
    )
    kb = os.path.getsize(out_path) / 1024
    total = sum(durations) / 1000
    print(f"  {os.path.basename(out_path):<18} {images[0].width}x{images[0].height}  "
          f"{len(frames):4d} frames  {total:5.1f}s  {kb:7.1f} KB")
    if kb > 1024 * 9:
        print("      ^ over GitHub's 10 MB inline limit -- lower --fps or --size")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("names", nargs="*", help="cast names to render (default: all)")
    ap.add_argument("--fps", type=float, default=10.0, help="sample rate (default 10)")
    ap.add_argument("--size", type=int, default=14, help="font size in px (default 14)")
    ap.add_argument("--theme", choices=sorted(THEMES), default="dark")
    ap.add_argument("--idle-cap", type=float, default=1.6,
                    help="longest a single still frame may hold, seconds")
    ap.add_argument("--hold", type=float, default=2.5,
                    help="extra pause on the final frame, seconds")
    ns = ap.parse_args()

    if not os.path.isdir(CAST):
        sys.exit(f"no recordings in {CAST} -- run ./record.py first")
    casts = sorted(f for f in os.listdir(CAST) if f.endswith(".cast"))
    if ns.names:
        casts = [f"{n}.cast" for n in ns.names]
    if not casts:
        sys.exit("nothing to render")

    print("rendering:")
    for name in casts:
        src = os.path.join(CAST, name)
        if not os.path.exists(src):
            print(f"  {name}: not found, skipping")
            continue
        build(src, os.path.join(GIF, name[:-5] + ".gif"),
              ns.fps, ns.size, ns.theme, ns.idle_cap, ns.hold)


if __name__ == "__main__":
    main()
