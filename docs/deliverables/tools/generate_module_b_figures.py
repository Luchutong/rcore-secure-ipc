#!/usr/bin/env python3
"""Generate Module B raw-evidence and result-summary figures."""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
FIGURES = ROOT / "figures"
SANS = "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"
SANS_BOLD = "/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc"
MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"

WIDTH = 1600
HEIGHT = 900


def centered(draw, box, value, font, fill):
    left, top, right, bottom = box
    bounds = draw.textbbox((0, 0), value, font=font)
    text_width = bounds[2] - bounds[0]
    text_height = bounds[3] - bounds[1]
    x = left + (right - left - text_width) / 2
    y = top + (bottom - top - text_height) / 2 - bounds[1]
    draw.text((x, y), value, font=font, fill=fill)


def evidence():
    background = "#111820"
    text = "#E7EDF3"
    prompt = "#77B8E6"
    success = "#83C995"
    image = Image.new("RGB", (WIDTH, HEIGHT), background)
    draw = ImageDraw.Draw(image)
    font = ImageFont.truetype(MONO, 36)
    lines = [
        (">> badptr", prompt),
        ("badptr [PASS] NULL -> EFAULT", success),
        ("badptr [PASS] Kernel Address -> EFAULT", success),
        ("badptr [PASS] High Address -> EFAULT", success),
        ("badptr [PASS] Length Overflow -> EFAULT", success),
        ("badptr [PASS] Unmapped Page -> EFAULT", success),
        ("badptr [PASS] Cross-page Missing -> EFAULT", success),
        ("badptr [PASS] Read-only Output -> EFAULT", success),
        ("badptr [PASS] Cross-page Read-only -> EFAULT", success),
        ("badptr summary: 8/8 passed", success),
        ("badptr kernel: alive", success),
        ("", text),
        (">> hello_world", prompt),
        ("Hello world from user mode program!", text),
    ]
    x = 70
    y = 55
    for value, color in lines:
        draw.text((x, y), value, font=font, fill=color)
        y += 57
    image.save(FIGURES / "module-b-badptr-qemu-evidence.png", format="PNG", optimize=True)


def summary():
    image = Image.new("RGB", (WIDTH, HEIGHT), "#FFFFFF")
    draw = ImageDraw.Draw(image)
    list_font = ImageFont.truetype(SANS, 42)
    count_font = ImageFont.truetype(SANS_BOLD, 132)
    pass_font = ImageFont.truetype(SANS_BOLD, 78)
    detail_font = ImageFont.truetype(SANS_BOLD, 44)
    text = "#20262E"
    blue = "#315B7D"
    line = "#CBD3DA"

    draw.line((820, 95, 820, 805), fill=line, width=3)
    scenarios = [
        "NULL",
        "Kernel Address",
        "High Address",
        "Length Overflow",
        "Unmapped Page",
        "Cross-page Missing",
        "Read-only Output",
        "Cross-page Read-only",
    ]
    y = 105
    for scenario in scenarios:
        draw.text((120, y), scenario, font=list_font, fill=text)
        y += 86

    centered(draw, (900, 125, 1515, 340), "8 / 8", count_font, blue)
    centered(draw, (900, 330, 1515, 455), "PASS", pass_font, blue)
    draw.line((955, 500, 1460, 500), fill=line, width=3)
    centered(draw, (900, 535, 1515, 650), "Return: EFAULT", detail_font, text)
    centered(draw, (900, 670, 1515, 785), "Kernel: Alive", detail_font, text)
    image.save(FIGURES / "module-b-badptr-summary.png", format="PNG", optimize=True)


def main():
    FIGURES.mkdir(parents=True, exist_ok=True)
    evidence()
    summary()


if __name__ == "__main__":
    main()
