#!/usr/bin/env python3
"""Generate the minimal Module A authorization result table for PPT use."""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "figures" / "module-a-auth-results.png"
REGULAR = "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"
BOLD = "/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc"

WIDTH = 1600
HEIGHT = 900
LEFT = 180
TOP = 110
RIGHT = 1420
BOTTOM = 790
DIVIDER = 1130
ROWS = 5
ROW_HEIGHT = (BOTTOM - TOP) // ROWS

BACKGROUND = "#FFFFFF"
LINE = "#AEB8C2"
TEXT = "#20262E"
HEADER = "#F1F4F7"
ALLOW = "#315B7D"
DENY = "#8B3A3A"


def centered(draw, box, value, font, fill):
    left, top, right, bottom = box
    bounds = draw.textbbox((0, 0), value, font=font)
    text_width = bounds[2] - bounds[0]
    text_height = bounds[3] - bounds[1]
    x = left + (right - left - text_width) / 2
    y = top + (bottom - top - text_height) / 2 - bounds[1]
    draw.text((x, y), value, font=font, fill=fill)


def main():
    image = Image.new("RGB", (WIDTH, HEIGHT), BACKGROUND)
    draw = ImageDraw.Draw(image)
    header_font = ImageFont.truetype(BOLD, 48)
    cell_font = ImageFont.truetype(REGULAR, 48)
    result_font = ImageFont.truetype(BOLD, 46)

    draw.rectangle((LEFT, TOP, RIGHT, TOP + ROW_HEIGHT), fill=HEADER)
    draw.rectangle((LEFT, TOP, RIGHT, BOTTOM), outline=LINE, width=3)
    draw.line((DIVIDER, TOP, DIVIDER, BOTTOM), fill=LINE, width=3)
    for row in range(1, ROWS):
        y = TOP + row * ROW_HEIGHT
        draw.line((LEFT, y, RIGHT, y), fill=LINE, width=3)

    centered(draw, (LEFT, TOP, DIVIDER, TOP + ROW_HEIGHT), "场景", header_font, TEXT)
    centered(draw, (DIVIDER, TOP, RIGHT, TOP + ROW_HEIGHT), "结果", header_font, TEXT)

    values = [
        ("自发送", "ALLOW", ALLOW),
        ("同 UID", "ALLOW", ALLOW),
        ("root / CAP_KILL", "ALLOW", ALLOW),
        ("跨 UID 无特权", "EPERM", DENY),
    ]
    for index, (scenario, result, color) in enumerate(values, start=1):
        top = TOP + index * ROW_HEIGHT
        bottom = top + ROW_HEIGHT
        centered(draw, (LEFT, top, DIVIDER, bottom), scenario, cell_font, TEXT)
        centered(draw, (DIVIDER, top, RIGHT, bottom), result, result_font, color)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    image.save(OUTPUT, format="PNG", optimize=True)


if __name__ == "__main__":
    main()
