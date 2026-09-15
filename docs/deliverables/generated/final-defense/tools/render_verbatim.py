#!/usr/bin/env python3
"""Render selected, contiguous blocks from real terminal transcripts.

This tool never contains test-result strings.  It reads the raw PTY captures
or the repository's final benchmark log, strips terminal control bytes, and
renders only text found in those sources.  The JSON index records the source
file and SHA-256 for every generated PNG.
"""

import hashlib
import json
import re
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "raw"
IMAGES = ROOT / "images"
REPO = ROOT.parents[3]
MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"

WIDTH = 1600
HEIGHT = 900
MARGIN_X = 65
MARGIN_Y = 60
BACKGROUND = "#FFFFFF"
TEXT = "#16263A"
BLUE = "#005BAC"
RULE = "#005BAC"

ANSI_CSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")

SPECS = [
    {
        "image": "01-qemu-suite-summary-verbatim.png",
        "source": RAW / "qemu-summary-filter-20260915.typescript",
        "start": "[usertests] expected-success suite result",
        "end": "Usertests passed!",
        "font_size": 42,
    },
    {
        "image": "02-qemu-badptr-verbatim.png",
        "source": RAW / "qemu-usertests-20260915.typescript",
        "start": "[usertests] RUN  badptr",
        "end": "[usertests] PASS badptr: exit=0",
        "font_size": 34,
    },
    {
        "image": "03-qemu-quota-verbatim.png",
        "source": RAW / "qemu-usertests-20260915.typescript",
        "start": "[usertests] RUN  quota_test",
        "end": "[usertests] PASS quota_test: exit=0",
        "font_size": 30,
    },
    {
        "image": "04-qemu-audit-stress-verbatim.png",
        "source": RAW / "qemu-usertests-20260915.typescript",
        "start": "[usertests] RUN  audit_stress_test",
        "end": "[usertests] PASS audit_stress_test: exit=0",
        "font_size": 36,
    },
    {
        "image": "05-host-audit-lib-verbatim.png",
        "source": RAW / "host-audit-20260915.typescript",
        "start": "running 7 tests",
        "end": "test result: ok. 7 passed",
        "font_size": 31,
    },
    {
        "image": "06-host-auditctl-verbatim.png",
        "source": RAW / "host-audit-20260915.typescript",
        "start": "running 12 tests",
        "end": "test result: ok. 12 passed",
        "font_size": 27,
    },
    {
        "image": "07-host-syscalls-verbatim.png",
        "source": RAW / "host-audit-20260915.typescript",
        "start": "running 9 tests",
        "end": "test result: ok. 9 passed",
        "font_size": 29,
    },
    {
        "image": "08-final-performance-log-verbatim.png",
        "source": REPO / "docs/deliverables/logs/final-performance.log",
        "start": "rCore Secure IPC v1.0.0 - final IPC benchmark",
        "end": "Conclusion: measurable constant-factor overhead; no order-of-magnitude regression.",
        "font_size": 20,
    },
]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def clean_lines(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    text = ANSI_CSI.sub("", text).replace("\r", "")
    return text.splitlines()


def find_block(lines: list[str], start: str, end: str) -> list[str]:
    begin = next(i for i, line in enumerate(lines) if start in line)
    finish = next(i for i, line in enumerate(lines[begin:], begin) if end in line)
    return lines[begin : finish + 1]


def wrap_verbatim(draw: ImageDraw.ImageDraw, line: str, font: ImageFont.FreeTypeFont) -> list[str]:
    """Wrap at character boundaries; every source character remains present."""
    limit = WIDTH - 2 * MARGIN_X
    if not line:
        return [""]
    chunks: list[str] = []
    current = ""
    for char in line:
        if current and draw.textlength(current + char, font=font) > limit:
            chunks.append(current)
            current = char
        else:
            current += char
    chunks.append(current)
    return chunks


def render(lines: list[str], output: Path, font_size: int) -> None:
    image = Image.new("RGB", (WIDTH, HEIGHT), BACKGROUND)
    draw = ImageDraw.Draw(image)
    for size in range(font_size, 11, -1):
        font = ImageFont.truetype(MONO, size)
        line_height = size + 12
        max_lines = (HEIGHT - 2 * MARGIN_Y - 10) // line_height
        visual_lines = [
            (chunk, line.startswith("[usertests]"))
            for line in lines
            for chunk in wrap_verbatim(draw, line, font)
        ]
        if len(visual_lines) <= max_lines:
            break
    else:
        raise ValueError(f"{output.name}: transcript block does not fit 16:9 canvas")

    draw.rectangle((0, 0, WIDTH, 12), fill=RULE)
    y = MARGIN_Y
    for line, is_usertest in visual_lines:
        color = BLUE if is_usertest else TEXT
        draw.text((MARGIN_X, y), line, font=font, fill=color)
        y += line_height
    image.save(output, format="PNG", optimize=True)


def main() -> None:
    IMAGES.mkdir(parents=True, exist_ok=True)
    records = []
    for spec in SPECS:
        source = spec["source"]
        lines = find_block(clean_lines(source), spec["start"], spec["end"])
        output = IMAGES / spec["image"]
        render(lines, output, spec["font_size"])
        records.append(
            {
                "image": str(output.relative_to(ROOT)),
                "image_sha256": sha256(output),
                "source": str(source.relative_to(ROOT)) if source.is_relative_to(ROOT) else str(source.relative_to(REPO)),
                "source_sha256": sha256(source),
                "start_marker": spec["start"],
                "end_marker": spec["end"],
                "line_count": len(lines),
            }
        )
    (ROOT / "VERIFICATION_INDEX.json").write_text(
        json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
