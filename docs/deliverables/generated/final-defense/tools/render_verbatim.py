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
# A dark terminal palette.  ANSI colours from the captured PTY are preserved
# when they are present; otherwise the terminal's normal foreground is used.
BACKGROUND = "#0C0C0C"
TEXT = "#CCCCCC"
ANSI_FOREGROUND = {
    30: "#0C0C0C",
    31: "#CD3131",
    32: "#0DBC79",
    33: "#E5E510",
    34: "#2472C8",
    35: "#BC3FBC",
    36: "#11A8CD",
    37: "#E5E5E5",
    90: "#666666",
    91: "#F14C4C",
    92: "#23D18B",
    93: "#F5F543",
    94: "#3B8EEA",
    95: "#D670D6",
    96: "#29B8DB",
    97: "#E5E5E5",
}

ANSI_CSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
ANSI_SGR = re.compile(r"\x1b\[([0-9;]*)m")

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


def source_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8", errors="replace").replace("\r", "").splitlines()


def clean_lines(path: Path) -> list[str]:
    return [ANSI_CSI.sub("", line) for line in source_lines(path)]


def find_block(lines: list[str], start: str, end: str) -> list[str]:
    begin = next(i for i, line in enumerate(lines) if start in line)
    finish = next(i for i, line in enumerate(lines[begin:], begin) if end in line)
    return lines[begin : finish + 1]


def styled_segments(line: str) -> list[tuple[str, str]]:
    """Decode only ANSI SGR colours that really occur in the captured line."""
    foreground = TEXT
    cursor = 0
    segments: list[tuple[str, str]] = []
    for match in ANSI_SGR.finditer(line):
        if cursor < match.start():
            segments.append((line[cursor : match.start()], foreground))
        for value in filter(None, match.group(1).split(";")):
            code = int(value)
            if code == 0 or code == 39:
                foreground = TEXT
            elif code in ANSI_FOREGROUND:
                foreground = ANSI_FOREGROUND[code]
        cursor = match.end()
    if cursor < len(line):
        segments.append((line[cursor:], foreground))
    return segments or [("", foreground)]


def wrap_verbatim(
    draw: ImageDraw.ImageDraw, segments: list[tuple[str, str]], font: ImageFont.FreeTypeFont
) -> list[list[tuple[str, str]]]:
    """Wrap at character boundaries; every non-control source character remains."""
    limit = WIDTH - 2 * MARGIN_X
    chunks: list[list[tuple[str, str]]] = []
    current: list[tuple[str, str]] = []
    current_width = 0.0
    for text, color in segments:
        for char in text:
            char_width = draw.textlength(char, font=font)
            if current and current_width + char_width > limit:
                chunks.append(current)
                current = []
                current_width = 0.0
            if current and current[-1][1] == color:
                current[-1] = (current[-1][0] + char, color)
            else:
                current.append((char, color))
            current_width += char_width
    if current:
        chunks.append(current)
    return chunks or [[("", TEXT)]]


def render(lines: list[str], output: Path, font_size: int) -> None:
    image = Image.new("RGB", (WIDTH, HEIGHT), BACKGROUND)
    draw = ImageDraw.Draw(image)
    for size in range(font_size, 11, -1):
        font = ImageFont.truetype(MONO, size)
        line_height = size + 12
        max_lines = (HEIGHT - 2 * MARGIN_Y - 10) // line_height
        visual_lines = [chunk for line in lines for chunk in wrap_verbatim(draw, styled_segments(line), font)]
        if len(visual_lines) <= max_lines:
            break
    else:
        raise ValueError(f"{output.name}: transcript block does not fit 16:9 canvas")

    y = MARGIN_Y
    for line in visual_lines:
        x = MARGIN_X
        for text, color in line:
            draw.text((x, y), text, font=font, fill=color)
            x += draw.textlength(text, font=font)
        y += line_height
    image.save(output, format="PNG", optimize=True)


def main() -> None:
    IMAGES.mkdir(parents=True, exist_ok=True)
    records = []
    for spec in SPECS:
        source = spec["source"]
        raw_lines = source_lines(source)
        clean = [ANSI_CSI.sub("", line) for line in raw_lines]
        begin = next(i for i, line in enumerate(clean) if spec["start"] in line)
        finish = next(i for i, line in enumerate(clean[begin:], begin) if spec["end"] in line)
        lines = raw_lines[begin : finish + 1]
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
