#!/usr/bin/env python3
"""Render the verified QEMU output and audit records as a PPT-ready image."""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "figures" / "module-a-qemu-audit-evidence.png"
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"

WIDTH = 1600
HEIGHT = 900
BACKGROUND = "#111820"
TEXT = "#E7EDF3"
PROMPT = "#77B8E6"
SUCCESS = "#83C995"
FAILURE = "#F08B86"
MUTED = "#AEBBC6"


LINES = [
    (">> sig_simple", PROMPT),
    ("signal_simple: sigaction", TEXT),
    ("signal_simple: kill", TEXT),
    ("user_sig_test passed", SUCCESS),
    ("signal_simple: Done", SUCCESS),
    ("", TEXT),
    (">> cred_test", PROMPT),
    ("[kernel] Killed, SIGKILL=9", TEXT),
    ("[kernel] Killed, SIGKILL=9", TEXT),
    ("cred_test passed!", SUCCESS),
    ("", TEXT),
    (">> auditctl read 0", PROMPT),
    ("seq=1  time_ms=20083 pid=3 uid=0 op=signal_send(1)", TEXT),
    ("       object_id=3 owner_uid=0 requested=1 result=1 status=OK", SUCCESS),
    ("seq=5  time_ms=20127 pid=5 uid=1 op=signal_send(1)", TEXT),
    ("       object_id=4 owner_uid=2 requested=1 status=ERROR errno=1(EPERM)", FAILURE),
    ("seq=7  time_ms=20128 pid=3 uid=0 op=signal_send(1)", TEXT),
    ("       object_id=4 owner_uid=2 requested=1 result=1 status=OK", SUCCESS),
    ("seq=11 time_ms=20130 pid=4 uid=3 op=signal_send(1)", TEXT),
    ("       object_id=5 owner_uid=3 requested=1 result=1 status=OK", SUCCESS),
    ("", TEXT),
    ("signal_send records shown; complete output saved in the test log", MUTED),
]


def main():
    image = Image.new("RGB", (WIDTH, HEIGHT), BACKGROUND)
    draw = ImageDraw.Draw(image)
    font = ImageFont.truetype(FONT, 30)
    line_height = 38
    x = 62
    y = 38

    for value, color in LINES:
        draw.text((x, y), value, font=font, fill=color)
        y += line_height

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    image.save(OUTPUT, format="PNG", optimize=True)


if __name__ == "__main__":
    main()
