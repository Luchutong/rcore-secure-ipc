#!/usr/bin/env python3
"""Generate PPT-ready quota and performance figures from verified test data."""

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


def quota_performance_summary():
    image = Image.new("RGB", (WIDTH, HEIGHT), "#FFFFFF")
    draw = ImageDraw.Draw(image)
    heading = ImageFont.truetype(SANS_BOLD, 40)
    card_text = ImageFont.truetype(SANS, 29)
    label = ImageFont.truetype(SANS_BOLD, 35)
    number = ImageFont.truetype(SANS_BOLD, 48)
    percent = ImageFont.truetype(SANS_BOLD, 103)
    detail = ImageFont.truetype(SANS_BOLD, 29)
    footer = ImageFont.truetype(SANS, 23)
    text = "#20262E"
    blue = "#315B7D"
    border = "#C6D0D9"
    pale = "#F5F8FA"

    cards = [
        ("达到上限", "Create → EMFILE / ENOSPC"),
        ("释放资源", "close → quota restored"),
        ("失败回滚", "No counter leak"),
        ("生命周期一致", "fork / dup / close"),
    ]
    positions = [(70, 90, 450, 330), (480, 90, 860, 330), (70, 370, 450, 610), (480, 370, 860, 610)]
    for (title, body), box in zip(cards, positions):
        draw.rounded_rectangle(box, radius=8, fill=pale, outline=border, width=2)
        left, top, right, bottom = box
        centered(draw, (left + 16, top + 36, right - 16, top + 112), title, heading, blue)
        centered(draw, (left + 16, top + 125, right - 16, bottom - 28), body, card_text, text)

    draw.line((900, 70, 900, 760), fill=border, width=3)
    centered(draw, (950, 75, 1540, 150), "Baseline: 647 ms", label, text)
    centered(draw, (950, 150, 1540, 285), "Secure IPC: 746 ms", number, blue)
    draw.line((1010, 335, 1480, 335), fill=border, width=3)
    centered(draw, (950, 360, 1540, 505), "+15.3%", percent, blue)
    centered(draw, (950, 535, 1540, 625), "20,000 × pipe → close(read) → close(write)", detail, text)
    centered(draw, (940, 665, 1550, 748), "可观测常数级开销，无数量级回退", detail, text)
    centered(draw, (70, 800, 1530, 855), "性能数据为五次 QEMU 运行的中位数；基线与安全版本跨日期比较。", footer, "#58636E")
    image.save(FIGURES / "module-c-quota-performance-summary.png", format="PNG", optimize=True)


def quota_evidence():
    image = Image.new("RGB", (WIDTH, HEIGHT), "#111820")
    draw = ImageDraw.Draw(image)
    font = ImageFont.truetype(MONO, 32)
    prompt = "#77B8E6"
    success = "#83C995"
    text = "#E7EDF3"
    lines = [
        ("[usertests] RUN  quota_test", prompt),
        ("========== quota_test ==========", text),
        ("[quota] open FD exhaustion + recovery passed", success),
        ("[quota] dup FD exhaustion + recovery passed", success),
        ("[quota] pipe exhaustion + recovery passed", success),
        ("[quota] pipe EMFILE + rollback passed", success),
        ("[quota] dup(pipe_fd) accounting passed", success),
        ("[quota] fork inheritance + isolation passed", success),
        ("[quota] concurrent create/close passed", success),
        ("quota_test passed!", success),
        ("[usertests] PASS quota_test: exit=0", success),
        ("", text),
        ("[usertests] PASS all tests: 32/32", success),
    ]
    x = 70
    y = 78
    for value, color in lines:
        draw.text((x, y), value, font=font, fill=color)
        y += 54
    image.save(FIGURES / "module-c-quota-qemu-evidence.png", format="PNG", optimize=True)


def performance_evidence():
    image = Image.new("RGB", (WIDTH, HEIGHT), "#111820")
    draw = ImageDraw.Draw(image)
    font = ImageFont.truetype(MONO, 29)
    prompt = "#77B8E6"
    success = "#83C995"
    text = "#E7EDF3"
    lines = [
        ("$ ipc_bench 20000   (five QEMU samples)", prompt),
        ("elapsed_ms: 778, 746, 737, 746, 727", text),
        ("sorted:     727, 737, 746, 746, 778", text),
        ("", text),
        ("secure IPC median:    746 ms", success),
        ("original baseline:    647 ms", text),
        ("observed difference:  +99 ms  (+15.3%)", success),
        ("", text),
        ("workload: 20,000 × pipe → close(read) → close(write)", text),
        ("audit events per run: 20,000 successful events", text),
        ("", text),
        ("conclusion: measurable constant-factor overhead", success),
        ("            no order-of-magnitude regression", success),
    ]
    x = 70
    y = 105
    for value, color in lines:
        draw.text((x, y), value, font=font, fill=color)
        y += 52
    image.save(FIGURES / "module-c-performance-evidence.png", format="PNG", optimize=True)


def main():
    FIGURES.mkdir(parents=True, exist_ok=True)
    quota_performance_summary()
    quota_evidence()
    performance_evidence()


if __name__ == "__main__":
    main()
