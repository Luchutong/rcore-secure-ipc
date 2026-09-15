#!/usr/bin/env python3
"""Verify that the delivery kit is internally consistent and complete."""

import re
import struct
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]

REQUIRED_DOCS = [
    "README.md",
    "TEAM_ASSIGNMENTS.md",
    "USER_TEST_PROGRAMS.md",
    "COURSE_REPORT.md",
    "SCREENSHOT_AND_LOG_GUIDE.md",
    "DEFENSE_PPT.md",
    "DEFENSE_PPT_10MIN_4PERSON.md",
    "DEFENSE_QA_MODULE_D.md",
    "FINAL_CHECKLIST.md",
    "templates/TEST_RECORD_TEMPLATE.md",
]
REQUIRED_LOGS = [
    "logs/main-ci-34799749443.log",
    "logs/host-audit-28-of-28.log",
    "logs/qemu-security-programs.log",
    "logs/final-performance.log",
]
PROGRAMS = [
    "cred_test.rs",
    "badptr.rs",
    "quota_test.rs",
    "ipc_audit_integration_test.rs",
    "auditctl_test.rs",
    "audit_test.rs",
    "audit_stress_test.rs",
    "ipc_bench.rs",
    "auditctl.rs",
    "usertests.rs",
]


def require(condition, message):
    if not condition:
        raise SystemExit(f"FAIL: {message}")
    print(f"PASS: {message}")


def png_size(path):
    data = path.read_bytes()[:24]
    require(data[:8] == b"\x89PNG\r\n\x1a\n", f"{path.name} is PNG")
    return struct.unpack(">II", data[16:24])


def verify_links(path):
    text = path.read_text(encoding="utf-8")
    for target in re.findall(r"\[[^]]*\]\(([^)]+)\)", text):
        if target.startswith(("http://", "https://", "#")):
            continue
        clean = target.split("#", 1)[0]
        if clean:
            require((path.parent / clean).exists(), f"local link {path.name} -> {clean}")


def main():
    for relative in REQUIRED_DOCS + REQUIRED_LOGS:
        require((ROOT / relative).is_file(), f"required file {relative}")

    for name in PROGRAMS:
        require((REPO / "user" / "src" / "bin" / name).is_file(), f"user program {name}")

    for index in range(1, 7):
        matches = list((ROOT / "figures").glob(f"fig-{index:02d}-*.svg"))
        require(len(matches) == 1, f"figure {index:02d} SVG exists once")
        svg = matches[0]
        png = svg.with_suffix(".png")
        require(png.is_file(), f"{png.name} exists")
        svg_text = svg.read_text(encoding="utf-8")
        require("<style" not in svg_text and "class=" not in svg_text, f"{svg.name} has no CSS")
        require("gradient" not in svg_text.lower() and "filter=" not in svg_text, f"{svg.name} has no decorative effects")
        require(png_size(png) == (1600, 900), f"{png.name} is 1600x900")

    ci = (ROOT / "logs/main-ci-34799749443.log").read_text(encoding="utf-8")
    require("28/28 passed" in ci and "4/4 passed" in ci and "32/32" in ci, "CI log has all suite totals")
    require("total=768 retained=256" in ci, "CI log has bounded stress result")

    host = (ROOT / "logs/host-audit-28-of-28.log").read_text(encoding="utf-8")
    require("Total: 28 passed; 0 failed" in host, "host log total is 28/28")

    performance = (ROOT / "logs/final-performance.log").read_text(encoding="utf-8")
    require(performance.count("BENCH pipe_create_close") == 5, "performance log has five raw samples")
    require("Median elapsed_ms: 746" in performance and "+15.3%" in performance, "performance summary is consistent")

    report = (ROOT / "COURSE_REPORT.md").read_text(encoding="utf-8")
    for fact in ("28/28", "32/32", "15.3%", "B→A→C→D", "v1.0.0"):
        require(fact in report, f"course report contains {fact}")

    docx = ROOT / "generated/rcore-secure-ipc-course-report-draft.docx"
    require(docx.is_file(), "editable DOCX report exists")
    with zipfile.ZipFile(docx) as archive:
        bad = archive.testzip()
        require(bad is None, "DOCX archive passes integrity test")
        media = [name for name in archive.namelist() if name.startswith("word/media/")]
        require(len(media) == 6, "DOCX embeds all six figures")

    for relative in REQUIRED_DOCS:
        verify_links(ROOT / relative)

    print("ALL DELIVERY CHECKS PASSED")


if __name__ == "__main__":
    main()
