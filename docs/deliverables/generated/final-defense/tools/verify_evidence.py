#!/usr/bin/env python3
"""Check that every defense image can be regenerated from its declared source."""

import hashlib
import importlib.util
import json
import struct
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RENDER_PATH = Path(__file__).with_name("render_verbatim.py")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def png_size(path: Path) -> tuple[int, int]:
    data = path.read_bytes()[:24]
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise SystemExit(f"FAIL: {path} is not a PNG")
    return struct.unpack(">II", data[16:24])


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")
    print(f"PASS: {message}")


def load_renderer():
    spec = importlib.util.spec_from_file_location("render_verbatim", RENDER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def main() -> None:
    renderer = load_renderer()
    index = json.loads((ROOT / "VERIFICATION_INDEX.json").read_text(encoding="utf-8"))
    require(len(index) == len(renderer.SPECS), "index has one record per rendering specification")

    by_image = {record["image"]: record for record in index}
    with tempfile.TemporaryDirectory() as temporary:
        temporary_dir = Path(temporary)
        for item in renderer.SPECS:
            relative_image = f"images/{item['image']}"
            record = by_image.get(relative_image)
            require(record is not None, f"index has {relative_image}")

            source = item["source"]
            image = ROOT / relative_image
            require(source.is_file(), f"source exists: {record['source']}")
            require(sha256(source) == record["source_sha256"], f"source hash matches: {record['source']}")
            require(image.is_file(), f"image exists: {relative_image}")
            require(png_size(image) == (1600, 900), f"image is 1600x900: {relative_image}")
            require(sha256(image) == record["image_sha256"], f"image hash matches index: {relative_image}")

            lines = renderer.find_block(renderer.clean_lines(source), item["start"], item["end"])
            regenerated = temporary_dir / item["image"]
            renderer.render(lines, regenerated, item["font_size"])
            require(sha256(regenerated) == sha256(image), f"image regenerates exactly: {relative_image}")

    print("ALL FINAL-DEFENSE EVIDENCE CHECKS PASSED")


if __name__ == "__main__":
    main()
