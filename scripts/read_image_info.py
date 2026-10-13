#!/usr/bin/env python3
"""
Read and visualize image information for the SITAS prototype.

Usage:
    python scripts/read_image_info.py path/to/image.png
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import mimetypes
import re
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Any

import numpy as np
from PIL import ExifTags, Image, ImageOps


TEXT_PREVIEW_BYTES = 256
DEFAULT_LSB_SAMPLE_BITS = 8192
MAX_THUMBNAIL_SIZE = (640, 480)
MAX_BITPLANE_SIZE = (640, 480)


@dataclass
class OutputPaths:
    html_report: Path
    json_report: Path | None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def human_size(num_bytes: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    value = float(num_bytes)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{num_bytes} B"


def is_mostly_text(text: str) -> bool:
    if not text:
        return False
    printable = sum(1 for char in text if char.isprintable() or char in "\r\n\t")
    return printable / len(text) >= 0.85


def safe_value(value: Any) -> Any:
    if isinstance(value, bytes):
        try:
            text = value.decode("utf-8")
            if is_mostly_text(text):
                return text
        except UnicodeDecodeError:
            pass
        return {"type": "bytes", "length": len(value), "hex_preview": value[:64].hex()}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return [safe_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): safe_value(item) for key, item in value.items()}
    return str(value)


def collect_exif(image: Image.Image) -> dict[str, Any]:
    exif_data: dict[str, Any] = {}
    raw_exif = image.getexif()
    for tag_id, value in raw_exif.items():
        tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
        exif_data[str(tag_name)] = safe_value(value)
    return exif_data


def collect_embedded_metadata(image: Image.Image) -> dict[str, Any]:
    ignored_keys = {"exif", "icc_profile", "XML:com.adobe.xmp"}
    info: dict[str, Any] = {}
    for key, value in image.info.items():
        if key in ignored_keys:
            continue
        info[str(key)] = safe_value(value)

    if "icc_profile" in image.info:
        profile = image.info["icc_profile"]
        info["icc_profile"] = {
            "type": "bytes",
            "length": len(profile),
            "sha256": hashlib.sha256(profile).hexdigest(),
        }
    if "XML:com.adobe.xmp" in image.info:
        info["xmp"] = safe_value(image.info["XML:com.adobe.xmp"])
    return info


def image_to_data_uri(image: Image.Image, max_size: tuple[int, int]) -> str:
    preview = ImageOps.exif_transpose(image).copy()
    preview.thumbnail(max_size)
    if preview.mode not in ("RGB", "RGBA"):
        preview = preview.convert("RGB")
    buffer = BytesIO()
    preview.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def bitplane_to_data_uri(bitplane: np.ndarray) -> str:
    visual = bitplane.astype(np.uint8) * 255
    image = Image.fromarray(visual, mode="L")
    image.thumbnail(MAX_BITPLANE_SIZE, Image.Resampling.NEAREST)
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def channel_array(image: Image.Image) -> tuple[np.ndarray, list[str]]:
    if image.mode == "L":
        return np.array(image), ["L"]
    if image.mode in ("RGB", "RGBA"):
        return np.array(image), list(image.mode)
    converted = image.convert("RGBA")
    return np.array(converted), list("RGBA")


def channel_statistics(arr: np.ndarray, channel_names: list[str]) -> dict[str, dict[str, float | int]]:
    if arr.ndim == 2:
        arr = arr[:, :, None]
    stats: dict[str, dict[str, float | int]] = {}
    for idx, name in enumerate(channel_names):
        channel = arr[:, :, idx].astype(np.float64)
        stats[name] = {
            "min": int(channel.min()),
            "max": int(channel.max()),
            "mean": round(float(channel.mean()), 4),
            "std": round(float(channel.std()), 4),
        }
    return stats


def lsb_statistics(arr: np.ndarray, channel_names: list[str]) -> tuple[dict[str, Any], np.ndarray]:
    if arr.ndim == 2:
        arr = arr[:, :, None]
    stats: dict[str, Any] = {}
    combined = np.zeros(arr.shape[:2], dtype=np.uint8)
    for idx, name in enumerate(channel_names):
        channel_lsb = (arr[:, :, idx] & 1).astype(np.uint8)
        zeros = int((channel_lsb == 0).sum())
        ones = int((channel_lsb == 1).sum())
        total = zeros + ones
        expected = total / 2 if total else 1
        chi_square = ((zeros - expected) ** 2 + (ones - expected) ** 2) / expected
        stats[name] = {
            "zeros": zeros,
            "ones": ones,
            "ones_ratio": round(ones / total if total else 0, 6),
            "chi_square_vs_50_50": round(float(chi_square), 4),
        }
        combined ^= channel_lsb
    return stats, combined


def bits_to_bytes(bits: list[int], msb_first: bool = True) -> bytes:
    output = bytearray()
    for pos in range(0, len(bits) - 7, 8):
        value = 0
        chunk = bits[pos : pos + 8]
        if msb_first:
            for bit in chunk:
                value = (value << 1) | bit
        else:
            for shift, bit in enumerate(chunk):
                value |= bit << shift
        output.append(value)
    return bytes(output)


def printable_preview(payload: bytes, limit: int = TEXT_PREVIEW_BYTES) -> dict[str, Any]:
    sample = payload[:limit]
    result: dict[str, Any] = {"byte_length": len(payload), "hex_preview": sample.hex()}
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            decoded = sample.decode(encoding, errors="strict")
        except UnicodeDecodeError:
            continue
        cleaned = decoded.replace("\x00", "")
        if is_mostly_text(cleaned):
            result["text_encoding_guess"] = encoding
            result["text_preview"] = cleaned[:limit]
            break
    return result


def extract_lsb_probe(arr: np.ndarray, channel_names: list[str], max_bits: int) -> dict[str, Any]:
    if arr.ndim == 2:
        arr = arr[:, :, None]
    probe_channels = [idx for idx, name in enumerate(channel_names) if name != "A"] or list(range(arr.shape[2]))
    bits: list[int] = []
    height, width = arr.shape[:2]
    for y in range(height):
        for x in range(width):
            for channel_idx in probe_channels:
                bits.append(int(arr[y, x, channel_idx] & 1))
                if len(bits) >= max_bits:
                    break
            if len(bits) >= max_bits:
                break
        if len(bits) >= max_bits:
            break
    return {
        "sampled_bits": len(bits),
        "channels_read_order": [channel_names[idx] for idx in probe_channels],
        "msb_first_preview": printable_preview(bits_to_bytes(bits, msb_first=True)),
        "lsb_first_preview": printable_preview(bits_to_bytes(bits, msb_first=False)),
        "note": "This is a probe only. Real decoding depends on the watermark write protocol.",
    }


def render_kv_table(data: dict[str, Any]) -> str:
    if not data:
        return "<p class='muted'>No data found.</p>"
    rows = []
    for key, value in data.items():
        display = json.dumps(value, ensure_ascii=False, indent=2) if isinstance(value, (dict, list)) else str(value)
        rows.append(f"<tr><th>{html.escape(str(key))}</th><td><pre>{html.escape(display)}</pre></td></tr>")
    return "<table>" + "\n".join(rows) + "</table>"


def render_channel_table(stats: dict[str, dict[str, Any]]) -> str:
    if not stats:
        return "<p class='muted'>No channel stats.</p>"
    headers = sorted({key for values in stats.values() for key in values})
    rows = ["<tr><th>Channel</th>" + "".join(f"<th>{html.escape(header)}</th>" for header in headers) + "</tr>"]
    for channel, values in stats.items():
        rows.append(
            "<tr>"
            f"<td>{html.escape(channel)}</td>"
            + "".join(f"<td>{html.escape(str(values.get(header, '')))}</td>" for header in headers)
            + "</tr>"
        )
    return "<table>" + "\n".join(rows) + "</table>"


def make_report(image_path: Path, lsb_sample_bits: int) -> tuple[dict[str, Any], str]:
    with Image.open(image_path) as image:
        image.load()
        arr, channel_names = channel_array(image)
        lsb_stats, bitplane = lsb_statistics(arr, channel_names)
        file_stat = image_path.stat()
        mime_type, _ = mimetypes.guess_type(image_path.name)
        basic = {
            "path": str(image_path.resolve()),
            "file_name": image_path.name,
            "file_size": file_stat.st_size,
            "file_size_human": human_size(file_stat.st_size),
            "mime_type": mime_type,
            "sha256": sha256_file(image_path),
            "format": image.format,
            "mode": image.mode,
            "width": image.width,
            "height": image.height,
            "pixel_count": image.width * image.height,
            "frames": getattr(image, "n_frames", 1),
        }
        report = {
            "basic": basic,
            "embedded_metadata": collect_embedded_metadata(image),
            "exif": collect_exif(image),
            "channel_statistics": channel_statistics(arr, channel_names),
            "lsb_statistics": lsb_stats,
            "lsb_probe": extract_lsb_probe(arr, channel_names, lsb_sample_bits),
        }
        html_report = render_html_report(report, image_to_data_uri(image, MAX_THUMBNAIL_SIZE), bitplane_to_data_uri(bitplane))
        return report, html_report


def render_html_report(report: dict[str, Any], image_preview: str, bitplane_preview: str) -> str:
    title = f"Image Info Report - {report['basic']['file_name']}"
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)}</title>
  <style>
    body {{ margin: 0; background: #f6f7f9; color: #1f2933; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
    header {{ padding: 24px 32px; background: #fff; border-bottom: 1px solid #d9dee7; }}
    main {{ max-width: 1120px; margin: 0 auto; padding: 24px; }}
    section {{ background: #fff; border: 1px solid #d9dee7; border-radius: 8px; padding: 18px; margin-bottom: 16px; overflow: hidden; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; }}
    img {{ max-width: 100%; border: 1px solid #d9dee7; border-radius: 6px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
    th, td {{ border-top: 1px solid #d9dee7; padding: 9px 10px; vertical-align: top; text-align: left; }}
    th {{ width: 220px; background: #fafafa; }}
    pre {{ margin: 0; white-space: pre-wrap; word-break: break-word; font-family: Menlo, Consolas, monospace; font-size: 12px; }}
    .muted {{ color: #667085; }}
  </style>
</head>
<body>
  <header><h1>{html.escape(title)}</h1><div class="muted">Read only. 这个报告只读取图片，不会修改文件。</div></header>
  <main>
    <div class="grid">
      <section><h2>图片预览</h2><img src="{image_preview}" alt="Image preview"></section>
      <section><h2>LSB 最低位平面预览</h2><img src="{bitplane_preview}" alt="LSB bit-plane preview"></section>
    </div>
    <section><h2>基础信息</h2>{render_kv_table(report["basic"])}</section>
    <section><h2>图片内置元数据</h2>{render_kv_table(report["embedded_metadata"])}</section>
    <section><h2>EXIF 信息</h2>{render_kv_table(report["exif"])}</section>
    <section><h2>通道统计</h2>{render_channel_table(report["channel_statistics"])}</section>
    <section><h2>LSB 统计</h2>{render_channel_table(report["lsb_statistics"])}</section>
    <section><h2>LSB 隐写内容探测</h2>{render_kv_table(report["lsb_probe"])}</section>
  </main>
</body>
</html>
"""


def default_outputs(image_path: Path, html_out: str | None, json_out: str | None) -> OutputPaths:
    safe_stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", image_path.stem).strip("_") or "image"
    html_report = Path(html_out) if html_out else Path("reports") / f"{safe_stem}_image_info.html"
    json_report = Path(json_out) if json_out else Path("reports") / f"{safe_stem}_image_info.json"
    return OutputPaths(html_report=html_report, json_report=json_report)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Read and visualize image metadata and LSB information.")
    parser.add_argument("image", help="Path to the image file to inspect.")
    parser.add_argument("--out", help="HTML report output path. Default: reports/<image>_image_info.html")
    parser.add_argument("--json", help="JSON report output path. Default: reports/<image>_image_info.json")
    parser.add_argument("--lsb-sample-bits", type=int, default=DEFAULT_LSB_SAMPLE_BITS)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    image_path = Path(args.image).expanduser()
    if not image_path.exists() or not image_path.is_file():
        print(f"Image not found: {image_path}")
        return 2
    outputs = default_outputs(image_path, args.out, args.json)
    outputs.html_report.parent.mkdir(parents=True, exist_ok=True)
    if outputs.json_report:
        outputs.json_report.parent.mkdir(parents=True, exist_ok=True)
    report, html_report = make_report(image_path, args.lsb_sample_bits)
    outputs.html_report.write_text(html_report, encoding="utf-8")
    if outputs.json_report:
        outputs.json_report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    basic = report["basic"]
    print("Image info read successfully.")
    print(f"File: {basic['path']}")
    print(f"Format: {basic['format']} | Mode: {basic['mode']} | Size: {basic['width']}x{basic['height']}")
    print(f"HTML report: {outputs.html_report.resolve()}")
    if outputs.json_report:
        print(f"JSON report: {outputs.json_report.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
