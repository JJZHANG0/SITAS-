#!/usr/bin/env python3
"""
Visual GUI for reading SITAS image information.

Run:
    python scripts/image_info_gui.py
    python scripts/image_info_gui.py path/to/image.png
"""

from __future__ import annotations

import json
import queue
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
from datetime import datetime
from io import BytesIO
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
import tkinter as tk
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import numpy as np
from PIL import Image, ImageDraw, ImageFont, ImageOps, ImageTk

try:
    import cv2
except ImportError:
    cv2 = None  # type: ignore[assignment]

from read_image_info import (
    DEFAULT_LSB_SAMPLE_BITS,
    MAX_BITPLANE_SIZE,
    channel_array,
    channel_statistics,
    collect_embedded_metadata,
    collect_exif,
    default_outputs,
    extract_lsb_probe,
    human_size,
    lsb_statistics,
    make_report,
    sha256_file,
)

from lsb_watermark import (
    embed_lsb_fragile_watermark,
    json_safe_result,
    lsb_embedding_change_map,
    make_overlay,
    make_tamper_heatmap,
    verify_lsb_fragile_watermark,
)


IMAGE_TYPES = (
    ("Image files", "*.png *.jpg *.jpeg *.bmp *.tif *.tiff *.webp"),
    ("PNG", "*.png"),
    ("JPEG", "*.jpg *.jpeg"),
    ("All files", "*.*"),
)

WATERMARK_MAGIC = b"SITAS5"
WATERMARK_HEADER_BYTES = len(WATERMARK_MAGIC) + 4
PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = PROJECT_ROOT / "outputs"
WATERMARK_RECORD_DIR = PROJECT_ROOT / "watermark_records"
BUNDLE_ROOT = Path(getattr(sys, "_MEIPASS", PROJECT_ROOT))
ASSET_DIR = BUNDLE_ROOT / "assets"
LOGO_MARK_PATH = ASSET_DIR / "sitas_logo_mark.png"

COLORS = {
    "app_bg": "#eef3f8",
    "surface": "#ffffff",
    "surface_soft": "#f8fbff",
    "line": "#dbe4f0",
    "line_strong": "#c4d2e3",
    "brand": "#071f4f",
    "brand_2": "#0b2f73",
    "accent": "#1d4ed8",
    "accent_hover": "#1e40af",
    "success": "#0f766e",
    "danger": "#dc2626",
    "text": "#172033",
    "muted": "#64748b",
    "status_bg": "#e7edf5",
}


def fifth_band_bounds(height: int) -> tuple[int, int]:
    return 0, height


def bytes_to_bits(payload: bytes) -> list[int]:
    bits: list[int] = []
    for value in payload:
        for shift in range(7, -1, -1):
            bits.append((value >> shift) & 1)
    return bits


def bits_to_bytes_msb(bits: list[int]) -> bytes:
    output = bytearray()
    for pos in range(0, len(bits) - 7, 8):
        value = 0
        for bit in bits[pos : pos + 8]:
            value = (value << 1) | bit
        output.append(value)
    return bytes(output)


def iter_fifth_band_lsb_bits(arr: np.ndarray, y_start: int, y_end: int, width: int):
    for y in range(y_start, y_end):
        for x in range(width):
            for channel in range(3):
                yield int(arr[y, x, channel] & 1)


def load_watermark_font(font_size: int) -> ImageFont.ImageFont:
    candidates = [
        "/System/Library/Fonts/PingFang.ttc",
        "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
        "/Library/Fonts/Arial Unicode.ttf",
        "/System/Library/Fonts/Supplemental/Arial.ttf",
    ]
    for candidate in candidates:
        try:
            return ImageFont.truetype(candidate, font_size)
        except OSError:
            continue
    return ImageFont.load_default()


def apply_subtle_visible_watermark(image: Image.Image, text: str, opacity: int = 52) -> Image.Image:
    if not text.strip():
        return image

    base = image.convert("RGBA")
    width, height = base.size
    overlay = Image.new("RGBA", base.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)

    font_size = max(16, min(width, height) // 24)
    font = load_watermark_font(font_size)
    bbox = draw.textbbox((0, 0), text, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]
    margin = max(12, min(width, height) // 35)
    x = max(margin, width - text_width - margin)
    y = max(margin, height - text_height - margin)

    alpha = max(15, min(120, int(opacity)))
    draw.text((x + 1, y + 1), text, font=font, fill=(0, 0, 0, max(10, alpha // 2)))
    draw.text((x, y), text, font=font, fill=(255, 255, 255, alpha))
    return Image.alpha_composite(base, overlay)


def build_watermark_record(watermark_text: str, visible_text: str | None) -> dict[str, str | bool]:
    watermark_id = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(8)}"
    return {
        "protocol": "SITAS5",
        "version": "2",
        "watermark_id": watermark_id,
        "watermark_secret": secrets.token_urlsafe(32),
        "watermark_text": watermark_text,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "random_rule": "A new cryptographic random watermark_secret is generated for every image.",
        "lsb_rule": "The saved watermark record is repeated across every RGB LSB in the whole image.",
        "visible_watermark": bool(visible_text),
        "visible_watermark_text": visible_text or "",
    }


def decode_watermark_record(payload_text: str) -> dict[str, str | bool] | None:
    try:
        decoded = json.loads(payload_text)
    except json.JSONDecodeError:
        return None
    if isinstance(decoded, dict) and decoded.get("protocol") == "SITAS5":
        return decoded
    return None


def encoded_record_bits(record: dict[str, str | bool]) -> list[int]:
    payload = json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    encoded = WATERMARK_MAGIC + len(payload).to_bytes(4, "big") + payload
    return bytes_to_bits(encoded)


def watermark_record_path(watermark_id: str, record_dir: Path = WATERMARK_RECORD_DIR) -> Path:
    safe_id = "".join(char if char.isalnum() or char in "-_" else "_" for char in watermark_id)
    return record_dir / f"{safe_id}.json"


def save_watermark_record(
    record: dict[str, str | bool],
    source_image_path: Path,
    output_image_path: Path,
    record_dir: Path = WATERMARK_RECORD_DIR,
) -> Path:
    watermark_id = str(record.get("watermark_id", "")).strip()
    if not watermark_id:
        raise ValueError("水印记录缺少 watermark_id，无法保存。")

    record_dir.mkdir(parents=True, exist_ok=True)
    package = {
        "record_type": "SITAS saved invisible watermark",
        "saved_at": datetime.now().isoformat(timespec="seconds"),
        "source_image_name": source_image_path.name,
        "watermarked_image_path": str(output_image_path.resolve()),
        "embedded_record": record,
    }
    path = watermark_record_path(watermark_id, record_dir)
    path.write_text(json.dumps(package, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def load_saved_watermark_record(watermark_id: str, record_dir: Path = WATERMARK_RECORD_DIR) -> tuple[dict[str, str | bool] | None, Path]:
    path = watermark_record_path(watermark_id, record_dir)
    if not path.exists():
        return None, path
    try:
        package = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None, path
    record = package.get("embedded_record")
    if isinstance(record, dict) and record.get("protocol") == "SITAS5":
        return record, path
    return None, path


def load_all_saved_watermark_records(record_dir: Path = WATERMARK_RECORD_DIR) -> list[tuple[dict[str, str | bool], Path]]:
    if not record_dir.exists():
        return []

    records: list[tuple[dict[str, str | bool], Path]] = []
    for path in sorted(record_dir.glob("*.json")):
        try:
            package = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        record = package.get("embedded_record")
        if isinstance(record, dict) and record.get("protocol") == "SITAS5":
            records.append((record, path))
    return records


def watermark_mismatch_map(arr: np.ndarray, record: dict[str, str | bool]) -> tuple[np.ndarray, np.ndarray, int]:
    expected_bits = encoded_record_bits(record)
    if not expected_bits:
        height, width = arr.shape[:2]
        empty = np.zeros((height, width, 3), dtype=bool)
        return empty, np.any(empty, axis=2), 0

    height, width = arr.shape[:2]
    actual = (arr[:, :, :3] & 1).reshape(-1)
    expected = np.resize(np.array(expected_bits, dtype=np.uint8), actual.size)
    channel_mismatches = (actual != expected).reshape(height, width, 3)
    pixel_mismatches = np.any(channel_mismatches, axis=2)
    return channel_mismatches, pixel_mismatches, int(channel_mismatches.sum())


def full_image_watermark_mismatch_count(arr: np.ndarray, record: dict[str, str | bool]) -> int:
    _channel_mismatches, _pixel_mismatches, mismatch_count = watermark_mismatch_map(arr, record)
    return mismatch_count


def find_best_saved_watermark_record(
    arr: np.ndarray,
    record_dir: Path = WATERMARK_RECORD_DIR,
) -> tuple[dict[str, str | bool] | None, Path | None, int | None]:
    best_record: dict[str, str | bool] | None = None
    best_path: Path | None = None
    best_mismatches: int | None = None

    for saved_record, saved_path in load_all_saved_watermark_records(record_dir):
        mismatch_count = full_image_watermark_mismatch_count(arr, saved_record)
        if best_mismatches is None or mismatch_count < best_mismatches:
            best_record = saved_record
            best_path = saved_path
            best_mismatches = mismatch_count

    return best_record, best_path, best_mismatches


def watermark_integrity_details(
    image_path: Path,
    record_dir: Path = WATERMARK_RECORD_DIR,
) -> dict[str, object]:
    with Image.open(image_path) as image:
        image.load()
        arr = np.array(image.convert("RGB"))

    payload_text = read_invisible_watermark_from_fifth_band(image_path)
    embedded_record = decode_watermark_record(payload_text) if payload_text is not None else None
    read_status = "readable" if embedded_record is not None else "unreadable"

    saved_record: dict[str, str | bool] | None = None
    saved_record_path: Path | None = None
    match_source = ""
    watermark_id = ""
    embedded_record_matches_saved = False

    if embedded_record is not None:
        watermark_id = str(embedded_record.get("watermark_id", "")).strip()
        if watermark_id:
            saved_record, saved_record_path = load_saved_watermark_record(watermark_id, record_dir)
            if saved_record is not None:
                match_source = "watermark_id"
                embedded_record_matches_saved = embedded_record == saved_record

    if saved_record is None:
        saved_record, saved_record_path, _best_mismatches = find_best_saved_watermark_record(arr, record_dir)
        match_source = "best_record_scan" if saved_record is not None else ""
        if saved_record is not None:
            watermark_id = str(saved_record.get("watermark_id", ""))

    if saved_record is None or saved_record_path is None:
        empty_mask = np.zeros(arr.shape[:2], dtype=bool)
        return {
            "has_watermark": payload_text is not None,
            "watermark_read_status": read_status,
            "system_record_found": False,
            "is_intact": False,
            "integrity_status": "not_found",
            "message": "没有在系统水印记录库里找到可匹配的原始水印记录，无法确认这张图片。",
            "pixel_mismatch_mask": empty_mask,
        }

    channel_mismatches, pixel_mismatches, mismatch_count = watermark_mismatch_map(arr, saved_record)
    total_channels = int(arr.shape[0] * arr.shape[1] * 3)
    mismatch_ratio = mismatch_count / total_channels if total_channels else 0.0
    is_intact = bool(mismatch_count == 0 and (embedded_record is None or embedded_record_matches_saved or match_source == "best_record_scan"))

    changed_positions = np.argwhere(pixel_mismatches)
    samples: list[dict[str, object]] = []
    for y, x in changed_positions[:300]:
        channel_flags = channel_mismatches[y, x].tolist()
        channels = [name for idx, name in enumerate(("R", "G", "B")) if channel_flags[idx]]
        samples.append({"x": int(x), "y": int(y), "mismatched_channels": channels})

    if is_intact:
        status = "complete"
        message = "图片水印完整，未发现篡改。"
    elif mismatch_ratio >= 0.35:
        status = "severely_damaged_or_wrong_image"
        message = "图片里的水印和系统保存记录差异很大，可能不是这张水印图，或水印已严重损坏。"
    else:
        status = "damaged_or_tampered"
        message = "图片里的水印不完整，疑似被篡改或处理过。"

    return {
        "has_watermark": payload_text is not None,
        "watermark_read_status": read_status,
        "system_record_found": True,
        "is_intact": is_intact,
        "integrity_status": status,
        "message": message,
        "watermark_id": watermark_id,
        "saved_record_path": str(saved_record_path.resolve()),
        "match_source": match_source,
        "embedded_record_matches_saved": embedded_record_matches_saved,
        "full_image_lsb_mismatches": mismatch_count,
        "mismatch_ratio": round(mismatch_ratio, 6),
        "damaged_pixels": int(pixel_mismatches.sum()),
        "damaged_R_bits": int(channel_mismatches[:, :, 0].sum()),
        "damaged_G_bits": int(channel_mismatches[:, :, 1].sum()),
        "damaged_B_bits": int(channel_mismatches[:, :, 2].sum()),
        "samples_first_300": samples,
        "watermark_text": str(saved_record.get("watermark_text", "")),
        "created_at": str(saved_record.get("created_at", "")),
        "visible_watermark": bool(saved_record.get("visible_watermark", False)),
        "visible_watermark_text": str(saved_record.get("visible_watermark_text", "")),
        "channel_mismatch_mask": channel_mismatches,
        "pixel_mismatch_mask": pixel_mismatches,
    }


def write_invisible_watermark_to_fifth_band(
    image_path: Path,
    watermark_text: str,
    output_path: Path,
    visible_text: str | None = None,
    visible_opacity: int = 52,
) -> dict[str, int | str]:
    with Image.open(image_path) as image:
        image.load()
        source_mode = image.mode
        working = image.convert("RGBA" if "A" in image.getbands() else "RGB")

    if visible_text:
        working = apply_subtle_visible_watermark(working, visible_text, visible_opacity)

    arr = np.array(working)
    record = build_watermark_record(watermark_text, visible_text)
    payload = json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    encoded = WATERMARK_MAGIC + len(payload).to_bytes(4, "big") + payload
    bits = bytes_to_bits(encoded)

    height, width = arr.shape[:2]
    y_start, y_end = fifth_band_bounds(height)
    watermark_height = y_end - y_start
    capacity_bits = width * watermark_height * 3
    if len(bits) > capacity_bits:
        capacity_bytes = max(0, capacity_bits // 8 - WATERMARK_HEADER_BYTES)
        raise ValueError(f"水印太长。整张图片最多可写入约 {capacity_bytes} 字节。")

    cursor = 0
    for y in range(y_start, y_end):
        for x in range(width):
            for channel in range(3):
                arr[y, x, channel] = (arr[y, x, channel] & 0xFE) | bits[cursor % len(bits)]
                cursor += 1

    output_path.parent.mkdir(parents=True, exist_ok=True)
    Image.fromarray(arr, mode=working.mode).save(output_path, format="PNG")
    record_path = save_watermark_record(record, image_path, output_path)

    return {
        "output_path": str(output_path.resolve()),
        "watermark_record_path": str(record_path.resolve()),
        "source_mode": source_mode,
        "saved_format": "PNG",
        "width": width,
        "height": height,
        "watermark_id": str(record.get("watermark_id", "")),
        "watermark_area": "whole_image",
        "watermark_y_start": y_start,
        "watermark_y_end": y_end - 1,
        "watermark_height": watermark_height,
        "capacity_bits": capacity_bits,
        "record_bits": len(bits),
        "written_bits": capacity_bits,
        "payload_bytes": len(payload),
        "random_watermark_saved": "yes",
        "visible_watermark": "yes" if visible_text else "no",
    }


def read_invisible_watermark_from_fifth_band(image_path: Path) -> str | None:
    with Image.open(image_path) as image:
        image.load()
        arr = np.array(image.convert("RGB"))

    height, width = arr.shape[:2]
    y_start, y_end = fifth_band_bounds(height)
    data_iter = iter_fifth_band_lsb_bits(arr, y_start, y_end, width)

    header_bits: list[int] = []
    for _ in range(WATERMARK_HEADER_BYTES * 8):
        try:
            header_bits.append(next(data_iter))
        except StopIteration:
            return None

    header = bits_to_bytes_msb(header_bits)
    if not header.startswith(WATERMARK_MAGIC):
        return None

    payload_len = int.from_bytes(header[len(WATERMARK_MAGIC) : WATERMARK_HEADER_BYTES], "big")
    payload_bits: list[int] = []
    for _ in range(payload_len * 8):
        try:
            payload_bits.append(next(data_iter))
        except StopIteration:
            return None

    try:
        return bits_to_bytes_msb(payload_bits).decode("utf-8")
    except UnicodeDecodeError:
        return None


def verify_image_integrity(image_path: Path, record_dir: Path = WATERMARK_RECORD_DIR) -> dict[str, object]:
    details = watermark_integrity_details(image_path, record_dir)
    return {
        key: value
        for key, value in details.items()
        if key not in {"pixel_mismatch_mask", "channel_mismatch_mask"}
    }  # type: ignore[return-value]


def watermark_damage_overlay_image(image_rgb: np.ndarray, damaged_pixels: np.ndarray, opacity: int = 130) -> Image.Image:
    base = Image.fromarray(image_rgb.astype(np.uint8), mode="RGB").convert("RGBA")
    overlay = Image.new("RGBA", base.size, (0, 0, 0, 0))
    overlay_arr = np.array(overlay)
    overlay_arr[damaged_pixels] = [255, 0, 0, max(0, min(255, int(opacity)))]
    return Image.alpha_composite(base, Image.fromarray(overlay_arr, mode="RGBA"))


def watermark_write_change_overlay_image(image_rgb: np.ndarray, changed_pixels: np.ndarray, opacity: int = 145) -> Image.Image:
    base = Image.fromarray(image_rgb.astype(np.uint8), mode="RGB").convert("RGBA")
    overlay = Image.new("RGBA", base.size, (0, 0, 0, 0))
    overlay_arr = np.array(overlay)
    overlay_arr[changed_pixels] = [29, 78, 216, max(0, min(255, int(opacity)))]
    return Image.alpha_composite(base, Image.fromarray(overlay_arr, mode="RGBA"))


def make_write_change_heatmap(pixel_change_mask: np.ndarray) -> Image.Image:
    height, width = pixel_change_mask.shape[:2]
    heatmap = np.zeros((height, width, 3), dtype=np.uint8)
    heatmap[pixel_change_mask] = [56, 189, 248]
    return Image.fromarray(heatmap, mode="RGB")


class ImageInfoApp(tk.Tk):
    def __init__(self, initial_image: Path | None = None) -> None:
        super().__init__()
        self.title("SITAS 图像安全分析工作台")
        self.geometry("1320x820")
        self.minsize(1080, 680)
        self.configure(background=COLORS["app_bg"])

        self.current_image: Path | None = None
        self.current_report: dict | None = None
        self.preview_photo: ImageTk.PhotoImage | None = None
        self.bitplane_photo: ImageTk.PhotoImage | None = None
        self.rgb_array: np.ndarray | None = None
        self.rgb_overview_image: Image.Image | None = None
        self.rgb_overview_photo: ImageTk.PhotoImage | None = None
        self.rgb_scale = 1.0
        self.rgb_offset_x = 0
        self.rgb_offset_y = 0
        self.rgb_current_pixel: tuple[int, int] | None = None
        self.watermark_preview_photo: ImageTk.PhotoImage | None = None
        self.watermark_integrity_result: dict[str, object] | None = None
        self.watermark_integrity_overlay_photo: ImageTk.PhotoImage | None = None
        self.watermark_integrity_scale = 1.0
        self.watermark_integrity_offset_x = 0
        self.watermark_integrity_offset_y = 0
        self.fragile_result: dict[str, object] | None = None
        self.fragile_embedding_change_result: dict[str, object] | None = None
        self.fragile_embedding_change_base_rgb: np.ndarray | None = None
        self.fragile_overlay_photo: ImageTk.PhotoImage | None = None
        self.fragile_scale = 1.0
        self.fragile_offset_x = 0
        self.fragile_offset_y = 0
        self.fragile_view_mode_var: tk.StringVar | None = None
        self.fragile_overlay_opacity_var: tk.IntVar | None = None
        self.fragile_status_var: tk.StringVar | None = None
        self.logo_photo: ImageTk.PhotoImage | None = None
        self.window_icon_photo: ImageTk.PhotoImage | None = None
        self.camera_capture: Any | None = None
        self.camera_running = False
        self.camera_after_id: str | None = None
        self.camera_photo: ImageTk.PhotoImage | None = None
        self.camera_frame_rgb: np.ndarray | None = None
        self.camera_frame_size_var: tk.StringVar | None = None
        self.camera_status_var: tk.StringVar | None = None
        self.camera_source_var: tk.StringVar | None = None
        self.camera_url_var: tk.StringVar | None = None
        self.camera_index_var: tk.IntVar | None = None
        self.camera_fps_var: tk.IntVar | None = None
        self.camera_network_interval_var: tk.IntVar | None = None
        self.camera_network_stop_event: threading.Event | None = None
        self.camera_network_thread: threading.Thread | None = None
        self.camera_stream_token = 0
        self.camera_event_queue: queue.Queue[tuple[int, str, Any]] = queue.Queue(maxsize=4)

        self._configure_style()
        self._install_window_icon()
        self._build_layout()
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.after(100, self._poll_camera_events)

        if initial_image:
            self.after(100, lambda: self.load_image(initial_image))

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        self.option_add("*Font", ("Arial", 12))
        self.option_add("*tearOff", False)
        style.configure(".", background=COLORS["app_bg"], foreground=COLORS["text"])
        style.configure("TLabel", background=COLORS["surface"], foreground=COLORS["text"])
        style.configure("TCheckbutton", background=COLORS["surface"], foreground=COLORS["text"])
        style.configure("App.TFrame", background=COLORS["app_bg"])
        style.configure("Surface.TFrame", background=COLORS["surface"])
        style.configure("Panel.TFrame", background=COLORS["surface"], relief=tk.FLAT)
        style.configure("ControlBar.TFrame", background=COLORS["surface"])
        style.configure("Header.TFrame", background=COLORS["brand"])
        style.configure("Status.TLabel", background=COLORS["status_bg"], foreground=COLORS["muted"], padding=(14, 8))
        style.configure("Hint.TLabel", background=COLORS["surface"], foreground=COLORS["muted"], font=("Arial", 11))
        style.configure("Subtle.TLabel", background=COLORS["app_bg"], foreground=COLORS["muted"], font=("Arial", 11))
        style.configure("Title.TLabel", background=COLORS["surface"], foreground=COLORS["text"], font=("Arial", 14, "bold"))
        style.configure(
            "Card.TLabelframe",
            background=COLORS["surface"],
            bordercolor=COLORS["line"],
            lightcolor=COLORS["line"],
            darkcolor=COLORS["line"],
            relief=tk.SOLID,
        )
        style.configure(
            "Card.TLabelframe.Label",
            background=COLORS["surface"],
            foreground=COLORS["brand"],
            font=("Arial", 12, "bold"),
        )
        style.configure("TButton", padding=(12, 7), font=("Arial", 11), background="#edf3fb", foreground=COLORS["brand"])
        style.map(
            "TButton",
            background=[("active", "#e2ebf7"), ("pressed", "#d6e4f5")],
            foreground=[("disabled", "#94a3b8")],
        )
        style.configure("Primary.TButton", padding=(14, 8), background=COLORS["accent"], foreground="#ffffff", font=("Arial", 11, "bold"))
        style.map("Primary.TButton", background=[("active", COLORS["accent_hover"]), ("pressed", COLORS["brand_2"])])
        style.configure("TEntry", fieldbackground="#ffffff", bordercolor=COLORS["line_strong"], lightcolor=COLORS["line_strong"])
        style.configure("TCombobox", fieldbackground="#ffffff", bordercolor=COLORS["line_strong"])
        style.configure("TSpinbox", fieldbackground="#ffffff", bordercolor=COLORS["line_strong"])
        style.configure(
            "Treeview",
            background="#fbfdff",
            fieldbackground="#fbfdff",
            foreground=COLORS["text"],
            rowheight=28,
            bordercolor=COLORS["line"],
            lightcolor=COLORS["line"],
            darkcolor=COLORS["line"],
            font=("Arial", 11),
        )
        style.configure("Treeview.Heading", background="#eaf1f9", foreground=COLORS["brand"], font=("Arial", 11, "bold"))
        style.map("Treeview", background=[("selected", "#dbeafe")], foreground=[("selected", COLORS["brand"])])
        style.configure(
            "TNotebook",
            background=COLORS["surface"],
            borderwidth=0,
            tabmargins=(8, 6, 8, 0),
        )
        style.configure(
            "TNotebook.Tab",
            background="#eaf1f9",
            foreground=COLORS["muted"],
            padding=(14, 8),
            font=("Arial", 11),
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", COLORS["surface"]), ("active", "#f5f8fc")],
            foreground=[("selected", COLORS["brand"]), ("active", COLORS["brand_2"])],
        )
        style.configure("Horizontal.TPanedwindow", background=COLORS["app_bg"])

    def _build_layout(self) -> None:
        self._build_header()

        workspace = ttk.Frame(self, style="App.TFrame", padding=(16, 14, 16, 12))
        workspace.pack(fill=tk.BOTH, expand=True)

        main = ttk.PanedWindow(workspace, orient=tk.HORIZONTAL, style="Horizontal.TPanedwindow")
        main.pack(fill=tk.BOTH, expand=True)

        left = ttk.Frame(main, style="Surface.TFrame", padding=10)
        right = ttk.Frame(main, style="Surface.TFrame", padding=10)
        main.add(left, weight=2)
        main.add(right, weight=3)

        self.preview_frame = ttk.LabelFrame(left, text="图片预览", padding=12, style="Card.TLabelframe")
        self.preview_frame.pack(fill=tk.BOTH, expand=True)
        self.preview_label = ttk.Label(self.preview_frame, text="点击“选择图片”开始读取", anchor=tk.CENTER, style="Hint.TLabel")
        self.preview_label.pack(fill=tk.BOTH, expand=True)

        self.bitplane_frame = ttk.LabelFrame(left, text="LSB 最低位可视化", padding=12, style="Card.TLabelframe")
        self.bitplane_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        self.bitplane_label = ttk.Label(self.bitplane_frame, text="读取图片后显示像素最低位黑白图", anchor=tk.CENTER, style="Hint.TLabel")
        self.bitplane_label.pack(fill=tk.BOTH, expand=True)

        self.notebook = ttk.Notebook(right)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self._add_camera_tab()
        self.basic_tree = self._add_tree_tab("基础信息")
        self._add_rgb_array_tab()
        self._add_watermark_tab()
        self._add_watermark_integrity_tab()
        self._add_fragile_watermark_tab()
        self.channel_tree = self._add_tree_tab("通道统计")
        self.metadata_text = self._add_text_tab("内置元数据")
        self.exif_text = self._add_text_tab("EXIF")
        self.lsb_tree = self._add_tree_tab("LSB 统计")
        self.lsb_probe_text = self._add_text_tab("LSB 探测")

        self.status_label = ttk.Label(self, text="准备就绪", style="Status.TLabel", anchor=tk.W)
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X)

    def _build_header(self) -> None:
        header = tk.Frame(self, bg=COLORS["brand"], height=92)
        header.pack(side=tk.TOP, fill=tk.X)
        header.pack_propagate(False)

        left = tk.Frame(header, bg=COLORS["brand"])
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(18, 10), pady=12)

        self.logo_photo = self._load_logo_photo(LOGO_MARK_PATH, (58, 58))
        if self.logo_photo is not None:
            tk.Label(left, image=self.logo_photo, bg=COLORS["brand"], bd=0).pack(side=tk.LEFT, padx=(0, 12))

        title_box = tk.Frame(left, bg=COLORS["brand"])
        title_box.pack(side=tk.LEFT, fill=tk.Y)
        tk.Label(
            title_box,
            text="SITAS 图像安全分析工作台",
            bg=COLORS["brand"],
            fg="#ffffff",
            font=("Arial", 19, "bold"),
            anchor=tk.W,
        ).pack(anchor=tk.W)
        tk.Label(
            title_box,
            text="图像信息读取 · RGB 可视化 · 隐形水印 · LSB 脆弱水印验证",
            bg=COLORS["brand"],
            fg="#b9c8e6",
            font=("Arial", 11),
            anchor=tk.W,
        ).pack(anchor=tk.W, pady=(5, 0))

        actions = tk.Frame(header, bg=COLORS["brand"])
        actions.pack(side=tk.RIGHT, fill=tk.Y, padx=18, pady=20)
        self._make_header_button(actions, "选择图片", self.open_image, primary=True).pack(side=tk.LEFT, padx=(0, 8))
        self._make_header_button(actions, "生成报告", self.export_report).pack(side=tk.LEFT, padx=(0, 8))
        self._make_header_button(actions, "报告目录", self.open_reports_folder).pack(side=tk.LEFT)

        self.path_label = tk.Label(
            header,
            text="还没有选择图片",
            bg=COLORS["brand"],
            fg="#d7e3f7",
            font=("Arial", 11),
            anchor=tk.E,
        )
        self.path_label.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(12, 6))

    def _make_header_button(self, parent: tk.Widget, text: str, command, primary: bool = False) -> tk.Button:
        bg = "#ffffff" if primary else COLORS["brand_2"]
        fg = COLORS["brand"] if primary else "#eaf1ff"
        active_bg = "#edf3ff" if primary else "#123f8f"
        return tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg,
            fg=fg,
            activebackground=active_bg,
            activeforeground=fg,
            relief=tk.FLAT,
            bd=0,
            padx=16,
            pady=8,
            cursor="hand2",
            font=("Arial", 11, "bold"),
            highlightthickness=0,
        )

    def _install_window_icon(self) -> None:
        self.window_icon_photo = self._load_logo_photo(LOGO_MARK_PATH, (256, 256))
        if self.window_icon_photo is not None:
            self.iconphoto(True, self.window_icon_photo)

    def _load_logo_photo(self, path: Path, size: tuple[int, int]) -> ImageTk.PhotoImage | None:
        if not path.exists():
            return None
        try:
            image = Image.open(path).convert("RGBA")
            image.thumbnail(size, Image.Resampling.LANCZOS)
            return ImageTk.PhotoImage(image)
        except OSError:
            return None

    def _style_text_widget(self, text: tk.Text) -> None:
        text.configure(
            background="#fbfdff",
            foreground=COLORS["text"],
            insertbackground=COLORS["brand"],
            selectbackground="#dbeafe",
            selectforeground=COLORS["brand"],
            relief=tk.FLAT,
            borderwidth=0,
            highlightthickness=1,
            highlightbackground=COLORS["line"],
            highlightcolor=COLORS["accent"],
        )

    def _add_tree_tab(self, title: str) -> ttk.Treeview:
        frame = ttk.Frame(self.notebook, padding=10, style="Surface.TFrame")
        self.notebook.add(frame, text=title)
        tree = ttk.Treeview(frame, columns=("key", "value"), show="headings")
        tree.heading("key", text="项目")
        tree.heading("value", text="内容")
        tree.column("key", width=220, anchor=tk.W, stretch=False)
        tree.column("value", width=520, anchor=tk.W)
        tree.tag_configure("odd", background="#ffffff")
        tree.tag_configure("even", background="#f5f8fc")
        tree.tag_configure("parent", background="#eaf1f9", foreground=COLORS["brand"])
        yscroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=yscroll.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        yscroll.pack(side=tk.RIGHT, fill=tk.Y)
        return tree

    def _add_text_tab(self, title: str) -> tk.Text:
        frame = ttk.Frame(self.notebook, padding=10, style="Surface.TFrame")
        self.notebook.add(frame, text=title)
        text = tk.Text(frame, wrap=tk.WORD, font=("Menlo", 12), padx=10, pady=10)
        self._style_text_widget(text)
        text.configure(state=tk.DISABLED)
        yscroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text.yview)
        text.configure(yscrollcommand=yscroll.set)
        text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        yscroll.pack(side=tk.RIGHT, fill=tk.Y)
        return text

    def _add_camera_tab(self) -> None:
        frame = ttk.Frame(self.notebook, padding=10, style="Surface.TFrame")
        self.notebook.add(frame, text="摄像头采集")

        source_bar = ttk.Frame(frame, style="ControlBar.TFrame")
        source_bar.pack(side=tk.TOP, fill=tk.X, pady=(0, 8))

        ttk.Label(source_bar, text="采集来源").pack(side=tk.LEFT)
        self.camera_source_var = tk.StringVar(value="ESP32 Wi-Fi")
        source = ttk.Combobox(
            source_bar,
            textvariable=self.camera_source_var,
            values=("ESP32 Wi-Fi", "本机 USB"),
            state="readonly",
            width=13,
        )
        source.pack(side=tk.LEFT, padx=(6, 14))
        source.bind("<<ComboboxSelected>>", lambda _event: self._on_camera_source_changed())

        ttk.Label(source_bar, text="ESP32 地址").pack(side=tk.LEFT)
        self.camera_url_var = tk.StringVar(value="http://192.168.4.1")
        ttk.Entry(source_bar, textvariable=self.camera_url_var, width=24).pack(side=tk.LEFT, padx=(6, 14))

        ttk.Label(source_bar, text="本机设备编号").pack(side=tk.LEFT)
        self.camera_index_var = tk.IntVar(value=0)
        ttk.Spinbox(source_bar, from_=0, to=8, width=5, textvariable=self.camera_index_var).pack(side=tk.LEFT, padx=(6, 0))

        controls = ttk.Frame(frame, style="ControlBar.TFrame")
        controls.pack(side=tk.TOP, fill=tk.X, pady=(0, 10))

        ttk.Label(controls, text="本机刷新 ms").pack(side=tk.LEFT)
        self.camera_fps_var = tk.IntVar(value=33)
        ttk.Spinbox(controls, from_=15, to=200, width=6, textvariable=self.camera_fps_var).pack(side=tk.LEFT, padx=(6, 12))
        ttk.Label(controls, text="网络刷新 ms").pack(side=tk.LEFT)
        self.camera_network_interval_var = tk.IntVar(value=250)
        ttk.Spinbox(controls, from_=100, to=2000, increment=50, width=6, textvariable=self.camera_network_interval_var).pack(side=tk.LEFT, padx=(6, 12))
        ttk.Button(controls, text="连接热点", command=self.connect_esp32_wifi).pack(side=tk.LEFT)
        ttk.Button(controls, text="检测 ESP32", command=self.test_esp32_camera).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(controls, text="扫描本机", command=self.scan_camera_devices).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(controls, text="开始预览", command=self.start_camera_stream, style="Primary.TButton").pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(controls, text="停止", command=self.stop_camera_stream).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(controls, text="拍摄并读取", command=self.capture_camera_frame).pack(side=tk.LEFT, padx=(8, 0))

        self.camera_status_var = tk.StringVar(
            value="请先让电脑连接 Wi-Fi：ESP32-Camera（密码 12345678），然后点击“检测 ESP32”。"
        )
        ttk.Label(frame, textvariable=self.camera_status_var, style="Hint.TLabel").pack(side=tk.TOP, fill=tk.X, pady=(0, 10))

        content = ttk.PanedWindow(frame, orient=tk.HORIZONTAL)
        content.pack(fill=tk.BOTH, expand=True)

        preview_frame = ttk.LabelFrame(content, text="实时视频流", padding=10, style="Card.TLabelframe")
        info_frame = ttk.LabelFrame(content, text="采集说明", padding=10, style="Card.TLabelframe")
        content.add(preview_frame, weight=3)
        content.add(info_frame, weight=2)

        self.camera_canvas = tk.Canvas(preview_frame, background="#07111f", highlightthickness=1, highlightbackground=COLORS["line"])
        self.camera_canvas.pack(fill=tk.BOTH, expand=True)
        self.camera_canvas.bind("<Configure>", lambda _event: self._render_camera_frame())
        self.camera_canvas.create_text(
            24,
            24,
            anchor=tk.NW,
            text="等待摄像头视频流",
            fill="#d7e3f7",
            font=("Arial", 13, "bold"),
        )

        info = tk.Text(info_frame, wrap=tk.WORD, font=("Arial", 12), padx=12, pady=12, height=10)
        self._style_text_widget(info)
        info.insert(
            "1.0",
            "使用流程：\n"
            "ESP32 Wi-Fi 模式：\n"
            "1. 给 ESP32 和 USB 摄像头供电。\n"
            "2. 点击“连接热点”，让电脑连接 ESP32-Camera。\n"
            "3. 点击“检测 ESP32”，成功后点击“开始预览”。\n"
            "4. 对准显微镜画面后点击“拍摄并读取”。\n\n"
            "本机 USB 模式：选择“本机 USB”，扫描设备后开始预览。\n\n"
            "抓拍会保存为 PNG，并自动进入现有图片信息读取、RGB 数组可视化、水印写入和篡改验证流程。",
        )
        info.configure(state=tk.DISABLED)
        info.pack(fill=tk.BOTH, expand=True)

        self.camera_frame_size_var = tk.StringVar(value="当前帧：-")
        ttk.Label(info_frame, textvariable=self.camera_frame_size_var, style="Hint.TLabel").pack(fill=tk.X, pady=(10, 0))

    def _add_rgb_array_tab(self) -> None:
        frame = ttk.Frame(self.notebook, padding=10, style="Surface.TFrame")
        self.notebook.add(frame, text="RGB 数组")

        controls = ttk.Frame(frame, style="ControlBar.TFrame")
        controls.pack(side=tk.TOP, fill=tk.X, pady=(0, 8))
        ttk.Label(controls, text="局部半径").pack(side=tk.LEFT)
        self.rgb_radius_var = tk.IntVar(value=4)
        radius = ttk.Spinbox(controls, from_=1, to=12, width=5, textvariable=self.rgb_radius_var, command=self._redraw_rgb_magnifier)
        radius.pack(side=tk.LEFT, padx=(6, 14))
        radius.bind("<Return>", lambda _event: self._redraw_rgb_magnifier())
        ttk.Label(controls, text="格子大小").pack(side=tk.LEFT)
        self.rgb_cell_size_var = tk.IntVar(value=58)
        cell_size = ttk.Spinbox(controls, from_=34, to=92, width=5, textvariable=self.rgb_cell_size_var, command=self._redraw_rgb_magnifier)
        cell_size.pack(side=tk.LEFT, padx=(6, 14))
        cell_size.bind("<Return>", lambda _event: self._redraw_rgb_magnifier())
        self.rgb_pixel_label = ttk.Label(controls, text="中心像素：-")
        self.rgb_pixel_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        split = ttk.PanedWindow(frame, orient=tk.HORIZONTAL)
        split.pack(fill=tk.BOTH, expand=True)
        overview_frame = ttk.LabelFrame(split, text="图片形状总览", padding=10, style="Card.TLabelframe")
        magnifier_frame = ttk.LabelFrame(split, text="局部 RGB 数组", padding=10, style="Card.TLabelframe")
        split.add(overview_frame, weight=2)
        split.add(magnifier_frame, weight=3)

        self.rgb_canvas = tk.Canvas(overview_frame, background=COLORS["surface_soft"], highlightthickness=1, highlightbackground=COLORS["line"])
        self.rgb_canvas.pack(fill=tk.BOTH, expand=True)
        self.rgb_canvas.bind("<Configure>", lambda _event: self._render_rgb_overview())
        self.rgb_canvas.bind("<Motion>", self._on_rgb_canvas_motion)
        self.rgb_canvas.bind("<Leave>", lambda _event: self.rgb_canvas.delete("rgb_marker"))

        container = ttk.Frame(magnifier_frame)
        container.pack(fill=tk.BOTH, expand=True)
        self.rgb_magnifier_canvas = tk.Canvas(container, background="#ffffff", highlightthickness=1, highlightbackground=COLORS["line"])
        xscroll = ttk.Scrollbar(container, orient=tk.HORIZONTAL, command=self.rgb_magnifier_canvas.xview)
        yscroll = ttk.Scrollbar(container, orient=tk.VERTICAL, command=self.rgb_magnifier_canvas.yview)
        self.rgb_magnifier_canvas.configure(xscrollcommand=xscroll.set, yscrollcommand=yscroll.set)
        self.rgb_magnifier_canvas.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        container.columnconfigure(0, weight=1)
        container.rowconfigure(0, weight=1)

    def _add_watermark_tab(self) -> None:
        frame = ttk.Frame(self.notebook, padding=10, style="Surface.TFrame")
        self.notebook.add(frame, text="水印/篡改验证")

        top = ttk.Frame(frame, style="ControlBar.TFrame")
        top.pack(side=tk.TOP, fill=tk.X, pady=(0, 8))
        ttk.Label(top, text="水印备注").pack(side=tk.LEFT)
        self.watermark_text_var = tk.StringVar(value=f"SITAS watermark {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        ttk.Entry(top, textvariable=self.watermark_text_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(8, 8))
        ttk.Button(top, text="写入水印", command=self.write_watermark).pack(side=tk.LEFT)
        ttk.Button(top, text="验证是否篡改", command=self.verify_current_watermark).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(top, text="打开水印记录库", command=self.open_watermark_records_folder).pack(side=tk.LEFT, padx=(8, 0))

        visible_bar = ttk.Frame(frame, style="ControlBar.TFrame")
        visible_bar.pack(side=tk.TOP, fill=tk.X, pady=(0, 8))
        self.visible_watermark_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(visible_bar, text="同时添加浅色可见水印", variable=self.visible_watermark_var).pack(side=tk.LEFT)
        ttk.Label(visible_bar, text="文字").pack(side=tk.LEFT, padx=(12, 0))
        self.visible_watermark_text_var = tk.StringVar(value="SITAS")
        ttk.Entry(visible_bar, textvariable=self.visible_watermark_text_var, width=22).pack(side=tk.LEFT, padx=(6, 12))
        ttk.Label(visible_bar, text="透明度").pack(side=tk.LEFT)
        self.visible_opacity_var = tk.IntVar(value=52)
        ttk.Spinbox(visible_bar, from_=15, to=120, width=5, textvariable=self.visible_opacity_var).pack(side=tk.LEFT, padx=(6, 0))

        content = ttk.PanedWindow(frame, orient=tk.HORIZONTAL)
        content.pack(fill=tk.BOTH, expand=True)
        preview_frame = ttk.LabelFrame(content, text="整张图片水印区域", padding=10, style="Card.TLabelframe")
        detail_frame = ttk.LabelFrame(content, text="写入/验证结果", padding=10, style="Card.TLabelframe")
        content.add(preview_frame, weight=2)
        content.add(detail_frame, weight=3)

        self.watermark_canvas = tk.Canvas(preview_frame, background=COLORS["surface_soft"], highlightthickness=1, highlightbackground=COLORS["line"])
        self.watermark_canvas.pack(fill=tk.BOTH, expand=True)
        self.watermark_canvas.bind("<Configure>", lambda _event: self._render_watermark_preview())

        self.watermark_result_text = tk.Text(detail_frame, wrap=tk.WORD, font=("Menlo", 12), padx=10, pady=10)
        self._style_text_widget(self.watermark_result_text)
        self.watermark_result_text.configure(state=tk.DISABLED)
        yscroll = ttk.Scrollbar(detail_frame, orient=tk.VERTICAL, command=self.watermark_result_text.yview)
        self.watermark_result_text.configure(yscrollcommand=yscroll.set)
        self.watermark_result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        yscroll.pack(side=tk.RIGHT, fill=tk.Y)

    def _add_watermark_integrity_tab(self) -> None:
        frame = ttk.Frame(self.notebook, padding=10, style="Surface.TFrame")
        self.notebook.add(frame, text="水印完整性定位")

        top = ttk.Frame(frame, style="ControlBar.TFrame")
        top.pack(side=tk.TOP, fill=tk.X, pady=(0, 8))
        ttk.Button(top, text="检查水印完整性", command=self.check_current_watermark_integrity).pack(side=tk.LEFT)
        self.watermark_integrity_label = ttk.Label(top, text="只对比图片水印和系统水印记录库", style="Hint.TLabel")
        self.watermark_integrity_label.pack(side=tk.LEFT, padx=(12, 0), fill=tk.X, expand=True)

        content = ttk.PanedWindow(frame, orient=tk.HORIZONTAL)
        content.pack(fill=tk.BOTH, expand=True)
        canvas_frame = ttk.LabelFrame(content, text="红色区域 = 隐形水印损坏的位置", padding=10, style="Card.TLabelframe")
        detail_frame = ttk.LabelFrame(content, text="水印完整性详情", padding=10, style="Card.TLabelframe")
        content.add(canvas_frame, weight=2)
        content.add(detail_frame, weight=3)

        self.watermark_integrity_canvas = tk.Canvas(canvas_frame, background=COLORS["surface_soft"], highlightthickness=1, highlightbackground=COLORS["line"])
        self.watermark_integrity_canvas.pack(fill=tk.BOTH, expand=True)
        self.watermark_integrity_canvas.bind("<Configure>", lambda _event: self._render_watermark_integrity_overlay())
        self.watermark_integrity_canvas.bind("<Motion>", self._on_watermark_integrity_canvas_motion)

        self.watermark_integrity_detail_text = tk.Text(detail_frame, wrap=tk.WORD, font=("Menlo", 12), padx=10, pady=10)
        self._style_text_widget(self.watermark_integrity_detail_text)
        self.watermark_integrity_detail_text.configure(state=tk.DISABLED)
        yscroll = ttk.Scrollbar(detail_frame, orient=tk.VERTICAL, command=self.watermark_integrity_detail_text.yview)
        self.watermark_integrity_detail_text.configure(yscrollcommand=yscroll.set)
        self.watermark_integrity_detail_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        yscroll.pack(side=tk.RIGHT, fill=tk.Y)

    def _add_fragile_watermark_tab(self) -> None:
        frame = ttk.Frame(self.notebook, padding=10, style="Surface.TFrame")
        self.notebook.add(frame, text="LSB 脆弱水印")

        top = ttk.Frame(frame, style="ControlBar.TFrame")
        top.pack(side=tk.TOP, fill=tk.X, pady=(0, 8))
        ttk.Label(top, text="密钥").pack(side=tk.LEFT)
        self.fragile_key_var = tk.StringVar(value="SITAS-secret-key")
        ttk.Entry(top, textvariable=self.fragile_key_var, show="*", width=28).pack(side=tk.LEFT, padx=(8, 8))
        ttk.Button(top, text="预览写入改动", command=self.preview_fragile_embedding_changes).pack(side=tk.LEFT)
        ttk.Button(top, text="写入脆弱水印", command=self.write_fragile_watermark).pack(side=tk.LEFT)
        ttk.Button(top, text="验证脆弱水印", command=self.verify_fragile_watermark).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(top, text="导出可视化", command=self.export_fragile_visuals).pack(side=tk.LEFT, padx=(8, 0))

        visual_bar = ttk.Frame(frame, style="ControlBar.TFrame")
        visual_bar.pack(side=tk.TOP, fill=tk.X, pady=(0, 8))
        ttk.Label(visual_bar, text="显示").pack(side=tk.LEFT)
        self.fragile_view_mode_var = tk.StringVar(value="叠加图")
        view_combo = ttk.Combobox(
            visual_bar,
            textvariable=self.fragile_view_mode_var,
            values=("叠加图", "热力图", "原图", "写入改动图", "写入改动热力图"),
            width=14,
            state="readonly",
        )
        view_combo.pack(side=tk.LEFT, padx=(6, 14))
        view_combo.bind("<<ComboboxSelected>>", lambda _event: self._render_fragile_overlay())
        ttk.Label(visual_bar, text="红色透明度").pack(side=tk.LEFT)
        self.fragile_overlay_opacity_var = tk.IntVar(value=130)
        opacity = ttk.Spinbox(
            visual_bar,
            from_=40,
            to=220,
            width=5,
            textvariable=self.fragile_overlay_opacity_var,
            command=self._render_fragile_overlay,
        )
        opacity.pack(side=tk.LEFT, padx=(6, 14))
        opacity.bind("<Return>", lambda _event: self._render_fragile_overlay())
        self.fragile_status_var = tk.StringVar(value="尚未验证")
        ttk.Label(visual_bar, textvariable=self.fragile_status_var, style="Hint.TLabel").pack(side=tk.LEFT, fill=tk.X, expand=True)

        content = ttk.PanedWindow(frame, orient=tk.HORIZONTAL)
        content.pack(fill=tk.BOTH, expand=True)
        canvas_frame = ttk.LabelFrame(content, text="红色区域 = 脆弱水印校验失败的位置", padding=10, style="Card.TLabelframe")
        detail_frame = ttk.LabelFrame(content, text="脆弱水印算法结果", padding=10, style="Card.TLabelframe")
        content.add(canvas_frame, weight=2)
        content.add(detail_frame, weight=3)

        self.fragile_canvas = tk.Canvas(canvas_frame, background=COLORS["surface_soft"], highlightthickness=1, highlightbackground=COLORS["line"])
        self.fragile_canvas.pack(fill=tk.BOTH, expand=True)
        self.fragile_canvas.bind("<Configure>", lambda _event: self._render_fragile_overlay())
        self.fragile_canvas.bind("<Motion>", self._on_fragile_canvas_motion)

        self.fragile_detail_text = tk.Text(detail_frame, wrap=tk.WORD, font=("Menlo", 12), padx=10, pady=10)
        self._style_text_widget(self.fragile_detail_text)
        self.fragile_detail_text.configure(state=tk.DISABLED)
        yscroll = ttk.Scrollbar(detail_frame, orient=tk.VERTICAL, command=self.fragile_detail_text.yview)
        self.fragile_detail_text.configure(yscrollcommand=yscroll.set)
        self.fragile_detail_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        yscroll.pack(side=tk.RIGHT, fill=tk.Y)

    def open_image(self) -> None:
        filename = filedialog.askopenfilename(title="选择要读取的图片", filetypes=IMAGE_TYPES)
        if filename:
            self.load_image(Path(filename))

    def scan_camera_devices(self) -> None:
        if cv2 is None:
            messagebox.showerror("缺少依赖", "当前环境没有安装 opencv-python，无法读取 USB 摄像头。")
            self._set_camera_status("缺少 opencv-python，无法扫描摄像头。")
            return
        found: list[str] = []
        for index in range(9):
            capture = self._open_video_capture(index)
            if capture is None:
                continue
            ok, frame = capture.read()
            if ok and frame is not None:
                height, width = frame.shape[:2]
                found.append(f"{index}: {width}x{height}")
            capture.release()
        if found:
            self._set_camera_status("可用摄像头：" + "；".join(found))
            first_index = int(found[0].split(":", 1)[0])
            if self.camera_index_var is not None:
                self.camera_index_var.set(first_index)
        else:
            self._set_camera_status("没有扫描到可用摄像头。请确认 USB 摄像头已连接，并允许 Python/终端访问摄像头。")

    def _on_camera_source_changed(self) -> None:
        self.stop_camera_stream()
        if self.camera_source_var is not None and self.camera_source_var.get() == "本机 USB":
            self._set_camera_status("本机 USB 模式：点击“扫描本机”，选择设备编号后开始预览。")
        else:
            self._set_camera_status("ESP32 Wi-Fi 模式：连接 ESP32-Camera 热点后，点击“检测 ESP32”。")

    def _camera_base_url(self) -> str:
        value = self.camera_url_var.get().strip() if self.camera_url_var is not None else ""
        if not value:
            value = "http://192.168.4.1"
        if not value.startswith(("http://", "https://")):
            value = "http://" + value
        value = value.rstrip("/")
        for suffix in ("/capture.jpg", "/latest.jpg", "/status"):
            if value.endswith(suffix):
                value = value[: -len(suffix)]
        return value

    def test_esp32_camera(self) -> None:
        self.stop_camera_stream()
        base_url = self._camera_base_url()
        self.camera_stream_token += 1
        token = self.camera_stream_token
        self._set_camera_status(f"正在检测 {base_url} ...")
        threading.Thread(
            target=self._network_camera_status_worker,
            args=(token, base_url),
            name="sitas-camera-status",
            daemon=True,
        ).start()

    def connect_esp32_wifi(self) -> None:
        self.stop_camera_stream()
        base_url = self._camera_base_url()
        self.camera_stream_token += 1
        token = self.camera_stream_token
        self._set_camera_status("正在连接 ESP32-Camera，请稍候 ...")
        threading.Thread(
            target=self._connect_esp32_wifi_worker,
            args=(token, base_url),
            name="sitas-esp32-wifi-connect",
            daemon=True,
        ).start()

    def _connect_esp32_wifi_worker(self, token: int, base_url: str) -> None:
        try:
            self._run_esp32_wifi_connect()
            last_error: Exception | None = None
            for _attempt in range(12):
                try:
                    request = Request(f"{base_url}/status", headers={"Cache-Control": "no-cache"})
                    with urlopen(request, timeout=2) as response:
                        status = json.loads(response.read(8192).decode("utf-8"))
                    self._queue_camera_event(token, "status", (base_url, status))
                    return
                except Exception as exc:
                    last_error = exc
                    time.sleep(1)
            raise RuntimeError(f"热点已切换，但 ESP32 状态接口没有响应：{last_error}")
        except Exception as exc:
            self._queue_camera_event(token, "error", f"连接 ESP32-Camera 失败：{exc}")

    def _run_esp32_wifi_connect(self) -> None:
        if sys.platform == "darwin":
            interface = self._mac_wifi_interface()
            command = ["networksetup", "-setairportnetwork", interface, "ESP32-Camera", "12345678"]
            result = subprocess.run(command, capture_output=True, text=True, timeout=25, check=False)
        elif sys.platform == "win32":
            result = self._connect_windows_wifi()
        elif sys.platform.startswith("linux"):
            command = ["nmcli", "device", "wifi", "connect", "ESP32-Camera", "password", "12345678"]
            result = subprocess.run(command, capture_output=True, text=True, timeout=25, check=False)
        else:
            raise RuntimeError("当前操作系统暂不支持自动切换 Wi-Fi")

        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            raise RuntimeError(detail or "系统没有完成 Wi-Fi 连接")

    @staticmethod
    def _mac_wifi_interface() -> str:
        result = subprocess.run(
            ["networksetup", "-listallhardwareports"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        lines = result.stdout.splitlines()
        for index, line in enumerate(lines):
            if line.strip() == "Hardware Port: Wi-Fi" and index + 1 < len(lines):
                prefix = "Device:"
                device_line = lines[index + 1].strip()
                if device_line.startswith(prefix):
                    return device_line[len(prefix):].strip()
        raise RuntimeError("没有找到 macOS Wi-Fi 接口")

    @staticmethod
    def _connect_windows_wifi() -> subprocess.CompletedProcess[str]:
        profile = """<?xml version=\"1.0\"?>
<WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\">
  <name>ESP32-Camera</name>
  <SSIDConfig><SSID><name>ESP32-Camera</name></SSID></SSIDConfig>
  <connectionType>ESS</connectionType><connectionMode>auto</connectionMode>
  <MSM><security><authEncryption><authentication>WPA2PSK</authentication>
  <encryption>AES</encryption><useOneX>false</useOneX></authEncryption>
  <sharedKey><keyType>passPhrase</keyType><protected>false</protected>
  <keyMaterial>12345678</keyMaterial></sharedKey></security></MSM>
</WLANProfile>"""
        profile_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False, encoding="utf-8") as file:
                file.write(profile)
                profile_path = Path(file.name)
            added = subprocess.run(
                ["netsh", "wlan", "add", "profile", f"filename={profile_path}", "user=current"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            if added.returncode != 0:
                return added
            return subprocess.run(
                ["netsh", "wlan", "connect", "name=ESP32-Camera", "ssid=ESP32-Camera"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        finally:
            if profile_path is not None:
                profile_path.unlink(missing_ok=True)

    def _network_camera_status_worker(self, token: int, base_url: str) -> None:
        try:
            request = Request(f"{base_url}/status", headers={"Cache-Control": "no-cache"})
            with urlopen(request, timeout=4) as response:
                status = json.loads(response.read(8192).decode("utf-8"))
            self._queue_camera_event(token, "status", (base_url, status))
        except Exception as exc:
            self._queue_camera_event(token, "error", self._network_error_message(exc, base_url))

    def start_camera_stream(self) -> None:
        source = self.camera_source_var.get() if self.camera_source_var is not None else "ESP32 Wi-Fi"
        if source == "ESP32 Wi-Fi":
            self._start_network_camera_stream()
            return
        if cv2 is None:
            messagebox.showerror("缺少依赖", "当前环境没有安装 opencv-python，无法读取 USB 摄像头。")
            self._set_camera_status("缺少 opencv-python，无法启动摄像头。")
            return
        self.stop_camera_stream()
        index = self._safe_int_var(self.camera_index_var, default=0, minimum=0, maximum=8) if self.camera_index_var else 0
        capture = self._open_video_capture(index)
        if capture is None or not capture.isOpened():
            if capture is not None:
                capture.release()
            messagebox.showerror("摄像头打开失败", f"无法打开摄像头编号 {index}。")
            self._set_camera_status(f"摄像头 {index} 打开失败。")
            return
        capture.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
        capture.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)
        self.camera_capture = capture
        self.camera_running = True
        self._set_camera_status(f"摄像头 {index} 已启动，正在读取实时视频流。")
        self._update_camera_stream()

    def _start_network_camera_stream(self) -> None:
        self.stop_camera_stream()
        base_url = self._camera_base_url()
        interval = (
            self._safe_int_var(self.camera_network_interval_var, default=250, minimum=100, maximum=2000)
            if self.camera_network_interval_var is not None
            else 250
        )
        self.camera_stream_token += 1
        token = self.camera_stream_token
        stop_event = threading.Event()
        self.camera_network_stop_event = stop_event
        self.camera_running = True
        self._set_camera_status(f"正在连接 ESP32 网络摄像头：{base_url}")
        self.camera_network_thread = threading.Thread(
            target=self._network_camera_worker,
            args=(token, base_url, interval, stop_event),
            name="sitas-camera-stream",
            daemon=True,
        )
        self.camera_network_thread.start()

    def _network_camera_worker(
        self,
        token: int,
        base_url: str,
        interval_ms: int,
        stop_event: threading.Event,
    ) -> None:
        last_reconnect = 0.0
        while not stop_event.is_set():
            try:
                request = Request(
                    f"{base_url}/capture.jpg?t={datetime.now().timestamp()}",
                    headers={"Cache-Control": "no-cache"},
                )
                with urlopen(request, timeout=7) as response:
                    data = response.read(4 * 1024 * 1024 + 1)
                if len(data) > 4 * 1024 * 1024:
                    raise ValueError("摄像头返回的单帧超过 4 MB")
                with Image.open(BytesIO(data)) as image:
                    frame_rgb = np.array(image.convert("RGB"), dtype=np.uint8)
                self._queue_camera_event(token, "frame", (base_url, frame_rgb))
                wait_seconds = interval_ms / 1000.0
            except Exception as exc:
                now = time.monotonic()
                if isinstance(exc, (URLError, TimeoutError)) and now - last_reconnect >= 8.0:
                    last_reconnect = now
                    self._queue_camera_event(token, "error", "ESP32 热点连接中断，正在自动重新连接 ...")
                    try:
                        self._run_esp32_wifi_connect()
                    except Exception as reconnect_error:
                        self._queue_camera_event(token, "error", f"自动重新连接失败：{reconnect_error}")
                else:
                    self._queue_camera_event(token, "error", self._network_error_message(exc, base_url))
                wait_seconds = max(1.0, interval_ms / 1000.0)
            if stop_event.wait(wait_seconds):
                break

    def _network_error_message(self, exc: Exception, base_url: str) -> str:
        if isinstance(exc, HTTPError):
            try:
                detail = exc.read(500).decode("utf-8", errors="replace").strip()
            except Exception:
                detail = ""
            if exc.code == 504:
                return (
                    "ESP32 Wi-Fi 已连接，但开发板没有收到摄像头画面。请依次检查："
                    "摄像头独立稳定 5V 供电；D+ 接 GPIO20；D- 接 GPIO19；电源与 ESP32 共地；"
                    "摄像头支持 UVC MJPEG。"
                )
            if exc.code == 503:
                return (
                    "ESP32 热点和服务均已连接，但开发板没有识别到 USB 摄像头。"
                    "请检查摄像头 5V 供电、D+→GPIO20、D-→GPIO19，并确保共地。"
                )
            return f"ESP32 返回 HTTP {exc.code}：{detail or exc.reason}"
        if isinstance(exc, URLError):
            return f"无法连接 {base_url}。请确认电脑已连接 ESP32-Camera 热点。({exc.reason})"
        return f"读取 ESP32 画面失败：{exc}"

    def _queue_camera_event(self, token: int, kind: str, payload: Any) -> None:
        event = (token, kind, payload)
        try:
            self.camera_event_queue.put_nowait(event)
        except queue.Full:
            try:
                self.camera_event_queue.get_nowait()
            except queue.Empty:
                pass
            try:
                self.camera_event_queue.put_nowait(event)
            except queue.Full:
                pass

    def _poll_camera_events(self) -> None:
        latest_frame: tuple[str, np.ndarray] | None = None
        latest_message: str | None = None
        try:
            while True:
                token, kind, payload = self.camera_event_queue.get_nowait()
                if token != self.camera_stream_token:
                    continue
                if kind == "frame":
                    latest_frame = payload
                elif kind == "status":
                    base_url, status = payload
                    if status.get("cameraOnline"):
                        camera_state = "摄像头在线"
                    elif not status.get("usbStartReturned"):
                        camera_state = "ESP32 已连接，但 USB 主机尚未完成初始化"
                    elif "usbDeviceConnected" in status and not status.get("usbDeviceConnected"):
                        camera_state = "ESP32 已连接，但没有识别到 USB 摄像头"
                    elif status.get("usbDeviceConnected"):
                        camera_state = "USB 摄像头已识别，正在等待 MJPEG 画面"
                    else:
                        camera_state = "ESP32 已连接，等待摄像头画面"
                    usb_state = "USB 主机已启动" if status.get("usbStartReturned") else "USB 主机未就绪"
                    resolution = f"{status.get('width', 0)} x {status.get('height', 0)}"
                    latest_message = (
                        f"{camera_state}；{usb_state}；地址 {base_url}；"
                        f"分辨率 {resolution}；累计帧 {status.get('totalFrames', 0)}"
                    )
                elif kind == "error":
                    latest_message = str(payload)
        except queue.Empty:
            pass

        if latest_frame is not None:
            base_url, frame_rgb = latest_frame
            self.camera_frame_rgb = frame_rgb
            height, width = frame_rgb.shape[:2]
            if self.camera_frame_size_var is not None:
                self.camera_frame_size_var.set(f"当前帧：{width} x {height} · ESP32 Wi-Fi")
            self._render_camera_frame()
            latest_message = f"ESP32 网络视频已连接：{base_url}；当前帧 {width} x {height}"

        if latest_message is not None:
            self._set_camera_status(latest_message)

        try:
            self.after(100, self._poll_camera_events)
        except tk.TclError:
            pass

    def stop_camera_stream(self) -> None:
        self.camera_running = False
        self.camera_stream_token += 1
        if self.camera_network_stop_event is not None:
            self.camera_network_stop_event.set()
            self.camera_network_stop_event = None
        self.camera_network_thread = None
        if self.camera_after_id is not None:
            try:
                self.after_cancel(self.camera_after_id)
            except tk.TclError:
                pass
            self.camera_after_id = None
        if self.camera_capture is not None:
            self.camera_capture.release()
            self.camera_capture = None
        self._set_camera_status("摄像头预览已停止。")

    def capture_camera_frame(self) -> None:
        if self.camera_frame_rgb is None:
            messagebox.showinfo("还没有视频帧", "请先开始摄像头预览，等画面出现后再抓拍。")
            return
        capture_dir = OUTPUT_DIR / "camera_captures"
        capture_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = capture_dir / f"sitas_camera_capture_{timestamp}.png"
        try:
            Image.fromarray(self.camera_frame_rgb.astype(np.uint8), mode="RGB").save(output_path, format="PNG")
            self._set_camera_status(f"已抓拍并保存：{output_path.resolve()}")
            self.load_image(output_path)
            self.notebook.select(1)
        except Exception as exc:
            messagebox.showerror("抓拍失败", f"无法保存摄像头抓拍图片：\n{exc}")
            self._set_camera_status("摄像头抓拍失败。")

    def _open_video_capture(self, index: int):
        if cv2 is None:
            return None
        if sys.platform == "darwin":
            return cv2.VideoCapture(index, cv2.CAP_AVFOUNDATION)
        return cv2.VideoCapture(index)

    def _update_camera_stream(self) -> None:
        if not self.camera_running or self.camera_capture is None:
            return
        ok, frame = self.camera_capture.read()
        if ok and frame is not None:
            self.camera_frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB) if cv2 is not None else frame
            height, width = self.camera_frame_rgb.shape[:2]
            if self.camera_frame_size_var is not None:
                self.camera_frame_size_var.set(f"当前帧：{width} x {height}")
            self._render_camera_frame()
        else:
            self._set_camera_status("暂时没有读到摄像头画面，正在继续尝试。")
        delay = self._safe_int_var(self.camera_fps_var, default=33, minimum=15, maximum=200) if self.camera_fps_var else 33
        self.camera_after_id = self.after(delay, self._update_camera_stream)

    def _render_camera_frame(self) -> None:
        if not hasattr(self, "camera_canvas"):
            return
        self.camera_canvas.delete("all")
        if self.camera_frame_rgb is None:
            self.camera_canvas.create_text(
                24,
                24,
                anchor=tk.NW,
                text="等待摄像头视频流",
                fill="#d7e3f7",
                font=("Arial", 13, "bold"),
            )
            return
        canvas_width = max(1, self.camera_canvas.winfo_width())
        canvas_height = max(1, self.camera_canvas.winfo_height())
        image = Image.fromarray(self.camera_frame_rgb.astype(np.uint8), mode="RGB")
        image_width, image_height = image.size
        scale = max(0.01, min(canvas_width / image_width, canvas_height / image_height))
        display_width = max(1, int(image_width * scale))
        display_height = max(1, int(image_height * scale))
        offset_x = max(0, (canvas_width - display_width) // 2)
        offset_y = max(0, (canvas_height - display_height) // 2)
        preview = image.resize((display_width, display_height), Image.Resampling.BILINEAR)
        self.camera_photo = ImageTk.PhotoImage(preview)
        self.camera_canvas.create_image(offset_x, offset_y, anchor=tk.NW, image=self.camera_photo)
        self.camera_canvas.create_rectangle(offset_x, offset_y, offset_x + display_width, offset_y + display_height, outline="#1d4ed8", width=2)

    def _set_camera_status(self, message: str) -> None:
        if self.camera_status_var is not None:
            self.camera_status_var.set(message)
        if hasattr(self, "status_label"):
            self.set_status(message)

    def load_image(self, image_path: Path) -> None:
        try:
            image_path = image_path.expanduser().resolve()
            with Image.open(image_path) as image:
                image.load()
                arr, channel_names = channel_array(image)
                lsb_stats, bitplane = lsb_statistics(arr, channel_names)
                report = self._build_report(image_path, image, arr, channel_names, lsb_stats)
                self.current_image = image_path
                self.current_report = report
                self.rgb_array = np.array(image.convert("RGB"))
                self.rgb_overview_image = image.convert("RGB")
                self._update_preview(image)
                self._update_bitplane(bitplane)
                self._update_report_views(report)
                self._update_rgb_array_view()
                self._update_watermark_view()
                self.watermark_integrity_result = None
                self._render_watermark_integrity_overlay()
                self._set_watermark_integrity_detail(
                    "当前图片已读取。\n点击“检查水印完整性”，程序会只用图片里的隐形水印和系统水印记录库进行验证。"
                )
                self.fragile_result = None
                self.fragile_embedding_change_result = None
                self.fragile_embedding_change_base_rgb = None
                self._render_fragile_overlay()
                self._set_fragile_status("尚未验证")
                self._set_fragile_detail(
                    "当前图片已读取。\n输入密钥后，可以写入或验证基于 SHA256 的 LSB 脆弱水印。"
                )
                self.path_label.configure(text=str(image_path))
                self.set_status(f"已读取：{image_path.name}")
        except Exception as exc:
            messagebox.showerror("读取失败", f"无法读取图片：\n{exc}")
            self.set_status("读取失败")

    def _build_report(self, image_path: Path, image: Image.Image, arr: np.ndarray, channel_names: list[str], lsb_stats: dict) -> dict:
        file_stat = image_path.stat()
        return {
            "basic": {
                "路径": str(image_path),
                "文件名": image_path.name,
                "文件大小": human_size(file_stat.st_size),
                "SHA256": sha256_file(image_path),
                "图片格式": image.format,
                "颜色模式": image.mode,
                "宽度": image.width,
                "高度": image.height,
                "像素总数": image.width * image.height,
                "帧数": getattr(image, "n_frames", 1),
            },
            "embedded_metadata": collect_embedded_metadata(image),
            "exif": collect_exif(image),
            "channel_statistics": channel_statistics(arr, channel_names),
            "lsb_statistics": lsb_stats,
            "lsb_probe": extract_lsb_probe(arr, channel_names, DEFAULT_LSB_SAMPLE_BITS),
        }

    def _update_preview(self, image: Image.Image) -> None:
        preview = ImageOps.exif_transpose(image).copy()
        preview.thumbnail((520, 320))
        if preview.mode not in ("RGB", "RGBA"):
            preview = preview.convert("RGB")
        self.preview_photo = ImageTk.PhotoImage(preview)
        self.preview_label.configure(image=self.preview_photo, text="")

    def _update_bitplane(self, bitplane: np.ndarray) -> None:
        visual = Image.fromarray((bitplane.astype(np.uint8) * 255), mode="L")
        visual.thumbnail(MAX_BITPLANE_SIZE, Image.Resampling.NEAREST)
        visual.thumbnail((520, 280), Image.Resampling.NEAREST)
        self.bitplane_photo = ImageTk.PhotoImage(visual)
        self.bitplane_label.configure(image=self.bitplane_photo, text="")

    def _update_report_views(self, report: dict) -> None:
        self._fill_tree(self.basic_tree, report["basic"])
        self._fill_tree(self.channel_tree, report["channel_statistics"])
        self._fill_tree(self.lsb_tree, report["lsb_statistics"])
        self._set_text(self.metadata_text, self._pretty_json(report["embedded_metadata"]))
        self._set_text(self.exif_text, self._pretty_json(report["exif"]))
        self._set_text(self.lsb_probe_text, self._pretty_json(report["lsb_probe"]))

    def _update_rgb_array_view(self) -> None:
        self.rgb_current_pixel = None
        self.rgb_pixel_label.configure(text="中心像素：-")
        self._render_rgb_overview()
        if self.rgb_array is not None:
            height, width = self.rgb_array.shape[:2]
            self.rgb_current_pixel = (width // 2, height // 2)
            self._draw_rgb_marker()
            self._redraw_rgb_magnifier()

    def _render_rgb_overview(self) -> None:
        if not hasattr(self, "rgb_canvas"):
            return
        self.rgb_canvas.delete("all")
        if self.rgb_overview_image is None:
            self.rgb_canvas.create_text(20, 20, anchor=tk.NW, text="选择图片后显示 RGB 数组总览", fill="#667085")
            return

        canvas_width = max(1, self.rgb_canvas.winfo_width())
        canvas_height = max(1, self.rgb_canvas.winfo_height())
        image_width, image_height = self.rgb_overview_image.size
        self.rgb_scale = max(0.01, min(canvas_width / image_width, canvas_height / image_height, 16.0))
        display_width = max(1, int(image_width * self.rgb_scale))
        display_height = max(1, int(image_height * self.rgb_scale))
        self.rgb_offset_x = max(0, (canvas_width - display_width) // 2)
        self.rgb_offset_y = max(0, (canvas_height - display_height) // 2)

        preview = self.rgb_overview_image.resize((display_width, display_height), Image.Resampling.NEAREST)
        self.rgb_overview_photo = ImageTk.PhotoImage(preview)
        self.rgb_canvas.create_image(self.rgb_offset_x, self.rgb_offset_y, anchor=tk.NW, image=self.rgb_overview_photo)
        self._draw_rgb_marker()

    def _draw_rgb_marker(self) -> None:
        self.rgb_canvas.delete("rgb_marker")
        if self.rgb_current_pixel is None or self.rgb_overview_image is None:
            return
        x, y = self.rgb_current_pixel
        left = self.rgb_offset_x + x * self.rgb_scale
        top = self.rgb_offset_y + y * self.rgb_scale
        if self.rgb_scale >= 3:
            self.rgb_canvas.create_rectangle(left, top, left + self.rgb_scale, top + self.rgb_scale, outline="#ff3b30", width=2, tags="rgb_marker")
        else:
            cx = left + self.rgb_scale / 2
            cy = top + self.rgb_scale / 2
            self.rgb_canvas.create_line(cx - 8, cy, cx + 8, cy, fill="#ff3b30", width=2, tags="rgb_marker")
            self.rgb_canvas.create_line(cx, cy - 8, cx, cy + 8, fill="#ff3b30", width=2, tags="rgb_marker")

    def _on_rgb_canvas_motion(self, event: tk.Event) -> None:
        if self.rgb_array is None:
            return
        height, width = self.rgb_array.shape[:2]
        x = int((event.x - self.rgb_offset_x) / self.rgb_scale)
        y = int((event.y - self.rgb_offset_y) / self.rgb_scale)
        if not (0 <= x < width and 0 <= y < height) or self.rgb_current_pixel == (x, y):
            return
        self.rgb_current_pixel = (x, y)
        red, green, blue = self.rgb_array[y, x].tolist()
        self.rgb_pixel_label.configure(text=f"中心像素：x={x}, y={y}, RGB=({red}, {green}, {blue})")
        self.set_status(f"RGB 数组位置：x={x}, y={y}, RGB=({red}, {green}, {blue})")
        self._draw_rgb_marker()
        self._redraw_rgb_magnifier()

    def _redraw_rgb_magnifier(self) -> None:
        if not hasattr(self, "rgb_magnifier_canvas"):
            return
        self.rgb_magnifier_canvas.delete("all")
        if self.rgb_array is None:
            self.rgb_magnifier_canvas.create_text(20, 20, anchor=tk.NW, text="选择图片后显示局部 RGB 数组", fill="#667085")
            return
        if self.rgb_current_pixel is None:
            return

        radius = self._safe_int_var(self.rgb_radius_var, default=4, minimum=1, maximum=12)
        cell_size = self._safe_int_var(self.rgb_cell_size_var, default=58, minimum=34, maximum=92)
        x_center, y_center = self.rgb_current_pixel
        height, width = self.rgb_array.shape[:2]
        x_start = max(0, x_center - radius)
        x_end = min(width - 1, x_center + radius)
        y_start = max(0, y_center - radius)
        y_end = min(height - 1, y_center + radius)
        grid_width = (x_end - x_start + 1) * cell_size
        grid_height = (y_end - y_start + 1) * cell_size
        self.rgb_magnifier_canvas.configure(scrollregion=(0, 0, grid_width, grid_height))

        font_size = 8 if cell_size < 48 else 9
        for y in range(y_start, y_end + 1):
            for x in range(x_start, x_end + 1):
                red, green, blue = self.rgb_array[y, x].tolist()
                left = (x - x_start) * cell_size
                top = (y - y_start) * cell_size
                fill = f"#{red:02x}{green:02x}{blue:02x}"
                brightness = (red * 299 + green * 587 + blue * 114) / 1000
                text_color = "#111827" if brightness > 150 else "#ffffff"
                outline = "#ff3b30" if (x, y) == (x_center, y_center) else "#d0d5dd"
                width_px = 3 if (x, y) == (x_center, y_center) else 1
                self.rgb_magnifier_canvas.create_rectangle(left, top, left + cell_size, top + cell_size, fill=fill, outline=outline, width=width_px)
                self.rgb_magnifier_canvas.create_text(left + cell_size / 2, top + cell_size / 2 - 8, text=f"{x},{y}", fill=text_color, font=("Menlo", font_size, "bold"))
                self.rgb_magnifier_canvas.create_text(left + cell_size / 2, top + cell_size / 2 + 8, text=f"{red},{green},{blue}", fill=text_color, font=("Menlo", font_size))

        red, green, blue = self.rgb_array[y_center, x_center].tolist()
        self.rgb_pixel_label.configure(text=f"中心像素：x={x_center}, y={y_center}, RGB=({red}, {green}, {blue})")

    def _safe_int_var(self, variable: tk.IntVar, default: int, minimum: int, maximum: int) -> int:
        try:
            value = int(variable.get())
        except (tk.TclError, ValueError):
            value = default
        value = max(minimum, min(maximum, value))
        try:
            current = int(variable.get())
        except (tk.TclError, ValueError):
            current = None
        if current != value:
            variable.set(value)
        return value

    def _update_watermark_view(self) -> None:
        self._render_watermark_preview()
        if self.current_image and self.rgb_array is not None:
            height, width = self.rgb_array.shape[:2]
            y_start, y_end = fifth_band_bounds(height)
            capacity_bits = width * (y_end - y_start) * 3
            capacity_bytes = max(0, capacity_bits // 8 - WATERMARK_HEADER_BYTES)
            self._set_watermark_result(
                "隐形水印会铺满整张图片的每个像素 RGB 最低位。\n"
                f"图片尺寸：{width} x {height}\n"
                f"水印区域：y={y_start} 到 y={y_end - 1}，覆盖整张图\n"
                f"整图容量：约 {capacity_bytes} 字节水印记录\n\n"
                "写入时会随机生成一份不可预测的隐形水印，并保存到系统水印记录库。\n"
                "验证时只读取上传图片里的隐形水印，再和系统保存的原始水印记录对比。"
            )

    def _render_watermark_preview(self) -> None:
        if not hasattr(self, "watermark_canvas"):
            return
        self.watermark_canvas.delete("all")
        if self.rgb_overview_image is None:
            self.watermark_canvas.create_text(20, 20, anchor=tk.NW, text="选择图片后显示整张图水印区域", fill="#667085")
            return

        canvas_width = max(1, self.watermark_canvas.winfo_width())
        canvas_height = max(1, self.watermark_canvas.winfo_height())
        image_width, image_height = self.rgb_overview_image.size
        scale = max(0.01, min(canvas_width / image_width, canvas_height / image_height, 16.0))
        display_width = max(1, int(image_width * scale))
        display_height = max(1, int(image_height * scale))
        offset_x = max(0, (canvas_width - display_width) // 2)
        offset_y = max(0, (canvas_height - display_height) // 2)

        preview = self.rgb_overview_image.resize((display_width, display_height), Image.Resampling.NEAREST)
        self.watermark_preview_photo = ImageTk.PhotoImage(preview)
        self.watermark_canvas.create_image(offset_x, offset_y, anchor=tk.NW, image=self.watermark_preview_photo)

        self.watermark_canvas.create_rectangle(
            offset_x,
            offset_y,
            offset_x + display_width,
            offset_y + display_height,
            outline="#ff3b30",
            width=3,
            fill="#0f766e",
            stipple="gray25",
        )
        self.watermark_canvas.create_text(
            offset_x + 10,
            offset_y + 10,
            anchor=tk.NW,
            text="整张图片：每个像素 RGB 最低位都参与隐形水印",
            fill="#ffffff",
            font=("Arial", 12, "bold"),
        )

    def write_watermark(self) -> None:
        if not self.current_image:
            messagebox.showinfo("还没有图片", "请先选择一张图片。")
            return
        watermark_text = self.watermark_text_var.get().strip()
        if not watermark_text:
            messagebox.showinfo("水印为空", "请输入要写入的隐形水印内容。")
            return

        visible_text = None
        if self.visible_watermark_var.get():
            visible_text = self.visible_watermark_text_var.get().strip() or watermark_text
        opacity = self._safe_int_var(self.visible_opacity_var, default=52, minimum=15, maximum=120)

        output_path = OUTPUT_DIR / f"{self.current_image.stem}_watermarked.png"
        try:
            result = write_invisible_watermark_to_fifth_band(self.current_image, watermark_text, output_path, visible_text, opacity)
            verify_result = verify_image_integrity(output_path)
            result["tamper_check"] = "intact" if verify_result["is_intact"] else "failed"
            result["visible_watermark_text"] = visible_text or ""
            self._set_watermark_result(json.dumps({"write_result": result, "verify_result": verify_result}, ensure_ascii=False, indent=2))
            self.set_status(f"水印已写入：{output_path.resolve()}")
            messagebox.showinfo("写入完成", f"已生成水印图片：\n{output_path.resolve()}")
            self.load_image(output_path)
        except Exception as exc:
            messagebox.showerror("写入失败", f"无法写入水印：\n{exc}")
            self.set_status("水印写入失败")

    def verify_current_watermark(self) -> None:
        if not self.current_image:
            messagebox.showinfo("还没有图片", "请先选择一张图片。")
            return
        try:
            details = watermark_integrity_details(self.current_image)
            self.watermark_integrity_result = details
            result = {
                key: value
                for key, value in details.items()
                if key not in {"pixel_mismatch_mask", "channel_mismatch_mask"}
            }
            self._set_watermark_result(json.dumps(result, ensure_ascii=False, indent=2))
            self._set_watermark_integrity_detail(json.dumps(result, ensure_ascii=False, indent=2))
            self._render_watermark_integrity_overlay()
            self.set_status(str(result["message"]))
        except Exception as exc:
            messagebox.showerror("验证失败", f"无法验证水印：\n{exc}")
            self.set_status("水印验证失败")

    def open_watermark_records_folder(self) -> None:
        WATERMARK_RECORD_DIR.mkdir(parents=True, exist_ok=True)
        webbrowser.open(WATERMARK_RECORD_DIR.resolve().as_uri())

    def check_current_watermark_integrity(self) -> None:
        if self.current_image is None or self.rgb_array is None:
            messagebox.showinfo("还没有当前图片", "请先选择或生成一张当前图片。")
            return
        try:
            details = watermark_integrity_details(self.current_image)
            self.watermark_integrity_result = details
            summary = {
                key: value
                for key, value in details.items()
                if key not in {"pixel_mismatch_mask", "channel_mismatch_mask"}
            }
            text = json.dumps(summary, ensure_ascii=False, indent=2)
            self._set_watermark_integrity_detail(text)
            self._set_watermark_result(text)
            self._render_watermark_integrity_overlay()
            self.set_status(str(summary["message"]))
        except Exception as exc:
            messagebox.showerror("检查失败", f"无法检查水印完整性：\n{exc}")
            self.set_status("水印完整性检查失败")

    def _render_watermark_integrity_overlay(self) -> None:
        if not hasattr(self, "watermark_integrity_canvas"):
            return
        self.watermark_integrity_canvas.delete("all")
        if self.watermark_integrity_result is None or self.rgb_array is None:
            self.watermark_integrity_canvas.create_text(
                20,
                20,
                anchor=tk.NW,
                text="点击“检查水印完整性”后显示隐形水印损坏位置。",
                fill="#667085",
            )
            return

        mask = self.watermark_integrity_result["pixel_mismatch_mask"]
        overlay = watermark_damage_overlay_image(self.rgb_array, mask)  # type: ignore[arg-type]
        canvas_width = max(1, self.watermark_integrity_canvas.winfo_width())
        canvas_height = max(1, self.watermark_integrity_canvas.winfo_height())
        image_width, image_height = overlay.size
        self.watermark_integrity_scale = max(0.01, min(canvas_width / image_width, canvas_height / image_height, 16.0))
        display_width = max(1, int(image_width * self.watermark_integrity_scale))
        display_height = max(1, int(image_height * self.watermark_integrity_scale))
        self.watermark_integrity_offset_x = max(0, (canvas_width - display_width) // 2)
        self.watermark_integrity_offset_y = max(0, (canvas_height - display_height) // 2)

        preview = overlay.resize((display_width, display_height), Image.Resampling.NEAREST)
        self.watermark_integrity_overlay_photo = ImageTk.PhotoImage(preview)
        self.watermark_integrity_canvas.create_image(
            self.watermark_integrity_offset_x,
            self.watermark_integrity_offset_y,
            anchor=tk.NW,
            image=self.watermark_integrity_overlay_photo,
        )

    def _on_watermark_integrity_canvas_motion(self, event: tk.Event) -> None:
        if self.watermark_integrity_result is None or self.rgb_array is None:
            return
        height, width = self.rgb_array.shape[:2]
        x = int((event.x - self.watermark_integrity_offset_x) / self.watermark_integrity_scale)
        y = int((event.y - self.watermark_integrity_offset_y) / self.watermark_integrity_scale)
        if not (0 <= x < width and 0 <= y < height):
            return
        pixel_mask = self.watermark_integrity_result["pixel_mismatch_mask"]
        channel_mask = self.watermark_integrity_result.get("channel_mismatch_mask")
        damaged_here = bool(pixel_mask[y, x])  # type: ignore[index]
        channels: list[str] = []
        if isinstance(channel_mask, np.ndarray):
            flags = channel_mask[y, x].tolist()
            channels = [name for idx, name in enumerate(("R", "G", "B")) if flags[idx]]
        red, green, blue = self.rgb_array[y, x].tolist()
        lsb = [red & 1, green & 1, blue & 1]
        self.set_status(
            f"x={x}, y={y} | watermark_damaged={damaged_here} | RGB=({red}, {green}, {blue}) | LSB={lsb} | damaged_channels={channels or '-'}"
        )

    def preview_fragile_embedding_changes(self) -> None:
        if self.current_image is None or self.rgb_array is None:
            messagebox.showinfo("还没有当前图片", "请先选择一张图片。")
            return
        key = self.fragile_key_var.get()
        if not key:
            messagebox.showinfo("密钥为空", "请输入 LSB 脆弱水印密钥。")
            return
        try:
            result = lsb_embedding_change_map(self.current_image, key)
            self.fragile_embedding_change_result = result
            self.fragile_embedding_change_base_rgb = self.rgb_array.copy()
            if self.fragile_view_mode_var is not None:
                self.fragile_view_mode_var.set("写入改动图")
            text = json.dumps(json_safe_result(result), ensure_ascii=False, indent=2)
            self._set_fragile_detail(
                "这是写入 LSB 脆弱水印时会发生数值变化的位置预览。\n"
                "蓝色代表：该像素至少有一个 RGB 分量的 LSB 会被改成校验位。\n\n"
                f"{text}"
            )
            self._set_fragile_status_from_embedding_change(result)
            self._render_fragile_overlay()
            self.set_status("已生成 LSB 写入改动预览")
        except Exception as exc:
            messagebox.showerror("预览失败", f"无法预览 LSB 写入改动：\n{exc}")
            self.set_status("LSB 写入改动预览失败")

    def write_fragile_watermark(self) -> None:
        if not self.current_image:
            messagebox.showinfo("还没有图片", "请先选择一张图片。")
            return
        key = self.fragile_key_var.get()
        if not key:
            messagebox.showinfo("密钥为空", "请输入 LSB 脆弱水印密钥。")
            return

        output_path = OUTPUT_DIR / f"{self.current_image.stem}_fragile_lsb.png"
        try:
            change_result = lsb_embedding_change_map(self.current_image, key)
            change_base_rgb = self.rgb_array.copy() if self.rgb_array is not None else None
            result = embed_lsb_fragile_watermark(self.current_image, output_path, key)
            verify_result = verify_lsb_fragile_watermark(output_path, key)
            summary = {
                "write_result": result,
                "embedding_change_result": json_safe_result(change_result),
                "verify_result": json_safe_result(verify_result),
            }
            self.set_status(f"LSB 脆弱水印已写入：{output_path.resolve()}")
            messagebox.showinfo("写入完成", f"已生成 LSB 脆弱水印图片：\n{output_path.resolve()}")
            self.load_image(output_path)
            self.fragile_result = verify_result
            self.fragile_embedding_change_result = change_result
            self.fragile_embedding_change_base_rgb = change_base_rgb
            if self.fragile_view_mode_var is not None:
                self.fragile_view_mode_var.set("写入改动图")
            self._set_fragile_detail(json.dumps(summary, ensure_ascii=False, indent=2))
            self._set_fragile_status_from_embedding_change(change_result)
            self._render_fragile_overlay()
        except Exception as exc:
            messagebox.showerror("写入失败", f"无法写入 LSB 脆弱水印：\n{exc}")
            self.set_status("LSB 脆弱水印写入失败")

    def verify_fragile_watermark(self) -> None:
        if self.current_image is None or self.rgb_array is None:
            messagebox.showinfo("还没有当前图片", "请先选择或生成一张当前图片。")
            return
        key = self.fragile_key_var.get()
        if not key:
            messagebox.showinfo("密钥为空", "请输入 LSB 脆弱水印密钥。")
            return
        try:
            result = verify_lsb_fragile_watermark(self.current_image, key)
            self.fragile_result = result
            if self.fragile_view_mode_var is not None and self.fragile_view_mode_var.get() in {"写入改动图", "写入改动热力图"}:
                self.fragile_view_mode_var.set("叠加图")
            text = json.dumps(json_safe_result(result), ensure_ascii=False, indent=2)
            self._set_fragile_detail(text)
            self._set_fragile_status_from_result(result)
            self._render_fragile_overlay()
            self.set_status(str(result["message"]))
        except Exception as exc:
            messagebox.showerror("验证失败", f"无法验证 LSB 脆弱水印：\n{exc}")
            self.set_status("LSB 脆弱水印验证失败")

    def _render_fragile_overlay(self) -> None:
        if not hasattr(self, "fragile_canvas"):
            return
        self.fragile_canvas.delete("all")
        if self.rgb_array is None:
            self.fragile_canvas.create_text(
                20,
                20,
                anchor=tk.NW,
                text="选择图片后，可以预览写入改动或验证篡改位置。",
                fill="#667085",
            )
            return

        view_mode = self.fragile_view_mode_var.get() if self.fragile_view_mode_var else "叠加图"
        if view_mode in {"写入改动图", "写入改动热力图"}:
            if self.fragile_embedding_change_result is None:
                self.fragile_canvas.create_text(
                    20,
                    20,
                    anchor=tk.NW,
                    text="点击“预览写入改动”后，蓝色显示 LSB 写入造成的肉眼不可见变化。",
                    fill="#667085",
                )
                return
            change_mask = self.fragile_embedding_change_result["pixel_change_mask"]
            if view_mode == "写入改动热力图":
                overlay = make_write_change_heatmap(change_mask).convert("RGBA")  # type: ignore[arg-type]
            else:
                opacity = self._safe_int_var(self.fragile_overlay_opacity_var, default=145, minimum=40, maximum=220) if self.fragile_overlay_opacity_var else 145
                base_rgb = self.fragile_embedding_change_base_rgb if self.fragile_embedding_change_base_rgb is not None else self.rgb_array
                overlay = watermark_write_change_overlay_image(base_rgb, change_mask, opacity)  # type: ignore[arg-type]
        elif view_mode == "热力图":
            if self.fragile_result is None:
                self.fragile_canvas.create_text(20, 20, anchor=tk.NW, text="点击“验证脆弱水印”后显示篡改热力图。", fill="#667085")
                return
            mask = self.fragile_result["pixel_mismatch_mask"]
            overlay = make_tamper_heatmap(mask).convert("RGBA")  # type: ignore[arg-type]
        elif view_mode == "原图":
            overlay = Image.fromarray(self.rgb_array.astype(np.uint8), mode="RGB").convert("RGBA")
        else:
            if self.fragile_result is None:
                self.fragile_canvas.create_text(20, 20, anchor=tk.NW, text="点击“验证脆弱水印”后显示篡改叠加图。", fill="#667085")
                return
            mask = self.fragile_result["pixel_mismatch_mask"]
            opacity = self._safe_int_var(self.fragile_overlay_opacity_var, default=130, minimum=40, maximum=220) if self.fragile_overlay_opacity_var else 130
            overlay = watermark_damage_overlay_image(self.rgb_array, mask, opacity)  # type: ignore[arg-type]
        canvas_width = max(1, self.fragile_canvas.winfo_width())
        canvas_height = max(1, self.fragile_canvas.winfo_height())
        image_width, image_height = overlay.size
        self.fragile_scale = max(0.01, min(canvas_width / image_width, canvas_height / image_height, 16.0))
        display_width = max(1, int(image_width * self.fragile_scale))
        display_height = max(1, int(image_height * self.fragile_scale))
        self.fragile_offset_x = max(0, (canvas_width - display_width) // 2)
        self.fragile_offset_y = max(0, (canvas_height - display_height) // 2)

        preview = overlay.resize((display_width, display_height), Image.Resampling.NEAREST)
        self.fragile_overlay_photo = ImageTk.PhotoImage(preview)
        self.fragile_canvas.create_image(self.fragile_offset_x, self.fragile_offset_y, anchor=tk.NW, image=self.fragile_overlay_photo)

    def export_fragile_visuals(self) -> None:
        if self.current_image is None:
            messagebox.showinfo("还没有当前图片", "请先选择一张图片。")
            return
        if self.fragile_result is None and self.fragile_embedding_change_result is None:
            messagebox.showinfo("还没有可视化结果", "请先验证脆弱水印，或点击“预览写入改动”。")
            return
        default_dir = OUTPUT_DIR / "fragile_visuals"
        default_dir.mkdir(parents=True, exist_ok=True)
        exported: list[Path] = []
        try:
            if self.fragile_result is not None:
                mismatch_mask = self.fragile_result.get("pixel_mismatch_mask")
                if isinstance(mismatch_mask, np.ndarray):
                    heatmap_path = default_dir / f"{self.current_image.stem}_fragile_tamper_heatmap.png"
                    overlay_path = default_dir / f"{self.current_image.stem}_fragile_tamper_overlay.png"
                    make_tamper_heatmap(mismatch_mask).save(heatmap_path, format="PNG")
                    make_overlay(self.current_image, mismatch_mask).save(overlay_path, format="PNG")
                    exported.extend([heatmap_path, overlay_path])
            if self.fragile_embedding_change_result is not None:
                change_mask = self.fragile_embedding_change_result.get("pixel_change_mask")
                if isinstance(change_mask, np.ndarray):
                    change_heatmap_path = default_dir / f"{self.current_image.stem}_fragile_write_change_heatmap.png"
                    change_overlay_path = default_dir / f"{self.current_image.stem}_fragile_write_change_overlay.png"
                    base_rgb = self.fragile_embedding_change_base_rgb if self.fragile_embedding_change_base_rgb is not None else self.rgb_array
                    make_write_change_heatmap(change_mask).save(change_heatmap_path, format="PNG")
                    if base_rgb is not None:
                        watermark_write_change_overlay_image(base_rgb, change_mask).save(change_overlay_path, format="PNG")
                        exported.append(change_overlay_path)
                    exported.append(change_heatmap_path)
            if not exported:
                messagebox.showerror("导出失败", "当前没有可导出的可视化数据。")
                return
            self.set_status(f"已导出 {len(exported)} 个 LSB 可视化文件")
            exported_text = "\n".join(str(path.resolve()) for path in exported)
            messagebox.showinfo("导出完成", f"已导出：\n{exported_text}")
        except Exception as exc:
            messagebox.showerror("导出失败", f"无法导出可视化结果：\n{exc}")

    def _set_fragile_status(self, text: str) -> None:
        if self.fragile_status_var is not None:
            self.fragile_status_var.set(text)

    def _set_fragile_status_from_result(self, result: dict[str, object]) -> None:
        status = str(result.get("integrity_status", "-"))
        damaged_pixels = result.get("damaged_pixels", "-")
        mismatched_channels = result.get("mismatched_channels", "-")
        ratio = result.get("mismatch_ratio", "-")
        self._set_fragile_status(
            f"状态：{status} | 可疑像素：{damaged_pixels} | 失败通道：{mismatched_channels} | 比例：{ratio}"
        )

    def _set_fragile_status_from_embedding_change(self, result: dict[str, object]) -> None:
        changed_pixels = result.get("changed_pixels", "-")
        changed_channels = result.get("changed_channels", "-")
        total_channels = result.get("total_channels", "-")
        ratio = result.get("change_ratio", "-")
        self._set_fragile_status(
            f"写入改动：像素 {changed_pixels} | RGB 分量 {changed_channels}/{total_channels} | 比例：{ratio}"
        )

    def _on_fragile_canvas_motion(self, event: tk.Event) -> None:
        if self.rgb_array is None:
            return
        height, width = self.rgb_array.shape[:2]
        x = int((event.x - self.fragile_offset_x) / self.fragile_scale)
        y = int((event.y - self.fragile_offset_y) / self.fragile_scale)
        if not (0 <= x < width and 0 <= y < height):
            return
        view_mode = self.fragile_view_mode_var.get() if self.fragile_view_mode_var else "叠加图"
        if view_mode in {"写入改动图", "写入改动热力图"}:
            if self.fragile_embedding_change_result is None:
                return
            pixel_mask = self.fragile_embedding_change_result["pixel_change_mask"]
            channel_mask = self.fragile_embedding_change_result.get("channel_change_mask")
            changed_here = bool(pixel_mask[y, x])  # type: ignore[index]
            channels: list[str] = []
            if isinstance(channel_mask, np.ndarray):
                flags = channel_mask[y, x].tolist()
                channels = [name for idx, name in enumerate(("R", "G", "B")) if flags[idx]]
            base_rgb = self.fragile_embedding_change_base_rgb if self.fragile_embedding_change_base_rgb is not None else self.rgb_array
            red, green, blue = base_rgb[y, x].tolist()
            lsb = [red & 1, green & 1, blue & 1]
            self.set_status(
                f"x={x}, y={y} | write_changed={changed_here} | 原RGB=({red}, {green}, {blue}) | 原LSB={lsb} | changed_channels={channels or '-'}"
            )
            return
        if self.fragile_result is None:
            return
        pixel_mask = self.fragile_result["pixel_mismatch_mask"]
        channel_mask = self.fragile_result.get("channel_mismatch_mask")
        damaged_here = bool(pixel_mask[y, x])  # type: ignore[index]
        channels: list[str] = []
        if isinstance(channel_mask, np.ndarray):
            flags = channel_mask[y, x].tolist()
            channels = [name for idx, name in enumerate(("R", "G", "B")) if flags[idx]]
        red, green, blue = self.rgb_array[y, x].tolist()
        lsb = [red & 1, green & 1, blue & 1]
        self.set_status(
            f"x={x}, y={y} | fragile_damaged={damaged_here} | RGB=({red}, {green}, {blue}) | LSB={lsb} | failed_channels={channels or '-'}"
        )

    def _set_watermark_result(self, value: str) -> None:
        if not hasattr(self, "watermark_result_text"):
            return
        self.watermark_result_text.configure(state=tk.NORMAL)
        self.watermark_result_text.delete("1.0", tk.END)
        self.watermark_result_text.insert("1.0", value)
        self.watermark_result_text.configure(state=tk.DISABLED)

    def _set_watermark_integrity_detail(self, value: str) -> None:
        if not hasattr(self, "watermark_integrity_detail_text"):
            return
        self.watermark_integrity_detail_text.configure(state=tk.NORMAL)
        self.watermark_integrity_detail_text.delete("1.0", tk.END)
        self.watermark_integrity_detail_text.insert("1.0", value)
        self.watermark_integrity_detail_text.configure(state=tk.DISABLED)

    def _set_fragile_detail(self, value: str) -> None:
        if not hasattr(self, "fragile_detail_text"):
            return
        self.fragile_detail_text.configure(state=tk.NORMAL)
        self.fragile_detail_text.delete("1.0", tk.END)
        self.fragile_detail_text.insert("1.0", value)
        self.fragile_detail_text.configure(state=tk.DISABLED)

    def _fill_tree(self, tree: ttk.Treeview, data: dict) -> None:
        tree.delete(*tree.get_children())
        if not data:
            tree.insert("", tk.END, values=("无数据", "没有读取到对应信息"))
            return
        for index, (key, value) in enumerate(data.items()):
            row_tag = "even" if index % 2 == 0 else "odd"
            if isinstance(value, dict):
                parent = tree.insert("", tk.END, values=(str(key), ""), tags=("parent",))
                for child_index, (child_key, child_value) in enumerate(value.items()):
                    child_tag = "even" if child_index % 2 == 0 else "odd"
                    tree.insert(parent, tk.END, values=(str(child_key), self._format_cell(child_value)), tags=(child_tag,))
                tree.item(parent, open=True)
            else:
                tree.insert("", tk.END, values=(str(key), self._format_cell(value)), tags=(row_tag,))

    def _set_text(self, text_widget: tk.Text, value: str) -> None:
        text_widget.configure(state=tk.NORMAL)
        text_widget.delete("1.0", tk.END)
        text_widget.insert("1.0", value)
        text_widget.configure(state=tk.DISABLED)

    def _pretty_json(self, data: dict) -> str:
        if not data:
            return "没有读取到对应信息。"
        return json.dumps(data, ensure_ascii=False, indent=2)

    def _format_cell(self, value: object) -> str:
        if isinstance(value, (dict, list)):
            return json.dumps(value, ensure_ascii=False)
        return str(value)

    def export_report(self) -> None:
        if not self.current_image:
            messagebox.showinfo("还没有图片", "请先选择一张图片。")
            return
        try:
            outputs = default_outputs(self.current_image, None, None)
            report, html_report = make_report(self.current_image, DEFAULT_LSB_SAMPLE_BITS)
            outputs.html_report.parent.mkdir(parents=True, exist_ok=True)
            outputs.html_report.write_text(html_report, encoding="utf-8")
            if outputs.json_report:
                outputs.json_report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
            self.set_status(f"报告已生成：{outputs.html_report.resolve()}")
            if messagebox.askyesno("报告已生成", f"HTML 报告：\n{outputs.html_report.resolve()}\n\n是否现在打开？"):
                webbrowser.open(outputs.html_report.resolve().as_uri())
        except Exception as exc:
            messagebox.showerror("导出失败", f"生成报告失败：\n{exc}")
            self.set_status("导出失败")

    def open_reports_folder(self) -> None:
        reports_dir = Path("reports").resolve()
        reports_dir.mkdir(exist_ok=True)
        webbrowser.open(reports_dir.as_uri())

    def set_status(self, message: str) -> None:
        self.status_label.configure(text=message)

    def on_close(self) -> None:
        self.stop_camera_stream()
        self.destroy()


def main() -> int:
    initial_image = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    app = ImageInfoApp(initial_image)
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
