#!/usr/bin/env python3
"""
SITAS Authenticity Studio.

A product-style desktop GUI for embedding and verifying LSB fragile watermarks.
Run locally:
    python scripts/sitas_watermark_app.py
"""

from __future__ import annotations

import json
import sys
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
import tkinter as tk

import numpy as np
from PIL import Image, ImageTk

from lsb_watermark import (
    embed_lsb_fragile_watermark,
    json_safe_result,
    make_tamper_heatmap,
    verify_lsb_fragile_watermark,
)


IMAGE_TYPES = (
    ("Image files", "*.png *.bmp *.tif *.tiff *.jpg *.jpeg"),
    ("Recommended lossless", "*.png *.bmp *.tif *.tiff"),
    ("All files", "*.*"),
)

APP_HOME = Path.home() / "SITAS_Watermark"
OUTPUT_DIR = APP_HOME / "outputs"
REPORT_DIR = APP_HOME / "reports"


def load_rgb(path: Path) -> np.ndarray:
    with Image.open(path) as image:
        image.load()
        return np.array(image.convert("RGB"), dtype=np.uint8)


def image_info(path: Path) -> dict[str, object]:
    with Image.open(path) as image:
        image.load()
        return {
            "文件名": path.name,
            "格式": image.format,
            "模式": image.mode,
            "宽度": image.width,
            "高度": image.height,
            "文件大小": f"{path.stat().st_size / 1024:.1f} KB",
        }


def overlay_damage(rgb: np.ndarray, damaged_pixels: np.ndarray, opacity: int = 135) -> Image.Image:
    base = Image.fromarray(rgb.astype(np.uint8), mode="RGB").convert("RGBA")
    overlay = Image.new("RGBA", base.size, (0, 0, 0, 0))
    overlay_arr = np.array(overlay)
    overlay_arr[damaged_pixels] = [255, 45, 45, max(0, min(255, int(opacity)))]
    return Image.alpha_composite(base, Image.fromarray(overlay_arr, mode="RGBA"))


class SitasWatermarkApp(tk.Tk):
    def __init__(self, initial_image: Path | None = None) -> None:
        super().__init__()
        self.title("SITAS Authenticity Studio")
        self.geometry("1240x800")
        self.minsize(1040, 680)

        self.current_image: Path | None = None
        self.rgb_array: np.ndarray | None = None
        self.verify_result: dict[str, object] | None = None
        self.preview_photo: ImageTk.PhotoImage | None = None
        self.preview_scale = 1.0
        self.preview_offset_x = 0
        self.preview_offset_y = 0

        self.key_var = tk.StringVar(value="")
        self.key_visible_var = tk.BooleanVar(value=False)
        self.view_mode_var = tk.StringVar(value="叠加图")
        self.opacity_var = tk.IntVar(value=135)
        self.status_var = tk.StringVar(value="选择一张 PNG/BMP/TIFF 图片开始")
        self.file_var = tk.StringVar(value="尚未选择图片")
        self.metrics_var = tk.StringVar(value="等待验证")

        self._configure_style()
        self._build_layout()

        if initial_image:
            self.after(100, lambda: self.open_path(initial_image))

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Root.TFrame", background="#f6f8fb")
        style.configure("Panel.TFrame", background="#ffffff")
        style.configure("Sidebar.TFrame", background="#0f172a")
        style.configure("SidebarTitle.TLabel", background="#0f172a", foreground="#ffffff", font=("Arial", 18, "bold"))
        style.configure("SidebarText.TLabel", background="#0f172a", foreground="#cbd5e1", font=("Arial", 11))
        style.configure("Card.TLabelframe", background="#ffffff", bordercolor="#d9e2ec")
        style.configure("Card.TLabelframe.Label", background="#ffffff", foreground="#0f172a", font=("Arial", 12, "bold"))
        style.configure("Hero.TLabel", background="#ffffff", foreground="#0f172a", font=("Arial", 18, "bold"))
        style.configure("Hint.TLabel", background="#ffffff", foreground="#64748b")
        style.configure("Status.TLabel", background="#e8eef7", foreground="#334155", padding=(12, 8))
        style.configure("Primary.TButton", font=("Arial", 11, "bold"))
        style.configure("Danger.TLabel", background="#fff1f2", foreground="#9f1239", padding=(10, 6))
        style.configure("Success.TLabel", background="#ecfdf5", foreground="#047857", padding=(10, 6))

    def _build_layout(self) -> None:
        root = ttk.Frame(self, style="Root.TFrame")
        root.pack(fill=tk.BOTH, expand=True)

        sidebar = ttk.Frame(root, style="Sidebar.TFrame", padding=(20, 20))
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.configure(width=280)
        sidebar.pack_propagate(False)

        ttk.Label(sidebar, text="SITAS", style="SidebarTitle.TLabel").pack(anchor=tk.W)
        ttk.Label(sidebar, text="图像真实性认证工具", style="SidebarText.TLabel").pack(anchor=tk.W, pady=(2, 20))

        ttk.Button(sidebar, text="选择图片", command=self.choose_image, style="Primary.TButton").pack(fill=tk.X, pady=(0, 10))
        ttk.Button(sidebar, text="生成认证图片", command=self.embed_current_image).pack(fill=tk.X, pady=(0, 10))
        ttk.Button(sidebar, text="验证当前图片", command=self.verify_current_image).pack(fill=tk.X, pady=(0, 10))
        ttk.Button(sidebar, text="导出验证报告", command=self.export_report).pack(fill=tk.X, pady=(0, 10))
        ttk.Button(sidebar, text="打开输出目录", command=self.open_output_folder).pack(fill=tk.X, pady=(0, 20))

        ttk.Label(sidebar, text="密钥", style="SidebarText.TLabel").pack(anchor=tk.W, pady=(6, 4))
        self.key_entry = ttk.Entry(sidebar, textvariable=self.key_var, show="*", width=24)
        self.key_entry.pack(fill=tk.X)
        ttk.Checkbutton(sidebar, text="显示密钥", variable=self.key_visible_var, command=self.toggle_key_visibility).pack(anchor=tk.W, pady=(6, 12))

        ttk.Label(sidebar, text="显示模式", style="SidebarText.TLabel").pack(anchor=tk.W, pady=(8, 4))
        for mode in ("叠加图", "热力图", "原图"):
            ttk.Radiobutton(sidebar, text=mode, value=mode, variable=self.view_mode_var, command=self.render_preview).pack(anchor=tk.W)

        ttk.Label(sidebar, text="红色透明度", style="SidebarText.TLabel").pack(anchor=tk.W, pady=(14, 4))
        opacity = ttk.Scale(sidebar, from_=45, to=220, variable=self.opacity_var, command=lambda _v: self.render_preview())
        opacity.pack(fill=tk.X)

        ttk.Label(
            sidebar,
            text="技术路线：像素内容 + 坐标 + 通道 + 密钥共同生成 LSB 校验位。图片被改动，校验位就会失配。",
            style="SidebarText.TLabel",
            wraplength=230,
            justify=tk.LEFT,
        ).pack(side=tk.BOTTOM, anchor=tk.W)

        content = ttk.Frame(root, style="Root.TFrame", padding=(18, 18))
        content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        header = ttk.Frame(content, style="Panel.TFrame", padding=(18, 14))
        header.pack(fill=tk.X, pady=(0, 14))
        ttk.Label(header, text="图像水印认证工作台", style="Hero.TLabel").pack(anchor=tk.W)
        ttk.Label(header, textvariable=self.file_var, style="Hint.TLabel").pack(anchor=tk.W, pady=(4, 0))

        body = ttk.PanedWindow(content, orient=tk.HORIZONTAL)
        body.pack(fill=tk.BOTH, expand=True)

        left = ttk.Frame(body, style="Panel.TFrame", padding=12)
        right = ttk.Frame(body, style="Panel.TFrame", padding=12)
        body.add(left, weight=3)
        body.add(right, weight=2)

        canvas_frame = ttk.LabelFrame(left, text="图片预览与篡改定位", style="Card.TLabelframe", padding=10)
        canvas_frame.pack(fill=tk.BOTH, expand=True)
        self.canvas = tk.Canvas(canvas_frame, background="#f8fafc", highlightthickness=1, highlightbackground="#d6dee9")
        self.canvas.pack(fill=tk.BOTH, expand=True)
        self.canvas.bind("<Configure>", lambda _event: self.render_preview())
        self.canvas.bind("<Motion>", self.on_canvas_motion)

        metrics = ttk.LabelFrame(right, text="认证结果", style="Card.TLabelframe", padding=12)
        metrics.pack(fill=tk.X)
        self.result_badge = ttk.Label(metrics, text="未验证", style="Danger.TLabel")
        self.result_badge.pack(fill=tk.X)
        ttk.Label(metrics, textvariable=self.metrics_var, style="Hint.TLabel", wraplength=380, justify=tk.LEFT).pack(fill=tk.X, pady=(12, 0))

        info = ttk.LabelFrame(right, text="图片信息", style="Card.TLabelframe", padding=12)
        info.pack(fill=tk.X, pady=(14, 0))
        self.info_text = tk.Text(info, height=8, wrap=tk.WORD, font=("Menlo", 11), background="#ffffff", relief=tk.FLAT)
        self.info_text.pack(fill=tk.X)
        self.info_text.configure(state=tk.DISABLED)

        details = ttk.LabelFrame(right, text="详细数据", style="Card.TLabelframe", padding=12)
        details.pack(fill=tk.BOTH, expand=True, pady=(14, 0))
        self.detail_text = tk.Text(details, wrap=tk.WORD, font=("Menlo", 11), background="#ffffff", relief=tk.FLAT)
        self.detail_text.pack(fill=tk.BOTH, expand=True)
        self.detail_text.configure(state=tk.DISABLED)

        ttk.Label(self, textvariable=self.status_var, style="Status.TLabel", anchor=tk.W).pack(side=tk.BOTTOM, fill=tk.X)

    def toggle_key_visibility(self) -> None:
        self.key_entry.configure(show="" if self.key_visible_var.get() else "*")

    def choose_image(self) -> None:
        filename = filedialog.askopenfilename(title="选择图片", filetypes=IMAGE_TYPES)
        if filename:
            self.open_path(Path(filename))

    def open_path(self, path: Path) -> None:
        try:
            path = path.expanduser().resolve()
            self.current_image = path
            self.rgb_array = load_rgb(path)
            self.verify_result = None
            self.file_var.set(str(path))
            self.status_var.set(f"已载入：{path.name}")
            self.result_badge.configure(text="未验证", style="Danger.TLabel")
            self.metrics_var.set("等待验证。生成认证图片后，请保管好密钥；验证必须使用同一个密钥。")
            self.set_info(json.dumps(image_info(path), ensure_ascii=False, indent=2))
            self.set_detail("当前图片已载入。\n\n建议流程：\n1. 输入密钥\n2. 点击“生成认证图片”\n3. 后续收到图片时，用同一密钥点击“验证当前图片”")
            self.render_preview()
        except Exception as exc:
            messagebox.showerror("读取失败", f"无法读取图片：\n{exc}")
            self.status_var.set("读取失败")

    def embed_current_image(self) -> None:
        if self.current_image is None:
            messagebox.showinfo("还没有图片", "请先选择一张图片。")
            return
        key = self.key_var.get()
        if not key:
            messagebox.showinfo("密钥为空", "请先输入密钥。")
            return
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        output_path = OUTPUT_DIR / f"{self.current_image.stem}_sitas_lsb.png"
        try:
            write_result = embed_lsb_fragile_watermark(self.current_image, output_path, key)
            verify_result = verify_lsb_fragile_watermark(output_path, key)
            self.open_path(output_path)
            self.verify_result = verify_result
            self.update_result_view(verify_result)
            self.set_detail(json.dumps({"write_result": write_result, "verify_result": json_safe_result(verify_result)}, ensure_ascii=False, indent=2))
            self.status_var.set(f"认证图片已生成：{output_path}")
        except Exception as exc:
            messagebox.showerror("生成失败", f"无法生成认证图片：\n{exc}")
            self.status_var.set("生成认证图片失败")

    def verify_current_image(self) -> None:
        if self.current_image is None:
            messagebox.showinfo("还没有图片", "请先选择一张图片。")
            return
        key = self.key_var.get()
        if not key:
            messagebox.showinfo("密钥为空", "请输入写入时使用的同一个密钥。")
            return
        try:
            result = verify_lsb_fragile_watermark(self.current_image, key)
            self.verify_result = result
            self.update_result_view(result)
            self.set_detail(json.dumps(json_safe_result(result), ensure_ascii=False, indent=2))
            self.render_preview()
            self.status_var.set(str(result["message"]))
        except Exception as exc:
            messagebox.showerror("验证失败", f"无法验证图片：\n{exc}")
            self.status_var.set("验证失败")

    def update_result_view(self, result: dict[str, object]) -> None:
        intact = bool(result.get("is_intact"))
        self.result_badge.configure(
            text="认证通过：未发现篡改" if intact else "认证失败：疑似篡改或密钥错误",
            style="Success.TLabel" if intact else "Danger.TLabel",
        )
        self.metrics_var.set(
            f"状态：{result.get('integrity_status')}\n"
            f"可疑像素：{result.get('damaged_pixels')}\n"
            f"失败通道：{result.get('mismatched_channels')} / {result.get('total_channels')}\n"
            f"失败比例：{result.get('mismatch_ratio')}\n"
            f"R/G/B：{result.get('damaged_R_bits')} / {result.get('damaged_G_bits')} / {result.get('damaged_B_bits')}"
        )

    def current_preview_image(self) -> Image.Image | None:
        if self.rgb_array is None:
            return None
        mode = self.view_mode_var.get()
        if self.verify_result is None or mode == "原图":
            return Image.fromarray(self.rgb_array, mode="RGB").convert("RGBA")
        mask = self.verify_result["pixel_mismatch_mask"]
        if mode == "热力图":
            return make_tamper_heatmap(mask).convert("RGBA")  # type: ignore[arg-type]
        return overlay_damage(self.rgb_array, mask, int(self.opacity_var.get()))  # type: ignore[arg-type]

    def render_preview(self) -> None:
        if not hasattr(self, "canvas"):
            return
        self.canvas.delete("all")
        image = self.current_preview_image()
        if image is None:
            self.canvas.create_text(28, 28, anchor=tk.NW, text="选择图片后开始", fill="#64748b", font=("Arial", 14))
            return
        canvas_width = max(1, self.canvas.winfo_width())
        canvas_height = max(1, self.canvas.winfo_height())
        width, height = image.size
        self.preview_scale = max(0.01, min(canvas_width / width, canvas_height / height, 12.0))
        display_width = max(1, int(width * self.preview_scale))
        display_height = max(1, int(height * self.preview_scale))
        self.preview_offset_x = max(0, (canvas_width - display_width) // 2)
        self.preview_offset_y = max(0, (canvas_height - display_height) // 2)
        preview = image.resize((display_width, display_height), Image.Resampling.NEAREST)
        self.preview_photo = ImageTk.PhotoImage(preview)
        self.canvas.create_image(self.preview_offset_x, self.preview_offset_y, anchor=tk.NW, image=self.preview_photo)

    def on_canvas_motion(self, event: tk.Event) -> None:
        if self.rgb_array is None:
            return
        height, width = self.rgb_array.shape[:2]
        x = int((event.x - self.preview_offset_x) / self.preview_scale)
        y = int((event.y - self.preview_offset_y) / self.preview_scale)
        if not (0 <= x < width and 0 <= y < height):
            return
        red, green, blue = self.rgb_array[y, x].tolist()
        lsb = [red & 1, green & 1, blue & 1]
        damaged = False
        channels: list[str] = []
        if self.verify_result is not None:
            pixel_mask = self.verify_result.get("pixel_mismatch_mask")
            channel_mask = self.verify_result.get("channel_mismatch_mask")
            if isinstance(pixel_mask, np.ndarray):
                damaged = bool(pixel_mask[y, x])
            if isinstance(channel_mask, np.ndarray):
                flags = channel_mask[y, x].tolist()
                channels = [name for idx, name in enumerate(("R", "G", "B")) if flags[idx]]
        self.status_var.set(f"x={x}, y={y} | RGB=({red}, {green}, {blue}) | LSB={lsb} | 可疑={damaged} | 通道={channels or '-'}")

    def export_report(self) -> None:
        if self.current_image is None or self.verify_result is None:
            messagebox.showinfo("还没有验证结果", "请先验证当前图片。")
            return
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = REPORT_DIR / f"{self.current_image.stem}_{stamp}"
        json_path = base.with_suffix(".json")
        heatmap_path = REPORT_DIR / f"{base.name}_heatmap.png"
        overlay_path = REPORT_DIR / f"{base.name}_overlay.png"
        try:
            json_path.write_text(json.dumps(json_safe_result(self.verify_result), ensure_ascii=False, indent=2), encoding="utf-8")
            mask = self.verify_result["pixel_mismatch_mask"]
            make_tamper_heatmap(mask).save(heatmap_path, format="PNG")  # type: ignore[arg-type]
            overlay_damage(self.rgb_array, mask).save(overlay_path, format="PNG")  # type: ignore[arg-type]
            messagebox.showinfo("导出完成", f"报告：\n{json_path}\n\n热力图：\n{heatmap_path}\n\n叠加图：\n{overlay_path}")
            self.status_var.set(f"报告已导出：{REPORT_DIR}")
        except Exception as exc:
            messagebox.showerror("导出失败", f"无法导出报告：\n{exc}")

    def open_output_folder(self) -> None:
        APP_HOME.mkdir(parents=True, exist_ok=True)
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        webbrowser.open(APP_HOME.resolve().as_uri())

    def set_info(self, text: str) -> None:
        self.info_text.configure(state=tk.NORMAL)
        self.info_text.delete("1.0", tk.END)
        self.info_text.insert("1.0", text)
        self.info_text.configure(state=tk.DISABLED)

    def set_detail(self, text: str) -> None:
        self.detail_text.configure(state=tk.NORMAL)
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert("1.0", text)
        self.detail_text.configure(state=tk.DISABLED)


def main() -> int:
    initial = Path(sys.argv[1]).expanduser() if len(sys.argv) > 1 else None
    app = SitasWatermarkApp(initial)
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
