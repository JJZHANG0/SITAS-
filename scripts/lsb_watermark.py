#!/usr/bin/env python3  # 告诉 macOS/Linux 这个文件可以用 Python3 直接运行
"""基于 LSB 脆弱水印的图像篡改检测算法。"""  # 用一句话说明这个脚本的用途

from __future__ import annotations  # 让类型注解在较新语法下更稳定

import argparse  # 导入 argparse，用来做命令行参数解析
import hashlib  # 导入 hashlib，用 SHA256 生成校验位
import json  # 导入 json，用来输出验证结果
from pathlib import Path  # 导入 Path，让文件路径处理更清晰

import numpy as np  # 导入 numpy，用数组方式批量处理 RGB 像素
from PIL import Image  # 导入 Pillow 的 Image，用来读取和保存图片


IMAGE_TYPES = {".png", ".bmp", ".tif", ".tiff"}  # 定义推荐使用的无损图片格式


def is_lossless_like(path: Path) -> bool:  # 定义函数：判断图片扩展名是否像无损格式
    return path.suffix.lower() in IMAGE_TYPES  # 返回扩展名是否在推荐格式集合里


def load_rgb_image(image_path: Path) -> tuple[np.ndarray, str]:  # 定义函数：读取图片为 RGB 数组并返回原模式
    with Image.open(image_path) as image:  # 打开图片文件，并保证用完自动关闭
        image.load()  # 立即把图片内容读入内存，避免文件关闭后再读失败
        source_mode = image.mode  # 记录原始颜色模式，方便写入结果里展示
        rgb = np.array(image.convert("RGB"), dtype=np.uint8)  # 转成 RGB 三通道 uint8 数组
    return rgb, source_mode  # 返回 RGB 数组和原始模式


def save_rgb_image(rgb: np.ndarray, output_path: Path) -> None:  # 定义函数：把 RGB 数组保存成图片
    output_path.parent.mkdir(parents=True, exist_ok=True)  # 确保输出目录存在
    Image.fromarray(rgb.astype(np.uint8), mode="RGB").save(output_path, format="PNG")  # 以 PNG 无损格式保存


def int_to_bytes(value: int) -> bytes:  # 定义函数：把整数转成固定 4 字节
    return int(value).to_bytes(4, "big", signed=False)  # 用大端序保存坐标，保证同样输入同样输出


def make_check_bit(high7_value: int, x: int, y: int, channel: int, key: str) -> int:  # 定义函数：生成 1 个校验位
    digest = hashlib.sha256()  # 创建一个 SHA256 哈希对象
    digest.update(bytes([int(high7_value) & 0x7F]))  # 写入像素分量的高 7 位，绑定内容
    digest.update(int_to_bytes(x))  # 写入 x 坐标，绑定横向位置
    digest.update(int_to_bytes(y))  # 写入 y 坐标，绑定纵向位置
    digest.update(bytes([int(channel) & 0x03]))  # 写入通道编号，区分 R/G/B
    digest.update(key.encode("utf-8"))  # 写入密钥，只有知道密钥的人才能重新生成合法校验位
    return digest.digest()[-1] & 1  # 取 SHA256 最后一个字节的最低位作为校验位


def expected_check_bits(rgb: np.ndarray, key: str) -> np.ndarray:  # 定义函数：计算整张图每个 RGB 分量应该有的校验位
    height, width = rgb.shape[:2]  # 取出图片高度和宽度
    expected = np.zeros((height, width, 3), dtype=np.uint8)  # 创建一个数组保存期望校验位
    high7 = rgb[:, :, :3] >> 1  # 右移 1 位得到高 7 位，忽略当前 LSB
    for y in range(height):  # 遍历每一行
        for x in range(width):  # 遍历这一行里的每一列
            for channel in range(3):  # 遍历 R/G/B 三个通道
                expected[y, x, channel] = make_check_bit(high7[y, x, channel], x, y, channel, key)  # 计算并保存校验位
    return expected  # 返回整张图的期望校验位数组


def embed_lsb_fragile_watermark(input_path: Path, output_path: Path, key: str) -> dict[str, object]:  # 定义函数：写入 LSB 脆弱水印
    rgb, source_mode = load_rgb_image(input_path)  # 读取输入图片为 RGB 数组
    expected = expected_check_bits(rgb, key)  # 根据当前高 7 位、坐标、通道和密钥计算校验位
    watermarked = (rgb & 0xFE) | expected  # 清空每个分量 LSB，再写入对应校验位
    save_rgb_image(watermarked, output_path)  # 把写入水印后的数组保存成 PNG
    height, width = rgb.shape[:2]  # 获取图片尺寸
    return {  # 返回写入过程的摘要信息
        "operation": "embed_lsb_fragile_watermark",  # 记录操作名称
        "source_path": str(input_path.resolve()),  # 记录输入图片路径
        "output_path": str(output_path.resolve()),  # 记录输出图片路径
        "source_mode": source_mode,  # 记录原始图片模式
        "saved_format": "PNG",  # 记录输出格式
        "width": width,  # 记录图片宽度
        "height": height,  # 记录图片高度
        "watermarked_channels": int(width * height * 3),  # 记录写入校验位总数
        "key_required_for_verification": True,  # 提醒验证必须使用同一个密钥
        "lossless_format_recommended": True,  # 提醒推荐无损格式
        "input_format_warning": "" if is_lossless_like(input_path) else "建议使用 PNG/BMP/TIFF；JPEG 等有损格式会破坏 LSB。",  # 给有损格式提示
    }  # 结束摘要字典


def lsb_embedding_change_map(input_path: Path, key: str) -> dict[str, object]:  # 定义函数：预览写入水印会改动哪些 RGB 分量
    rgb, source_mode = load_rgb_image(input_path)  # 读取输入图片为 RGB 数组
    expected = expected_check_bits(rgb, key)  # 计算每个 RGB 分量应该写入的 LSB 校验位
    watermarked = (rgb & 0xFE) | expected  # 生成写入水印后的 RGB 数组，但这里不保存文件
    channel_change_mask = rgb != watermarked  # 找出 R/G/B 哪些分量的数值真的发生了变化
    pixel_change_mask = np.any(channel_change_mask, axis=2)  # 只要某个像素的任一通道变化，就标记该像素
    height, width = rgb.shape[:2]  # 取图片高度和宽度
    total_channels = int(width * height * 3)  # 计算总 RGB 分量数量
    changed_channels = int(channel_change_mask.sum())  # 统计实际发生变化的 RGB 分量数量
    changed_pixels = int(pixel_change_mask.sum())  # 统计实际发生变化的像素数量
    return {  # 返回 GUI 可用的预览结果
        "operation": "lsb_embedding_change_map",  # 记录操作名称
        "image_path": str(input_path.resolve()),  # 记录图片路径
        "source_mode": source_mode,  # 记录原始图片模式
        "width": width,  # 记录图片宽度
        "height": height,  # 记录图片高度
        "total_channels": total_channels,  # 记录总 RGB 分量数量
        "watermarked_channels": total_channels,  # 说明算法会覆盖写入所有 RGB 分量的 LSB
        "changed_channels": changed_channels,  # 记录真正发生数值变化的 RGB 分量数量
        "changed_pixels": changed_pixels,  # 记录真正发生数值变化的像素数量
        "unchanged_channels": int(total_channels - changed_channels),  # 记录校验位刚好相同、数值不用变的分量数量
        "change_ratio": round(changed_channels / total_channels, 6) if total_channels else 0.0,  # 记录实际变化比例
        "changed_R_bits": int(channel_change_mask[:, :, 0].sum()),  # 记录 R 通道实际变化数量
        "changed_G_bits": int(channel_change_mask[:, :, 1].sum()),  # 记录 G 通道实际变化数量
        "changed_B_bits": int(channel_change_mask[:, :, 2].sum()),  # 记录 B 通道实际变化数量
        "pixel_change_mask": pixel_change_mask,  # 返回像素级改动 mask，给 GUI 画图用
        "channel_change_mask": channel_change_mask,  # 返回通道级改动 mask，给鼠标悬停查看用
    }  # 结束结果字典


def verify_lsb_fragile_watermark(image_path: Path, key: str) -> dict[str, object]:  # 定义函数：验证 LSB 脆弱水印
    rgb, source_mode = load_rgb_image(image_path)  # 读取待验证图片为 RGB 数组
    expected = expected_check_bits(rgb, key)  # 按当前高 7 位、坐标、通道和密钥重新计算校验位
    actual = rgb[:, :, :3] & 1  # 读取图片里真实保存的 RGB 最低位
    channel_mismatch_mask = actual != expected  # 比较真实最低位和期望校验位，得到通道级错误位置
    pixel_mismatch_mask = np.any(channel_mismatch_mask, axis=2)  # 任一通道错误，就认为这个像素可疑
    height, width = rgb.shape[:2]  # 取图片尺寸
    total_channels = int(width * height * 3)  # 计算总校验位数量
    mismatched_channels = int(channel_mismatch_mask.sum())  # 计算损坏或不匹配的通道数量
    damaged_pixels = int(pixel_mismatch_mask.sum())  # 计算可疑像素数量
    mismatch_ratio = mismatched_channels / total_channels if total_channels else 0.0  # 计算通道级不匹配比例
    if mismatched_channels == 0:  # 如果没有任何通道不匹配
        status = "complete"  # 状态就是完整
        message = "LSB 脆弱水印完整，未发现篡改。"  # 给用户看的说明
    elif mismatch_ratio >= 0.35:  # 如果不匹配比例非常大
        status = "severely_damaged_or_wrong_key"  # 状态可能是严重损坏或密钥错误
        message = "大量校验位不匹配，可能图片被严重处理、密钥不对，或不是该算法写入的图片。"  # 给用户看的说明
    else:  # 否则就是局部不匹配
        status = "damaged_or_tampered"  # 状态是损坏或疑似篡改
        message = "部分校验位不匹配，疑似发生局部篡改或处理。"  # 给用户看的说明
    samples = mismatch_samples(channel_mismatch_mask)  # 生成前 300 个可疑位置样本
    return {  # 返回验证详情
        "operation": "verify_lsb_fragile_watermark",  # 记录操作名称
        "image_path": str(image_path.resolve()),  # 记录待验证图片路径
        "source_mode": source_mode,  # 记录图片模式
        "width": width,  # 记录图片宽度
        "height": height,  # 记录图片高度
        "is_intact": mismatched_channels == 0,  # 记录是否完整
        "integrity_status": status,  # 记录状态码
        "message": message,  # 记录说明文字
        "total_channels": total_channels,  # 记录总校验位数量
        "mismatched_channels": mismatched_channels,  # 记录不匹配通道数量
        "damaged_pixels": damaged_pixels,  # 记录可疑像素数量
        "mismatch_ratio": round(mismatch_ratio, 6),  # 记录不匹配比例
        "damaged_R_bits": int(channel_mismatch_mask[:, :, 0].sum()),  # 记录 R 通道损坏位数量
        "damaged_G_bits": int(channel_mismatch_mask[:, :, 1].sum()),  # 记录 G 通道损坏位数量
        "damaged_B_bits": int(channel_mismatch_mask[:, :, 2].sum()),  # 记录 B 通道损坏位数量
        "samples_first_300": samples,  # 记录前 300 个可疑像素样本
        "pixel_mismatch_mask": pixel_mismatch_mask,  # 返回像素级 mask，给 GUI 或热力图使用
        "channel_mismatch_mask": channel_mismatch_mask,  # 返回通道级 mask，给鼠标悬停查看 R/G/B 使用
    }  # 结束结果字典


def mismatch_samples(channel_mismatch_mask: np.ndarray, limit: int = 300) -> list[dict[str, object]]:  # 定义函数：提取可疑点样本
    pixel_mismatch_mask = np.any(channel_mismatch_mask, axis=2)  # 先把通道级错误合并成像素级错误
    positions = np.argwhere(pixel_mismatch_mask)  # 找出所有可疑像素坐标
    samples: list[dict[str, object]] = []  # 准备保存样本列表
    for y, x in positions[:limit]:  # 只遍历前 limit 个可疑位置，避免输出太长
        flags = channel_mismatch_mask[y, x].tolist()  # 取出该像素 R/G/B 哪些通道不匹配
        channels = [name for index, name in enumerate(("R", "G", "B")) if flags[index]]  # 把 True 的通道转成人类可读名称
        samples.append({"x": int(x), "y": int(y), "mismatched_channels": channels})  # 保存这个可疑像素
    return samples  # 返回样本列表


def make_tamper_heatmap(pixel_mismatch_mask: np.ndarray) -> Image.Image:  # 定义函数：用 mask 生成黑红二值热力图
    height, width = pixel_mismatch_mask.shape[:2]  # 读取 mask 尺寸
    heatmap = np.zeros((height, width, 3), dtype=np.uint8)  # 创建黑色背景
    heatmap[pixel_mismatch_mask] = [255, 0, 0]  # 把可疑像素标成红色
    return Image.fromarray(heatmap, mode="RGB")  # 转成 PIL 图片并返回


def make_overlay(image_path: Path, pixel_mismatch_mask: np.ndarray) -> Image.Image:  # 定义函数：把红色可疑区域叠加到原图上
    rgb, _source_mode = load_rgb_image(image_path)  # 读取原图 RGB 数组
    base = Image.fromarray(rgb, mode="RGB").convert("RGBA")  # 转成 RGBA，方便叠加半透明红色
    overlay = Image.new("RGBA", base.size, (0, 0, 0, 0))  # 创建透明图层
    overlay_array = np.array(overlay)  # 把透明图层转成 numpy 数组
    overlay_array[pixel_mismatch_mask] = [255, 0, 0, 130]  # 可疑区域设置成半透明红色
    return Image.alpha_composite(base, Image.fromarray(overlay_array, mode="RGBA"))  # 把原图和红色图层合成


def save_heatmap_and_overlay(image_path: Path, result: dict[str, object], heatmap_path: Path | None, overlay_path: Path | None) -> None:  # 定义函数：按需保存热力图和叠加图
    pixel_mismatch_mask = result["pixel_mismatch_mask"]  # 从验证结果里取出像素级错误 mask
    if not isinstance(pixel_mismatch_mask, np.ndarray):  # 检查 mask 类型是否正确
        raise TypeError("pixel_mismatch_mask 必须是 numpy 数组。")  # 类型不对就报错
    if heatmap_path is not None:  # 如果用户要求保存热力图
        heatmap_path.parent.mkdir(parents=True, exist_ok=True)  # 确保热力图输出目录存在
        make_tamper_heatmap(pixel_mismatch_mask).save(heatmap_path, format="PNG")  # 保存黑红热力图
    if overlay_path is not None:  # 如果用户要求保存叠加图
        overlay_path.parent.mkdir(parents=True, exist_ok=True)  # 确保叠加图输出目录存在
        make_overlay(image_path, pixel_mismatch_mask).save(overlay_path, format="PNG")  # 保存半透明红色叠加图


def json_safe_result(result: dict[str, object]) -> dict[str, object]:  # 定义函数：移除不能直接 JSON 序列化的大数组
    return {  # 返回一个普通 JSON 可以保存和显示的字典
        key: value  # 保留每个普通字段
        for key, value in result.items()  # 遍历原始结果里的所有字段
        if key not in {"pixel_mismatch_mask", "channel_mismatch_mask", "pixel_change_mask", "channel_change_mask"}  # 去掉 numpy mask
    }  # 结束字典推导


def build_parser() -> argparse.ArgumentParser:  # 定义函数：创建命令行解析器
    parser = argparse.ArgumentParser(description="LSB 脆弱水印写入与篡改检测")  # 创建主解析器
    subparsers = parser.add_subparsers(dest="command", required=True)  # 创建子命令解析器
    embed_parser = subparsers.add_parser("embed", help="写入 LSB 脆弱水印")  # 创建 embed 子命令
    embed_parser.add_argument("input", type=Path, help="输入图片路径")  # 添加输入图片参数
    embed_parser.add_argument("output", type=Path, help="输出 PNG 图片路径")  # 添加输出图片参数
    embed_parser.add_argument("--key", required=True, help="写入和验证都必须使用的密钥")  # 添加密钥参数
    verify_parser = subparsers.add_parser("verify", help="验证 LSB 脆弱水印")  # 创建 verify 子命令
    verify_parser.add_argument("image", type=Path, help="待验证图片路径")  # 添加待验证图片参数
    verify_parser.add_argument("--key", required=True, help="写入时使用的同一个密钥")  # 添加密钥参数
    verify_parser.add_argument("--heatmap", type=Path, help="可选：保存黑红篡改热力图")  # 添加热力图输出参数
    verify_parser.add_argument("--overlay", type=Path, help="可选：保存红色叠加定位图")  # 添加叠加图输出参数
    return parser  # 返回解析器


def main() -> int:  # 定义命令行入口函数
    parser = build_parser()  # 构建命令行解析器
    args = parser.parse_args()  # 解析用户输入的命令行参数
    if args.command == "embed":  # 如果用户选择写入水印
        result = embed_lsb_fragile_watermark(args.input, args.output, args.key)  # 执行写入
        print(json.dumps(result, ensure_ascii=False, indent=2))  # 打印写入结果
        return 0  # 返回成功状态码
    if args.command == "verify":  # 如果用户选择验证水印
        result = verify_lsb_fragile_watermark(args.image, args.key)  # 执行验证
        save_heatmap_and_overlay(args.image, result, args.heatmap, args.overlay)  # 按需保存热力图和叠加图
        print(json.dumps(json_safe_result(result), ensure_ascii=False, indent=2))  # 打印 JSON 安全的验证结果
        return 0 if result["is_intact"] else 2  # 完整返回 0，不完整返回 2
    return 1  # 理论上不会走到这里，保底返回错误


if __name__ == "__main__":  # 如果这个文件被直接运行
    raise SystemExit(main())  # 调用 main，并把返回值作为进程退出码
