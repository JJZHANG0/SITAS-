#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

APP_NAME="SITAS Image Security Workbench"
DIST_DIR="$ROOT_DIR/dist"
STAGE_DIR="$ROOT_DIR/packaging/macos_dmg_stage"
DMG_PATH="$DIST_DIR/SITAS-Image-Security-Workbench-macOS.dmg"

"$ROOT_DIR/.venv/bin/python" -m PyInstaller \
  --noconfirm \
  --windowed \
  --name "$APP_NAME" \
  --distpath "$DIST_DIR" \
  --workpath "$ROOT_DIR/build" \
  --specpath "$ROOT_DIR/packaging" \
  --icon "$ROOT_DIR/assets/sitas_logo_icon.icns" \
  --add-data "$ROOT_DIR/assets:assets" \
  "$ROOT_DIR/scripts/image_info_gui.py"

plutil -replace NSCameraUsageDescription \
  -string "SITAS needs camera access to preview and capture microscope images from a connected USB camera." \
  "$DIST_DIR/$APP_NAME.app/Contents/Info.plist"

"$ROOT_DIR/.venv/bin/python" - <<PY
from pathlib import Path
import shutil

stage = Path("$STAGE_DIR")
dmg = Path("$DMG_PATH")
if stage.exists():
    shutil.rmtree(stage)
stage.mkdir(parents=True, exist_ok=True)
if dmg.exists():
    dmg.unlink()
shutil.copytree(Path("$DIST_DIR") / "$APP_NAME.app", stage / "$APP_NAME.app")
PY

ln -s /Applications "$STAGE_DIR/Applications"
hdiutil create -volname "$APP_NAME" -srcfolder "$STAGE_DIR" -ov -format UDZO "$DMG_PATH"

echo "$DMG_PATH"
