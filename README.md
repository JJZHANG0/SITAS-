# SITAS Image Security Workbench

SITAS is a Python desktop application for inspecting image metadata and RGB data, embedding visible and LSB fragile watermarks, and visualizing integrity checks.

## Requirements

- Python 3.10 or newer
- Tk support in the Python installation

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

On Windows, activate the environment with `.venv\\Scripts\\activate`.

## Run

```bash
python scripts/image_info_gui.py
```

To inspect an image at startup:

```bash
python scripts/image_info_gui.py path/to/image.png
```

The optional USB camera feature uses OpenCV. The ESP32 Wi-Fi camera path expects an ESP32-S3 running the companion Arduino firmware and reachable at `http://192.168.4.1`.

## Build installers

Packaging scripts and PyInstaller specifications are in `packaging/`.
