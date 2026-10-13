$ErrorActionPreference = "Stop"

$RootDir = Resolve-Path (Join-Path $PSScriptRoot "..")
$AppName = "SITAS Image Security Workbench"
$Python = Join-Path $RootDir ".venv\Scripts\python.exe"

if (!(Test-Path $Python)) {
  py -3 -m venv (Join-Path $RootDir ".venv")
  $Python = Join-Path $RootDir ".venv\Scripts\python.exe"
}

& $Python -m pip install --upgrade pip
& $Python -m pip install -r (Join-Path $RootDir "requirements.txt")
& $Python -m pip install pyinstaller

& $Python -m PyInstaller `
  --noconfirm `
  --windowed `
  --onefile `
  --name "SITAS-Image-Security-Workbench" `
  --distpath (Join-Path $RootDir "dist-windows") `
  --workpath (Join-Path $RootDir "build-windows") `
  --specpath (Join-Path $RootDir "packaging") `
  --icon (Join-Path $RootDir "assets\sitas_logo_icon.ico") `
  --add-data "$RootDir\assets;assets" `
  (Join-Path $RootDir "scripts\image_info_gui.py")

Write-Host "Windows EXE generated at:" (Join-Path $RootDir "dist-windows\SITAS-Image-Security-Workbench.exe")
