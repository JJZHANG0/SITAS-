# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['/Users/jjzhang/Downloads/加密目镜/scripts/image_info_gui.py'],
    pathex=[],
    binaries=[],
    datas=[('/Users/jjzhang/Downloads/加密目镜/assets', 'assets')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='SITAS Image Security Workbench',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['/Users/jjzhang/Downloads/加密目镜/assets/sitas_logo_icon.icns'],
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='SITAS Image Security Workbench',
)
app = BUNDLE(
    coll,
    name='SITAS Image Security Workbench.app',
    icon='/Users/jjzhang/Downloads/加密目镜/assets/sitas_logo_icon.icns',
    bundle_identifier=None,
)
