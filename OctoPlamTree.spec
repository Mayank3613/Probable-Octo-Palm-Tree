# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['app_tray.py'],
    pathex=[],
    binaries=[],
    datas=[('dashboard/dist', 'dashboard/dist'), ('ai-engine/model.joblib', 'ai-engine'), ('local-agent/GeoLite2-City.mmdb', 'local-agent')],
    hiddenimports=['uvicorn', 'fastapi', 'sklearn.ensemble._forest', 'scapy', 'psutil', 'geoip2', 'ipwhois', 'watchdog', 'pystray', 'PIL', 'aiosqlite'],
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
    name='OctoPlamTree',
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
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='OctoPlamTree',
)
