# -*- mode: python ; coding: utf-8 -*-
"""Generic PyInstaller spec for Muse-built Windows apps (REUSABLE).

One spec builds any of our single-file stdlib + Tkinter apps. All
per-app values come from ``app-config.json`` in this folder (single
source of truth), with environment overrides for CI:

    APPBUILD_SOURCE_FILE, APPBUILD_EXE_NAME, APPBUILD_VERSION

Build (from the repo root, on Windows):

    pyinstaller --noconfirm --clean packaging\\pyinstaller.spec ^
        --distpath dist --workpath build\\pyinstaller

Produces a single-file, windowed exe named per config (for this app:
``dist\\WindowsHealthRepair.exe``). No console window. UPX is OFF on
purpose (UPX-packed exes draw antivirus false positives).

Frozen-app contract the source must honour (see TEMPLATE-NOTES.md):
``app_dir()`` must resolve next to the exe when ``sys.frozen`` is set
(PyInstaller unpacks ``__file__`` into a temp dir that vanishes), and
self-relaunch / scheduled-task command lines must not append a
``.py`` script path when frozen.
"""

import json
import os

_spec_dir = os.path.abspath(SPECPATH)  # noqa: F821 - PyInstaller builtin
_repo_root = os.path.dirname(_spec_dir)

_cfg_path = os.path.join(_spec_dir, "app-config.json")
_cfg = {}
if os.path.exists(_cfg_path):
    with open(_cfg_path, "r", encoding="utf-8") as _fh:
        _cfg = json.load(_fh)


def _pick(env_key, cfg_key, default):
    return os.environ.get(env_key) or _cfg.get(cfg_key) or default


_source_file = _pick("APPBUILD_SOURCE_FILE", "source_file", "app.py")
_exe_name = _pick("APPBUILD_EXE_NAME", "exe_name", "App.exe")
_exe_stem = os.path.splitext(_exe_name)[0]
_windowed = _cfg.get("windowed", True)

_source_path = os.path.join(_repo_root, _source_file)
if not os.path.exists(_source_path):
    raise SystemExit("spec: source file not found: %s" % _source_path)

_version_file = os.path.join(_spec_dir, "version_info.txt")
if not os.path.exists(_version_file):
    _version_file = None

_icon_file = os.path.join(_spec_dir, "app.ico")
if not os.path.exists(_icon_file):
    # No custom icon ships yet; PyInstaller's default is used and the
    # Inno installer likewise. Cosmetic only - see TEMPLATE-NOTES.md.
    _icon_file = None

a = Analysis(
    [_source_path],
    pathex=[_repo_root],
    binaries=[],
    datas=[],
    # tkinter is imported lazily (inside the GUI launcher) by our apps,
    # so name it explicitly instead of trusting import scanning alone.
    hiddenimports=[
        "tkinter",
        "tkinter.ttk",
        "tkinter.messagebox",
        "tkinter.scrolledtext",
        "_tkinter",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name=_exe_stem,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=not _windowed,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version=_version_file,
    icon=_icon_file,
)
