#!/usr/bin/env python3
"""Validate the easy-install packaging WITHOUT a Windows machine.

PyInstaller does not cross-compile and Inno Setup is Windows-only, so
on Linux/macOS this is as far as validation honestly goes:

  * app-config.json parses, has every required key, and its version
    matches APP_VERSION in the app source;
  * naming follows the standing rule (``<App>-Setup.exe`` installer);
  * pyinstaller.spec and version_info.txt compile as Python, and the
    version-info numbers match the config version;
  * setup.iss carries the per-user contract (lowest privileges,
    {localappdata} install dir, Start Menu + desktop icons, uninstall);
  * the GitHub Actions workflow parses as YAML (when PyYAML is
    present) and contains the required build steps.

Exit 0 = all checks passed (skips are reported, never hidden).

Usage: python packaging/validate_packaging.py [repo_root]
"""

import json
import os
import re
import sys

REQUIRED_CONFIG_KEYS = [
    "app_id", "app_name", "display_name", "exe_name", "setup_name",
    "source_file", "version", "publisher", "install_folder",
]

GUID_RE = re.compile(
    r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")


def main():
    root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1
                           else os.path.join(os.path.dirname(__file__),
                                             ".."))
    pkg = os.path.join(root, "packaging")
    results = []

    def check(name, ok, note=""):
        results.append((name, bool(ok), note))

    def skip(name, note):
        results.append((name, None, note))

    # --- config -----------------------------------------------------
    cfg = None
    try:
        with open(os.path.join(pkg, "app-config.json"),
                  encoding="utf-8") as fh:
            cfg = json.load(fh)
        check("app-config.json parses", True)
    except Exception as exc:  # noqa: BLE001 - report any parse failure
        check("app-config.json parses", False, str(exc))
    if cfg is None:
        return report(results)

    for key in REQUIRED_CONFIG_KEYS:
        check("config has %s" % key, bool(cfg.get(key)))
    check("config app_id is a GUID", bool(GUID_RE.match(
        str(cfg.get("app_id", "")))))
    check("exe_name ends .exe", str(cfg.get("exe_name", ""))
          .endswith(".exe"))
    check("setup_name is <App>-Setup.exe",
          str(cfg.get("setup_name", "")).endswith("-Setup.exe"))
    check("exe and setup names differ",
          cfg.get("exe_name") != cfg.get("setup_name"))

    # --- config vs app source ---------------------------------------
    src_path = os.path.join(root, cfg.get("source_file", ""))
    src = ""
    if os.path.exists(src_path):
        with open(src_path, encoding="utf-8") as fh:
            src = fh.read()
        m = re.search(r'APP_VERSION\s*=\s*"([^"]+)"', src)
        check("config version == APP_VERSION in source",
              bool(m) and m.group(1) == cfg.get("version"),
              "source=%s config=%s" % (m.group(1) if m else "?",
                                       cfg.get("version")))
        check("source honours frozen app_dir() contract",
              "is_frozen" in src and "sys.frozen" in src
              and "sys.executable" in src)
    else:
        check("source file exists", False, src_path)

    # --- PyInstaller spec + version info -----------------------------
    for name in ("pyinstaller.spec", "version_info.txt"):
        path = os.path.join(pkg, name)
        try:
            with open(path, encoding="utf-8") as fh:
                compile(fh.read(), name, "exec")
            check("%s compiles as Python" % name, True)
        except Exception as exc:  # noqa: BLE001
            check("%s compiles as Python" % name, False, str(exc))
    try:
        with open(os.path.join(pkg, "version_info.txt"),
                  encoding="utf-8") as fh:
            vi = fh.read()
        nums = tuple(int(p) for p in str(cfg["version"]).split("."))
        nums = nums + (0,) * (4 - len(nums))
        needle = ("filevers=%s" % (nums,)).replace(" ", "")
        check("version_info filevers matches config",
              needle in vi.replace(" ", ""))
    except Exception as exc:  # noqa: BLE001
        check("version_info filevers matches config", False, str(exc))
    with open(os.path.join(pkg, "pyinstaller.spec"),
              encoding="utf-8") as fh:
        spec = fh.read()
    check("spec is windowed-capable (console flag from config)",
          "console=not _windowed" in spec)
    check("spec disables UPX (AV false positives)", "upx=False" in spec)

    # --- Inno Setup script -------------------------------------------
    with open(os.path.join(pkg, "setup.iss"), encoding="utf-8") as fh:
        iss = fh.read()
    for token, label in (
            ("PrivilegesRequired=lowest", "per-user (no admin) install"),
            ("{localappdata}\\Programs", "installs under LocalAppData"),
            ("[Icons]", "shortcut section present"),
            ("{group}", "Start Menu shortcut"),
            ("{autodesktop}", "desktop shortcut"),
            ("UninstallDisplayName", "uninstaller in Settings > Apps"),
            ("OutputBaseFilename", "named installer output")):
        check("setup.iss: %s" % label, token in iss)
    check("setup.iss: values are /D-overridable defines",
          iss.count("#ifndef") >= 7 and iss.count("#define") >= 7)
    # Inno Setup 6 rejects any OverridesAllowed value other than
    # "commandline"/"dialog" at compile time (CI failure 2026-10-17);
    # local validation missed it once, so guard it here.
    import re as _re
    _ovr = _re.search(r"(?m)^PrivilegesRequiredOverridesAllowed\s*=\s*(\S.*)$",
                      iss)
    check("setup.iss: PrivilegesRequiredOverridesAllowed value is valid",
          _ovr is None or
          set(_ovr.group(1).lower().replace(",", " ").split()) <=
          {"commandline", "dialog"})

    # --- PowerShell build script -------------------------------------
    ps1_path = os.path.join(pkg, "build-installer.ps1")
    check("build-installer.ps1 exists", os.path.exists(ps1_path))
    if os.path.exists(ps1_path):
        with open(ps1_path, encoding="utf-8") as fh:
            ps1 = fh.read()
        check("build script reads app-config.json",
              "app-config.json" in ps1)
        check("build script has a test gate", "unittest" in ps1)

    # --- GitHub Actions workflow --------------------------------------
    wf = os.path.join(root, ".github", "workflows",
                      "build-installer.yml")
    check("workflow exists", os.path.exists(wf))
    if os.path.exists(wf):
        with open(wf, encoding="utf-8") as fh:
            wf_text = fh.read()
        for token, label in (
                ("windows-latest", "runs on a Windows runner"),
                ("3.12", "Python 3.12"),
                ("pyinstaller", "installs PyInstaller"),
                ("ISCC", "compiles with Inno Setup"),
                ("upload-artifact", "uploads artifacts"),
                ("action-gh-release", "attaches to releases"),
                ("workflow_dispatch", "manually dispatchable")):
            check("workflow: %s" % label, token in wf_text)
        try:
            import yaml  # optional; not a build dependency
            yaml.safe_load(wf_text)
            check("workflow is valid YAML", True)
        except ImportError:
            skip("workflow is valid YAML", "PyYAML not installed here")
        except Exception as exc:  # noqa: BLE001
            check("workflow is valid YAML", False, str(exc))

    return report(results)


def report(results):
    failed = 0
    for name, ok, note in results:
        if ok is None:
            print("  [SKIP] %s%s" % (name, (" - " + note) if note else ""))
        else:
            print("  [%s] %s%s" % ("PASS" if ok else "FAIL", name,
                                   (" - " + note) if note else ""))
            failed += 0 if ok else 1
    print("Packaging validation: %d passed, %d failed, %d skipped"
          % (sum(1 for _, ok, _ in results if ok is True), failed,
             sum(1 for _, ok, _ in results if ok is None)))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
