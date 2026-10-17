# Packaging template — how every Windows app gets its Setup.exe

Standing rule (Shawn, 2026-10-17): **every Windows app we build ships
as one easy installer** — a single `*-Setup.exe`: PyInstaller
single-file exe + Inno Setup, per-user install (no admin needed to
install), no Python prerequisite for the user, Start Menu + Desktop
shortcut, uninstaller in Settings → Apps. The Python + `.bat` path is
a developer fallback only, never the user delivery.

This folder is the reusable template. Windows Health & Repair is the
first conversion; usb-prep / Scout laptop tools, the Tiara kit, and
future Windows apps copy this setup unchanged except for names.

## Files

| File | What it is |
|---|---|
| `app-config.json` | **Single source of truth** for every per-app value (names, version, GUID, source file). All other files read from it. |
| `pyinstaller.spec` | Generic PyInstaller spec: one-file, windowed (per config), UPX off, lazy-`tkinter` hidden imports, version info + icon wired if present. |
| `version_info.txt` | Windows version resource stamped into the exe. |
| `setup.iss` | Generic Inno Setup script. Every value is a `#define` with a default, overridable via `ISCC /DName=Value`. Per-user (`PrivilegesRequired=lowest`), installs to `{localappdata}\Programs\<folder>`. |
| `build-installer.ps1` | One-command Windows build: test gate → PyInstaller → exe smoke test → Inno compile. Used locally *and* by CI so both take the same path. |
| `validate_packaging.py` | Windows-free validation (config/spec/ISS/workflow consistency). Run it anywhere: `python packaging/validate_packaging.py` |
| `../.github/workflows/build-installer.yml` | CI: `windows-latest`, Python 3.12, test gate, PyInstaller, Inno Setup (preinstalled on the runner; chocolatey fallback), artifacts on every run, Release assets on tag push / dispatch with `release_tag`. |

## Reuse checklist for the next app

1. Copy `packaging/` and `.github/workflows/build-installer.yml` into
   the new repo. Nothing app-specific lives outside `app-config.json`
   and `version_info.txt`.
2. Edit `app-config.json` — the only values to change:
   - `app_name`, `display_name`, `exe_name`, `setup_name`
     (installer must stay `<Something>-Setup.exe`),
   - `source_file` (the app's single `.py` file, repo-root relative),
   - `version` (must equal `APP_VERSION` in the source — the
     validator fails the build otherwise),
   - `install_folder`, `publisher`.
   - **`app_id`: generate a NEW GUID** (`python -c "import uuid;
     print(uuid.uuid4())"`). It is the app's uninstall identity in
     Windows; two apps sharing one GUID collide in Settings → Apps.
3. Update `version_info.txt`: `filevers`/`prodvers` tuples,
   `FileVersion`/`ProductVersion`, and the display-name strings.
4. Make the source honour the **frozen-app contract** (Health &
   Repair does; copy its three shims):
   - `app_dir()` returns the folder next to **`sys.executable`** when
     `getattr(sys, "frozen", False)` — under `--onefile`, `__file__`
     points into a temp unpack dir that is deleted on exit, so logs,
     backups, reports and history must never be based on it.
   - "Relaunch as admin" re-runs `sys.executable` with **no** script
     argument when frozen (the exe *is* the program).
   - Any self-invocation you register (e.g. a scheduled
     `--scan-only` task) is `"<exe>" --scan-only` when frozen, not
     `"<python>" "<script.py>" --scan-only`.
   - Non-frozen behaviour must stay byte-for-byte the old behaviour;
     these shims only branch on `sys.frozen`.
5. Icon (optional, cosmetic): drop a real `app.ico` into `packaging/`
   and both the spec and installer pick it up. Without one, Windows
   shows the default PyInstaller/Inno icons — acceptable, but say so
   in the app's BUILD-STATUS instead of implying a custom icon.
6. Run `python packaging/validate_packaging.py`, then the app's own
   tests. Push. Run the workflow (Actions → *Build Windows installer*
   → Run workflow), or push a `v*` tag to also cut a Release.
7. Verify on a real Windows PC (the part CI cannot prove): install
   as a non-admin user, launch from Start Menu + Desktop, exercise
   the app's admin flow, uninstall from Settings → Apps, confirm
   user data folders behave as designed.

## Honest limits

- **Unsigned binaries.** Until a code-signing certificate exists,
  SmartScreen warns on first download/run: **More info → Run
  anyway**. Every app's README documents this; never promise it away.
- **No cross-compiling.** PyInstaller builds only for the OS it runs
  on. A Linux box can validate this packaging (above) but can never
  produce or fake the Windows exe — the build happens in CI or on a
  Windows PC, full stop.
- **Windowed-exe smoke tests check exit codes only.** A
  `--windowed` exe has no console, so `--self-test` prints go
  nowhere; `Start-Process -Wait` + exit code is the check.
