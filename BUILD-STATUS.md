# Windows Health & Repair — BUILD STATUS

Task started 2026-10-16 (Fri evening, PDT). v1 scope per Shawn's request:
scan + report, user-checked fixes only, conservative registry module,
Microsoft's own repair machinery (SFC/DISM), restore-point hard gate.
Added same evening at Shawn's direction: security posture section
(Defender/firewall audit + opt-in Quick Scan; no homemade AV),
Malwarebytes detect/launch-or-official-download-button (never bundled),
and the over-the-top set — PC Health Certificate, monthly auto-check
(opt-in, scan-only), driver backup, boot-time report,
installed-programs audit — plus safe driver search/install via the
Windows Update Agent API only.

## Progress
- [x] docs/AUDITS.md — change-impact + pre-build audits before building,
      plus a 2026-10-16 addendum covering the security section, feature
      pack, and driver installs
- [x] windows_health.py — main app (scan / fix / GUI / --self-test /
      --scan-only), stdlib only
- [x] start-windows-health.bat — double-click launcher with Python check
- [x] tests/ — unittest suite with recorded fixtures
- [x] py_compile clean; **59/59 unit tests pass; --self-test 30/30 pass**;
      --scan-only degrades honestly on non-Windows (exit 2, nothing faked)
- [x] README.md
- [x] GitHub: new public repo smartyourtv/windows-health-repair — created,
      8 files uploaded via Contents API, read-back verified (repo public,
      HTML page confirmed HTTP 200)
- [x] Google Drive: windows-health-repair-v1.zip uploaded
      (file ID 1QVYz3oIOzcBFCdLMpw7Cbm1W1gEZ-19e) —
      https://drive.google.com/file/d/1QVYz3oIOzcBFCdLMpw7Cbm1W1gEZ-19e/view?usp=drivesdk

## Bugs the tests caught (fixed, regression-covered)
- SFC/DISM parsers: result sentences that wrap across console lines
  ("unable to fix\nsome of them") parsed as "unknown" — whitespace now
  collapsed before matching. This was the single most important SFC
  result (unfixed corruption) being missed.
- Certificate HTML builder crashed on CSS `width:100%` under
  %-formatting — escaped.
- Defender parser treated an empty `{}` status as present — now absent.
- `__main__` block sat mid-file after appended feature code — moved to
  the true end of file.
- cmd_scan_only passed a path string as RunLog's sink — fixed.

## Easy-install packaging (2026-10-17)
Shawn: "I want something easy to install" — and the Setup.exe shape is
now the standing rule for EVERY Windows app we build (packaging kept
reusable as a template, not a one-off; see packaging/TEMPLATE-NOTES.md).

- [x] Packaging audit (change-impact + pre-build mindset): stdlib-only
      confirmed — top-level imports are argparse/ctypes/datetime/json/
      os/re/subprocess/sys/threading; tkinter is imported lazily inside
      launch_gui(). Entry points verified on Linux: --version prints
      "Windows Health & Repair 1.0.0", --self-test 30/30 PASS,
      --scan-only degrades honestly (exit 2 off-Windows). Admin model:
      installer is per-user (no admin to install); the app itself still
      offers "Relaunch as admin" for fixes. No icon ships (no .ico in
      repo) — exe/installer use default PyInstaller/Inno icons,
      cosmetic only. Blast radius: packaging/ + workflow + docs, plus
      the frozen shims below. No scan/fix logic touched.
- [x] Frozen-compat shims in windows_health.py (branch ONLY on
      sys.frozen; Python behaviour unchanged, tests still 59/59):
      app_dir() resolves next to sys.executable when frozen (onefile
      __file__ lives in a temp unpack dir that vanishes — logs/backups/
      reports/history would be lost there); relaunch_admin() passes no
      .py script arg when frozen; monthly_register() registers
      '"<exe>" --scan-only' when frozen. Without these the built exe
      would have broken data storage, admin relaunch, and the monthly
      check. No GUI-contract strings changed.
- [x] packaging/app-config.json — single source of truth (names,
      version 1.0.0, fresh AppId GUID, source file); all other
      packaging files read from it.
- [x] packaging/pyinstaller.spec — generic; one-file, windowed,
      UPX off (AV false positives), tkinter hidden imports,
      version_info.txt wired, app.ico used if ever added.
- [x] packaging/version_info.txt — 1.0.0, matches APP_VERSION.
- [x] packaging/setup.iss — generic Inno Setup; every value a
      /D-overridable define; PrivilegesRequired=lowest;
      {localappdata}\Programs\WindowsHealthRepair; Start Menu +
      optional Desktop shortcut; standard uninstaller.
- [x] packaging/build-installer.ps1 — test gate → PyInstaller →
      exe smoke test (exit codes) → ISCC. Same path locally and in CI.
- [x] packaging/validate_packaging.py — 41/41 PASS on Linux
      (config/spec/ISS/workflow consistency, YAML valid).
- [x] .github/workflows/build-installer.yml — windows-latest,
      Python 3.12, reads app-config.json, test gate, PyInstaller,
      Inno Setup (preinstalled; choco fallback), uploads exe +
      Setup.exe artifacts, attaches both to a Release on v* tags or
      workflow_dispatch with a release_tag input.
- [ ] First Windows build: trigger the workflow after push; a Setup.exe
      exists only once that run (or a Windows PC build) completes —
      PyInstaller does not cross-compile from this Linux VM and no exe
      was faked locally. Then the README's Windows-only installer
      verification list (non-admin install, SmartScreen step, admin
      relaunch, monthly task on the exe, uninstall).

## Notes
- Sandbox is Linux: all Windows execution paths degrade to honest
  NEEDS-WINDOWS states; parsers/logic are what get tested here.
- Delivery pattern matches the other Windows tools (usb-prep): Python +
  Tkinter + .bat launcher, admin-aware, resizable window
  (resizable(True, True), minsize 900x600 — GUI-contract test asserts it).
- Driver installs: WU-Agent-only source, per-driver opt-in, gated on
  restore point + same-run driver backup, one-at-a-time, one failure
  stops the queue — gates unit-tested with mocked executors.
- Windows-only-to-verify list is in the README.
