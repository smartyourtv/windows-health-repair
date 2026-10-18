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
- [x] GitHub push (2026-10-17, Contents API, same route as v1):
      windows_health.py, README.md, BUILD-STATUS.md updated and all 7
      packaging/ files created — read-back verified byte-identical,
      head commits 18911801 (app) / 470a89e1 (template notes).
- [!] Workflow file push BLOCKED: .github/workflows/build-installer.yml
      returns HTTP 404 via both Contents and Git Data APIs — the stored
      GitHub credential lacks the `workflow` scope (same known limit
      as scout-android-source). The file is ready locally and inside
      windows-health-repair-easy-install.zip. One manual step unblocks
      CI: on github.com, Add file → Create new file →
      .github/workflows/build-installer.yml, paste the zipped copy,
      commit — then Actions → Build Windows installer → Run workflow.
      workflow_dispatch could not be triggered before that (workflow
      must exist on the default branch first).
- [ ] First Windows build: trigger the workflow after the step above; a Setup.exe
      exists only once that run (or a Windows PC build) completes —
      PyInstaller does not cross-compile from this Linux VM and no exe
      was faked locally. Then the README's Windows-only installer
      verification list (non-admin install, SmartScreen step, admin
      relaunch, monthly task on the exe, uninstall).

## v1.1.0 — troubleshooter + preventative scans (2026-10-17)
Per Shawn: the app should systematically troubleshoot an issue until
it finds the cause, fix it if it safely can, explain step-by-step
when it can't, and run preventative scans. Plus his v1.0.0 report
that he could NOT see the Defender tie-in or the Malwarebytes
suggestion on his PC — audited first, then made unmistakable
(full findings in docs/AUDITS.md, v1.1.0 sections A/B/C).

- [x] Security restructure: the scan's Security section now leads
      with a one-line plain-language Defender summary (RTP, signature
      VERSION + age, last scans, threat count); signature update is
      ALWAYS offered (was: only when signatures were >2 days old —
      why a healthy PC showed almost nothing); a new "Open Windows
      Security" action; the Malwarebytes card sits directly under
      the summary (installed → launch via a broader search incl.
      standard install paths; absent → suggestion + official-page
      button). Each sub-part is isolated: a failure in one no longer
      collapses the whole section into one vague row, and PowerShell
      output noise can no longer break the Defender JSON parse.
- [x] Troubleshooter: 7 problem areas (slow/startup, crashes &
      freezes, network, sound, Windows Update, disk/storage,
      security) driven by 33 ordered real checks (cheap → deep) over
      probe methods that never invent results. Exactly three honest
      outcomes: fixable (restores behind the existing hard gate,
      then VERIFIED by re-running the failing check), guided
      (step-by-step guide screen, copyable), not-found (what was
      ruled out + next manual steps). GUI window runs checks on a
      worker thread with live evidence.
- [x] New safe fixes: wu_reset (WU cache rename-aside backup, never
      deleted), dns_flush (verified by a follow-up lookup),
      service_start (pre-state saved to backups/ first). Existing
      3-class registry rules and net_reset (warning, opt-in only)
      untouched.
- [x] Preventative scans: SMART PredictFailure (WMI), free-space
      level + change, Defender state/signature age, firewall,
      pending-update count, startup-item additions, event-log
      patterns (disk/WHEA/service failures with thresholds), newest
      restore-point age. History in preventative-history.json
      (last 24); "what changed / what needs attention" in the GUI and
      in the headless --scan-only report; every attention item
      routes into the troubleshooter ("Troubleshoot this").
- [x] Auto-check frequency: user picks Weekly or Monthly (monthly
      default; same task name, re-registered when changed while on).
- [x] Version 1.1.0 (APP_VERSION + packaging config/version_info).
- [x] Tests: 96/96 unit (59 baseline preserved + 37 new), self-test
      40/40 (30 + 10 new), packaging validation 42/42.
- [x] CI build + release + Drive update (2026-10-17 evening):
      workflow run 39090368640 SUCCESS (test gate: 96 unit +
      40 self-test on windows-latest). Release v1.1.0 published:
      WindowsHealthRepair-Setup.exe 13,455,039 B (SHA-256
      00ca715f…), WindowsHealthRepair.exe 11,716,773 B. Drive copy
      updated IN PLACE (file ID 1dyC6B82FdFntVJVbQnFlXj3n9KoVtDe_,
      so Shawn's existing link now serves v1.1.0) — Drive size
      13,455,039 B and MD5 225a35a30e9107727ff362d2aa9f1fd7 both
      match the release asset/local download exactly.
- [ ] Real-Windows verification still owed (Shawn's PC): Defender
      summary/actions live, Malwarebytes card, troubleshooter
      windows, preventative scan, weekly/monthly task firing.

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
