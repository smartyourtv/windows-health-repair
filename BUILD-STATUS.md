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
