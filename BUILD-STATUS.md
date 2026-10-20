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

## v1.1.1 — in-app updater + crash reports + self-repair (2026-10-17)

Shipped on Shawn's instruction (the standing updater rule,
2026-10-15 — this was the one app missing it). The crash-report
and self-repair standing rules (2026-10-17) arrived while v1.1.1
was still unreleased, so both are folded into this release (not
a separate v1.1.2):

- **In-app updater:** "Check for updates" button + a launch
  check throttled to once a day; queries this repo's GitHub
  releases; ONE subtle notice per version (dismissed = never
  reshown for that version); Update downloads the new
  Setup.exe, verifies it (size always; SHA-256 from the GitHub
  API asset digest — a `.sha256` checksum asset is preferred
  when one is present), then launches the installer and exits.
  Never forced, never silent; every failure is plain-language
  with the release page offered. (A workflow step to attach the
  checksum file was prepared, but the contents API cannot
  write workflow files — no `workflow` scope — so the workflow
  is unchanged and digest verification carries the hash check.)
- **Crash & error reports:** global capture installed at the
  top of main() (sys + threading excepthook, Tk callback
  errors) writes `WindowsHealthRepair-crash-<YYYYMMDD-HHMMSS>.txt`
  to the user's Downloads folder — plain-language summary,
  timestamp, app + Windows version, exception + traceback, log
  tail — synchronously, rate-guarded. In-app "Crash & error
  reports" viewer (list / read / copy-to-share / open / delete)
  in the troubleshooter window style. Never auto-uploaded.
- **Self-repair of the app's own state:** the four JSON stores
  (update state, auto-check, preventative history, scan
  history) load/save through one repairing path — saves keep
  the previous good copy (.bak); corrupt files are restored
  from it, salvaged entry-by-entry, or quarantined (renamed,
  never deleted) and rebuilt from defaults; a repair counts
  only after the store re-reads cleanly, and every attempt is
  logged (repaired / repair-failed) and shown in the reports
  window. Startup clears abandoned update downloads and stray
  temp files; a download that fails verification is deleted
  and reported, never installed.

Tests: **131 unit + 56 self-test + 42 packaging**, all green
(unit: 96 baseline + 13 updater + 10 crash + 12 self-repair;
self-test +16 over the v1.1.0 suite's 40). CI run
**39091702648** (workflow_dispatch, release_tag=v1.1.1)
**SUCCESS** — its gate re-ran unit tests + self-test from
source, built the exe, smoke-tested it (`--version` prints
1.1.1, `--self-test` passes on Windows), compiled the
installer. Release **v1.1.1** published:
WindowsHealthRepair-Setup.exe **14,089,090 B** (SHA-256
b2d6044bdd39f52c31871eb072cb4e220f37e288a82ab850ada67fd13f320da5,
served by GitHub as the asset digest — the hash the in-app
updater verifies against) + WindowsHealthRepair.exe
12,350,974 B. Drive copy updated IN PLACE (same file ID
1dyC6B82FdFntVJVbQnFlXj3n9KoVtDe_, so Shawn's link is
unchanged), size and MD5 verified against the release asset.
Repo head after the v1.1.1 pushes: 0e8168b3 (this addendum's
push follows). Real-Windows behavior (live update check/apply,
a crash file landing in a real Downloads folder, GUI flows)
remains **unverified** — no Windows machine here.

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

---

## v1.2.0 — Defender malware scans + threat history (2026-10-19)

Phase 2 of the Scout security capability (laptop ClamAV = Phase 1,
live in talk.py v1.3.14). Spec: scout-security-troubleshooting-design
Phase 2. Audits: v1.2.0 change-impact + pre-build addenda in
docs/AUDITS.md.

What shipped:
- Full Defender scan set, all through the restore-point-gated fix
  plan: Quick, Full, Custom folder scan (GUI folder picker), and
  Offline Scan — the offline finding states in its title that it
  RESTARTS the PC and in its detail that the app cannot verify it;
  verify_step says the same. Defender refusing to start a scan
  because one is already running surfaces as an honest failure.
- Threat history by name (Get-MpThreat joined onto detections):
  Defender's own state per detection (detected/still needs action,
  cleaned, quarantined, removed, allowed, blocked; unknown codes
  printed raw). Newest 8 shown; a note keeps older counts honest.
- Defender's own threat actions: Remove-MpThreat for anything
  still active (result re-reads the active count), and a standing
  Quarantine/Remove/Allow per named threat via
  Set-MpPreference -ThreatIDDefaultAction_Ids/-Actions (codes read
  back as raw numbers — Defender publishes no name table; refusal
  text names Tamper Protection and offers no workaround).
- Both new fix kinds are OPT_IN (never default-checked). The
  troubleshooter's threats check stays guided and now points at
  these actions. Signature state still shown with its real
  age/source; nothing faked.

Tests: **147 unit** (131 + 16 new TestDefenderScanPhase2) /
**63 self-test** (56 + 7 new: threat names parse, threat status
text is honest, threat default actions parse, defender scan
commands, all four defender scans offered, threat history names +
remove offered, new defender kinds are opt-in and ordered) /
**42 packaging**. Ran green locally; CI reproduced on
windows-latest (run 39380832939, SUCCESS).

Release: GitHub release **v1.2.0** (published, not draft).
WindowsHealthRepair-Setup.exe = **14,115,777 bytes**,
SHA-256 `991a3353c96d6d09995e78a5daf672ef21fc72e14df88d552dd5093dba1fc818`,
MD5 `bc51b274c0e6d7ad217e03193c7f701b` (downloaded and hash-verified
against GitHub's recorded digest). Drive file
`WindowsHealthRepair-Setup.exe` (ID 1dyC6B82FdFntVJVbQnFlXj3n9KoVtDe_)
updated IN PLACE to the same bytes (post-upload size + MD5 verified).

Honest limits: real-Windows behavior is UNVERIFIED until Shawn
installs v1.2.0 on his PC — same status as every prior release of
this app. The per-threat standing-action button copies one action
to every listed threat's ID (labels say "listed threats"); a
strictly per-threat picker is follow-up polish if wanted.

## v1.2.1 — scan-hang fix (2026-10-20)

Forensic fix for the owner's v1.1.1 incident (scan started
2026-10-19 18:06, still "Scanning..." with an empty findings list
at 21:44). Root cause, proven by code inspection + an off-Windows
semantic reproduction: `do_scan`'s nested progress callback was
named `progress`, shadowing the progressbar widget, and its body
subscripted the function object — TypeError on the first callback,
before any check ran, killing the worker thread silently. The same
defect sat in the fix path's progress callback (a fix run would die
identically, before the restore point — fail-safe but broken).
Full write-up: docs/AUDITS.md, 2026-10-20 addendum.

Fixes: both progress callbacks renamed + marshaled to the UI thread
via root.after; run_scan streams findings per check (on_findings)
and the GUI appends them immediately; per-check start/finish log
lines with elapsed times; a 1s watchdog ticker names the running
check + elapsed (scan_status_text); both workers wrapped so an
unexpected failure is logged, crash-reported, dialogued, and always
clears the busy state.

Tests: **154 unit** (147 + 7 new TestScanHangRegression) /
**63 self-test** / **42 packaging** — green locally; CI must
reproduce on windows-latest before release.

Honest limits: not proven on real Windows — the owner's install
(v1.1.1 → v1.2.1 via the in-app updater or the Drive setup file)
remains the test.
