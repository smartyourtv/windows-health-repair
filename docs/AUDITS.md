# Audits — Windows Health & Repair v1

Written BEFORE building, per standing law (change-impact audit first, then
pre-build audit). Dated 2026-10-16.

## 1. Change-impact audit

**What is being built:** a brand-new, self-contained Windows desktop tool
(Python + Tkinter, stdlib only) in `~/workspace/windows-health/`. It scans a
Windows PC with Microsoft's own diagnostic/repair machinery, reports findings
in plain language, and applies ONLY the fixes the user checks off — behind a
hard safety gate (a System Restore point is created first; registry removals
are exported to `.reg` backups first; everything is logged).

**Blast radius:**
- New files only, in a new folder. No existing project, repo, or app is
  modified. The phone Scout app, laptop Scout, Tiara, and Nuri codebases are
  untouched.
- On the user's machine (when he later runs it): the tool can change real
  system state — that is its purpose. The impact is bounded by design:
  - Fixes run only on user-checked items, never "fix all".
  - Restore point creation is a hard gate: if it fails, no fix runs.
  - Registry changes are limited to three conservative staleness classes
    (dead App Paths targets, dead Uninstall locations, dead Run targets),
    each individually listed, each exported to a `.reg` file first.
  - Startup "disable" never silently deletes: Run values are exported then
    removed (restorable from the backup), scheduled tasks are disabled, not
    deleted.
  - Destructive-adjacent actions (temp/cache deletion) target well-known
    cache/temp locations only, and locked/in-use files are skipped, never
    forced.
- Reputation/safety impact: registry cleaners have a scareware reputation.
  This tool must never imitate them: no inflated "error" counts, no red-alert
  styling for trivia, no mass deletion. Findings are reported as what they
  are, including "usually harmless" where that is the truth (e.g. DCOM 10016).

**Alternatives considered:**
- Wrapping existing "PC optimizer" products — rejected (snake oil, and
  against the user's stated position from 2026-10-15).
- PowerShell-only script pack — rejected: the user asked for an app with the
  same delivery pattern as the other Windows tools (GUI + double-click .bat).
- Deeper registry "cleaning" (orphaned CLSIDs, MRU lists, etc.) — rejected
  for v1 by design law: unproven benefit, real breakage risk.

**Rollback:** the tool itself is the rollback story — restore point +
per-item `.reg` exports + a timestamped log of every action, stored next to
the app. The repo can be deleted without side effects.

## 2. Pre-build audit

**Correctness risks and mitigations:**
- *Parser fragility:* SFC/DISM output varies by Windows version and locale.
  Mitigation: parsers match on several known message variants, and anything
  unrecognized is reported as "couldn't interpret the result — see the log"
  (honest unknown), never guessed. All parsers are unit-tested against
  recorded outputs here in the sandbox.
- *Long-running commands:* `sfc /verifyonly`, `DISM /ScanHealth`, and event
  log queries can take minutes. Mitigation: worker thread, progress updates,
  generous timeouts, cancel honored between steps (a running system command
  is allowed to finish — killing SFC/DISM mid-flight is worse than waiting).
- *Restore-point throttle:* Windows refuses a second restore point within
  24h by default. Mitigation: if creation fails for that specific reason AND
  a restore point younger than 24h exists, the gate passes with an explicit
  note; any other failure aborts all fixes.
- *Explorer restart for cache rebuilds:* icon/thumbnail cache rebuild stops
  Explorer. Mitigation: warn in the fix description; restart Explorer
  afterwards even on error paths (try/finally).
- *Service restarts for the Windows Update cache:* stop wuauserv/BITS, clear,
  restart — restart happens in a finally block.
- *Elevation:* SFC/DISM/restore points/registry HKLM writes need admin.
  Mitigation: detect at launch; if not elevated, scanning still works where
  possible but the Fix button is gated behind "Relaunch as admin" with a
  plain explanation.
- *Non-Windows sandbox:* this build machine is Linux. Every Windows execution
  path checks the platform first and degrades to an honest "needs Windows"
  state. Nothing is faked: no simulated scan results anywhere in the app.

**Security/privacy:**
- No network calls at all in v1 (no telemetry, no update checks, no driver
  downloads). The app is fully local.
- Logs may contain file paths and user names (startup entries, event logs).
  Logs stay on the user's own machine next to the app; nothing is uploaded
  by the app. (The source repo contains no logs.)
- GitHub credential handling for the upload uses the established
  surrogate-credential helper; tokens are never printed or stored in files.

**GUI rules (learned from the usb-prep clipped-window bug):**
- Main window: `resizable(True, True)`, explicit `minsize`, geometry that
  fits at common display scaling, long content in scrollable panes. A test
  asserts these calls exist in the source.

**Testing plan:**
- unittest suite (stdlib) with recorded fixtures: SFC (clean + violations),
  DISM (healthy + repairable), Get-PhysicalDisk/Get-Volume JSON, problem
  device JSON, event-log grouping + explanation dictionary, startup-item
  classification (console-type hunter for the black-CMD-popup issue),
  registry command-string parsing, registry staleness logic against fake key
  sets, fix-plan ordering + the restore-point gate, and the self-test entry
  point itself.
- `py_compile` on every .py file; `windows_health.py --self-test` must exit 0
  in this Linux sandbox (parser/logic checks pass; Windows-hardware checks
  report NEEDS-WINDOWS, which is not a failure).


---

## Addendum 2026-10-16 (late) — security section, feature pack, driver installs

Scope added by Shawn after the initial audit, audited here before building:

**Security posture section.** Impact: read-only Defender/firewall queries
plus three fix kinds (enable real-time protection, enable a firewall
profile, remove a Defender exclusion) and one opt-in action (Defender
Quick Scan). No homemade AV engine — detections are reported from
Get-MpThreatDetection and handled by Defender itself; the app never
quarantines or deletes. Malwarebytes is detect-and-launch only; if absent,
a button opens the official download page (their license forbids
redistributing the installer, and a bundled copy would go stale anyway).

**Feature pack.** PC Health Certificate (grades computed from actual
findings by a rubric documented in code; no data = "Not checked", never an
invented grade — HTML builder must escape CSS `%` when using `%`-formatting,
a bug the test suite caught). Monthly auto-check is opt-in, scan-only,
registered via Task Scheduler; it never fixes anything headless. Driver
backup = DISM /Export-Driver to a timestamped folder; restore path is
Device Manager, documented, no fake one-click restore. Boot-time report and
installed-programs audit are report-only; the programs audit opens Windows'
own uninstall page and never uninstalls silently.

**Driver search & install (WU Agent API only).** The only driver-update
source is the Windows Update Agent COM API, which matches updates to this
machine's hardware IDs. No vendor scraping, no third-party databases, no
"N outdated drivers" scare counts (old ≠ broken, stated in UI + README).
Installs are per-driver opt-in, one at a time, gated on (a) restore point
created in the same run and (b) driver backup completed in the same run;
one failed install stops the queue; GPU/storage drivers get a caution line
and default unticked; reboot-required is surfaced, never forced. The gates
and queue-stop are unit-tested with mocked executors.

**Bugs the test suite caught and fixed during this build:**
- SFC/DISM parsers missed results whose sentences wrap across lines in real
  console output ("unable to fix\nsome of them" parsed as unknown) —
  parsers now collapse whitespace before matching.
- Certificate HTML builder crashed on the CSS `width:100%` under
  `%`-formatting — escaped; regression-tested via build_certificate_html.
- Defender parser treated an empty `{}` status as a present-but-broken
  Defender — now reported as absent.
- The `__main__` entry block sat mid-file after GUI work was appended;
  moved to the true end of file so script execution reaches every
  definition.
