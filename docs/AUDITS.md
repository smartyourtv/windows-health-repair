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

---

## Addendum 2026-10-17 — v1.1.0: troubleshooter, preventative scans,
## and the Defender/Malwarebytes visibility audit

### A. Why v1.0.0's Defender section + Malwarebytes suggestion were
###    invisible on Shawn's real PC (audit of the shipped code path)

The features exist in v1.0.0 code and pass fixture tests, but the
shipped flow buries or loses them. Findings, from reading the code:

1. **One flat list, no security summary.** Defender status and the
   Malwarebytes suggestion are ordinary rows in the same tree as ~40
   other findings. There is no "Windows Security" panel or summary
   line, so a user looking for "the app using my antivirus" sees
   undifferentiated text rows.
2. **Defender actions are conditional, so on a healthy PC almost none
   show.** "Update signatures" is only offered when signatures are
   >2 days old; "enable real-time protection" only when RTP is off.
   On a healthy machine the ONLY Defender action in the whole app is
   the quick-scan row, mid-list. There is no "Open Windows Security"
   action anywhere in v1.0.0.
3. **The Malwarebytes card is one `info` row near the END of the
   Security category**, after Defender, exclusions, firewall and
   SmartScreen rows. Its download button exists only as a detail-pane
   action: it materializes only when that exact row is clicked, and
   the row title never says a download is behind it.
4. **Single point of failure.** `run_scan` catches exceptions per
   scanner, so ANY exception inside `scan_security` (registry read,
   uninstall enumeration, a parser edge) collapses the ENTIRE
   category — Defender status AND the Malwarebytes suggestion — into
   one "This check failed to run" row.
5. **Brittle JSON path.** `ps_json` requires exit code 0 AND clean
   JSON. First-run PowerShell noise (module-load progress text) or a
   non-terminating error makes `parse_json_list` return [], which
   `parse_defender_status` reports as "could not read" — one vague
   warning row, no partial status, no reason detail.
6. **Malwarebytes launch detection is thin**: it only probes two exe
   names inside the registry InstallLocation; a miss degrades to
   "launch it from the Start menu" with no button at all.

v1.1.0 fixes all six: a Defender summary line leads the category,
per-part failure isolation inside the security scan, a noise-tolerant
JSON extractor for the Defender status path, always-offered Defender
actions (quick scan, signature update, Open Windows Security), the
Malwarebytes card directly under the Defender summary with its
official-site button, and standard-install-path exe probing.

### B. Change-impact audit — v1.1.0

**What is being added** (per Shawn, 2026-10-17): (A) a systematic
troubleshooter — pick a problem area, run ordered REAL checks
cheap→deep, end in exactly one honest outcome (safe fix under the
existing restore-point gate with post-fix re-verification / a
step-by-step plain-language guide / "cause not found" with what was
ruled out); (B) an expanded verifiable safe-fix set (WU cache reset
with the old cache renamed as backup, DNS flush, a start-a-disabled-
service fix); (C) preventative scans (SMART incl. failure prediction,
free-space trend, Defender signature age/state, firewall, pending
update count, startup changes, watched event-log patterns,
restore-point age) with stored history, a "what changed / what needs
attention" report, findings routing into the troubleshooter, and a
weekly-or-monthly schedule choice (monthly stays default);
(D) flow/scan logging in the app's existing log style.

**Blast radius:**
- `windows_health.py` only, plus tests/fixtures, README,
  BUILD-STATUS, packaging version strings (1.0.0 → 1.1.0 in
  app-config.json, version_info.txt, APP_VERSION — the packaging
  validator enforces the three agree).
- All v1.0.0 scanners, the 3-class registry rules, the fix-plan gate,
  driver gates, and the certificate rubric are untouched. New fix
  kinds are appended to FIX_ORDER; existing kinds keep their order
  values.
- New on-disk state next to the app: `preventative-history.json`,
  `auto-check.json` (schedule mode), service-start backups under
  `backups/`. The WU reset RENAMES the download cache instead of
  deleting it — the old cache stays as the backup until the user
  deletes it.
- The troubleshooter reuses `build_fix_plan`/`execute_plan`, so the
  restore-point hard gate, driver gates and verification notes apply
  identically. No new network calls except the ones Windows itself
  makes (WU search, signature update) — same as v1.0.0.

**Alternatives considered:**
- A separate troubleshooter executable — rejected: one app, one
  installer, one safety model.
- Free-form "AI diagnosis" text — rejected: causes must come from
  real probe evidence; a cause the checks didn't produce is never
  printed (the v1 honesty rule, extended).

### C. Pre-build audit — v1.1.0

- *Probe layer:* every troubleshooter check reads through an `env`
  probe object; unit tests inject a fake env, so flow logic (order,
  stop-at-first-cause, outcome selection, post-fix verification) is
  fully tested off-Windows. Windows probes wrap the existing parsers
  and degrade to `unknown` evidence, never invented results.
- *Fix safety:* the three new fix kinds follow the house pattern —
  pre-state recorded (service start type saved to a backup JSON; WU
  cache renamed, not deleted; DNS flush has nothing persistent to
  back up and says so), services restarted in `finally` blocks,
  and a `verify_step` branch re-probes the fixed thing.
- *Preventative evaluation is pure:* raw measurements in, findings +
  change lines out; history is a JSON file with the last 24 scans.
  The scheduled `--scan-only` run collects the same data and appends
  the preventative section to its report; headless runs still never
  fix anything.
- *Schedule change:* the Task Scheduler job keeps its existing name
  (renaming would orphan the v1.0.0 task on user PCs); only its
  /SC trigger changes (MONTHLY /D 1 vs WEEKLY /D MON) per the saved
  mode. Default remains monthly.
- *GUI:* troubleshooter opens as its own resizable Toplevel window
  (minsize set) so the main window layout — and its GUI-contract
  test — is undisturbed. Long flows run on worker threads like the
  main scan.

## Addendum 2026-10-17 (later) — v1.1.1: in-app updater, crash
## reports, and self-repair of the app's own state

Change-impact (delta over v1.1.0; the full audits above stand —
this release adds three features and touches no scan, fix,
security, troubleshooter, or preventative logic):

- *Network surface:* the app's first network calls, exactly two,
  both to its own GitHub repository's releases on user-visible
  flows: the update check (launch, throttled to once a day, and
  the manual button) and the update download itself (only after
  the user taps Update). Crash reports and repair logs are never
  uploaded. The module docstring states this honestly.
- *Updater safety:* a download is verified before it may run —
  size always, SHA-256 whenever GitHub provides one (the API
  asset `digest`, verified present on the v1.1.0 release; the
  code also prefers a `.sha256` checksum asset if one is ever
  attached). A checksum-asset workflow step was prepared but the
  contents API cannot write workflow files (no `workflow`
  scope), so the workflow is unchanged and digest verification
  carries the hash check — stated plainly, no silent downgrade:
  when neither hash exists the user is told and offered the
  release page instead. Failed downloads and downloads that fail
  verification are deleted, never installed. Never forced,
  never silent; dismissal is per version and persisted.
- *Crash capture:* hooks installed at the top of main()
  (sys.excepthook + threading.excepthook chained to the previous
  hooks, Tk's report_callback_exception), writing synchronously
  to Downloads before the app dies, rate-guarded so a crash loop
  cannot flood the folder. Tk callback errors report but do not
  kill the app. GUI work stays on Tk's thread via root.after.
- *Self-repair blast radius:* the four JSON stores (update
  state, auto-check setting, preventative history, scan history)
  now load/save through one repairing path. Saves keep the
  previous good copy as .bak; corrupt loads restore the .bak,
  salvage valid entries, or quarantine (rename, never delete)
  plus rebuild from defaults — claimed only after a re-read
  verifies the store, and logged to the repair log shown in the
  crash-reports window (repaired / repair-failed). Loaders keep
  their exact signatures and defaults, so every caller behaves
  as before on healthy state.
- *Layout regression risk:* the main window gains one button
  row's worth of surface (a second bottom row: Check for
  updates / Crash & error reports / status line) plus a notice
  bar that is packed only when an update is available. The
  v1.0.0 GUI-contract test (buttons, text variables, layout
  order) still passes unchanged; the crash view follows the
  troubleshooter's Toplevel pattern.
- *Tests:* 131 unit (96 baseline + 13 updater + 10 crash + 12
  self-repair), self-test 56 (40 baseline + 16 new), packaging
  42/42 at version 1.1.1.

## Addendum 2026-10-19 — v1.2.0: Defender malware-scan feature
## (Scout security capability, Phase 2)

Spec: goals/kitt-van-voice-ai-build/hidden_files/
scout-security-troubleshooting-design-2026-10-19.md, Phase 2.
Owner order: laptop first (ClamAV, done — talk.py v1.3.14), then
Windows. This release extends the EXISTING Defender plumbing
(fix_defender_scan, parse_defender_status, parse_threat_
detections, the defender_update fix kind) — no bundled engine,
no duplicate machinery.

### Change-impact audit (written BEFORE implementing)

- *What changes:* windows_health.py only (plus tests, fixtures,
  version strings, README/BUILD-STATUS docs). New pure parsers:
  parse_threat_names (Get-MpThreat), parse_threat_default_
  actions (Get-MpPreference ThreatIDDefaultAction_*), threat
  status text mapping for ThreatStatusID, and pure command
  builders for the scan types. fix_defender_scan generalizes
  from QuickScan-only to payload scan_type quick|full|custom|
  offline. Two new fix kinds — defender_threat_remove
  (Remove-MpThreat) and defender_threat_action (Set-MpPreference
  -ThreatIDDefaultAction_*: Defender's standing Quarantine/
  Remove/Allow instruction for FUTURE detections of one threat)
  — both in FIX_ORDER after defender_scan and both OPT_IN
  (never default-checked). verify_step gains matching re-reads.
- *Fix machinery:* every new action is a FixStep executed only
  by execute_plan, whose step zero is the restore point; the
  hard gate is untouched. No new execution path bypasses it:
  the GUI's new buttons (folder scan; per-threat standing
  actions) build a plan and call the same runner do_fix uses.
- *Honesty boundaries:* Defender decides what quarantine and
  removal mean; the app keeps NO quarantine store of its own
  on Windows and reports Defender's own state back. The
  standing-action buttons are labelled as FUTURE-detection
  instructions — they do not act on the existing detection
  (Remove-MpThreat does), and the UI text says exactly that.
  The offline scan (Start-MpWDOSScan) RESTARTS the PC: the
  finding's label and detail say so BEFORE the restore-point
  gate, and its result text states the app cannot verify the
  outcome until Windows is back (verify_step returns that
  sentence, not a success claim).
- *Regression risk:* _defender_findings gains an optional
  third argument (names text) — existing 2-arg callers and
  tests unaffected. parse_threat_detections gains one key
  (action_success); existing keys unchanged. FIX_ORDER and
  OPT_IN_KINDS are additive. The troubleshooter's threats
  check stays a GUIDED outcome on purpose: detection history
  persists after removal, so a "fixable" cause could never
  verify — its guide text now points at the new Security
  section actions instead. The spec's other Phase-2 lines
  (signature update kind, gated Set-MpPreference fixes,
  refusal-reported-not-worked-around) already exist in
  v1.1.1 and are not re-built.
- *Crash/self-repair coverage:* new fix code runs inside
  run_fix_step's existing try; new findings build inside
  scan_security's per-part isolation; GUI handlers follow the
  existing payload-button pattern with error dialogs. The
  four self-repairing JSON stores are untouched.
- *Data/compat:* no stored-format changes; no new files on
  the PC beyond the app's existing logs/reports.
- *Tests:* new fixtures (Get-MpThreat names, preference
  default actions, mixed-status detections) + a new unit
  class; self-test gains parser/command-builder checks.
  Baselines to preserve: 131 unit / 56 self-test / 42
  packaging.

### Pre-build audit (v1.2.0, after implementation, before build)

- *Permissions:* no new permissions. All new Defender calls are
  the same PowerShell surface the app already used (Defender
  cmdlets + MpCmdRun fallback). Set-MpPreference changes ride
  the existing admin + restore-point gates; Tamper Protection
  refusals surface as failures with the Windows Security route
  named — never bypassed or retried around.
- *Null/error paths:* parsers return [] / {} on empty or
  unparseable output (pinned by tests); command builders raise
  ValueError BEFORE anything runs on a bad scan type or a
  path-less custom scan; the custom scan also refuses a folder
  that does not exist; threat-action steps refuse a non-integer
  threat ID or a verb outside Defender's three.
- *API use:* Start-MpWDOSScan is fire-and-forget by design —
  the result text and verify_step both state the app cannot
  verify an offline scan until Windows is back. No threading
  changes: GUI actions run through confirm_and_run_plan's
  worker thread, same as do_fix always did.
- *Contracts:* Finding/FixStep shapes unchanged; the two new
  payload buttons follow the existing payload-button pattern
  in show_detail (launch/url/open_target precedents). The
  troubleshooter threats check deliberately stays guided
  (detection history persists after removal, so its cause
  could never verify) and now points at the new actions.
- *Security:* no new network surface (still only the updater's
  GitHub calls); no secrets; custom paths are single-quote
  escaped for PowerShell and validated to exist; threat IDs
  are type-checked ints before entering a command string.
- *Versions:* APP_VERSION, packaging/app-config.json and
  packaging/version_info.txt all 1.2.0 — validate_packaging
  re-checks this in CI. Baselines after the change: unit 147
  (131 + 16 new), self-test 63/63 (56 + 7 new), packaging
  42/42. CI must reproduce all three on windows-latest before
  any release is published.

---

# Addendum — 2026-10-20: scan-hang forensic + general audit (v1.2.1)

Triggered by the owner's report: "Scan this PC" started 2026-10-19
18:06:13; at 21:44 the window still showed "Scanning... SFC/DISM
checks can take several minutes." with a completely empty findings
list (~3.5 h). Owner runs v1.1.1; the defect is present unchanged in
the v1.2.0 tree.

## Forensic findings — the hang

**Root cause (proven, reproduced): name shadowing in the scan
progress callback.** `do_scan` (windows_health.py:4192) defines a
nested `def progress(cat, i, total)` whose body subscripts
`progress["maximum"]` / `progress["value"]`. That shadows the
`ttk.Progressbar` named `progress` in the enclosing GUI scope (line
3949), so inside the callback `progress` is the *function object* and
the first call raises `TypeError: 'function' object does not support
item assignment`. Reproduced off-Windows with a semantic replica of
the nesting (a dict standing in for the widget): same TypeError.

Failure chain: `run_scan` invokes the progress callback *before* the
first scanner (line 2378, outside its per-scanner try/except). The
TypeError kills the worker thread; in the frozen windowed exe the
threading excepthook writes to a stderr nobody sees. `populate()` and
`set_busy(False)` are only reachable after `run_scan` returns, so the
UI keeps the pre-scan state forever: the static busy label (whose text
mentions SFC/DISM — a red herring; no check ever ran), an empty
findings list, and a log containing only the header + "Scan started".

**Same defect, fix path:** `confirm_and_run_plan`'s progress callback
(line 4236) has the identical shadowing. `execute_plan` calls it
before step zero, so any fix run in v1.1.1/v1.2.0 dies the same way —
before the restore point is created. Fail-safe (nothing is changed)
but fully broken.

**Contributing design flaws:** (1) all-or-nothing rendering —
findings reach the tree only via one `populate()` call after the
whole scan; (2) neither worker has try/finally, so a dead worker
leaves the busy state up with no error anywhere; (3) no watchdog or
elapsed-time display naming the check in progress.

**Ruled out / ruled down:** pipe-drain deadlock (`run_cmd` uses
`subprocess.run(capture_output=True)`, which drains via communicate);
missing timeouts (every command call carries one; the SFC/DISM check's
worst case is 1800+600+1800 = 70 min and the all-scanner worst case
is ~2.2 h, both under the observed 3.5 h, and each would still have
produced log lines and earlier findings); console-input waits (none
in the scan path); cross-thread Tk mutation (a real latent defect in
the same two callbacks, but unreachable — the TypeError fires first;
the fix therefore renames *and* marshals via `root.after`, matching
the download progress callback at line ~4758, the one place that
already did it correctly).

**Confirming evidence on the owner's PC:** the scan log
(`logs\health-20261019-180613.log`) should contain only the header
and "Scan started" — no `$` command lines at all — proving no check
ever ran.

## General audit (standing areas)

- *Permissions/elevation:* scanning needs no admin; every fix path
  funnels through `confirm_and_run_plan`, which refuses without
  admin and points at Relaunch-as-admin (ShellExecuteW "runas"). OK.
- *Invariants hold:* `plan_is_safe` (line 620) + `execute_plan`'s
  hard refusal (line 3262) keep the restore point at step zero;
  `OPT_IN_KINDS` (line 587) covers net_reset/wsreset/defender_scan
  and the v1.2.0 threat kinds; `Finding.default_checked` defaults
  False (line 203); crash reports (in-app view + Downloads file) and
  the self-repair event log cover the v1.2.0 code paths.
- *Security:* updater still verifies the downloaded setup against
  the expected SHA-256 (GitHub-reported digest or the .sha256 asset;
  lines 4765, 8117-8119); no secrets; stdlib-only imports.
- *Null/error handling:* `run_scan` isolates per-scanner exceptions
  into honest "check failed" findings (lines 2381-2390); parsers
  return []/{} on unparseable output (pinned by tests). The gap was
  never in the scanners — it was in the GUI callbacks above them.
- *Versions:* APP_VERSION, packaging/app-config.json and
  packaging/version_info.txt in step (1.2.0 at audit time;
  validate_packaging re-checks in CI).

## Fixes shipped in v1.2.1

1. Both progress callbacks renamed (`scan_progress`, `fix_progress`)
   and marshaled to the UI thread with `root.after(0, ...)`; the
   progressbar is reached through a UI-thread closure, never
   shadowed, never touched from a worker.
2. `run_scan` streams: new `on_findings(batch)` callback fires as
   each check finishes, and the GUI appends findings to the tree
   immediately (category sections appear as their check completes).
   The list can never again sit empty through a long scan.
3. Per-check log lines: "Check i/N: <title>" at start and
   "Check <title> finished in Ns — M finding(s)." at end, so any
   future stall is pinpointed by the log's last line.
4. Watchdog: a 1-second UI ticker (guarded by a per-scan token)
   shows the running check's name + elapsed time via the pure
   `scan_status_text()` helper; past 3 minutes it adds a plain
   "still running — this check has a time limit and will be
   reported if it overruns" note.
5. Both workers wrapped in try/except: an unexpected worker failure
   is logged, written to the crash-report store, shown in a dialog,
   and always clears the busy state.

Not proven on real Windows — the owner's install remains the test.
