# Windows Health & Repair

A conservative Windows health-check and repair tool. It scans with
Microsoft's own diagnostic machinery, reports what it finds in plain
language, and fixes **only what you tick** — always after creating a
System Restore point, always logged, and verified afterwards.

Most "PC repair" apps are scareware: they invent thousands of registry
"errors," then offer to "fix all" and break things. This is the honest
version of that app.

## How to run

1. Install Python 3 from [python.org](https://www.python.org/downloads/windows/)
   (tick **"Add python.exe to PATH"** during setup).
2. Double-click **`start-windows-health.bat`**.
3. Press **Scan this PC**. Scanning only reads — nothing changes.
4. Tick the fixes you want and press **Fix checked items**.
   Fixes need administrator rights; the app offers **Relaunch as admin**.
5. **Save report** writes the full before/after report next to the app,
   and **Health certificate** produces a printable one-page summary.

No installer, no background service, no network calls except the ones
below (Windows Update driver matching, done by Windows itself).

## What the scan checks

- **Safety snapshot** — is System Restore on, and how old is the newest
  restore point? (The app creates a fresh one before any fix — if that
  fails, no fixes run. Hard gate, no exceptions.)
- **System files** — SFC verify + DISM component-store health.
- **Disks & storage** — physical disk health/SMART status, free space.
- **Boot performance** — last boot time and the slowest boot offenders
  from the Diagnostics-Performance log, in plain language.
- **Windows Update** — update-service states, pending-reboot flags,
  recent update history.
- **Security posture** — Windows Defender status (real-time protection,
  signature age, tamper protection, scan timestamps), Defender
  **exclusions audit** (unexpected exclusions are a real malware hiding
  trick), firewall profiles, SmartScreen state. Plus one opt-in action:
  run a Defender Quick Scan — detections are reported and **handled by
  Defender itself**; this app never quarantines or deletes anything.
- **Drivers & devices** — full signed-driver inventory (provider,
  version, date), problem devices with translated error codes, and
  driver updates **matched by Windows Update** (see below).
- **Startup programs** — everything that runs at logon (Run keys,
  Startup folders, logon tasks), with console-type entries
  (cmd/PowerShell/.bat) flagged with full paths. Nothing is disabled
  without your tick; disabling a Run entry exports it first.
- **Recent system errors** — 14 days of Error/Critical events grouped by
  source + ID, with plain-language explanations for common IDs and an
  honest "no built-in explanation" for the rest.
- **Junk & caches** — temp folders, Windows Update download cache,
  Recycle Bin size, and the thumbnail/icon/font caches (rebuilding those
  caches is the legitimate fix for broken icons, thumbnails, and fonts).
- **Registry leftovers (conservative)** — see below.
- **Installed programs** — full list with size/install date where
  Windows provides them, flagging toolbars, trialware, and duplicate
  updaters as report-only. A button opens Windows' own uninstall page;
  the app **never uninstalls anything silently**.
- **Memory** — RAM summary + an offer to schedule Windows Memory
  Diagnostic at next reboot.

## The registry module — deliberately conservative

Registry "cleaners" that claim thousands of errors are lying; blind
registry "fix all" breaks Windows. This app will only ever offer to
remove **three provably stale classes**, each listed individually with
its full key path:

1. **App Paths** entries whose target `.exe` no longer exists,
2. **Uninstall** entries whose install-location folder is gone,
3. **Startup Run** values whose target file is gone.

Every removal is preceded by a per-item `.reg` export backup in the
app's `backups/` folder. No scare counts. No "fix all."

## Driver updates — Windows Update is the only source

The app asks the **Windows Update Agent API** which driver updates
Microsoft has matched to this machine's actual hardware IDs. That is
the only search source — **no vendor-site scraping, no third-party
driver databases** — because third-party driver sources are a classic
malware/bundleware vector and frequently install the wrong driver.

If Windows Update matches nothing, the app says exactly that — **even
if some installed drivers are old. Old is not broken.**

Installing is deliberately gated:

- Per-driver checkboxes, **never** bulk-auto. GPU/display and
  storage-controller drivers carry an extra caution and start unticked.
- A restore point **and** a driver backup (DISM export of all
  third-party drivers, safety action in the Drivers section) must
  complete **in the same fix run** before any driver installs.
- Installs run **one at a time** through Windows Update itself. After
  each, the device is re-checked and old → new versions are logged.
- One failed install **stops the queue**; the report names the driver
  and the recovery path (Device Manager → Roll Back Driver, or the
  driver-backup folder).
- If Windows says a reboot is required, the app says so — it never
  forces one.

## About antivirus

This app does **not** contain a homemade antivirus engine, on purpose:
real AV needs continuously updated signature feeds, behavioral
engines, and kernel drivers. A fake one would create false confidence,
which is worse than none. Instead, the app audits and drives the
protection Windows already ships (Defender + firewall + SmartScreen).

**Malwarebytes** is supported as a second-opinion scanner: if it's
installed, the app offers to launch it. If not, a button opens
Malwarebytes' official download page. It is **not bundled** —
Malwarebytes' license forbids redistributing their installer without
written permission, and a bundled AV copy would go stale immediately
anyway. Downloads come from them, current version, their terms.

## Monthly auto-check (opt-in, off by default)

The **Monthly auto-check** button registers a Task Scheduler job that
runs the app headless (`--scan-only`) on the 1st of each month. It
**only scans** — headless runs never fix anything. It saves a report
next to the app and records a small history, so the app can show when
it last ran and whether findings got better or worse. One click on the
same button removes the job.

## PC Health Certificate

After a scan (and optionally a fix run), **Health certificate** writes
a one-page printable report (HTML + text): graded categories (System
files, Disk, Updates, Drivers, Security, Startup, Junk), plain-language
status, and BEFORE → AFTER where fixes ran.

Grades are computed from actual findings by a fixed rubric — A = no
problems, B = 1, C = 2–3, D = 4+ (errors count double). A category the
scan has no data for shows **"Not checked"** — grades are never
invented.

## Safety model

- Restore point **before** any fix; failure aborts the whole run.
- Fixes run only for items **you ticked**, in a safe order.
- Registry removals and startup disables are backed up first
  (`.reg` exports / task state / moved shortcuts in `backups/`).
- Driver installs additionally require the driver backup, same run.
- Every step is written to a timestamped log in `logs/`, and fixed
  items are re-checked afterwards (before/after in the report).
- Risky optional items (network reset, Store cache reset, Defender
  Quick Scan) are **off by default** and clearly labelled.

## What it deliberately does NOT do

- No mass registry cleaning, no scare counts, no "fix all."
- No RAM "boosters," no "optimizer" snake oil, no driver downloads
  from third-party sites, no silent uninstalls, no forced reboots.
- No homemade antivirus, no quarantining/deleting on its own.
- No telemetry, no accounts, no background service (unless you opt
  into the monthly scan-only check).

## Headless / developer use

```
python windows_health.py --self-test   # parser/logic self-test
python windows_health.py --scan-only   # monthly auto-check entry point
python windows_health.py --version
python -m unittest discover -s tests   # full fixture test suite
```

The app is a single stdlib-only Python file (`windows_health.py`) plus
a double-click `.bat` launcher. On non-Windows systems every hardware
scan degrades to an honest "needs Windows" state — results are never
faked.

## Still needs a real Windows PC to verify

Built and unit-tested off-device (parsers, plan safety, certificate
rubric, monthly diff — all against recorded fixtures). The following
only real Windows hardware can confirm: live SFC/DISM runs, restore
point creation, Defender cmdlets on a real install, the WU Agent
driver search/install round-trip, Task Scheduler registration,
cache-rebuild Explorer restart behavior, and the GUI end-to-end.
