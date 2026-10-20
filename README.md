# Windows Health & Repair

A conservative Windows health-check and repair tool. It scans with
Microsoft's own diagnostic machinery, reports what it finds in plain
language, and fixes **only what you tick** — always after creating a
System Restore point, always logged, and verified afterwards.

Most "PC repair" apps are scareware: they invent thousands of registry
"errors," then offer to "fix all" and break things. This is the honest
version of that app.

## Install (the easy way)

1. Download **`WindowsHealthRepair-Setup.exe`** from the
   [latest GitHub Release](https://github.com/smartyourtv/windows-health-repair/releases/latest).
2. Double-click it. Windows SmartScreen will warn because the app is
   not code-signed yet — click **More info → Run anyway**. (That
   warning appears for every unsigned app; it is expected, and the
   source is right here in this repo if you want to check it.)
3. Click **Next → Finish**. That's it — **no Python to install**,
   and no administrator rights are needed to install: the app
   installs just for your user account and puts a shortcut in the
   Start Menu (and on the Desktop, unless you untick it).
4. Launch **Windows Health & Repair** and press **Scan this PC**.
   Scanning only reads — nothing changes.
5. Tick the fixes you want and press **Fix checked items**.
   Fixes need administrator rights; the app offers **Relaunch as admin**.
6. **Save report** writes the full before/after report next to the app,
   and **Health certificate** produces a printable one-page summary.

To remove it: **Settings → Apps → Windows Health & Repair → Uninstall.**

No background service, no network calls except the ones below
(Windows Update driver matching, done by Windows itself).

## Developer fallback (run from Python source)

Only needed if you want to hack on the code — the installer above is
the normal way to use the app.

1. Install Python 3 from [python.org](https://www.python.org/downloads/windows/)
   (tick **"Add python.exe to PATH"** during setup).
2. Double-click **`start-windows-health.bat`** (or run
   `python windows_health.py`).

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

**Windows Security (Microsoft Defender) — first-class in the app:**
the Security section of every scan opens with a plain-language
Defender summary: real-time protection on/off, antivirus signature
version and age, last quick/full scan times, and threat detections.
Under it sit working actions, always visible: run a Defender Quick
Scan, update Defender signatures, and **Open Windows Security**
(opens Windows' own security app). If Defender cannot be read, the
app says so and says why — never a silent dead button.

**Malware scanning (new in v1.2.0):** the Security section now
offers Defender's full scan set, each behind the same
restore-point gate as every fix: a **Quick Scan**, a **Full Scan**,
a **folder scan** (pick any folder — a downloads folder, a USB
stick), and the **Offline Scan**, which *restarts the PC* to scan
before Windows loads (the finding says so in plain words, and the
app honestly cannot verify that one — its result is read in
Windows Security → Protection history). Detections are listed as a
**threat history, by name**, with Defender's own state for each
one (quarantined / removed / still needs action) — live from
Defender, never a copy this app keeps. From the history you can
run Defender's own removal for anything still active, and set
Defender's **standing action** (quarantine / remove / allow) for
future detections of a named threat. Defender decides what
quarantine and removal mean; this app reports Defender's state
and never invents its own.

**Malwarebytes** is supported as a second-opinion scanner, and its
card sits directly under the Defender summary: if Malwarebytes is
installed, the app offers to launch it; if not, the card explains
what it is (a respected second-opinion scanner from
malwarebytes.com) and one button opens the official download page.
It is **not bundled** — Malwarebytes' license forbids redistributing
their installer without written permission, and a bundled AV copy
would go stale immediately anyway. Downloads come from them,
current version, their terms.

## Troubleshooter (new in v1.1.0)

Press **Troubleshoot a problem…** and pick what is wrong:

- **PC is slow / startup trouble**
- **Crashes & freezes (blue screens)**
- **Internet / network not working**
- **No sound / sound problems**
- **Windows Update keeps failing**
- **Disk / storage trouble**
- **Security concerns**

The app runs real checks in order (cheap ones first), showing the
evidence as it goes, and ends in exactly one honest outcome:

1. **Cause found and safely fixable** → the fix is offered behind the
   usual rules: restore point first (hard gate), per-change backup,
   then the failing check is re-run to **verify** the result and
   report pass/fail truthfully.
2. **Cause found but bigger than a safe automatic fix** → a
   step-by-step guide screen, tailored to the found cause (numbered,
   plain language, copyable for printing).
3. **Cause not found** → the app says so, lists everything it checked
   and ruled out, and gives the next manual steps. It never invents
   a cause.

The safe-fix set grew conservatively: a Windows Update cache reset
(the old cache folder is renamed aside as a backup, never deleted),
a DNS flush (with a verification lookup afterwards), re-enabling a
stopped/disabled Windows service (its previous state is saved to
`backups/` first), plus the existing network-stack reset (clearly
labelled, off by default) and icon/thumbnail cache rebuild.

## Preventative scans (new in v1.1.0)

Press **Preventative scan**, or let the scheduled auto-check run it:
disk health (SMART failure prediction via WMI, not just the status
flag), free-space level and how it changed since the last scan,
Defender state and signature age, firewall state, pending Windows
Update count, startup-item changes, error-log patterns worth
watching (disk errors, WHEA hardware errors, repeated service
failures), and the age of the newest restore point. Results are
stored as history, reported as a plain-language "what changed /
what needs attention" list, and every attention item has a
**Troubleshoot this** button that opens the matching troubleshooter
flow.

## App updates (new in v1.1.1)

The app can update itself. **Check for updates** (bottom row of
buttons) asks this project's GitHub releases whether a newer
version exists; the app also checks quietly at most once a day
when it starts, and if a newer version appears it shows **one**
small notice above the buttons — tap **Not now** and that version
is never mentioned again. Nothing is ever downloaded or installed
without you tapping **Update**.

When you do: the new `WindowsHealthRepair-Setup.exe` downloads
(with progress shown), and is **verified before it runs** — its
size must match the release, and its SHA-256 must match the hash
GitHub reports for the file. A download that fails verification is
deleted, never installed, and the app says what happened and
offers the release page for a manual download. When the check
passes, the installer launches and the app closes, so the new
version replaces this one (same per-user install as always).

## Crash & error reports, and self-repair (new in v1.1.1)

If the app ever hits an unexpected error, it saves a
plain-language report — **WindowsHealthRepair-crash-<date>-<time>.txt**
— into your **Downloads** folder: what happened, when, the app
and Windows versions, the technical details, and the tail of the
app's own log. **Crash & error reports** (bottom row) lists the
saved reports so you can read, copy, open, or delete them.
Reports are **never uploaded anywhere** — they stay on your PC
until you share one.

The app also looks after its **own** state. If one of its
settings or history files gets corrupted, it repairs it —
restored from the last good copy it keeps, or rebuilt from safe
defaults with whatever data could be salvaged kept and the
corrupt file set aside (never deleted) — then re-reads the file
to make sure the repair worked before carrying on. Abandoned
partial update downloads from an interrupted run are cleared at
startup. Every repair is noted in the **Crash & error reports**
window, marked *repaired* — or *repair-failed*, honestly, if it
couldn't be fixed.

## Auto-check schedule (opt-in, off by default)

The **Auto-check** button registers a Task Scheduler job that runs
the app headless (`--scan-only`). It **only scans** — headless runs
never fix anything. Use the **Auto-check: Monthly / Weekly** button
to choose: monthly (the default, 1st of each month) or weekly
(Mondays). It saves a report next to the app — including the
preventative "what changed" section — and records a small history,
so the app can show when it last ran and whether findings got better
or worse. One click on the same button removes the job.

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
  into the weekly/monthly scan-only auto-check).

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

## Packaging (reusable template)

The Setup.exe is built from `packaging/` — a PyInstaller single-file
windowed exe (`packaging/pyinstaller.spec`) wrapped by Inno Setup
(`packaging/setup.iss`), driven by `packaging/app-config.json` and
built by the *Build Windows installer* GitHub Actions workflow on
`windows-latest` (or locally with `packaging/build-installer.ps1`).
`packaging/TEMPLATE-NOTES.md` documents how the next Windows app
reuses the same template with only name changes, and
`python packaging/validate_packaging.py` checks the packaging on any
OS.

## Still needs a real Windows PC to verify

Built and unit-tested off-device (parsers, plan safety, certificate
rubric, monthly diff — all against recorded fixtures). The
v1.1.0 machinery (troubleshooter flows, preventative evaluation,
security restructure) is unit-tested with mocked probes the same
way. The following only real Windows hardware can confirm: live
SFC/DISM runs, restore point creation, Defender cmdlets on a real
install, the WU Agent driver search/install round-trip, Task
Scheduler registration, cache-rebuild Explorer restart behavior,
the new troubleshooter/preventative GUI windows end-to-end, and the
GUI generally. For the installer specifically: the first CI run on
`windows-latest`, then a real-PC pass — install as a non-admin user,
the SmartScreen step above, launch from Start Menu/Desktop,
Relaunch-as-admin inside the app, the scheduled `--scan-only` task
firing against the installed exe, and uninstall from
Settings → Apps.
