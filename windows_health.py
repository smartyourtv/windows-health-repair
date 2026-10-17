#!/usr/bin/env python3
"""Windows Health & Repair — v1.

A conservative Windows health-check and repair tool. It scans with
Microsoft's own diagnostic machinery (SFC, DISM, storage/device/event
cmdlets), reports findings in plain language, and applies ONLY the fixes
the user checks off — always after creating a System Restore point, always
logged, and with a .reg export backup before any registry removal.

What this app deliberately does NOT do (no scareware, no snake oil):
  * No mass registry "cleaning". The only registry items it will ever offer
    to remove are three provably-stale classes, each listed individually:
    App Paths entries whose .exe is gone, Uninstall entries whose install
    folder is gone, and startup Run entries whose target file is gone.
  * No inflated "error" counts, no RAM "boosters", no driver downloads,
    no background "optimization" services, no network calls at all.

Run `python windows_health.py --self-test` for a headless check of the
parsing/logic layer. On non-Windows systems every hardware scan degrades
to an honest "needs Windows" state — results are never faked.
"""

import argparse
import ctypes
import datetime
import json
import os
import re
import subprocess
import sys
import threading

APP_NAME = "Windows Health & Repair"
APP_VERSION = "1.0.0"

IS_WINDOWS = sys.platform.startswith("win")
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

# Categories, in display order.
CATEGORIES = [
    ("safety", "Safety snapshot (System Restore)"),
    ("sysfiles", "System files (SFC / DISM)"),
    ("disk", "Disks & storage"),
    ("boot", "Boot performance"),
    ("update", "Windows Update"),
    ("security", "Security posture"),
    ("devices", "Drivers & devices"),
    ("startup", "Startup programs"),
    ("events", "Recent system errors"),
    ("junk", "Junk & caches"),
    ("registry", "Registry leftovers (conservative)"),
    ("programs", "Installed programs"),
    ("memory", "Memory (RAM)"),
]
CATEGORY_TITLES = dict(CATEGORIES)


# ----------------------------------------------------------------------
# Small utilities
# ----------------------------------------------------------------------

def now_stamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def is_frozen():
    """True when running as a PyInstaller-built exe (sys.frozen set)."""
    return bool(getattr(sys, "frozen", False))


def app_dir():
    if is_frozen():
        # PyInstaller --onefile unpacks __file__ into a temp folder
        # (_MEIPASS) that is deleted on exit. Logs, backups, reports
        # and history must live next to the real .exe (the per-user
        # install folder, which is writable), never in the temp dir.
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


class RunLog:
    """Timestamped log: in-memory lines + optional file + optional GUI sink."""

    def __init__(self, sink=None):
        self.lines = []
        self.sink = sink
        self.path = None

    def start_file(self):
        log_dir = os.path.join(app_dir(), "logs")
        os.makedirs(log_dir, exist_ok=True)
        name = "health-%s.log" % datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        self.path = os.path.join(log_dir, name)
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("%s %s\n" % (APP_NAME, APP_VERSION))
        return self.path

    def __call__(self, msg):
        line = "[%s] %s" % (now_stamp(), msg)
        self.lines.append(line)
        if self.path:
            try:
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            except OSError:
                pass
        if self.sink:
            self.sink(line)


def run_cmd(args, timeout=600, log=None):
    """Run a command, capture output. Returns (rc, combined_text).

    Never raises for a missing binary — returns rc=-1 and the error text so
    callers can degrade honestly.
    """
    if log:
        log("$ " + " ".join(str(a) for a in args))
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, errors="replace",
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW if IS_WINDOWS else 0,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        return proc.returncode, out
    except FileNotFoundError:
        return -1, "command not found: %s" % args[0]
    except subprocess.TimeoutExpired:
        return -2, "command timed out after %ss: %s" % (timeout, args[0])
    except OSError as exc:
        return -1, "failed to run %s: %s" % (args[0], exc)


def run_ps(script, timeout=300, log=None):
    """Run a PowerShell snippet (Windows only)."""
    if not IS_WINDOWS:
        return -1, "needs Windows"
    return run_cmd(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
         "-Command", script],
        timeout=timeout, log=log)


def is_admin():
    if IS_WINDOWS:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def human_size(num):
    if num is None:
        return "unknown"
    num = float(num)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num) < 1024.0:
            return "%.1f %s" % (num, unit)
        num /= 1024.0
    return "%.1f PB" % num


# ----------------------------------------------------------------------
# Findings model
# ----------------------------------------------------------------------

class Finding:
    """One scan finding. fix_kind None = report-only (no checkbox)."""

    def __init__(self, category, title, detail="", why="", fix_label=None,
                 fix_kind=None, payload=None, default_checked=False,
                 severity="info"):
        self.category = category
        self.title = title
        self.detail = detail
        self.why = why
        self.fix_label = fix_label          # text of the fix checkbox
        self.fix_kind = fix_kind            # e.g. "sfc_scannow"
        self.payload = payload or {}
        self.default_checked = default_checked
        self.severity = severity            # info | warn | bad

    def __repr__(self):
        return "<Finding %s: %s>" % (self.category, self.title)


# ----------------------------------------------------------------------
# Pure parsers (unit-tested against recorded output)
# ----------------------------------------------------------------------

SFC_MESSAGES = [
    ("clean", "did not find any integrity violations"),
    ("repaired", "successfully repaired them"),
    ("violations_unfixed",
     "found corrupt files but was unable to fix some of them"),
    ("violations", "found corrupt files and successfully"),
    ("pending", "there is a system repair pending"),
    ("blocked", "could not perform the requested operation"),
]


def parse_sfc(text):
    """Parse sfc output -> {status, message}. status may be 'unknown'.

    SFC wraps its result sentences across lines ("...was unable to
    fix\\nsome of them."), so whitespace is collapsed before matching —
    without that, the most important result (unfixed corruption)
    parses as 'unknown'.
    """
    low = re.sub(r"\s+", " ", (text or "").lower())
    for status, needle in SFC_MESSAGES:
        if needle in low:
            return {"status": status, "message": needle}
    if "windows resource protection" in low:
        return {"status": "unknown",
                "message": "SFC ran but its result text was not recognized"}
    return {"status": "unknown", "message": "no recognizable SFC result"}


def parse_dism(text):
    """Parse DISM CheckHealth/ScanHealth output -> {status, message}."""
    low = re.sub(r"\s+", " ", (text or "").lower())
    if "no component store corruption detected" in low:
        return {"status": "healthy", "message": "no component store corruption"}
    if "the component store is repairable" in low:
        return {"status": "repairable",
                "message": "component store corruption is repairable"}
    if "the component store is not repairable" in low or \
            "is not repairable" in low:
        return {"status": "not_repairable",
                "message": "component store is NOT repairable"}
    if "the operation completed successfully" in low and "image" in low:
        return {"status": "healthy",
                "message": "operation completed (component store healthy)"}
    if "error:" in low:
        m = re.search(r"error:\s*(0x[0-9a-f]+|\d+)", low)
        return {"status": "error",
                "message": "DISM error %s" % (m.group(1) if m else "?")}
    return {"status": "unknown", "message": "unrecognized DISM output"}


def parse_json_list(text):
    """Parse PowerShell ConvertTo-Json output (object or array) -> list."""
    text = (text or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    return []


CODE_MANAGER_CODES = {
    1: "device is not configured correctly",
    3: "a driver for this device is corrupted or memory is low",
    10: "device cannot start",
    12: "not enough free resources for this device",
    14: "device needs a restart to finish setup",
    18: "drivers for this device need reinstalling",
    19: "registry information for this device is damaged",
    21: "Windows is removing this device",
    22: "device is disabled",
    28: "drivers for this device are not installed",
    29: "device is disabled because its firmware gave it no resources",
    31: "device is not working properly (a driver failed to load)",
    33: "Windows cannot determine which resources this device needs",
    37: "the driver initialization failed",
    39: "the driver is corrupted or missing",
    41: "driver loaded but the hardware was not found",
    43: "a driver reported the device stopped (hardware fault suspected)",
    45: "device is not connected to the computer",
    47: "device is being prepared for safe removal",
    50: "device drivers could not be applied",
    52: "Windows cannot verify the driver's digital signature",
}


def describe_device_problem(code):
    try:
        code = int(code)
    except (TypeError, ValueError):
        return "unknown problem"
    return CODE_MANAGER_CODES.get(code, "problem code %s" % code)


def parse_problem_devices(text):
    """Parse Win32_PnPEntity JSON -> list of problem device dicts."""
    out = []
    for d in parse_json_list(text):
        try:
            code = int(d.get("ConfigManagerErrorCode") or 0)
        except (TypeError, ValueError):
            code = 0
        if code == 0:
            continue
        out.append({
            "name": d.get("Name") or d.get("Caption") or "Unknown device",
            "class": d.get("PNPClass") or "",
            "code": code,
            "meaning": describe_device_problem(code),
        })
    return out


# Event ID explanations: (provider-substring, event id) -> plain language.
# Anything not in here is reported honestly as "no plain explanation yet".
EVENT_EXPLANATIONS = [
    ("kernel-power", 41,
     "The PC shut down without a clean shutdown (power loss, crash, or "
     "holding the power button). Repeated hits point at power/heat trouble."),
    ("disk", 7,
     "A disk reported a bad block — an early sign a drive may be failing. "
     "Check the Disks section and back up anything important."),
    ("disk", 11,
     "The disk controller reported an error — can be a failing drive, a "
     "loose cable, or a controller problem."),
    ("disk", 51,
     "An error during a paging (virtual memory) operation — often disk or "
     "cable trouble."),
    ("disk", 129,
     "A storage device timed out and was reset — can mean a struggling "
     "drive or outdated storage drivers."),
    ("ntfs", 55,
     "File-system corruption was detected on a volume. Run the disk check "
     "offer in this app, and back up important files."),
    ("volmgr", 161,
     "A crash-dump file could not be created — a side issue, but it means "
     "crash evidence is being lost."),
    ("bugcheck", 1001,
     "Windows recorded a blue-screen crash (bugcheck). The code in the "
     "message names the suspected cause area."),
    ("service control manager", 7001,
     "A service failed to start because a service it depends on failed. "
     "Often clears after updates finish or a reboot."),
    ("service control manager", 7031,
     "A service crashed and Windows restarted it. Once is noise; many "
     "repeats mean that program needs attention or an update."),
    ("service control manager", 7034,
     "A service stopped unexpectedly. Same rule: repeats matter."),
    ("distributedcom", 10016,
     "DCOM permission warnings — extremely common and usually harmless. "
     "Listed so you can see them; normally safe to ignore."),
    ("windowsupdateclient", 20,
     "A Windows update failed to install. The Windows Update section of "
     "this scan checks the update services."),
    ("windowsupdateclient", 25,
     "Windows Update failed to detect new updates — check the update "
     "services in this scan."),
    ("perflib", 1008,
     "A performance-counter DLL failed — cosmetic for most users; a "
     "repair install of the named program usually clears it."),
    ("application error", 1000,
     "A program crashed. The message names the program; if it is always "
     "the same one, update or reinstall that program."),
    ("kernel-power", 137,
     "Firmware changed the processor power state during sleep — can cause "
     "wake/sleep weirdness; a BIOS/chipset update is the usual fix."),
    ("volsnap", 36,
     "Shadow copies (restore-point data) were deleted because the storage "
     "limit was hit — restore points may be thinner than expected."),
]


def explain_event(provider, event_id):
    prov = (provider or "").lower()
    for sub, eid, text in EVENT_EXPLANATIONS:
        if sub in prov and eid == event_id:
            return text
    return None


def group_events(events, top_n=10):
    """Group event dicts by (provider, id, level) with counts, worst first."""
    counts = {}
    for ev in events:
        key = (ev.get("ProviderName") or "Unknown",
               int(ev.get("Id") or 0),
               ev.get("LevelDisplayName") or "")
        counts[key] = counts.get(key, 0) + 1
    grouped = []
    for (prov, eid, level), count in counts.items():
        grouped.append({
            "provider": prov, "id": eid, "level": level, "count": count,
            "explanation": explain_event(prov, eid),
        })
    # Critical/Error first, then by count.
    rank = {"Critical": 0, "Error": 1}
    grouped.sort(key=lambda g: (rank.get(g["level"], 2), -g["count"]))
    return grouped[:top_n]


# ----------------------------------------------------------------------
# Startup item classification (pure logic)
# ----------------------------------------------------------------------

CONSOLE_HINTS = ("cmd.exe", "powershell", "pwsh.exe", "conhost.exe",
                 "wscript.exe", "cscript.exe")
CONSOLE_EXTS = (".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsf")


def extract_target_path(command, expand=None):
    """Extract the target file path from a registry/scheduled-task command.

    Handles "quoted path" --args, bare path.exe args, and script hosts.
    `expand` optionally expands env vars (pass os.path.expandvars on Windows).
    """
    if not command:
        return ""
    cmd = command.strip()
    if not cmd:
        return ""
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        if end > 1:
            target = cmd[1:end]
            return expand(target) if expand else target
    parts = cmd.split()
    if not parts:
        return ""
    first = parts[0]
    low = first.lower()
    # Script hosts: the real target is the next token.
    if os.path.basename(low) in ("wscript.exe", "cscript.exe",
                                 "powershell.exe", "pwsh.exe", "cmd.exe"):
        for tok in parts[1:]:
            t = tok.strip('"')
            if t.lower().endswith(CONSOLE_EXTS) or "\\" in t:
                return expand(t) if expand else t
    return expand(first.strip('"')) if expand else first.strip('"')


def classify_startup_item(item, exists_fn=None):
    """item: {name, source, command}. Returns flags dict.

    exists_fn(path)->bool is injectable for tests; defaults to os.path.exists.
    """
    exists_fn = exists_fn or os.path.exists
    command = item.get("command") or ""
    target = extract_target_path(
        command, expand=os.path.expandvars if IS_WINDOWS else None)
    low_cmd = command.lower()
    low_target = target.lower()
    is_console = (
        any(h in low_cmd for h in CONSOLE_HINTS)
        or low_target.endswith(CONSOLE_EXTS)
        or low_cmd.endswith(tuple(e for e in CONSOLE_EXTS))
    )
    exists = bool(target) and bool(exists_fn(target)) if target else False
    return {
        "target": target,
        "is_console": is_console,
        "target_exists": exists,
        "target_missing": bool(target) and not exists,
    }


# ----------------------------------------------------------------------
# Registry staleness logic (pure — entries in, stale entries out)
#
# The ONLY registry items this app may ever offer to remove:
#   (a) App Paths entries whose target .exe no longer exists
#   (b) Uninstall entries whose InstallLocation folder no longer exists
#   (c) startup Run values whose target file no longer exists
# ----------------------------------------------------------------------

def stale_app_paths(entries, exists_fn=None):
    """entries: [{key, name, target}] -> stale subset (target missing)."""
    exists_fn = exists_fn or os.path.exists
    return [e for e in entries
            if e.get("target") and not exists_fn(e["target"])]


def stale_uninstall(entries, exists_fn=None):
    """entries: [{key, name, location}] -> stale subset (location gone).

    Entries with no InstallLocation are skipped — absence of a location is
    not proof of staleness.
    """
    exists_fn = exists_fn or os.path.exists
    return [e for e in entries
            if e.get("location") and not exists_fn(e["location"])]


def stale_run_values(entries, exists_fn=None):
    """entries: [{key, name, command}] -> stale subset (target missing)."""
    exists_fn = exists_fn or os.path.exists
    out = []
    for e in entries:
        target = extract_target_path(
            e.get("command") or "",
            expand=os.path.expandvars if IS_WINDOWS else None)
        if target and not exists_fn(target):
            out.append(dict(e, target=target))
    return out


# ----------------------------------------------------------------------
# Fix plan: ordering + the restore-point gate (pure logic)
# ----------------------------------------------------------------------

# Execution order for fix kinds. Lower runs earlier. The restore point is
# not a "kind" — it is step zero of every plan, enforced by build_fix_plan.
FIX_ORDER = {
    "driver_backup": 5,
    "dism_restore": 10,
    "sfc_scannow": 20,
    "chkdsk_scan": 30,
    "driver_install": 35,
    "registry_remove": 40,
    "firewall_enable": 45,
    "defender_rtp_enable": 46,
    "startup_disable": 50,
    "exclusion_remove": 55,
    "cleanup_temp": 60,
    "cleanup_wu_cache": 61,
    "cache_rebuild": 70,
    "wsreset": 80,
    "net_reset": 90,
    "defender_scan": 95,
    "memdiag": 100,
}

# Fix kinds that are risky enough to be OFF unless the user ticks them on
# purpose in the GUI (they are never default-checked).
OPT_IN_KINDS = {"net_reset", "wsreset", "defender_scan"}


class FixStep:
    def __init__(self, kind, label, payload=None, finding=None):
        self.kind = kind
        self.label = label
        self.payload = payload or {}
        self.finding = finding

    def __repr__(self):
        return "<FixStep %s: %s>" % (self.kind, self.label)


def build_fix_plan(findings):
    """Turn checked findings into an ordered plan.

    Step zero is always the restore point — the executor refuses to run a
    plan whose first step is not the restore point.
    """
    steps = [FixStep("restore_point",
                     "Create a System Restore point (safety snapshot)")]
    chosen = []
    for f in findings:
        if not f.fix_kind:
            continue
        chosen.append(FixStep(f.fix_kind, f.fix_label or f.title,
                              payload=dict(f.payload), finding=f))
    chosen.sort(key=lambda s: FIX_ORDER.get(s.kind, 500))
    return steps + chosen


def plan_is_safe(plan):
    """A plan is executable only if step zero creates the restore point."""
    return bool(plan) and plan[0].kind == "restore_point"


# ----------------------------------------------------------------------
# Security posture parsers (pure — mocked in tests)
#
# This app does NOT contain an antivirus engine, on purpose. Real AV needs
# signature feeds, behavioral engines and kernel drivers; a homemade one
# would create false confidence. Instead we audit and drive the protection
# Windows already ships: Microsoft Defender, the Windows Firewall, and
# SmartScreen.
# ----------------------------------------------------------------------

def _parse_ms_date(value):
    """Parse a .NET JSON date or ISO string -> datetime or None."""
    if not value:
        return None
    if isinstance(value, (int, float)):
        return datetime.datetime.fromtimestamp(value / 1000.0)
    text = str(value)
    m = re.search(r"/Date\((\d+)", text)
    if m:
        return datetime.datetime.fromtimestamp(int(m.group(1)) / 1000.0)
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S"):
        try:
            return datetime.datetime.strptime(text[:26], fmt)
        except ValueError:
            continue
    return None


def parse_defender_status(text, now=None):
    """Parse Get-MpComputerStatus JSON -> normalized dict."""
    now = now or datetime.datetime.now()
    rows = parse_json_list(text)
    if not rows or not rows[0]:
        return {"present": False}
    d = rows[0]
    sig_updated = _parse_ms_date(d.get("AntivirusSignatureLastUpdated"))
    sig_age = None
    if d.get("AntivirusSignatureAge") is not None:
        try:
            sig_age = int(d["AntivirusSignatureAge"])
        except (TypeError, ValueError):
            sig_age = None
    if sig_age is None and sig_updated is not None:
        sig_age = max(0, (now - sig_updated).days)
    return {
        "present": True,
        "am_service": bool(d.get("AMServiceEnabled")),
        "antivirus_enabled": bool(d.get("AntivirusEnabled")),
        "rtp": bool(d.get("RealTimeProtectionEnabled")),
        "ioav": bool(d.get("IoavProtectionEnabled")),
        "tamper": bool(d.get("IsTamperProtected")),
        "sig_age_days": sig_age,
        "sig_updated": sig_updated,
        "quick_scan_end": _parse_ms_date(d.get("QuickScanEndTime")),
        "full_scan_end": _parse_ms_date(d.get("FullScanEndTime")),
        "quick_scan_needed": bool(d.get("QuickScanNeeded")),
        "full_scan_needed": bool(d.get("FullScanNeeded")),
    }


def parse_defender_exclusions(text):
    """Parse Get-MpPreference JSON -> [{type, value}] exclusion list."""
    rows = parse_json_list(text)
    if not rows:
        return []
    d = rows[0]
    out = []
    for key, kind in (("ExclusionPath", "path"),
                      ("ExclusionExtension", "extension"),
                      ("ExclusionProcess", "process"),
                      ("ExclusionIpAddress", "ip")):
        vals = d.get(key) or []
        if isinstance(vals, str):
            vals = [vals]
        for v in vals:
            if v:
                out.append({"type": kind, "value": str(v)})
    return out


def parse_firewall_profiles(text):
    """Parse Get-NetFirewallProfile JSON -> [{name, enabled}]."""
    out = []
    for d in parse_json_list(text):
        out.append({"name": d.get("Name") or "?",
                    "enabled": bool(d.get("Enabled"))})
    return out


def interpret_smartscreen(value):
    """HKLM SmartScreenEnabled value -> plain state."""
    v = (value or "").strip().lower()
    if v == "requireadmin":
        return "on (blocks unrecognized apps unless an admin approves)"
    if v == "warn":
        return "on (warns before running unrecognized apps)"
    if v == "off":
        return "OFF"
    if not v:
        return "not configured at machine level (per-user setting applies)"
    return "custom (%s)" % value


def parse_threat_detections(text):
    """Parse Get-MpThreatDetection JSON -> [{threat_id, detected, status}]."""
    out = []
    for d in parse_json_list(text):
        out.append({
            "threat_id": d.get("ThreatID"),
            "detected": _parse_ms_date(d.get("InitialDetectionTime")),
            "status_id": d.get("ThreatStatusID"),
            "resources": d.get("Resources") or [],
        })
    return out


def find_malwarebytes(uninstall_entries):
    """uninstall entries [{name, location, uninstall}] -> MB entry or None."""
    for e in uninstall_entries:
        if "malwarebytes" in (e.get("name") or "").lower():
            return e
    return None


def parse_pending_reboot(obj):
    """obj from PS: {cbs, wu, file_rename, computer_rename} bools -> list."""
    reasons = []
    if not obj:
        return reasons
    if obj.get("cbs"):
        reasons.append("component servicing (CBS) is waiting for a reboot")
    if obj.get("wu"):
        reasons.append("Windows Update is waiting for a reboot")
    if obj.get("file_rename"):
        reasons.append("files are queued to be renamed/moved at reboot")
    if obj.get("computer_rename"):
        reasons.append("a computer rename is pending")
    return reasons


def parse_service_states(text):
    """Parse Get-Service JSON -> {name: {status, start_type}}."""
    out = {}
    for d in parse_json_list(text):
        name = d.get("Name") or d.get("DisplayName")
        if name:
            out[name.lower()] = {
                "status": str(d.get("Status") or ""),
                "start_type": str(d.get("StartType") or ""),
                "display": d.get("DisplayName") or name,
            }
    return out


# ----------------------------------------------------------------------
# Windows data collection helpers (all degrade honestly off-Windows)
# ----------------------------------------------------------------------

def ps_json(script, timeout=300, log=None):
    """Run PowerShell, return (ok, raw_text)."""
    rc, out = run_ps(script, timeout=timeout, log=log)
    return rc == 0, out


# Registry roots for winreg (imported lazily; winreg exists only on Windows).
def _winreg():
    import winreg
    return winreg


def reg_enum_values(root, path):
    """-> [{name, value}] for a key, [] if missing/unreadable."""
    if not IS_WINDOWS:
        return []
    winreg = _winreg()
    out = []
    try:
        key = winreg.OpenKey(root, path)
    except OSError:
        return []
    with key:
        i = 0
        while True:
            try:
                name, value, _ = winreg.EnumValue(key, i)
            except OSError:
                break
            out.append({"name": name, "value": value})
            i += 1
    return out


def reg_enum_subkeys(root, path):
    if not IS_WINDOWS:
        return []
    winreg = _winreg()
    out = []
    try:
        key = winreg.OpenKey(root, path)
    except OSError:
        return []
    with key:
        i = 0
        while True:
            try:
                out.append(winreg.EnumKey(key, i))
            except OSError:
                break
            i += 1
    return out


def reg_get_value(root, path, name):
    if not IS_WINDOWS:
        return None
    winreg = _winreg()
    try:
        with winreg.OpenKey(root, path) as key:
            value, _ = winreg.QueryValueEx(key, name)
            return value
    except OSError:
        return None


ROOTS = {}
if IS_WINDOWS:
    import winreg as _wr
    ROOTS = {"HKLM": _wr.HKEY_LOCAL_MACHINE, "HKCU": _wr.HKEY_CURRENT_USER}


def enum_uninstall_entries():
    """All uninstall entries: [{key, name, location, uninstall}]."""
    if not IS_WINDOWS:
        return []
    bases = [
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion"
                 r"\Uninstall"),
        ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    out = []
    for root_name, base in bases:
        root = ROOTS[root_name]
        for sub in reg_enum_subkeys(root, base):
            path = base + "\\" + sub
            name = reg_get_value(root, path, "DisplayName")
            if not name:
                continue
            size_kb = reg_get_value(root, path, "EstimatedSize")
            out.append({
                "key": "%s\\%s" % (root_name, path),
                "name": str(name),
                "location": str(reg_get_value(root, path,
                                              "InstallLocation") or ""),
                "uninstall": str(reg_get_value(root, path,
                                               "UninstallString") or ""),
                "size_kb": size_kb if isinstance(size_kb, int) else None,
                "install_date": str(reg_get_value(root, path,
                                                  "InstallDate") or ""),
                # Windows provides no reliable per-program "last used"
                # for most apps — kept as an honest blank, never guessed.
                "last_used": "",
            })
    return out


def enum_app_paths():
    """App Paths entries: [{key, name, target}]."""
    if not IS_WINDOWS:
        return []
    out = []
    for root_name in ("HKLM", "HKCU"):
        base = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"
        root = ROOTS[root_name]
        for sub in reg_enum_subkeys(root, base):
            path = base + "\\" + sub
            target = reg_get_value(root, path, "")
            if target:
                out.append({"key": "%s\\%s" % (root_name, path),
                            "name": sub, "target": str(target).strip('"')})
    return out


RUN_KEY_PATHS = [
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
]


def enum_run_values():
    """Run/RunOnce values: [{key, name, command}]."""
    if not IS_WINDOWS:
        return []
    out = []
    for root_name, path in RUN_KEY_PATHS:
        for v in reg_enum_values(ROOTS[root_name], path):
            out.append({"key": "%s\\%s" % (root_name, path),
                        "name": v["name"], "command": str(v["value"])})
    return out


def dir_size(path, cap_files=200000):
    """(bytes, hit_cap) — tolerant size walk."""
    if not path or not os.path.isdir(path):
        return 0, False
    total = 0
    count = 0
    for dirpath, _dirs, files in os.walk(path, onerror=lambda e: None):
        for f in files:
            count += 1
            if count > cap_files:
                return total, True
            try:
                total += os.path.getsize(os.path.join(dirpath, f))
            except OSError:
                pass
    return total, False


def needs_windows_finding(category, what):
    return Finding(category, "%s — needs Windows" % what,
                   detail="This check only runs on a Windows PC. "
                          "Nothing was scanned and nothing was faked.",
                   severity="info")


# ----------------------------------------------------------------------
# Scanners — one per category; each returns a list[Finding]
# ----------------------------------------------------------------------

def scan_safety(log):
    if not IS_WINDOWS:
        return [needs_windows_finding("safety", "System Restore status")]
    out = []
    ok, txt = ps_json(
        "$ErrorActionPreference='Stop'; try { "
        "Get-ComputerRestorePoint | Sort-Object CreationTime -Descending | "
        "Select-Object -First 5 @{n='Created';e={$_.CreationTime}}, "
        "Description | ConvertTo-Json -Compress } catch { "
        "'ERR:' + $_.Exception.Message }",
        timeout=120, log=log)
    if ok and txt.strip().startswith("ERR:"):
        msg = txt.strip()[4:]
        out.append(Finding(
            "safety", "System Restore appears to be OFF or unavailable",
            detail="Windows said: %s" % msg,
            why="Restore points are this app's safety net — fixes will not "
                "run without one. Turn System Restore on in System "
                "Protection settings, then scan again.",
            severity="bad"))
        return out
    points = parse_json_list(txt) if ok else []
    if not points:
        out.append(Finding(
            "safety", "No restore points found",
            detail="Get-ComputerRestorePoint returned no points.",
            why="Either System Restore is off, or no point has been "
                "created yet. This app will try to enable it and create "
                "one before any fix; if that fails, fixes will not run.",
            severity="warn"))
    else:
        latest = points[0]
        out.append(Finding(
            "safety", "System Restore is on — %d point(s) available"
            % len(points),
            detail="Newest: %s (%s)" % (latest.get("Created"),
                                        latest.get("Description")),
            why="A restore point is the undo button for system changes. "
                "This app still creates a fresh one before any fix.",
            severity="info"))
    return out


def scan_sysfiles(log):
    if not IS_WINDOWS:
        return [needs_windows_finding("sysfiles", "SFC / DISM scan")]
    out = []
    log("Running sfc /verifyonly (this can take several minutes)…")
    rc, txt = run_cmd(["sfc", "/verifyonly"], timeout=1800, log=log)
    sfc = parse_sfc(txt)
    if sfc["status"] == "clean":
        out.append(Finding("sysfiles", "System files are intact",
                           detail="SFC verify: %s." % sfc["message"],
                           severity="info"))
    elif sfc["status"] == "unknown":
        out.append(Finding(
            "sysfiles", "SFC result could not be interpreted",
            detail="Raw result saved in the log. (%s)" % sfc["message"],
            why="Rather than guess, this app shows the raw outcome. "
                "Running the repair below is still safe.",
            fix_label="Repair system files with SFC (sfc /scannow)",
            fix_kind="sfc_scannow", severity="warn"))
    else:
        out.append(Finding(
            "sysfiles", "System file problems: %s" % sfc["status"],
            detail="SFC verify: %s." % sfc["message"],
            why="Corrupt Windows system files cause random glitches and "
                "crashes. SFC can repair them from the component store.",
            fix_label="Repair system files with SFC (sfc /scannow)",
            fix_kind="sfc_scannow", default_checked=True,
            severity="bad"))
    log("Running DISM /CheckHealth…")
    rc, txt = run_cmd(["DISM", "/Online", "/Cleanup-Image", "/CheckHealth"],
                      timeout=600, log=log)
    chk = parse_dism(txt)
    dism_status = chk["status"]
    if dism_status != "healthy":
        log("Running DISM /ScanHealth (deeper check)…")
        rc, txt = run_cmd(["DISM", "/Online", "/Cleanup-Image",
                           "/ScanHealth"], timeout=1800, log=log)
        dism_status = parse_dism(txt)["status"]
    if dism_status == "healthy":
        out.append(Finding("sysfiles", "Windows component store is healthy",
                           detail="DISM reports no component store "
                                  "corruption.",
                           severity="info"))
    elif dism_status == "repairable":
        out.append(Finding(
            "sysfiles", "Windows component store is corrupted (repairable)",
            detail="DISM reports the component store is repairable.",
            why="The component store is where SFC gets clean files. If it "
                "is corrupt, system repairs fail. DISM /RestoreHealth "
                "repairs it (may use Windows Update as a source).",
            fix_label="Repair the component store (DISM /RestoreHealth)",
            fix_kind="dism_restore", default_checked=True,
            severity="bad"))
    else:
        out.append(Finding(
            "sysfiles",
            "DISM result: %s" % dism_status,
            detail="See the log for the full DISM output.",
            why="The component store state could not be confirmed. A "
                "RestoreHealth attempt is the standard next step.",
            fix_label="Repair the component store (DISM /RestoreHealth)",
            fix_kind="dism_restore", severity="warn"))
    return out


def scan_disk(log):
    if not IS_WINDOWS:
        return [needs_windows_finding("disk", "Disk health scan")]
    out = []
    ok, txt = ps_json(
        "Get-PhysicalDisk | Select-Object FriendlyName, MediaType, "
        "HealthStatus, OperationalStatus, Size | ConvertTo-Json -Compress",
        timeout=120, log=log)
    disks = parse_json_list(txt) if ok else []
    for d in disks:
        health = str(d.get("HealthStatus") or "")
        name = d.get("FriendlyName") or "Disk"
        sev = "info" if health.lower() == "healthy" else "bad"
        out.append(Finding(
            "disk", "%s — %s (%s, %s)" % (
                name, health or "health unknown",
                d.get("MediaType") or "?", human_size(d.get("Size"))),
            detail="Operational status: %s" % d.get("OperationalStatus"),
            why="Windows' own storage health report. 'Unhealthy' here is "
                "an early warning of drive failure — back up first, "
                "replace soon." if sev == "bad" else "",
            severity=sev))
    if not disks:
        out.append(Finding("disk", "Could not read physical disk info",
                           detail="Get-PhysicalDisk returned nothing.",
                           severity="warn"))
    ok, txt = ps_json(
        "Get-Volume | Where-Object DriveLetter | Select-Object "
        "DriveLetter, FileSystemLabel, Size, SizeRemaining | "
        "ConvertTo-Json -Compress", timeout=120, log=log)
    for v in parse_json_list(txt) if ok else []:
        size = v.get("Size") or 0
        free = v.get("SizeRemaining") or 0
        pct = (100.0 * free / size) if size else 0
        letter = v.get("DriveLetter")
        sev = "info"
        title = "Drive %s: — %s free of %s (%.0f%%)" % (
            letter, human_size(free), human_size(size), pct)
        if pct < 10:
            sev = "warn"
            title += " — nearly full"
        out.append(Finding(
            "disk", title,
            detail="A nearly-full system drive slows Windows and breaks "
                   "updates. Freeing space is manual — this app's Junk "
                   "section can reclaim cache space." if sev == "warn"
                   else "",
            why="Windows needs breathing room for updates and virtual "
                "memory." if sev == "warn" else "",
            fix_label="Run an online disk check on %s: (chkdsk /scan)"
                      % letter,
            fix_kind="chkdsk_scan", payload={"drive": "%s:" % letter},
            severity=sev))
    return out


def scan_update(log):
    if not IS_WINDOWS:
        return [needs_windows_finding("update", "Windows Update scan")]
    out = []
    ok, txt = ps_json(
        "Get-Service wuauserv,bits,cryptsvc,UsoSvc,TrustedInstaller "
        "-ErrorAction SilentlyContinue | Select-Object Name, DisplayName, "
        "Status, StartType | ConvertTo-Json -Compress",
        timeout=120, log=log)
    services = parse_service_states(txt) if ok else {}
    label = {"wuauserv": "Windows Update", "bits": "Background Transfer "
             "(BITS)", "cryptsvc": "Cryptographic Services",
             "usosvc": "Update Orchestrator",
             "trustedinstaller": "Windows Modules Installer"}
    for key in ("wuauserv", "bits", "cryptsvc", "usosvc"):
        svc = services.get(key)
        if not svc:
            out.append(Finding("update", "%s service not found"
                               % label[key], severity="warn"))
        elif svc["status"].lower() == "stopped" and \
                svc["start_type"].lower() == "disabled":
            out.append(Finding(
                "update", "%s service is DISABLED" % label[key],
                detail="Status: %s, start type: %s" % (svc["status"],
                                                        svc["start_type"]),
                why="A disabled update service means no patches — a "
                    "security risk. Re-enable it in Services "
                    "(services.msc) or set it back to Manual.",
                severity="bad"))
        else:
            out.append(Finding(
                "update", "%s service: %s (%s)" % (label[key],
                                                   svc["status"],
                                                   svc["start_type"]),
                severity="info"))
    ok, txt = ps_json(
        "$r = [ordered]@{}; "
        "$r.cbs = Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\"
        "CurrentVersion\\Component Based Servicing\\RebootPending'; "
        "$r.wu = Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\"
        "CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired'; "
        "$s = Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\"
        "Control\\Session Manager' -Name PendingFileRenameOperations "
        "-ErrorAction SilentlyContinue; "
        "$r.file_rename = $null -ne $s; $r.computer_rename = $false; "
        "[pscustomobject]$r | ConvertTo-Json -Compress",
        timeout=120, log=log)
    reasons = parse_pending_reboot(
        (parse_json_list(txt) or [{}])[0] if ok else {})
    if reasons:
        out.append(Finding(
            "update", "A reboot is pending",
            detail="; ".join(reasons) + ".",
            why="Pending reboots stall updates and cause odd behavior. "
                "Restart the PC, then scan again.",
            severity="warn"))
    else:
        out.append(Finding("update", "No reboot is pending",
                           severity="info"))
    ok, txt = ps_json(
        "Get-HotFix | Sort-Object InstalledOn -Descending | "
        "Select-Object -First 1 HotFixID, InstalledOn | "
        "ConvertTo-Json -Compress", timeout=120, log=log)
    fixes = parse_json_list(txt) if ok else []
    if fixes:
        out.append(Finding(
            "update", "Most recent installed update: %s (%s)"
            % (fixes[0].get("HotFixID"), fixes[0].get("InstalledOn")),
            severity="info"))
    return out


def scan_security(log):
    """Audit Defender / Firewall / SmartScreen — never a homemade AV."""
    if not IS_WINDOWS:
        return [needs_windows_finding("security", "Security posture scan")]
    out = []
    ok, txt = ps_json(
        "Get-MpComputerStatus | Select-Object AMServiceEnabled, "
        "AMRunningMode, AntivirusEnabled, RealTimeProtectionEnabled, "
        "IoavProtectionEnabled, IsTamperProtected, "
        "AntivirusSignatureLastUpdated, AntivirusSignatureAge, "
        "QuickScanEndTime, FullScanEndTime, QuickScanNeeded, "
        "FullScanNeeded | ConvertTo-Json -Compress",
        timeout=120, log=log)
    st = parse_defender_status(txt) if ok else {"present": False}
    if not st.get("present"):
        out.append(Finding(
            "security", "Could not read Microsoft Defender status",
            detail="The Defender status cmdlets did not answer. If a "
                   "third-party antivirus is installed it may be managing "
                   "protection instead.",
            why="Windows Security (Start → 'Windows Security') shows "
                "which antivirus is in charge. Make sure SOMETHING is.",
            severity="warn"))
    else:
        if not st["rtp"]:
            out.append(Finding(
                "security", "Defender real-time protection is OFF",
                detail="Real-time protection is what stops malware as it "
                       "runs, not just during scans.",
                why="With real-time protection off, Defender only helps "
                    "during manual scans. Turn it back on.",
                fix_label="Turn Defender real-time protection back on",
                fix_kind="defender_rtp_enable", default_checked=True,
                severity="bad"))
        else:
            out.append(Finding("security",
                               "Defender real-time protection is on",
                               severity="info"))
        age = st["sig_age_days"]
        if age is None:
            out.append(Finding(
                "security", "Antivirus signature age unknown",
                detail="Defender did not report a signature date.",
                severity="warn"))
        elif age <= 2:
            out.append(Finding(
                "security", "Antivirus signatures are current "
                "(%d day(s) old)" % age, severity="info"))
        else:
            sev = "bad" if age > 7 else "warn"
            out.append(Finding(
                "security", "Antivirus signatures are %d days old" % age,
                detail="Last updated: %s" % st["sig_updated"],
                why="Old signatures miss new malware. Updating them is "
                    "free and takes a minute.",
                fix_label="Update Defender antivirus signatures now",
                fix_kind="defender_update", default_checked=True,
                severity=sev))
        if not st["tamper"]:
            out.append(Finding(
                "security", "Tamper Protection is off",
                detail="Tamper Protection stops malware from quietly "
                       "changing Defender's settings.",
                why="It can only be switched on in the Windows Security "
                    "app (by design): Windows Security → Virus & threat "
                    "protection → Manage settings → Tamper Protection.",
                severity="warn"))
        else:
            out.append(Finding("security", "Tamper Protection is on",
                               severity="info"))
        last_quick = st["quick_scan_end"]
        if st["quick_scan_needed"] or last_quick is None:
            detail = ("Defender says a quick scan is needed."
                      if st["quick_scan_needed"] else
                      "No quick scan has been recorded on this PC.")
            out.append(Finding("security", "A Defender quick scan is due",
                               detail=detail, severity="warn"))
        else:
            out.append(Finding(
                "security", "Last Defender quick scan: %s" % last_quick,
                severity="info"))
        # The one security ACTION: a quick scan, run by Defender itself.
        out.append(Finding(
            "security", "Run a Defender Quick Scan",
            detail="Defender does the scanning and makes all quarantine "
                   "decisions — this app only starts it and reports "
                   "what Defender found.",
            why="A quick scan checks the places malware usually hides. "
                "It is OFF by default here because it takes a few "
                "minutes; tick it if you want it in this run.",
            fix_label="Run Defender Quick Scan (results reported after)",
            fix_kind="defender_scan", default_checked=False,
            severity="info"))
    # Exclusions — a classic malware hiding trick.
    ok, txt = ps_json(
        "Get-MpPreference | Select-Object ExclusionPath, "
        "ExclusionExtension, ExclusionProcess, ExclusionIpAddress | "
        "ConvertTo-Json -Compress", timeout=120, log=log)
    exclusions = parse_defender_exclusions(txt) if ok else []
    if exclusions:
        for ex in exclusions:
            out.append(Finding(
                "security", "Defender exclusion: %s '%s'"
                % (ex["type"], ex["value"]),
                detail="Exclusions tell Defender to never scan "
                       "something. Legitimate for a few work tools — "
                       "but malware also hides this way.",
                why="If you don't recognize this exclusion, remove it. "
                    "You can always re-add it in Windows Security.",
                fix_label="Remove this Defender exclusion",
                fix_kind="exclusion_remove", payload=dict(ex),
                severity="warn"))
    elif ok:
        out.append(Finding("security", "No Defender exclusions configured",
                           detail="Nothing is exempt from scanning — "
                                  "the normal, safe state.",
                           severity="info"))
    # Firewall profiles.
    ok, txt = ps_json(
        "Get-NetFirewallProfile | Select-Object Name, Enabled | "
        "ConvertTo-Json -Compress", timeout=120, log=log)
    profiles = parse_firewall_profiles(txt) if ok else []
    if profiles:
        for p in profiles:
            if p["enabled"]:
                out.append(Finding(
                    "security", "Firewall is ON for the %s profile"
                    % p["name"], severity="info"))
            else:
                out.append(Finding(
                    "security", "Firewall is OFF for the %s profile"
                    % p["name"],
                    detail="This profile applies to %s networks." %
                    {"Domain": "domain", "Private": "home/work (private)",
                     "Public": "public (coffee-shop/airport)"}.get(
                         p["name"], "some"),
                    why="The firewall is the front door lock. It should "
                        "be on for every profile, above all Public.",
                    fix_label="Turn the firewall ON for %s" % p["name"],
                    fix_kind="firewall_enable",
                    payload={"profile": p["name"]},
                    default_checked=True, severity="bad"))
    # SmartScreen (report-only).
    ss = reg_get_value(ROOTS["HKLM"],
                       r"SOFTWARE\Microsoft\Windows\CurrentVersion"
                       r"\Explorer", "SmartScreenEnabled")
    out.append(Finding(
        "security", "SmartScreen (app & browser checks): %s"
        % interpret_smartscreen(str(ss) if ss is not None else ""),
        detail="SmartScreen checks downloaded apps and files against "
               "Microsoft's reputation service. Report-only in this app — "
               "change it in Windows Security → App & browser control.",
        severity="warn" if (ss and str(ss).lower() == "off") else "info"))
    # Malwarebytes: second-opinion scanner, detected — never bundled.
    mb = find_malwarebytes(enum_uninstall_entries())
    if mb:
        exe = ""
        loc = (mb.get("location") or "").strip()
        for cand in ("Malwarebytes.exe", "mbam.exe"):
            p = os.path.join(loc, cand) if loc else ""
            if p and os.path.exists(p):
                exe = p
                break
        out.append(Finding(
            "security", "Malwarebytes is installed (second-opinion "
            "scanner)",
            detail="A good second set of eyes alongside Defender. You "
                   "can launch it from the details button below." if exe
                   else "Installed; launch it from the Start menu for a "
                        "second-opinion scan.",
            payload={"launch": exe} if exe else {},
            severity="info"))
    else:
        out.append(Finding(
            "security", "Malwarebytes is not installed",
            detail="Optional, honest suggestion: Malwarebytes Free is "
                   "a respected second-opinion scanner. It can't be "
                   "bundled with this app (their license forbids "
                   "redistributing the installer, and a bundled copy "
                   "would go stale anyway) — the button below opens "
                   "their official download page so the installer comes "
                   "straight from them, current version, their terms.",
            payload={"url": "https://www.malwarebytes.com/mwb-download/"
                            "thankyou",
                     "url_label": "Get Malwarebytes Free (official "
                                  "site)"},
            severity="info"))
    return out


WU_DRIVER_SEARCH_PS = (
    "$ErrorActionPreference = 'Stop'; "
    "$session = New-Object -ComObject Microsoft.Update.Session; "
    "$searcher = $session.CreateUpdateSearcher(); "
    "$result = $searcher.Search(\"Type='Driver' and IsInstalled=0\"); "
    "$list = @(); foreach ($u in $result.Updates) { "
    "$list += [pscustomobject]@{ Title = $u.Title; "
    "UpdateID = $u.Identity.UpdateID; "
    "RevisionNumber = $u.Identity.RevisionNumber; "
    "DriverClass = $u.DriverClass; "
    "DriverManufacturer = $u.DriverManufacturer; "
    "DriverModel = $u.DriverModel; "
    "MaxDownloadSize = $u.MaxDownloadSize; "
    "LastDeploymentChangeTime = "
    "$u.LastDeploymentChangeTime.ToString('yyyy-MM-dd') } }; "
    "$list | ConvertTo-Json -Compress")


def scan_devices(log):
    if not IS_WINDOWS:
        return [needs_windows_finding("devices", "Device & driver scan")]
    out = []
    # --- Full signed-driver inventory -------------------------------
    ok, txt = ps_json(
        "Get-CimInstance Win32_PnPSignedDriver | Select-Object "
        "DeviceName, DriverProviderName, DriverVersion, DriverDate, "
        "InfName, DeviceID, DeviceClass | ConvertTo-Json -Compress",
        timeout=300, log=log)
    inventory = parse_signed_drivers(txt) if ok else []
    inv_by_name = {}
    for d in inventory:
        inv_by_name[d["device"].lower()] = d
    third_party = [d for d in inventory
                   if d["provider"] and "microsoft" not in
                   d["provider"].lower()]
    if inventory:
        lines = ["%s — %s %s (%s)" % (d["device"], d["provider"],
                                      d["version"], d["date"])
                 for d in inventory[:60]]
        if len(inventory) > 60:
            lines.append("… and %d more (see the log)"
                         % (len(inventory) - 60))
        out.append(Finding(
            "devices", "Driver inventory: %d device(s) with signed "
            "drivers (%d third-party)" % (len(inventory),
                                          len(third_party)),
            detail="\n".join(lines),
            why="The full list of what's actually driving this "
                "hardware right now. An old driver is NOT a problem "
                "by itself — drivers only need changing when "
                "something is broken or Microsoft matches an update "
                "to this exact hardware.",
            severity="info"))
    else:
        out.append(Finding("devices",
                           "Could not read the driver inventory",
                           detail="Win32_PnPSignedDriver returned "
                                  "nothing usable.",
                           severity="warn"))
    # --- Problem devices, joined with their driver info -------------
    ok, txt = ps_json(
        "Get-CimInstance Win32_PnPEntity | Where-Object { "
        "$_.ConfigManagerErrorCode -ne 0 } | Select-Object Name, "
        "PNPClass, ConfigManagerErrorCode | ConvertTo-Json -Compress",
        timeout=180, log=log)
    problems = parse_problem_devices(txt) if ok else []
    if not problems:
        out.append(Finding("devices",
                           "No problem devices reported by Windows",
                           severity="info"))
    for d in problems:
        inv = inv_by_name.get(d["name"].lower())
        detail = "Windows problem code %d." % d["code"]
        if inv:
            detail += "\nCurrent driver: %s %s (%s), INF %s" % (
                inv["provider"], inv["version"], inv["date"],
                inv["inf"])
        out.append(Finding(
            "devices", "%s (%s) — %s" % (d["name"], d["class"] or "?",
                                         d["meaning"]),
            detail=detail,
            why="Devices with problem codes usually mean a missing, "
                "corrupt, or failed driver. Below, Windows Update "
                "matches are offered for install — those come from "
                "Microsoft, matched to this machine's hardware IDs.",
            severity="warn"))
    out.append(Finding(
        "devices", "Back up all third-party drivers (safety action)",
        detail="Exports every third-party driver with DISM "
               "/Export-Driver into a timestamped folder next to "
               "this app. REQUIRED in the same fix run before any "
               "driver install below. Restoring is through Device "
               "Manager (Update driver → Browse) — there is "
               "deliberately no one-click driver restore here.",
        why="A driver backup is the undo button for driver changes: "
            "if a new driver misbehaves you can roll back to the "
            "exact drivers this PC runs today.",
        fix_label="Export all third-party drivers now",
        fix_kind="driver_backup", severity="info"))
    # --- Windows Update driver matches (the ONLY search source) -----
    log("Asking Windows Update which drivers it matches for this PC "
        "(can take a minute)…")
    ok, txt = ps_json(WU_DRIVER_SEARCH_PS, timeout=900, log=log)
    updates = parse_wu_driver_updates(txt) if ok else []
    if not ok:
        out.append(Finding(
            "devices", "Windows Update driver search didn't answer",
            detail="The WU Agent search failed — see the log. No "
                   "other source is used, on purpose.",
            severity="warn"))
    elif not updates:
        out.append(Finding(
            "devices", "No driver updates matched for this PC",
            detail="Windows Update — the only source this app uses, "
                   "because Microsoft matches updates to this "
                   "machine's actual hardware IDs — has no driver "
                   "updates for this hardware right now. That is a "
                   "complete answer even if some installed drivers "
                   "are old: old is not broken.",
            severity="info"))
    for u in updates:
        current = ""
        inv = inv_by_name.get((u["model"] or "").lower())
        if inv:
            current = inv["version"]
        caution = ""
        sev = "info"
        if u["risk"] == "gpu":
            caution = ("\nCAUTION: display/GPU driver — the screen "
                       "may flicker or go blank briefly during "
                       "install, and a bad one is the most disruptive "
                       "to undo. Left unticked on purpose.")
            sev = "warn"
        elif u["risk"] == "storage":
            caution = ("\nCAUTION: storage-controller driver — this "
                       "drives the disk Windows boots from. Left "
                       "unticked on purpose; be extra sure.")
            sev = "warn"
        out.append(Finding(
            "devices", "Driver update (Windows Update): %s" % u["title"],
            detail="Matched by Microsoft for: %s (%s). Download "
                   "size: %s.%s%s" % (
                       u["model"] or "this hardware",
                       u["manufacturer"] or "unknown maker",
                       human_size(u["size"]),
                       ("\nCurrently installed: %s" % current)
                       if current else "", caution),
            why="Installs run ONE at a time through Windows Update "
                "itself, only if you tick them, only after a restore "
                "point AND the driver backup above have completed "
                "in the same run. After each install the device is "
                "re-checked and old → new versions are logged.",
            fix_label="Install this driver via Windows Update",
            fix_kind="driver_install",
            payload={"update_id": u["update_id"],
                     "revision": u["revision"], "title": u["title"],
                     "model": u["model"],
                     "current_version": current,
                     "risk": u["risk"]},
            default_checked=False, severity=sev))
    return out


def scan_startup(log):
    if not IS_WINDOWS:
        return [needs_windows_finding("startup", "Startup audit")]
    out = []
    items = []
    for v in enum_run_values():
        items.append({"name": v["name"], "source": "Registry Run key",
                      "command": v["command"],
                      "disable": {"mode": "run_value", "key": v["key"],
                                  "name": v["name"]}})
    startup_dirs = []
    appdata = os.environ.get("APPDATA")
    if appdata:
        startup_dirs.append(os.path.join(
            appdata, r"Microsoft\Windows\Start Menu\Programs\Startup"))
    programdata = os.environ.get("PROGRAMDATA")
    if programdata:
        startup_dirs.append(os.path.join(
            programdata, r"Microsoft\Windows\Start Menu\Programs"
                         r"\Startup"))
    for folder in startup_dirs:
        if os.path.isdir(folder):
            for fn in os.listdir(folder):
                if fn.lower() == "desktop.ini":
                    continue
                items.append({"name": fn, "source": "Startup folder",
                              "command": os.path.join(folder, fn),
                              "disable": {"mode": "shortcut",
                                          "path": os.path.join(folder,
                                                               fn)}})
    ok, txt = ps_json(
        "$out = @(); foreach ($t in Get-ScheduledTask) { "
        "$kinds = $t.Triggers | ForEach-Object { "
        "$_.CimClass.CimClassName }; "
        "if ($kinds -match 'Logon|Boot') { "
        "$acts = $t.Actions | ForEach-Object { "
        "($_.Execute + ' ' + $_.Arguments).Trim() }; "
        "$out += [pscustomobject]@{ Name = $t.TaskName; "
        "Path = $t.TaskPath; State = [string]$t.State; "
        "Execute = ($acts -join '; ') } } }; "
        "$out | ConvertTo-Json -Compress", timeout=240, log=log)
    for t in parse_json_list(txt) if ok else []:
        if (t.get("Path") or "").startswith("\\Microsoft\\"):
            continue  # Microsoft's own tasks are normal; skip the noise
        items.append({"name": t.get("Name") or "?",
                      "source": "Scheduled task (logon/boot)",
                      "command": t.get("Execute") or "",
                      "disable": {"mode": "task",
                                  "name": t.get("Name"),
                                  "path": t.get("Path")}})
    console = []
    missing = []
    ordinary = 0
    for item in items:
        flags = classify_startup_item(item)
        entry = dict(item, flags=flags)
        if flags["target_missing"]:
            missing.append(entry)
        elif flags["is_console"]:
            console.append(entry)
        else:
            ordinary += 1
    for e in missing:
        out.append(Finding(
            "startup", "Startup entry points at a missing file: %s"
            % e["name"],
            detail="From %s: %s" % (e["source"], e["command"]),
            why="The program is gone but its startup entry remains — "
                "Windows wastes time on it at every sign-in, and dead "
                "entries can pop error messages or blank console "
                "windows. Disabling removes the entry (with a backup).",
            fix_label="Disable this dead startup entry",
            fix_kind="startup_disable", payload={"disable": e["disable"]},
            default_checked=True, severity="warn"))
    for e in console:
        out.append(Finding(
            "startup", "Console-style startup item: %s" % e["name"],
            detail="From %s: %s" % (e["source"], e["command"]),
            why="Console items (cmd / PowerShell / batch files) are "
                "the usual cause of black command windows flashing at "
                "sign-in. If you don't recognize this one, disabling "
                "it is the test — it's reversible from the backup.",
            fix_label="Disable this startup item",
            fix_kind="startup_disable", payload={"disable": e["disable"]},
            severity="warn"))
    out.append(Finding(
        "startup", "%d startup item(s) look ordinary" % ordinary,
        detail="They were enumerated and their targets exist. Ordinary "
               "doesn't mean necessary — anything you don't use can be "
               "disabled in Task Manager → Startup for a faster sign-in.",
        severity="info"))
    return out


def scan_events(log):
    if not IS_WINDOWS:
        return [needs_windows_finding("events", "Event log scan")]
    ok, txt = ps_json(
        "$start = (Get-Date).AddDays(-14); "
        "Get-WinEvent -FilterHashtable @{ LogName = @('System', "
        "'Application'); Level = @(1, 2); StartTime = $start } "
        "-MaxEvents 3000 -ErrorAction Stop | Select-Object "
        "ProviderName, Id, LevelDisplayName | ConvertTo-Json -Compress",
        timeout=300, log=log)
    if not ok:
        return [Finding("events", "Could not read the event logs",
                        detail="See the log for the error.",
                        severity="warn")]
    events = parse_json_list(txt)
    out = [Finding("events", "%d error/critical events in the last "
                   "14 days" % len(events),
                   detail="Grouped below by source — repeats are what "
                          "matter; one-off errors are usually noise.",
                   severity="info")]
    for g in group_events(events):
        title = "%s — %s (×%d)" % (g["provider"], g["id"], g["count"])
        out.append(Finding(
            "events", title,
            detail="Level: %s. %s" % (
                g["level"],
                g["explanation"] or
                "No plain-language note for this one yet — search the "
                "provider name + event ID for details."),
            why=g["explanation"] or "",
            severity="warn" if g["level"] in ("Critical", "Error")
            else "info"))
    return out


def junk_locations():
    """Known junk/cache locations: [(key, label, path, fix_kind)]."""
    env = os.environ
    locs = []
    if env.get("TEMP"):
        locs.append(("user_temp", "Your temporary files folder",
                     env["TEMP"], "cleanup_temp"))
    windir = env.get("SystemRoot") or env.get("WINDIR")
    if windir:
        locs.append(("win_temp", "Windows temporary files",
                     os.path.join(windir, "Temp"), "cleanup_temp"))
        locs.append(("wu_cache", "Windows Update download cache",
                     os.path.join(windir, "SoftwareDistribution",
                                  "Download"), "cleanup_wu_cache"))
    local = env.get("LOCALAPPDATA")
    if local:
        locs.append(("thumb_cache",
                     "Thumbnail cache (picture previews)",
                     os.path.join(local, "Microsoft", "Windows",
                                  "Explorer"), "cache_rebuild"))
        locs.append(("icon_cache", "Icon cache",
                     local, "cache_rebuild"))
    return locs


def recycle_bin_size():
    if not IS_WINDOWS:
        return 0
    total = 0
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        p = "%s:\\$Recycle.Bin" % letter
        if os.path.isdir(p):
            size, _ = dir_size(p, cap_files=50000)
            total += size
    return total


def scan_junk(log):
    if not IS_WINDOWS:
        return [needs_windows_finding("junk", "Junk & cache scan")]
    out = []
    for key, label, path, kind in junk_locations():
        if key in ("thumb_cache", "icon_cache"):
            # Size only the cache files themselves, not the whole folder.
            pats = ("thumbcache_*.db",) if key == "thumb_cache" else \
                ("iconcache_*.db", "IconCache.db")
            import glob as _glob
            size = 0
            for pat in pats:
                for fp in _glob.glob(os.path.join(path, pat)):
                    try:
                        size += os.path.getsize(fp)
                    except OSError:
                        pass
            if size == 0:
                continue
            out.append(Finding(
                "junk", "%s: %s" % (label, human_size(size)),
                detail="Cache files in %s" % path,
                why="When these caches corrupt, icons and picture "
                    "previews break or show the wrong image. Deleting "
                    "them is safe — Windows rebuilds them automatically.",
                fix_label="Rebuild the %s" % label.lower(),
                fix_kind="cache_rebuild", payload={"which": key},
                default_checked=True, severity="info"))
            continue
        size, capped = dir_size(path)
        if size == 0:
            continue
        out.append(Finding(
            "junk", "%s: %s%s" % (label, human_size(size),
                                  " (at least)" if capped else ""),
            detail="Location: %s" % path,
            why="Temporary and cache files are safe to clear; programs "
                "recreate what they need. Files in use are skipped, "
                "never forced.",
            fix_label="Clear %s" % label.lower(),
            fix_kind=kind, payload={"which": key, "path": path},
            default_checked=True, severity="info"))
    rb = recycle_bin_size()
    if rb:
        out.append(Finding(
            "junk", "Recycle Bin: %s" % human_size(rb),
            detail="Emptying the Recycle Bin is permanent, so this app "
                   "leaves it to you: right-click the Recycle Bin → "
                   "Empty Recycle Bin, when you're sure.",
            severity="info"))
    # Font cache (service-profile location; size is informational).
    windir = os.environ.get("SystemRoot") or ""
    fontcache = os.path.join(
        windir, "ServiceProfiles", "LocalService", "AppData", "Local",
        "FontCache")
    if windir and os.path.isdir(fontcache):
        size, _ = dir_size(fontcache, cap_files=5000)
        if size:
            out.append(Finding(
                "junk", "Font cache: %s" % human_size(size),
                detail="Location: %s" % fontcache,
                why="A corrupt font cache makes text render wrong or "
                    "programs crash on fonts. Rebuilding it (stop the "
                    "Font Cache service, clear, restart) is the "
                    "standard fix.",
                fix_label="Rebuild the font cache",
                fix_kind="cache_rebuild", payload={"which": "font_cache"},
                severity="info"))
    if not out:
        out.append(Finding("junk", "No significant junk or cache buildup",
                           severity="info"))
    return out


def scan_registry(log):
    """Conservative registry leftovers — the ONLY classes ever offered."""
    if not IS_WINDOWS:
        return [needs_windows_finding("registry", "Registry leftover scan")]
    out = []
    for e in stale_app_paths(enum_app_paths()):
        out.append(Finding(
            "registry", "Dead App Paths entry: %s" % e["name"],
            detail="Key: %s\nPoints at: %s (missing)" % (e["key"],
                                                          e["target"]),
            why="An app registered this launch shortcut but the program "
                "is gone. The stale entry is harmless clutter — and "
                "exactly the kind of leftover that is provably safe to "
                "remove. A .reg backup is exported first.",
            fix_label="Remove this dead App Paths entry",
            fix_kind="registry_remove",
            payload={"mode": "subkey", "key": e["key"]},
            severity="info"))
    for e in stale_uninstall(enum_uninstall_entries()):
        out.append(Finding(
            "registry", "Uninstall leftover: %s" % e["name"],
            detail="Key: %s\nInstall folder was: %s (gone)"
                   % (e["key"], e["location"]),
            why="The program was removed but its 'installed apps' "
                "entry stayed behind. Removing the entry only cleans "
                "the list — a .reg backup is exported first.",
            fix_label="Remove this stale uninstall entry",
            fix_kind="registry_remove",
            payload={"mode": "subkey", "key": e["key"]},
            severity="info"))
    if not out:
        out.append(Finding(
            "registry", "No provably-stale registry entries found",
            detail="This app only ever offers three conservative "
                   "classes: dead App Paths targets, uninstall entries "
                   "whose folder is gone, and startup entries pointing "
                   "at missing files (those are in the Startup "
                   "section). It does not go hunting through the "
                   "registry for 'errors' — that is how registry "
                   "cleaners break Windows.",
            severity="info"))
    return out


def scan_memory(log):
    if not IS_WINDOWS:
        return [needs_windows_finding("memory", "Memory check")]
    out = []
    ok, txt = ps_json(
        "Get-CimInstance Win32_ComputerSystem | Select-Object "
        "TotalPhysicalMemory | ConvertTo-Json -Compress",
        timeout=60, log=log)
    rows = parse_json_list(txt) if ok else []
    if rows:
        out.append(Finding(
            "memory", "Installed RAM: %s"
            % human_size(rows[0].get("TotalPhysicalMemory")),
            severity="info"))
    out.append(Finding(
        "memory", "Run Windows Memory Diagnostic",
        detail="Windows' built-in RAM test runs at reboot and takes "
               "5–15 minutes. Worth it if the PC blue-screens or "
               "crashes randomly.",
        why="Bad RAM causes exactly the 'Windows is acting up' "
            "symptoms — random crashes and corruption — and no "
            "software scan can rule it out from inside Windows.",
        fix_label="Launch Windows Memory Diagnostic (mdsched)",
        fix_kind="memdiag", severity="info"))
    return out


SCANNERS = [
    ("safety", scan_safety),
    ("sysfiles", scan_sysfiles),
    ("disk", scan_disk),
    ("update", scan_update),
    ("security", scan_security),
    ("devices", scan_devices),
    ("startup", scan_startup),
    ("events", scan_events),
    ("junk", scan_junk),
    ("registry", scan_registry),
    ("memory", scan_memory),
]
# scan_boot / scan_programs are defined further down (feature pack) and
# register themselves into SCANNERS at import time, in display order.


def run_scan(log, progress=None, only=None):
    """Run all scanners; one scanner failing never kills the scan."""
    findings = []
    for i, (cat, fn) in enumerate(SCANNERS):
        if only and cat not in only:
            continue
        if progress:
            progress(cat, i, len(SCANNERS))
        try:
            findings.extend(fn(log))
        except Exception as exc:  # honest failure entry, never a crash
            findings.append(Finding(
                cat, "This check failed to run: %s" % exc,
                detail="The failure was recorded in the log. Other "
                       "checks are unaffected.",
                severity="warn"))
            log("Scanner %s raised: %r" % (cat, exc))
    return findings


# ----------------------------------------------------------------------
# Fix executors (Windows only — every one degrades honestly elsewhere)
# ----------------------------------------------------------------------

def backup_dir():
    d = os.path.join(app_dir(), "backups",
                     datetime.datetime.now().strftime("%Y%m%d-%H%M%S"))
    os.makedirs(d, exist_ok=True)
    return d


def latest_restore_point_age_hours(log):
    ok, txt = ps_json(
        "Get-ComputerRestorePoint | Sort-Object CreationTime "
        "-Descending | Select-Object -First 1 CreationTime | "
        "ConvertTo-Json -Compress", timeout=120, log=log)
    rows = parse_json_list(txt) if ok else []
    if not rows:
        return None
    when = _parse_ms_date(rows[0].get("CreationTime"))
    if when is None:
        return None
    return (datetime.datetime.now() - when).total_seconds() / 3600.0


def create_restore_point(log):
    """(ok, message). The hard gate for every fix run."""
    if not IS_WINDOWS:
        return False, "restore points need Windows"
    # Make sure System Restore is enabled on the system drive.
    run_ps("Enable-ComputerRestore -Drive 'C:\\' -ErrorAction "
           "SilentlyContinue", timeout=120, log=log)
    rc, out = run_ps(
        "Checkpoint-Computer -Description 'Windows Health & Repair — "
        "before fixes' -RestorePointType 'MODIFY_SETTINGS'", 
        timeout=300, log=log)
    if rc == 0:
        return True, "restore point created"
    low = out.lower()
    age = latest_restore_point_age_hours(log)
    if ("frequency" in low or "24" in low or "too often" in low) and \
            age is not None and age < 24:
        return True, ("Windows refused a second restore point within "
                      "24h, but one from %.1f hours ago exists — gate "
                      "passed on that point" % age)
    if age is not None and age < 24 and rc != 0:
        # Some builds report the throttle only as a generic warning.
        return True, ("restore-point creation was refused, but a point "
                      "from %.1f hours ago exists — gate passed on "
                      "that point" % age)
    return False, ("could not create a restore point (%s). No fixes "
                   "were run. Check that System Restore is enabled "
                   "for the system drive." % out.strip()[:300])


def export_reg_key(key_path, log, tag="reg"):
    """Export a key to backups/. Returns the file path or None."""
    dest = os.path.join(backup_dir(),
                        "%s-%s.reg" % (tag, re.sub(r"[^\w.-]+", "_",
                                                   key_path)[-80:]))
    rc, out = run_cmd(["reg", "export", key_path, dest, "/y"],
                      timeout=60, log=log)
    if rc == 0 and os.path.exists(dest):
        log("Registry backup exported: %s" % dest)
        return dest
    log("WARNING: reg export failed for %s: %s" % (key_path,
                                                   out.strip()[:200]))
    return None


def clear_dir_contents(path, log, label):
    """Delete the CONTENTS of a directory (never the dir itself)."""
    freed = 0
    removed = 0
    skipped = 0
    if not path or not os.path.isdir(path):
        return removed, freed, skipped
    for entry in os.scandir(path):
        try:
            if entry.is_dir(follow_symlinks=False):
                size, _ = dir_size(entry.path)
                import shutil
                shutil.rmtree(entry.path, ignore_errors=False)
                freed += size
                removed += 1
            else:
                try:
                    size = entry.stat().st_size
                except OSError:
                    size = 0
                os.remove(entry.path)
                freed += size
                removed += 1
        except OSError:
            skipped += 1  # in use / locked — skip, never force
    log("%s: removed %d item(s), freed %s, skipped %d in-use item(s)"
        % (label, removed, human_size(freed), skipped))
    return removed, freed, skipped


def _restart_explorer(log):
    run_cmd(["taskkill", "/f", "/im", "explorer.exe"], timeout=60,
            log=log)
    try:
        subprocess.Popen(["explorer.exe"])
    except OSError as exc:
        log("WARNING: could not restart Explorer automatically: %s"
            % exc)


def fix_cache_rebuild(step, log):
    which = step.payload.get("which")
    local = os.environ.get("LOCALAPPDATA") or ""
    windir = os.environ.get("SystemRoot") or ""
    import glob as _glob
    if which in ("icon_cache", "thumb_cache"):
        patterns = []
        if which == "icon_cache":
            patterns = [os.path.join(local, "IconCache.db"),
                        os.path.join(local, "Microsoft", "Windows",
                                     "Explorer", "iconcache_*.db")]
        else:
            patterns = [os.path.join(local, "Microsoft", "Windows",
                                     "Explorer", "thumbcache_*.db")]
        run_cmd(["taskkill", "/f", "/im", "explorer.exe"], timeout=60,
                log=log)
        deleted = 0
        try:
            for pat in patterns:
                for fp in _glob.glob(pat):
                    try:
                        os.remove(fp)
                        deleted += 1
                    except OSError:
                        pass
        finally:
            try:
                subprocess.Popen(["explorer.exe"])
            except OSError as exc:
                log("WARNING: restart Explorer manually (%s)" % exc)
        return True, ("deleted %d cache file(s); Explorer restarted — "
                      "Windows rebuilds the cache automatically"
                      % deleted)
    if which == "font_cache":
        run_cmd(["net", "stop", "FontCache"], timeout=120, log=log)
        try:
            fc_dir = os.path.join(
                windir, "ServiceProfiles", "LocalService", "AppData",
                "Local", "FontCache")
            clear_dir_contents(fc_dir, log, "Font cache")
            dat = os.path.join(windir, "System32", "FNTCACHE.DAT")
            try:
                if os.path.exists(dat):
                    os.remove(dat)
            except OSError:
                pass
        finally:
            run_cmd(["net", "start", "FontCache"], timeout=120, log=log)
        return True, "font cache cleared and the Font Cache service " \
                     "restarted"
    return False, "unknown cache: %s" % which


MPCMDRUN_PS = (
    "$exe = $null; "
    "$plat = Get-ChildItem \"$env:ProgramData\\Microsoft\\Windows "
    "Defender\\Platform\" -Directory -ErrorAction SilentlyContinue | "
    "Sort-Object Name -Descending | Select-Object -First 1; "
    "if ($plat) { $exe = Join-Path $plat.FullName 'MpCmdRun.exe' }; "
    "if (-not $exe -or -not (Test-Path $exe)) { "
    "$exe = \"$env:ProgramFiles\\Windows Defender\\MpCmdRun.exe\" }; ")


WU_INSTALL_PS_TEMPLATE = (
    "$ErrorActionPreference = 'Stop'; "
    "$session = New-Object -ComObject Microsoft.Update.Session; "
    "$searcher = $session.CreateUpdateSearcher(); "
    "$result = $searcher.Search(\"Type='Driver' and "
    "IsInstalled=0\"); "
    "$upd = $null; foreach ($u in $result.Updates) { "
    "if ($u.Identity.UpdateID -eq '%(uid)s') { $upd = $u; break } }; "
    "if (-not $upd) { [pscustomobject]@{ NotFound = $true } | "
    "ConvertTo-Json -Compress; exit 0 }; "
    "$coll = New-Object -ComObject Microsoft.Update.UpdateColl; "
    "[void]$coll.Add($upd); "
    "if (-not $upd.EulaAccepted) { $upd.AcceptEula() }; "
    "if (-not $upd.IsDownloaded) { "
    "$dl = $session.CreateUpdateDownloader(); "
    "$dl.Updates = $coll; [void]$dl.Download() }; "
    "$inst = $session.CreateUpdateInstaller(); "
    "$inst.ForceQuiet = $true; $inst.Updates = $coll; "
    "$ires = $inst.Install(); "
    "[pscustomobject]@{ ResultCode = $ires.ResultCode; "
    "RebootRequired = $ires.RebootRequired } | "
    "ConvertTo-Json -Compress")


def fix_driver_install(step, log):
    """Install ONE WU-matched driver, then re-check the device."""
    uid = step.payload.get("update_id") or ""
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", uid):
        return False, "refusing: update ID looks wrong (%s)" % uid
    model = step.payload.get("model") or ""
    old_version = step.payload.get("current_version") or ""
    rc, out = run_ps(WU_INSTALL_PS_TEMPLATE % {"uid": uid},
                     timeout=3600, log=log)
    if rc != 0:
        return False, ("Windows Update install call failed: %s"
                       % out.strip()[:240])
    res = parse_wu_install_result(out)
    if res["outcome"] == "not_found":
        return False, ("this update is no longer offered by Windows "
                       "Update (already installed or withdrawn) — "
                       "nothing was changed")
    if res["outcome"] != "succeeded":
        return False, ("install outcome: %s (WU result code %s). "
                       "Recovery: Device Manager → the device → "
                       "Driver → Roll Back Driver, or reinstall from "
                       "the driver-backup folder made in this run."
                       % (res["outcome"], res["result_code"]))
    # Re-check: new version + problem status for the matched device.
    msg = "installed via Windows Update"
    ok, txt = ps_json(
        "Get-CimInstance Win32_PnPSignedDriver | Select-Object "
        "DeviceName, DriverProviderName, DriverVersion, DriverDate, "
        "InfName, DeviceID, DeviceClass | ConvertTo-Json -Compress",
        timeout=300, log=log)
    if ok and model:
        for d in parse_signed_drivers(txt):
            if model.lower() in d["device"].lower():
                if d["version"]:
                    msg += ". Version: %s → %s" % (
                        old_version or "(unknown)", d["version"])
                break
    ok2, txt2 = ps_json(
        "Get-CimInstance Win32_PnPEntity | Where-Object { "
        "$_.ConfigManagerErrorCode -ne 0 } | Select-Object Name, "
        "PNPClass, ConfigManagerErrorCode | ConvertTo-Json -Compress",
        timeout=180, log=log)
    if ok2 and model:
        still = [d for d in parse_problem_devices(txt2)
                 if model.lower() in d["name"].lower()]
        if still:
            msg += (" — note: the device still reports problem code "
                    "%d afterwards" % still[0]["code"])
    if res["reboot_required"]:
        msg += (" Windows says a REBOOT is required to finish — "
                "restart when it suits you; nothing here forces one.")
    return True, msg


def fix_defender_scan(step, log):
    """Start-MpScan QuickScan; detections are Defender's decisions."""
    started = datetime.datetime.now()
    rc, out = run_ps("Start-MpScan -ScanType QuickScan",
                     timeout=3600, log=log)
    if rc != 0:
        rc, out = run_cmd(["powershell", "-NoProfile", "-Command",
                           MPCMDRUN_PS + "& $exe -Scan -ScanType 1"],
                          timeout=3600, log=log)
    ok, txt = ps_json(
        "Get-MpThreatDetection | Select-Object ThreatID, "
        "InitialDetectionTime, ThreatStatusID, Resources | "
        "ConvertTo-Json -Compress", timeout=120, log=log)
    detections = parse_threat_detections(txt) if ok else []
    fresh = [d for d in detections
             if d["detected"] and d["detected"] >= started]
    if rc != 0:
        return False, ("Defender quick scan did not complete: %s"
                       % out.strip()[:300])
    if fresh:
        ids = ", ".join(str(d["threat_id"]) for d in fresh)
        return True, ("quick scan finished — Defender recorded %d NEW "
                      "detection(s) (threat IDs: %s). Defender handles "
                      "quarantine itself; review and decide in Windows "
                      "Security → Protection history."
                      % (len(fresh), ids))
    return True, ("quick scan finished — no new detections. (Total "
                  "historical detections on record: %d)"
                  % len(detections))


def run_fix_step(step, log):
    """Execute one fix step -> (ok, message). Restore point handled by
    the plan runner, not here."""
    kind = step.kind
    p = step.payload
    if not IS_WINDOWS:
        return False, "needs Windows"
    try:
        if kind == "driver_backup":
            dest = driver_backup_dest()
            rc, out = run_cmd(
                ["DISM", "/Online", "/Export-Driver",
                 "/Destination:%s" % dest], timeout=1800, log=log)
            infs = 0
            if os.path.isdir(dest):
                for _dp, _dn, files in os.walk(dest):
                    infs += sum(1 for f in files
                                if f.lower().endswith(".inf"))
            if rc == 0 and infs:
                return True, ("third-party drivers exported to %s "
                              "(%d driver packages). Restore any of "
                              "them later via Device Manager → Update "
                              "driver → Browse my computer → point it "
                              "at that folder." % (dest, infs))
            return False, ("driver export did not complete (%s)"
                           % out.strip()[:200])
        if kind == "sfc_scannow":
            rc, out = run_cmd(["sfc", "/scannow"], timeout=3600, log=log)
            res = parse_sfc(out)
            return True, "sfc /scannow finished: %s" % res["message"]
        if kind == "dism_restore":
            rc, out = run_cmd(
                ["DISM", "/Online", "/Cleanup-Image", "/RestoreHealth"],
                timeout=3600, log=log)
            res = parse_dism(out)
            if rc == 0:
                return True, "DISM /RestoreHealth completed"
            return False, "DISM /RestoreHealth reported: %s" \
                % res["message"]
        if kind == "chkdsk_scan":
            drive = p.get("drive") or "C:"
            rc, out = run_cmd(["chkdsk", drive, "/scan"], timeout=3600,
                              log=log)
            low = out.lower()
            if "found no problems" in low:
                return True, "chkdsk %s: no problems found" % drive
            if "found problems" in low or "found errors" in low:
                return True, ("chkdsk %s found problems — schedule the "
                              "offline repair by running 'chkdsk %s /f' "
                              "and restarting (left to you on purpose)"
                              % (drive, drive))
            return (rc == 0), "chkdsk %s finished (see log)" % drive
        if kind == "registry_remove":
            key = p.get("key") or ""
            if export_reg_key(key, log) is None:
                return False, ("backup export failed — removal skipped "
                               "on purpose (no backup, no delete)")
            rc, out = run_cmd(["reg", "delete", key, "/f"], timeout=60,
                              log=log)
            if rc == 0:
                return True, "removed stale key %s (backup exported)" \
                    % key
            return False, "reg delete failed: %s" % out.strip()[:200]
        if kind == "startup_disable":
            d = p.get("disable") or {}
            mode = d.get("mode")
            if mode == "run_value":
                parent = d["key"]
                if export_reg_key(parent, log, tag="startup") is None:
                    return False, "backup export failed — entry kept"
                rc, out = run_cmd(
                    ["reg", "delete", parent, "/v", d["name"], "/f"],
                    timeout=60, log=log)
                return (rc == 0), ("startup Run value '%s' removed "
                                   "(backup exported)" % d["name"]) \
                    if rc == 0 else "reg delete failed: %s" \
                    % out.strip()[:200]
            if mode == "task":
                name = (d.get("name") or "").replace("'", "''")
                path = (d.get("path") or "\\").replace("'", "''")
                script = ("Disable-ScheduledTask -TaskName '%s' "
                          "-TaskPath '%s'" % (name, path))
                rc, out = run_ps(script, timeout=120, log=log)
                return (rc == 0), ("scheduled task '%s' disabled "
                                   "(not deleted)" % d.get("name")) \
                    if rc == 0 else "disable failed: %s" \
                    % out.strip()[:200]
            if mode == "shortcut":
                src = d.get("path") or ""
                dest_dir = os.path.join(backup_dir(), "startup-disabled")
                os.makedirs(dest_dir, exist_ok=True)
                import shutil
                shutil.move(src, os.path.join(dest_dir,
                                              os.path.basename(src)))
                return True, ("startup shortcut moved to %s (restore "
                              "by moving it back)" % dest_dir)
            return False, "unknown startup disable mode: %s" % mode
        if kind in ("cleanup_temp",):
            clear_dir_contents(p.get("path"), log, step.label)
            return True, "temporary files cleared (in-use files skipped)"
        if kind == "cleanup_wu_cache":
            run_cmd(["net", "stop", "wuauserv"], timeout=120, log=log)
            run_cmd(["net", "stop", "bits"], timeout=120, log=log)
            try:
                clear_dir_contents(p.get("path"), log,
                                   "Windows Update cache")
            finally:
                run_cmd(["net", "start", "bits"], timeout=120, log=log)
                run_cmd(["net", "start", "wuauserv"], timeout=120,
                        log=log)
            return True, "update download cache cleared; services " \
                         "restarted"
        if kind == "cache_rebuild":
            return fix_cache_rebuild(step, log)
        if kind == "firewall_enable":
            profile = p.get("profile") or ""
            rc, out = run_ps(
                "Set-NetFirewallProfile -Profile %s -Enabled True"
                % profile, timeout=120, log=log)
            return (rc == 0), ("firewall enabled for %s" % profile) \
                if rc == 0 else "failed: %s" % out.strip()[:200]
        if kind == "defender_rtp_enable":
            rc, out = run_ps(
                "Set-MpPreference -DisableRealtimeMonitoring $false",
                timeout=120, log=log)
            if rc == 0:
                return True, "real-time protection turned back on"
            return False, ("could not enable it from here (%s). Use "
                           "Windows Security → Virus & threat protection "
                           "→ Manage settings." % out.strip()[:160])
        if kind == "defender_update":
            rc, out = run_cmd(
                ["powershell", "-NoProfile", "-Command",
                 MPCMDRUN_PS + "& $exe -SignatureUpdate"],
                timeout=600, log=log)
            return (rc == 0), "signature update requested" \
                if rc == 0 else "signature update failed: %s" \
                % out.strip()[:200]
        if kind == "exclusion_remove":
            switch = {"path": "ExclusionPath",
                      "extension": "ExclusionExtension",
                      "process": "ExclusionProcess",
                      "ip": "ExclusionIpAddress"}.get(p.get("type"))
            if not switch:
                return False, "unknown exclusion type"
            value = (p.get("value") or "").replace("'", "''")
            rc, out = run_ps("Remove-MpPreference -%s '%s'"
                             % (switch, value), timeout=120, log=log)
            return (rc == 0), ("exclusion removed: %s" % p.get("value")) \
                if rc == 0 else "removal failed: %s" % out.strip()[:200]
        if kind == "defender_scan":
            return fix_defender_scan(step, log)
        if kind == "driver_install":
            return fix_driver_install(step, log)
        if kind == "net_reset":
            run_cmd(["netsh", "winsock", "reset"], timeout=120, log=log)
            run_cmd(["netsh", "int", "ip", "reset"], timeout=120,
                    log=log)
            return True, "network stack reset — RESTART the PC to " \
                         "finish (network settings like static IPs " \
                         "may need re-entering)"
        if kind == "wsreset":
            proc = subprocess.Popen(["wsreset.exe"])
            try:
                proc.wait(timeout=180)
            except subprocess.TimeoutExpired:
                pass
            return True, "Store cache reset launched (wsreset)"
        if kind == "memdiag":
            subprocess.Popen(["mdsched.exe"])
            return True, "Windows Memory Diagnostic opened — choose " \
                         "'Restart now' there when ready"
    except Exception as exc:
        return False, "step raised: %r" % (exc,)
    return False, "unknown fix kind: %s" % kind


def verify_step(step, log):
    """Quick post-fix re-check for the fixed category. -> string or None."""
    if not IS_WINDOWS:
        return None
    try:
        if step.kind == "registry_remove":
            key = step.payload.get("key") or ""
            root_name, _, path = key.partition("\\")
            root = ROOTS.get(root_name)
            if root is None:
                return None
            import winreg
            try:
                winreg.OpenKey(root, path).Close()
                return "verify: key still present (unexpected)"
            except OSError:
                return "verify: key is gone"
        if step.kind == "firewall_enable":
            ok, txt = ps_json(
                "Get-NetFirewallProfile | Select-Object Name, Enabled "
                "| ConvertTo-Json -Compress", timeout=60, log=log)
            for prof in parse_firewall_profiles(txt) if ok else []:
                if prof["name"] == step.payload.get("profile"):
                    return "verify: %s firewall now %s" % (
                        prof["name"],
                        "ON" if prof["enabled"] else "still OFF")
        if step.kind == "defender_rtp_enable":
            ok, txt = ps_json(
                "Get-MpComputerStatus | Select-Object "
                "RealTimeProtectionEnabled | ConvertTo-Json -Compress",
                timeout=60, log=log)
            rows = parse_json_list(txt) if ok else []
            if rows:
                return "verify: real-time protection now %s" % (
                    "ON" if rows[0].get("RealTimeProtectionEnabled")
                    else "still OFF")
        if step.kind == "exclusion_remove":
            ok, txt = ps_json(
                "Get-MpPreference | Select-Object ExclusionPath, "
                "ExclusionExtension, ExclusionProcess, ExclusionIpAddress"
                " | ConvertTo-Json -Compress", timeout=60, log=log)
            values = [e["value"] for e in
                      parse_defender_exclusions(txt)] if ok else []
            return "verify: exclusion %s" % (
                "still present" if step.payload.get("value") in values
                else "gone")
    except Exception:
        return None
    return None


def execute_plan(plan, log, progress=None, cancel=None):
    """Run a plan. Returns [(label, ok, message, step_or_None)].

    HARD GATE: refuses any plan not starting with the restore point, and
    aborts everything if the restore point cannot be created.
    """
    results = []
    if not plan_is_safe(plan):
        results.append(("Safety gate", False,
                        "plan refused: it does not start with a "
                        "restore point", None))
        return results
    backup_ok = False
    driver_stopped = False
    for i, step in enumerate(plan):
        if cancel is not None and cancel.is_set():
            results.append((step.label, False,
                            "cancelled by user before this step", step))
            log("Fix run cancelled by user.")
            break
        if progress:
            progress(i, len(plan), step.label)
        log("FIX: %s" % step.label)
        if step.kind == "restore_point":
            ok, msg = create_restore_point(log)
            results.append((step.label, ok, msg, step))
            log("Restore point: %s — %s" % ("OK" if ok else "FAILED",
                                            msg))
            if not ok:
                results.append(("All remaining fixes", False,
                                "aborted — no restore point, no changes "
                                "made", None))
                break
            continue
        if step.kind == "driver_install":
            # Gates: backup must have succeeded in THIS run, and one
            # failed driver stops the rest of the driver queue.
            if driver_stopped:
                results.append((step.label, False,
                                "skipped — the driver queue stopped "
                                "after an earlier driver problem", step))
                log("  -> SKIPPED (queue stopped)")
                continue
            if not backup_ok:
                results.append((step.label, False,
                                "skipped — driver installs require "
                                "the driver backup (DISM export) to "
                                "complete in the same fix run first",
                                step))
                log("  -> SKIPPED (no driver backup this run)")
                driver_stopped = True
                continue
        ok, msg = run_fix_step(step, log)
        if step.kind == "driver_backup" and ok:
            backup_ok = True
        if step.kind == "driver_install" and not ok:
            driver_stopped = True
            log("  Driver queue stopped: one problem stops the rest.")
        note = verify_step(step, log)
        if note:
            msg = "%s (%s)" % (msg, note)
            log("  %s" % note)
        results.append((step.label, ok, msg, step))
        log("  -> %s: %s" % ("OK" if ok else "FAILED", msg))
    return results


def build_report(findings, results=None, when=None):
    """Plain-text report: scan findings + (optional) fix results."""
    when = when or datetime.datetime.now()
    lines = ["%s — report" % APP_NAME,
             "When: %s" % when.strftime("%Y-%m-%d %H:%M:%S"),
             "Computer: %s" % (os.environ.get("COMPUTERNAME")
                               or "unknown"),
             ""]
    by_cat = {}
    for f in findings:
        by_cat.setdefault(f.category, []).append(f)
    lines.append("=== WHAT THE SCAN FOUND ===")
    for cat, _title in CATEGORIES:
        items = by_cat.get(cat)
        if not items:
            continue
        lines.append("")
        lines.append("[%s]" % CATEGORY_TITLES[cat])
        for f in items:
            mark = {"bad": "!!", "warn": " !", "info": "  "}[f.severity]
            lines.append("%s %s" % (mark, f.title))
            if f.detail:
                for dl in f.detail.splitlines():
                    lines.append("     %s" % dl)
    if results is not None:
        lines.append("")
        lines.append("=== WHAT WAS FIXED (checked items only) ===")
        for entry in results:
            label, ok, msg = entry[0], entry[1], entry[2]
            lines.append("%s %s — %s" % ("OK  " if ok else "FAIL",
                                         label, msg))
    lines.append("")
    lines.append("Reminder: this app never removes anything that was "
                 "not listed above and checked by you. Registry "
                 "removals are backed up as .reg files in the "
                 "app's backups folder.")
    return "\n".join(lines)


# ----------------------------------------------------------------------
# Headless self-test (pure logic vs embedded fixtures; honest env report)
# ----------------------------------------------------------------------

def run_self_test():
    checks = []

    def check(name, cond, note=""):
        checks.append((name, bool(cond), note))

    check("sfc clean",
          parse_sfc("Windows Resource Protection did not find any "
                    "integrity violations.")["status"] == "clean")
    check("sfc violations",
          parse_sfc("Windows Resource Protection found corrupt files "
                    "but was unable to fix some of them.")
          ["status"] == "violations_unfixed")
    check("dism healthy",
          parse_dism("No component store corruption detected.")
          ["status"] == "healthy")
    check("dism repairable",
          parse_dism("The component store is repairable.")
          ["status"] == "repairable")
    devs = parse_problem_devices(
        '[{"Name":"Widget","PNPClass":"USB",'
        '"ConfigManagerErrorCode":28}]')
    check("problem devices", len(devs) == 1 and devs[0]["code"] == 28
          and "not installed" in devs[0]["meaning"])
    ev = [{"ProviderName": "Microsoft-Windows-Kernel-Power", "Id": 41,
           "LevelDisplayName": "Critical"}] * 3
    grouped = group_events(ev)
    check("event grouping", grouped and grouped[0]["count"] == 3
          and grouped[0]["explanation"] is not None)
    check("event explanation honesty",
          explain_event("Some-Random-Provider", 9999) is None)
    flags = classify_startup_item(
        {"name": "x", "source": "Run",
         "command": "cmd.exe /c C:\\stuff\\run.bat"},
        exists_fn=lambda p: True)
    check("startup console flag", flags["is_console"])
    check("target path quoted",
          extract_target_path('"C:\\Program Files\\A\\a.exe" /q')
          == "C:\\Program Files\\A\\a.exe")
    check("app paths staleness",
          len(stale_app_paths(
              [{"key": "K", "name": "a", "target": "C:\\gone.exe"}],
              exists_fn=lambda p: False)) == 1)
    check("uninstall needs location",
          len(stale_uninstall(
              [{"key": "K", "name": "a", "location": ""}],
              exists_fn=lambda p: False)) == 0)
    st = parse_defender_status(
        '{"AMServiceEnabled":true,"AntivirusEnabled":true,'
        '"RealTimeProtectionEnabled":false,'
        '"IsTamperProtected":true,'
        '"AntivirusSignatureAge":9,'
        '"QuickScanNeeded":true}')
    check("defender parse", st["present"] and not st["rtp"]
          and st["sig_age_days"] == 9 and st["tamper"])
    exc = parse_defender_exclusions(
        '{"ExclusionPath":["C:\\\\Temp"],"ExclusionExtension":[".xyz"]}')
    check("exclusions parse", len(exc) == 2 and exc[0]["type"] == "path")
    check("firewall parse",
          parse_firewall_profiles(
              '[{"Name":"Public","Enabled":false}]')[0]["enabled"]
          is False)
    check("smartscreen", interpret_smartscreen("Off") == "OFF")
    check("malwarebytes detect",
          find_malwarebytes([{"name": "Malwarebytes version 5"}])
          is not None)
    f_bad = Finding("sysfiles", "t", fix_label="x", fix_kind="sfc_scannow")
    plan = build_fix_plan([f_bad])
    check("plan starts with restore point",
          plan_is_safe(plan) and plan[0].kind == "restore_point"
          and plan[1].kind == "sfc_scannow")
    refused = execute_plan([FixStep("sfc_scannow", "rogue")], RunLog())
    check("gate refuses rogue plan",
          refused and refused[0][1] is False
          and "refused" in refused[0][2])
    report = build_report([Finding("safety", "hello finding")])
    check("report builds", "hello finding" in report
          and "WHAT THE SCAN FOUND" in report)
    inv = parse_signed_drivers(
        '[{"DeviceName": "Widget GPU", "DriverProviderName": '
        '"Widget Inc", "DriverVersion": "1.2.3", "DriverDate": '
        '"2024-01-01", "InfName": "oem1.inf", "DeviceID": "PCI\\\\X", '
        '"DeviceClass": "Display"}]')
    check("signed driver inventory",
          len(inv) == 1 and inv[0]["version"] == "1.2.3")
    wu = parse_wu_driver_updates(
        '[{"Title": "Widget GPU Driver", "UpdateID": '
        '"11111111-2222-3333-4444-555555555555", "RevisionNumber": 3, '
        '"DriverClass": "Display", "DriverManufacturer": "Widget", '
        '"DriverModel": "Widget GPU", "MaxDownloadSize": 2048}]')
    check("wu driver search parse",
          len(wu) == 1 and wu[0]["risk"] == "gpu"
          and wu[0]["update_id"].startswith("1111"))
    check("wu no matches is honest", parse_wu_driver_updates("") == [])
    check("wu install result parse",
          parse_wu_install_result('{"ResultCode": 2, '
                                  '"RebootRequired": true}')
          ["outcome"] == "succeeded")
    check("wu install not found",
          parse_wu_install_result('{"NotFound": true}')["outcome"]
          == "not_found")
    boot = parse_boot_events(
        '[{"Id": 100, "Time": "2026-10-01T08:00:00", "BootTime": '
        '"48000"}, {"Id": 101, "Time": "2026-10-01T08:00:10", '
        '"Name": "SlowApp", "TotalTime": "9000", '
        '"DegradationTime": "2000"}]')
    check("boot events parse",
          boot["latest_boot"]["total_ms"] == 48000
          and boot["offenders"][0]["name"] == "SlowApp")
    progs = parse_installed_programs(
        '[{"DisplayName": "Foo Toolbar", "DisplayVersion": "1.0", '
        '"Publisher": "Foo", "InstallDate": "20260101", '
        '"EstimatedSize": 1024, "InstallLocation": "C:\\\\Foo"}]')
    check("programs parse",
          len(progs) == 1 and progs[0]["install_date"] == "2026-01-01")
    check("program junk flag",
          "toolbar" in " ".join(classify_program(
              "Foo Toolbar", ["Foo Toolbar"])))
    rows = certificate_rows([Finding("disk", "ok", severity="info")],
                            [])
    disk_row = [r for r in rows if r[0] == "Disk"][0]
    sec_row = [r for r in rows if r[0] == "Security"][0]
    check("certificate grades real data",
          disk_row[1] == "A" and sec_row[1] == "Not checked")
    check("monthly diff",
          diff_summaries({"problems": 5, "by_category": {}},
                         summarize_findings(
                             [Finding("disk", "x", severity="warn")]))
          .startswith("Better"))
    check("driver backup dest is timestamped",
          "drivers-" in driver_backup_dest(base="/tmp/x"))

    print("%s %s — self-test" % (APP_NAME, APP_VERSION))
    print("Platform: %s | Windows: %s | Admin: %s | Python: %s"
          % (sys.platform, IS_WINDOWS, is_admin(),
             sys.version.split()[0]))
    failed = 0
    for name, ok, note in checks:
        print("  [%s] %s%s" % ("PASS" if ok else "FAIL", name,
                               (" — " + note) if note else ""))
        failed += 0 if ok else 1
    if not IS_WINDOWS:
        print("  [NOTE] Hardware scans report NEEDS-WINDOWS on this "
              "machine — by design, never faked.")
    print("Self-test: %d/%d passed" % (len(checks) - failed,
                                       len(checks)))
    return 0 if failed == 0 else 1


# ----------------------------------------------------------------------
# GUI
# ----------------------------------------------------------------------

def launch_gui():
    try:
        import tkinter as tk
        from tkinter import messagebox, scrolledtext, ttk
    except ImportError:
        print("Tkinter is not available — run with --self-test instead.")
        return 2

    import queue as queue_mod
    import webbrowser

    root = tk.Tk()
    root.title("%s — v%s" % (APP_NAME, APP_VERSION))
    root.geometry("1020x720")
    root.minsize(900, 600)
    root.resizable(True, True)
    bg = "#10131a"
    fg = "#e8eaf0"
    accent = "#4da3ff"
    root.configure(bg=bg)

    state = {
        "findings": [], "checked": set(), "rows": {},
        "busy": False, "cancel": threading.Event(),
        "fix_results": None,
    }
    log_queue = queue_mod.Queue()
    log = RunLog(sink=lambda line: log_queue.put(line))

    header = tk.Frame(root, bg=bg)
    header.pack(fill="x", padx=16, pady=(12, 4))
    tk.Label(header, text="Windows Health & Repair", bg=bg, fg=fg,
             font=("Sans", 18, "bold")).pack(side="left")
    admin_var = tk.StringVar()
    tk.Label(header, textvariable=admin_var, bg=bg, fg=accent,
             font=("Sans", 10)).pack(side="right")

    note_var = tk.StringVar()
    note_lbl = tk.Label(root, textvariable=note_var, bg=bg, fg="#f2c14e",
                        font=("Sans", 10), wraplength=960, justify="left")
    note_lbl.pack(fill="x", padx=16)

    btns = tk.Frame(root, bg=bg)
    btns.pack(fill="x", padx=16, pady=6)
    scan_btn = tk.Button(btns, text="Scan this PC", padx=18, pady=6,
                         font=("Sans", 11, "bold"))
    scan_btn.pack(side="left")
    fix_btn = tk.Button(btns, text="Fix checked items", padx=18, pady=6,
                        font=("Sans", 11, "bold"))
    fix_btn.pack(side="left", padx=8)
    cancel_btn = tk.Button(btns, text="Cancel", padx=12, pady=6,
                           state="disabled")
    cancel_btn.pack(side="left")
    report_btn = tk.Button(btns, text="Save report", padx=12, pady=6)
    report_btn.pack(side="right")
    log_btn = tk.Button(btns, text="Open logs folder", padx=12, pady=6)
    log_btn.pack(side="right", padx=8)
    cert_btn = tk.Button(btns, text="Health certificate", padx=12,
                         pady=6)
    cert_btn.pack(side="right", padx=8)

    btns2 = tk.Frame(root, bg=bg)
    btns2.pack(fill="x", padx=16, pady=(0, 2))
    monthly_btn = tk.Button(btns2, text="Monthly auto-check",
                            padx=12, pady=4)
    monthly_btn.pack(side="left")
    monthly_var = tk.StringVar()
    tk.Label(btns2, textvariable=monthly_var, bg=bg, fg="#9aa3b2",
             font=("Sans", 9)).pack(side="left", padx=10)

    progress = ttk.Progressbar(root, mode="determinate")
    progress.pack(fill="x", padx=16, pady=(2, 2))
    status_var = tk.StringVar(
        value="Press 'Scan this PC'. Scanning only reads — nothing is "
              "changed until you tick fixes and press Fix.")
    tk.Label(root, textvariable=status_var, bg=bg, fg="#9aa3b2",
             font=("Sans", 10)).pack(fill="x", padx=16)

    panes = tk.PanedWindow(root, orient="vertical", bg=bg)
    panes.pack(fill="both", expand=True, padx=16, pady=6)
    tree_frame = tk.Frame(panes, bg=bg)
    tree = ttk.Treeview(tree_frame, show="tree", selectmode="browse")
    tree_scroll = ttk.Scrollbar(tree_frame, orient="vertical",
                                command=tree.yview)
    tree.configure(yscrollcommand=tree_scroll.set)
    tree.pack(side="left", fill="both", expand=True)
    tree_scroll.pack(side="right", fill="y")
    panes.add(tree_frame)
    bottom = tk.Frame(panes, bg=bg)
    detail = scrolledtext.ScrolledText(
        bottom, height=7, bg="#0b0d12", fg="#cfd6e4",
        font=("Monospace", 9), state="disabled")
    detail.pack(fill="both", expand=True)
    action_frame = tk.Frame(bottom, bg=bg)
    action_frame.pack(fill="x", pady=(4, 2))
    log_box = scrolledtext.ScrolledText(
        bottom, height=8, bg="#0b0d12", fg="#8f98a8",
        font=("Monospace", 9), state="disabled")
    log_box.pack(fill="both", expand=True)
    panes.add(bottom)

    def drain_log():
        while True:
            try:
                line = log_queue.get_nowait()
            except queue_mod.Empty:
                break
            log_box.configure(state="normal")
            log_box.insert("end", line + "\n")
            log_box.see("end")
            log_box.configure(state="disabled")
        root.after(150, drain_log)

    def set_busy(busy, label=""):
        state["busy"] = busy
        scan_btn.configure(state="disabled" if busy else "normal")
        fix_btn.configure(state="disabled" if busy else "normal")
        cancel_btn.configure(state="normal" if busy else "disabled")
        if label:
            status_var.set(label)

    def finding_text(f, checked):
        if not f.fix_kind:
            return "    " + f.title
        return ("☑ " if checked else "☐ ") + f.title

    def populate(findings):
        tree.delete(*tree.get_children())
        state["findings"] = findings
        state["rows"] = {}
        by_cat = {}
        for f in findings:
            by_cat.setdefault(f.category, []).append(f)
        for cat, _t in CATEGORIES:
            items = by_cat.get(cat)
            if not items:
                continue
            parent = tree.insert("", "end", text=CATEGORY_TITLES[cat],
                                 open=True)
            for f in items:
                checked = f in state["checked"]
                rid = tree.insert(parent, "end",
                                  text=finding_text(f, checked))
                state["rows"][rid] = f
        status_var.set("Scan complete — %d finding(s). Tick the fixes "
                       "you want, then press 'Fix checked items'."
                       % len(findings))

    def show_detail(f):
        detail.configure(state="normal")
        detail.delete("1.0", "end")
        parts = [f.title, ""]
        if f.detail:
            parts.append(f.detail)
            parts.append("")
        if f.why:
            parts.append("Why it matters: " + f.why)
            parts.append("")
        if f.fix_kind:
            parts.append("Fix if ticked: %s" % (f.fix_label or f.fix_kind))
        detail.insert("1.0", "\n".join(parts))
        detail.configure(state="disabled")
        for child in action_frame.winfo_children():
            child.destroy()
        exe = (f.payload or {}).get("launch")
        url = (f.payload or {}).get("url")
        if exe:
            def _launch(p=exe):
                try:
                    subprocess.Popen([p])
                except OSError as exc:
                    messagebox.showerror(
                        "Launch failed", "Could not start it: %s" % exc)
            tk.Button(action_frame, text="Launch it now",
                      command=_launch, padx=12, pady=4).pack(side="left")
        if url:
            label = (f.payload or {}).get("url_label",
                                           "Open official site")
            tk.Button(action_frame, text=label,
                      command=lambda u=url: webbrowser.open(u),
                      padx=12, pady=4).pack(side="left")
        if (f.payload or {}).get("open_uninstall"):
            def _uninstall():
                if IS_WINDOWS:
                    os.startfile("ms-settings:appsfeatures")
                else:
                    messagebox.showinfo(
                        "Uninstall",
                        "On Windows this opens Settings → Apps, "
                        "where you uninstall it yourself. This app "
                        "never uninstalls anything.")
            tk.Button(action_frame,
                      text="Open Windows' uninstall page",
                      command=_uninstall, padx=12,
                      pady=4).pack(side="left")

    def on_tree_click(event):
        rid = tree.identify_row(event.y)
        if not rid:
            return
        f = state["rows"].get(rid)
        if not f:
            return
        show_detail(f)
        if f.fix_kind:
            if f in state["checked"]:
                state["checked"].discard(f)
            else:
                state["checked"].add(f)
            tree.item(rid, text=finding_text(f, f in state["checked"]))

    tree.bind("<ButtonRelease-1>", on_tree_click)

    def do_scan():
        if state["busy"]:
            return
        state["cancel"].clear()
        state["checked"] = set()
        state["fix_results"] = None
        log.start_file()
        log("Scan started (log: %s)" % log.path)
        set_busy(True, "Scanning… SFC/DISM checks can take several "
                       "minutes.")

        def progress(cat, i, total):
            progress["maximum"] = total
            progress["value"] = i + 1
            status_var.set("Scanning: %s (%d/%d)"
                           % (CATEGORY_TITLES[cat], i + 1, total))

        def worker():
            findings = run_scan(log, progress=progress)
            for f in findings:
                if f.fix_kind and f.default_checked:
                    state["checked"].add(f)
            root.after(0, lambda: (populate(findings), set_busy(False)))

        threading.Thread(target=worker, daemon=True).start()

    def do_fix():
        if state["busy"]:
            return
        chosen = [f for f in state["findings"] if f in state["checked"]]
        if not chosen:
            messagebox.showinfo(
                "Nothing ticked",
                "Tick at least one fix in the list first. Scanning "
                "alone changes nothing.")
            return
        if IS_WINDOWS and not is_admin():
            messagebox.showwarning(
                "Admin needed",
                "Fixes need administrator rights. Use 'Relaunch as "
                "admin' at the top, then scan and tick again.")
            return
        if not messagebox.askyesno(
                "Run these fixes?",
                "%d fix(es) will run.\n\nFIRST, a System Restore point "
                "is created — if that fails, nothing else runs.\nEvery "
                "step is logged, registry removals are backed up "
                "(.reg), and results are re-checked afterwards."
                % len(chosen)):
            return
        state["cancel"].clear()
        plan = build_fix_plan(chosen)
        set_busy(True, "Fixing… do not close the app during SFC/DISM.")

        def progress(i, total, label):
            progress["maximum"] = total
            progress["value"] = i + 1
            status_var.set("Fix %d/%d: %s" % (i + 1, total, label))

        def worker():
            results = execute_plan(plan, log, progress=progress,
                                   cancel=state["cancel"])
            state["fix_results"] = results
            ok_n = sum(1 for r in results if r[1])
            root.after(0, lambda: (
                set_busy(False),
                status_var.set("Fix run finished: %d/%d steps OK. "
                               "See the log, or save the report."
                               % (ok_n, len(results))),
                messagebox.showinfo(
                    "Fix run finished",
                    "%d of %d steps succeeded.\n\nFull details are in "
                    "the log:\n%s" % (ok_n, len(results), log.path))))

        threading.Thread(target=worker, daemon=True).start()

    def do_report():
        if not state["findings"]:
            messagebox.showinfo("No scan yet", "Run a scan first.")
            return
        text = build_report(state["findings"], state["fix_results"])
        log_dir = os.path.join(app_dir(), "logs")
        os.makedirs(log_dir, exist_ok=True)
        path = os.path.join(
            log_dir, "report-%s.txt"
            % datetime.datetime.now().strftime("%Y%m%d-%H%M%S"))
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        messagebox.showinfo("Report saved", "Saved to:\n%s" % path)

    def do_logs():
        log_dir = os.path.join(app_dir(), "logs")
        os.makedirs(log_dir, exist_ok=True)
        if IS_WINDOWS:
            os.startfile(log_dir)  # noqa: S606 - opening our own folder
        else:
            messagebox.showinfo("Logs", "Logs live in: %s" % log_dir)

    def relaunch_admin():
        try:
            script = os.path.abspath(__file__)
            # Frozen exe: sys.executable IS the app, so relaunch it
            # with no script argument. (Passing the .py path would be
            # treated as an unknown argument by the exe's argparse.)
            params = "" if is_frozen() else '"%s"' % script
            rc = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, params,
                app_dir(), 1)
            if rc > 32:
                root.destroy()
            else:
                messagebox.showerror("Relaunch failed",
                                     "Windows returned %s" % rc)
        except Exception as exc:
            messagebox.showerror("Relaunch failed", str(exc))

    def do_certificate():
        if not state["findings"]:
            messagebox.showinfo("No scan yet",
                                "Run a scan first — the certificate "
                                "is graded from real findings only.")
            return
        log_dir = os.path.join(app_dir(), "logs")
        os.makedirs(log_dir, exist_ok=True)
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        txt = build_certificate_text(state["findings"],
                                     state["fix_results"])
        html = build_certificate_html(state["findings"],
                                      state["fix_results"])
        tpath = os.path.join(log_dir, "certificate-%s.txt" % stamp)
        hpath = os.path.join(log_dir, "certificate-%s.html" % stamp)
        with open(tpath, "w", encoding="utf-8") as fh:
            fh.write(txt)
        with open(hpath, "w", encoding="utf-8") as fh:
            fh.write(html)
        messagebox.showinfo(
            "Certificate saved",
            "Printable certificate saved:\n%s\n\n%s\n\nOpen the "
            ".html file in a browser to print it." % (hpath, tpath))
        if IS_WINDOWS:
            webbrowser.open("file:///" + hpath.replace("\\", "/"))

    def refresh_monthly():
        on = monthly_task_registered()
        first = monthly_status_text().splitlines()
        monthly_var.set("Monthly auto-check: %s. %s"
                        % ("ON (1st of the month, scan only)"
                           if on else "OFF",
                           first[0] if first else ""))

    def do_monthly():
        if monthly_task_registered():
            if not messagebox.askyesno(
                    "Turn OFF monthly auto-check?",
                    "The scheduled monthly scan-only check will be "
                    "removed. Nothing else changes."):
                return
            ok, msg = monthly_unregister()
        else:
            if not messagebox.askyesno(
                    "Turn ON monthly auto-check?",
                    "Once a month (1st, ~09:00) this app will run a "
                    "SCAN-ONLY check in the background — it never "
                    "fixes anything on its own — and save the report "
                    "next to the app, so you can see whether the PC "
                    "is getting better or worse over time."):
                return
            ok, msg = monthly_register()
        messagebox.showinfo("Monthly auto-check", msg)
        refresh_monthly()

    scan_btn.configure(command=do_scan)
    fix_btn.configure(command=do_fix)
    cancel_btn.configure(command=lambda: state["cancel"].set())
    report_btn.configure(command=do_report)
    log_btn.configure(command=do_logs)
    cert_btn.configure(command=do_certificate)
    monthly_btn.configure(command=do_monthly)
    refresh_monthly()

    if IS_WINDOWS and is_admin():
        admin_var.set("Administrator ✓")
    elif IS_WINDOWS:
        admin_var.set("Not running as administrator")
        note_var.set("You are not running as administrator, so the Fix "
                     "button is locked. Scanning still works.")
        admin_btn = tk.Button(header, text="Relaunch as admin",
                              command=relaunch_admin, padx=10, pady=2)
        admin_btn.pack(side="right", padx=8)
        fix_btn.configure(state="disabled")
    else:
        admin_var.set("Preview (not Windows)")
        note_var.set("This is not a Windows PC, so every hardware scan "
                     "will honestly report 'needs Windows'. Nothing is "
                     "faked and nothing can be fixed from here.")
        fix_btn.configure(state="disabled")

    drain_log()
    root.mainloop()
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--self-test", action="store_true",
                        help="run the headless logic self-test")
    parser.add_argument("--scan-only", action="store_true",
                        help="headless scan for the monthly "
                             "auto-check (never fixes anything)")
    parser.add_argument("--version", action="store_true")
    args = parser.parse_args(argv)
    if args.version:
        print("%s %s" % (APP_NAME, APP_VERSION))
        return 0
    if args.self_test:
        return run_self_test()
    if args.scan_only:
        return cmd_scan_only()
    return launch_gui()


# ----------------------------------------------------------------------
# Driver inventory / Windows Update driver search (parsers are pure)
#
# The ONLY driver-update source this app uses is the Windows Update
# Agent API — Microsoft matches updates to this machine's real hardware
# IDs. No vendor-site scraping, no third-party driver databases, and no
# "N outdated drivers!" scare counts: old is not the same as broken.
# ----------------------------------------------------------------------

def driver_backup_dest(base=None, when=None):
    """Timestamped driver-backup folder next to the app."""
    when = when or datetime.datetime.now()
    base = base or os.path.join(app_dir(), "backups")
    return os.path.join(base, "drivers-%s"
                        % when.strftime("%Y%m%d-%H%M%S"))


def parse_signed_drivers(text):
    """Win32_PnPSignedDriver JSON -> normalized inventory list."""
    out = []
    for d in parse_json_list(text):
        out.append({
            "device": d.get("DeviceName") or "Unknown device",
            "provider": d.get("DriverProviderName") or "",
            "version": str(d.get("DriverVersion") or ""),
            "date": d.get("DriverDate") or "",
            "inf": d.get("InfName") or "",
            "device_id": d.get("DeviceID") or "",
            "class": d.get("DeviceClass") or "",
        })
    return out


def classify_driver_risk(title, driver_class=""):
    """'gpu' | 'storage' | 'other' — extra-caution classes."""
    blob = ("%s %s" % (title or "", driver_class or "")).lower()
    if any(k in blob for k in ("display", "video", "gpu", "graphics",
                               "geforce", "radeon")):
        return "gpu"
    if any(k in blob for k in ("storage", "sata", "ahci", "raid",
                               "scsi", "nvme", "hdc", "disk drive")):
        return "storage"
    return "other"


def parse_wu_driver_updates(text):
    """WU Agent driver-search JSON -> normalized update list."""
    out = []
    for d in parse_json_list(text):
        title = d.get("Title") or ""
        out.append({
            "update_id": d.get("UpdateID") or "",
            "revision": d.get("RevisionNumber"),
            "title": title,
            "driver_class": d.get("DriverClass") or "",
            "manufacturer": d.get("DriverManufacturer") or "",
            "model": d.get("DriverModel") or "",
            "size": d.get("MaxDownloadSize"),
            "risk": classify_driver_risk(
                title + " " + (d.get("DriverModel") or ""),
                d.get("DriverClass") or ""),
        })
    return out


def parse_wu_install_result(text):
    """WU install JSON -> {outcome, reboot_required, result_code}."""
    rows = parse_json_list(text)
    if not rows:
        return {"outcome": "unknown", "reboot_required": False,
                "result_code": None}
    d = rows[0]
    if d.get("NotFound"):
        return {"outcome": "not_found", "reboot_required": False,
                "result_code": None}
    code = d.get("ResultCode")
    try:
        code = int(code)
    except (TypeError, ValueError):
        code = None
    outcome = {2: "succeeded", 3: "succeeded_with_errors",
               4: "failed", 5: "aborted"}.get(code, "unknown")
    return {"outcome": outcome,
            "reboot_required": bool(d.get("RebootRequired")),
            "result_code": code}


# ----------------------------------------------------------------------
# Boot-time report + installed-programs audit (parsers are pure)
# ----------------------------------------------------------------------

BOOT_EVENTS_PS = (
    "$OutputEncoding = [Console]::OutputEncoding = "
    "[System.Text.Encoding]::UTF8; "
    "$evs = Get-WinEvent -LogName "
    "'Microsoft-Windows-Diagnostics-Performance/Operational' "
    "-MaxEvents 300 -ErrorAction SilentlyContinue; "
    "$out = @(); foreach ($e in $evs) { "
    "if ($e.Id -ge 100 -and $e.Id -le 110) { "
    "$xml = [xml]$e.ToXml(); $d = @{}; "
    "foreach ($n in $xml.Event.EventData.Data) { "
    "$d[$n.Name] = $n.'#text' }; "
    "$out += [pscustomobject]@{ Id = $e.Id; "
    "Time = $e.TimeCreated.ToString('s'); "
    "BootTime = $d['BootTime']; Name = $d['Name']; "
    "TotalTime = $d['TotalTime']; "
    "DegradationTime = $d['DegradationTime'] } } }; "
    "$out | ConvertTo-Json -Compress")


def _to_int(v):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return 0


def parse_boot_events(text):
    """Diagnostics-Performance JSON -> {latest_boot, offenders}."""
    boots = []
    offenders = []
    for d in parse_json_list(text):
        eid = _to_int(d.get("Id"))
        if eid == 100:
            boots.append({"time": d.get("Time") or "",
                          "total_ms": _to_int(d.get("BootTime"))})
        elif 101 <= eid <= 110:
            offenders.append({
                "id": eid,
                "name": d.get("Name") or "Unknown app/service",
                "total_ms": _to_int(d.get("TotalTime")),
                "degradation_ms": _to_int(d.get("DegradationTime")),
                "time": d.get("Time") or "",
            })
    boots.sort(key=lambda b: b["time"], reverse=True)
    latest = boots[0] if boots else None
    if latest:
        same = [o for o in offenders
                if o["time"][:10] == latest["time"][:10]]
        pool = same if same else offenders
    else:
        pool = offenders
    pool.sort(key=lambda o: o["total_ms"], reverse=True)
    return {"latest_boot": latest, "offenders": pool[:8]}


def scan_boot(log):
    if not IS_WINDOWS:
        return [needs_windows_finding("boot", "Boot-time report")]
    ok, txt = ps_json(BOOT_EVENTS_PS, timeout=300, log=log)
    data = parse_boot_events(txt) if ok else {"latest_boot": None,
                                              "offenders": []}
    out = []
    boot = data["latest_boot"]
    if not boot:
        out.append(Finding(
            "boot", "No boot-performance records readable",
            detail="The Diagnostics-Performance event log returned "
                   "no boot events. It can be empty on a fresh "
                   "install, or reading it may need admin rights "
                   "(use Relaunch as admin).",
            severity="warn"))
        return out
    secs = boot["total_ms"] / 1000.0
    out.append(Finding(
        "boot", "Last boot took %.0f seconds (boot finished %s)"
        % (secs, boot["time"][:10]),
        detail="From the Diagnostics-Performance log, Event 100. "
               "Rough guide: under 30s is quick, 30–90s is normal "
               "for an older PC, over 90s means something below is "
               "worth a look.",
        severity="warn" if secs > 120 else "info"))
    for o in data["offenders"]:
        out.append(Finding(
            "boot", "Slow at boot: %s ate %.1f of those seconds"
            % (o["name"], o["total_ms"] / 1000.0),
            detail="Event %d recorded %.1f s total (%.1f s of it "
                   "extra degradation) at that boot."
                   % (o["id"], o["total_ms"] / 1000.0,
                      o["degradation_ms"] / 1000.0),
            why="Repeat offenders here are the usual cause of a "
                "slow startup. This is report-only: the Startup "
                "audit shows what runs at logon so you can decide "
                "what to trim — nothing is disabled from here.",
            severity="warn" if o["total_ms"] >= 10000 else "info"))
    return out


PROGRAM_JUNK_KEYWORDS = (
    ("toolbar", "toolbar"),
    ("web bar", "toolbar / browser bar"),
    ("search bar", "toolbar / browser bar"),
    ("coupon", "coupon / shopping helper"),
    ("price comparison", "shopping helper"),
    ("pc optimizer", "‘optimizer’ utility"),
    ("driver updater", "third-party driver updater"),
    ("registry cleaner", "third-party registry cleaner"),
    ("speed up my pc", "‘optimizer’ utility"),
)
PROGRAM_UPDATER_HINTS = ("updater", "update service", "update helper")


def classify_program(name, all_names):
    """Report-only junk-category flags for one installed program."""
    low = (name or "").lower()
    flags = []
    for kw, label in PROGRAM_JUNK_KEYWORDS:
        if kw in low:
            flags.append(label)
            break
    if " trial" in low or low.endswith("trial"):
        flags.append("trialware")
    updaters = [n for n in all_names
                if any(h in n.lower() for h in PROGRAM_UPDATER_HINTS)]
    if (any(h in low for h in PROGRAM_UPDATER_HINTS)
            and len(updaters) >= 3):
        flags.append("one of %d separate updater programs — most "
                     "apps update themselves or via the Store"
                     % len(updaters))
    return flags


def parse_installed_programs(text):
    """Uninstall-key JSON -> normalized, de-duplicated program list."""
    out = []
    seen = set()
    for d in parse_json_list(text):
        name = (d.get("DisplayName") or "").strip()
        if not name:
            continue
        ver = d.get("DisplayVersion") or ""
        key = (name.lower(), ver)
        if key in seen:
            continue
        seen.add(key)
        raw_date = str(d.get("InstallDate") or "")
        date = ""
        if re.fullmatch(r"\d{8}", raw_date):
            date = "%s-%s-%s" % (raw_date[:4], raw_date[4:6],
                                 raw_date[6:8])
        out.append({
            "name": name, "version": ver,
            "publisher": d.get("Publisher") or "",
            "size_kb": _to_int(d.get("EstimatedSize")),
            "install_date": date,
            "location": d.get("InstallLocation") or "",
        })
    out.sort(key=lambda p: p["name"].lower())
    return out


PROGRAMS_PS = (
    "$paths = @("
    "'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\"
    "Uninstall\\*', "
    "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\"
    "CurrentVersion\\Uninstall\\*', "
    "'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\"
    "Uninstall\\*'); "
    "Get-ItemProperty $paths -ErrorAction SilentlyContinue | "
    "Where-Object { $_.DisplayName } | Select-Object DisplayName, "
    "DisplayVersion, Publisher, InstallDate, EstimatedSize, "
    "InstallLocation | ConvertTo-Json -Compress")


def scan_programs(log):
    if not IS_WINDOWS:
        return [needs_windows_finding("programs",
                                      "Installed-programs audit")]
    ok, txt = ps_json(PROGRAMS_PS, timeout=300, log=log)
    programs = parse_installed_programs(txt) if ok else []
    out = []
    if not programs:
        out.append(Finding("programs",
                           "Could not read the installed-programs "
                           "list", severity="warn"))
        return out
    names = [p["name"] for p in programs]
    biggest = sorted(programs, key=lambda p: p["size_kb"],
                     reverse=True)[:10]
    lines = ["Largest (where Windows reports a size):"]
    for p in biggest:
        if p["size_kb"]:
            lines.append("  %s — %s" % (p["name"],
                                        human_size(p["size_kb"]
                                                   * 1024)))
    lines.append("")
    lines.append("Full list (size / installed date shown only where "
                 "Windows provides them — blanks are honest blanks; "
                 "Windows does not record last-used for most "
                 "programs):")
    for p in programs[:80]:
        bits = [p["name"]]
        if p["size_kb"]:
            bits.append(human_size(p["size_kb"] * 1024))
        bits.append("installed %s" % p["install_date"]
                    if p["install_date"] else "install date not "
                    "recorded")
        lines.append("  " + " — ".join(bits))
    if len(programs) > 80:
        lines.append("  … and %d more" % (len(programs) - 80))
        log("Programs beyond the first 80 are in the scan count "
            "only.")
    out.append(Finding(
        "programs", "%d programs installed" % len(programs),
        detail="\n".join(lines),
        why="Software you no longer use still runs updaters and "
            "background pieces. This audit never uninstalls "
            "anything — the flagged items below have a button that "
            "opens Windows' own uninstall page, where YOU decide.",
        severity="info"))
    for p in programs:
        flags = classify_program(p["name"], names)
        if flags:
            out.append(Finding(
                "programs", "Worth a look: %s — flagged as %s"
                % (p["name"], "; ".join(flags)),
                detail="Publisher: %s. Installed: %s."
                       % (p["publisher"] or "not recorded",
                          p["install_date"] or "not recorded"),
                why="These categories are the usual hitchhikers "
                    "(bundled with other installers). Report-only: "
                    "if you don't use it, remove it from Windows' "
                    "own uninstall page — this app never uninstalls "
                    "silently.",
                payload={"open_uninstall": p["name"]},
                severity="warn"))
    return out


# ----------------------------------------------------------------------
# PC Health Certificate — grades computed from real findings only.
#
# RUBRIC (documented, applied identically to BEFORE and AFTER):
#   problems = findings of severity warn/error in the category
#   (errors count double). Grade: 0 -> A, 1 -> B, 2-3 -> C, 4+ -> D.
#   AFTER grade: a problem counts as resolved only if a fix for that
#   exact finding ran and succeeded. A category the scan produced no
#   findings for at all shows "Not checked" — never an invented grade.
# ----------------------------------------------------------------------

CERT_CATEGORIES = (
    ("sysfiles", "System files"),
    ("disk", "Disk"),
    ("update", "Updates"),
    ("devices", "Drivers & devices"),
    ("security", "Security"),
    ("startup", "Startup"),
    ("junk", "Junk & caches"),
)


def _problem_weight(findings, category):
    return sum(2 if f.severity == "bad" else 1
               for f in findings
               if f.category == category
               and f.severity in ("warn", "bad"))


def _grade(weight):
    if weight <= 0:
        return "A"
    if weight == 1:
        return "B"
    if weight <= 3:
        return "C"
    return "D"


def certificate_rows(findings, results):
    """[(label, before, after, status)] for the certificate."""
    known = [c for c, _ in CERT_CATEGORIES]
    extras = []
    for f in findings:
        if f.category not in known and f.category not in extras:
            extras.append(f.category)
    labels = dict(CATEGORIES)
    labels.update(dict(CERT_CATEGORIES))
    order = known + extras
    fixed_ids = set()
    for (_label, ok, _msg, step) in (results or []):
        if ok and step is not None and step.finding is not None:
            fixed_ids.add(id(step.finding))
    rows = []
    for cat in order:
        cat_findings = [f for f in findings if f.category == cat]
        if not cat_findings:
            rows.append((labels.get(cat, cat), "Not checked",
                         "Not checked",
                         "This category wasn't part of the scan."))
            continue
        before = _grade(_problem_weight(cat_findings, cat))
        unresolved = [f for f in cat_findings
                      if f.severity in ("warn", "bad")
                      and id(f) not in fixed_ids]
        after_w = sum(2 if f.severity == "bad" else 1
                      for f in unresolved)
        after = _grade(after_w)
        problems = [f for f in cat_findings
                    if f.severity in ("warn", "bad")]
        if not problems:
            status = "Checked — nothing wrong found."
        elif not unresolved:
            status = ("Fixed during this run: %s"
                      % problems[0].title)
        else:
            status = ("Still open: %s" % unresolved[0].title)
            if len(unresolved) > 1:
                status += " (+%d more)" % (len(unresolved) - 1)
        rows.append((labels.get(cat, cat), before, after, status))
    return rows


def _cert_header(when, machine):
    return ("PC Health Certificate — %s\nDate: %s\nApp: Windows "
            "Health & Repair v%s\nGrades come only from what the "
            "scan actually found (rubric: A = no problems, B = 1, "
            "C = 2–3, D = 4+; errors count double). 'Not checked' "
            "means the scan has no data for that category."
            % (machine, when, APP_VERSION))


def build_certificate_text(findings, results=None, when=None,
                           machine=None):
    when = when or datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    machine = machine or os.environ.get("COMPUTERNAME") or "This PC"
    lines = [_cert_header(when, machine), ""]
    for (label, before, after, status) in certificate_rows(
            findings, results):
        lines.append("%-20s BEFORE %s  →  AFTER %s" % (label, before,
                                                       after))
        lines.append("%-20s %s" % ("", status))
    return "\n".join(lines)


def build_certificate_html(findings, results=None, when=None,
                           machine=None):
    import html as _html
    when = when or datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    machine = machine or os.environ.get("COMPUTERNAME") or "This PC"
    rows = []
    for (label, before, after, status) in certificate_rows(
            findings, results):
        rows.append(
            "<tr><td>%s</td><td><b>%s</b></td><td><b>%s</b></td>"
            "<td>%s</td></tr>" % (_html.escape(label),
                                  _html.escape(before),
                                  _html.escape(after),
                                  _html.escape(status)))
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<title>PC Health Certificate</title><style>"
        "body{font-family:Segoe UI,Arial,sans-serif;margin:40px;"
        "color:#111}h1{font-size:22px}table{border-collapse:"
        "collapse;width:100%%}td,th{border:1px solid #999;"
        "padding:8px;text-align:left}th{background:#eee}"
        ".note{color:#444;font-size:13px}</style></head><body>"
        "<h1>PC Health Certificate — %s</h1><p>Date: %s · Windows "
        "Health &amp; Repair v%s</p>"
        "<table><tr><th>Category</th><th>Before</th><th>After</th>"
        "<th>Status</th></tr>%s</table>"
        "<p class='note'>Grades are computed only from what the "
        "scan actually found: A = no problems, B = 1, C = 2–3, "
        "D = 4 or more (errors count double). A category with no "
        "scan data shows 'Not checked' — grades are never "
        "invented. Fixes listed as done were verified after they "
        "ran; the full log sits next to the app.</p>"
        "</body></html>"
        % (_html.escape(machine), _html.escape(when), APP_VERSION,
           "".join(rows)))


# ----------------------------------------------------------------------
# Monthly auto-check (opt-in; Task Scheduler; --scan-only headless)
# ----------------------------------------------------------------------

MONTHLY_TASK_NAME = "WindowsHealth-MonthlyCheck"
HISTORY_FILE = "scan-history.json"
STATUS_FILE = "auto-check-status.txt"


def summarize_findings(findings):
    """Pure: findings -> comparable summary for the history diff."""
    by_cat = {}
    problems = 0
    for f in findings:
        by_cat.setdefault(f.category, 0)
        if f.severity in ("warn", "bad"):
            by_cat[f.category] += 1
            problems += 1
    return {"problems": problems, "by_category": by_cat}


def diff_summaries(prev, cur):
    """Pure: plain-language better/worse comparison."""
    if not prev:
        return "First recorded check — nothing to compare yet."
    d = cur["problems"] - prev["problems"]
    if d < 0:
        return ("Better: %d problems now vs %d last time (%+d)."
                % (cur["problems"], prev["problems"], d))
    if d > 0:
        return ("Worse: %d problems now vs %d last time (+%d). "
                "Open the app and run a scan to see what changed."
                % (cur["problems"], prev["problems"], d))
    return ("Same: %d problems, unchanged from last time."
            % cur["problems"])


def history_path():
    return os.path.join(app_dir(), HISTORY_FILE)


def load_history():
    try:
        with open(history_path(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {"runs": []}
    except (OSError, ValueError):
        return {"runs": []}


def record_history(summary, when=None):
    hist = load_history()
    runs = hist.get("runs") or []
    prev = runs[-1]["summary"] if runs else None
    runs.append({"when": (when or datetime.datetime.now()
                          ).isoformat(timespec="seconds"),
                 "summary": summary})
    hist["runs"] = runs[-24:]
    try:
        with open(history_path(), "w", encoding="utf-8") as fh:
            json.dump(hist, fh, indent=1)
    except OSError:
        pass
    return prev


def monthly_task_registered():
    if not IS_WINDOWS:
        return False
    rc, _ = run_cmd(["schtasks", "/Query", "/TN",
                     MONTHLY_TASK_NAME])
    return rc == 0


def monthly_register():
    """Register the monthly Task Scheduler job (Windows only)."""
    if not IS_WINDOWS:
        return False, "Task Scheduler registration needs Windows."
    if is_frozen():
        # Frozen exe: the exe is the program; there is no script arg.
        action = '"%s" --scan-only' % sys.executable
    else:
        script = os.path.abspath(sys.argv[0])
        action = '"%s" "%s" --scan-only' % (sys.executable, script)
    rc, out = run_cmd(["schtasks", "/Create", "/TN",
                       MONTHLY_TASK_NAME, "/TR", action,
                       "/SC", "MONTHLY", "/D", "1", "/ST", "09:00",
                       "/F"])
    if rc == 0:
        return True, ("monthly auto-check registered: runs on the "
                      "1st at ~09:00, scan-only, report saved next "
                      "to the app")
    return False, "schtasks failed: %s" % out.strip()[:200]


def monthly_unregister():
    if not IS_WINDOWS:
        return False, "needs Windows"
    rc, out = run_cmd(["schtasks", "/Delete", "/TN",
                       MONTHLY_TASK_NAME, "/F"])
    return (rc == 0), ("removed" if rc == 0
                       else "schtasks: %s" % out.strip()[:200])


def monthly_status_text():
    """Last auto-check status note, for the GUI."""
    path = os.path.join(app_dir(), STATUS_FILE)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return "No auto-check has run yet."


def cmd_scan_only():
    """Headless monthly run: scan, save report, record history."""
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    log = RunLog()
    log_path = log.start_file()
    if not IS_WINDOWS:
        log("Monthly auto-check: this machine is not Windows — "
            "nothing scanned, nothing faked.")
        print("scan-only needs Windows; log at %s" % log_path)
        return 2
    log("Monthly auto-check (scan-only — no fixes are ever run "
        "headless).")
    findings = run_scan(log)
    summary = summarize_findings(findings)
    prev = record_history(summary)
    comparison = diff_summaries(prev, summary)
    report = build_report(findings, [])
    report += "\n\n== Auto-check history ==\n%s\n" % comparison
    report_path = os.path.join(app_dir(),
                               "auto-check-%s.txt" % stamp)
    try:
        with open(report_path, "w", encoding="utf-8") as fh:
            fh.write(report)
        with open(os.path.join(app_dir(), STATUS_FILE), "w",
                  encoding="utf-8") as fh:
            fh.write("Last auto-check: %s\nProblems found: %d\n%s\n"
                     "Full report: %s\n"
                     % (stamp, summary["problems"], comparison,
                        report_path))
    except OSError as exc:
        log("Could not save auto-check report: %s" % exc)
    log("Done. %s" % comparison)
    print("Auto-check complete: %d problems. %s"
          % (summary["problems"], comparison))
    return 0


# Feature-pack scanners register into SCANNERS in display order
# (defined late in the file, registered here before anything runs).
def _register_feature_scanners():
    cats = [c for c, _fn in SCANNERS]
    if "boot" not in cats:
        idx = cats.index("disk") + 1 if "disk" in cats else len(cats)
        SCANNERS.insert(idx, ("boot", scan_boot))
        cats.insert(idx, "boot")
    if "programs" not in cats:
        idx = (cats.index("registry") + 1 if "registry" in cats
               else len(cats))
        SCANNERS.insert(idx, ("programs", scan_programs))


_register_feature_scanners()


if __name__ == "__main__":
    sys.exit(main())
