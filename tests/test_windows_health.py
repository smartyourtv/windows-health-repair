"""Unit tests for Windows Health & Repair logic.

Everything here tests pure logic against recorded fixtures — the
Windows-only command paths are never exercised on this machine and
must present as honest 'needs Windows' states instead.
"""
import hashlib
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import windows_health as wh
from tests import fixtures as fx


class TestSystemFileParsers(unittest.TestCase):
    def test_sfc_clean(self):
        r = wh.parse_sfc(fx.SFC_CLEAN)
        self.assertEqual(r["status"], "clean")

    def test_sfc_repaired(self):
        # Fixture wraps "successfully\nrepaired them" across lines —
        # the parser must collapse whitespace or this reads 'unknown'.
        self.assertEqual(wh.parse_sfc(fx.SFC_REPAIRED)["status"],
                         "repaired")

    def test_sfc_unfixed(self):
        # Same wrap hazard: "unable to fix\nsome of them".
        r = wh.parse_sfc(fx.SFC_VIOLATIONS)
        self.assertEqual(r["status"], "violations_unfixed")

    def test_sfc_garbage_is_unknown(self):
        self.assertEqual(wh.parse_sfc("")["status"], "unknown")
        self.assertEqual(wh.parse_sfc("hello")["status"], "unknown")

    def test_dism_states(self):
        self.assertEqual(wh.parse_dism(fx.DISM_HEALTHY)["status"],
                         "healthy")
        self.assertEqual(
            wh.parse_dism(fx.DISM_REPAIRABLE_SCAN)["status"],
            "repairable")
        r = wh.parse_dism(fx.DISM_ERROR)
        self.assertEqual(r["status"], "error")
        self.assertIn("0x800f081f", r["message"])


class TestDiskAndDeviceParsers(unittest.TestCase):
    def test_physical_disk_fixture_contract(self):
        # scan_disk consumes Get-PhysicalDisk JSON via parse_json_list;
        # the fixture must carry the fields it reads.
        disks = wh.parse_json_list(fx.PHYSICAL_DISKS_JSON)
        self.assertEqual(len(disks), 2)
        self.assertEqual(disks[0]["HealthStatus"], "Healthy")
        self.assertEqual(disks[1]["HealthStatus"], "Warning")
        self.assertEqual(disks[1]["OperationalStatus"], "Degraded")

    def test_volume_fixture_free_space_math(self):
        vols = wh.parse_json_list(fx.VOLUMES_JSON)
        c = [v for v in vols if v["DriveLetter"] == "C"][0]
        used_pct = 100.0 * (1 - c["SizeRemaining"] / c["Size"])
        self.assertGreater(used_pct, 90)  # the low-space case

    def test_human_size(self):
        self.assertEqual(wh.human_size(0), "0.0 B")
        self.assertEqual(wh.human_size(1024 * 1024), "1.0 MB")
        self.assertEqual(wh.human_size(None), "unknown")

    def test_problem_devices_filtered_and_translated(self):
        devs = wh.parse_problem_devices(fx.PNP_PROBLEMS_JSON)
        # the code-0 "Fine Device" is filtered out
        self.assertEqual(len(devs), 2)
        by_code = {d["code"]: d for d in devs}
        self.assertIn("not installed", by_code[28]["meaning"])
        self.assertIn("hardware fault", by_code[43]["meaning"])

    def test_unknown_device_code_is_honest(self):
        self.assertEqual(wh.describe_device_problem(999),
                         "problem code 999")
        self.assertIn("not installed", wh.describe_device_problem(28))


class TestUpdateAndServiceParsers(unittest.TestCase):
    def test_service_states(self):
        states = wh.parse_service_states(fx.SERVICES_JSON)
        self.assertEqual(states["wuauserv"]["status"], "Stopped")
        self.assertEqual(states["wuauserv"]["start_type"], "Manual")
        self.assertEqual(states["bits"]["status"], "Running")
        self.assertEqual(states["usosvc"]["start_type"], "Disabled")

    def test_pending_reboot_reasons(self):
        reasons = wh.parse_pending_reboot(
            json.loads(fx.PENDING_REBOOT_JSON))
        self.assertEqual(len(reasons), 2)
        self.assertTrue(any("CBS" in r for r in reasons))

    def test_no_pending_reboot(self):
        self.assertEqual(wh.parse_pending_reboot(
            {"cbs": False, "wu": False, "file_rename": False,
             "computer_rename": False}), [])
        self.assertEqual(wh.parse_pending_reboot(None), [])


class TestEventMining(unittest.TestCase):
    def _groups(self):
        return wh.group_events(wh.parse_json_list(fx.EVENTS_JSON))

    def test_grouping_counts_and_order(self):
        groups = self._groups()
        top = groups[0]
        self.assertEqual(top["provider"],
                         "Microsoft-Windows-Kernel-Power")
        self.assertEqual(top["id"], 41)
        self.assertEqual(top["count"], 2)  # Critical sorts first

    def test_known_ids_explained(self):
        self.assertIn("shut down without a clean shutdown",
                      wh.explain_event(
                          "Microsoft-Windows-Kernel-Power", 41))
        self.assertIn("bad block", wh.explain_event("disk", 7))

    def test_unknown_id_is_none_not_invented(self):
        self.assertIsNone(wh.explain_event("Mystery-Provider", 4242))
        groups = self._groups()
        mystery = [g for g in groups
                   if g["provider"] == "Mystery-Provider"][0]
        self.assertIsNone(mystery["explanation"])


class TestStartupAudit(unittest.TestCase):
    def test_extract_target_path(self):
        self.assertEqual(
            wh.extract_target_path('"C:\\Apps\\tool.exe" /silent'),
            "C:\\Apps\\tool.exe")
        self.assertEqual(wh.extract_target_path(""), "")

    def test_console_classification(self):
        flags = wh.classify_startup_item(
            {"name": "x", "source": "Run",
             "command": "C:\\Windows\\System32\\cmd.exe /c job.bat"},
            exists_fn=lambda p: True)
        self.assertTrue(flags["is_console"])

    def test_missing_target_flagged(self):
        flags = wh.classify_startup_item(
            {"name": "gone", "source": "Run",
             "command": '"C:\\Gone\\gone.exe"'},
            exists_fn=lambda p: False)
        self.assertTrue(flags["target_missing"])
        self.assertFalse(flags["target_exists"])

    def test_normal_app_not_console(self):
        flags = wh.classify_startup_item(
            {"name": "app", "source": "Run",
             "command": '"C:\\Program Files\\App\\app.exe" /min'},
            exists_fn=lambda p: True)
        self.assertFalse(flags["is_console"])
        self.assertTrue(flags["target_exists"])


class TestRegistryStaleness(unittest.TestCase):
    EXISTS = staticmethod(lambda p: p.startswith("C:\\Here"))

    def test_app_paths(self):
        entries = [
            {"key": "K1", "name": "old.exe", "target": "C:\\Gone\\o.exe"},
            {"key": "K2", "name": "fine.exe",
             "target": "C:\\Here\\fine.exe"},
            {"key": "K3", "name": "blank.exe", "target": ""},
        ]
        stale = wh.stale_app_paths(entries, self.EXISTS)
        self.assertEqual([s["name"] for s in stale], ["old.exe"])

    def test_uninstall(self):
        entries = [
            {"key": "K1", "name": "Ghost", "location": "C:\\GoneDir"},
            {"key": "K2", "name": "Real", "location": "C:\\Here"},
            {"key": "K3", "name": "NoLoc", "location": ""},
        ]
        stale = wh.stale_uninstall(entries, self.EXISTS)
        self.assertEqual([s["name"] for s in stale], ["Ghost"])

    def test_run_values(self):
        entries = [
            {"key": "K", "name": "Dead",
             "command": '"C:\\Gone\\dead.exe"'},
            {"key": "K", "name": "Alive",
             "command": '"C:\\Here\\alive.exe"'},
        ]
        stale = wh.stale_run_values(entries, self.EXISTS)
        self.assertEqual([s["name"] for s in stale], ["Dead"])


class TestSecurityParsers(unittest.TestCase):
    def test_defender_good_posture(self):
        s = wh.parse_defender_status(fx.DEFENDER_STATUS_JSON)
        self.assertTrue(s["present"])
        self.assertTrue(s["rtp"])
        self.assertTrue(s["tamper"])
        self.assertEqual(s["sig_age_days"], 1)
        self.assertFalse(s["quick_scan_needed"])

    def test_defender_bad_posture(self):
        s = wh.parse_defender_status(fx.DEFENDER_STATUS_BAD_JSON)
        self.assertTrue(s["present"])
        self.assertFalse(s["rtp"])
        self.assertFalse(s["tamper"])
        self.assertEqual(s["sig_age_days"], 12)
        self.assertTrue(s["quick_scan_needed"])

    def test_defender_absent_is_flagged_not_faked(self):
        self.assertEqual(wh.parse_defender_status(""),
                         {"present": False})
        self.assertEqual(wh.parse_defender_status("{}"),
                         {"present": False})

    def test_exclusions_flat_list(self):
        ex = wh.parse_defender_exclusions(fx.DEFENDER_EXCLUSIONS_JSON)
        pairs = {(e["type"], e["value"]) for e in ex}
        self.assertIn(("path", "C:\\Games"), pairs)
        self.assertIn(("extension", ".tmp"), pairs)
        # empty categories contribute nothing
        self.assertEqual(len(ex), 3)

    def test_firewall_profiles(self):
        profs = wh.parse_firewall_profiles(fx.FIREWALL_JSON)
        by_name = {p["name"]: p["enabled"] for p in profs}
        self.assertEqual(by_name, {"Domain": True, "Private": True,
                                   "Public": False})

    def test_smartscreen_wording(self):
        self.assertEqual(wh.interpret_smartscreen("Off"), "OFF")
        self.assertTrue(wh.interpret_smartscreen("Warn")
                        .startswith("on"))
        self.assertEqual(wh.interpret_smartscreen("Block"),
                         "custom (Block)")

    def test_threat_detections(self):
        threats = wh.parse_threat_detections(fx.THREATS_JSON)
        self.assertEqual(len(threats), 1)
        self.assertEqual(threats[0]["threat_id"], 2147735505)
        self.assertEqual(threats[0]["status_id"], 3)
        self.assertTrue(threats[0]["resources"])

    def test_malwarebytes_detect_and_absent(self):
        entries = [
            {"name": "Some App", "location": "C:\\App",
             "uninstall": "C:\\App\\unins.exe"},
            {"name": "Malwarebytes", "location": "C:\\MB",
             "uninstall": "C:\\MB\\mbam.exe"},
        ]
        hit = wh.find_malwarebytes(entries)
        self.assertIsNotNone(hit)
        self.assertEqual(hit["name"], "Malwarebytes")
        self.assertIsNone(wh.find_malwarebytes(entries[:1]))
        self.assertIsNone(wh.find_malwarebytes([]))

    def test_official_malwarebytes_url_in_source(self):
        # The app must only ever point at Malwarebytes' own site —
        # bundling/redistributing their installer is not allowed.
        # (The URL is split across two literals in the source.)
        src = open(os.path.join(os.path.dirname(__file__), "..",
                                "windows_health.py"),
                   encoding="utf-8").read()
        self.assertIn("https://www.malwarebytes.com/mwb-download/", src)
        self.assertIn("Get Malwarebytes Free (official", src)


class TestDriverParsers(unittest.TestCase):
    def test_signed_driver_inventory(self):
        inv = wh.parse_signed_drivers(fx.SIGNED_DRIVERS_JSON)
        self.assertEqual(len(inv), 3)
        gpu = inv[0]
        self.assertEqual(gpu["provider"], "NVIDIA")
        self.assertEqual(gpu["version"], "32.0.15.6094")
        self.assertEqual(gpu["inf"], "oem42.inf")

    def test_wu_search_parse_and_risk(self):
        ups = wh.parse_wu_driver_updates(fx.WU_DRIVER_SEARCH_JSON)
        self.assertEqual(len(ups), 2)
        self.assertEqual(ups[0]["risk"], "gpu")
        self.assertEqual(ups[1]["risk"], "other")
        self.assertEqual(ups[0]["model"],
                         "NVIDIA GeForce GTX 1660 Ti")

    def test_wu_search_empty_is_empty(self):
        self.assertEqual(wh.parse_wu_driver_updates(""), [])
        self.assertEqual(wh.parse_wu_driver_updates("null"), [])

    def test_driver_risk_classes(self):
        self.assertEqual(
            wh.classify_driver_risk("Intel SATA RAID Controller",
                                    "HDC"), "storage")
        self.assertEqual(
            wh.classify_driver_risk("Printer Driver", "Printer"),
            "other")
        self.assertEqual(
            wh.classify_driver_risk("AMD Radeon Graphics", ""), "gpu")

    def test_wu_install_outcomes(self):
        ok = wh.parse_wu_install_result(fx.WU_INSTALL_OK_JSON)
        self.assertEqual(ok["outcome"], "succeeded")
        self.assertFalse(ok["reboot_required"])
        rb = wh.parse_wu_install_result(fx.WU_INSTALL_REBOOT_JSON)
        self.assertTrue(rb["reboot_required"])
        self.assertEqual(
            wh.parse_wu_install_result(fx.WU_INSTALL_FAILED_JSON)
            ["outcome"], "failed")
        self.assertEqual(
            wh.parse_wu_install_result(fx.WU_INSTALL_NOTFOUND_JSON)
            ["outcome"], "not_found")
        self.assertEqual(wh.parse_wu_install_result("")["outcome"],
                         "unknown")


class TestBootAndPrograms(unittest.TestCase):
    def test_boot_parse_latest_and_offenders(self):
        data = wh.parse_boot_events(fx.BOOT_EVENTS_JSON)
        self.assertEqual(data["latest_boot"]["total_ms"], 48000)
        names = [o["name"] for o in data["offenders"]]
        self.assertTrue(any("slow.exe" in n for n in names))
        self.assertEqual(data["offenders"][0]["total_ms"], 9200)

    def test_boot_parse_empty(self):
        data = wh.parse_boot_events("")
        self.assertIsNone(data["latest_boot"])
        self.assertEqual(data["offenders"], [])

    def test_programs_parse_dedup_and_dates(self):
        progs = wh.parse_installed_programs(fx.PROGRAMS_JSON)
        names = [p["name"] for p in progs]
        self.assertEqual(names.count("Useful App"), 1)
        useful = [p for p in progs if p["name"] == "Useful App"][0]
        self.assertEqual(useful["install_date"], "2026-03-01")
        ask = [p for p in progs if p["name"] == "Ask Toolbar"][0]
        self.assertEqual(ask["install_date"], "")  # honest blank

    def test_program_classification(self):
        progs = wh.parse_installed_programs(fx.PROGRAMS_JSON)
        names = [p["name"] for p in progs]
        self.assertIn("toolbar",
                      " ".join(wh.classify_program("Ask Toolbar",
                                                    names)))
        self.assertIn("trialware",
                      " ".join(wh.classify_program(
                          "Photo Suite Trial", names)))
        upd = wh.classify_program("Alpha Updater", names)
        self.assertTrue(any("updater" in f for f in upd))
        self.assertEqual(wh.classify_program("Useful App", names), [])


class TestCertificateAndHistory(unittest.TestCase):
    def _rows(self, findings, results=None):
        return {r[0]: r for r in wh.certificate_rows(findings,
                                                     results or [])}

    def test_clean_category_grades_a(self):
        rows = self._rows([wh.Finding("disk", "fine",
                                      severity="info")])
        self.assertEqual(rows["Disk"][1], "A")

    def test_no_data_is_not_checked_never_invented(self):
        rows = self._rows([wh.Finding("disk", "fine",
                                      severity="info")])
        self.assertEqual(rows["Security"][1], "Not checked")

    def test_problem_grades_by_rubric(self):
        rows = self._rows([wh.Finding("disk", "one",
                                      severity="warn")])
        self.assertEqual(rows["Disk"][1], "B")
        rows = self._rows([wh.Finding("disk", "x", severity="bad")])
        self.assertEqual(rows["Disk"][1], "C")  # errors count double
        four = [wh.Finding("disk", "p%d" % i, severity="warn")
                for i in range(4)]
        self.assertEqual(self._rows(four)["Disk"][1], "D")

    def test_after_grade_improves_only_with_successful_fix(self):
        f = wh.Finding("disk", "problem", severity="warn",
                       fix_label="fix it", fix_kind="cleanup_temp")
        step = wh.FixStep("cleanup_temp", "fix it", finding=f)
        rows = self._rows([f], [("fix it", True, "done", step)])
        self.assertEqual(rows["Disk"][1], "B")
        self.assertEqual(rows["Disk"][2], "A")
        rows = self._rows([f], [("fix it", False, "nope", step)])
        self.assertEqual(rows["Disk"][2], "B")

    def test_certificate_text_and_html(self):
        fs = [wh.Finding("disk", "fine", severity="info")]
        txt = wh.build_certificate_text(fs, [], when="2026-10-16",
                                        machine="TESTPC")
        self.assertIn("PC Health Certificate — TESTPC", txt)
        self.assertIn("Not checked", txt)
        html = wh.build_certificate_html(fs, [], when="2026-10-16",
                                         machine="TESTPC")
        self.assertIn("<table>", html)
        self.assertIn("TESTPC", html)

    def test_history_diff_wording(self):
        self.assertIn("nothing to compare",
                      wh.diff_summaries(None, {"problems": 3}))
        better = wh.diff_summaries({"problems": 5},
                                   {"problems": 2})
        self.assertTrue(better.startswith("Better"))
        worse = wh.diff_summaries({"problems": 2}, {"problems": 6})
        self.assertTrue(worse.startswith("Worse"))
        same = wh.diff_summaries({"problems": 4}, {"problems": 4})
        self.assertTrue(same.startswith("Same"))

    def test_summarize_counts_problems(self):
        s = wh.summarize_findings([
            wh.Finding("disk", "a", severity="warn"),
            wh.Finding("disk", "b", severity="info"),
            wh.Finding("security", "c", severity="bad")])
        self.assertEqual(s["problems"], 2)
        self.assertEqual(s["by_category"]["security"], 1)


class TestFixPlanSafety(unittest.TestCase):
    def test_restore_point_is_always_step_zero(self):
        f = wh.Finding("sysfiles", "t", fix_label="SFC",
                       fix_kind="sfc_scannow")
        plan = wh.build_fix_plan([f])
        self.assertEqual(plan[0].kind, "restore_point")
        self.assertTrue(wh.plan_is_safe(plan))

    def test_rogue_plan_refused(self):
        rogue = [wh.FixStep("sfc_scannow", "rogue")]
        self.assertFalse(wh.plan_is_safe(rogue))
        results = wh.execute_plan(rogue, wh.RunLog())
        self.assertFalse(results[0][1])
        self.assertIn("refused", results[0][2])

    def test_driver_backup_sorts_before_driver_install(self):
        fb = wh.Finding("devices", "backup", fix_label="backup",
                        fix_kind="driver_backup")
        fi = wh.Finding(
            "devices", "install", fix_label="install",
            fix_kind="driver_install",
            payload={"update_id": "aaaaaaaa-1111-2222-3333-"
                                  "444444444444"})
        plan = wh.build_fix_plan([fi, fb])  # reversed input order
        kinds = [s.kind for s in plan]
        self.assertLess(kinds.index("driver_backup"),
                        kinds.index("driver_install"))

    def _run_with_fakes(self, findings, fake_run):
        orig_create = wh.create_restore_point
        orig_run = wh.run_fix_step
        try:
            wh.create_restore_point = lambda log: (True, "ok")
            wh.run_fix_step = fake_run
            return wh.execute_plan(wh.build_fix_plan(findings),
                                   wh.RunLog())
        finally:
            wh.create_restore_point = orig_create
            wh.run_fix_step = orig_run

    def _driver_finding(self, n=1):
        return wh.Finding(
            "devices", "install %d" % n, fix_label="i%d" % n,
            fix_kind="driver_install",
            payload={"update_id": "aaaaaaaa-1111-2222-3333-"
                                  "444444444444"})

    def test_driver_install_blocked_without_backup(self):
        calls = []

        def fake_run(step, log):
            calls.append(step.kind)
            return True, "fake ok"

        results = self._run_with_fakes([self._driver_finding()],
                                       fake_run)
        inst = [r for r in results if r[3] is not None
                and r[3].kind == "driver_install"][0]
        self.assertFalse(inst[1])
        self.assertIn("backup", inst[2])
        self.assertNotIn("driver_install", calls)

    def test_driver_install_runs_after_backup_ok(self):
        calls = []

        def fake_run(step, log):
            calls.append(step.kind)
            return True, "fake ok"

        fb = wh.Finding("devices", "backup", fix_label="backup",
                        fix_kind="driver_backup")
        results = self._run_with_fakes(
            [fb, self._driver_finding()], fake_run)
        inst = [r for r in results if r[3] is not None
                and r[3].kind == "driver_install"][0]
        self.assertTrue(inst[1])
        self.assertEqual(calls, ["driver_backup", "driver_install"])

    def test_failed_driver_stops_queue(self):
        def fake_run(step, log):
            if step.kind == "driver_install":
                return False, "boom"
            return True, "ok"

        fb = wh.Finding("devices", "backup", fix_label="backup",
                        fix_kind="driver_backup")
        results = self._run_with_fakes(
            [fb, self._driver_finding(1), self._driver_finding(2)],
            fake_run)
        installs = [r for r in results if r[3] is not None
                    and r[3].kind == "driver_install"]
        self.assertEqual(len(installs), 2)
        self.assertIn("queue stopped", installs[1][2])

    def test_opt_in_fixes_unchecked_by_default(self):
        for kind in ("net_reset", "wsreset", "defender_scan"):
            self.assertIn(kind, wh.OPT_IN_KINDS)
        self.assertFalse(wh.Finding(
            "security", "t", fix_kind="defender_scan").default_checked)
        self.assertFalse(wh.Finding(
            "devices", "t", fix_kind="driver_install")
            .default_checked)


class TestOfflineHonesty(unittest.TestCase):
    def test_scanners_need_windows_not_faked(self):
        if wh.IS_WINDOWS:
            self.skipTest("running on Windows")
        for fn in (wh.scan_sysfiles, wh.scan_disk, wh.scan_security,
                   wh.scan_devices, wh.scan_boot, wh.scan_programs):
            out = fn(wh.RunLog())
            self.assertTrue(out)
            self.assertIn("needs Windows", out[0].title)

    def test_driver_backup_dest_timestamped(self):
        dest = wh.driver_backup_dest(base="/tmp/wh-test")
        self.assertIn("drivers-", dest)
        self.assertTrue(dest.startswith("/tmp/wh-test"))

    def test_version_present(self):
        self.assertTrue(wh.APP_VERSION)


class TestGuiContract(unittest.TestCase):
    def test_window_is_resizable_with_minsize(self):
        src = open(os.path.join(os.path.dirname(__file__), "..",
                                "windows_health.py"),
                   encoding="utf-8").read()
        self.assertIn("resizable(True, True)", src)
        self.assertIn("minsize(900, 600)", src)
        self.assertNotIn("resizable(False", src)


# ----------------------------------------------------------------------
# v1.1.0 — security restructure, troubleshooter, preventative scans
# ----------------------------------------------------------------------

class TestSecurityRestructure(unittest.TestCase):
    def test_noisy_defender_json_still_read(self):
        # v1.0.0 lost this to first-run PowerShell progress noise.
        st = wh.parse_defender_status(
            wh.extract_json_text(fx.DEFENDER_STATUS_NOISY))
        self.assertTrue(st["present"])
        self.assertEqual(st["sig_version"], "1.453.123.0")

    def test_defender_findings_lead_with_summary_and_actions(self):
        out = wh._defender_findings(fx.DEFENDER_STATUS_NOISY, "")
        self.assertTrue(out[0].title.startswith(
            "Windows Security (Microsoft Defender):"))
        self.assertIn("v1.453.123.0", out[0].title)
        kinds = [f.fix_kind for f in out if f.fix_kind]
        # even on a healthy PC the actions are offered (v1.0.0 hid
        # them — why the Defender tie-in looked absent)
        self.assertIn("defender_update", kinds)
        self.assertIn("defender_scan", kinds)
        targets = [f.payload.get("open_target") for f in out]
        self.assertIn("ms-windows-security:", targets)

    def test_defender_findings_bad_posture(self):
        out = wh._defender_findings(fx.DEFENDER_STATUS_BAD_JSON,
                                    fx.THREATS_JSON)
        kinds = [f.fix_kind for f in out if f.fix_kind]
        self.assertIn("defender_rtp_enable", kinds)
        self.assertEqual(out[0].severity, "bad")
        self.assertIn("1 threat detection(s)", out[0].title)

    def test_defender_unreadable_is_honest_not_fatal(self):
        out = wh._defender_findings("", None)
        self.assertEqual(len(out), 2)
        self.assertIn("could not be read", out[0].title.lower())

    def test_malwarebytes_card_not_installed(self):
        f = wh._malwarebytes_finding([])
        self.assertEqual(f.payload.get("url"),
                         "https://www.malwarebytes.com/mwb-download/"
                         "thankyou")
        self.assertIn("not installed", f.title)

    def test_malwarebytes_launch_found_via_standard_path(self):
        entry = {"name": "Malwarebytes", "location": "",
                 "uninstall": ""}
        exe = wh.find_malwarebytes_exe(
            entry, exists_fn=lambda p: p.endswith("mbam.exe"))
        self.assertTrue(exe.endswith("mbam.exe"))
        self.assertEqual(
            wh.find_malwarebytes_exe(entry,
                                     exists_fn=lambda p: False), "")

    def test_malwarebytes_card_installed(self):
        entries = [{"name": "Malwarebytes",
                    "location": "C:\\Program Files\\Malwarebytes",
                    "uninstall": "x"}]
        f = wh._malwarebytes_finding(entries)
        self.assertIn("is installed", f.title)
        self.assertNotIn("url", f.payload)

    def test_exclusion_and_firewall_builders(self):
        ex = wh._exclusion_findings(True, fx.DEFENDER_EXCLUSIONS_JSON)
        self.assertEqual(len(ex), 3)
        self.assertTrue(all(f.fix_kind == "exclusion_remove"
                            for f in ex))
        fw = wh._firewall_findings(True, fx.FIREWALL_JSON)
        off = [f for f in fw if f.fix_kind == "firewall_enable"]
        self.assertEqual(len(off), 1)
        self.assertEqual(off[0].payload["profile"], "Public")


# ----------------------------------------------------------------------
# v1.2.0 — Defender malware scans (quick/full/custom/offline),
# named threat history, Defender's own threat actions
# ----------------------------------------------------------------------

class TestDefenderScanPhase2(unittest.TestCase):
    def _with_fakes(self, fn, run_ps=None, run_cmd=None, ps_json=None,
                    detections=None):
        orig = (wh.run_ps, wh.run_cmd, wh.ps_json,
                wh._defender_detections_now)
        try:
            if run_ps is not None:
                wh.run_ps = run_ps
            if run_cmd is not None:
                wh.run_cmd = run_cmd
            if ps_json is not None:
                wh.ps_json = ps_json
            if detections is not None:
                wh._defender_detections_now = \
                    lambda log: (True, detections)
            return fn()
        finally:
            (wh.run_ps, wh.run_cmd, wh.ps_json,
             wh._defender_detections_now) = orig

    def test_threat_names_parse_and_join(self):
        names = wh.parse_threat_names(fx.THREAT_NAMES_JSON)
        self.assertEqual(len(names), 2)
        by_id = wh.threat_names_by_id(names)
        self.assertEqual(by_id[2147735505],
                         "Trojan:Win32/Wacatac.B!ml")
        self.assertEqual(wh.parse_threat_names(""), [])

    def test_threat_status_text_known_and_unknown(self):
        self.assertTrue(wh.threat_status_text(1)
                        .startswith("detected"))
        self.assertTrue(wh.threat_status_text(4)
                        .startswith("removed"))
        unknown = wh.threat_status_text(999)
        self.assertIn("999", unknown)
        self.assertIn("unknown", wh.threat_status_text(None))

    def test_threat_default_actions_parse(self):
        out = wh.parse_threat_default_actions(
            fx.DEFENDER_PREFERENCE_ACTIONS_JSON)
        self.assertEqual(out, {2147735505: 2})
        self.assertEqual(wh.parse_threat_default_actions(""), {})
        single = wh.parse_threat_default_actions(
            '{"ThreatIDDefaultAction_Ids":5,'
            '"ThreatIDDefaultAction_Actions":3}')
        self.assertEqual(single, {5: 3})

    def test_detections_gain_action_success_key(self):
        d = wh.parse_threat_detections(fx.THREATS_ACTIVE_JSON)[0]
        self.assertIs(d["action_success"], False)
        self.assertEqual(d["status_id"], 1)

    def test_scan_command_builders(self):
        self.assertEqual(wh.defender_scan_ps("quick"),
                         "Start-MpScan -ScanType QuickScan")
        self.assertEqual(wh.defender_scan_ps("full"),
                         "Start-MpScan -ScanType FullScan")
        self.assertEqual(
            wh.defender_scan_ps("custom", r"C:\My Downloads"),
            "Start-MpScan -ScanType CustomScan "
            "-ScanPath 'C:\\My Downloads'")
        self.assertIsNone(wh.defender_scan_ps("offline"))
        self.assertEqual(wh.defender_scan_mpcmdrun_suffix("quick"),
                         "-Scan -ScanType 1")
        self.assertEqual(
            wh.defender_scan_mpcmdrun_suffix("custom", "D:\\stick"),
            "-Scan -ScanType 3 -File 'D:\\stick'")
        self.assertIsNone(wh.defender_scan_mpcmdrun_suffix("offline"))
        with self.assertRaises(ValueError):
            wh.defender_scan_ps("custom")
        with self.assertRaises(ValueError):
            wh.defender_scan_ps("sideways")

    def test_findings_offer_full_scan_set(self):
        out = wh._defender_findings(fx.DEFENDER_STATUS_JSON,
                                    fx.THREATS_ACTIVE_JSON,
                                    fx.THREAT_NAMES_JSON)
        scans = {f.payload.get("scan_type"): f for f in out
                 if f.fix_kind == "defender_scan"}
        self.assertEqual(set(scans), {"quick", "full", "offline"})
        self.assertTrue(all(not f.default_checked
                            for f in scans.values()))
        offline = scans["offline"]
        self.assertIn("RESTARTS", offline.title)
        self.assertIn("CANNOT see or verify", offline.detail)
        folder = [f for f in out
                  if (f.payload or {}).get("defender_folder_scan")]
        self.assertEqual(len(folder), 1)

    def test_threat_history_named_with_actions(self):
        out = wh._defender_findings(fx.DEFENDER_STATUS_JSON,
                                    fx.THREATS_MIXED_JSON,
                                    fx.THREAT_NAMES_JSON)
        hist = [f for f in out
                if f.title.startswith("Threat detected:")]
        self.assertEqual(len(hist), 2)
        active = [f for f in hist
                  if "Wacatac" in f.title][0]
        self.assertEqual(active.severity, "bad")
        self.assertIn("still needs action", active.detail)
        self.assertEqual(
            active.payload["threat_actions"]["threat_id"],
            2147735505)
        removed = [f for f in hist if "Packunwan" in f.title][0]
        self.assertEqual(removed.severity, "warn")
        self.assertIn("removed by Defender", removed.detail)
        kinds = [f.fix_kind for f in out if f.fix_kind]
        self.assertIn("defender_threat_remove", kinds)

    def test_threat_history_no_remove_when_none_active(self):
        out = wh._defender_findings(fx.DEFENDER_STATUS_JSON,
                                    fx.THREATS_JSON,  # status 3
                                    fx.THREAT_NAMES_JSON)
        kinds = [f.fix_kind for f in out if f.fix_kind]
        self.assertNotIn("defender_threat_remove", kinds)

    def test_threat_action_validation_refuses_garbage(self):
        log = wh.RunLog()
        bad_id = wh.FixStep("defender_threat_action", "x",
                            payload={"threat_id": "abc",
                                     "action": "Remove"})
        ok, msg = wh.fix_defender_threat_action(bad_id, log)
        self.assertFalse(ok)
        self.assertIn("refusing", msg)
        bad_verb = wh.FixStep("defender_threat_action", "x",
                              payload={"threat_id": 5,
                                       "action": "Nuke"})
        ok, msg = wh.fix_defender_threat_action(bad_verb, log)
        self.assertFalse(ok)
        self.assertIn("refusing", msg)

    def test_threat_action_command_and_refusal(self):
        seen = []

        def fake_ps(cmd, timeout=0, log=None):
            seen.append(cmd)
            return 0, ""

        step = wh.FixStep("defender_threat_action", "x",
                          payload={"threat_id": 2147735505,
                                   "threat_name": "Trojan:X",
                                   "action": "Quarantine"})
        ok, msg = self._with_fakes(
            lambda: wh.fix_defender_threat_action(step, wh.RunLog()),
            run_ps=fake_ps)
        self.assertTrue(ok)
        self.assertIn("ThreatIDDefaultAction_Ids 2147735505",
                      seen[0])
        self.assertIn("NEXT time", msg)

        def refusing_ps(cmd, timeout=0, log=None):
            return 1, "Access denied by tamper protection"

        ok, msg = self._with_fakes(
            lambda: wh.fix_defender_threat_action(step, wh.RunLog()),
            run_ps=refusing_ps)
        self.assertFalse(ok)
        self.assertIn("refused", msg)
        self.assertIn("does not", msg)  # no workaround offered

    def test_threat_remove_recounts_active(self):
        step = wh.FixStep("defender_threat_remove", "x")
        gone = wh.parse_threat_detections(fx.THREATS_JSON)  # st. 3
        ok, msg = self._with_fakes(
            lambda: wh.fix_defender_threat_remove(step, wh.RunLog()),
            run_ps=lambda cmd, timeout=0, log=None: (0, ""),
            detections=gone)
        self.assertTrue(ok)
        self.assertIn("no detections remain", msg)
        still = wh.parse_threat_detections(fx.THREATS_ACTIVE_JSON)
        ok, msg = self._with_fakes(
            lambda: wh.fix_defender_threat_remove(step, wh.RunLog()),
            run_ps=lambda cmd, timeout=0, log=None: (0, ""),
            detections=still)
        self.assertTrue(ok)
        self.assertIn("still marked", msg)

    def test_offline_scan_scheduling_and_honesty(self):
        step = wh.FixStep("defender_scan", "x",
                          payload={"scan_type": "offline"})
        ok, msg = self._with_fakes(
            lambda: wh.fix_defender_scan(step, wh.RunLog()),
            run_ps=lambda cmd, timeout=0, log=None: (0, ""))
        self.assertTrue(ok)
        self.assertIn("RESTART", msg)
        self.assertIn("CANNOT verify", msg)
        ok, msg = self._with_fakes(
            lambda: wh.fix_defender_scan(step, wh.RunLog()),
            run_ps=lambda cmd, timeout=0, log=None: (1, "nope"))
        self.assertFalse(ok)

    def test_custom_scan_missing_folder_refused(self):
        step = wh.FixStep(
            "defender_scan", "x",
            payload={"scan_type": "custom",
                     "scan_path": "/definitely/not/a/real/folder"})
        ok, msg = wh.fix_defender_scan(step, wh.RunLog())
        self.assertFalse(ok)
        self.assertIn("folder not found", msg)

    def test_verify_threat_action_reads_back(self):
        step = wh.FixStep("defender_threat_action", "x",
                          payload={"threat_id": 2147735505,
                                   "action": "Remove"})
        note = self._with_fakes(
            lambda: wh.verify_step(step, wh.RunLog()),
            ps_json=lambda cmd, timeout=0, log=None:
                (True, fx.DEFENDER_PREFERENCE_ACTIONS_JSON))
        if wh.IS_WINDOWS:
            self.assertIn("standing action for threat", note)
        else:
            self.assertIsNone(note)  # verify degrades off-Windows

    def test_new_kinds_opt_in_and_ordered(self):
        self.assertIn("defender_threat_remove", wh.OPT_IN_KINDS)
        self.assertIn("defender_threat_action", wh.OPT_IN_KINDS)
        self.assertLess(wh.FIX_ORDER["defender_scan"],
                        wh.FIX_ORDER["defender_threat_remove"])
        self.assertLess(wh.FIX_ORDER["defender_threat_remove"],
                        wh.FIX_ORDER["defender_threat_action"])

    def test_gui_contract_defender_actions(self):
        src = open(os.path.join(os.path.dirname(__file__), "..",
                                "windows_health.py"),
                   encoding="utf-8").read()
        self.assertIn("def confirm_and_run_plan", src)
        self.assertIn('get("defender_folder_scan")', src)
        self.assertIn('get("threat_actions")', src)
        self.assertIn("askdirectory", src)
        # do_fix runs through the same single plan path
        self.assertIn("confirm_and_run_plan(\n            "
                      "build_fix_plan(chosen)", src)


class TestNewParsers(unittest.TestCase):
    def test_nslookup(self):
        self.assertTrue(wh.parse_nslookup(fx.NSLOOKUP_OK)["ok"])
        self.assertFalse(wh.parse_nslookup(fx.NSLOOKUP_FAIL)["ok"])
        self.assertFalse(wh.parse_nslookup("")["ok"])

    def test_ping(self):
        self.assertEqual(wh.parse_ping(fx.PING_OK),
                         {"sent": 2, "received": 2, "ok": True})
        self.assertFalse(wh.parse_ping(fx.PING_FAIL)["ok"])
        self.assertIsNone(wh.parse_ping("total garbage"))

    def test_adapters_and_sound(self):
        ads = wh.parse_net_adapters(fx.NET_ADAPTERS_JSON)
        self.assertEqual(ads[0]["status"], "Up")
        snd = wh.parse_sound_devices(fx.SOUND_DEVICES_JSON)
        self.assertEqual(snd[0]["status"], "OK")

    def test_smart_predict(self):
        preds = wh.parse_smart_predict(fx.SMART_PREDICT_JSON)
        self.assertEqual([p["predict_failure"] for p in preds],
                         [False, True])
        self.assertIsNone(wh.parse_smart_predict(""))

    def test_wu_pending_count(self):
        self.assertEqual(wh.parse_wu_pending_count(fx.WU_PENDING_JSON),
                         5)
        self.assertIsNone(wh.parse_wu_pending_count("not json"))

    def test_bugcheck_and_wu_error_codes(self):
        self.assertEqual(wh.bugcheck_codes(fx.BUGCHECK_EVENTS),
                         [("0x000000d1", 2)])
        self.assertEqual(wh.wu_error_codes(fx.WU_FAIL_EVENTS),
                         [("0x80070422", 1)])
        self.assertEqual(wh.bugcheck_codes([]), [])


class FakeEnv:
    """Troubleshooter probe double — a healthy PC unless poked."""

    GB = 1024 ** 3

    def __init__(self):
        self._sfc = {"status": "clean", "message": "clean"}
        self._dism = {"status": "healthy", "message": "healthy"}
        self._services = {}
        self._events = []
        self._problems = []
        self._audio = {"services": {
            "audiosrv": {"status": "Running", "start_type": "Auto",
                         "display": "Windows Audio"},
            "audioendpointbuilder": {
                "status": "Running", "start_type": "Auto",
                "display": "Audio Endpoint Builder"}},
            "devices": [{"name": "Speakers", "status": "OK"}],
            "endpoints": [{"FriendlyName": "Speakers",
                           "Status": "OK"}],
            "problem_devices": []}
        self._defender = {"present": True, "rtp": True,
                          "sig_age_days": 0}
        self._wu_search = {"ok": True, "count": 0, "error": None}

    def sfc(self):
        return self._sfc

    def dism(self):
        return self._dism

    def services(self, names):
        return {n.lower(): self._services[n.lower()]
                for n in names if n.lower() in self._services}

    def events(self, days, provider_like=None):
        return list(self._events)

    def boot(self):
        return {"latest_boot": {"total_ms": 30000, "time": "2026"},
                "offenders": []}

    def startup_items(self):
        return {"total": 4, "missing": [], "console": []}

    def junk_sizes(self):
        return {}

    def volumes(self):
        return [{"DriveLetter": "C", "Size": 500 * self.GB,
                 "SizeRemaining": 250 * self.GB}]

    def disk_health(self):
        return [{"FriendlyName": "D0", "HealthStatus": "Healthy"}]

    def smart_predict(self):
        return [{"instance": "D0", "predict_failure": False}]

    def problem_devices(self):
        return list(self._problems)

    def memory_diag(self):
        return {"ran": False, "failed": None}

    def adapters(self):
        return [{"name": "Wi-Fi", "status": "Up",
                 "link_speed": "866 Mbps", "desc": ""}]

    def ping_gateway(self):
        return {"sent": 2, "received": 2, "ok": True}

    def dns_lookup(self):
        return {"ok": True, "detail": "resolved"}

    def proxy(self):
        return {"enabled": False, "server": ""}

    def audio(self):
        return self._audio

    def pending_reboot(self):
        return []

    def wu_search(self):
        return self._wu_search

    def defender(self):
        return self._defender

    def firewall(self):
        return [{"name": "Public", "enabled": True}]

    def exclusions(self):
        return []

    def threats(self):
        return []


class TestTroubleshooter(unittest.TestCase):
    def test_healthy_pc_is_not_found_with_ruled_out_list(self):
        out = wh.run_troubleshooter("slow_startup", FakeEnv())
        self.assertEqual(out["outcome"], "not_found")
        self.assertEqual(len(out["checks"]), 6)
        self.assertTrue(out["next_steps"])
        self.assertIsNone(out["cause"])

    def test_dead_startup_entries_are_fixable(self):
        env = FakeEnv()
        env.startup_items = lambda: {
            "total": 5,
            "missing": [{"name": "Ghost",
                         "disable": {"mode": "run_value",
                                     "key": "HKCU\\Run",
                                     "name": "Ghost"}}],
            "console": []}
        out = wh.run_troubleshooter("slow_startup", env)
        self.assertEqual(out["outcome"], "fixable")
        self.assertEqual(out["cause"]["id"],
                         "dead_startup_entries")
        findings = wh.cause_to_findings(out)
        self.assertEqual(findings[0].fix_kind, "startup_disable")
        plan = wh.build_fix_plan(findings)
        self.assertTrue(wh.plan_is_safe(plan))

    def test_flow_stops_at_first_cause(self):
        env = FakeEnv()
        env.smart_predict = lambda: [
            {"instance": "D0", "predict_failure": True}]
        out = wh.run_troubleshooter("disk", env)
        self.assertEqual(out["outcome"], "guided")
        self.assertEqual(len(out["checks"]), 1)  # SMART is first
        self.assertTrue(out["cause"]["guide"])

    def test_dns_failure_fixable_and_verifies(self):
        env = FakeEnv()
        state = {"ok": False}
        env.dns_lookup = lambda: {
            "ok": state["ok"],
            "detail": "resolved" if state["ok"] else "failed"}
        out = wh.run_troubleshooter("network", env)
        self.assertEqual(out["outcome"], "fixable")
        self.assertEqual(out["cause"]["id"], "dns_failing")
        passed, _ev = wh.verify_troubleshoot(out, env)
        self.assertFalse(passed)  # still broken before the fix
        state["ok"] = True
        passed, _ev = wh.verify_troubleshoot(out, env)
        self.assertTrue(passed)

    def test_disabled_update_service_fixable(self):
        env = FakeEnv()
        env._services = {"wuauserv": {
            "status": "Stopped", "start_type": "Disabled",
            "display": "Windows Update"}}
        out = wh.run_troubleshooter("update", env)
        self.assertEqual(out["outcome"], "fixable")
        fx0 = out["cause"]["fixes"][0]
        self.assertEqual(fx0["kind"], "service_start")
        self.assertEqual(fx0["payload"]["name"], "wuauserv")

    def test_sfc_violations_fixable(self):
        env = FakeEnv()
        env._sfc = {"status": "violations_unfixed",
                    "message": "unable to fix some"}
        out = wh.run_troubleshooter("crashes", env)
        self.assertEqual(out["outcome"], "fixable")
        self.assertEqual(out["cause"]["fixes"][0]["kind"],
                         "sfc_scannow")

    def test_security_rtp_off_fixable(self):
        env = FakeEnv()
        env._defender = {"present": True, "rtp": False,
                         "sig_age_days": 0}
        out = wh.run_troubleshooter("security", env)
        self.assertEqual(out["outcome"], "fixable")
        self.assertEqual(out["cause"]["id"], "rtp_off")

    def test_broken_probe_degrades_to_unknown_not_crash(self):
        class BoomEnv(FakeEnv):
            def dism(self):
                raise RuntimeError("boom")

        out = wh.run_troubleshooter("crashes", BoomEnv())
        dism = [r for r in out["checks"] if r["id"] == "dism"][0]
        self.assertEqual(dism["status"], "unknown")
        self.assertEqual(out["outcome"], "not_found")

    def test_bugcheck_is_guided_with_code(self):
        env = FakeEnv()
        env._events = fx.BUGCHECK_EVENTS
        out = wh.run_troubleshooter("crashes", env)
        self.assertEqual(out["outcome"], "guided")
        self.assertIn("0x000000d1", out["checks"][0]["evidence"])

    def test_real_probes_off_windows_degrade_honestly(self):
        if wh.IS_WINDOWS:
            self.skipTest("running on Windows")
        out = wh.run_troubleshooter("slow_startup",
                                    wh.WindowsProbes(wh.RunLog()))
        self.assertEqual(out["outcome"], "not_found")
        self.assertTrue(all(r["status"] in ("pass", "unknown")
                            for r in out["checks"]))


class TestPreventative(unittest.TestCase):
    GB = 1024 ** 3

    def _data(self, **kw):
        d = {"collected_at": "2026-10-17T09:00:00",
             "disks": [{"FriendlyName": "D0",
                        "HealthStatus": "Healthy"}],
             "smart": [{"instance": "D0", "predict_failure": False}],
             "volumes": [{"DriveLetter": "C",
                          "Size": 500 * self.GB,
                          "SizeRemaining": 250 * self.GB}],
             "defender": {"present": True, "rtp": True,
                          "sig_age_days": 1},
             "firewall": [{"name": "Public", "enabled": True}],
             "pending_updates": 0, "startup_names": ["A"],
             "event_patterns": [], "restore_point_age_days": 3.0}
        d.update(kw)
        return d

    def test_healthy_data_no_issues(self):
        issues, changes = wh.evaluate_preventative(
            self._data(), self._data())
        self.assertEqual(issues, [])
        self.assertEqual(changes, [])

    def test_attention_items_found(self):
        issues, _ = wh.evaluate_preventative(self._data(
            smart=[{"instance": "D9", "predict_failure": True}],
            defender={"present": True, "rtp": False,
                      "sig_age_days": 20},
            firewall=[{"name": "Public", "enabled": False}],
            pending_updates=12))
        keys = {i["key"] for i in issues}
        self.assertIn("smart:D9", keys)
        self.assertIn("defender-rtp", keys)
        self.assertIn("defender-sig", keys)
        self.assertIn("firewall:Public", keys)
        self.assertIn("pending-updates", keys)
        for i in issues:
            self.assertIn("area", i)

    def test_changes_vs_previous(self):
        prev = self._data()
        cur = self._data(
            volumes=[{"DriveLetter": "C", "Size": 500 * self.GB,
                      "SizeRemaining": 100 * self.GB}],
            startup_names=["A", "NewApp"], pending_updates=3)
        _issues, changes = wh.evaluate_preventative(cur, prev)
        joined = " ".join(changes)
        self.assertIn("free space dropped", joined)
        self.assertIn("NewApp", joined)
        self.assertIn("Pending updates: 3 now, was 0", joined)

    def test_first_scan_has_no_change_claims(self):
        _issues, changes = wh.evaluate_preventative(self._data(),
                                                    None)
        self.assertEqual(changes, [])

    def test_event_pattern_thresholds(self):
        grouped = [
            {"provider": "disk", "id": 7, "count": 1},
            {"provider": "Service Control Manager", "id": 7031,
             "count": 2},
            {"provider": "Microsoft-Windows-WHEA-Logger", "id": 18,
             "count": 1},
        ]
        pats = wh.select_event_patterns(grouped)
        keys = {p["key"] for p in pats}
        self.assertIn("disk", keys)
        self.assertIn("whea-logger", keys)
        # 2 service failures is under the >=3 pattern threshold
        self.assertNotIn("service control manager", keys)

    def test_history_round_trip(self):
        import tempfile
        path = os.path.join(tempfile.mkdtemp(), "prev.json")
        self.assertIsNone(wh.record_preventative(self._data(), path))
        prev = wh.record_preventative(self._data(), path)
        self.assertEqual(prev["startup_names"], ["A"])
        hist = wh.load_preventative_history(path)
        self.assertEqual(len(hist["scans"]), 2)

    def test_findings_carry_troubleshooter_routing(self):
        findings, _changes, attention = \
            wh.build_preventative_findings(
                self._data(defender={"present": True, "rtp": False,
                                     "sig_age_days": 1}), None)
        self.assertEqual(attention, 1)
        routed = [f for f in findings
                  if f.payload.get("ts_area") == "security"]
        self.assertEqual(len(routed), 1)
        self.assertEqual(routed[0].category, "preventative")


class TestScheduleAndNewFixes(unittest.TestCase):
    def test_mode_default_and_roundtrip(self):
        import tempfile
        path = os.path.join(tempfile.mkdtemp(), "mode.json")
        self.assertEqual(wh.auto_check_mode(path), "monthly")
        wh.save_auto_check_mode("weekly", path)
        self.assertEqual(wh.auto_check_mode(path), "weekly")
        with self.assertRaises(ValueError):
            wh.save_auto_check_mode("daily", path)

    def test_schtasks_args(self):
        weekly = wh.auto_check_schtasks_args("weekly", "ACT")
        self.assertIn("WEEKLY", weekly)
        self.assertIn("MON", weekly)
        monthly = wh.auto_check_schtasks_args("monthly", "ACT")
        self.assertIn("MONTHLY", monthly)
        self.assertIn(wh.MONTHLY_TASK_NAME, monthly)

    def test_new_fix_kinds_ordered_after_existing(self):
        self.assertGreater(wh.FIX_ORDER["service_start"],
                           wh.FIX_ORDER["defender_rtp_enable"])
        self.assertLess(wh.FIX_ORDER["cleanup_wu_cache"],
                        wh.FIX_ORDER["wu_reset"])
        self.assertLess(wh.FIX_ORDER["dns_flush"],
                        wh.FIX_ORDER["cache_rebuild"])

    def test_service_backup_written(self):
        import tempfile
        dest = tempfile.mkdtemp()
        path = wh.write_service_backup(
            {"name": "wuauserv", "start_type_before": "Disabled"},
            dest_dir=dest)
        with open(path, encoding="utf-8") as fh:
            rec = json.load(fh)
        self.assertEqual(rec["start_type_before"], "Disabled")

    def test_wu_backup_name(self):
        name = wh.wu_cache_backup_name(
            wh.datetime.datetime(2026, 10, 17, 9, 30, 0))
        self.assertEqual(name, "Download.bak-20261017-093000")

    def test_new_kinds_need_windows_off_windows(self):
        if wh.IS_WINDOWS:
            self.skipTest("running on Windows")
        for kind in ("dns_flush", "wu_reset", "service_start"):
            ok, msg = wh.run_fix_step(wh.FixStep(kind, "x"),
                                      wh.RunLog())
            self.assertFalse(ok)
            self.assertIn("needs Windows", msg)


# ----------------------------------------------------------------------
# v1.1.1 — in-app updater + crash & error reports
# ----------------------------------------------------------------------

class _FakeResp:
    """Minimal HTTP response stand-in (context manager + read)."""

    def __init__(self, data):
        self._buf = data

    def read(self, n=-1):
        if n is None or n < 0:
            out, self._buf = self._buf, b""
            return out
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _release_payload(version="9.9.9", size=123, sha="a" * 64,
                     checksum=True):
    assets = [{"name": wh.UPDATE_SETUP_NAME, "size": size,
               "browser_download_url": "https://example.invalid/s",
               "digest": "sha256:" + sha}]
    if checksum:
        assets.append({"name": wh.UPDATE_CHECKSUM_NAME,
                       "browser_download_url":
                           "https://example.invalid/c"})
    return {"tag_name": "v" + version,
            "html_url": "https://example.invalid/r",
            "assets": assets}


class TestInAppUpdater(unittest.TestCase):
    def test_parse_version(self):
        self.assertEqual(wh.parse_version("v1.2.3"), (1, 2, 3))
        self.assertEqual(wh.parse_version("1.2"), (1, 2))
        self.assertEqual(wh.parse_version("v2.0.0-rc1"), (2, 0, 0))
        self.assertIsNone(wh.parse_version("soon"))
        self.assertIsNone(wh.parse_version(""))
        self.assertIsNone(wh.parse_version(None))

    def test_is_newer_version_compares_numbers_not_text(self):
        self.assertTrue(wh.is_newer_version("1.10.0", "1.9.9"))
        self.assertTrue(wh.is_newer_version("v1.1.1", "1.1.0"))
        self.assertFalse(wh.is_newer_version("1.1.0", "1.1.0"))
        self.assertFalse(wh.is_newer_version("1.0.9", "1.1.0"))
        self.assertFalse(wh.is_newer_version("junk", "1.1.0"))

    def test_parse_release(self):
        info = wh.parse_release(_release_payload())
        self.assertEqual(info["version"], "9.9.9")
        self.assertEqual(info["setup"]["size"], 123)
        self.assertEqual(info["setup"]["sha256"], "a" * 64)
        self.assertTrue(info["checksum_url"].endswith("/c"))

    def test_parse_release_rejects_unusable_payloads(self):
        self.assertIsNone(wh.parse_release(None))
        self.assertIsNone(wh.parse_release({"tag_name": "hello"}))
        info = wh.parse_release({"tag_name": "v1.0.0", "assets": []})
        self.assertIsNone(info["setup"])
        bad = _release_payload()
        bad["assets"][0]["digest"] = "sha256:not-a-hash"
        self.assertIsNone(wh.parse_release(bad)["setup"]["sha256"])

    def test_notice_once_per_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "u.json")
            self.assertTrue(wh.update_notice_wanted(
                {}, "2.0.0", current="1.0.0"))
            st = wh.dismiss_update_notice({}, "2.0.0", path=path)
            self.assertFalse(wh.update_notice_wanted(
                st, "2.0.0", current="1.0.0"))
            self.assertTrue(wh.update_notice_wanted(
                st, "2.0.1", current="1.0.0"))
            self.assertFalse(wh.update_notice_wanted(
                st, "1.0.0", current="1.0.0"))
            self.assertEqual(wh.load_update_state(path), st)

    def test_check_due_throttle(self):
        now = wh.datetime.datetime(2026, 10, 17, 12, 0, 0)
        self.assertTrue(wh.update_check_due({}, now=now))
        self.assertFalse(wh.update_check_due(
            {"last_check": "2026-10-17T11:00:00"}, now=now))
        self.assertTrue(wh.update_check_due(
            {"last_check": "2026-10-16T11:00:00"}, now=now))
        self.assertTrue(wh.update_check_due(
            {"last_check": "not a date"}, now=now))

    def test_record_check_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "u.json")
            st = wh.record_update_check({}, "9.9.9", path=path)
            loaded = wh.load_update_state(path)
            self.assertEqual(loaded["last_seen_version"], "9.9.9")
            self.assertEqual(loaded["last_check"],
                             st["last_check"])
            self.assertFalse(wh.update_check_due(loaded))

    def test_fetch_latest_release_ok(self):
        payload = json.dumps(_release_payload()).encode()
        info, err = wh.fetch_latest_release(
            opener=lambda req, timeout=None: _FakeResp(payload))
        self.assertIsNone(err)
        self.assertEqual(info["version"], "9.9.9")

    def test_fetch_latest_release_errors_are_plain(self):
        def http_error(req, timeout=None):
            raise urllib.error.HTTPError("https://x", 503, "e",
                                         {}, None)
        info, err = wh.fetch_latest_release(opener=http_error)
        self.assertIsNone(info)
        self.assertIn("503", err)

        def unreachable(req, timeout=None):
            raise urllib.error.URLError("down")
        info, err = wh.fetch_latest_release(opener=unreachable)
        self.assertIsNone(info)
        self.assertIn("Could not reach GitHub", err)

        info, err = wh.fetch_latest_release(
            opener=lambda req, timeout=None: _FakeResp(b"no json"))
        self.assertIsNone(info)
        self.assertIsNotNone(err)

    def test_expected_sha256_prefers_checksum_file(self):
        info = wh.parse_release(_release_payload(sha="b" * 64))
        text = ("a" * 64 + "  " + wh.UPDATE_SETUP_NAME).encode()
        sha = wh.fetch_expected_sha256(
            info, opener=lambda req, timeout=None: _FakeResp(text))
        self.assertEqual(sha, "a" * 64)

    def test_expected_sha256_falls_back_to_digest(self):
        info = wh.parse_release(_release_payload(sha="b" * 64))

        def unreachable(req, timeout=None):
            raise urllib.error.URLError("down")
        self.assertEqual(wh.fetch_expected_sha256(
            info, opener=unreachable), "b" * 64)
        info2 = wh.parse_release(_release_payload(
            checksum=False, sha="b" * 64))
        self.assertEqual(wh.fetch_expected_sha256(info2), "b" * 64)
        info3 = wh.parse_release({"tag_name": "v1.0.0", "assets": [
            {"name": wh.UPDATE_SETUP_NAME, "size": 1,
             "browser_download_url": "https://example.invalid/s"}]})
        self.assertIsNone(wh.fetch_expected_sha256(info3))

    def test_download_and_verify(self):
        blob = b"installer-bytes" * 30000
        digest = hashlib.sha256(blob).hexdigest()
        calls = []
        with tempfile.TemporaryDirectory() as tmp:
            dest, err = wh.download_update(
                {"setup": {"url": "https://example.invalid/s",
                           "size": len(blob)}},
                dest_dir=tmp,
                opener=lambda req, timeout=None: _FakeResp(blob),
                progress=lambda d, t: calls.append((d, t)))
            self.assertIsNone(err)
            self.assertEqual(calls[-1], (len(blob), len(blob)))
            ok, _msg = wh.verify_download(dest, len(blob), digest)
            self.assertTrue(ok)
            ok, _ = wh.verify_download(dest, len(blob) + 1, digest)
            self.assertFalse(ok)
            ok, _ = wh.verify_download(dest, len(blob), "0" * 64)
            self.assertFalse(ok)
            ok, msg = wh.verify_download(dest, len(blob))
            self.assertTrue(ok)
            self.assertIn("SHA-256", msg)
            ok, _ = wh.verify_download(dest + ".missing",
                                       len(blob), digest)
            self.assertFalse(ok)

    def test_download_failure_leaves_no_partial_file(self):
        class _FlakyResp:
            def __init__(self):
                self._reads = 0

            def read(self, n=-1):
                self._reads += 1
                if self._reads == 1:
                    return b"partial"
                raise urllib.error.URLError("connection reset")

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        with tempfile.TemporaryDirectory() as tmp:
            dest, err = wh.download_update(
                {"setup": {"url": "https://example.invalid/s",
                           "size": 10}},
                dest_dir=tmp,
                opener=lambda req, timeout=None: _FlakyResp())
            self.assertIsNone(dest)
            self.assertIsNotNone(err)
            self.assertFalse(os.path.exists(
                os.path.join(tmp, wh.UPDATE_SETUP_NAME)))


class TestCrashReports(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = self._tmp.name

    def _raise(self, exc):
        try:
            raise exc
        except Exception:
            return sys.exc_info()

    def test_downloads_dir_uses_userprofile(self):
        if wh.IS_WINDOWS:
            self.skipTest("known-folder path differs on Windows")
        with mock.patch.dict(os.environ,
                             {"USERPROFILE": self.dir}):
            self.assertEqual(wh.downloads_dir(),
                             os.path.join(self.dir, "Downloads"))

    def test_report_name_format(self):
        name = wh.crash_report_name(
            wh.datetime.datetime(2026, 10, 17, 9, 5, 3))
        self.assertEqual(
            name, "WindowsHealthRepair-crash-20261017-090503.txt")
        self.assertTrue(wh._CRASH_NAME_RE.match(name))

    def test_write_report_contents(self):
        when = wh.datetime.datetime(2026, 10, 17, 9, 5, 3)
        log = wh.RunLog()
        log("first line")
        log("second line")
        t, v, tb = self._raise(RuntimeError("kaput"))
        path = wh.write_crash_report(t, v, tb, when=when,
                                     dirs=[self.dir], log=log)
        self.assertIsNotNone(path)
        text = wh.read_crash_report(path)
        self.assertIn("ran into an unexpected problem", text)
        self.assertIn("Nothing was sent anywhere", text)
        self.assertIn("When: 2026-10-17 09:05:03", text)
        self.assertIn("App: %s %s" % (wh.APP_NAME, wh.APP_VERSION),
                      text)
        self.assertIn("RuntimeError: kaput", text)
        self.assertIn("Traceback (most recent call last)", text)
        self.assertIn("first line", text)
        self.assertIn("second line", text)

    def test_report_tail_is_only_the_tail(self):
        log = wh.RunLog()
        for i in range(120):
            log("L%d" % i)
        t, v, tb = self._raise(ValueError("x"))
        path = wh.write_crash_report(t, v, tb, dirs=[self.dir],
                                     log=log)
        text = wh.read_crash_report(path)
        self.assertIn("Last %d lines" % wh.CRASH_TAIL_LINES, text)
        self.assertIn("L119", text)
        self.assertIn("L40", text)
        self.assertNotIn("L39", text)

    def test_list_reports_newest_first_and_filtered(self):
        older = os.path.join(
            self.dir, wh.crash_report_name(
                wh.datetime.datetime(2026, 10, 16, 8, 0, 0)))
        newer = os.path.join(
            self.dir, wh.crash_report_name(
                wh.datetime.datetime(2026, 10, 17, 8, 0, 0)))
        for p in (older, newer):
            with open(p, "w", encoding="utf-8") as fh:
                fh.write("report")
        os.utime(older, (1000, 1000))
        os.utime(newer, (2000, 2000))
        for decoy in ("notes.txt",
                      "WindowsHealthRepair-crash-bad.txt"):
            with open(os.path.join(self.dir, decoy), "w") as fh:
                fh.write("nope")
        reports = wh.list_crash_reports(dirs=[self.dir])
        self.assertEqual([r["path"] for r in reports],
                         [newer, older])

    def test_list_dedupes_same_name_across_dirs(self):
        other = os.path.join(self.dir, "elsewhere")
        os.makedirs(other)
        name = wh.crash_report_name(
            wh.datetime.datetime(2026, 10, 17, 8, 0, 0))
        for folder in (self.dir, other):
            with open(os.path.join(folder, name), "w") as fh:
                fh.write("report")
        reports = wh.list_crash_reports(dirs=[self.dir, other])
        self.assertEqual(len(reports), 1)

    def test_delete_report(self):
        path = os.path.join(
            self.dir, wh.crash_report_name(
                wh.datetime.datetime(2026, 10, 17, 8, 0, 0)))
        with open(path, "w") as fh:
            fh.write("report")
        self.assertTrue(wh.delete_crash_report(path))
        self.assertFalse(os.path.exists(path))
        decoy = os.path.join(self.dir, "important.txt")
        with open(decoy, "w") as fh:
            fh.write("keep me")
        self.assertFalse(wh.delete_crash_report(decoy))
        self.assertTrue(os.path.exists(decoy))
        self.assertFalse(wh.delete_crash_report(path))

    def test_handle_unhandled_exception(self):
        old_guard = dict(wh._CRASH_GUARD)
        try:
            wh._CRASH_GUARD.update({"last": 0.0, "count": 0})
            with mock.patch.object(
                    wh, "crash_report_dirs",
                    lambda: [self.dir]):
                self.assertIsNone(wh.handle_unhandled_exception(
                    KeyboardInterrupt, KeyboardInterrupt(), None))
                t, v, tb = self._raise(ValueError("handled"))
                path = wh.handle_unhandled_exception(t, v, tb)
                self.assertIsNotNone(path)
                self.assertTrue(os.path.exists(path))
                # Rate guard: an immediate second crash is skipped.
                self.assertIsNone(
                    wh.handle_unhandled_exception(t, v, tb))
        finally:
            wh._CRASH_GUARD.update(old_guard)

    def test_hooks_install_is_idempotent(self):
        old_sys = sys.excepthook
        old_thread = threading.excepthook
        try:
            wh.install_crash_hooks()
            self.assertIs(sys.excepthook, wh._sys_excepthook)
            self.assertIs(threading.excepthook,
                          wh._thread_excepthook)
            prev = wh._PREV_THREAD_HOOK
            wh.install_crash_hooks()
            self.assertIs(wh._PREV_THREAD_HOOK, prev)
        finally:
            sys.excepthook = old_sys
            threading.excepthook = old_thread

    def test_gui_contract_crash_reports(self):
        src = open(os.path.join(os.path.dirname(__file__), "..",
                                "windows_health.py"),
                   encoding="utf-8").read()
        self.assertIn("Crash & error reports", src)
        self.assertIn("report_callback_exception", src)
        self.assertIn("install_crash_hooks()", src)


class TestSelfRepair(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = self._tmp.name

    def _store(self, name="store.json"):
        return os.path.join(self.dir, name)

    def _events(self):
        return wh.load_repair_events(
            path=os.path.join(self.dir, wh.REPAIR_EVENTS_FILE))

    def test_save_rotates_previous_good_copy_to_bak(self):
        path = self._store()
        self.assertTrue(wh.save_json_store(path, {"a": 1}))
        self.assertTrue(wh.save_json_store(path, {"a": 2}))
        self.assertEqual(wh._read_json_file(path)[0], {"a": 2})
        self.assertEqual(wh._read_json_file(path + ".bak")[0],
                         {"a": 1})

    def test_missing_file_is_not_corruption(self):
        path = self._store()
        data = wh.load_json_store(path, wh._salvage_auto_check,
                                  lambda: {"mode": "monthly"},
                                  "test store")
        self.assertEqual(data, {"mode": "monthly"})
        self.assertFalse(os.path.exists(path))
        self.assertEqual(self._events(), [])

    def test_corrupt_store_restored_from_bak(self):
        path = self._store()
        with open(path, "w") as fh:
            fh.write("{corrupt")
        wh._write_json_file(path + ".bak", {"mode": "weekly"})
        data = wh.load_json_store(path, wh._salvage_auto_check,
                                  lambda: {"mode": "monthly"},
                                  "test store")
        self.assertEqual(data, {"mode": "weekly"})
        # Verified by re-read: the store itself is good again.
        self.assertEqual(wh._read_json_file(path)[0],
                         {"mode": "weekly"})
        events = self._events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["result"], "repaired")
        self.assertIn("last good copy", events[0]["detail"])

    def test_corrupt_store_no_bak_rebuilds_and_quarantines(self):
        path = self._store()
        with open(path, "w") as fh:
            fh.write("junk!")
        data = wh.load_json_store(path, wh._salvage_auto_check,
                                  lambda: {"mode": "monthly"},
                                  "test store")
        self.assertEqual(data, {"mode": "monthly"})
        quarantined = [n for n in os.listdir(self.dir)
                       if n.startswith("store.json.corrupt-")]
        self.assertEqual(len(quarantined), 1)
        with open(os.path.join(self.dir, quarantined[0])) as fh:
            self.assertEqual(fh.read(), "junk!")
        self.assertEqual(wh._read_json_file(path)[0],
                         {"mode": "monthly"})
        self.assertEqual(self._events()[0]["result"], "repaired")

    def test_salvage_keeps_good_entries(self):
        path = self._store()
        wh._write_json_file(path, {"scans": [
            {"when": "t1", "data": {"x": 1}},
            {"nope": True},
            "junk",
            {"when": "t2", "data": {}}]})
        data = wh.load_json_store(path, wh._salvage_preventative,
                                  lambda: {"scans": []},
                                  "test store")
        self.assertEqual(data, {"scans": [
            {"when": "t1", "data": {"x": 1}},
            {"when": "t2", "data": {}}]})
        self.assertEqual(self._events()[0]["result"], "repaired")

    def test_update_state_salvage_drops_unknown_and_bad_keys(self):
        data = wh._salvage_update_state(
            {"last_check": "2026-10-17T00:00:00", "evil": 1,
             "dismissed_version": 5})
        self.assertEqual(data,
                         {"last_check": "2026-10-17T00:00:00"})
        self.assertIsNone(wh._salvage_update_state([1, 2, 3]))

    def test_valid_store_loads_quietly(self):
        path = self._store()
        wh._write_json_file(path, {"mode": "weekly"})
        data = wh.load_json_store(path, wh._salvage_auto_check,
                                  lambda: {"mode": "monthly"},
                                  "test store")
        self.assertEqual(data, {"mode": "weekly"})
        self.assertEqual(self._events(), [])

    def test_repair_failed_is_reported_not_raised(self):
        blocker = os.path.join(self.dir, "blocker")
        with open(blocker, "w") as fh:
            fh.write("a file, not a folder")
        path = os.path.join(blocker, "store.json")
        data = wh.load_json_store(path, wh._salvage_auto_check,
                                  lambda: {"mode": "monthly"},
                                  "test store")
        self.assertEqual(data, {"mode": "monthly"})

    def test_cleanup_stale_state(self):
        upd = os.path.join(self.dir, wh.UPDATE_DIR_NAME)
        os.makedirs(upd)
        with open(os.path.join(upd, "partial.exe"), "wb") as fh:
            fh.write(b"x")
        with open(os.path.join(self.dir, "stray.tmp"), "w") as fh:
            fh.write("x")
        keep = os.path.join(self.dir, "keep.txt")
        with open(keep, "w") as fh:
            fh.write("x")
        cleared = wh.cleanup_stale_state(base=self.dir)
        self.assertEqual(len(cleared), 2)
        self.assertFalse(os.listdir(upd))
        self.assertTrue(os.path.exists(keep))
        self.assertEqual(wh.cleanup_stale_state(base=self.dir),
                         [])
        events = self._events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["what"], "startup cleanup")
        self.assertEqual(events[0]["result"], "repaired")

    def test_discard_download(self):
        path = os.path.join(self.dir, "bad.exe")
        with open(path, "wb") as fh:
            fh.write(b"x")
        self.assertTrue(wh.discard_download(path))
        self.assertFalse(os.path.exists(path))
        self.assertTrue(wh.discard_download(path))
        self.assertFalse(wh.discard_download(self.dir))

    def test_repair_events_round_trip_and_cap(self):
        path = os.path.join(self.dir, wh.REPAIR_EVENTS_FILE)
        for i in range(wh.REPAIR_EVENTS_MAX + 5):
            wh.record_repair_event("thing %d" % i, "repaired",
                                   path=path)
        events = wh.load_repair_events(path=path)
        self.assertEqual(len(events), wh.REPAIR_EVENTS_MAX)
        self.assertEqual(events[-1]["what"],
                         "thing %d" % (wh.REPAIR_EVENTS_MAX + 4))

    def test_gui_contract_self_repair(self):
        src = open(os.path.join(os.path.dirname(__file__), "..",
                                "windows_health.py"),
                   encoding="utf-8").read()
        self.assertIn("cleanup_stale_state()", src)
        self.assertIn("Recent self-repairs", src)


# ----------------------------------------------------------------------
# v1.2.1 — scan-hang regression (docs/AUDITS.md, 2026-10-20 addendum).
# The v1.1.1/v1.2.0 GUI died on the scan's FIRST progress callback: a
# nested def named `progress` shadowed the progressbar widget and its
# body subscripted the function object (TypeError), killing the worker
# thread before any check ran.
# ----------------------------------------------------------------------

class TestScanHangRegression(unittest.TestCase):
    def setUp(self):
        self._scanners = wh.SCANNERS
        self.addCleanup(setattr, wh, "SCANNERS", self._scanners)
        self.lines = []
        self.log = lambda msg: self.lines.append(msg)

    def _patch(self, scanners):
        wh.SCANNERS = scanners

    def test_run_scan_streams_each_check_as_it_finishes(self):
        def one(log):
            return [wh.Finding("safety", "a", severity="info"),
                    wh.Finding("safety", "b", severity="info")]

        def two(log):
            return [wh.Finding("disk", "c", severity="info")]
        self._patch([("safety", one), ("disk", two)])
        batches, prog = [], []
        out = wh.run_scan(self.log,
                          progress=lambda c, i, t: prog.append((c, i, t)),
                          on_findings=batches.append)
        self.assertEqual([len(b) for b in batches], [2, 1])
        self.assertEqual([f.title for b in batches for f in b],
                         ["a", "b", "c"])
        self.assertEqual([f.title for f in out], ["a", "b", "c"])
        self.assertEqual(prog, [("safety", 0, 2), ("disk", 1, 2)])

    def test_run_scan_streams_failure_finding_for_raising_check(self):
        def boom(log):
            raise RuntimeError("wedged")

        def fine(log):
            return [wh.Finding("disk", "ok", severity="info")]
        self._patch([("safety", boom), ("disk", fine)])
        batches = []
        out = wh.run_scan(self.log, on_findings=batches.append)
        self.assertEqual(len(batches), 2)
        self.assertIn("failed to run", batches[0][0].title)
        self.assertEqual(batches[1][0].title, "ok")
        self.assertEqual(len(out), 2)

    def test_progress_runs_before_each_scanner_even_on_failure(self):
        def boom(log):
            raise RuntimeError("wedged")
        self._patch([("safety", boom), ("disk", lambda log: [])])
        prog = []
        wh.run_scan(self.log, progress=lambda c, i, t: prog.append(c))
        self.assertEqual(prog, ["safety", "disk"])

    def test_run_scan_logs_check_start_and_finish_lines(self):
        self._patch([("safety", lambda log: [])])
        wh.run_scan(self.log)
        self.assertTrue(any(l.startswith("Check 1/1:") for l in self.lines))
        self.assertTrue(any("finished in" in l and "finding(s)" in l
                            for l in self.lines))

    def test_scan_status_text_names_check_and_elapsed(self):
        base = wh.scan_status_text("sysfiles", 1, 12)
        self.assertEqual(base, "Scanning: System files (SFC / DISM) (2/12)")
        slow = wh.scan_status_text("sysfiles", 1, 12, elapsed=65)
        self.assertIn("1 min 05s so far", slow)
        self.assertNotIn("still running", slow)
        stuck = wh.scan_status_text("sysfiles", 1, 12, elapsed=600)
        self.assertIn("still running", stuck)
        self.assertIn("time limit", stuck)

    def test_human_duration(self):
        self.assertEqual(wh.human_duration(45), "45s")
        self.assertEqual(wh.human_duration(60), "1 min")
        self.assertEqual(wh.human_duration(65), "1 min 05s")
        self.assertEqual(wh.human_duration(3600), "1h 00min")

    def test_no_shadowed_progress_callback_remains(self):
        src = open(os.path.join(os.path.dirname(__file__), "..",
                                "windows_health.py"),
                   encoding="utf-8").read()
        # The download progress(done, total) is the only def progress
        # left, and it never subscripts itself.
        self.assertEqual(src.count("def progress("), 1)
        self.assertNotIn("def progress(cat", src)
        self.assertNotIn("def progress(i, total, label)", src)
        # The scan/fix callbacks are renamed and marshaled.
        self.assertIn("def scan_progress(cat, i, total)", src)
        self.assertIn("def fix_progress(i, total, label)", src)
        self.assertIn("on_findings=stream", src)
        self.assertIn('state["scan_token"]', src)


if __name__ == "__main__":
    unittest.main()
