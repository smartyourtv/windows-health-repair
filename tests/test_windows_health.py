"""Unit tests for Windows Health & Repair logic.

Everything here tests pure logic against recorded fixtures — the
Windows-only command paths are never exercised on this machine and
must present as honest 'needs Windows' states instead.
"""
import json
import os
import sys
import unittest

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


if __name__ == "__main__":
    unittest.main()
