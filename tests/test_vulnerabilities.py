"""A missing/old/filtered scan must not become a clean selected-image result."""
import datetime as dt
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import vulnerabilities as scan

IMAGE = "ghcr.io/example/application@sha256:" + "a" * 64
LIDERSEA = "github.com/snaraj/lidersea.com"
NOW = dt.datetime(2026, 11, 1, tzinfo=dt.timezone.utc)


def clean():
    return {"SchemaVersion": 2, "ArtifactType": "container_image", "ArtifactName": IMAGE,
            "Trivy": {"Version": scan.VERSION},
            "Metadata": {"ImageConfig": {"architecture": "arm64", "os": "linux"},
                         "OS": {"Family": "debian", "Name": "13"}},
            "Results": [{"Class": "os-pkgs", "Type": "debian", "Packages": [{"Name": "ca-certificates", "Version": "1"}]}]}


class VulnerabilityTests(unittest.TestCase):
    def test_clean_inventory_and_fresh_database(self):
        self.assertEqual(scan.findings(clean(), IMAGE), [])
        scan.fresh_database({"Version": 2, "UpdatedAt": NOW.isoformat()}, NOW)

    def test_all_severities_and_unfixed_findings_remain_visible(self):
        for severity in ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
            report = clean()
            report["Results"][0]["Vulnerabilities"] = [{"VulnerabilityID": "CVE-2026-12345",
                "PkgName": "example", "InstalledVersion": "1", "Severity": severity}]
            rows = scan.findings(report, IMAGE)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["Severity"], severity)
            self.assertEqual(rows[0]["FixedVersion"], "")

    def test_absent_inventory_wrong_image_platform_and_version_refuse(self):
        for field, value in (("Results", []), ("Results", None), ("ArtifactName", IMAGE + "0"),
                             ("ArtifactType", "filesystem"), ("SchemaVersion", 1),
                             ("Trivy", {"Version": "0.1.0"})):
            report = clean(); report[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                scan.findings(report, IMAGE)
        for architecture in ("amd64", "", None):
            report = clean(); report["Metadata"]["ImageConfig"]["architecture"] = architecture
            with self.assertRaises(ValueError):
                scan.findings(report, IMAGE)
        for packages in (None, [], [{}], [{"Name": "example"}], "not-an-inventory"):
            report = clean(); report["Results"][0]["Packages"] = packages
            with self.assertRaises(ValueError):
                scan.findings(report, IMAGE)
        report = clean(); report["Metadata"]["OS"]["EOSL"] = True
        with self.assertRaises(ValueError):
            scan.findings(report, IMAGE)

    def test_stale_future_naive_and_wrong_schema_databases_refuse(self):
        for value in ((NOW - dt.timedelta(hours=25)).isoformat(),
                      (NOW + dt.timedelta(minutes=6)).isoformat(),
                      NOW.replace(tzinfo=None).isoformat(), "invalid"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                scan.fresh_database({"Version": 2, "UpdatedAt": value}, NOW)
        with self.assertRaises(ValueError):
            scan.fresh_database({"Version": 1, "UpdatedAt": NOW.isoformat()}, NOW)

    def test_partial_os_and_go_analysis_refuses(self):
        for os_data in ({}, {"Family": "unknown", "Name": ""}):
            report = clean(); report["Metadata"]["OS"] = os_data
            with self.assertRaises(ValueError):
                scan.findings(report, IMAGE)
        report = clean(); del report["Metadata"]["OS"]
        with self.assertRaises(ValueError):
            scan.findings(report, IMAGE)
        with self.assertRaises(ValueError):
            scan.findings(clean(), IMAGE, go_module=LIDERSEA)
        report = clean()
        report["Results"].append({"Class": "lang-pkgs", "Type": "gobinary",
                                  "Packages": [{"Name": "stdlib", "Version": "v1.26.10"},
                                               {"Name": "github.com/snaraj/lidersea.com", "Relationship": "root"}]})
        self.assertEqual(scan.findings(report, IMAGE, go_module=LIDERSEA), [])
        stdlib = report["Results"][-1]["Packages"].pop(0)
        with self.assertRaises(ValueError):
            scan.findings(report, IMAGE, go_module=LIDERSEA)
        report["Results"][-1]["Packages"].insert(0, stdlib)
        report["Results"][-1]["Packages"].append({"Name": "unversioned-third-party", "Relationship": "root"})
        with self.assertRaises(ValueError):
            scan.findings(report, IMAGE, go_module=LIDERSEA)
        report["Results"][-1]["Packages"].pop()
        report["Results"].pop(0)
        with self.assertRaises(ValueError):
            scan.findings(report, IMAGE, go_module=LIDERSEA)

    def test_each_go_application_admits_only_its_own_unversioned_root(self):
        """Review finding on #87: the selected hospedajedonlolo.com image's real
        report names its own main module as an unversioned root. That report
        parses; the same module in any sibling's report is refused."""
        modules = scan.GO_APPLICATIONS
        self.assertEqual(modules["hospedajedonlolo-com"], "github.com/snaraj/hospedajedonlolo.com")
        for slug, own in modules.items():
            for module in modules.values():
                report = clean()
                report["Results"].append({"Class": "lang-pkgs", "Type": "gobinary", "Packages": [
                    {"Name": "stdlib", "Version": "v1.26.10", "Relationship": "direct"},
                    {"Name": module, "Relationship": "root"}]})
                with self.subTest(slug=slug, module=module):
                    if module == own:
                        self.assertEqual(scan.findings(report, IMAGE, own), [])
                    else:
                        with self.assertRaises(ValueError):
                            scan.findings(report, IMAGE, own)
        report = clean()
        report["Results"].append({"Class": "lang-pkgs", "Type": "gobinary", "Packages": [
            {"Name": "stdlib", "Version": "v1.26.10"},
            {"Name": modules["hospedajedonlolo-com"], "Relationship": "direct"}]})
        with self.assertRaises(ValueError):
            scan.findings(report, IMAGE, modules["hospedajedonlolo-com"])

    def test_failed_provenance_prevents_scanner_execution(self):
        with patch.object(scan.validate, "verify", side_effect=ValueError("bad signature")), \
                patch.object(scan.subprocess, "run") as command:
            with self.assertRaises(ValueError):
                scan.run()
            command.assert_not_called()

    def test_changed_application_set_requires_reviewed_analysis_expectations(self):
        with patch.object(scan.validate, "verify"), \
                patch.object(scan.validate, "check", return_value=({}, {"records": {}})), \
                patch.object(scan.subprocess, "run") as command:
            with self.assertRaises(ValueError):
                scan.run()
            command.assert_not_called()

    def test_real_orchestration_keeps_scan_errors_and_findings_failing(self):
        record = {"workloadImage": IMAGE.split("@")[0] + ":v1.0.0@sha256:" + "b" * 64,
                  "arm64Digest": IMAGE.split("@")[1]}
        for mode, expected in (("clean", 0), ("finding", 1), ("error", None),
                               ("stale", None), ("nonzero-with-report", None), ("missing-go", None)):
            observed = []
            def command(args, **kwargs):
                observed.append(args)
                if "--version" in args:
                    return subprocess.CompletedProcess(args, 0, json.dumps({"Version": scan.VERSION}))
                cache = Path(args[args.index("--cache-dir") + 1])
                if "--download-db-only" in args:
                    (cache / "db").mkdir(parents=True)
                    stamp = dt.datetime.now(dt.timezone.utc)
                    if mode == "stale":
                        stamp -= dt.timedelta(hours=25)
                    (cache / "db/metadata.json").write_text(json.dumps({"Version": 2,
                        "UpdatedAt": stamp.isoformat()}))
                else:
                    self.assertNotIn("TRIVY_IGNORE_UNFIXED", kwargs["env"])
                    self.assertIn("--list-all-pkgs", args)
                    self.assertIn("--ignore-unfixed=false", args)
                    self.assertEqual(args[args.index("--platform") + 1], "linux/arm64")
                    self.assertIn("UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL", args)
                    self.assertEqual(args[-1], IMAGE)
                    self.assertEqual(Path(args[args.index("--ignorefile") + 1]).read_text(), "")
                    if mode == "error":
                        raise subprocess.CalledProcessError(1, args)
                    report = clean()
                    slug = Path(args[args.index("--output") + 1]).stem
                    if slug in scan.GO_APPLICATIONS and mode != "missing-go":
                        report["Results"].append({"Class": "lang-pkgs", "Type": "gobinary",
                            "Packages": [{"Name": "stdlib", "Version": "v1.26.10"},
                                         {"Name": scan.GO_APPLICATIONS[slug], "Relationship": "root"}]})
                    if mode == "finding":
                        report["Results"][0]["Vulnerabilities"] = [{"VulnerabilityID": "CVE-2026-12345",
                            "PkgName": "example", "InstalledVersion": "1", "Severity": "LOW"}]
                    Path(args[args.index("--output") + 1]).write_text(json.dumps(report))
                    if mode == "nonzero-with-report":
                        if kwargs.get("check"):
                            raise subprocess.CalledProcessError(1, args)
                        return subprocess.CompletedProcess(args, 1, "")
                return subprocess.CompletedProcess(args, 0, "")
            with patch.object(scan.validate, "verify"), \
                    patch.object(scan.validate, "check", return_value=({}, {"records":
                        {slug: record for slug in ("naranjo-online", "lidersea-com", "obsync", "hospedajedonlolo-com")}})), \
                    patch.dict(scan.os.environ, {"TRIVY_IGNORE_UNFIXED": "true"}), \
                    patch.object(scan.subprocess, "run", side_effect=command):
                if expected is None:
                    with self.assertRaises((subprocess.CalledProcessError, ValueError)):
                        scan.run()
                else:
                    self.assertEqual(scan.run(), expected)
            self.assertEqual(len(observed), 2 if mode == "stale" else (6 if expected is not None else 3))


if __name__ == "__main__":
    unittest.main()
