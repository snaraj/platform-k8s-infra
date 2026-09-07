"""Guard unattended verification authority and seven-day update coverage.

These two small definitions use JSON, a YAML subset, so the standard library
can inspect their structure without another dependency or a custom YAML parser.
Workflow syntax also passes actionlint before publication.
"""
import json
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def definition(path):
    return json.loads((ROOT / path).read_text())


class UpkeepTests(unittest.TestCase):
    def setUp(self):
        self.workflow = definition(".github/workflows/selected-artifacts.yml")
        self.job = self.workflow["jobs"]["verify-selected-artifacts"]

    def assert_every_day(self, value):
        fields = value.split()
        self.assertEqual(len(fields), 5)
        self.assertTrue(fields[0].isdigit() and 0 <= int(fields[0]) < 60)
        self.assertTrue(fields[1].isdigit() and 0 <= int(fields[1]) < 24)
        self.assertEqual(fields[2:], ["*", "*", "*"])

    def test_dependabot_covers_actions_every_day_and_groups_each_codeql_update_kind(self):
        config = definition(".github/dependabot.yml")
        self.assertEqual(set(config), {"version", "updates"})
        self.assertEqual(config["version"], 2)
        self.assertEqual(len(config["updates"]), 1)
        entry = config["updates"][0]
        self.assertEqual(set(entry), {"package-ecosystem", "directory", "schedule",
                                     "open-pull-requests-limit", "groups"})
        self.assertEqual((entry["package-ecosystem"], entry["directory"]), ("github-actions", "/"))
        schedule = entry["schedule"]
        self.assertEqual(set(schedule), {"interval", "cronjob", "timezone"})
        self.assertEqual((schedule["interval"], schedule["timezone"]), ("cron", "UTC"))
        self.assert_every_day(schedule["cronjob"])
        self.assertGreater(entry["open-pull-requests-limit"], 0)
        groups = list(entry["groups"].values())
        self.assertEqual(len(groups), 2)
        self.assertEqual({g["applies-to"] for g in groups}, {"version-updates", "security-updates"})
        for group in groups:
            self.assertEqual(set(group), {"patterns", "applies-to"})
            self.assertEqual(group["patterns"], ["github/codeql-action*"])

    def test_artifact_verification_has_daily_and_manual_entry_points(self):
        self.assertEqual(set(self.workflow["on"]), {"schedule", "workflow_dispatch"})
        self.assertEqual(self.workflow["on"]["workflow_dispatch"], {})
        schedules = self.workflow["on"]["schedule"]
        self.assertEqual(len(schedules), 1)
        self.assertEqual(set(schedules[0]), {"cron"})
        self.assert_every_day(schedules[0]["cron"])
        self.assertEqual(set(self.workflow["jobs"]), {"verify-selected-artifacts"})

    def test_verification_is_bounded_read_only_and_cannot_hide_a_failure(self):
        self.assertEqual(set(self.workflow), {"name", "on", "permissions", "concurrency", "jobs"})
        self.assertEqual(set(self.job), {"runs-on", "timeout-minutes", "permissions", "env", "steps"})
        self.assertEqual(self.workflow["permissions"], {})
        self.assertEqual(self.job["permissions"], {"contents": "read"})
        self.assertEqual(self.job["runs-on"], "ubuntu-24.04")
        self.assertTrue(0 < self.job["timeout-minutes"] <= 15)
        self.assertIs(self.workflow["concurrency"]["cancel-in-progress"], False)
        text = json.dumps(self.workflow)
        for forbidden in ("continue-on-error", '"if"', "secrets.", "write", "always()"):
            self.assertNotIn(forbidden, text)
        self.assertEqual(self.job["env"], {"PYTHONDONTWRITEBYTECODE": "1"})

    def test_only_main_can_reach_the_pinned_checkout_and_existing_verifier(self):
        steps = self.job["steps"]
        self.assertEqual(len(steps), 4)
        main_guard, checkout, tools, verify = steps
        self.assertEqual(set(main_guard), {"name", "run"})
        for ref, expected in (("refs/heads/main", 0), ("refs/heads/candidate", 1), ("", 1)):
            result = subprocess.run(["/bin/sh", "-eu", "-c", main_guard["run"]],
                                    env={"GITHUB_REF": ref}, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, expected)
        self.assertEqual(set(checkout), {"uses", "with"})
        existing = (ROOT / ".github/workflows/checks.yml").read_text()
        existing_pin = re.search(r"uses: (actions/checkout@[0-9a-f]{40})", existing).group(1)
        self.assertEqual(checkout["uses"], existing_pin)
        self.assertEqual(checkout["with"], {"ref": "${{ github.sha }}", "persist-credentials": False})
        self.assertEqual(set(tools), {"name", "run"})
        self.assertEqual(tools["run"], "bash scripts/ci/install-tools.sh verify")
        self.assertEqual(set(verify), {"name", "env", "run"})
        self.assertEqual(verify["env"], {"GH_TOKEN": "${{ github.token }}"})
        self.assertEqual(verify["run"], "make verify")
        makefile = (ROOT / "Makefile").read_text()
        self.assertEqual(re.search(r"^verify:\n(\t[^\n]+)\n", makefile, re.MULTILINE).group(1),
                         "\t$(PYTHON) -I -B scripts/validate.py verify")


if __name__ == "__main__":
    unittest.main()
