"""Bound actual child processes without signalling a reaped session leader."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("artifacts_process", Path(__file__).resolve().parents[1] / "scripts/artifacts.py")
artifacts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(artifacts)


class ProcessTests(unittest.TestCase):
    def test_normal_failure_and_output_bounds(self):
        self.assertEqual(artifacts.run_command([sys.executable, "-c", "print('ok')"]), "ok\n")
        with self.assertRaisesRegex(artifacts.Refusal, "failed"):
            artifacts.run_command([sys.executable, "-c", "raise SystemExit(4)"])
        with self.assertRaises(artifacts.Refusal):
            artifacts.run_command([sys.executable, "-c", "import os; os.write(1, b'x' * 4000000); os.write(1, b'x')"])

    def test_group_is_signalled_before_any_wait(self):
        events = []
        real_kill, real_wait = os.killpg, artifacts.subprocess.Popen.wait
        def kill(pid, sig):
            events.append("kill")
            return real_kill(pid, sig)
        def wait(process, *args, **kwargs):
            events.append("wait")
            return real_wait(process, *args, **kwargs)
        with patch.object(artifacts.os, "killpg", kill), patch.object(artifacts.subprocess.Popen, "wait", wait):
            artifacts.run_command([sys.executable, "-c", "pass"])
        self.assertEqual(events[:2], ["kill", "wait"])

    def test_command_timeout_and_inherited_descendant_cleanup(self):
        for finish in (False, True):
            with self.subTest(normal_exit=finish), tempfile.TemporaryDirectory() as directory:
                marker = Path(directory) / "late-marker"
                descendant = f"import pathlib,time; time.sleep(0.8); pathlib.Path({str(marker)!r}).touch()"
                command = f"import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',{descendant!r}]); "
                command += "pass" if finish else "time.sleep(5)"
                if finish:
                    artifacts.run_command([sys.executable, "-c", command])
                else:
                    with self.assertRaisesRegex(artifacts.Refusal, "time bound"):
                        artifacts.run_command([sys.executable, "-c", command], timeout=0.2)
                time.sleep(1)
                self.assertFalse(marker.exists())

    def test_explicit_command_environment_excludes_ambient_overrides(self):
        with patch.dict(os.environ, {"APPLICATION_UNEXPECTED": "ambient"}):
            output = artifacts.run_command(
                [sys.executable, "-c", "import os; print(os.getenv('APPLICATION_UNEXPECTED', 'absent')); print(os.getenv('APPLICATION_EXPECTED'))"],
                env={"PATH": os.environ["PATH"], "APPLICATION_EXPECTED": "explicit"})
        self.assertEqual(output, "absent\nexplicit\n")
        with self.assertRaisesRegex(artifacts.Refusal, "outside its bound"):
            artifacts.run_command([sys.executable, "-c", "pass"], timeout=121)

    def test_registry_configuration_is_always_anonymous(self):
        env = artifacts.pinned_environment({"DOCKER_CONFIG": "/invalid/ambient"})
        self.assertNotEqual(env["DOCKER_CONFIG"], "/invalid/ambient")
        self.assertEqual((Path(env["DOCKER_CONFIG"]) / "config.json").read_text(), "{}\n")
        self.assertEqual(env["GH_PROMPT_DISABLED"], "1")


if __name__ == "__main__":
    unittest.main()
