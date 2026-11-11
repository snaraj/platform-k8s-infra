"""Exercise real Git history, including material removed before the tip."""
import ast
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("publication", Path(__file__).resolve().parents[1] / "scripts/publication.py")
publication = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publication)


class Repository(unittest.TestCase):
    """A disposable repository; holds no tests of its own."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.git("init", "-b", "main")
        self.base = self.commit("initial")

    def git(self, *args):
        env = dict(os.environ, GIT_AUTHOR_NAME="Example", GIT_AUTHOR_EMAIL="author@example.invalid",
                   GIT_COMMITTER_NAME="Example", GIT_COMMITTER_EMAIL="author@example.invalid")
        return subprocess.check_output(["git", "-C", str(self.root), "-c", "commit.gpgSign=false",
                                       "-c", "core.hooksPath=/dev/null", *args], env=env, stderr=subprocess.DEVNULL).decode().strip()

    def commit(self, message):
        self.git("add", "--all")
        self.git("commit", "--allow-empty", "-m", message)
        return self.git("rev-parse", "HEAD")


class PublicationTests(Repository):
    def test_valid_closed_tree_and_linear_range_pass(self):
        (self.root / "README.md").write_text("Public configuration.\n")
        head = self.commit("add public configuration")
        publication.history(self.base, head, self.root)
        publication.working_tree(self.root)

    def test_dependabot_addition_preserves_the_closed_configuration_path(self):
        publication.path_allowed(".github/dependabot.yml")
        for path in (".github/dependabot.yaml", ".github/dependabot.yml.bak",
                     ".github/renovate.json", ".github/other.yml"):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "unexpected publication"):
                publication.path_allowed(path)

    def test_deleted_intermediate_private_content_cannot_escape(self):
        path = self.root / "README.md"
        path.write_text("workstation=" + "/" + "Users/" + "example/private\n")
        self.commit("add configuration")
        path.write_text("Public configuration.\n")
        head = self.commit("remove local reference")
        publication.snapshot(head, self.root)
        with self.assertRaisesRegex(ValueError, "workstation"):
            publication.history(self.base, head, self.root)

    # An address in RFC 2544's benchmarking range: reserved for tests, never a
    # LAN or public host, and outside the documentation allowlist, so the
    # scanner must still refuse it. Assembled so this file stays publishable.
    BENCHMARK_ADDRESS = "198.18." + "0.1"

    def test_private_commit_metadata_is_scanned(self):
        head = self.commit("device=" + self.BENCHMARK_ADDRESS)
        with self.assertRaisesRegex(ValueError, "network identifier"):
            publication.history(self.base, head, self.root)

    def test_inventory_identity_and_nontext_content_are_rejected(self):
        identifiers = ("a1b2c3d4" + "-abcd-1234-abcd-" + "123456789abc",
                       "ab12cd34" * 4, ":".join(["a1", "b2", "c3", "d4", "e5", "f6"]),
                       "ssh-" + "ed25519 " + "A" * 64, "private@" + "example.com", "opaque\x01")
        for value in identifiers:
            with self.subTest(kind=value[:5]), self.assertRaises(ValueError):
                publication.content(value.encode())

    def test_replace_refs_cannot_hide_an_intermediate_tree(self):
        path = self.root / "README.md"
        path.write_text("device=" + self.BENCHMARK_ADDRESS)
        unsafe = self.commit("intermediate")
        path.write_text("Public configuration.\n")
        head = self.commit("clean candidate")
        self.git("replace", unsafe, head)
        with self.assertRaisesRegex(ValueError, "network identifier"):
            publication.history(self.base, head, self.root)

    def test_links_opaque_files_and_untracked_files_are_rejected(self):
        path = self.root / "README.md"
        path.symlink_to("missing")
        head = self.commit("add invalid link")
        with self.assertRaisesRegex(ValueError, "non-ordinary"):
            publication.snapshot(head, self.root)
        path.unlink()
        path.write_bytes(b"opaque\0binary")
        with self.assertRaisesRegex(ValueError, "opaque"):
            publication.working_tree(self.root)
        path.write_text("Public configuration.\n")
        (self.root / "unexpected.txt").write_text("unexpected")
        with self.assertRaisesRegex(ValueError, "unexpected publication"):
            publication.working_tree(self.root)

    def test_noncommit_unrelated_and_merge_ranges_are_rejected(self):
        first = self.commit("first branch")
        with self.assertRaises(ValueError):
            publication.history(self.base, "main", self.root)
        self.git("checkout", "-b", "other", self.base)
        other = self.commit("second branch")
        with self.assertRaises(subprocess.CalledProcessError):
            publication.history(first, other, self.root)
        self.git("merge", "--no-ff", "main", "-m", "join branches")
        merged = self.git("rev-parse", "HEAD")
        with self.assertRaisesRegex(ValueError, "not linear"):
            publication.history(self.base, merged, self.root)

    def test_ci_binds_merge_checkout_to_current_base_and_event_head(self):
        current_base = self.commit("base advancement")
        self.git("checkout", "-b", "task", current_base)
        candidate = self.commit("candidate")
        self.git("checkout", "main")
        self.git("merge", "--no-ff", "task", "-m", "candidate merge")
        merge = self.git("rev-parse", "HEAD")
        self.git("update-ref", "refs/remotes/origin/main", current_base)
        environment = {"GITHUB_REPOSITORY": publication.REPOSITORY, "GITHUB_REPOSITORY_ID": publication.REPOSITORY_ID, "GITHUB_SHA": merge,
                       "GITHUB_EVENT_NAME": "pull_request", "GITHUB_REF": "refs/pull/1/merge",
                       "PR_NUMBER": "1", "PR_HEAD_SHA": candidate, "PR_BASE_SHA": self.base, "PR_BASE_REF": "main"}
        real_git = publication.git
        with patch.object(publication, "git", lambda *args: real_git(*args, root=self.root)):
            with patch.dict(os.environ, environment, clear=True):
                self.assertEqual(publication.ci_range(), (current_base, candidate))
            for key, value in (("GITHUB_REPOSITORY", "foreign/repository"), ("GITHUB_REPOSITORY_ID", "1"), ("GITHUB_SHA", candidate),
                               ("GITHUB_REF", "refs/heads/main"), ("PR_HEAD_SHA", self.base),
                               ("PR_BASE_REF", "other"), ("PR_BASE_SHA", candidate)):
                with self.subTest(changed=key), patch.dict(os.environ, dict(environment, **{key: value}), clear=True):
                    with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                        publication.ci_range()

    def test_first_main_push_is_not_a_normal_publication_range(self):
        # The owner seeds an empty, separately scanned root before workflows
        # enter through a PR; no all-zero bypass belongs in the normal gate.
        head = self.commit("candidate")
        with self.assertRaises(subprocess.CalledProcessError):
            publication.history("0" * 40, head, self.root)

    def test_repository_name_cannot_substitute_for_immutable_object_identity(self):
        good = {"id": int(publication.REPOSITORY_ID), "full_name": publication.REPOSITORY,
                "owner": {"id": 39077795}, "private": False}
        with patch.object(publication.subprocess, "check_output", return_value=json.dumps(good).encode()):
            publication.verify_repository()
        for key, value in (("id", 1), ("full_name", "foreign/repository"), ("owner", {"id": 1}), ("private", True)):
            with self.subTest(field=key), patch.object(publication.subprocess, "check_output", return_value=json.dumps(dict(good, **{key: value})).encode()):
                with self.assertRaisesRegex(ValueError, "object identity"):
                    publication.verify_repository()


class RefusalReasonTests(Repository):
    """Every refusal prints one fixed category word, never the rejected input."""

    SENTINEL = "sentinel-" + "private@" + "example.com"

    def deny(self, action, *patches):
        with contextlib.ExitStack() as stack:
            for target in patches:
                stack.enter_context(target)
            try:
                action()
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                return publication.category(error)
        self.fail("the action was not refused")

    def test_each_refusal_class_prints_its_category(self):
        (self.root / "README.md").write_text("Public configuration.\n")
        clean = self.commit("clean")
        metadata = self.commit("note " + self.SENTINEL)
        self.git("checkout", "-q", "-b", "side", self.base)
        unrelated = self.commit("unrelated")
        cases = {
            "path": lambda: publication.path_allowed("unexpected.txt"),
            "size": (lambda: publication.snapshot(clean, self.root), patch.object(publication, "MAX_BLOB", 4)),
            "content": lambda: publication.content(self.SENTINEL.encode()),
            "metadata": lambda: publication.history(clean, metadata, self.root),
            "history": lambda: publication.history(clean, clean, self.root),
            "ci": (publication.ci_range, patch.dict(os.environ, {"GITHUB_REPOSITORY": "foreign/repository"}, clear=True),
                   patch.object(publication, "git", lambda *args, **kwargs: b"0" * 40)),
            "secret": (lambda: publication.secrets(self.base, clean),
                       patch.object(publication.subprocess, "check_output", return_value="v8.30.1\n"),
                       patch.object(publication.subprocess, "run",
                                    side_effect=subprocess.CalledProcessError(1, ["gitleaks"]))),
            "identity": (publication.verify_repository,
                         patch.object(publication.subprocess, "check_output", return_value=b"[]")),
            "git": lambda: publication.history(unrelated, clean, self.root),
            "environment": (lambda: publication.secrets(self.base, clean),
                            patch.object(publication.subprocess, "check_output", side_effect=FileNotFoundError)),
            "other": lambda: int("not a size"),
        }
        self.assertEqual(set(cases) | {"usage"}, set(publication.CATEGORIES))
        for expected, case in cases.items():
            action, *patches = case if isinstance(case, tuple) else (case,)
            with self.subTest(expected):
                self.assertEqual(self.deny(action, *patches), expected)

    def test_main_prints_the_category_and_never_the_input(self):
        head = self.commit("note " + self.SENTINEL)
        real_git = publication.git
        for argv, expected in ((["publication.py", self.base, head], "PUBLICATION=DENY reason=metadata\n"),
                               (["publication.py", "--identity", self.base], "PUBLICATION=DENY reason=usage\n"),
                               (["publication.py", self.base], "PUBLICATION=DENY reason=usage\n")):
            with self.subTest(argv=argv), patch("sys.argv", argv), \
                    patch.object(publication, "git", lambda *args, **kwargs: real_git(*args, root=self.root)), \
                    contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(publication.main(), 1)
            self.assertEqual(out.getvalue(), expected)
            self.assertNotIn("sentinel", out.getvalue())

    def test_every_refusal_names_a_fixed_category(self):
        tree = ast.parse((Path(publication.__file__)).read_text())
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name) and node.func.id == "Denied"]
        self.assertGreater(len(calls), 30)
        for call in calls:
            self.assertIsInstance(call.args[0], ast.Constant)
            self.assertIn(call.args[0].value, publication.CATEGORIES)
        self.assertNotIn("ValueError(", (Path(publication.__file__)).read_text())


if __name__ == "__main__":
    unittest.main()
