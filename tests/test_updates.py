"""Reject drift blind spots and exercise each proposal publication boundary."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("updates", ROOT / "scripts/updates.py")
updates = importlib.util.module_from_spec(spec)
spec.loader.exec_module(updates)


class UpdatesTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve() / "source"
        self.root.mkdir()
        for relative in ("kubernetes", "policies", "docs/assurance"):
            shutil.copytree(ROOT / relative, self.root / relative)
        self.selections, self.receipt = updates.validate.check(self.root)
        self.releases = {}
        for n, (slug, selection) in enumerate(self.selections.items(), 1):
            self.releases[selection.source_repository] = {
                "tag_name": f"v{selection.version}", "id": n, "immutable": True,
                "draft": False, "prerelease": False,
                "html_url": f"https://github.com/{selection.source_repository}/releases/tag/v{selection.version}"}
        self.github = Mock()
        self.github.api.side_effect = lambda path: copy.deepcopy(self.releases[path.split("/releases/")[0][6:]])
        self.cosign = Mock()
        self.cosign.require_pinned_version.return_value = "v3.1.3"
        self.records = copy.deepcopy(self.receipt["records"])

    def advance(self, slug):
        selection = self.selections[slug]
        parts = list(updates.version(selection.version))
        parts[2] += 1
        target = ".".join(map(str, parts))
        release = self.releases[selection.source_repository]
        release["tag_name"] = f"v{target}"
        release["html_url"] = f"https://github.com/{selection.source_repository}/releases/tag/v{target}"
        record = self.records[slug]
        record["chartTag"] = target
        record["chart"]["version"] = record["chart"]["appVersion"] = target
        record["manifestDigest"] = "sha256:" + "8" * 64
        record["workloadImage"] = f"ghcr.io/snaraj/{slug}:v{target}@sha256:" + "9" * 64
        return target

    def pending_application(self, slug="pending-fixture", template="obsync"):
        """Declare a synthetic PENDING application, and prove it admissible.

        The two rules below are pending-only, and activation emptied the map
        they read. Skipping them would park the only tests that hold the
        proposer off a pending path, so the subject is built here instead: an
        active application's directory copied under a new slug, byte-pinned like
        any other, with the sentinel digest and a suspended, not-ready release.
        `check` runs before this returns, so the fixture is admissible and any
        later refusal is the mutation under test.
        """

        validate = updates.validate
        validate.PENDING_APPLICATIONS[slug] = slug
        validate.NAMESPACES[slug] = validate.NAMESPACES[template]
        self.addCleanup(validate.PENDING_APPLICATIONS.pop, slug, None)
        self.addCleanup(validate.NAMESPACES.pop, slug, None)
        target = self.root / "kubernetes/websites" / slug
        target.mkdir()
        shapes_path = self.root / "policies/manifest-shapes.json"
        shapes = json.loads(shapes_path.read_text())
        for name in validate.FILES:
            text = (self.root / "kubernetes/websites" / template / name).read_text()
            text = text.replace(template, slug)
            if name == "source.yaml":
                text = validate.DIGEST_LINE.sub(
                    "    digest: " + validate.SENTINEL_DIGEST, text)
            if name == "release.yaml":
                text = validate.SUSPEND_LINE.sub("  suspend: true", text)
                text = validate.READY_LINE.sub("    deploymentReady: false", text)
            (target / name).write_text(text)
            normalized, _, _ = validate.normalized_manifest(
                (target / name).read_bytes(), name == "source.yaml", True
            )
            shapes[f"kubernetes/websites/{slug}/{name}"] = hashlib.sha256(normalized).hexdigest()
        shapes_path.write_text(json.dumps(shapes, indent=2) + "\n")
        validate.check(self.root)
        return slug

    def plan(self, effect=None, run=None):
        if effect is None:
            effect = lambda selection, *_: (copy.deepcopy(self.records[selection.slug]), {})
        with patch.object(updates.artifacts, "acquire", side_effect=effect) as acquire:
            result = updates.plan(self.root, self.github, object(), self.cosign,
                                  run or Mock(return_value="Version: 1.3.4+Homebrew\n"))
        return result, acquire

    def test_current_and_drift_cover_every_application_and_compare_numerically(self):
        current = updates.check_latest(self.root, self.github)
        self.assertEqual(current["status"], "CURRENT")
        self.assertEqual(set(current["applications"]), set(updates.validate.APPLICATIONS))
        target = self.advance("lidersea-com")
        result = updates.check_latest(self.root, self.github)
        self.assertEqual(result["status"], "DRIFT")
        self.assertEqual(result["applications"]["lidersea-com"]["version"], target)
        self.assertGreater(updates.version("0.1.100"), updates.version("0.1.99"))

    def test_missing_both_apps_cannot_turn_drift_into_success(self):
        shutil.rmtree(self.root / "kubernetes")
        with self.assertRaisesRegex(ValueError, "inventory"):
            updates.check_latest(self.root, self.github)
        with self.assertRaisesRegex(ValueError, "inventory"):
            updates.latest({}, self.github)
        self.github.api.assert_not_called()

    def test_latest_malformed_mutable_prerelease_regression_or_wrong_identity_denies(self):
        repo = "snaraj/naranjo.online"
        original = self.releases[repo]
        changes = ({"immutable": False}, {"draft": True}, {"prerelease": True},
                   {"id": True}, {"id": 0}, {"html_url": "https://example.invalid/release"},
                   {"tag_name": "v0.0.1"}, {"tag_name": "v01.2.3"},
                   {"tag_name": "v1.2.3-rc1"}, {"tag_name": "1.2.3"})
        for delta in changes:
            with self.subTest(delta=delta):
                self.releases[repo] = {**original, **delta}
                if "tag_name" in delta:
                    self.releases[repo]["html_url"] = f"https://github.com/{repo}/releases/tag/{delta['tag_name']}"
                with self.assertRaises(ValueError):
                    updates.latest(self.selections, self.github)
        self.releases[repo] = original

    def test_current_plan_reacquires_every_application_and_writes_nothing(self):
        (files, targets), acquire = self.plan()
        self.assertEqual(files, {})
        self.assertEqual(acquire.call_count, len(updates.validate.APPLICATIONS))
        self.assertEqual(set(targets), set(self.selections))

    def test_new_plan_has_only_changed_selection_and_complete_valid_receipt(self):
        self.advance("naranjo-online")
        before = {p.relative_to(self.root): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        (files, _targets), acquire = self.plan()
        self.assertEqual(set(files), {"kubernetes/websites/naranjo-online/source.yaml", str(updates.validate.RECEIPT)})
        self.assertEqual(acquire.call_count, len(updates.validate.APPLICATIONS))
        self.assertEqual(before, {p.relative_to(self.root): p.read_bytes() for p in self.root.rglob("*") if p.is_file()})
        for relative, payload in files.items():
            (self.root / relative).write_bytes(payload)
        selected, receipt = updates.validate.check(self.root)
        self.assertEqual(receipt["records"], self.records)
        self.assertEqual(selected["naranjo-online"].digest, self.records["naranjo-online"]["manifestDigest"])
        self.assertEqual(receipt["tools"], {"cosign": "3.1.3", "oras": "1.3.4"})

    def test_failed_acquisition_or_changed_selected_record_prevents_plan(self):
        with self.assertRaises(updates.artifacts.Refusal):
            self.plan(effect=Mock(side_effect=updates.artifacts.Refusal("verification failed")))
        self.records["naranjo-online"]["arm64Digest"] = "sha256:" + "7" * 64
        with self.assertRaisesRegex(ValueError, "selected acquisition changed"):
            self.plan()

    def test_plan_denies_changed_publisher_and_tool_versions(self):
        self.advance("naranjo-online")
        self.records["naranjo-online"]["signer"]["subject"] = "unexpected"
        with self.assertRaisesRegex(ValueError, "publisher"):
            self.plan()
        self.records["naranjo-online"]["signer"]["subject"] = self.selections["naranjo-online"].subject
        with self.assertRaisesRegex(ValueError, "ORAS"):
            self.plan(run=Mock(return_value="Version: 1.3.3\n"))
        with self.assertRaisesRegex(ValueError, "ORAS"):
            self.plan(run=Mock(return_value="Version: 1.3.4\nVersion: 1.3.4\n"))
        self.cosign.require_pinned_version.return_value = "v3.1.2"
        with self.assertRaisesRegex(ValueError, "cosign"):
            self.plan()

    def test_latest_changing_during_acquisition_prevents_any_files(self):
        self.advance("naranjo-online")
        def acquire(selection, *_):
            self.releases[selection.source_repository]["id"] += 100
            return self.records[selection.slug], {}
        with self.assertRaisesRegex(ValueError, "changed during"):
            self.plan(effect=acquire)

    def test_destination_object_owner_public_main_and_signature_are_bound(self):
        repo = {"id": int(updates.publication.REPOSITORY_ID), "full_name": updates.REPOSITORY,
                "owner": {"id": updates.OWNER}, "private": False, "default_branch": "main"}
        commit = {"sha": "1" * 40, "commit": {"verification": {"verified": True}}}
        github = Mock()
        github.api.side_effect = lambda path: copy.deepcopy(commit if path.endswith("/commits/main") else repo)
        self.assertEqual(updates.REPOSITORY, "snaraj/platform-k8s-infra")
        self.assertEqual(updates.publication.REPOSITORY_ID, "1358883107")
        self.assertEqual(updates.protected_base(github), "1" * 40)
        for key, value in (("id", 4), ("owner", {"id": 5}), ("private", True),
                           ("full_name", "snaraj/platform"), ("default_branch", "candidate")):
            original = repo[key]
            repo[key] = value
            with self.assertRaisesRegex(ValueError, "repository identity"):
                updates.protected_base(github)
            repo[key] = original
        commit["commit"]["verification"]["verified"] = False
        with self.assertRaisesRegex(ValueError, "verified commit"):
            updates.protected_base(github)

    def test_clean_guard_rejects_head_changes_and_uncommitted_files(self):
        for head, status in (("changed", ""), ("expected", " M source.yaml")):
            def answer(root, *args):
                return head if args[0] == "rev-parse" else status
            with patch.object(updates, "git", side_effect=answer), self.assertRaises(ValueError):
                updates.clean(self.root, "expected")

    def test_proposals_and_key_inventory_fail_closed(self):
        run = Mock(return_value="[]")
        updates.no_open_proposals(run)
        for value in ([{"head": {"ref": "application-update/existing"}}], [{}], [{}] * 100):
            run.return_value = json.dumps(value)
            with self.assertRaises(ValueError):
                updates.no_open_proposals(run)
        key = "ssh-ed25519 YWJj"
        values = [json.dumps({"id": updates.OWNER, "login": "snaraj"}),
                  json.dumps([{"key": key}]), key + " fixture@example.invalid\n"]
        self.assertEqual(updates.signing_key(Mock(side_effect=values)), key)
        for delta in ([json.dumps({"id": 9, "login": "snaraj"}), *values[1:]],
                      [*values[:2], "ssh-ed25519 ZGVm\n"],
                      [values[0], json.dumps([{"key": key}, {"key": "ssh-ed25519 ZGVm"}]), key + "\nssh-ed25519 ZGVm\n"]):
            with self.assertRaises(ValueError):
                updates.signing_key(Mock(side_effect=delta))

    def test_draft_state_exact_head_base_owner_body_and_refs_are_mandatory(self):
        value = {"state": "OPEN", "isDraft": True, "headRefOid": "h", "headRefName": "branch",
                 "baseRefOid": "b", "baseRefName": "main", "body": "body", "author": {"login": "snaraj"}}
        updates.draft_matches(value, "b", "h", "branch", "body")
        for key, replacement in (("state", "CLOSED"), ("isDraft", False), ("headRefOid", "changed"),
                                 ("headRefName", "main"), ("baseRefOid", "new"), ("baseRefName", "other"),
                                 ("body", "changed"), ("author", {"login": "other"})):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "Draft identity"):
                updates.draft_matches({**value, key: replacement}, "b", "h", "branch", "body")

    def test_command_scrubs_git_override_and_retains_only_normal_role_access(self):
        with patch.dict(os.environ, {"GIT_CONFIG_COUNT": "1", "GIT_DIR": "unexpected", "GH_TOKEN": "synthetic"}), \
             patch.object(updates.artifacts, "run_command", return_value="ok") as runner:
            self.assertEqual(updates.command(["gh", "api", "user"]), "ok")
        environment = runner.call_args.kwargs["env"]
        self.assertNotIn("GIT_CONFIG_COUNT", environment)
        self.assertNotIn("GIT_DIR", environment)
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(environment["GH_TOKEN"], "synthetic")

    def test_real_git_diff_denies_a_nonselection_change_or_changed_planned_bytes(self):
        self.pending_application()
        env = updates.publication.git_environment()
        def git(*args):
            return subprocess.run(["git", "-C", str(self.root), *args], check=True,
                                  capture_output=True, env=env).stdout.decode().strip()
        git("init", "-b", "main")
        git("add", ".")
        git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", "fixture")
        base = git("rev-parse", "HEAD")
        self.advance("naranjo-online")
        (files, _), _acquire = self.plan()
        for relative, payload in files.items():
            (self.root / relative).write_bytes(payload)
        updates.verify_delta(self.root, base, files)
        path = self.root / "kubernetes/websites/naranjo-online/default-deny.yaml"
        path.write_text(path.read_text() + "\n# extra\n")
        with self.assertRaisesRegex(ValueError, "unexpected paths"):
            updates.verify_delta(self.root, base, files)
        git("restore", str(path))
        path = self.root / "kubernetes/websites/naranjo-online/source.yaml"
        path.write_text(path.read_text() + "\n")
        with self.assertRaisesRegex(ValueError, "bytes changed"):
            updates.verify_delta(self.root, base, files)


    # --- Pending applications never reach a proposal (issue #348) -----------

    def test_the_drift_check_and_plan_see_active_applications_only(self):
        """A pending application has no release to compare and none is invented.

        `latest` requires the inventory it is handed to be EXACTLY the active
        set, so a pending slug leaking into the selections would be a hard
        refusal rather than a request to GitHub for a release that does not
        exist. The positive half matters as much: the two active applications
        must still be checked, or this would pass by checking nothing.
        """

        self.pending_application()
        pending = sorted(updates.validate.PENDING_APPLICATIONS)
        self.assertTrue(pending)
        self.assertEqual(set(self.selections), set(updates.validate.APPLICATIONS))
        for slug in pending:
            self.assertNotIn(slug, self.selections)
        status = updates.check_latest(self.root, self.github)
        self.assertEqual(set(status["applications"]), set(updates.validate.APPLICATIONS))
        for slug in pending:
            self.assertNotIn(slug, status["applications"])
        intruder = dict(self.selections)
        intruder[pending[0]] = next(iter(self.selections.values()))
        with self.assertRaisesRegex(ValueError, "inventory is not exact"):
            updates.latest(intruder, self.github)

    def test_a_proposal_cannot_write_a_pending_application_path(self):
        """The allowed-path set is derived from ACTIVE applications only.

        The pending subject is declared HERE, inside the test and before the
        baseline commit, so the denial below has something to deny. At a head
        whose pending map was empty this loop ran zero times and the test
        passed by checking nothing — a vacuous pass a delta review caught —
        and the count at the end is what refuses that shape from now on.
        """

        pending = self.pending_application()
        self.assertIn(pending, updates.validate.PENDING_APPLICATIONS)
        env = updates.publication.git_environment()
        def git(*args):
            return subprocess.run(["git", "-C", str(self.root), *args], check=True,
                                  capture_output=True, env=env).stdout.decode().strip()
        git("init", "-b", "main")
        git("add", ".")
        git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", "fixture")
        base = git("rev-parse", "HEAD")
        self.advance("naranjo-online")
        (files, _), _acquire = self.plan()
        for relative, payload in files.items():
            (self.root / relative).write_bytes(payload)
        updates.verify_delta(self.root, base, files)
        # The mutation this has to survive is a WIDENED allowed set, not an
        # extra file. Declaring the pending path in `files` too makes the
        # changed-equals-planned check pass, so the only thing left standing
        # between the proposal and a pending application is `allowed` itself.
        denied = []
        for slug in sorted(updates.validate.PENDING_APPLICATIONS):
            denied.append(slug)
            relative = f"kubernetes/websites/{slug}/source.yaml"
            path = self.root / relative
            original = path.read_bytes()
            mutated = original.replace(
                updates.validate.SENTINEL_DIGEST.encode(), b"sha256:" + b"1" * 64)
            self.assertNotEqual(mutated, original)
            path.write_bytes(mutated)
            declared = {**files, relative: mutated}
            with self.assertRaisesRegex(ValueError, "unexpected paths"):
                updates.verify_delta(self.root, base, declared)
            # And the undeclared form, which the equality arm catches instead.
            with self.assertRaisesRegex(ValueError, "unexpected paths"):
                updates.verify_delta(self.root, base, files)
            path.write_bytes(original)
        self.assertEqual(denied, [pending], "the denial ran against the declared pending subject")

    def test_the_publication_surface_admits_no_undeclared_application(self):
        """A fourth directory is refused by the publication gate as well.

        The composition inventory refuses it too, so neither gate is alone
        load-bearing — which is the point: the publication allowlist is an
        exact directory alternation rather than a wildcard, so a path that
        passed the inventory by some future edit still cannot be published.
        """

        for slug in sorted(updates.validate.APPLICATIONS) + sorted(updates.validate.PENDING_APPLICATIONS):
            updates.publication.path_allowed(
                f"kubernetes/websites/{slug}/source.yaml")
        for undeclared in ("undeclared", "obsync-staging", "naranjo-online-copy"):
            with self.subTest(directory=undeclared):
                with self.assertRaisesRegex(ValueError, "unexpected publication file"):
                    updates.publication.path_allowed(
                        f"kubernetes/websites/{undeclared}/source.yaml")


class ProposalFlowTests(unittest.TestCase):
    setUp = UpdatesTests.setUp
    advance = UpdatesTests.advance

    def exercise(self, fault=None):
        """Real Git worktrees and SSH signatures; public services stay synthetic."""
        self.advance("naranjo-online")
        parent = self.root.parent
        private = parent / "fixture-signing"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(private)],
                       check=True, capture_output=True)
        public = " ".join(private.with_suffix(".pub").read_text().split()[:2])
        native_git = updates.git
        native_git(self.root, "init", "-b", "main")
        native_git(self.root, "add", ".")
        native_git(self.root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                   "commit", "-m", "base")
        native_git(self.root, "remote", "add", "origin", updates.REMOTE)
        base = native_git(self.root, "rev-parse", "HEAD")
        destination = parent / "proposal"
        steps = []
        published = {}
        calls = {"main": 0, "latest": 0}

        def git(root, *args):
            # Only this disposable fixture substitutes a generated private key
            # for the production ssh-agent signer; verify-commit remains real.
            args = tuple(f"user.signingkey={private}" if a.startswith("user.signingkey=key::") else a for a in args)
            if "commit" in args:
                steps.append("commit")
                if fault == "signature":
                    raise ValueError("fixture signing refused")
            if "verify-commit" in args:
                steps.append("signature")
                if fault == "verify-signature":
                    raise ValueError("fixture signature verification refused")
            if "worktree" in args:
                steps.append("worktree")
            return native_git(root, *args)

        def run(argv, timeout=60):
            self.assertLessEqual(timeout, 120)
            if argv[0] == "oras":
                return "Version: 1.3.4\n"
            if argv == ["ssh-add", "-L"]:
                return public + "\n"
            if argv[:2] == ["gh", "api"]:
                path = argv[-1]
                if path == "user":
                    return json.dumps({"id": updates.OWNER, "login": "snaraj"})
                if path.startswith("users/snaraj/ssh_signing_keys"):
                    return json.dumps([{"key": public}])
                if path.endswith("/releases/latest"):
                    calls["latest"] += 1
                    repo = path.split("/releases/")[0][6:]
                    release = copy.deepcopy(self.releases[repo])
                    # Keyed on the PHASE, not a call ordinal: the ordinal was
                    # tuned for two applications and moved the moment a third
                    # was promoted, firing the drift before the gate instead of
                    # between the gate and the signature. `verify` in `steps`
                    # means the gate has run, so the next read of the release is
                    # the one that must see the source move under it.
                    if fault == "latest-before-sign" and "verify" in steps:
                        release["id"] += 100
                    return json.dumps(release)
                if path.endswith("pulls?state=open&per_page=100"):
                    return "[]"
                if path.endswith("/commits/main"):
                    calls["main"] += 1
                    sha = "7" * 40 if fault == "base-before-push" and calls["main"] >= 3 else base
                    return json.dumps({"sha": sha, "commit": {"verification": {"verified": True}}})
                if "/commits/" in path:
                    return json.dumps({"sha": path.split("/")[-1], "commit": {
                        "verification": {"verified": fault != "remote-signature"}}})
                if path == f"repos/{updates.REPOSITORY}":
                    return json.dumps({"id": int(updates.publication.REPOSITORY_ID),
                                       "full_name": updates.REPOSITORY, "owner": {"id": updates.OWNER},
                                       "private": False, "default_branch": "main"})
                self.fail("unexpected public API path")
            if argv[0] == "make":
                gate = argv[-1]
                steps.append(gate)
                if fault == gate:
                    raise updates.artifacts.Refusal("fixture gate failed")
                updates.validate.check(destination)
                return "PASS\n"
            if "--secrets" in argv:
                steps.append("publication")
                if fault == "publication":
                    raise updates.artifacts.Refusal("fixture scan failed")
                updates.publication.history(argv[-2], argv[-1], root=destination)
                updates.publication.working_tree(root=destination)
                return "PUBLICATION=PASS\n"
            if argv[0] == "git":
                steps.append("push")
                self.assertIn("core.hooksPath=.githooks", argv)
                self.assertIn(f"remote.origin.pushurl={updates.REMOTE}", argv)
                self.assertNotIn(f"remote.origin.url={updates.REMOTE}", argv)
                self.assertEqual(argv[-2], "origin")
                self.assertEqual(argv[-1].split(":"), ["refs/heads/" + native_git(destination, "branch", "--show-current")] * 2)
                self.assertNotIn("--force", argv)
                if fault == "push":
                    raise updates.artifacts.Refusal("fixture push refused")
                return ""
            if argv[:3] == ["gh", "pr", "create"]:
                steps.append("draft")
                self.assertIn("--draft", argv)
                self.assertIn("--no-maintainer-edit", argv)
                self.assertEqual(argv[argv.index("--repo") + 1], updates.REPOSITORY)
                body = Path(argv[argv.index("--body-file") + 1]).read_text()
                published.update(state="OPEN", isDraft=True, body=body, author={"login": "snaraj"},
                                 headRefOid=native_git(destination, "rev-parse", "HEAD"),
                                 headRefName=native_git(destination, "branch", "--show-current"),
                                 baseRefOid=base, baseRefName="main")
                return f"https://github.com/{updates.REPOSITORY}/pull/999\n"
            if argv[:3] == ["gh", "pr", "view"]:
                steps.append("readback")
                if fault == "readback":
                    published["isDraft"] = False
                return json.dumps(published)
            self.fail(f"unexpected command family {argv[0]}")

        acquisition = lambda selection, *_: (copy.deepcopy(self.records[selection.slug]), {})
        with patch.object(updates, "git", git), patch.object(updates.artifacts, "acquire", side_effect=acquisition), \
             patch.object(updates.artifacts, "Cosign", return_value=self.cosign):
            if fault:
                with self.assertRaises((ValueError, updates.artifacts.Refusal)):
                    updates.propose(destination, self.root, run)
            else:
                result = updates.propose(destination, self.root, run)
                self.assertEqual(result["status"], "DRAFT")
                self.assertEqual(result["head"], published["headRefOid"])
                self.assertEqual(result["base"], base)
                self.assertTrue(native_git(destination, "show", "-s", "--format=%B", result["head"]).endswith("- Application update proposer"))
                self.assertEqual(native_git(destination, "show", "-s", "--format=%an%n%ae%n%cn%n%ce", result["head"]).splitlines(),
                                 ["Samuel Naranjo", "39077795+snaraj@users.noreply.github.com",
                                  "Samuel Naranjo", "39077795+snaraj@users.noreply.github.com"])
        self.assertEqual(native_git(self.root, "rev-parse", "HEAD"), base)
        self.assertEqual(native_git(self.root, "status", "--porcelain=v1"), "")
        if fault:
            prefixes = {
                "verify": ["worktree", "check", "verify"],
                "latest-before-sign": ["worktree", "check", "verify"],
                "signature": ["worktree", "check", "verify", "commit"],
                "verify-signature": ["worktree", "check", "verify", "commit", "signature"],
                "publication": ["worktree", "check", "verify", "commit", "signature", "publication"],
                "base-before-push": ["worktree", "check", "verify", "commit", "signature", "publication"],
                "push": ["worktree", "check", "verify", "commit", "signature", "publication", "push"],
                "remote-signature": ["worktree", "check", "verify", "commit", "signature", "publication", "push"],
                "readback": ["worktree", "check", "verify", "commit", "signature", "publication", "push", "draft", "readback"],
            }
            self.assertEqual(steps, prefixes[fault])
        return steps

    def test_wrong_push_destination_refuses_before_acquisition_or_worktree(self):
        github = Mock()
        github.api.side_effect = [
            {"id": int(updates.publication.REPOSITORY_ID), "full_name": updates.REPOSITORY,
             "owner": {"id": updates.OWNER}, "private": False, "default_branch": "main"},
            {"sha": "1" * 40, "commit": {"verification": {"verified": True}}}]
        def git(root, *args):
            if args[:2] == ("rev-parse", "HEAD"):
                return "1" * 40
            if args[0] == "status":
                return ""
            if args[0] == "config":
                raise subprocess.CalledProcessError(1, ["git", "config"])
            if "--push" in args:
                return "git@github.com:snaraj/platform.git"
            return updates.REMOTE
        with patch.object(updates, "git", git), patch.object(updates.artifacts, "GitHub", return_value=github), \
             patch.object(updates, "no_open_proposals"), \
             patch.object(updates, "plan", return_value=({}, {})) as plan:
            with self.assertRaisesRegex(ValueError, "push origin"):
                updates.prepare_and_publish(self.root.parent / "new", self.root, Mock())
        plan.assert_not_called()

    def test_native_push_url_is_single_and_the_override_is_not_persisted(self):
        updates.git(self.root, "init", "-b", "main")
        updates.git(self.root, "remote", "add", "origin", f"https://github.com/{updates.REPOSITORY}.git")
        updates.no_existing_pushurl(self.root)
        actual = updates.git(self.root, "-c", f"remote.origin.pushurl={updates.REMOTE}",
                             "remote", "get-url", "--push", "--all", "origin")
        self.assertEqual(actual.splitlines(), [updates.REMOTE])
        updates.no_existing_pushurl(self.root)
        self.assertEqual(updates.git(self.root, "remote", "get-url", "origin"),
                         f"https://github.com/{updates.REPOSITORY}.git")
        updates.git(self.root, "config", "remote.origin.pushurl", updates.REMOTE)
        with self.assertRaisesRegex(ValueError, "already configured"):
            updates.no_existing_pushurl(self.root)

    def test_native_lock_refuses_a_second_proposal_writer(self):
        updates.git(self.root, "init", "-b", "main")
        with updates.proposal_lock(self.root):
            with self.assertRaises(BlockingIOError), updates.proposal_lock(self.root):
                self.fail("a second writer acquired the lock")
        with updates.proposal_lock(self.root):
            pass

    def test_real_signed_candidate_reaches_only_draft_after_every_gate(self):
        steps = self.exercise()
        self.assertEqual(steps, ["worktree", "check", "verify", "commit", "signature", "publication", "push", "draft", "readback"])

    def test_gate_failure_stops_before_signing(self):
        self.assertNotIn("commit", self.exercise("verify"))

    def test_source_drift_stops_before_signing(self):
        self.assertNotIn("commit", self.exercise("latest-before-sign"))

    def test_signature_failure_stops_before_publication(self):
        self.assertNotIn("publication", self.exercise("signature"))

    def test_signature_verification_failure_stops_before_scan(self):
        self.assertNotIn("publication", self.exercise("verify-signature"))

    def test_scan_failure_stops_before_push(self):
        self.assertNotIn("push", self.exercise("publication"))

    def test_base_drift_stops_before_push(self):
        self.assertNotIn("push", self.exercise("base-before-push"))

    def test_push_failure_is_not_retried_or_followed_by_a_draft(self):
        steps = self.exercise("push")
        self.assertEqual(steps.count("push"), 1)
        self.assertNotIn("draft", steps)

    def test_github_signature_failure_stops_before_draft(self):
        self.assertNotIn("draft", self.exercise("remote-signature"))

    def test_changed_draft_readback_is_not_success_or_an_implicit_retry(self):
        steps = self.exercise("readback")
        self.assertEqual(steps.count("draft"), 1)
        self.assertEqual(steps.count("readback"), 1)


if __name__ == "__main__":
    unittest.main()
