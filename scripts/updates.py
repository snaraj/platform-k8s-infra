#!/usr/bin/env python3
"""Detect release drift and explicitly publish signed Draft application updates."""
from __future__ import annotations

import argparse
import copy
import datetime
import contextlib
import fcntl
import os
import importlib.util
import json
from pathlib import Path
import re
import sys
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]

def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"scripts/{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

validate, publication = load("validate"), load("publication")
artifacts = validate.artifacts
REPOSITORY = publication.REPOSITORY
OWNER = 39077795
EMAIL = "39077795+snaraj@users.noreply.github.com"
NAME = "Samuel Naranjo"
REMOTE = f"git@github.com:{REPOSITORY}.git"
FOOTER = "- Application update proposer"


def command(argv, timeout=artifacts.COMMAND_TIMEOUT_SECONDS):
    """Preserve configured GH access and SSH agent; exclude ambient Git overrides."""
    return artifacts.run_command(argv, timeout=timeout, env=publication.git_environment())


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def version(value):
    require(isinstance(value, str) and artifacts.VERSION_RE.fullmatch(value), "invalid release version")
    return tuple(map(int, value.split(".")))


def latest(selections, github):
    """An exact two-application inventory is required even for a read-only check."""
    require(set(selections) == set(validate.APPLICATIONS), "application inventory is not exact")
    result = {}
    for slug, selection in sorted(selections.items()):
        release = github.api(f"repos/{selection.source_repository}/releases/latest")
        tag = release.get("tag_name", "")
        require(isinstance(tag, str) and tag.startswith("v"), "latest tag is malformed")
        target = tag[1:]
        require(version(target) >= version(selection.version), "latest release regressed")
        require(release.get("immutable") is True and release.get("draft") is False
                and release.get("prerelease") is False and type(release.get("id")) is int
                and release["id"] > 0 and release.get("html_url") ==
                f"https://github.com/{selection.source_repository}/releases/tag/{tag}",
                "latest release is not an immutable final source release")
        result[slug] = {"version": target, "releaseId": release["id"]}
    return result


def check_latest(root=ROOT, github=None):
    selections, _receipt = validate.check(root)
    targets = latest(selections, github or artifacts.GitHub())
    drift = any(targets[slug]["version"] != selection.version for slug, selection in selections.items())
    return {"status": "DRIFT" if drift else "CURRENT", "applications": {
        slug: {"selected": selection.version, **targets[slug]} for slug, selection in sorted(selections.items())}}


def plan(root, github, registry, cosign, run=command):
    """Acquire both desired releases before writing anything; unchanged records must reproduce."""
    selections, receipt = validate.check(root)
    targets = latest(selections, github)
    records = {}
    for slug, selection in sorted(selections.items()):
        target = targets[slug]["version"]
        record, _inspection = artifacts.acquire(selection, target, registry, github, cosign)
        selected = copy.copy(selection)
        selected.version, selected.digest = target, record["manifestDigest"]
        validate.validate_record(record, slug, selected)
        require(record["chartTag"] == target and record["chartRepository"] == selection.chart_repository
                and record["signer"] == {"issuer": artifacts.ACTIONS_ISSUER, "subject": selection.subject},
                "acquisition changed publisher identity")
        if target == selection.version:
            require(record == receipt["records"][slug], "selected acquisition changed")
        records[slug] = record
    require(latest(selections, github) == targets, "latest release changed during acquisition")
    if all(targets[slug]["version"] == selection.version for slug, selection in selections.items()):
        return {}, targets
    # Receipt-v2 records the checked tool versions. Acquisition itself uses the
    # existing Python registry client; ORAS is checked for receipt compatibility.
    require(cosign.require_pinned_version() == "v3.1.3", "cosign pin differs")
    oras = re.findall(r"^Version:\s+(1\.3\.4)(?:\+Homebrew)?\s*$", run(["oras", "version"]), re.MULTILINE)
    require(oras == ["1.3.4"], "ORAS compatibility pin differs")
    updated = {**receipt, "records": records, "tools": {"cosign": "3.1.3", "oras": oras[0]},
               "capturedDate": datetime.datetime.now(datetime.timezone.utc).date().isoformat()}
    files = {validate.RECEIPT.as_posix(): artifacts.render_receipt_json(updated).encode()}
    for slug, selection in selections.items():
        if targets[slug]["version"] != selection.version:
            text = validate.read_file(root, Path(selection.path)).decode()
            text = validate.VERSION_LINE.sub(f'    platform.snaraj.dev/chart-release: "{targets[slug]["version"]}"', text)
            text = validate.DIGEST_LINE.sub(f'    digest: {records[slug]["manifestDigest"]}', text)
            files[selection.path] = text.encode()
    return files, targets


def gh_json(*arguments, run=command):
    return json.loads(run(["gh", *arguments]))


def git(root, *arguments):
    return publication.git(*arguments, root=root).decode().strip()


def clean(root, head):
    require(git(root, "rev-parse", "HEAD") == head, "local head changed")
    require(not git(root, "status", "--porcelain=v1", "--untracked-files=normal"), "checkout is not clean")


def no_existing_pushurl(root):
    # A command-line URL adds to configured URLs. Require no configured pushurl
    # so this invocation can set exactly one without an HTTPS fallback attempt.
    try:
        git(root, "config", "--name-only", "--get-regexp", r"^remote\.origin\.pushurl$")
    except subprocess.CalledProcessError as error:
        require(error.returncode == 1, "push URL configuration could not be checked")
        return
    raise ValueError("an explicit origin push URL is already configured")


def protected_base(github):
    repository = github.api(f"repos/{REPOSITORY}")
    require(str(repository.get("id")) == publication.REPOSITORY_ID
            and repository.get("full_name") == REPOSITORY and repository.get("private") is False
            and repository.get("owner", {}).get("id") == OWNER
            and repository.get("default_branch") == "main", "destination repository identity changed")
    commit = github.api(f"repos/{REPOSITORY}/commits/main")
    sha = commit.get("sha", "")
    require(artifacts.SHA_RE.fullmatch(sha) and sha != "0" * 40
            and commit.get("commit", {}).get("verification", {}).get("verified") is True,
            "main is not a verified commit")
    return sha


def no_open_proposals(run=command):
    pulls = gh_json("api", "-X", "GET", f"repos/{REPOSITORY}/pulls?state=open&per_page=100", run=run)
    require(isinstance(pulls, list) and len(pulls) < 100, "PR inventory exceeds its bound")
    require(all(isinstance(p, dict) and isinstance(p.get("head"), dict)
                and isinstance(p["head"].get("ref"), str) for p in pulls), "malformed PR inventory")
    require(not any(p["head"]["ref"].startswith("application-update/") for p in pulls),
            "an application update already needs review")


def signing_key(run=command):
    """Public registered keys intersect loaded public keys; never read a private key."""
    owner = gh_json("api", "-X", "GET", "user", run=run)
    require(owner.get("id") == OWNER and owner.get("login") == "snaraj", "publication principal is not the owner")
    registered = gh_json("api", "-X", "GET", "users/snaraj/ssh_signing_keys?per_page=100", run=run)
    require(isinstance(registered, list) and len(registered) < 100, "signing key inventory exceeds its bound")
    def public_key(value):
        fields = value.split()
        require(len(fields) >= 2 and fields[0] == "ssh-ed25519"
                and re.fullmatch(r"[A-Za-z0-9+/]+=*", fields[1]), "unsupported signing public key")
        return " ".join(fields[:2])
    registered_keys = {public_key(item["key"]) for item in registered}
    loaded = {public_key(line) for line in run(["ssh-add", "-L"]).splitlines() if line.strip()}
    matches = registered_keys & loaded
    require(len(matches) == 1, "exactly one registered loaded signing key is required")
    return matches.pop()


def verify_delta(root, base, files):
    changed = set(git(root, "diff", "--name-only", base).splitlines())
    allowed = {validate.RECEIPT.as_posix(), *(f"kubernetes/websites/{slug}/source.yaml" for slug in validate.APPLICATIONS)}
    # The receipt plus one to every active application: the bound follows the
    # application set, never a constant. A constant (2, 3) was the two-application
    # shape this helper was written for, and it refused the first proposal that
    # moved all three active applications at once (issue #13).
    require(changed == set(files) and changed <= allowed
            and 2 <= len(changed) <= len(validate.APPLICATIONS) + 1, "proposal changes unexpected paths")
    for relative, payload in files.items():
        require(validate.read_file(root, Path(relative)) == payload, "proposal bytes changed")
    validate.check(root)


def draft_matches(pull, base, head, branch, body):
    require(pull.get("state") == "OPEN" and pull.get("isDraft") is True
            and pull.get("headRefOid") == head and pull.get("headRefName") == branch
            and pull.get("baseRefOid") == base and pull.get("baseRefName") == "main"
            and pull.get("body") == body and pull.get("author", {}).get("login") == "snaraj",
            "resulting Draft identity differs")


@contextlib.contextmanager
def proposal_lock(root):
    """Serialize this repository's local proposal writers without stale lock ownership."""
    common = Path(git(root, "rev-parse", "--path-format=absolute", "--git-common-dir"))
    descriptor = os.open(common / "application-update.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


def propose(destination: Path, root=ROOT, run=command):
    with proposal_lock(root):
        return prepare_and_publish(destination, root, run)


def prepare_and_publish(destination: Path, root, run):
    """One new worktree, one signed commit, one explicit branch, one Draft PR.

    Failures retain the candidate for inspection. Never delete refs, retry a
    write, change PR state, or fetch/advance the caller's checkout implicitly.
    """
    github = artifacts.GitHub(run=run)
    base = protected_base(github)
    clean(root, base)
    require(git(root, "remote", "get-url", "origin") in
            {f"https://github.com/{REPOSITORY}.git", REMOTE}, "origin is not the destination")
    require(git(root, "remote", "get-url", "--push", "--all", "origin") in
            {f"https://github.com/{REPOSITORY}.git", REMOTE}, "push origin is not the destination")
    no_existing_pushurl(root)
    no_open_proposals(run)
    require(not destination.exists() and not destination.is_symlink()
            and destination.parent.is_dir() and destination.parent.resolve() == destination.parent
            and not destination.is_relative_to(root.resolve()),
            "worktree destination is not an unused ordinary location")
    files, targets = plan(root, github, artifacts.Registry(), artifacts.Cosign(pinned_version="v3.1.3"), run)
    if not files:
        return {"status": "CURRENT"}
    key = signing_key(run)
    versions = "_".join(f"{slug}-{target['version']}" for slug, target in sorted(targets.items()))
    branch = f"application-update/{base[:12]}/{versions}"
    clean(root, base)
    require(protected_base(github) == base, "protected main changed before preparation")
    git(root, "worktree", "add", "-b", branch, str(destination), base)
    for relative, payload in files.items():
        # The protected tree and validator have already excluded symlinks.
        validate.read_file(destination, Path(relative))
        (destination / relative).write_bytes(payload)
    verify_delta(destination, base, files)
    run(["make", "-C", str(destination), "check"], timeout=120)
    run(["make", "-C", str(destination), "verify"], timeout=120)
    require(latest(validate.check(root)[0], github) == targets, "latest release changed before signing")
    require(signing_key(run) == key, "signing identity changed")
    with tempfile.TemporaryDirectory(prefix="application-proposal-signing-") as temporary:
        signers = Path(temporary) / "allowed-signers"
        signers.write_text(f"{EMAIL} {key}\n")
        config = ("-c", f"user.name={NAME}", "-c", f"user.email={EMAIL}",
                  "-c", "gpg.format=ssh", "-c", f"user.signingkey=key::{key}",
                  "-c", f"gpg.ssh.allowedSignersFile={signers}", "-c", "core.hooksPath=.githooks")
        git(destination, "add", "--", *sorted(files))
        message = f"chore: update verified application releases\n\n{versions}\n\n{FOOTER}\n"
        git(destination, *config, "commit", "-S", "-m", message)
        head = git(destination, "rev-parse", "HEAD")
        require(git(destination, "show", "-s", "--format=%P", head) == base, "proposal is not one additive commit")
        require(git(destination, "show", "-s", "--format=%an%n%ae%n%cn%n%ce%n%B", head) ==
                f"{NAME}\n{EMAIL}\n{NAME}\n{EMAIL}\n{message}".strip(), "commit identity differs")
        git(destination, *config, "verify-commit", head)
        verify_delta(destination, base, files)
        clean(destination, head)
        run([sys.executable, "-I", "-B", str(destination / "scripts/publication.py"), "--secrets", base, head], timeout=120)
        clean(root, base)
        require(protected_base(github) == base, "protected main changed before publication")
        no_open_proposals(run)
        no_existing_pushurl(root)
        # Mandatory pre-push hook repeats the exact remote/main/history checks.
        # The per-command URL avoids persisting a remote or credential change.
        run(["git", "-C", str(destination), "-c", "core.hooksPath=.githooks", "-c",
             f"remote.origin.pushurl={REMOTE}", "push", "origin", f"refs/heads/{branch}:refs/heads/{branch}"], timeout=120)
        require(protected_base(github) == base, "protected main changed after push; leave branch for review")
        remote_commit = github.api(f"repos/{REPOSITORY}/commits/{head}")
        require(remote_commit.get("sha") == head and remote_commit.get("commit", {}).get("verification", {}).get("verified") is True,
                "published commit signature is not verified")
        body = (f"Update the declared application selections from independently acquired immutable releases.\n\n"
                f"Base: `{base}`\nHead: `{head}`\n\n" +
                "\n".join(f"- {slug}: `{target['version']}` (Release `{target['releaseId']}`)" for slug, target in sorted(targets.items())) +
                "\n\nValidation: composition and tests, fresh artifact verification, signed commit and complete outgoing-history privacy/secret checks passed.\n\n"
                "Only chart selection fields and the complete acquisition receipt change. Independent exact-head review, required hosted checks and coordinator Ready remain required; the owner alone merges. Repository selection is not live deployment evidence.\n")
        body_file = Path(temporary) / "body.md"
        body_file.write_text(body)
        url = run(["gh", "pr", "create", "--repo", REPOSITORY, "--base", "main", "--head", branch,
                   "--draft", "--no-maintainer-edit", "--title", "Update verified application releases",
                   "--body-file", str(body_file)]).strip()
        require(re.fullmatch(rf"https://github.com/{REPOSITORY}/pull/[1-9][0-9]*", url), "publication returned no exact PR URL")
        pull = gh_json("pr", "view", url, "--repo", REPOSITORY, "--json",
                       "state,isDraft,headRefOid,headRefName,baseRefOid,baseRefName,body,author", run=run)
        draft_matches(pull, base, head, branch, body)
        require(protected_base(github) == base, "protected main changed after Draft creation")
        clean(destination, head)
        return {"status": "DRAFT", "url": url, "head": head, "base": base}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check-latest", "propose"))
    parser.add_argument("--worktree", type=Path, help="new absolute worktree path; required only for propose")
    args = parser.parse_args()
    try:
        require((args.command == "propose") == (args.worktree is not None), "worktree argument does not match command")
        if args.command == "propose":
            require(args.worktree.is_absolute(), "worktree path must be absolute")
            result = propose(args.worktree)
        else:
            result = check_latest()
        print(json.dumps(result, sort_keys=True))
        return 1 if result["status"] == "DRIFT" else 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, artifacts.Refusal) as error:
        print(f"APPLICATION_UPDATE=UNKNOWN reason={type(error).__name__}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
