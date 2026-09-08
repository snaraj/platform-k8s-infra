#!/usr/bin/env python3
"""Scan every outgoing commit and file without printing private input."""
import argparse
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import select
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "snaraj/platform-k8s-infra"
REPOSITORY_ID = "1358883107"
OID = re.compile(r"[0-9a-f]{40}")
MAX_BLOB = 2 * 1024 * 1024
MAX_TREE = 16 * 1024 * 1024
ROOT_FILES = {"README.md", "AGENTS.md", "SECURITY.md", "Makefile", ".gitignore"}
PATHS = re.compile(r"(?:scripts/[a-z0-9_/-]+\.(?:py|sh)|tests/test_[a-z0-9_]+\.py|"
                   r"policies/[a-z0-9_-]+\.(?:json|toml)|docs/[a-z0-9_/-]+\.(?:json|md)|"
                   r"\.github/workflows/[a-z0-9_-]+\.yml|\.github/CODEOWNERS|\.github/dependabot\.yml|\.githooks/pre-push|"
                   # Exact directory alternation, never a wildcard: the publication
                   # surface is the last place a new path should be admitted by
                   # pattern. `obsync` is the pending third application; a fourth
                   # directory is refused here as well as by the composition
                   # inventory, so neither gate alone is load-bearing.
                   r"kubernetes/websites/(?:naranjo-online|lidersea-com|obsync)/[a-z-]+\.yaml)")
EMAIL = re.compile(r"[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}")
IPV4 = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")
IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])")
DOC_NETS = tuple(ipaddress.ip_network(s) for s in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"))
UUID = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}(?![0-9a-f])")
OPAQUE_ID = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])")
MAC = re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])")


def git_environment():
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(GIT_NO_REPLACE_OBJECTS="1", GIT_OPTIONAL_LOCKS="0", GIT_CONFIG_NOSYSTEM="1",
                       GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0")
    return environment


def git(*args, root=ROOT):
    command = ["git", "-C", str(root), *args]
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, env=git_environment())
    output = bytearray()
    deadline = time.monotonic() + 30
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
                raise ValueError("Git exceeded its time bound")
            chunk = os.read(process.stdout.fileno(), 65536)
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > MAX_TREE:
                raise ValueError("Git output exceeds its bound")
        if process.wait(timeout=max(0.01, deadline - time.monotonic())) != 0:
            raise subprocess.CalledProcessError(process.returncode, command)
        return bytes(output)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()


def content(payload):
    if len(payload) > MAX_BLOB or b"\0" in payload:
        raise ValueError("opaque or oversized content")
    text = payload.decode("utf-8")
    if any(ord(character) < 32 and character not in "\n\r\t" for character in text):
        raise ValueError("opaque control character")
    if UUID.search(text) or OPAQUE_ID.search(text) or MAC.search(text):
        raise ValueError("private infrastructure identifier")
    if re.search(r"ssh-(?:ed25519|rsa)\s+[A-Za-z0-9+/]{32,}", text):
        raise ValueError("SSH identity material")
    for value in EMAIL.findall(text):
        if value not in {"39077795+snaraj@users.noreply.github.com", "noreply@github.com", "git@github.com"} and not value.endswith("@example.invalid"):
            raise ValueError("private email")
    # Patterns are assembled to keep the detector's own source publishable.
    for prefix in ("/" + "Users/", "/" + "home/", "C:" + "\\Users\\", "file:" + "///"):
        if prefix.lower() in text.lower():
            raise ValueError("private workstation path")
    for value in [*IPV4.findall(text), *IPV6.findall(text)]:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if not address.is_loopback and not any(address in network for network in DOC_NETS if address.version == network.version):
            raise ValueError("non-documentation network identifier")


def path_allowed(path):
    parts = PurePosixPath(path).parts
    if not parts or any(part in {".", ".."} for part in parts) or PurePosixPath(path).is_absolute():
        raise ValueError("invalid publication path")
    if path not in ROOT_FILES and PATHS.fullmatch(path) is None:
        raise ValueError("unexpected publication file")


def snapshot(commit, root=ROOT):
    entries = git("ls-tree", "-rz", "--full-tree", commit, root=root).split(b"\0")
    total = 0
    for entry in filter(None, entries):
        header, name = entry.split(b"\t", 1)
        mode, kind, oid = header.decode("ascii").split()
        path_allowed(name.decode("utf-8"))
        if mode not in {"100644", "100755"} or kind != "blob":
            raise ValueError("non-ordinary publication file")
        size = int(git("cat-file", "-s", oid, root=root))
        if size > MAX_BLOB:
            raise ValueError("oversized blob")
        total += size
        if total > MAX_TREE:
            raise ValueError("oversized tree")
        content(git("cat-file", "blob", oid, root=root))


def history(base, head, root=ROOT):
    if any(OID.fullmatch(value) is None for value in (base, head)) or base == head:
        raise ValueError("invalid publication range")
    if git("rev-parse", "--is-shallow-repository", root=root).strip() != b"false":
        raise ValueError("publication history is shallow")
    grafts = git("rev-parse", "--git-path", "info/grafts", root=root).decode().strip()
    if (root / grafts).exists():
        raise ValueError("publication history has grafts")
    git("merge-base", "--is-ancestor", base, head, root=root)
    commits = git("rev-list", "--reverse", f"{base}..{head}", root=root).decode().splitlines()
    if not 1 <= len(commits) <= 256:
        raise ValueError("outgoing history exceeds its bound")
    previous = base
    for commit in commits:
        parents = git("show", "-s", "--format=%P", commit, root=root).decode().split()
        if parents != [previous]:
            raise ValueError("publication history is not linear")
        metadata = git("show", "-s", "--format=%an <%ae>%n%cn <%ce>%n%B", commit, root=root)
        content(metadata)
        snapshot(commit, root)
        previous = commit
    if previous != head:
        raise ValueError("publication head was not scanned")


def working_tree(root=ROOT):
    # Scan untracked files too. Git internals are not publication inputs.
    listing = git("ls-files", "-z", "--cached", "--others", "--exclude-standard", root=root)
    for name in filter(None, listing.split(b"\0")):
        relative = name.decode("utf-8")
        path_allowed(relative)
        path = root / relative
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError("non-ordinary working file")
        for parent in path.parents:
            if parent == root:
                break
            if parent.is_symlink():
                raise ValueError("symbolic working directory")
        if path.stat().st_size > MAX_BLOB:
            raise ValueError("oversized working file")
        content(path.read_bytes())


def secrets(base, head):
    version = subprocess.check_output(["gitleaks", "version"], timeout=10, text=True).strip().removeprefix("v")
    if version != "8.30.1":
        raise ValueError("Gitleaks version is not pinned")
    with tempfile.NamedTemporaryFile() as ignore:
        common = ["--no-banner", "--no-color", "--redact", "--ignore-gitleaks-allow",
                  f"--gitleaks-ignore-path={ignore.name}", "--max-archive-depth=1", "--max-decode-depth=1",
                  "--max-target-megabytes=2", "--timeout=120", "--config", str(ROOT / "policies/gitleaks.toml")]
        for args in (["git", f"--log-opts={base}..{head}"], ["dir"]):
            subprocess.run(["gitleaks", *args, *common, str(ROOT)], check=True, timeout=150,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=git_environment())


def ci_range():
    head = git("rev-parse", "HEAD").decode().strip()
    if (os.environ.get("GITHUB_REPOSITORY") != REPOSITORY
            or os.environ.get("GITHUB_REPOSITORY_ID") != REPOSITORY_ID
            or head != os.environ.get("GITHUB_SHA")):
        raise ValueError("CI repository or checkout is not exact")
    if os.environ.get("GITHUB_EVENT_NAME") == "pull_request":
        number, candidate = os.environ.get("PR_NUMBER", ""), os.environ.get("PR_HEAD_SHA", "")
        if not number.isdecimal() or os.environ.get("GITHUB_REF") != f"refs/pull/{number}/merge":
            raise ValueError("CI pull request ref is not exact")
        base = git("rev-parse", "refs/remotes/origin/main").decode().strip()
        parents = git("show", "-s", "--format=%P", head).decode().split()
        if parents != [base, candidate] or os.environ.get("PR_BASE_REF") != "main":
            raise ValueError("CI merge does not bind the current base and head")
        event_base = os.environ.get("PR_BASE_SHA", "")
        if OID.fullmatch(event_base) is None:
            raise ValueError("invalid event base")
        git("merge-base", "--is-ancestor", event_base, base)
        return base, candidate
    if os.environ.get("GITHUB_EVENT_NAME") != "push" or os.environ.get("GITHUB_REF") != "refs/heads/main":
        raise ValueError("unsupported publication event")
    return os.environ.get("PUSH_BASE_SHA", ""), head


def verify_repository():
    raw = subprocess.check_output(["gh", "api", "-X", "GET", f"/repos/{REPOSITORY}"],
                                  stderr=subprocess.DEVNULL, timeout=30)
    value = json.loads(raw)
    if (str(value.get("id")) != REPOSITORY_ID or value.get("full_name") != REPOSITORY
            or value.get("owner", {}).get("id") != 39077795 or value.get("private") is not False):
        raise ValueError("repository object identity changed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ci", action="store_true")
    parser.add_argument("--secrets", action="store_true")
    parser.add_argument("--identity", action="store_true")
    parser.add_argument("range", nargs="*")
    args = parser.parse_args()
    try:
        if args.identity:
            if args.range or args.ci or args.secrets:
                raise ValueError("identity check has incompatible arguments")
            verify_repository()
            print("REPOSITORY_IDENTITY=PASS")
            return 0
        bounds = ci_range() if args.ci and not args.range else args.range
        if len(bounds) != 2:
            raise ValueError("two immutable bounds are required")
        base, head = bounds
        history(base, head)
        working_tree()
        if args.secrets:
            secrets(base, head)
        print("PUBLICATION=PASS")
        return 0
    except (OSError, ValueError, subprocess.SubprocessError):
        print("PUBLICATION=DENY")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
