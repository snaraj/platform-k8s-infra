#!/usr/bin/env python3
"""Verify application chart/image acquisition without platform publication authority.

The acquisition checks are extracted from the reviewed platform promoter.
This module has no repository mutation, review, scheduler or cluster client.
"""

from __future__ import annotations

import atexit
import base64
import contextlib
import datetime as dt
import gzip
import hashlib
import io
import json
import os
import posixpath
import re
import select
import signal
import sys
import socket
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from pathlib import Path


REGISTRY_HOST = "ghcr.io"


OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"


OCI_INDEX = "application/vnd.oci.image.index.v1+json"


HELM_CONFIG = "application/vnd.cncf.helm.config.v1+json"


HELM_LAYER = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"


ACTIONS_ISSUER = "https://token.actions.githubusercontent.com"


SLSA_V1 = "https://slsa.dev/provenance/v1"


IN_TOTO = "application/vnd.in-toto+json"


COMMAND_TIMEOUT_SECONDS = 60


COSIGN_TIMEOUT_SECONDS = 120


COSIGN_ATTEMPTS = 2


MAX_JSON_BYTES = 1024 * 1024


MAX_BLOB_BYTES = 64 * 1024 * 1024


ARCHIVE_MEMBER_CEILING = 4096


ARCHIVE_EXPANSION_CEILING = 64 * 1024 * 1024


CHART_FILE_CEILING = 1024 * 1024


TIMEOUT = 60


DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


SHA_RE = re.compile(r"^[0-9a-f]{40}$")


VERSION_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


class Refusal(Exception):
    """A fail-closed judgment. The message names the exact check that failed."""


def sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def log(message: str) -> None:
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"{stamp} {message}", flush=True)


_FAILURE_DECISION = ["refuse"]


@contextlib.contextmanager
def timed_call(kind: str, target: str, budget: int, decision: str = ""):
    """One START line, one DONE line with elapsed seconds and the outcome.

    The failure line carries the decision AND the reason together, so reading
    the log never means correlating two lines to learn what a stall cost. The
    reason is redacted at the source: it can quote a registry or Release the
    promoter does not control.
    """

    log(f"START {kind} {target} budget={budget}s")
    started = time.monotonic()
    try:
        yield
    except BaseException as error:
        taken = decision or _FAILURE_DECISION[-1]
        log(
            f"DONE {kind} {target} elapsed={time.monotonic() - started:.1f}s FAILED"
            f" decision={taken} reason={redact(str(error))[:200]}"
        )
        raise
    log(f"DONE {kind} {target} elapsed={time.monotonic() - started:.1f}s OK")


class Selection:
    """One promotable workload as its committed manifest states it."""

    __slots__ = (
        "slug",
        "path",
        "version",
        "digest",
        "chart_repository",
        "source_repository",
        "subject",
        "domain",
    )

    def __init__(self, slug, path, version, digest, chart_repository, source_repository, subject):
        self.slug = slug
        self.path = path
        self.version = version
        self.digest = digest
        self.chart_repository = chart_repository
        self.source_repository = source_repository
        self.subject = subject
        # The human name is the source repository's own name (naranjo.online).
        self.domain = source_repository.split("/", 1)[1]


def _bounded_read(response, limit: int) -> bytes:
    data = response.read(limit + 1)
    if len(data) > limit:
        raise Refusal(f"response exceeds the {limit}-byte bound")
    return data


def http_fetch(url: str, headers: dict, limit: int) -> tuple:
    """One bounded anonymous GET; transport failures are Refusals, so the
    tick reports them instead of dying on a traceback."""

    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            body = _bounded_read(response, limit)
            return body, {key.lower(): value for key, value in response.headers.items()}
    except (urllib.error.URLError, OSError) as error:
        raise Refusal(f"{url.split('?', 1)[0]}: {error}") from None


class Registry:
    """Anonymous OCI distribution reads with the pull-scope bearer token.

    Repository names arrive host-qualified from the manifests
    (``ghcr.io/snaraj/charts/<slug>``); the distribution API wants the
    path without the host, and a name on any other host is refused."""

    def __init__(self, fetch=http_fetch, host: str = REGISTRY_HOST):
        self._fetch = fetch
        self.host = host
        self._tokens = {}

    def _name(self, repository: str) -> str:
        host, _, path = repository.partition("/")
        if host != self.host or not path:
            raise Refusal(f"{repository}: not a repository on {self.host}")
        return path

    def _token(self, name: str) -> str:
        if name not in self._tokens:
            url = f"https://{self.host}/token?scope=repository:{name}:pull"
            # The traced target names the repository and the scope, never the
            # answer: the pull token itself is a credential and stays out of
            # every log line the same way the reviewer App's token does.
            with timed_call("registry-token", f"{name} scope=pull", TIMEOUT):
                body, _ = self._fetch(url, {}, MAX_JSON_BYTES)
            token = json.loads(body).get("token")
            if not isinstance(token, str) or not token:
                raise Refusal(f"{name}: registry issued no pull token")
            self._tokens[name] = token
        return self._tokens[name]

    def manifest(self, repository: str, reference: str, accept: str) -> tuple:
        """Return ``(bytes, docker-content-digest)`` for one reference."""

        name = self._name(repository)
        headers = {"Authorization": "Bearer " + self._token(name), "Accept": accept}
        url = f"https://{self.host}/v2/{name}/manifests/{reference}"
        with timed_call("registry-manifest", f"{repository}:{reference}", TIMEOUT):
            body, response_headers = self._fetch(url, headers, MAX_JSON_BYTES)
        header = response_headers.get("docker-content-digest")
        if not isinstance(header, str) or DIGEST_RE.fullmatch(header) is None:
            raise Refusal(f"{repository}:{reference}: registry answered without a content digest")
        return body, header

    def blob(self, repository: str, digest: str) -> bytes:
        name = self._name(repository)
        headers = {"Authorization": "Bearer " + self._token(name)}
        url = f"https://{self.host}/v2/{name}/blobs/{digest}"
        with timed_call("registry-blob", f"{repository}@{digest}", TIMEOUT):
            body, _ = self._fetch(url, headers, MAX_BLOB_BYTES)
        if sha256_hex(body) != digest:
            raise Refusal(f"{repository}@{digest}: blob bytes do not hash to their digest")
        return body


_anonymous_registry_directory = None


def anonymous_registry_config() -> str:
    """One private, credential-free Docker config for this process lifetime."""
    global _anonymous_registry_directory
    if _anonymous_registry_directory is None:
        directory = tempfile.TemporaryDirectory(prefix="application-registry-")
        atexit.register(directory.cleanup)
        config = Path(directory.name) / "config.json"
        descriptor = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            stream.write("{}\n")
        _anonymous_registry_directory = directory
    return _anonymous_registry_directory.name


def pinned_environment(env=None) -> dict:
    """Use anonymous OCI access even when the caller has registry credentials."""
    merged = dict(os.environ if env is None else env)
    merged["DOCKER_CONFIG"] = anonymous_registry_config()
    merged["GH_PROMPT_DISABLED"] = "1"
    return merged


# Keep a live session leader until the parent disposes of the entire group.
# The status pipe closes on exec, so a command cannot hold it open accidentally.
# Output goes to bounded private files, never an unbounded communicate() buffer.
SUPERVISOR = r"""
import os, resource, signal, subprocess, sys
status_fd = int(sys.argv[1])
os.set_inheritable(status_fd, False)
resource.setrlimit(resource.RLIMIT_FSIZE, (2 * 1024 * 1024, 2 * 1024 * 1024))
try:
    code = subprocess.call(sys.argv[2:], stdin=subprocess.DEVNULL)
except OSError:
    code = 127
os.write(status_fd, str(code).encode())
os.close(status_fd)
while True:
    signal.pause()
"""


def run_command(argv, timeout=COMMAND_TIMEOUT_SECONDS, *, env=None) -> str:
    """Bound gh/cosign execution; signal the group before reaping its leader.

    The leader remains alive after its command exits. On every path we dispose
    of the group before wait(), preventing PID reuse from selecting another
    process group. Commands that deliberately create a new session are outside
    this boundary; this verifier executes only the fixed gh/cosign tool set.
    """
    if not 0 < timeout <= COSIGN_TIMEOUT_SECONDS:
        raise Refusal("command timeout is outside its bound")
    process = None
    read_fd, write_fd = os.pipe()
    try:
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            process = subprocess.Popen(
                [sys.executable, "-I", "-B", "-c", SUPERVISOR, str(write_fd), *map(str, argv)],
                stdin=subprocess.DEVNULL, stdout=output, stderr=errors,
                pass_fds=(write_fd,), env=pinned_environment(env), start_new_session=True,
            )
            os.close(write_fd)
            write_fd = -1
            if not select.select([read_fd], [], [], timeout)[0]:
                raise Refusal("command exceeded its time bound")
            status = os.read(read_fd, 16)
            if re.fullmatch(rb"-?[0-9]{1,3}", status) is None:
                raise Refusal("command supervisor returned no valid status")
            # No poll(), wait() or communicate() has reaped the leader here.
            _kill_process_group(process)
            process = None
            if int(status) != 0:
                raise Refusal("command failed; output is not recorded")
            output.seek(0)
            return _bounded_read(output, 2 * MAX_JSON_BYTES).decode("utf-8")
    except OSError as error:
        raise Refusal(f"command could not be run ({type(error).__name__})") from None
    finally:
        if process is not None:
            _kill_process_group(process)
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)


def _kill_process_group(process) -> None:
    """The parent still owns the unreaped session leader's PID."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=5)


class GitHub:
    """Read public release metadata through the configured GitHub CLI."""

    def __init__(self, run=run_command, fetch=http_fetch):
        self._run, self._fetch = run, fetch

    def api(self, path: str) -> dict:
        with timed_call("github-api", f"GET {path}", COMMAND_TIMEOUT_SECONDS):
            output = self._run(["gh", "api", "-X", "GET", "-H",
                                "Accept: application/vnd.github+json", path])
        value = json.loads(output)
        if not isinstance(value, dict):
            raise Refusal("GitHub response must be one object")
        return value

    def download(self, url: str) -> bytes:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or parsed.netloc != "github.com":
            raise Refusal(f"refusing to download a Release asset from {parsed.netloc}")
        with timed_call("release-asset", parsed.path, TIMEOUT):
            body, _ = self._fetch(url, {}, MAX_JSON_BYTES)
        return body


class Cosign:
    """The two cosign verifications, always AT A DIGEST, never at a tag."""

    def __init__(self, run=run_command, pinned_version: str = ""):
        self._run = run
        self.pinned_version = pinned_version
        self._verified_version = None

    def require_pinned_version(self) -> str:
        """The pin is checked before the first verification and cached; a
        cosign that is not the required tool pin verifies nothing."""

        if self._verified_version is None:
            with timed_call("cosign-version", "cosign version --json", COSIGN_TIMEOUT_SECONDS):
                output = self._run(["cosign", "version", "--json"], timeout=COSIGN_TIMEOUT_SECONDS)
            version = json.loads(output).get("gitVersion")
            if version != self.pinned_version:
                raise Refusal(
                    f"cosign {version!r} is not the required tool pin {self.pinned_version!r}"
                )
            self._verified_version = version
        return self._verified_version

    def _bounded(self, argv, kind: str, target: str) -> str:
        """One cosign call under a SHORT budget, with exactly one retry.

        Cosign reaches Sigstore and the registry in the same call, so a stall
        there is the one failure mode that used to cost a whole tick silently.
        Each attempt is traced and bounded; the first failure logs
        ``decision=retry`` and the second the caller's real decision, so the
        log says what a stall cost without anyone correlating lines.
        """

        failure = None
        for attempt in range(1, COSIGN_ATTEMPTS + 1):
            decision = "retry" if attempt < COSIGN_ATTEMPTS else ""
            try:
                with timed_call(kind, f"{target} attempt={attempt}/{COSIGN_ATTEMPTS}", COSIGN_TIMEOUT_SECONDS, decision):
                    return self._run(argv, timeout=COSIGN_TIMEOUT_SECONDS)
            except Refusal as error:
                failure = error
        raise failure

    def verify_chart(self, repository: str, digest: str, subject: str) -> None:
        self.require_pinned_version()
        output = self._bounded(
            [
                "cosign",
                "verify",
                "--certificate-identity",
                subject,
                "--certificate-oidc-issuer",
                ACTIONS_ISSUER,
                f"{repository}@{digest}",
            ],
            "cosign-verify-chart",
            f"{repository}@{digest}",
        )
        entries = json.loads(output)
        if not isinstance(entries, list) or not entries:
            raise Refusal(f"{repository}@{digest}: cosign returned no signature")
        for entry in entries:
            bound = entry.get("critical", {}).get("image", {}).get("docker-manifest-digest")
            if bound != digest:
                raise Refusal(f"{repository}: signature binds {bound}, not {digest}")

    def verify_provenance(self, repository: str, digest: str, subject: str) -> None:
        self.require_pinned_version()
        output = self._bounded(
            [
                "cosign",
                "verify-attestation",
                "--type",
                "slsaprovenance1",
                "--new-bundle-format",
                "--certificate-identity",
                subject,
                "--certificate-oidc-issuer",
                ACTIONS_ISSUER,
                f"{repository}@{digest}",
            ],
            "cosign-verify-provenance",
            f"{repository}@{digest}",
        )
        statements = 0
        for line in output.splitlines():
            if not line.strip():
                continue
            envelope = json.loads(line)
            if envelope.get("payloadType") != IN_TOTO:
                raise Refusal(f"{repository}: attestation payload type is not in-toto")
            statement = json.loads(base64.b64decode(envelope["payload"]))
            if statement.get("predicateType") != SLSA_V1:
                raise Refusal(f"{repository}: attestation is not SLSA v1 provenance")
            subjects = {
                "sha256:" + item.get("digest", {}).get("sha256", "")
                for item in statement.get("subject", [])
            }
            if subjects != {digest}:
                raise Refusal(f"{repository}: provenance subject is not exactly {digest}")
            statements += 1
        if statements == 0:
            raise Refusal(f"{repository}@{digest}: no SLSA v1 provenance statement")


def resolve_twice(registry: Registry, repository: str, reference: str, accept: str) -> tuple:
    """Resolve one reference twice; both answers must agree with their bytes
    and with each other. Returns ``(digest, bytes)``."""

    answers = []
    for _ in range(2):
        body, header = registry.manifest(repository, reference, accept)
        computed = sha256_hex(body)
        if header != computed:
            raise Refusal(
                f"{repository}:{reference}: content digest {header} disagrees with the bytes ({computed})"
            )
        answers.append((computed, body))
    if answers[0] != answers[1]:
        raise Refusal(f"{repository}:{reference}: the reference moved between two resolutions")
    return answers[0]


def _yaml_scalar(text: str, key: str, indent: str = "") -> str:
    pattern = re.compile(rf"^{indent}{re.escape(key)}:\s*(.+?)\s*$", re.MULTILINE)
    values = [value.strip("'\"") for value in pattern.findall(text)]
    if len(values) != 1:
        raise Refusal(f"expected exactly one `{key}` in the chart document, found {len(values)}")
    return values[0]


def chart_identity(chart_yaml: str) -> dict:
    return {
        "appVersion": _yaml_scalar(chart_yaml, "appVersion"),
        "name": _yaml_scalar(chart_yaml, "name"),
        "version": _yaml_scalar(chart_yaml, "version"),
    }


def image_pin(values_yaml: str) -> dict:
    """The embedded workload pin: ``image.repository``, ``image.tag``,
    ``image.digest`` — each exactly once, inside the top-level image block."""

    block = re.search(r"^image:\n((?:[ \t]+.*\n|[ \t]*#.*\n)*)", values_yaml, re.MULTILINE)
    if block is None:
        raise Refusal("values.yaml carries no top-level image block")
    body = block.group(1)
    return {
        "repository": _yaml_scalar(body, "repository", indent="  "),
        "tag": _yaml_scalar(body, "tag", indent="  "),
        "digest": _yaml_scalar(body, "digest", indent="  "),
    }


class _BoundedReader:
    """Serves a decompressing stream and refuses once more than ``ceiling``
    bytes have been produced, so an archive's expansion is bounded before
    any entry is materialized."""

    def __init__(self, inner, ceiling: int):
        self._inner, self._ceiling, self._seen = inner, ceiling, 0

    def read(self, size=-1) -> bytes:
        chunk = self._inner.read(size)
        self._seen += len(chunk)
        if self._seen > self._ceiling:
            raise Refusal(f"chart layer expands past {self._ceiling} bytes")
        return chunk


def chart_members(layer: bytes, names: tuple) -> dict:
    """The exact bytes of ``names`` from the chart layer, read in ONE
    bounded streaming pass. Every entry path is normalized and must be
    unique — a second entry for a path, or a ``./``-prefixed twin, is
    refused outright rather than resolved, because Helm's choice among such
    entries need not be this tool's — every entry must be a regular file or
    a directory (a link or device anywhere in the chart is refused), and
    each wanted name must be a regular file within the per-file ceiling.
    Entries outside the archive root are refused."""

    wanted = set(names)
    found, seen, count = {}, set(), 0
    stream = _BoundedReader(gzip.GzipFile(fileobj=io.BytesIO(layer)), ARCHIVE_EXPANSION_CEILING)
    try:
        with tarfile.open(fileobj=stream, mode="r|") as archive:
            for member in archive:
                count += 1
                if count > ARCHIVE_MEMBER_CEILING:
                    raise Refusal(f"chart layer carries more than {ARCHIVE_MEMBER_CEILING} entries")
                normalized = posixpath.normpath(member.name)
                if normalized.startswith("/") or normalized == "." or ".." in normalized.split("/"):
                    raise Refusal("chart layer carries an entry outside the archive root")
                if normalized in seen:
                    raise Refusal(f"chart layer carries {normalized} more than once")
                seen.add(normalized)
                if not (member.isfile() or member.isdir()):
                    raise Refusal(f"chart layer member {normalized} is not a regular file")
                if normalized not in wanted:
                    continue
                if not member.isfile():
                    raise Refusal(f"chart layer member {normalized} is not a regular file")
                if member.size > CHART_FILE_CEILING:
                    raise Refusal(f"chart layer member {normalized} exceeds {CHART_FILE_CEILING} bytes")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise Refusal(f"chart layer member {normalized} is unreadable")
                # tarfile refuses a member whose data falls short of its
                # header (ReadError, caught below); the read is exactly the
                # declared, already-bounded size.
                found[normalized] = extracted.read(member.size)
    except (tarfile.TarError, EOFError, OSError, zlib.error) as error:
        raise Refusal(f"chart layer is not a readable gzip tar: {type(error).__name__}") from None
    for name in names:
        if name not in found:
            raise Refusal(f"chart layer carries no {name}")
    return found


def profile_for(subject: str) -> str:
    """Select the acquisition profile from the publisher identity.

    A subject this file has no profile for is refused: the promoter never
    guesses how an unknown publisher should be verified.
    """

    if re.fullmatch(
        r"https://github\.com/snaraj/[^/]+/\.github/workflows/release-publisher\.yml@refs/heads/main",
        subject,
    ):
        return "release-publisher"
    raise Refusal(f"no acquisition profile for publisher identity {subject}")


def release_manifest_statements(asset: dict) -> dict:
    """Every statement a Release manifest makes about the resolved identities,
    across both publisher schemas in the fleet (``lidersea.release-manifest/v1``
    carries ``tag``/``version``/``workflow_identity`` and nested ``signature``
    blocks; the naranjo schema carries ``release``/``publisher`` blocks and
    ``signature_identity`` fields). Absent statements are omitted, never
    defaulted, so a schema that states nothing cannot pass by silence."""

    artifacts = asset.get("artifacts") or {}
    chart = artifacts.get("chart") or {}
    image = artifacts.get("image") or {}
    publisher = asset.get("publisher") or {}
    release = asset.get("release") or {}
    candidates = {
        "repository": [asset.get("repository")],
        "version": [asset.get("version"), release.get("version"), chart.get("tag")],
        "tag": [asset.get("tag"), release.get("tag"), image.get("tag")],
        "identity": [
            asset.get("workflow_identity"),
            chart.get("signature_identity"),
            image.get("signature_identity"),
            (chart.get("signature") or {}).get("certificate_identity"),
            (image.get("signature") or {}).get("certificate_identity"),
            (
                f"https://github.com/{asset.get('repository')}/{publisher.get('workflow')}@{publisher.get('ref')}"
                if publisher.get("workflow") and publisher.get("ref")
                else None
            ),
        ],
        "chart.repository": [chart.get("repository"), chart.get("registry")],
        "chart.digest": [chart.get("digest")],
        "image.repository": [image.get("repository"), image.get("registry")],
        "image.digest": [image.get("digest")],
    }
    return {key: [value for value in values if value is not None] for key, values in candidates.items()}


def bind_release_manifest(asset: dict, expected: dict, label: str) -> None:
    """Every stated value must equal the resolved one, and the load-bearing
    fields — repository, version, publisher identity, chart and image
    digests — must be stated at least once."""

    statements = release_manifest_statements(asset)
    for field, value in expected.items():
        stated = statements.get(field, [])
        for candidate in stated:
            if candidate != value:
                raise Refusal(f"{label}: release manifest {field} states {candidate!r}, not {value!r}")
        if not stated:
            raise Refusal(f"{label}: release manifest states no {field}")


def acquire_release_publisher(
    selection: Selection, version: str, registry: Registry, github: GitHub, cosign: Cosign
) -> tuple:
    """The ``release-publisher`` profile. Returns ``(record, inspection)``.

    ``record`` is one receipt-v2 record; ``inspection`` holds the exact-layer
    hashes of ``Chart.yaml`` and ``values.yaml`` the Markdown view states.
    """

    slug, chart_repo, subject = selection.slug, selection.chart_repository, selection.subject
    # The site publisher contract names the workload image after the chart.
    image_repo = f"{REGISTRY_HOST}/snaraj/{slug}"
    tag = f"v{version}"

    manifest_digest, manifest_bytes = resolve_twice(registry, chart_repo, version, OCI_MANIFEST)
    manifest = json.loads(manifest_bytes)
    if manifest.get("schemaVersion") != 2 or manifest.get("mediaType", OCI_MANIFEST) != OCI_MANIFEST:
        raise Refusal(f"{chart_repo}:{version}: not an OCI image manifest")
    config = manifest.get("config", {})
    if config.get("mediaType") != HELM_CONFIG:
        raise Refusal(f"{chart_repo}:{version}: config is not a Helm config blob")
    layers = [layer for layer in manifest.get("layers", []) if layer.get("mediaType") == HELM_LAYER]
    if len(layers) != 1 or len(manifest.get("layers", [])) != 1:
        raise Refusal(f"{chart_repo}:{version}: expected exactly one Helm chart layer")
    layer = layers[0]

    config_bytes = registry.blob(chart_repo, config["digest"])
    config_document = json.loads(config_bytes)
    expected_chart = {"appVersion": version, "name": slug, "version": version}
    if {key: config_document.get(key) for key in expected_chart} != expected_chart:
        raise Refusal(f"{chart_repo}:{version}: Helm config identity is not {expected_chart}")

    layer_bytes = registry.blob(chart_repo, layer["digest"])
    if layer.get("size") != len(layer_bytes):
        raise Refusal(f"{chart_repo}:{version}: layer size disagrees with its bytes")
    members = chart_members(layer_bytes, (f"{slug}/Chart.yaml", f"{slug}/values.yaml"))
    chart_yaml = members[f"{slug}/Chart.yaml"]
    values_yaml = members[f"{slug}/values.yaml"]
    if chart_identity(chart_yaml.decode("utf-8")) != expected_chart:
        raise Refusal(f"{chart_repo}:{version}: Chart.yaml identity is not {expected_chart}")
    pin = image_pin(values_yaml.decode("utf-8"))
    if pin["repository"] != image_repo or pin["tag"] != tag:
        raise Refusal(f"{slug}: embedded image pin {pin} is not {image_repo}:{tag}")
    if DIGEST_RE.fullmatch(pin["digest"]) is None:
        raise Refusal(f"{slug}: embedded image digest {pin['digest']!r} is malformed")

    index_digest, index_bytes = resolve_twice(registry, image_repo, tag, OCI_INDEX)
    if index_digest != pin["digest"]:
        raise Refusal(f"{image_repo}:{tag}: index {index_digest} is not the embedded pin {pin['digest']}")
    index = json.loads(index_bytes)
    if index.get("mediaType") != OCI_INDEX:
        raise Refusal(f"{image_repo}:{tag}: not an OCI image index")
    arm64 = [
        child["digest"]
        for child in index.get("manifests", [])
        if child.get("platform", {}).get("os") == "linux"
        and child.get("platform", {}).get("architecture") == "arm64"
    ]
    if len(arm64) != 1 or DIGEST_RE.fullmatch(arm64[0]) is None:
        raise Refusal(f"{image_repo}:{tag}: expected exactly one linux/arm64 child")

    cosign.verify_chart(chart_repo, manifest_digest, subject)
    cosign.verify_provenance(image_repo, index_digest, subject)

    release = github.api(f"repos/{selection.source_repository}/releases/tags/{tag}")
    if release.get("immutable") is not True or release.get("draft") or release.get("prerelease"):
        raise Refusal(f"{selection.source_repository} {tag}: Release is not an immutable final release")
    assets = [asset for asset in release.get("assets", []) if asset.get("name", "").endswith("release-manifest.json")]
    if len(assets) != 1:
        raise Refusal(f"{selection.source_repository} {tag}: expected exactly one release-manifest.json asset")
    asset_url = assets[0]["browser_download_url"]
    expected_url = f"https://github.com/{selection.source_repository}/releases/download/{tag}/{assets[0]['name']}"
    if asset_url != expected_url or "/" in assets[0]["name"] or assets[0]["name"] in {".", ".."}:
        raise Refusal("refusing to download a Release asset outside its exact source release")
    asset_bytes = github.download(asset_url)
    asset_digest = sha256_hex(asset_bytes)
    if assets[0].get("digest") != asset_digest:
        raise Refusal(f"{selection.source_repository} {tag}: asset bytes hash to {asset_digest}, GitHub states {assets[0].get('digest')}")
    asset = json.loads(asset_bytes)
    source_sha = asset.get("source_sha")
    bind_release_manifest(
        asset,
        {
            "repository": selection.source_repository,
            "version": version,
            "tag": tag,
            "identity": subject,
            "chart.repository": chart_repo,
            "chart.digest": manifest_digest,
            "image.repository": image_repo,
            "image.digest": index_digest,
        },
        f"{selection.source_repository} {tag}",
    )
    if not isinstance(source_sha, str) or SHA_RE.fullmatch(source_sha) is None:
        raise Refusal(f"{selection.source_repository} {tag}: release manifest source_sha is malformed")

    reference = github.api(f"repos/{selection.source_repository}/git/ref/tags/{tag}")
    if reference.get("object", {}).get("type") != "tag":
        raise Refusal(f"{selection.source_repository} {tag}: not an annotated tag")
    tag_object = github.api(f"repos/{selection.source_repository}/git/tags/{reference['object']['sha']}")
    if tag_object.get("tag") != tag or tag_object.get("object", {}).get("type") != "commit":
        raise Refusal(f"{selection.source_repository} {tag}: tag object does not name a commit")
    if tag_object["object"].get("sha") != source_sha:
        raise Refusal(
            f"{selection.source_repository} {tag}: annotated tag dereferences to {tag_object['object'].get('sha')}, the Release asset names {source_sha}"
        )
    # "Protected-main source" is a claim the receipt makes; earn it: the
    # source commit must be an ancestor of (or equal to) the site's main.
    ancestry = github.api(f"repos/{selection.source_repository}/compare/main...{source_sha}").get("status")
    if ancestry not in {"identical", "behind"}:
        raise Refusal(f"{selection.source_repository} {tag}: source {source_sha} is not reachable from protected main ({ancestry})")

    record = {
        "arm64Digest": arm64[0],
        "chart": expected_chart,
        "chartConfigDigest": config["digest"],
        "chartLayerDigest": layer["digest"],
        "chartRepository": chart_repo,
        "chartTag": version,
        "manifestDigest": manifest_digest,
        "matchingChartLayerCount": 1,
        "release": {"assetDigest": asset_digest, "sourceSha": source_sha},
        "signer": {"issuer": ACTIONS_ISSUER, "subject": subject},
        "workloadImage": f"{image_repo}:{tag}@{index_digest}",
    }
    inspection = {"Chart.yaml": sha256_hex(chart_yaml), "values.yaml": sha256_hex(values_yaml)}
    return record, inspection


PROFILES = {"release-publisher": acquire_release_publisher}


def acquire(selection: Selection, version: str, registry, github, cosign) -> tuple:
    if VERSION_RE.fullmatch(version) is None:
        raise Refusal(f"{selection.slug}: version {version!r} is not a plain semantic version")
    profile = PROFILES[profile_for(selection.subject)]
    try:
        return profile(selection, version, registry, github, cosign)
    except (KeyError, TypeError, ValueError, tarfile.TarError, OSError) as error:
        # A malformed registry, Release or cosign answer is a refusal with a
        # name, never a traceback the tick cannot report.
        raise Refusal(f"{selection.slug} {version}: malformed answer ({type(error).__name__}: {error})") from None


def _compact(mapping: dict) -> str:
    return "{" + ", ".join(f'"{key}": {json.dumps(mapping[key])}' for key in sorted(mapping)) + "}"


def render_receipt_json(receipt: dict) -> str:
    """Render exactly the committed layout: nested identity objects on one
    line each, records sorted by slug, fields sorted within a record."""

    lines = [
        "{",
        f'  "chartLayerMediaType": {json.dumps(receipt["chartLayerMediaType"])},',
        f'  "capturedDate": {json.dumps(receipt["capturedDate"])},',
        '  "records": {',
    ]
    slugs = sorted(receipt["records"])
    for index, slug in enumerate(slugs):
        record = receipt["records"][slug]
        lines.append(f'    "{slug}": {{')
        keys = sorted(record)
        for position, key in enumerate(keys):
            value = record[key]
            rendered = _compact(value) if isinstance(value, dict) else json.dumps(value)
            comma = "," if position < len(keys) - 1 else ""
            lines.append(f'      "{key}": {rendered}{comma}')
        lines.append("    }" + ("," if index < len(slugs) - 1 else ""))
    lines += [
        "  },",
        f'  "schema": {json.dumps(receipt["schema"])},',
        f'  "tools": {_compact(receipt["tools"])}',
        "}",
    ]
    return "\n".join(lines) + "\n"


def redact(text: str) -> str:
    """What a public failure comment may carry: one line, no Markdown
    fences, and no private host detail — every path-shaped token that is not
    a scheme URL, every dotted address, this workstation's host name and the
    login name are replaced. The raw text stays in the local log."""

    flat = re.sub(r"[`\r\n]+", " ", text)
    flat = re.sub(r"(?<!\S)(?!\w+://)\S*/\S*", "<path>", flat)
    flat = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<addr>", flat)
    for private in (socket.gethostname(), socket.gethostname().split(".")[0], os.environ.get("USER"), os.environ.get("LOGNAME")):
        if private and len(private) > 2:
            flat = flat.replace(private, "<host>")
    return flat
