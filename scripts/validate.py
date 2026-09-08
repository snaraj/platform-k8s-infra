#!/usr/bin/env python3
"""Check the closed application boundary; optionally re-verify public artifacts."""
from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("application_artifacts", ROOT / "scripts/artifacts.py")
artifacts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(artifacts)

# ACTIVE applications: slug -> application repository. Each one has a published
# release, an acquired artifact and an exact record in the acquisition receipt,
# and the receipt is required to bind EXACTLY this set.
APPLICATIONS = {"lidersea-com": "lidersea.com", "naranjo-online": "naranjo.online"}

# PENDING applications: the same shape, for a workload whose publisher has not
# cut a release yet. This is a second, NARROWER declaration rather than a third
# entry above, because a third ACTIVE entry cannot be honest: there is no
# acquired artifact and no receipt record to point at, and inserting one to
# reserve a place would put a name into the receipt closure that no acquisition
# ceremony ever resolved.
#
# What membership here means, exactly:
#
#   * the closed file set includes this application's directory, so its four
#     manifests are inventoried and byte-pinned like any other;
#   * its `source.yaml` may select ONLY the all-zero sentinel digest. A REAL
#     digest is refused while pending — the exact inverse of the rule the
#     active applications carry, where the sentinel is refused;
#   * its `release.yaml` must be `suspend: true` with `deploymentReady: false`.
#     An unsuspended or ready release while pending is refused;
#   * it contributes NO selection, so the receipt stays exact over the ACTIVE
#     applications only and `updates.py` never proposes for it.
#
# Promotion is ONE reviewed change that moves the entry from this map to
# APPLICATIONS and adds its acquisition receipt record. The two rules above are
# opposites, so that change cannot half-land: leaving the sentinel while active
# fails, and committing a real digest while pending fails.
PENDING_APPLICATIONS = {"obsync": "obsync"}

FILES = ("kustomization.yaml", "default-deny.yaml", "source.yaml", "release.yaml")
RECEIPT = Path("docs/assurance/195-chart-acquisition-receipt.json")
VERSION_LINE = re.compile(r'^    platform\.snaraj\.dev/chart-release: "([0-9.]+)"$', re.MULTILINE)
DIGEST_LINE = re.compile(r'^    digest: (sha256:[0-9a-f]{64})$', re.MULTILINE)
SENTINEL_DIGEST = "sha256:" + "0" * 64
# The two identity fields a source manifest states in its own bytes. They are
# what makes the map VALUE load-bearing for an application that has no receipt
# yet: an active application's repository is bound by comparing the receipt's
# signer subject to the one derived from the map, but a pending application has
# no receipt record to compare against, so the same derivation is checked
# against the manifest instead. Applied to every application, not only pending
# ones, so one rule covers both maps and neither can drift.
URL_LINE = re.compile(r'^  url: (\S+)$', re.MULTILINE)
SUBJECT_LINE = re.compile(r'^        subject: (\S+)$', re.MULTILINE)
SUSPEND_LINE = re.compile(r'^  suspend: (\S+)$', re.MULTILINE)
READY_LINE = re.compile(r'^    deploymentReady: (\S+)$', re.MULTILINE)
# Storage activation is an operator decision, never an application one: a
# permanent volume, its class and the node path behind it stay bootstrap-owned.
# A chart may create CLAIMS at render time; this repository's own manifests may
# not declare storage or mount one, and that is asserted here rather than left
# to the byte pins so the refusal names the property it refuses.
STORAGE_KIND_LINE = re.compile(
    r'^kind:\s*(?:PersistentVolume|PersistentVolumeClaim|StorageClass'
    r'|CSIDriver|CSIStorageCapacity|VolumeAttachment)\s*$',
    re.MULTILINE,
)
# The dash is deliberate: a volume entry is a YAML sequence item, so the source
# key is written `- persistentVolumeClaim:` and a pattern anchored on
# whitespace alone matches nothing and guards nothing.
# `ReadWriteOnce` excludes other NODES, not other Pods, so on a single-node
# cluster it prevents no second writer at all. Nor does the server's own journal
# lock: it refuses COOPERATIVE duplicate starts, but a process with the same uid
# owns the directory and can rename the lock aside. Excluding a second Pod is an
# ADMISSION decision — `replicas: 1` and `strategy: Recreate` in the signed
# chart, asserted by the platform over the rendered Deployment. This
# repository's part is narrow and exact: a platform values block may not ASK for
# either, so no composition change can weaken it even if a future chart made
# them overridable.
# The keys that would ask a single-writer workload for a second Pod.
SECOND_POD_KEYS = frozenset({"replicas", "replicacount", "strategy", "updatestrategy"})
# Every `spec` key at two-space indent, however it is spelled, so a QUOTED or
# TAGGED `values` key is caught rather than silently unmatched.
SPEC_KEY_LINE = re.compile(r'(?m)^  (?P<raw>[^\s#][^:]*?)\s*:\s*(?P<rest>.*)$')
# The complete admissible grammar for one values line. Anything outside it is
# REFUSED rather than skipped — see `parse_values_block`.
VALUES_LINE = re.compile(
    r'^(?P<indent> *)(?P<key>[A-Za-z][A-Za-z0-9]*):'
    r'(?:[ ](?P<value>""|\[\]|[A-Za-z0-9][A-Za-z0-9._/:@+-]*))?$'
)
CLAIM_VOLUME_LINE = re.compile(
    r'^\s*(?:-\s+)?(?:persistentVolumeClaim|ephemeral|csi):\s*$', re.MULTILINE
)


def unique_object(pairs):
    """Reject duplicate JSON keys instead of silently accepting the last one."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def read_file(root: Path, relative: Path) -> bytes:
    """The closed file set contains ordinary files inside this checkout only."""
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise ValueError("required ordinary file is missing")
    for parent in path.parents:
        if parent == root:
            break
        if parent.is_symlink():
            raise ValueError("symbolic manifest directory")
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("file escaped the repository")
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("configuration file exceeds its bound")
    return path.read_bytes()


def normalized_manifest(payload: bytes, source: bool, pending: bool = False) -> tuple[bytes, str, str]:
    """Only chart version and digest vary during a routine promotion.

    All other non-comment manifest bytes are bound to the reviewed initial
    composition. This denies extra fields and objects without a permissive YAML
    parser; structural changes require independent review of the shape policy.

    A PENDING application inverts the digest rule rather than relaxing it: the
    sentinel is the only admissible value, so the placeholder cannot quietly
    become a real selection outside the reviewed promotion.
    """
    text = payload.decode("utf-8")
    version = digest = ""
    if source:
        versions, digests = VERSION_LINE.findall(text), DIGEST_LINE.findall(text)
        if len(versions) != 1 or len(digests) != 1:
            raise ValueError("selection must have one version and one digest")
        version, digest = versions[0], digests[0]
        if artifacts.VERSION_RE.fullmatch(version) is None:
            raise ValueError("invalid or unresolved chart selection")
        if pending:
            if digest != SENTINEL_DIGEST:
                raise ValueError("pending application must select the sentinel digest")
        elif digest == SENTINEL_DIGEST:
            raise ValueError("invalid or unresolved chart selection")
        text = VERSION_LINE.sub('    platform.snaraj.dev/chart-release: "VERSION"', text)
        text = DIGEST_LINE.sub('    digest: DIGEST', text)
    normalized = "\n".join(line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#"))
    return normalized.encode(), version, digest


def publisher_subject(repository: str) -> str:
    """The anchored cosign subject for one application repository's publisher.

    Dots are escaped because the subject is a REGULAR EXPRESSION in the
    manifest, and an unescaped dot in `naranjo.online` would match any
    character — `naranjoXonline` would verify. The anchors are what stop a
    look-alike host or a longer path from matching at all.
    """
    escaped = repository.replace(".", r"\.")
    return (
        r"^https://github\.com/" + escaped
        + r"/\.github/workflows/release-publisher\.yml@refs/heads/main$"
    )


def identity_errors(payload: bytes, slug: str, repository: str) -> None:
    """Bind the declared application repository to the manifest's own bytes.

    Without this the map value is decoration: replacing it with
    `foreign-publisher` changed nothing any check read, because the receipt
    comparison that consumes it is skipped for a pending application and the
    byte pins are computed FROM the file rather than from the declaration.

    It runs AFTER the byte pins deliberately, so it reports only what those
    pins cannot see. A manifest edited alone already fails the pin. The case
    this catches is the one that gets past it: a substituted chart repository
    or publisher subject committed TOGETHER with a re-pinned hash, which is
    self-consistent bytes and a lie about which repository publishes this
    application. The expected URL is derived from the SLUG and the expected
    publisher from the map VALUE, so both halves of a declaration are load
    bearing and neither can be a comment.
    """
    text = payload.decode("utf-8")
    if URL_LINE.findall(text) != ["oci://ghcr.io/snaraj/charts/" + slug]:
        raise ValueError("chart repository is not the declared application identity")
    if SUBJECT_LINE.findall(text) != [publisher_subject("snaraj/" + repository)]:
        raise ValueError("publisher identity is not the declared application repository")


def parse_values_block(text: str) -> set[str]:
    """Return every key in `spec.values`, or refuse the block outright.

    This gate has no YAML parser: `make check` runs stdlib Python and invokes
    neither helm nor yq, so there is nothing here that reads the document the
    way its consumer does. A scanner that guesses at YAML is exactly how the
    previous two versions of this guard were bypassed — first by a quoted key,
    then by tags, complex keys, escapes and flow collections. So this does not
    guess. It admits a CLOSED grammar and REFUSES everything else, including
    forms that are perfectly valid YAML:

      * keys are bare `[A-Za-z][A-Za-z0-9]*` — no quoting, no tag, no `?`
        complex key, no escape, so `"replicas"`, `"replic\x61s"` and
        `!!str replicas` are refused rather than normalised and possibly
        normalised wrongly;
      * values are a nested mapping, one plain scalar, `""`, or `[]` — no flow
        collection, no anchor, no alias, no block scalar, no inline comment;
      * indentation is exactly two spaces per level.

    Refusing a valid form is the acceptable failure here: a composition that
    needs one says so in review, and the alternative is a guard that reads a
    document differently from the controller that will act on it.
    """
    keys: set[str] = set()
    indents = [2]
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        match = VALUES_LINE.fullmatch(raw)
        if match is None:
            raise ValueError("values block uses a form this gate refuses to guess at")
        indent = len(match.group("indent"))
        if indent % 2 or indent < 4:
            raise ValueError("values block indentation is outside the closed grammar")
        while indents and indent < indents[-1]:
            indents.pop()
        if indent > indents[-1] + 2:
            raise ValueError("values block indentation is outside the closed grammar")
        if indent > indents[-1]:
            indents.append(indent)
        keys.add(match.group("key"))
    return keys


def values_block(text: str) -> str:
    """The `spec.values` block, refusing any spelling of the key but the bare one.

    Quoting the outer key made the block VANISH from the previous scanner while
    the consumer still resolved `.spec.values.replicas`. A missing block is
    therefore not "nothing to check" — it is a release with no values at all, or
    a key spelled a way this gate will not read, and both are refused.
    """
    lines = text.splitlines()
    start = None
    for index, line in enumerate(lines):
        match = SPEC_KEY_LINE.fullmatch(line)
        if match is None:
            continue
        raw = match.group("raw").strip()
        if raw == "values":
            if match.group("rest"):
                raise ValueError("values must open a block mapping")
            start = index + 1
            continue
        if raw.strip("\"'") == "values" or raw.endswith("values"):
            raise ValueError("values key must be spelled bare, without quoting or a tag")
    if start is None:
        raise ValueError("release has no spec.values block")
    body = []
    for line in lines[start:]:
        if line.strip() and not line.startswith("    ") and not line.lstrip().startswith("#"):
            break
        body.append(line)
    return "\n".join(body)


def single_writer_errors(payload: bytes) -> None:
    """No composition value may ask a single-writer workload for a second Pod.

    `ReadWriteOnce` is node exclusion, not Pod exclusion, so this is not the
    writer boundary — it is the one part of that boundary this repository can
    hold: no values block may ASK for a second Pod, at any depth of the parsed
    mapping.

    Keys are compared case-folded, which is deliberately BROADER than the YAML
    lookup the consumer performs: `REPLICAS` is a different key to Helm and
    would not be read, but no reviewed chart here has two values keys differing
    only in case, so a near-miss spelling is refused rather than reasoned about.
    """
    keys = {key.casefold() for key in parse_values_block(values_block(payload.decode("utf-8")))}
    if keys & SECOND_POD_KEYS:
        raise ValueError("composition must not set a replica count or rollout strategy")


def pending_release_errors(payload: bytes) -> None:
    """A pending application deploys nothing, stated as its own refusal.

    The byte pins would already reject an edit here, but they would reject it as
    "changes the reviewed application boundary" — which is true of a comment fix
    too. This names the property, so a release unsuspended while its selection
    is still a placeholder fails for the reason it actually fails.
    """
    text = payload.decode("utf-8")
    if SUSPEND_LINE.findall(text) != ["true"] or READY_LINE.findall(text) != ["false"]:
        raise ValueError("pending application release must be suspended and not ready")


def storage_activation_errors(payload: bytes) -> None:
    """Application composition never activates storage."""
    text = payload.decode("utf-8")
    if STORAGE_KIND_LINE.search(text) or CLAIM_VOLUME_LINE.search(text):
        raise ValueError("application composition must not activate storage")


def check(root: Path = ROOT) -> tuple[dict, dict]:
    """Validate inventory, all fixed manifest fields and receipt bindings."""
    shapes = json.loads(read_file(root, Path("policies/manifest-shapes.json")), object_pairs_hook=unique_object)
    inventory = {**APPLICATIONS, **PENDING_APPLICATIONS}
    if set(APPLICATIONS) & set(PENDING_APPLICATIONS):
        raise ValueError("an application cannot be active and pending at once")
    expected = {f"kubernetes/websites/{slug}/{name}" for slug in inventory for name in FILES}
    if set(shapes) != expected:
        raise ValueError("manifest shape policy has an unexpected file set")
    tree = root / "kubernetes"
    if tree.is_symlink():
        raise ValueError("symbolic manifest root")
    observed = {p.relative_to(root).as_posix() for p in tree.rglob("*") if p.is_file() or p.is_symlink()}
    if observed != expected:
        raise ValueError("application manifest inventory is not exact")
    selections = {}
    for relative in sorted(expected):
        path = Path(relative)
        slug = path.parent.name
        pending = slug in PENDING_APPLICATIONS
        payload = read_file(root, path)
        storage_activation_errors(payload)
        if path.name == "release.yaml":
            single_writer_errors(payload)
        if pending and path.name == "release.yaml":
            pending_release_errors(payload)
        normalized, version, digest = normalized_manifest(
            payload, path.name == "source.yaml", pending
        )
        if hashlib.sha256(normalized).hexdigest() != shapes[relative]:
            raise ValueError("manifest changes the reviewed application boundary")
        if path.name == "source.yaml":
            identity_errors(payload, slug, inventory[slug])
        if version and not pending:
            repository = f"snaraj/{APPLICATIONS[slug]}"
            selections[slug] = artifacts.Selection(
                slug, relative, version, digest, f"ghcr.io/snaraj/charts/{slug}",
                repository, f"https://github.com/{repository}/.github/workflows/release-publisher.yml@refs/heads/main")
    payload = read_file(root, RECEIPT)
    receipt = json.loads(payload, object_pairs_hook=unique_object)
    if set(receipt) != {"capturedDate", "chartLayerMediaType", "records", "schema", "tools"}:
        raise ValueError("receipt fields are not exact")
    tools = receipt.get("tools")
    tool_versions_are_closed = (
        isinstance(tools, dict)
        and set(tools) == {"cosign", "oras"}
        and all(isinstance(value, str) and artifacts.VERSION_RE.fullmatch(value)
                for value in tools.values())
    )
    if (receipt["schema"] != "dev.snaraj.chart-acquisition-receipt/v2"
            or receipt["chartLayerMediaType"] != artifacts.HELM_LAYER
            or not tool_versions_are_closed
            or set(receipt["records"]) != set(APPLICATIONS)):
        raise ValueError("receipt authority is not exact")
    if datetime.date.fromisoformat(receipt["capturedDate"]).isoformat() != receipt["capturedDate"]:
        raise ValueError("capture date is not canonical")
    if artifacts.render_receipt_json(receipt).encode() != payload:
        raise ValueError("receipt bytes are not canonical")
    for slug, selection in selections.items():
        record = receipt["records"][slug]
        validate_record(record, slug, selection)
        if (record["chartTag"] != selection.version or record["manifestDigest"] != selection.digest
                or record["chartRepository"] != selection.chart_repository
                or record["signer"] != {"issuer": artifacts.ACTIONS_ISSUER, "subject": selection.subject}):
            raise ValueError("receipt and manifest identity disagree")
    return selections, receipt


def validate_record(record: dict, slug: str, selection) -> None:
    """Close the complete receipt schema before any network acquisition."""
    keys = {"arm64Digest", "chart", "chartConfigDigest", "chartLayerDigest",
            "chartRepository", "chartTag", "manifestDigest", "matchingChartLayerCount",
            "release", "signer", "workloadImage"}
    if not isinstance(record, dict) or set(record) != keys:
        raise ValueError("receipt record fields are not exact")
    def digest(value):
        return (isinstance(value, str) and artifacts.DIGEST_RE.fullmatch(value)
                and value != "sha256:" + "0" * 64)
    if any(not digest(record[key]) for key in
           ("arm64Digest", "chartConfigDigest", "chartLayerDigest", "manifestDigest")):
        raise ValueError("receipt digest is malformed")
    if (type(record["matchingChartLayerCount"]) is not int
            or record["matchingChartLayerCount"] != 1
            or record["chart"] != {"name": slug, "version": selection.version, "appVersion": selection.version}):
        raise ValueError("receipt chart identity is malformed")
    release = record["release"]
    if (not isinstance(release, dict) or set(release) != {"assetDigest", "sourceSha"}
            or not digest(release["assetDigest"])
            or not isinstance(release["sourceSha"], str)
            or artifacts.SHA_RE.fullmatch(release["sourceSha"]) is None
            or release["sourceSha"] == "0" * 40):
        raise ValueError("receipt release identity is malformed")
    prefix = f"ghcr.io/snaraj/{slug}:v{selection.version}@"
    image = record["workloadImage"]
    if not isinstance(image, str) or not image.startswith(prefix) or not digest(image[len(prefix):]):
        raise ValueError("receipt workload image is malformed")


def verify(root: Path = ROOT, registry=None, github=None, cosign=None) -> None:
    """Reproduce every acquisition record from the independently pinned source."""
    selections, receipt = check(root)
    registry = registry or artifacts.Registry()
    github = github or artifacts.GitHub()
    cosign = cosign or artifacts.Cosign(pinned_version="v3.1.3")
    for slug, selection in selections.items():
        record, _inspection = artifacts.acquire(selection, selection.version, registry, github, cosign)
        if record != receipt["records"][slug]:
            raise ValueError("fresh acquisition does not reproduce the committed receipt")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "verify"))
    args = parser.parse_args()
    try:
        if args.command == "verify":
            verify()
        else:
            check()
        print("ARTIFACT_VERIFICATION=PASS" if args.command == "verify" else "APPLICATION_BOUNDARY=PASS")
        return 0
    except (OSError, ValueError, KeyError, TypeError, artifacts.Refusal) as error:
        print(f"APPLICATION_CHECK=DENY reason={type(error).__name__}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
