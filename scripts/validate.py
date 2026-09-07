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
        if pending and path.name == "release.yaml":
            pending_release_errors(payload)
        normalized, version, digest = normalized_manifest(
            payload, path.name == "source.yaml", pending
        )
        if hashlib.sha256(normalized).hexdigest() != shapes[relative]:
            raise ValueError("manifest changes the reviewed application boundary")
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
