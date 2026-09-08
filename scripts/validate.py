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
# The namespace each application composes into. `obsync` is the one slug whose
# namespace is not its own name: the owner's `obsidian` namespace may later hold
# other Obsidian-related workloads, and nothing about this application is
# derived from it. Envelope closure below reads this map, so it cannot rot.
NAMESPACES = {"lidersea-com": "lidersea-com", "naranjo-online": "naranjo-online",
              "obsync": "obsidian"}
HELM_CHART_MEDIA_TYPE = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"
# The exact object each file must name: API version, kind, `metadata.name`
# template, the complete set of top-level keys, and the complete set of `spec`
# keys. Both sets are equality, not containment, because a HelmRelease can ask
# for a second Pod with no values key at all — `postRenderers` patching the
# rendered Deployment, `valuesFrom` reading a ConfigMap this file set does not
# hold, `targetNamespace` moving the release out of its namespace — and the
# same shape holds for the other three kinds. A file that carries anything else
# is refused before a single field inside it is read.
ENVELOPES = {
    "kustomization.yaml": ("kustomize.config.k8s.io/v1beta1", "Kustomization", None,
                           frozenset({"apiVersion", "kind", "resources"}), None, {}),
    "default-deny.yaml": ("networking.k8s.io/v1", "NetworkPolicy", "default-deny",
                          frozenset({"apiVersion", "kind", "metadata", "spec"}),
                          frozenset({"podSelector", "policyTypes"}), {}),
    "source.yaml": ("source.toolkit.fluxcd.io/v1", "OCIRepository", "{slug}-chart",
                    frozenset({"apiVersion", "kind", "metadata", "spec"}),
                    frozenset({"interval", "layerSelector", "ref", "timeout", "url", "verify"}),
                    {"ref": (frozenset({"digest"}), {}),
                     "layerSelector": (frozenset({"mediaType", "operation"}),
                                       {"mediaType": HELM_CHART_MEDIA_TYPE,
                                        "operation": "copy"})}),
    "release.yaml": ("helm.toolkit.fluxcd.io/v2", "HelmRelease", "{slug}",
                     frozenset({"apiVersion", "kind", "metadata", "spec"}),
                     frozenset({"chartRef", "driftDetection", "install", "interval",
                                "maxHistory", "releaseName", "serviceAccountName",
                                "suspend", "upgrade", "values"}),
                     {"chartRef": (frozenset({"kind", "name"}),
                                   {"kind": "OCIRepository", "name": "{slug}-chart"})}),
}
# The three fetch-path fields, closed by exact key set and exact value. The
# values path is closed by the grammar and the identity path by the identity
# binding; this is what a substitution committed WITH a re-pinned shape hash
# could still move — a `tag` or `semver` beside the digest, a layer selector
# that no longer selects a chart, a chartRef pointed at another namespace.
RESOURCE_ENTRY = re.compile(r'^  - (?P<name>[a-z0-9-]+\.yaml)$')
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
# The closed file set closes FILES, not YAML objects, so until a file is closed
# to one document naming one expected object, every field read below can be
# answered by a decoy the consumer never reads. These four close it in that
# order: document, envelope, then values.
DOCUMENT_BREAK = re.compile(r'^(?:---|\.\.\.)')
KEY_LINE = re.compile(r'^(?P<indent> *)(?P<key>[^\s#][^:]*?)\s*:\s*(?P<rest>.*)$')
BARE_KEY = re.compile(r'[A-Za-z][A-Za-z0-9]*')
BARE_SCALAR = re.compile(r'[A-Za-z0-9][A-Za-z0-9._/-]*')
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


def closed_document(text: str) -> list[tuple[int, str]]:
    """One YAML document per allowed file, numbered for the refusals below.

    The inventory closes FILES. A file may still hold any number of documents,
    and a review that reads the first one is answering about a different object
    from the controller that reconciles the last. A two-document release whose
    real HelmRelease spells its outer key `"values"` and whose decoy holds the
    only bare `values:` block is accepted by every field-level guard and rejected
    by this one, so this runs before any field is read.
    """
    numbered = []
    for number, raw in enumerate(text.splitlines(), 1):
        if raw.startswith("%"):
            raise ValueError(f"line {number}: a YAML directive is outside the closed document form")
        if DOCUMENT_BREAK.match(raw):
            raise ValueError(f"line {number}: an allowed file holds exactly one YAML document")
        numbered.append((number, raw))
    return numbered


def block_body(numbered: list[tuple[int, str]], opener: int, indent: int) -> list[tuple[int, str]]:
    """The lines strictly inside the block opened at line `opener`."""
    body, started = [], False
    for number, raw in numbered:
        if number == opener:
            started = True
            continue
        if not started:
            continue
        if not raw.strip() or raw.lstrip().startswith("#"):
            body.append((number, raw))
            continue
        if len(raw) - len(raw.lstrip(" ")) <= indent:
            break
        body.append((number, raw))
    return body


def bare_keys(numbered: list[tuple[int, str]], indent: int, where: str) -> dict[str, tuple[int, str]]:
    """Every key at one depth, refusing any spelling that is not bare."""
    found: dict[str, tuple[int, str]] = {}
    for number, raw in numbered:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if len(raw) - len(raw.lstrip(" ")) != indent:
            continue
        match = KEY_LINE.fullmatch(raw)
        if match is None:
            raise ValueError(f"line {number}: {where} holds a form this gate refuses to read")
        key = match.group("key")
        if BARE_KEY.fullmatch(key) is None:
            raise ValueError(f"line {number}: {where} key is not a bare, unquoted, untagged spelling")
        if key in found:
            raise ValueError(f"line {number}: duplicate {where} key {key}")
        found[key] = (number, match.group("rest"))
    return found


def sole_key(numbered: list[tuple[int, str]], wanted: str) -> None:
    """`wanted` appears once in the file, at any depth and however it is spelled."""
    seen = []
    for number, raw in numbered:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        match = KEY_LINE.fullmatch(raw)
        if match is None:
            continue
        key = match.group("key").strip()
        if key.startswith("!") and " " in key:
            key = key.split(None, 1)[1]
        if key.strip("\"'").lstrip("?").strip() == wanted:
            seen.append(number)
    if len(seen) != 1:
        raise ValueError(f"file must hold exactly one {wanted} key, found {len(seen)}")


def manifest_envelope(payload: bytes, name: str, slug: str) -> list[tuple[int, str]] | None:
    """Close the document and its envelope; return the `spec` block, if any.

    Closure runs outside in — one document, then the exact top-level keys, then
    the exact GVK, name and namespace the inventory expects for this file —
    because each step is what makes the next one meaningful. A decoy object is
    refused here for naming the wrong thing, not later for holding the wrong
    field, and the values guard below is reachable only through this function.
    """
    api_version, kind, name_template, top_keys, spec_keys, fetch_fields = ENVELOPES[name]
    numbered = closed_document(payload.decode("utf-8"))
    top: dict[str, tuple[int, str]] = {}
    for number, raw in numbered:
        if not raw.strip() or raw.lstrip().startswith("#") or raw.startswith(" "):
            continue
        match = KEY_LINE.fullmatch(raw)
        if match is None:
            raise ValueError(f"line {number}: top level is not a key")
        key = match.group("key")
        if BARE_KEY.fullmatch(key) is None:
            raise ValueError(f"line {number}: top-level key is not a bare, unquoted, untagged spelling")
        if key in top:
            raise ValueError(f"line {number}: duplicate top-level key {key}")
        top[key] = (number, match.group("rest"))
    if set(top) != top_keys:
        raise ValueError(f"{name} does not carry the exact top-level keys of a {kind}")
    if top["apiVersion"][1] != api_version or top["kind"][1] != kind:
        raise ValueError(f"{name} does not name a {api_version} {kind}")
    if name_template is None:
        listed = []
        for number, raw in block_body(numbered, top["resources"][0], 0):
            if not raw.strip() or raw.lstrip().startswith("#"):
                continue
            entry = RESOURCE_ENTRY.fullmatch(raw)
            if entry is None:
                raise ValueError(f"line {number}: resources entry is not a composed manifest of this application")
            listed.append(entry.group("name"))
        if tuple(listed) != FILES[1:]:
            raise ValueError(f"{name} does not compose exactly the other files of this application")
        return None
    sole_key(numbered, "spec")
    if top["metadata"][1] or top["spec"][1]:
        raise ValueError(f"{name} metadata and spec must open block mappings")
    fields = bare_keys(block_body(numbered, top["metadata"][0], 0), 2, "metadata")
    expected = (name_template.format(slug=slug), NAMESPACES[slug])
    observed = (fields.get("name", (0, ""))[1], fields.get("namespace", (0, ""))[1])
    if any(BARE_SCALAR.fullmatch(value) is None for value in observed) or observed != expected:
        raise ValueError(f"{name} does not name {expected[1]}/{expected[0]}")
    spec_lines = block_body(numbered, top["spec"][0], 0)
    declared = bare_keys(spec_lines, 2, "spec")
    for key in sorted(set(declared) - spec_keys):
        raise ValueError(f"line {declared[key][0]}: {key} is not a spec key of the reviewed {kind}")
    if spec_keys - set(declared):
        missing = ", ".join(sorted(spec_keys - set(declared)))
        raise ValueError(f"{name} is missing spec keys of the reviewed {kind}: {missing}")
    for key, (fields, constants) in fetch_fields.items():
        observed = bare_keys(block_body(spec_lines, declared[key][0], 2), 4, f"spec.{key}")
        for extra in sorted(set(observed) - fields):
            raise ValueError(f"line {observed[extra][0]}: {extra} is not a spec.{key} field of the reviewed {kind}")
        if fields - set(observed):
            missing = ", ".join(sorted(fields - set(observed)))
            raise ValueError(f"{name} is missing spec.{key} fields of the reviewed {kind}: {missing}")
        for field, constant in constants.items():
            wanted = constant.format(slug=slug)
            if observed[field][1] != wanted:
                raise ValueError(f"line {observed[field][0]}: spec.{key}.{field} is not the reviewed {wanted}")
    return spec_lines


def values_body(spec_lines: list[tuple[int, str]]) -> list[tuple[int, str]]:
    """The `values` block, read only as the bare two-space key of the closed spec.

    The predecessor scanned the whole file for a bare `values:` and kept the
    first one it liked, which bound the guard to no object at all.
    """
    keys = bare_keys(spec_lines, 2, "spec")
    if "values" not in keys:
        raise ValueError("release has no bare spec.values block")
    opener, rest = keys["values"]
    if rest:
        raise ValueError(f"line {opener}: values must open a block mapping")
    return block_body(spec_lines, opener, 2)


def parse_values_block(body: list[tuple[int, str]]) -> set[str]:
    """Return every key in `spec.values`, or refuse the block outright.

    This gate has no YAML parser: `make check` runs stdlib Python and invokes
    neither helm nor yq, so there is nothing here that reads the document the
    way its consumer does. A scanner that guesses at YAML is exactly how the
    earlier versions of this guard were bypassed — a quoted key, then tags,
    complex keys, escapes and flow collections. So this does not guess. It
    admits a CLOSED grammar and REFUSES everything else, including forms that
    are perfectly valid YAML:

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
    for number, raw in body:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        match = VALUES_LINE.fullmatch(raw)
        if match is None:
            raise ValueError(f"line {number}: values block uses a form this gate refuses to guess at")
        indent = len(match.group("indent"))
        if indent % 2 or indent < 4:
            raise ValueError(f"line {number}: values block indentation is outside the closed grammar")
        while indents and indent < indents[-1]:
            indents.pop()
        if indent > indents[-1] + 2:
            raise ValueError(f"line {number}: values block indentation is outside the closed grammar")
        if indent > indents[-1]:
            indents.append(indent)
        keys.add(match.group("key"))
    return keys


def single_writer_errors(payload: bytes, spec_lines: list[tuple[int, str]]) -> None:
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
    sole_key(closed_document(payload.decode("utf-8")), "values")
    keys = {key.casefold() for key in parse_values_block(values_body(spec_lines))}
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
        # Before closure, deliberately: this is a deny-if-present scan over raw
        # bytes, and extra documents can only ADD matches to it, never hide one.
        storage_activation_errors(payload)
        spec_lines = manifest_envelope(payload, path.name, slug)
        if path.name == "release.yaml":
            single_writer_errors(payload, spec_lines)
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
