"""Exercise the extracted acquisition checks with byte-derived artifact fixtures."""
from __future__ import annotations

import base64
import gzip
import hashlib
import importlib.util
import io
import json
import re
import tarfile
import unittest
from pathlib import Path

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("artifacts", root / "scripts/artifacts.py")
MODULE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MODULE)
SUBJECT = "https://github.com/snaraj/naranjo.online/.github/workflows/release-publisher.yml@refs/heads/main"

def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class FakeFleet:
    """One workload's registry, Release and cosign answers, all derived from
    bytes. ``perturb`` hooks let a test change exactly one answer."""

    def __init__(self, slug="naranjo-online", site="snaraj/naranjo.online", version="0.1.71", schema="naranjo"):
        self.slug, self.site, self.version, self.schema = slug, site, version, schema
        self.chart_repo = f"ghcr.io/snaraj/charts/{slug}"
        self.image_repo = f"ghcr.io/snaraj/{slug}"
        self.subject = f"https://github.com/{site}/.github/workflows/release-publisher.yml@refs/heads/main"
        self.source_sha = hashlib.sha1(f"{site} {version}".encode()).hexdigest()
        self.tag_object_sha = hashlib.sha1(f"tag {version}".encode()).hexdigest()
        self.calls = []
        self.manifest_answers = {}
        self.blobs = {}
        self.gh = {}
        self.downloads = {}
        # A mutation that changes chart bytes sets one of these and rebuilds,
        # so every digest downstream of the change is re-derived honestly.
        self.overrides = {}
        self.build()

    # -- construction ------------------------------------------------------
    def build(self):
        amd64 = json.dumps({"schemaVersion": 2, "layers": [{"digest": "sha256:" + "1" * 64}]}).encode()
        arm64 = json.dumps({"schemaVersion": 2, "layers": [{"digest": "sha256:" + "2" * 64}]}).encode()
        self.arm64_digest = sha(arm64)
        self.index_children = self.overrides.get(
            "index_children",
            [
                {"mediaType": MODULE.OCI_MANIFEST, "digest": sha(amd64), "platform": {"os": "linux", "architecture": "amd64"}},
                {"mediaType": MODULE.OCI_MANIFEST, "digest": self.arm64_digest, "platform": {"os": "linux", "architecture": "arm64"}},
                {"mediaType": MODULE.OCI_MANIFEST, "digest": "sha256:" + "3" * 64, "platform": {"os": "unknown", "architecture": "unknown"}},
            ],
        )
        self.index_bytes = json.dumps({"schemaVersion": 2, "mediaType": MODULE.OCI_INDEX, "manifests": self.index_children}).encode()
        self.index_digest = sha(self.index_bytes)
        self.chart_yaml = self.overrides.get(
            "chart_yaml",
            (
                f"apiVersion: v2\nappVersion: {self.version}\ndescription: test\nname: {self.slug}\n"
                f"type: application\nversion: {self.version}\n"
            ).encode(),
        )
        self.values_yaml = (
            "replicaCount: 1\n\nimage:\n"
            f"  repository: {self.image_repo}\n  # the published tag\n  tag: v{self.version}\n"
            f"  digest: {self.overrides.get('values_digest', self.index_digest)}\n  pullPolicy: IfNotPresent\n\nservice:\n  port: 8080\n"
        ).encode()
        self.layer_bytes = self.overrides.get("layer_bytes") or self.tar({f"{self.slug}/Chart.yaml": self.chart_yaml, f"{self.slug}/values.yaml": self.values_yaml})
        self.layer_digest = sha(self.layer_bytes)
        self.config_bytes = json.dumps(
            {"name": self.slug, "version": self.version, "apiVersion": "v2", "appVersion": self.version, "type": "application"}
        ).encode()
        self.config_digest = sha(self.config_bytes)
        self.layers = [{"mediaType": MODULE.HELM_LAYER, "digest": self.layer_digest, "size": len(self.layer_bytes)}]
        self.manifest_bytes = json.dumps(
            {
                "schemaVersion": 2,
                "config": {"mediaType": MODULE.HELM_CONFIG, "digest": self.config_digest, "size": len(self.config_bytes)},
                "layers": self.layers,
            }
        ).encode()
        self.manifest_digest = sha(self.manifest_bytes)
        self.asset_bytes = json.dumps(self.release_manifest()).encode()
        self.asset_digest = sha(self.asset_bytes)
        self.asset_url = f"https://github.com/{self.site}/releases/download/v{self.version}/release-manifest.json"
        self.blobs = {
            (self.chart_repo, self.config_digest): self.config_bytes,
            (self.chart_repo, self.layer_digest): self.layer_bytes,
        }
        self.manifest_answers = {
            (self.chart_repo, self.version, MODULE.OCI_MANIFEST): (self.manifest_bytes, self.manifest_digest),
            (self.image_repo, f"v{self.version}", MODULE.OCI_INDEX): (self.index_bytes, self.index_digest),
        }
        self.gh = {
            f"repos/{self.site}/releases/tags/v{self.version}": {
                "immutable": True,
                "draft": False,
                "prerelease": False,
                "assets": [{"name": "release-manifest.json", "digest": self.asset_digest, "browser_download_url": self.asset_url}],
            },
            f"repos/{self.site}/git/ref/tags/v{self.version}": {"object": {"type": "tag", "sha": self.tag_object_sha}},
            f"repos/{self.site}/git/tags/{self.tag_object_sha}": {
                "tag": f"v{self.version}",
                "object": {"type": "commit", "sha": self.source_sha},
            },
            f"repos/{self.site}/compare/main...{self.source_sha}": {"status": "behind"},
        }
        self.downloads = {self.asset_url: self.asset_bytes}

    def release_manifest(self):
        if self.schema == "lidersea":
            return {
                "schema": "lidersea.release-manifest/v1",
                "repository": self.site,
                "tag": f"v{self.version}",
                "version": self.version,
                "workflow_identity": self.subject,
                "source_sha": self.source_sha,
                "artifacts": {
                    "chart": {"registry": self.chart_repo, "digest": self.manifest_digest, "signature": {"certificate_identity": self.subject, "oidc_issuer": MODULE.ACTIONS_ISSUER, "required": True}},
                    "image": {"registry": self.image_repo, "digest": self.index_digest, "signature": {"certificate_identity": self.subject, "oidc_issuer": MODULE.ACTIONS_ISSUER, "required": True}},
                },
            }
        return {
            "schema": "https://naranjo.online/schemas/release-manifest/v1",
            "repository": self.site,
            "release": {"tag": f"v{self.version}", "version": self.version},
            "publisher": {"workflow": ".github/workflows/release-publisher.yml", "ref": "refs/heads/main"},
            "source_sha": self.source_sha,
            "artifacts": {
                "chart": {"repository": self.chart_repo, "tag": self.version, "digest": self.manifest_digest, "signature_identity": self.subject},
                "image": {"repository": self.image_repo, "tag": f"v{self.version}", "digest": self.index_digest, "signature_identity": self.subject, "platforms": ["linux/amd64", "linux/arm64"]},
            },
        }

    @staticmethod
    def tar(members: dict) -> bytes:
        return hostile_tar([(name, data, tarfile.REGTYPE) for name, data in members.items()])

    # -- transports --------------------------------------------------------
    def fetch(self, url, headers, limit):
        self.calls.append(("fetch", url))
        # The distribution API takes the repository PATH; a host-qualified
        # name in the URL or the token scope is the real registry's 404.
        if url.startswith("https://ghcr.io/token?"):
            if "repository:ghcr.io/" in url:
                raise MODULE.Refusal(f"fake registry: host-qualified token scope {url}")
            return b'{"token": "anonymous-pull"}', {}
        if url.startswith("https://ghcr.io/v2/ghcr.io/"):
            raise MODULE.Refusal(f"fake registry: host-qualified repository path {url}")
        match = re.match(r"https://ghcr\.io/v2/(snaraj/[a-z0-9/-]+)/manifests/([^/]+)$", url)
        if match:
            key = ("ghcr.io/" + match.group(1), match.group(2), headers.get("Accept"))
            if key not in self.manifest_answers:
                raise MODULE.Refusal(f"fake registry: no manifest for {key}")
            body, header = self.manifest_answers[key]
            return body, {"docker-content-digest": header}
        match = re.match(r"https://ghcr\.io/v2/(snaraj/[a-z0-9/-]+)/blobs/(sha256:[0-9a-f]{64})$", url)
        if match:
            return self.blobs[("ghcr.io/" + match.group(1), match.group(2))], {}
        if url in self.downloads:
            return self.downloads[url], {}
        raise AssertionError(f"unexpected fetch {url}")

    def run(self, argv, cwd=None, input_text=None, env=None, timeout=None):
        self.calls.append(("run", tuple(argv)))
        if argv[:2] == ["gh", "api"]:
            path = argv[-1] if "--input" not in argv else argv[argv.index("--input") - 1]
            path = [a for a in argv if not a.startswith("-") and a not in ("gh", "api", "GET", "POST", "PATCH", "DELETE", "Accept: application/vnd.github+json")][-1]
            if path not in self.gh:
                raise MODULE.Refusal(f"`gh api {path}` exited 1: gh: Not Found (HTTP 404)")
            answer = self.gh[path]
            if isinstance(answer, Exception):
                raise answer
            return json.dumps(answer)
        if argv[:3] == ["cosign", "version", "--json"]:
            return json.dumps({"gitVersion": "v3.1.3"})
        if argv[:2] == ["cosign", "verify"]:
            digest = argv[-1].split("@", 1)[1]
            return json.dumps([{"critical": {"image": {"docker-manifest-digest": digest}, "identity": {"docker-reference": argv[-1]}}, "optional": {}}])
        if argv[:2] == ["cosign", "verify-attestation"]:
            digest = argv[-1].split("@", 1)[1]
            statement = {"_type": "https://in-toto.io/Statement/v0.1", "subject": [{"name": argv[-1].split("@")[0], "digest": {"sha256": digest.split(":")[1]}}], "predicateType": MODULE.SLSA_V1, "predicate": {}}
            envelope = {"payloadType": MODULE.IN_TOTO, "payload": base64.b64encode(json.dumps(statement).encode()).decode(), "signatures": []}
            return json.dumps(envelope) + "\n" + json.dumps(envelope) + "\n"
        raise AssertionError(f"unexpected command {argv}")

    def registry(self):
        return MODULE.Registry(fetch=self.fetch)

    def github(self):
        return MODULE.GitHub(run=self.run, fetch=self.fetch)

    def cosign(self):
        return MODULE.Cosign(run=self.run, pinned_version="v3.1.3")

    def selection(self, committed="0.1.69"):
        return MODULE.Selection(self.slug, f"kubernetes/websites/{self.slug}/source.yaml", committed, "sha256:" + "0" * 64, self.chart_repo, self.site, self.subject)

    def acquire(self):
        return MODULE.acquire(self.selection(), self.version, self.registry(), self.github(), self.cosign())

    def expected_record(self):
        return {
            "arm64Digest": self.arm64_digest,
            "chart": {"appVersion": self.version, "name": self.slug, "version": self.version},
            "chartConfigDigest": self.config_digest,
            "chartLayerDigest": self.layer_digest,
            "chartRepository": self.chart_repo,
            "chartTag": self.version,
            "manifestDigest": self.manifest_digest,
            "matchingChartLayerCount": 1,
            "release": {"assetDigest": self.asset_digest, "sourceSha": self.source_sha},
            "signer": {"issuer": MODULE.ACTIONS_ISSUER, "subject": self.subject},
            "workloadImage": f"{self.image_repo}:v{self.version}@{self.index_digest}",
        }


class ObsSyncFleet(FakeFleet):
    """Producer-shaped metadata; native payloads are never installed or fetched."""
    def __init__(self, version="0.1.11"):
        self.native = tuple(map(int, version.split("."))) > (0, 1, 10)
        self.release_tag = version if self.native else "v" + version
        self.native_files = {
            "main.js": (b"synthetic script", "application/javascript"),
            "manifest.json": (json.dumps({"id": "obsync", "version": version}).encode(), "application/json"),
            "styles.css": (b"synthetic style", "text/css"),
        }
        super().__init__("obsync", "snaraj/obsync", version, "obsync")

    def release_manifest(self):
        result = super().release_manifest()
        result["schema"] = "https://github.com/snaraj/obsync/schemas/release-manifest/v" + ("2" if self.native else "1")
        result["release"]["tag"] = self.release_tag
        result["artifacts"]["plugin_bundle"] = {
            "name": f"obsync-plugin-{self.release_tag}.zip", "digest": sha(b"synthetic bundle"),
            "contents": ["main.js", "manifest.json", "styles.css"],
        }
        if self.native:
            result["artifacts"]["plugin_files"] = {name: {
                "digest": sha(body), "size": len(body), "content_type": content_type,
            } for name, (body, content_type) in self.native_files.items()}
        return result

    def build(self):
        super().build()
        old = "v" + self.version
        self.release = self.gh.pop(f"repos/{self.site}/releases/tags/{old}")
        self.gh[f"repos/{self.site}/releases/tags/{self.release_tag}"] = self.release
        self.gh[f"repos/{self.site}/git/ref/tags/{self.release_tag}"] = self.gh.pop(f"repos/{self.site}/git/ref/tags/{old}")
        self.gh[f"repos/{self.site}/git/tags/{self.tag_object_sha}"]["tag"] = self.release_tag
        self.downloads.pop(self.asset_url)
        name = f"obsync-{self.release_tag}-release-manifest.json"
        self.asset_url = f"https://github.com/{self.site}/releases/download/{self.release_tag}/{name}"
        self.downloads[self.asset_url] = self.asset_bytes
        self.release["assets"] = [{"name": name, "digest": self.asset_digest,
            "browser_download_url": self.asset_url, "size": len(self.asset_bytes),
            "content_type": "application/json", "state": "uploaded"}]
        if self.native:
            artifact = self.release_manifest()["artifacts"]
            records = {artifact["plugin_bundle"]["name"]: {
                "digest": artifact["plugin_bundle"]["digest"], "size": 42, "content_type": "application/zip"},
                **artifact["plugin_files"]}
            for name, record in records.items():
                self.release["assets"].append({**record, "name": name, "state": "uploaded",
                    "browser_download_url": f"https://github.com/{self.site}/releases/download/{self.release_tag}/{name}"})

    def replace_evidence(self, asset, mirror=False):
        self.asset_bytes = json.dumps(asset).encode()
        self.asset_digest = sha(self.asset_bytes)
        self.downloads[self.asset_url] = self.asset_bytes
        self.release["assets"][0].update(digest=self.asset_digest, size=len(self.asset_bytes))
        if mirror:
            for record in self.release["assets"][1:]:
                file = asset["artifacts"].get("plugin_files", {}).get(record["name"])
                if isinstance(file, dict):
                    record.update(file)
                elif record["name"].endswith(".zip"):
                    record["digest"] = asset["artifacts"]["plugin_bundle"]["digest"]


class ObsSyncReleaseTests(unittest.TestCase):
    def test_other_publishers_still_bind_every_stated_image_tag(self):
        for schema in ("naranjo", "lidersea"):
            fleet = FakeFleet(schema=schema); asset = fleet.release_manifest()
            asset["artifacts"]["image"]["tag"] = "v9.9.9"
            body = json.dumps(asset).encode(); fleet.downloads[fleet.asset_url] = body
            fleet.gh[f"repos/{fleet.site}/releases/tags/v{fleet.version}"]["assets"][0]["digest"] = sha(body)
            with self.subTest(schema=schema), self.assertRaisesRegex(MODULE.Refusal, "manifest tag"):
                fleet.acquire()

    def test_tag_parser_requires_plain_versions_and_exact_repository_identity(self):
        for value in (None, 1, "", "v0.1.11", "0.1", "0.01.11", "1.0.0-rc1"):
            with self.subTest(value=value), self.assertRaises(MODULE.Refusal):
                MODULE.github_release_tag("snaraj/obsync", value)
        for repository in ("snaraj/obsync-extra", "other/obsync", "snaraj/naranjo.online", "snaraj/lidersea.com"):
            self.assertEqual(MODULE.github_release_tag(repository, "0.1.11"), "v0.1.11")

    def test_legacy_and_native_versions_bind_distinct_release_and_image_tags(self):
        for version in ("0.1.9", "0.1.10", "0.1.11", "0.1.12", "0.2.0", "1.0.0"):
            with self.subTest(version=version):
                fleet = ObsSyncFleet(version)
                record, _ = fleet.acquire()
                self.assertEqual(record, fleet.expected_record())
                self.assertIn(f":v{version}@", record["workloadImage"])
                requests = [c[1][-1] for c in fleet.calls if c[0] == "run" and c[1][:2] == ("gh", "api")]
                self.assertIn(f"repos/snaraj/obsync/releases/tags/{fleet.release_tag}", requests)
                self.assertIn(f"repos/snaraj/obsync/git/ref/tags/{fleet.release_tag}", requests)
                self.assertEqual([c for c in fleet.calls if c[0] == "fetch" and "/releases/download/" in c[1]], [("fetch", fleet.asset_url)])

    def test_schema_is_version_closed_and_never_falls_back(self):
        for version in ("0.1.10", "0.1.11"):
            for schema in (None, "", "https://naranjo.online/schemas/release-manifest/v1",
                           "https://github.com/snaraj/obsync/schemas/release-manifest/v" + ("2" if version == "0.1.10" else "1")):
                with self.subTest(version=version, schema=schema):
                    fleet = ObsSyncFleet(version); asset = fleet.release_manifest()
                    asset["schema"] = schema; fleet.replace_evidence(asset)
                    with self.assertRaisesRegex(MODULE.Refusal, "evidence schema"):
                        fleet.acquire()

    def test_native_declarations_are_complete_and_closed(self):
        cases = [
            ("plugin_files", None, "file inventory"), ("plugin_files", {}, "file inventory"),
            ("plugin_files", [], "file inventory"), ("plugin_bundle", None, "bundle declaration"),
        ]
        for field, value, reason in cases:
            fleet = ObsSyncFleet(); asset = fleet.release_manifest(); asset["artifacts"][field] = value
            fleet.replace_evidence(asset)
            with self.subTest(field=field, value=value), self.assertRaisesRegex(MODULE.Refusal, reason):
                fleet.acquire()
        for field, value in (("name", "obsync-plugin-v0.1.11.zip"), ("contents", ["main.js"]), ("extra", True)):
            fleet = ObsSyncFleet(); asset = fleet.release_manifest(); asset["artifacts"]["plugin_bundle"][field] = value
            fleet.replace_evidence(asset)
            with self.subTest(bundle=field), self.assertRaisesRegex(MODULE.Refusal, "bundle declaration"):
                fleet.acquire()
        for name in ("main.js", "manifest.json", "styles.css"):
            for rename in (None, "other.js"):
                fleet = ObsSyncFleet(); asset = fleet.release_manifest()
                value = asset["artifacts"]["plugin_files"].pop(name)
                if rename: asset["artifacts"]["plugin_files"][rename] = value
                fleet.replace_evidence(asset)
                with self.subTest(name=name, rename=rename), self.assertRaisesRegex(MODULE.Refusal, "file inventory"):
                    fleet.acquire()

    def test_native_file_and_bundle_metadata_refuses_independent_invalid_values(self):
        for name in ("main.js", "manifest.json", "styles.css"):
            for field, value, reason in (
                ("size", True, "file metadata"), ("size", 1.0, "file metadata"),
                ("size", 0, "file metadata"), ("size", 16 * 1024 * 1024 + 1, "file metadata"),
                ("content_type", "text/plain", "file metadata"), ("extra", True, "file metadata"),
                ("digest", "sha256:" + "0" * 64, "asset digest"), ("digest", "wrong", "asset digest"),
                ("digest", None, "asset digest"),
            ):
                fleet = ObsSyncFleet(); asset = fleet.release_manifest()
                asset["artifacts"]["plugin_files"][name][field] = value
                fleet.replace_evidence(asset, mirror=True)
                with self.subTest(name=name, field=field, value=value), self.assertRaisesRegex(MODULE.Refusal, reason):
                    fleet.acquire()
            for value in (None, [], {"size": 1}):
                fleet = ObsSyncFleet(); asset = fleet.release_manifest()
                asset["artifacts"]["plugin_files"][name] = value; fleet.replace_evidence(asset)
                with self.subTest(name=name, record=value), self.assertRaisesRegex(MODULE.Refusal, "file metadata"):
                    fleet.acquire()
        for value in (None, "wrong", "sha256:" + "0" * 64):
            fleet = ObsSyncFleet(); asset = fleet.release_manifest()
            asset["artifacts"]["plugin_bundle"]["digest"] = value; fleet.replace_evidence(asset, mirror=True)
            with self.subTest(bundleDigest=value), self.assertRaisesRegex(MODULE.Refusal, "asset digest"):
                fleet.acquire()

    def test_non_object_native_answers_refuse_without_a_traceback(self):
        for malformed in ("evidence", "artifacts", "release-asset", "assets-map", "asset-name"):
            fleet = ObsSyncFleet()
            if malformed == "evidence": fleet.replace_evidence([])
            elif malformed == "artifacts":
                asset = fleet.release_manifest(); asset["artifacts"] = ["wrong"]
                fleet.replace_evidence(asset)
            elif malformed == "release-asset": fleet.release["assets"][-1] = ["wrong"]
            elif malformed == "assets-map": fleet.release["assets"] = {str(i): {} for i in range(5)}
            else: fleet.release["assets"][-1]["name"] = None
            with self.subTest(malformed=malformed), self.assertRaisesRegex(MODULE.Refusal, "malformed answer"):
                fleet.acquire()

    def test_native_expanded_size_boundary_matches_the_producer(self):
        fleet = ObsSyncFleet(); asset = fleet.release_manifest(); files = asset["artifacts"]["plugin_files"]
        limit = 16 * 1024 * 1024
        files["main.js"]["size"] = limit - files["manifest.json"]["size"] - files["styles.css"]["size"]
        fleet.replace_evidence(asset, mirror=True); fleet.acquire()
        files["main.js"]["size"] += 1; fleet.replace_evidence(asset, mirror=True)
        with self.assertRaisesRegex(MODULE.Refusal, "expanded bundle limit"):
            fleet.acquire()

    def test_native_release_inventory_and_metadata_are_bound(self):
        for change, reason in (
            (lambda r: r.pop(), "asset inventory"),
            (lambda r: r.append(dict(r[-1])), "asset inventory"),
            (lambda r: r.__setitem__(-1, dict(r[-2])), "asset name"),
            (lambda r: r[-1].update(name="other.css"), "asset name"),
        ):
            fleet = ObsSyncFleet(); change(fleet.release["assets"])
            with self.assertRaisesRegex(MODULE.Refusal, reason): fleet.acquire()
        for index in range(5):
            for field, value, reason in (
                ("state", "new", "uploaded asset"), ("size", True, "uploaded asset"),
                ("size", 0, "uploaded asset"), ("size", 16 * 1024 * 1024 + 1, "uploaded asset"),
                ("browser_download_url", "https://example.invalid/asset", "outside|uploaded asset"),
                ("content_type", "text/plain", "metadata contradicts"),
                ("digest", "sha256:" + "f" * 64, "GitHub states|metadata contradicts"),
            ):
                fleet = ObsSyncFleet(); fleet.release["assets"][index][field] = value
                with self.subTest(index=index, field=field), self.assertRaisesRegex(MODULE.Refusal, reason):
                    fleet.acquire()
        fleet = ObsSyncFleet(); fleet.release["assets"][2]["size"] += 1
        with self.assertRaisesRegex(MODULE.Refusal, "metadata contradicts"): fleet.acquire()

    def test_native_tag_identity_and_protected_source_bindings_remain_required(self):
        for path in (("release", "tag"), ("artifacts", "image", "tag")):
            for missing in (False, True):
                fleet = ObsSyncFleet(); asset = fleet.release_manifest(); target = asset
                for key in path[:-1]: target = target[key]
                if missing: target.pop(path[-1])
                else: target[path[-1]] = "incorrect"
                fleet.replace_evidence(asset)
                with self.subTest(path=path, missing=missing), self.assertRaisesRegex(MODULE.Refusal, "manifest.*tag"):
                    fleet.acquire()
        fleet = ObsSyncFleet(); asset = fleet.release_manifest(); asset["tag"] = "v0.1.11"
        fleet.replace_evidence(asset)
        with self.assertRaisesRegex(MODULE.Refusal, "manifest tag"): fleet.acquire()
        for changed in ("tag", "source", "ancestry"):
            fleet = ObsSyncFleet()
            if changed == "tag": fleet.gh[f"repos/{fleet.site}/git/tags/{fleet.tag_object_sha}"]["tag"] = "v0.1.11"
            elif changed == "source": fleet.gh[f"repos/{fleet.site}/git/tags/{fleet.tag_object_sha}"]["object"]["sha"] = "a" * 40
            else: fleet.gh[f"repos/{fleet.site}/compare/main...{fleet.source_sha}"] = {"status": "diverged"}
            with self.subTest(changed=changed), self.assertRaises(MODULE.Refusal): fleet.acquire()

    def test_native_chart_must_still_pin_the_prefixed_image_tag(self):
        for tag in ("0.1.11", "v0.1.12"):
            fleet = ObsSyncFleet()
            values = fleet.values_yaml.replace(b"tag: v0.1.11", ("tag: " + tag).encode())
            fleet.overrides["layer_bytes"] = fleet.tar({
                "obsync/Chart.yaml": fleet.chart_yaml, "obsync/values.yaml": values})
            fleet.build()
            with self.subTest(tag=tag), self.assertRaisesRegex(MODULE.Refusal, "embedded image pin"):
                fleet.acquire()


class CeremonyTests(unittest.TestCase):
    def test_honest_fleet_yields_the_exact_record_and_pins_cosign_at_digests(self):
        for schema in ("naranjo", "lidersea"):
            with self.subTest(schema=schema):
                fleet = FakeFleet(schema=schema)
                record, inspection = fleet.acquire()
                self.assertEqual(record, fleet.expected_record())
                self.assertEqual(inspection, {"Chart.yaml": sha(fleet.chart_yaml), "values.yaml": sha(fleet.values_yaml)})
                verify = [c for c in fleet.calls if c[0] == "run" and c[1][:2] == ("cosign", "verify")]
                attest = [c for c in fleet.calls if c[0] == "run" and c[1][:2] == ("cosign", "verify-attestation")]
                self.assertEqual(len(verify), 1)
                self.assertEqual(len(attest), 1)
                self.assertEqual(verify[0][1][-1], f"{fleet.chart_repo}@{fleet.manifest_digest}")
                self.assertIn("--certificate-identity", verify[0][1])
                self.assertEqual(verify[0][1][verify[0][1].index("--certificate-identity") + 1], fleet.subject)
                self.assertEqual(attest[0][1][-1], f"{fleet.image_repo}@{fleet.index_digest}")
                self.assertIn("--new-bundle-format", attest[0][1])
                self.assertEqual(attest[0][1][attest[0][1].index("--type") + 1], "slsaprovenance1")
                manifests = [c[1] for c in fleet.calls if c[0] == "fetch" and "/manifests/" in c[1]]
                # The distribution path carries the repository NAME; the host
                # is the URL's, never repeated inside the path.
                chart_name = fleet.chart_repo.removeprefix("ghcr.io/")
                image_name = fleet.image_repo.removeprefix("ghcr.io/")
                self.assertEqual(manifests.count(f"https://ghcr.io/v2/{chart_name}/manifests/{fleet.version}"), 2)
                self.assertEqual(manifests.count(f"https://ghcr.io/v2/{image_name}/manifests/v{fleet.version}"), 2)
                for call in fleet.calls:
                    if call[0] == "run" and call[1][0] == "cosign":
                        self.assertNotIn(f":{fleet.version}", call[1][-1])
                        self.assertNotIn(f":v{fleet.version}", call[1][-1])

    def refusal(self, mutate, message):
        fleet = FakeFleet()
        mutate(fleet)
        with self.assertRaisesRegex(MODULE.Refusal, message):
            fleet.acquire()

    def test_every_moved_or_lying_answer_is_refused(self):
        def header_lies(f):
            body, _ = f.manifest_answers[(f.chart_repo, f.version, MODULE.OCI_MANIFEST)]
            f.manifest_answers[(f.chart_repo, f.version, MODULE.OCI_MANIFEST)] = (body, "sha256:" + "e" * 64)

        def second_resolution_moves(f):
            original = f.fetch
            state = {"count": 0}

            def fetch(url, headers, limit):
                body, headers_out = original(url, headers, limit)
                if url.endswith(f"/manifests/{f.version}"):
                    state["count"] += 1
                    if state["count"] == 2:
                        body = body + b" "
                        headers_out = {"docker-content-digest": sha(body)}
                return body, headers_out

            f.fetch = fetch

        def two_layers(f):
            f.layers.append(dict(f.layers[0]))
            manifest = json.loads(f.manifest_bytes)
            manifest["layers"] = f.layers
            body = json.dumps(manifest).encode()
            f.manifest_answers[(f.chart_repo, f.version, MODULE.OCI_MANIFEST)] = (body, sha(body))

        def config_version_off(f):
            config = json.loads(f.config_bytes)
            config["version"] = "0.1.70"
            body = json.dumps(config).encode()
            f.blobs[(f.chart_repo, f.config_digest)] = body  # digest now lies too

        def layer_size_off(f):
            manifest = json.loads(f.manifest_bytes)
            manifest["layers"][0]["size"] += 1
            body = json.dumps(manifest).encode()
            f.manifest_answers[(f.chart_repo, f.version, MODULE.OCI_MANIFEST)] = (body, sha(body))

        def chart_yaml_name_off(f):
            f.overrides["chart_yaml"] = f.chart_yaml.replace(b"name: naranjo-online", b"name: other")
            f.build()

        def values_pin_off(f):
            f.overrides["values_digest"] = "sha256:" + "d" * 64
            f.build()

        def no_arm64(f):
            f.overrides["index_children"] = [m for m in f.index_children if m["platform"]["architecture"] != "arm64"]
            f.build()

        def two_arm64(f):
            f.overrides["index_children"] = f.index_children + [dict(f.index_children[1], digest="sha256:" + "4" * 64)]
            f.build()

        def signature_binds_other_digest(f):
            original = f.run

            def run(argv, **kwargs):
                if argv[:2] == ["cosign", "verify"]:
                    return json.dumps([{"critical": {"image": {"docker-manifest-digest": "sha256:" + "b" * 64}}}])
                return original(argv, **kwargs)

            f.run = run

        def attestation_subject_off(f):
            original = f.run

            def run(argv, **kwargs):
                out = original(argv, **kwargs)
                if argv[:2] == ["cosign", "verify-attestation"]:
                    envelope = json.loads(out.splitlines()[0])
                    statement = json.loads(base64.b64decode(envelope["payload"]))
                    statement["subject"][0]["digest"]["sha256"] = "c" * 64
                    envelope["payload"] = base64.b64encode(json.dumps(statement).encode()).decode()
                    return json.dumps(envelope) + "\n"
                return out

            f.run = run

        def attestation_not_slsa(f):
            original = f.run

            def run(argv, **kwargs):
                out = original(argv, **kwargs)
                if argv[:2] == ["cosign", "verify-attestation"]:
                    envelope = json.loads(out.splitlines()[0])
                    statement = json.loads(base64.b64decode(envelope["payload"]))
                    statement["predicateType"] = "https://slsa.dev/provenance/v0.2"
                    envelope["payload"] = base64.b64encode(json.dumps(statement).encode()).decode()
                    return json.dumps(envelope) + "\n"
                return out

            f.run = run

        def no_attestation(f):
            original = f.run
            f.run = lambda argv, **kw: "" if argv[:2] == ["cosign", "verify-attestation"] else original(argv, **kw)

        def cosign_off_pin(f):
            original = f.run
            f.run = lambda argv, **kw: json.dumps({"gitVersion": "v3.1.2"}) if argv[:3] == ["cosign", "version", "--json"] else original(argv, **kw)

        def release_mutable(f):
            f.gh[f"repos/{f.site}/releases/tags/v{f.version}"]["immutable"] = False

        def two_assets(f):
            assets = f.gh[f"repos/{f.site}/releases/tags/v{f.version}"]["assets"]
            assets.append(dict(assets[0], name="other-release-manifest.json"))

        def asset_digest_lies(f):
            f.gh[f"repos/{f.site}/releases/tags/v{f.version}"]["assets"][0]["digest"] = "sha256:" + "f" * 64

        def manifest_chart_digest_off(f):
            asset = json.loads(f.asset_bytes)
            asset["artifacts"]["chart"]["digest"] = "sha256:" + "9" * 64
            body = json.dumps(asset).encode()
            f.downloads[f.asset_url] = body
            f.gh[f"repos/{f.site}/releases/tags/v{f.version}"]["assets"][0]["digest"] = sha(body)

        def manifest_states_no_identity(f):
            asset = json.loads(f.asset_bytes)
            asset.pop("publisher")
            for kind in ("chart", "image"):
                asset["artifacts"][kind].pop("signature_identity")
            body = json.dumps(asset).encode()
            f.downloads[f.asset_url] = body
            f.gh[f"repos/{f.site}/releases/tags/v{f.version}"]["assets"][0]["digest"] = sha(body)

        def source_sha_disagrees(f):
            f.gh[f"repos/{f.site}/git/tags/{f.tag_object_sha}"]["object"]["sha"] = "a" * 40

        def lightweight_tag(f):
            f.gh[f"repos/{f.site}/git/ref/tags/v{f.version}"]["object"]["type"] = "commit"

        def foreign_download_host(f):
            f.gh[f"repos/{f.site}/releases/tags/v{f.version}"]["assets"][0]["browser_download_url"] = "https://evil.example/release-manifest.json"

        def source_not_on_main(f):
            f.gh[f"repos/{f.site}/compare/main...{f.source_sha}"] = {"status": "diverged"}

        def source_ancestry_unknown(f):
            f.gh[f"repos/{f.site}/compare/main...{f.source_sha}"] = {}

        def manifest_omits_chart_repository(f):
            asset = json.loads(f.asset_bytes)
            asset["artifacts"]["chart"].pop("repository")
            body = json.dumps(asset).encode()
            f.downloads[f.asset_url] = body
            f.gh[f"repos/{f.site}/releases/tags/v{f.version}"]["assets"][0]["digest"] = sha(body)

        def archive(f, entries):
            f.overrides["layer_bytes"] = hostile_tar(entries)
            f.build()

        good = lambda f: [(f"{f.slug}/Chart.yaml", f.chart_yaml, tarfile.REGTYPE), (f"{f.slug}/values.yaml", f.values_yaml, tarfile.REGTYPE)]

        def duplicate_chart_yaml(f):
            archive(f, good(f) + [(f"{f.slug}/Chart.yaml", f.chart_yaml.replace(b"version: ", b"version: 9."), tarfile.REGTYPE)])

        def dot_prefixed_twin(f):
            archive(f, good(f) + [(f"./{f.slug}/Chart.yaml", f.chart_yaml.replace(b"name: ", b"name: x"), tarfile.REGTYPE)])

        def unrelated_symlink(f):
            archive(f, [(f"{f.slug}/Chart.yaml", f.chart_yaml, tarfile.REGTYPE), (f"{f.slug}/values.yaml", f.values_yaml, tarfile.REGTYPE), (f"{f.slug}/templates/link.yaml", b"", tarfile.SYMTYPE)])

        def unrelated_hardlink(f):
            archive(f, [(f"{f.slug}/Chart.yaml", f.chart_yaml, tarfile.REGTYPE), (f"{f.slug}/values.yaml", f.values_yaml, tarfile.REGTYPE), (f"{f.slug}/templates/link.yaml", b"", tarfile.LNKTYPE)])

        def symlinked_chart_yaml(f):
            archive(f, [(f"{f.slug}/Chart.yaml", b"", tarfile.SYMTYPE), (f"{f.slug}/values.yaml", f.values_yaml, tarfile.REGTYPE)])

        def entry_outside_root(f):
            archive(f, good(f) + [("../escape", b"x", tarfile.REGTYPE)])

        def too_many_entries(f):
            archive(f, good(f) + [(f"{f.slug}/pad-{i}", b"", tarfile.REGTYPE) for i in range(MODULE.ARCHIVE_MEMBER_CEILING)])

        def oversized_chart_yaml(f):
            archive(f, [(f"{f.slug}/Chart.yaml", f.chart_yaml + b"#" * MODULE.CHART_FILE_CEILING, tarfile.REGTYPE), (f"{f.slug}/values.yaml", f.values_yaml, tarfile.REGTYPE)])

        def expansion_bomb(f):
            archive(f, [(f"{f.slug}/pad", b"\0" * (MODULE.ARCHIVE_EXPANSION_CEILING + 1024 * 1024), tarfile.REGTYPE)] + good(f))

        def truncated_archive(f):
            raw = gzip.decompress(hostile_tar(good(f)))
            f.overrides["layer_bytes"] = gzip.compress(raw[: 512 + 40])
            f.build()

        def not_a_gzip_tar(f):
            f.overrides["layer_bytes"] = b"\x1f\x8b" + b"not really" * 8
            f.build()

        def asset_is_not_json(f):
            body = b"not json"
            f.downloads[f.asset_url] = body
            f.gh[f"repos/{f.site}/releases/tags/v{f.version}"]["assets"][0]["digest"] = sha(body)

        cases = {
            "content digest header lies": (header_lies, "disagrees with the bytes"),
            "reference moves between resolutions": (second_resolution_moves, "moved between two resolutions"),
            "two helm layers": (two_layers, "exactly one Helm chart layer"),
            "config blob altered": (config_version_off, "do not hash to their digest"),
            "layer size disagrees": (layer_size_off, "layer size disagrees"),
            "chart yaml identity": (chart_yaml_name_off, "Chart.yaml identity"),
            "values pin is not the index": (values_pin_off, "is not the embedded pin"),
            "no arm64 child": (no_arm64, "exactly one linux/arm64 child"),
            "two arm64 children": (two_arm64, "exactly one linux/arm64 child"),
            "signature binds another digest": (signature_binds_other_digest, "signature binds"),
            "attestation subject": (attestation_subject_off, "provenance subject is not exactly"),
            "attestation predicate": (attestation_not_slsa, "not SLSA v1"),
            "no attestation": (no_attestation, "no SLSA v1 provenance statement"),
            "cosign off pin": (cosign_off_pin, "not the required tool pin"),
            "release not immutable": (release_mutable, "not an immutable final release"),
            "two assets": (two_assets, "exactly one release-manifest.json"),
            "asset digest lies": (asset_digest_lies, "GitHub states"),
            "manifest chart digest": (manifest_chart_digest_off, "release manifest chart.digest states"),
            "manifest states no identity": (manifest_states_no_identity, "states no identity"),
            "source sha disagrees": (source_sha_disagrees, "annotated tag dereferences to"),
            "lightweight tag": (lightweight_tag, "not an annotated tag"),
            "foreign download host": (foreign_download_host, "refusing to download"),
            "source not on main": (source_not_on_main, "not reachable from protected main"),
            "source ancestry unknown": (source_ancestry_unknown, "not reachable from protected main"),
            "manifest omits chart repository": (manifest_omits_chart_repository, "states no chart.repository"),
            "asset is not json": (asset_is_not_json, "malformed answer"),
            "duplicate Chart.yaml entries": (duplicate_chart_yaml, "more than once"),
            "dot-prefixed twin of Chart.yaml": (dot_prefixed_twin, "more than once"),
            "symlinked Chart.yaml": (symlinked_chart_yaml, "not a regular file"),
            "unrelated symlink under templates": (unrelated_symlink, "not a regular file"),
            "unrelated hardlink under templates": (unrelated_hardlink, "not a regular file"),
            "entry outside the archive root": (entry_outside_root, "outside the archive root"),
            "too many entries": (too_many_entries, f"more than {MODULE.ARCHIVE_MEMBER_CEILING} entries"),
            "oversized Chart.yaml": (oversized_chart_yaml, f"exceeds {MODULE.CHART_FILE_CEILING} bytes"),
            "expansion bomb": (expansion_bomb, "expands past"),
            "not a gzip tar": (not_a_gzip_tar, "not a readable gzip tar"),
            "truncated archive": (truncated_archive, "not a readable gzip tar"),
        }
        for name, (mutate, message) in cases.items():
            with self.subTest(case=name):
                self.refusal(mutate, message)

    def test_chart_layer_hash_mismatch_is_refused_by_the_registry_layer(self):
        fleet = FakeFleet()
        fleet.blobs[(fleet.chart_repo, fleet.layer_digest)] = fleet.layer_bytes + b"\0"
        with self.assertRaisesRegex(MODULE.Refusal, "do not hash to their digest"):
            fleet.acquire()

    def test_registry_names_are_host_stripped_and_foreign_hosts_refused(self):
        fleet = FakeFleet()
        registry = fleet.registry()
        body, header = registry.manifest(fleet.chart_repo, fleet.version, MODULE.OCI_MANIFEST)
        self.assertEqual(sha(body), header)
        self.assertIn(("fetch", f"https://ghcr.io/v2/snaraj/charts/{fleet.slug}/manifests/{fleet.version}"), fleet.calls)
        self.assertIn(("fetch", f"https://ghcr.io/token?scope=repository:snaraj/charts/{fleet.slug}:pull"), fleet.calls)
        with self.assertRaisesRegex(MODULE.Refusal, "not a repository on ghcr.io"):
            registry.manifest("docker.io/snaraj/charts/x", "1.0.0", MODULE.OCI_MANIFEST)
        with self.assertRaisesRegex(MODULE.Refusal, "not a repository on ghcr.io"):
            registry.blob("snaraj/charts/x", "sha256:" + "0" * 64)

    def test_version_must_be_plain_semver(self):
        fleet = FakeFleet()
        for bad in ("v0.1.71", "0.1", "0.01.1", "latest"):
            with self.subTest(version=bad), self.assertRaisesRegex(MODULE.Refusal, "plain semantic version"):
                MODULE.acquire(fleet.selection(), bad, fleet.registry(), fleet.github(), fleet.cosign())

    def test_release_manifest_binding_covers_both_fleet_schemas(self):
        for schema in ("naranjo", "lidersea"):
            fleet = FakeFleet(schema=schema)
            asset = fleet.release_manifest()
            expected = {
                "repository": fleet.site, "version": fleet.version, "tag": f"v{fleet.version}", "identity": fleet.subject,
                "chart.repository": fleet.chart_repo, "chart.digest": fleet.manifest_digest,
                "image.repository": fleet.image_repo, "image.digest": fleet.index_digest,
            }
            with self.subTest(schema=schema):
                MODULE.bind_release_manifest(asset, expected, schema)
                statements = MODULE.release_manifest_statements(asset)
                self.assertTrue(all(statements[key] for key in ("repository", "version", "identity", "chart.digest", "image.digest")))
                for field in expected:
                    wrong = dict(expected, **{field: "not-" + expected[field]})
                    with self.subTest(schema=schema, field=field), self.assertRaisesRegex(MODULE.Refusal, re.escape(field)):
                        MODULE.bind_release_manifest(asset, wrong, schema)
                for field in expected:
                    with self.subTest(schema=schema, missing=field), self.assertRaisesRegex(MODULE.Refusal, "states no " + re.escape(field)):
                        MODULE.bind_release_manifest({}, {field: expected[field]}, "empty")


def hostile_tar(entries) -> bytes:
    """A gzip tar with exactly the given entries, in order: ``(name, data,
    type)``; duplicates, twins, links and directories are all expressible."""

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data, kind in entries:
            info = tarfile.TarInfo(name)
            info.type = kind
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                info.linkname = "values.yaml"
                archive.addfile(info)
            elif kind == tarfile.DIRTYPE:
                archive.addfile(info)
            else:
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()
