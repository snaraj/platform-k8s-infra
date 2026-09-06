"""Prove that the extracted composition admits selections, not new authority."""
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("composition", ROOT / "scripts/validate.py")
composition = importlib.util.module_from_spec(spec)
spec.loader.exec_module(composition)


class CompositionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for relative in ("kubernetes", "policies", "docs/assurance"):
            shutil.copytree(ROOT / relative, self.root / relative)

    def receipt(self):
        return json.loads((self.root / composition.RECEIPT).read_text())

    def write_receipt(self, value):
        (self.root / composition.RECEIPT).write_text(composition.artifacts.render_receipt_json(value))

    def test_initial_boundary_is_exactly_the_two_existing_applications(self):
        selections, _ = composition.check(self.root)
        self.assertEqual(set(selections), {"naranjo-online", "lidersea-com"})
        for slug, value in selections.items():
            self.assertEqual(value.chart_repository, f"ghcr.io/snaraj/charts/{slug}")
            self.assertTrue(value.subject.endswith("/release-publisher.yml@refs/heads/main"))

    def test_missing_default_deny_and_extra_resources_are_rejected(self):
        path = self.root / "kubernetes/websites/naranjo-online/default-deny.yaml"
        original = path.read_bytes()
        path.unlink()
        with self.assertRaisesRegex(ValueError, "inventory"):
            composition.check(self.root)
        path.write_bytes(original)
        extra = path.with_name("extra.yaml")
        extra.write_text("apiVersion: v1\nkind: ConfigMap\n")
        with self.assertRaisesRegex(ValueError, "inventory"):
            composition.check(self.root)

    def test_changes_to_installed_boundaries_are_rejected(self):
        changes = (
            ("source.yaml", "provider: cosign", "provider: other"),
            ("source.yaml", "@refs/heads/main$", "@refs/heads/other$"),
            ("source.yaml", "  interval: 1m0s", "  interval: 10m0s"),
            ("source.yaml", "  timeout: 60s", "  timeout: 60s\n  secretRef:\n    name: registry"),
            ("release.yaml", "  maxHistory: 2", "  maxHistory: 5"),
            ("release.yaml", "    deploymentReady: true", "    deploymentReady: true\n    image: replacement"),
            ("release.yaml", "  serviceAccountName: helm-reconciler", "  serviceAccountName: default"),
            ("release.yaml", "    name: naranjo-online-chart", "    name: naranjo-online-chart\n    namespace: another"),
            ("default-deny.yaml", "    - Egress", "    - Ingress"),
            ("kustomization.yaml", "  - default-deny.yaml", "  - release.yaml"),
        )
        for name, before, after in changes:
            with self.subTest(file=name, mutation=after):
                path = self.root / "kubernetes/websites/naranjo-online" / name
                original = path.read_text()
                self.assertEqual(original.count(before), 1)
                try:
                    path.write_text(original.replace(before, after))
                    with self.assertRaisesRegex(ValueError, "reviewed application boundary"):
                        composition.check(self.root)
                finally:
                    path.write_text(original)

    def test_symbolic_manifest_files_are_rejected(self):
        path = self.root / "kubernetes/websites/naranjo-online/default-deny.yaml"
        replacement = self.root / "replacement.yaml"
        replacement.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(replacement)
        with self.assertRaisesRegex(ValueError, "ordinary file"):
            composition.check(self.root)

    def test_duplicate_json_keys_do_not_silently_replace_policy(self):
        path = self.root / "policies/manifest-shapes.json"
        path.write_text('{"same": "first", "same": "last"}')
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            composition.check(self.root)

    def test_receipt_identity_and_canonical_bytes_are_required(self):
        original = self.receipt()
        foreign = json.loads(json.dumps(original))
        foreign["records"]["naranjo-online"]["signer"]["subject"] = "foreign-publisher"
        self.write_receipt(foreign)
        with self.assertRaisesRegex(ValueError, "identity disagree"):
            composition.check(self.root)
        self.write_receipt(original)
        path = self.root / composition.RECEIPT
        path.write_text(path.read_text() + "\n")
        with self.assertRaisesRegex(ValueError, "not canonical"):
            composition.check(self.root)

    def test_a_new_selection_changes_only_the_two_permitted_fields(self):
        receipt = self.receipt()
        old = receipt["records"]["naranjo-online"]
        path = self.root / "kubernetes/websites/naranjo-online/source.yaml"
        major, minor, patch_number = old["chartTag"].split(".")
        successor = f"{major}.{minor}.{int(patch_number) + 1}"
        digest = "sha256:" + "1" * 64
        path.write_text(path.read_text().replace(f'"{old["chartTag"]}"', f'"{successor}"').replace(old["manifestDigest"], digest))
        old["chartTag"], old["manifestDigest"] = successor, digest
        old["chart"]["version"] = old["chart"]["appVersion"] = successor
        old["workloadImage"] = f"ghcr.io/snaraj/naranjo-online:v{successor}@{digest}"
        self.write_receipt(receipt)
        selections, _ = composition.check(self.root)
        self.assertEqual(selections["naranjo-online"].version, successor)
        # A structural selection is not artifact proof: mismatching fresh
        # evidence must still fail the distinct acquisition gate.
        with patch.object(composition.artifacts, "acquire", return_value=({}, {})):
            with self.assertRaisesRegex(ValueError, "fresh acquisition"):
                composition.verify(self.root)

    def test_complete_record_schema_is_closed_before_network_access(self):
        original = self.receipt()
        changes = (
            lambda r: r.update(extraAuthority=True),
            lambda r: r.update(arm64Digest="malformed"),
            lambda r: r.update(chartConfigDigest=7),
            lambda r: r.update(chartLayerDigest="sha256:" + "0" * 64),
            lambda r: r.update(matchingChartLayerCount=True),
            lambda r: r["chart"].update(extra=True),
            lambda r: r["release"].update(extra=True),
            lambda r: r["release"].update(sourceSha="0" * 40),
            lambda r: r["release"].update(assetDigest=[]),
            lambda r: r.update(workloadImage="foreign"),
        )
        for mutate in changes:
            receipt = json.loads(json.dumps(original))
            mutate(receipt["records"]["naranjo-online"])
            self.write_receipt(receipt)
            with self.assertRaisesRegex(ValueError, "receipt"):
                composition.check(self.root)


if __name__ == "__main__":
    unittest.main()
