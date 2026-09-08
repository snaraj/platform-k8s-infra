"""Prove that the extracted composition admits selections, not new authority."""
import hashlib
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

    def test_receipt_tool_inventory_and_versions_are_closed(self):
        original = self.receipt()
        changes = (
            lambda tools: tools.pop("oras"),
            lambda tools: tools.update(extra="1.2.3"),
            lambda tools: tools.update(oras="v1.3.4"),
            lambda tools: tools.update(oras="1.03.4"),
            lambda tools: tools.update(oras=True),
            lambda tools: tools.update(cosign=None),
        )
        for mutate in changes:
            receipt = json.loads(json.dumps(original))
            mutate(receipt["tools"])
            self.write_receipt(receipt)
            with self.assertRaisesRegex(ValueError, "authority is not exact"):
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

    # --- The pending-application declaration (issue #348) -------------------
    #
    # A third application cannot simply be appended to APPLICATIONS before its
    # publisher cuts a release: there is no acquired artifact and no receipt
    # record to point at. PENDING_APPLICATIONS is the narrower declaration that
    # admits its directory without admitting it to the receipt closure, and
    # every rule below is an INVERSION of an active application's rule rather
    # than an exemption from it. Each is proven in both directions, because a
    # pending rule that only ever fires on pending input would let the active
    # rule rot unnoticed and vice versa.

    def pending_slug(self):
        slugs = sorted(composition.PENDING_APPLICATIONS)
        self.assertEqual(len(slugs), 1, "one pending application is declared")
        return slugs[0]

    def test_the_two_maps_are_disjoint_and_the_boundary_covers_both(self):
        self.assertEqual(
            set(composition.APPLICATIONS) & set(composition.PENDING_APPLICATIONS), set()
        )
        selections, receipt = composition.check(self.root)
        # The positive control the rest of this block needs: a pending
        # application contributes NO selection and NO receipt record, and the
        # two active applications are untouched by its presence.
        self.assertEqual(set(selections), set(composition.APPLICATIONS))
        self.assertEqual(set(receipt["records"]), set(composition.APPLICATIONS))
        self.assertNotIn(self.pending_slug(), selections)
        self.assertNotIn(self.pending_slug(), receipt["records"])

    def test_the_declared_application_repository_is_load_bearing(self):
        """The map VALUE must change an outcome, or it is documentation.

        Review finding: `PENDING_APPLICATIONS = {"obsync": "obsync"}` was
        documented as slug -> application repository while nothing read the
        value, so `{"obsync": "foreign-publisher"}` left the suite green. The
        active map's value is bound by the receipt's signer comparison; a
        pending application has no receipt record, so the same derivation is
        checked against the manifest's own publisher subject instead.

        Both maps are exercised here, because a rule that only fired on pending
        input would let the active binding rot unnoticed.
        """

        for attribute in ("APPLICATIONS", "PENDING_APPLICATIONS"):
            declared = getattr(composition, attribute)
            for slug, repository in sorted(declared.items()):
                with self.subTest(map=attribute, slug=slug):
                    original = dict(declared)
                    try:
                        declared[slug] = "foreign-publisher"
                        with self.assertRaisesRegex(
                            ValueError, "declared application repository"
                        ):
                            composition.check(self.root)
                    finally:
                        declared.clear()
                        declared.update(original)
        composition.check(self.root)

    def test_a_substituted_identity_survives_a_re_pin_and_is_still_refused(self):
        """The bypass the byte pins cannot see, which is why this check exists.

        Editing a manifest alone already fails its shape pin. The realistic
        attempt is a substituted chart repository or publisher subject
        committed TOGETHER with a re-pinned hash: self-consistent bytes, and a
        lie about which repository publishes this application. Each mutation
        below is therefore re-pinned before `check` runs, so the pin passes and
        the identity binding is the only thing left standing.
        """

        shapes_path = self.root / "policies/manifest-shapes.json"
        for slug in sorted({**composition.APPLICATIONS, **composition.PENDING_APPLICATIONS}):
            relative = f"kubernetes/websites/{slug}/source.yaml"
            path = self.root / relative
            original, original_shapes = path.read_text(), shapes_path.read_text()
            pending = slug in composition.PENDING_APPLICATIONS
            url = composition.URL_LINE.findall(original)[0]
            subject = composition.SUBJECT_LINE.findall(original)[0]
            for label, before, after, expected in (
                ("foreign chart repository", url,
                 "oci://ghcr.io/snaraj/charts/foreign", "chart repository is not the declared"),
                ("foreign publisher", subject,
                 subject.replace("release-publisher", "foreign-publisher"),
                 "publisher identity is not the declared"),
                # An unescaped dot matches ANY character, so `naranjoXonline`
                # would verify against a subject that reads identical.
                ("unescaped dot", subject, subject.replace("\\.", "."),
                 "publisher identity is not the declared"),
                ("unanchored subject", subject, subject.rstrip("$"),
                 "publisher identity is not the declared"),
            ):
                if before == after:
                    continue
                with self.subTest(slug=slug, mutation=label):
                    path.write_text(original.replace(before, after))
                    shapes = json.loads(original_shapes)
                    normalized, _, _ = composition.normalized_manifest(
                        path.read_bytes(), True, pending
                    )
                    shapes[relative] = hashlib.sha256(normalized).hexdigest()
                    shapes_path.write_text(json.dumps(shapes, indent=2) + "\n")
                    with self.assertRaisesRegex(ValueError, expected):
                        composition.check(self.root)
                path.write_text(original)
                shapes_path.write_text(original_shapes)
        composition.check(self.root)

    def test_composition_cannot_ask_for_a_second_pod(self):
        """`ReadWriteOnce` is node exclusion, so this is not the writer boundary.

        It is the one part of that boundary this repository holds: no values
        block may ASK for a second Pod. Two review rounds bypassed the earlier
        versions of this guard — first a quoted key past a raw-text regex, then
        tags, complex keys, escapes and flow collections past a hand-rolled
        scanner. This gate has no YAML parser (`make check` is stdlib Python and
        invokes neither helm nor yq), so it no longer guesses: it admits a
        closed grammar and REFUSES everything else, valid YAML included.

        Every mutation is RE-PINNED before `check` runs, so the byte hash is out
        of the equation and only the guard is under test. Both refusal messages
        are accepted, because which one fires is a property of the form: a
        spelling inside the grammar is caught by the key set, and one outside it
        is caught by the grammar itself.
        """

        shapes_path = self.root / "policies/manifest-shapes.json"
        refusal = (
            "replica count or rollout strategy"
            "|refuses to guess at"
            "|outside the closed grammar"
            "|spelled bare"
            "|no spec.values block"
        )
        # Inside the grammar: caught by the key set.
        plain = (
            "    replicas: 2",
            "    replicaCount: 2",
            "    strategy: RollingUpdate",
            "    updateStrategy: RollingUpdate",
            "    deployment:\n      replicas: 2",
        )
        # Outside it: caught by the grammar. Every form the review listed.
        hostile = (
            '    "replicas": 2',
            "    'replicas': 2",
            '    "replic\\x61s": 2',
            "    !!str replicas: 2",
            "    ? replicas\n    : 2",
            "    deployment: {replicas: 2}",
            "    deployment: [replicas: 2]",
            "    REPLICAS: 2",
            "    replicas: &anchor 2",
            "    replicas: 2 # inline",
        )
        for slug in sorted({**composition.APPLICATIONS, **composition.PENDING_APPLICATIONS}):
            relative = f"kubernetes/websites/{slug}/release.yaml"
            path = self.root / relative
            original, original_shapes = path.read_text(), shapes_path.read_text()
            pending = slug in composition.PENDING_APPLICATIONS

            def repin_and_expect(mutated_text, label):
                path.write_text(mutated_text)
                shapes = json.loads(original_shapes)
                normalized, _, _ = composition.normalized_manifest(
                    path.read_bytes(), False, pending
                )
                shapes[relative] = hashlib.sha256(normalized).hexdigest()
                shapes_path.write_text(json.dumps(shapes, indent=2) + "\n")
                with self.subTest(slug=slug, mutation=label):
                    with self.assertRaisesRegex(ValueError, refusal):
                        composition.check(self.root)
                path.write_text(original)
                shapes_path.write_text(original_shapes)

            for addition in plain + hostile:
                repin_and_expect(
                    original.rstrip("\n") + "\n" + addition + "\n", addition.strip()
                )

            # Quoting the OUTER key made the block vanish from the previous
            # scanner while the consumer still resolved `.spec.values.replicas`.
            # A missing block is refused rather than treated as nothing to check.
            for quoted in ('  "values":', "  'values':", "  !!map values:"):
                repin_and_expect(
                    original.replace("  values:", quoted, 1).rstrip("\n")
                    + "\n    replicas: 2\n",
                    quoted.strip(),
                )

            # The sibling that must stay admissible: a guard that refused the
            # reviewed tree would be broken rather than stricter.
            self.assertIn("      strategy: rollback", original)
        composition.check(self.root)

    def test_an_application_cannot_be_active_and_pending_at_once(self):
        """The overlap guard, exercised directly.

        Review finding: deleting this guard left the suite green, because
        nothing constructed the overlap it refuses. An application in both maps
        would be checked under the pending rules and ALSO acquire a receipt
        record, which is exactly the reserved place the pending state exists to
        prevent.
        """

        slug = self.pending_slug()
        composition.APPLICATIONS[slug] = "obsync"
        try:
            with self.assertRaisesRegex(ValueError, "active and pending at once"):
                composition.check(self.root)
        finally:
            del composition.APPLICATIONS[slug]
        composition.check(self.root)

    def test_a_pending_selection_may_be_the_sentinel_and_nothing_else(self):
        slug = self.pending_slug()
        path = self.root / "kubernetes/websites" / slug / "source.yaml"
        original = path.read_text()
        self.assertIn(composition.SENTINEL_DIGEST, original)
        for replacement in ("sha256:" + "1" * 64, "sha256:" + "a" * 64):
            with self.subTest(digest=replacement):
                path.write_text(original.replace(composition.SENTINEL_DIGEST, replacement))
                with self.assertRaisesRegex(ValueError, "must select the sentinel digest"):
                    composition.check(self.root)
        path.write_text(original)
        composition.check(self.root)

    def test_an_active_selection_may_be_anything_but_the_sentinel(self):
        """The inverse arm, so neither rule can be deleted without a red run."""

        path = self.root / "kubernetes/websites/naranjo-online/source.yaml"
        original = path.read_text()
        digest = composition.DIGEST_LINE.findall(original)[0]
        path.write_text(original.replace(digest, composition.SENTINEL_DIGEST))
        with self.assertRaisesRegex(ValueError, "invalid or unresolved"):
            composition.check(self.root)
        path.write_text(original)

    def test_a_pending_release_must_stay_suspended_and_not_ready(self):
        slug = self.pending_slug()
        path = self.root / "kubernetes/websites" / slug / "release.yaml"
        original = path.read_text()
        for before, after in (
            ("  suspend: true", "  suspend: false"),
            ("    deploymentReady: false", "    deploymentReady: true"),
        ):
            with self.subTest(mutation=after):
                self.assertEqual(original.count(before), 1)
                path.write_text(original.replace(before, after))
                with self.assertRaisesRegex(ValueError, "suspended and not ready"):
                    composition.check(self.root)
            path.write_text(original)

    def test_a_third_undeclared_directory_is_refused(self):
        """A directory nobody declared is inventory, not composition."""

        extra = self.root / "kubernetes/websites/undeclared"
        extra.mkdir()
        source = self.root / "kubernetes/websites" / self.pending_slug()
        for name in composition.FILES:
            (extra / name).write_bytes((source / name).read_bytes())
        with self.assertRaisesRegex(ValueError, "inventory"):
            composition.check(self.root)

    def test_a_tag_or_a_second_digest_cannot_join_a_pending_selection(self):
        slug = self.pending_slug()
        path = self.root / "kubernetes/websites" / slug / "source.yaml"
        original = path.read_text()
        digest_line = "    digest: " + composition.SENTINEL_DIGEST
        self.assertEqual(original.count(digest_line), 1)
        for label, replacement, expected in (
            ("tag beside the digest", digest_line + "\n    tag: v0.1.0", "reviewed application boundary"),
            ("second digest", digest_line + "\n" + digest_line, "one version and one digest"),
            ("semver range", digest_line + "\n    semver: \">=0.1.0\"", "reviewed application boundary"),
        ):
            with self.subTest(mutation=label):
                path.write_text(original.replace(digest_line, replacement))
                with self.assertRaisesRegex(ValueError, expected):
                    composition.check(self.root)
            path.write_text(original)

    def test_a_cross_namespace_reference_is_refused_in_the_pending_release(self):
        slug = self.pending_slug()
        path = self.root / "kubernetes/websites" / slug / "release.yaml"
        original = path.read_text()
        for before, after in (
            ("    name: obsync-chart", "    name: obsync-chart\n    namespace: naranjo-online"),
            ("  namespace: obsidian", "  namespace: naranjo-online"),
            ("  serviceAccountName: obsync-helm-reconciler", "  serviceAccountName: default"),
            ("  serviceAccountName: obsync-helm-reconciler", "  serviceAccountName: helm-reconciler"),
        ):
            with self.subTest(mutation=after):
                self.assertEqual(original.count(before), 1)
                path.write_text(original.replace(before, after))
                with self.assertRaisesRegex(ValueError, "reviewed application boundary"):
                    composition.check(self.root)
            path.write_text(original)

    def test_composition_may_not_activate_storage(self):
        """Storage activation is an operator decision, never an application one.

        The chart creates CLAIMS at render time and this repository never
        renders it, so nothing here needs a claim volume or a storage object.
        A manifest that declared one would be reaching past the application
        boundary into the volume, class and node path an operator owns; the
        refusal names that rather than reporting a changed byte pin.
        """

        slug = self.pending_slug()
        path = self.root / "kubernetes/websites" / slug / "release.yaml"
        original = path.read_text()
        for label, addition in (
            ("claim object", "---\napiVersion: v1\nkind: PersistentVolumeClaim\n"),
            ("storage class", "---\napiVersion: storage.k8s.io/v1\nkind: StorageClass\n"),
            ("claim volume", "    volumes:\n      - persistentVolumeClaim:\n          claimName: obsync-blobs\n"),
            ("csi volume", "    volumes:\n      - csi:\n          driver: example\n"),
        ):
            with self.subTest(mutation=label):
                path.write_text(original + addition)
                with self.assertRaisesRegex(ValueError, "must not activate storage"):
                    composition.check(self.root)
            path.write_text(original)

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
