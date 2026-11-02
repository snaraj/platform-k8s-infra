#!/usr/bin/env python3
"""Rescan authenticated selected arm64 images; unknown evidence never passes."""
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import validate

VERSION = "0.76.1"
MAX_AGE = dt.timedelta(hours=24)
# Each Go application with its own main module. Go embeds that module without
# a semantic version, so it is admitted unversioned in its own report only.
GO_APPLICATIONS = {
    "naranjo-online": "github.com/snaraj/naranjo.online",
    "lidersea-com": "github.com/snaraj/lidersea.com",
    "hospedajedonlolo-com": "github.com/snaraj/hospedajedonlolo.com",
}
RUST_APPLICATIONS = {"obsync"}


def fresh_database(metadata, now):
    if metadata.get("Version") != 2:
        raise ValueError("unsupported vulnerability database")
    updated = dt.datetime.fromisoformat(metadata["UpdatedAt"].replace("Z", "+00:00"))
    if updated.tzinfo is None or not -dt.timedelta(minutes=5) <= now - updated <= MAX_AGE:
        raise ValueError("vulnerability database is stale or future-dated")


def findings(report, image, go_module=None):
    if (report.get("SchemaVersion") != 2
            or report.get("ArtifactType") != "container_image"
            or report.get("ArtifactName") != image
            or report.get("Trivy", {}).get("Version") != VERSION):
        raise ValueError("scanner identity or image binding mismatch")
    metadata = report["Metadata"]
    if (metadata["ImageConfig"].get("architecture") != "arm64"
            or metadata["ImageConfig"].get("os") != "linux"
            or metadata.get("OS", {}).get("Family") != "debian"
            or not isinstance(metadata.get("OS", {}).get("Name"), str)
            or not metadata["OS"]["Name"]
            or metadata["OS"].get("EOSL")):
        raise ValueError("unexpected platform or unsupported OS")
    results = report.get("Results")
    if not isinstance(results, list) or not results:
        raise ValueError("missing package analysis")
    rows = []
    kinds = set()
    for result in results:
        kind = (result.get("Class"), result.get("Type"))
        if kind not in (("os-pkgs", "debian"), ("lang-pkgs", "gobinary")):
            raise ValueError("unexpected analysis class")
        kinds.add(kind)
        packages = result.get("Packages")
        if not isinstance(packages, list) or not packages:
            raise ValueError("missing package inventory")
        for package in packages:
            if not isinstance(package, dict) or not isinstance(package.get("Name"), str) or not package["Name"]:
                raise ValueError("malformed package name")
            # Only this application's own main module may be unversioned.
            # Its stdlib and every external dependency must still be versioned.
            local_root = (kind == ("lang-pkgs", "gobinary")
                          and package.get("Relationship") == "root"
                          and package["Name"] == go_module)
            if not local_root and (not isinstance(package.get("Version"), str) or not package["Version"]):
                raise ValueError("missing dependency version")
        if kind == ("lang-pkgs", "gobinary") and not any(
                package["Name"] == "stdlib" for package in packages):
            raise ValueError("missing Go standard library version")
        vulns = result.get("Vulnerabilities", [])
        if not isinstance(vulns, list):
            raise ValueError("malformed vulnerability results")
        for vuln in vulns:
            row = {key: vuln[key] for key in
                   ("VulnerabilityID", "PkgName", "InstalledVersion", "Severity")}
            if not all(isinstance(value, str) and value for value in row.values()):
                raise ValueError("incomplete vulnerability")
            row["FixedVersion"] = vuln.get("FixedVersion", "")
            rows.append(row)
    if ("os-pkgs", "debian") not in kinds or (
            go_module is not None and ("lang-pkgs", "gobinary") not in kinds):
        raise ValueError("incomplete application analysis")
    return rows


def run(root=validate.ROOT):
    # Reproduce signatures/provenance before trusting the committed receipt.
    # This is also required for direct local invocation, not just the workflow.
    validate.verify(root)
    _, receipt = validate.check(root)
    if set(receipt["records"]) != set(GO_APPLICATIONS) | RUST_APPLICATIONS:
        raise ValueError("application analysis expectations are incomplete")
    env = {key: value for key, value in os.environ.items()
           if not key.startswith("TRIVY_")}
    with tempfile.TemporaryDirectory(prefix="selected-image-scan-") as directory:
        scratch = Path(directory)
        (scratch / "empty.yaml").write_text("{}\n")
        (scratch / "empty.ignore").write_text("")
        common = ["trivy", "--config", str(scratch / "empty.yaml"),
                  "--cache-dir", str(scratch / "cache")]

        def command(args):
            return subprocess.run(args, check=True, cwd=scratch, env=env,
                                  capture_output=True, text=True, timeout=180)

        version = json.loads(command(["trivy", "--version", "--format", "json"]).stdout)
        if version.get("Version") != VERSION:
            raise ValueError("unexpected scanner version")
        command(common + ["image", "--download-db-only"])
        metadata = json.loads((scratch / "cache/db/metadata.json").read_text())
        fresh_database(metadata, dt.datetime.now(dt.timezone.utc))
        print(json.dumps({"scanner": VERSION, "database": metadata}, sort_keys=True))
        rejected = False
        for slug, record in sorted(receipt["records"].items()):
            # Acquisition verifies this manifest belongs to the selected index.
            repository = record["workloadImage"].split(":v", 1)[0]
            image = repository + "@" + record["arm64Digest"]
            output = scratch / f"{slug}.json"
            command(common + ["image", "--image-src", "remote", "--platform", "linux/arm64",
                    "--scanners", "vuln", "--skip-db-update", "--list-all-pkgs",
                    "--ignore-unfixed=false", "--ignorefile", str(scratch / "empty.ignore"),
                    "--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL", "--exit-code", "0",
                    "--format", "json", "--output", str(output), image])
            fresh_database(metadata, dt.datetime.now(dt.timezone.utc))
            rows = findings(json.loads(output.read_text()), image, GO_APPLICATIONS.get(slug))
            print(json.dumps({"application": slug, "image": image, "findings": rows}, sort_keys=True))
            rejected |= bool(rows)
        return 1 if rejected else 0


if __name__ == "__main__":
    try:
        status = run()
        print("SELECTED_IMAGE_VULNERABILITIES=" + ("FOUND" if status else "PASS"))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError,
            validate.artifacts.Refusal) as error:
        print(f"SELECTED_IMAGE_VULNERABILITIES=UNKNOWN reason={type(error).__name__}")
        status = 2
    sys.exit(status)
