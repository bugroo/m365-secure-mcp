from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APACHE_LICENSE_SHA256 = (
    "86ca31b31bff9dc84a6a1acdf947627baa8655cf179486e36c06bc60e0f33f44"
)


def test_apache_license_is_unchanged_and_project_metadata_is_consistent() -> None:
    license_path = ROOT / "LICENSE"
    assert hashlib.sha256(license_path.read_bytes()).hexdigest() == (
        APACHE_LICENSE_SHA256
    )
    assert "Apache License" in license_path.read_text()
    assert 'license = { text = "Apache-2.0" }' in (
        ROOT / "pyproject.toml"
    ).read_text()


def test_public_boundary_and_trademark_docs_are_factual() -> None:
    boundary = (ROOT / "docs/OPEN_SOURCE_BOUNDARY.md").read_text()
    trademarks = (ROOT / "TRADEMARKS.md").read_text()
    combined = f"{boundary}\n{trademarks}".lower()

    for required in (
        "community",
        "apache license 2.0",
        "commercial use",
        "customer policies",
        "external integrations",
        "inbound authorization",
        "trademarks",
    ):
        assert required in combined
    assert "registered trademark" not in combined
    assert "®" not in combined
    assert "werixo.internal" not in combined


def test_readme_links_to_open_source_boundary() -> None:
    readme = (ROOT / "README.md").read_text()
    assert "docs/OPEN_SOURCE_BOUNDARY.md" in readme


def test_control_signing_runbook_preserves_public_private_boundary() -> None:
    runbook = (ROOT / "docs/CONTROL_SIGNING_RUNBOOK.md").read_text()
    readme = (ROOT / "README.md").read_text()
    for required in (
        "Manifest approver",
        "Signing operator",
        "direct cutover",
        "retired",
        "compromised",
        "historical_manifest_digests",
        "local-unattested",
        "not-a-release",
        "release-attestation-required",
        "no SLSA or signed-release-provenance claim",
    ):
        assert required in runbook
    assert "docs/CONTROL_SIGNING_RUNBOOK.md" in readme
    assert "CI compiles and verifies; it never receives" in runbook
