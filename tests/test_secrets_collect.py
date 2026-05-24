"""Tests for secrets.collect and _run_on_files."""

from __future__ import annotations

from pathlib import Path

from agentscrub.discover import ScanTarget
from agentscrub.secrets import _run_on_files, collect


def test_run_on_files_scans_linked_files(tmp_path: Path, agentscrub_paths: Path) -> None:
    fp = tmp_path / "log.jsonl"
    secret = "ghp_" + "z" * 36
    fp.write_text(secret + "\n")

    def fake_detector(scan_dir: Path) -> dict[str, str]:
        for child in scan_dir.iterdir():
            text = child.read_text()
            if secret in text:
                return {secret: "github-pat"}
        return {}

    found = _run_on_files([fp], fake_detector)
    assert found[secret] == "github-pat"


def test_collect_merges_detectors(
    tmp_path: Path,
    monkeypatch,
) -> None:
    secret = "sk-" + "a" * 24
    fp = tmp_path / "s.jsonl"
    fp.write_text(secret + "\n")
    target = ScanTarget(path=tmp_path, tool="custom", display="Custom")

    monkeypatch.setattr(
        "agentscrub.secrets._gitleaks",
        lambda d: {secret: "generic-api-key"},
    )
    monkeypatch.setattr("agentscrub.secrets._trufflehog", lambda d: {})
    monkeypatch.setattr("agentscrub.secrets._titus", lambda d: {})

    secrets, counts = collect([target])
    assert secret in secrets
    assert counts["gitleaks"] >= 1
