"""Tests for secrets.py — merge helpers and detector JSON parsing."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from agentscrub.secrets import _gitleaks, _titus, _trufflehog, all_typed, top_types


class TestMergeHelpers:
    def test_all_typed_last_wins(self) -> None:
        by_tool = {
            "gitleaks": {"secret-a": "jwt"},
            "trufflehog": {"secret-a": "JWT", "secret-b": "aws"},
        }
        merged = all_typed(by_tool)
        assert merged["secret-a"] == "JWT"
        assert merged["secret-b"] == "aws"

    def test_top_types_filters_low_signal(self) -> None:
        by_tool = {
            "gitleaks": {
                "a" * 10: "jwt",
                "b" * 10: "Uri",
            },
        }
        top = top_types(by_tool, n=5)
        labels = [label for label, _ in top]
        assert "Uri" not in labels
        assert any("jwt" in lbl.lower() or lbl == "jwt" for lbl in labels)


class TestDetectorParsing:
    def test_gitleaks_parses_report(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        secret = "ghp_" + "x" * 36
        report = [{"Secret": secret, "RuleID": "github-pat"}]
        out = tmp_path / "gl.json"
        out.write_text(json.dumps(report))

        def fake_run(cmd, **kwargs):
            # Write report path from cmd
            report_path = cmd[cmd.index("--report-path") + 1]
            Path(report_path).write_text(json.dumps(report))

            class R:
                returncode = 0

            return R()

        monkeypatch.setattr("agentscrub.secrets.GITLEAKS", tmp_path / "gitleaks")
        (tmp_path / "gitleaks").write_text("# fake")
        with patch("agentscrub.secrets.subprocess.run", fake_run):
            found = _gitleaks(tmp_path)
        assert found[secret] == "github-pat"

    def test_gitleaks_skips_short_secrets(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        report = [{"Secret": "short", "RuleID": "x"}]

        def fake_run(cmd, **kwargs):
            report_path = cmd[cmd.index("--report-path") + 1]
            Path(report_path).write_text(json.dumps(report))

            class R:
                returncode = 0

            return R()

        monkeypatch.setattr("agentscrub.secrets.GITLEAKS", tmp_path / "gitleaks")
        (tmp_path / "gitleaks").touch()
        with patch("agentscrub.secrets.subprocess.run", fake_run):
            assert _gitleaks(tmp_path) == {}

    def test_trufflehog_parses_jsonl(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        secret = "sk-" + "y" * 20
        line = json.dumps({"DetectorName": "OpenAI", "Raw": secret})

        def fake_run(cmd, **kwargs):
            class R:
                returncode = 0
                stdout = line + "\n"

            return R()

        monkeypatch.setattr("agentscrub.secrets.TRUFFLEHOG", tmp_path / "trufflehog")
        (tmp_path / "trufflehog").touch()
        with patch("agentscrub.secrets.subprocess.run", fake_run):
            found = _trufflehog(tmp_path)
        assert found[secret] == "OpenAI"

    def test_titus_decodes_groups(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import base64

        secret = "mysecretvalue12345"
        encoded = base64.b64encode(secret.encode()).decode().rstrip("=")
        payload = [{"rule_name": "Generic", "Groups": [encoded]}]

        def fake_run(cmd, **kwargs):
            class R:
                returncode = 0
                stdout = json.dumps(payload)

            return R()

        monkeypatch.setattr("agentscrub.secrets.TITUS", tmp_path / "titus")
        (tmp_path / "titus").touch()
        with patch("agentscrub.secrets.subprocess.run", fake_run):
            found = _titus(tmp_path)
        assert secret in found
