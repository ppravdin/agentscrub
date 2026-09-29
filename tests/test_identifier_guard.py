"""Values that merely look like IDs, paths or hostnames must never be rewritten."""

from __future__ import annotations

import pytest

from agentscrub import cli
from agentscrub.discover import ScanTarget
from agentscrub.redact import (
    is_redactable_finding,
    looks_like_identifier,
    partition_secrets_by_precision,
)

UUID = "6971a2f0-1b2c-4d3e-8f90-a1b2c3d4e5f6"
REAL_GHP = "ghp_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"


class TestLooksLikeIdentifier:
    @pytest.mark.parametrize(
        ("value", "why"),
        [
            (UUID, "UUID"),
            (UUID.upper(), "UUID"),
            ("0123456789abcdef0123456789abcdef01234567", "git commit hash"),
            ("home/p/code/project/tool.py", "file path"),
            ("/home/p/.config/app/settings.json", "file path"),
            ("~/notes/todo.md", "file path"),
            ("boca-1a2b3c4d5", "hostname or slug"),
            ("web-server-01", "hostname or slug"),
        ],
    )
    def test_identifiers_are_recognised(self, value: str, why: str) -> None:
        assert looks_like_identifier(value) == why

    @pytest.mark.parametrize(
        "value",
        [
            REAL_GHP,
            "sk-ant-api03-abcDEF123456ghiJKL",
            "tly-dev-abcdef123456",  # lowercase-hyphenated, but a real vendor prefix
            "pplx-abcdef1234567890",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEF123",
            "Zm9vYmFy/abcDEF+123456789012345678901234==",  # base64 with "/" is not a path
            "AIzaSyA-1234567890abcdefghijklmnopqrstu",
            "0123456789abcdef0123456789abcdef",  # 32-hex may be a real key: stays redactable
            "AKIAIOSFODNN7EXAMPLE",
            "-----BEGIN PRIVATE KEY-----",
        ],
    )
    def test_real_credentials_are_never_vetoed(self, value: str) -> None:
        assert looks_like_identifier(value) is None


class TestGuardIsAppliedEverywhere:
    def test_partition_reports_but_does_not_redact_identifiers(self) -> None:
        secrets = {UUID, REAL_GHP, "boca-1a2b3c4d5"}
        type_map = {
            UUID: "npm-access-token",
            REAL_GHP: "github-pat",
            "boca-1a2b3c4d5": "generic-api-key",
        }
        redactable, report_only = partition_secrets_by_precision(secrets, type_map)
        assert redactable == {REAL_GHP}
        assert report_only == {UUID, "boca-1a2b3c4d5"}

    def test_finding_level_decision(self) -> None:
        good = {"type": "GitHub PAT", "_secret": REAL_GHP}
        uuid = {"type": "NPM Token", "_secret": UUID}
        assert is_redactable_finding(good) is True
        assert is_redactable_finding(uuid) is False  # trusted label, identifier value
        assert is_redactable_finding({"type": "Password", "_secret": REAL_GHP}) is False

    def test_summary_excludes_lookalikes_and_counts_them(self, tmp_path) -> None:
        t = ScanTarget(path=tmp_path, tool="a", display="A")
        f = tmp_path / "s.jsonl"

        def finding(kind: str, secret: str, hits: int) -> dict[str, object]:
            return {
                "type": kind,
                "proof": kind,
                "_secret": secret,
                "secret_hash": secret[:8],
                "hits": hits,
            }

        findings = {f: [finding("GitHub PAT", REAL_GHP, 3), finding("NPM Token", UUID, 40_000)]}
        s = cli._redaction_summary([t], [f], findings)
        assert (
            s["secrets"] == 1 and s["occurrences"] == 3
        )  # the 40,000 UUID hits are not "to redact"
        assert s["lookalikes"] == 1
        assert cli._secrets_removed([f], findings) == 1
