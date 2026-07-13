"""Tests for redact.py — credential preservation, labeling, and redaction."""

from __future__ import annotations

import json
import sqlite3
import stat
from pathlib import Path

import pytest

from agentscrub.discover import ScanTarget
from agentscrub.redact import (
    REDACTED,
    _proof,
    _redact_obj,
    _redact_raw_line,
    _short_label,
    collect_files,
    file_findings,
    grep_filter,
    is_high_precision_label,
    is_low_signal_label,
    is_managed_credential_file,
    partition_secrets_by_precision,
    redact_file,
    redact_short_text,
    redact_sqlite,
    top_exposed,
)


class TestManagedCredentials:
    def test_claude_credentials_managed(self, fake_home: Path) -> None:
        p = fake_home / ".claude" / ".credentials.json"
        p.parent.mkdir(parents=True)
        p.write_text("{}")
        assert is_managed_credential_file(p)

    def test_session_log_not_managed(self, fake_home: Path) -> None:
        p = fake_home / ".claude" / "projects" / "x" / "session.jsonl"
        p.parent.mkdir(parents=True)
        p.write_text("{}")
        assert not is_managed_credential_file(p)

    def test_mcp_auth_tree_managed(self, fake_home: Path) -> None:
        p = fake_home / ".mcp-auth" / "server" / "tokens.json"
        p.parent.mkdir(parents=True)
        p.write_text("{}")
        assert is_managed_credential_file(p)

    def test_suffix_match_codex_auth(self, tmp_path: Path) -> None:
        p = tmp_path / "somewhere" / ".codex" / "auth.json"
        p.parent.mkdir(parents=True)
        p.write_text("{}")
        assert is_managed_credential_file(p)


class TestLabelPrecision:
    def test_low_signal_labels(self) -> None:
        assert is_low_signal_label("Uri")
        assert not is_low_signal_label("JWT")

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("jwt", "JWT"),
            ("github-pat", "GitHub PAT"),
            ("npm access token fine grained", "NPM Token"),
            ("unknown", "Secret"),
        ],
    )
    def test_short_label(self, raw: str, expected: str) -> None:
        assert _short_label(raw) == expected

    @pytest.mark.parametrize(
        "label,precise",
        [
            ("JWT", True),
            ("jwt", True),
            ("npm-token", True),
            ("Postgres URI", False),
            ("Bearer Token", False),
            ("Generic Secret", False),
        ],
    )
    def test_high_precision(self, label: str, precise: bool) -> None:
        assert is_high_precision_label(label) is precise

    def test_partition_splits_by_precision(self, sample_secret: str) -> None:
        generic = "postgres://user:pass@localhost/db"
        secrets = {sample_secret, generic}
        type_map = {
            sample_secret: "github-pat",
            generic: "Postgres URI",
        }
        redactable, report_only = partition_secrets_by_precision(secrets, type_map)
        assert sample_secret in redactable
        assert generic in report_only
        assert sample_secret not in report_only


class TestProof:
    def test_proof_never_contains_full_secret(self, sample_secret: str) -> None:
        proof = _proof(sample_secret, "github-pat")
        assert sample_secret not in proof
        assert "#" in proof

    def test_proof_short_secret(self) -> None:
        proof = _proof("short12", "jwt")
        assert "short12" not in proof


class TestRedactObj:
    def test_nested_json_redaction(self, sample_secret: str) -> None:
        obj = {"messages": [{"content": f"key={sample_secret}"}]}
        new, n = _redact_obj(obj, frozenset({sample_secret}))
        assert n >= 1
        assert sample_secret not in json.dumps(new)
        assert REDACTED in json.dumps(new)

    def test_raw_line_redaction(self, sample_secret: str) -> None:
        line = f"export TOKEN={sample_secret}\n"
        new, n = _redact_raw_line(line, frozenset({sample_secret}))
        assert n == 1
        assert REDACTED in new
        assert sample_secret not in new


class TestRedactShortText:
    def test_redacts_known_secret_in_terminal_line(self, sample_secret: str) -> None:
        text = f"request failed: Authorization: Bearer {sample_secret}"
        new, count = redact_short_text(text, {sample_secret})
        assert count == 1
        assert sample_secret not in new
        assert REDACTED in new

    def test_redacts_high_precision_token_without_known_secret_set(self) -> None:
        token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
        new, count = redact_short_text(f"remote: token={token}")
        assert count == 1
        assert token not in new
        assert new == f"remote: token={REDACTED}"

    def test_redacts_short_multiline_terminal_update(self) -> None:
        aws_key = "AKIAIOSFODNN7EXAMPLE"
        text = f"line 1\nline 2\nAWS_ACCESS_KEY_ID={aws_key}\nline 4\n"
        new, count = redact_short_text(text)
        assert count == 1
        assert aws_key not in new
        assert REDACTED in new

    def test_large_text_returns_unchanged(self) -> None:
        token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
        text = ("clean\n" * 8) + token
        new, count = redact_short_text(text)
        assert count == 0
        assert new == text

    def test_high_entropy_token_requires_explicit_opt_in(self) -> None:
        token = "ZxPrtgigTMcYHx3@NtXyMMoipkzTrHWfzTY4PsT6gg83xjL3Jxuci@mX7u_32NeN"
        text = f"value={token}"
        unchanged, count = redact_short_text(text)
        assert count == 0
        assert unchanged == text

        redacted, count = redact_short_text(text, high_entropy=True)
        assert count == 1
        assert token not in redacted
        assert redacted == "value=[REDACTED]"


class TestRedactFile:
    def test_jsonl_redacted_on_disk(self, tmp_path: Path, sample_secret: str) -> None:
        fp = tmp_path / "line.jsonl"
        fp.write_text(
            json.dumps({"content": sample_secret}) + "\n",
            encoding="utf-8",
        )
        path_str, count, err = redact_file((str(fp), frozenset({sample_secret}), False))
        assert err is None
        assert count >= 1
        assert sample_secret not in fp.read_text()
        assert REDACTED in fp.read_text()

    def test_dry_run_leaves_file(self, tmp_path: Path, sample_secret: str) -> None:
        fp = tmp_path / "line.jsonl"
        original = json.dumps({"content": sample_secret}) + "\n"
        fp.write_text(original, encoding="utf-8")
        _, count, _ = redact_file((str(fp), frozenset({sample_secret}), True))
        assert count >= 1
        assert fp.read_text() == original

    def test_plain_text_line(self, tmp_path: Path, sample_secret: str) -> None:
        fp = tmp_path / "plain.log"
        fp.write_text(f"password={sample_secret}\n", encoding="utf-8")
        _, count, _ = redact_file((str(fp), frozenset({sample_secret}), False))
        assert count >= 1
        assert REDACTED in fp.read_text()

    def test_redaction_preserves_file_mode(self, tmp_path: Path, sample_secret: str) -> None:
        fp = tmp_path / "restricted.log"
        fp.write_text(f"password={sample_secret}\n", encoding="utf-8")
        fp.chmod(0o600)
        redact_file((str(fp), frozenset({sample_secret}), False))
        assert stat.S_IMODE(fp.stat().st_mode) == 0o600


class TestCollectFiles:
    def test_excludes_telemetry_dir(self, fake_home: Path, scan_target: ScanTarget) -> None:
        telem = fake_home / ".claude" / "telemetry" / "events.json"
        telem.parent.mkdir(parents=True)
        telem.write_text("{}")
        files = collect_files([scan_target])
        assert telem not in files

    def test_includes_session_logs(self, claude_tree: Path, scan_target: ScanTarget) -> None:
        files = collect_files([scan_target])
        assert any("session.jsonl" in str(f) for f in files)


class TestGrepFilter:
    @pytest.mark.needs_grep
    def test_finds_files_with_secret(self, tmp_path: Path, sample_secret: str) -> None:
        a = tmp_path / "a.txt"
        b = tmp_path / "b.txt"
        a.write_text(sample_secret)
        b.write_text("clean")
        hits = grep_filter({sample_secret}, [a, b])
        assert a in hits
        assert b not in hits


class TestFileFindings:
    def test_findings_shape(self, tmp_path: Path, sample_secret: str) -> None:
        fp = tmp_path / "a.txt"
        fp.write_text(sample_secret, encoding="utf-8")
        findings = file_findings({sample_secret}, fp, {sample_secret: "github-pat"})
        assert len(findings) == 1
        assert findings[0]["type"] == "GitHub PAT"
        assert sample_secret not in str(findings[0]["proof"])
        assert findings[0]["hits"] == 1


class TestTopExposed:
    def test_ranks_by_unique_patterns(self, tmp_path: Path, sample_secret: str) -> None:
        a = tmp_path / "a.txt"
        b = tmp_path / "b.txt"
        other = "sk-othersecretvalue123456789012345678"
        a.write_text(sample_secret + "\n" + other, encoding="utf-8")
        b.write_text(sample_secret, encoding="utf-8")
        secrets = {sample_secret, other}
        type_map = {sample_secret: "github-pat", other: "openai-api-key"}
        top = top_exposed(secrets, [a, b], n=2, type_map=type_map)
        assert len(top) == 2
        assert top[0][0] == a  # more unique patterns


class TestRedactSqlite:
    def test_redacts_text_column(
        self,
        tmp_path: Path,
        vscdb_with_secret: Path,
        sample_secret: str,
        scan_target: ScanTarget,
    ) -> None:
        target = ScanTarget(
            path=tmp_path,
            tool="cursor",
            display="Cursor",
        )
        # Copy vscdb into target tree
        dest = tmp_path / "state.vscdb"
        dest.write_bytes(vscdb_with_secret.read_bytes())

        total, results = redact_sqlite({sample_secret}, [target], dry_run=False)
        assert total >= 1
        con = sqlite3.connect(dest)
        val = con.execute("SELECT value FROM ItemTable").fetchone()[0]
        con.close()
        assert sample_secret not in val
        assert REDACTED in val
