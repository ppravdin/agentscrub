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

    def test_redacts_every_row_across_pagination_batches(
        self, tmp_path: Path, sample_secret: str
    ) -> None:
        """Rows are read in batches while UPDATEs run; none may be skipped."""
        dest = tmp_path / "big.db"
        con = sqlite3.connect(dest)
        con.execute("CREATE TABLE msgs (id INTEGER PRIMARY KEY, data TEXT)")
        n_rows = 1000  # several pages of the internal batch size
        con.executemany(
            "INSERT INTO msgs(data) VALUES (?)",
            [(f"row {i} " + "x" * 200 + f" key={sample_secret}",) for i in range(n_rows)],
        )
        con.commit()
        con.close()

        target = ScanTarget(path=tmp_path, tool="cursor", display="Cursor")
        total, _ = redact_sqlite({sample_secret}, [target], dry_run=False)

        assert total == n_rows
        con = sqlite3.connect(dest)
        leaked = con.execute(
            "SELECT COUNT(*) FROM msgs WHERE data LIKE ?", (f"%{sample_secret}%",)
        ).fetchone()[0]
        redacted = con.execute(
            "SELECT COUNT(*) FROM msgs WHERE data LIKE ?", (f"%{REDACTED}%",)
        ).fetchone()[0]
        con.close()
        assert leaked == 0
        assert redacted == n_rows


class TestLargeFiles:
    def test_collect_files_has_no_size_limit(self, tmp_path: Path) -> None:
        from agentscrub.redact import collect_files

        big = tmp_path / "session.jsonl"
        with big.open("w") as fh:
            for _ in range(120_000):
                fh.write("x" * 99 + "\n")  # ~12 MB, past the old 10 MB cap
        assert big.stat().st_size > 10 * 1024 * 1024
        target = ScanTarget(path=tmp_path, tool="claude", display="Claude Code")
        assert big in collect_files([target])

    @pytest.mark.parametrize("offset", [0, 1, 37, 90, 99, 100, 101, 150, 297, 298, 299, 300])
    def test_oversized_line_redacted_across_block_boundaries(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sample_secret: str, offset: int
    ) -> None:
        import agentscrub.redact as R

        monkeypatch.setattr(R, "_MAX_JSON_LINE_CHARS", 100)
        line = "a" * offset + sample_secret + "b" * (700 - offset)
        fp = tmp_path / "huge.jsonl"
        fp.write_text("first\n" + line + "\nlast\n")

        _, n, err = R.redact_file((str(fp), frozenset({sample_secret}), False))
        assert err is None and n == 1
        text = fp.read_text()
        assert sample_secret not in text
        assert text == "first\n" + "a" * offset + R.REDACTED + "b" * (700 - offset) + "\nlast\n"

    def test_oversized_line_without_trailing_newline(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sample_secret: str
    ) -> None:
        import agentscrub.redact as R

        monkeypatch.setattr(R, "_MAX_JSON_LINE_CHARS", 100)
        fp = tmp_path / "huge.txt"
        fp.write_text("z" * 250 + sample_secret + "z" * 250)
        _, n, err = R.redact_file((str(fp), frozenset({sample_secret}), False))
        assert err is None and n == 1
        assert fp.read_text() == "z" * 250 + R.REDACTED + "z" * 250

    def test_file_findings_counts_across_block_boundaries(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sample_secret: str
    ) -> None:
        import agentscrub.redact as R

        monkeypatch.setattr(R, "_FINDINGS_BLOCK_CHARS", 64)
        body = ("q" * 50 + sample_secret) * 7 + "tail"
        fp = tmp_path / "f.log"
        fp.write_text(body)
        findings = R.file_findings({sample_secret}, fp, {})
        assert len(findings) == 1 and findings[0]["hits"] == 7


class TestSqliteCacheAndSafety:
    def _make_db(self, tmp_path: Path, secret: str) -> Path:
        db = tmp_path / "hist.db"
        con = sqlite3.connect(db)
        con.execute("CREATE TABLE m (id INTEGER PRIMARY KEY, body TEXT)")
        con.executemany("INSERT INTO m(body) VALUES (?)", [("hello",), ("world",)])
        con.commit()
        con.close()
        return db

    def test_unchanged_clean_db_is_not_rescanned(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sample_secret: str
    ) -> None:
        import agentscrub.redact as R

        db = self._make_db(tmp_path, sample_secret)
        target = ScanTarget(path=tmp_path, tool="cursor", display="Cursor")
        calls: list[set[str]] = []
        real = R._redact_one_db
        monkeypatch.setattr(
            R, "_redact_one_db", lambda p, s, d: (calls.append(set(s)), real(p, s, d))[1]
        )

        R.redact_sqlite({sample_secret}, [target], dry_run=True)
        R.redact_sqlite({sample_secret}, [target], dry_run=True)
        assert len(calls) == 1  # second run skipped the DB

        R.redact_sqlite({sample_secret, "another-new-secret-value"}, [target], dry_run=True)
        assert calls[-1] == {"another-new-secret-value"}  # only the new one is searched

        con = sqlite3.connect(db)
        con.execute("INSERT INTO m(body) VALUES (?)", (f"leak {sample_secret}",))
        con.commit()
        con.close()
        total, res = R.redact_sqlite({sample_secret}, [target], dry_run=True)
        assert total == 1 and res[0][0] == db  # a changed DB is scanned again

    def test_only_paths_limits_the_live_pass(self, tmp_path: Path, sample_secret: str) -> None:
        import agentscrub.redact as R

        a, b = tmp_path / "a.db", tmp_path / "b.db"
        for db in (a, b):
            con = sqlite3.connect(db)
            con.execute("CREATE TABLE m (id INTEGER PRIMARY KEY, body TEXT)")
            con.execute("INSERT INTO m(body) VALUES (?)", (f"x {sample_secret}",))
            con.commit()
            con.close()
        target = ScanTarget(path=tmp_path, tool="cursor", display="Cursor")
        total, res = R.redact_sqlite({sample_secret}, [target], dry_run=False, only_paths={a})
        assert [p for p, _, _ in res] == [a]
        assert sample_secret in sqlite3.connect(b).execute("SELECT body FROM m").fetchone()[0]

    def test_connection_closed_when_scan_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sample_secret: str
    ) -> None:
        import agentscrub.redact as R

        db = tmp_path / "broken.db"
        db.write_bytes(b"SQLite format 3\0" + b"\xff" * 4096)  # corrupt
        opened: list[_Tracked] = []
        real_connect = sqlite3.connect

        class _Tracked:
            def __init__(self, con: sqlite3.Connection) -> None:
                self.con, self.closed = con, False

            def __getattr__(self, name: str):
                return getattr(self.con, name)

            def close(self) -> None:
                self.closed = True
                self.con.close()

        def tracking_connect(*a, **k):
            t = _Tracked(real_connect(*a, **k))
            opened.append(t)
            return t

        monkeypatch.setattr(R.sqlite3, "connect", tracking_connect)
        target = ScanTarget(path=tmp_path, tool="cursor", display="Cursor")
        total, res = R.redact_sqlite({sample_secret}, [target], dry_run=False)
        assert res and res[0][1] == -1  # reported as an error
        assert opened and all(t.closed for t in opened)


class TestShortTextRedaction:
    @pytest.mark.parametrize(
        "text",
        [
            '{"monkey": "banana"}',
            '{"hockey": "regular_value"}',
            'TURKEY: "sandwich"',
        ],
    )
    def test_colon_assignments_require_secret_key_segments_and_strong_values(
        self, text: str
    ) -> None:
        res, count = redact_short_text(text)
        assert count == 0
        assert res == text

    def test_long_text_assignment_is_not_hidden_by_marker_gate(self) -> None:
        secret = "PjRLVUtHmD5Na2FGpBTC1NmAMkozbyKVVhf_CE5d7Po"
        text = ("x" * 140) + f"api_token_value={secret}"
        res, count = redact_short_text(text)
        assert count == 1
        assert secret not in res
        assert res.startswith("x" * 140 + "api_")

    def test_bearer_scheme_is_case_insensitive(self) -> None:
        token = "PjRLVUtHmD5Na2FGpBTC1NmAMkozbyKVVhf"
        res, count = redact_short_text(f"BEARER {token}")
        assert count == 1
        assert token not in res

    def test_vendor_like_value_falls_back_to_generic_redaction(self) -> None:
        value = "sk-abcdefghijklmnop-qrstuvwxyz-1234567890"
        res, count = redact_short_text(f"api_token={value}")
        assert count == 1
        assert value not in res
        assert res == REDACTED

    @pytest.mark.parametrize(
        "suffix", ["-extraSECRET", "/extraSECRET", "=extraSECRET", ".extraSECRET"]
    )
    def test_vendor_prefix_with_suffix_falls_back_to_whole_value(self, suffix: str) -> None:
        value = "ghp_abcdefghijklmnopqrstuvwxyz1234567890" + suffix
        res, count = redact_short_text(f"api_token={value}")
        assert count == 1
        assert value not in res
        assert res == REDACTED

    def test_vendor_token_followed_by_sentence_period_is_redacted(self) -> None:
        token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
        res, count = redact_short_text(f"leaked {token}.")
        assert count == 1
        assert token not in res
        assert res.endswith(".")

    @pytest.mark.parametrize(
        "key",
        [
            "accessToken",
            "clientSecret",
            "apiKey",
            "dbPassword",
            "tokenValue",
            "secretValue",
            "APIKey",
            "JWTSecret",
        ],
    )
    def test_redacts_camel_case_credential_keys(self, key: str) -> None:
        value = "PjRLVUtHmD5Na2FGpBTC1NmAMkozbyKVVhf_CE5d7Po"
        res, count = redact_short_text(f'{{"{key}": "{value}"}}')
        assert count == 1
        assert value not in res

    @pytest.mark.parametrize(
        "key", ["accessTokenExpires", "refreshTokenExpiresAt", "tokenType", "secretName", "monKey"]
    )
    def test_ignores_metadata_and_ambiguous_camel_keys(self, key: str) -> None:
        value = "2026-08-12T12:34:56Z"
        res, count = redact_short_text(f'{{"{key}": "{value}"}}')
        assert count == 0
        assert res == f'{{"{key}": "{value}"}}'

    def test_assignment_heuristic_uses_key_semantics(self) -> None:
        password = "qjzmxncbvlasdfgh"
        res, count = redact_short_text(f"PASSWORD: {password}")
        assert count == 1
        assert password not in res

        public_key = "AAAAB3NzaC1yc2EAAAADAQABAAABAQC7"
        res, count = redact_short_text(f"PUBLIC_KEY: {public_key}")
        assert count == 0
        assert res == f"PUBLIC_KEY: {public_key}"

        placeholder = "ExamplePlaceholder1234"
        res, count = redact_short_text(f"TOKEN: {placeholder}")
        assert count == 0
        assert res == f"TOKEN: {placeholder}"

    def test_redacts_redis_url(self) -> None:
        from agentscrub.redact import redact_short_text

        text = "REDIS_URL: redis://:b27f91a87b9dce7f0f3dc9fe42a50d38f223e4c26f435310247bf1114b1384eb@dokku-redis-aiche-redis:6379"
        res, count = redact_short_text(text)
        assert count == 1
        assert "b27f91a87b9dce7f0f3dc9fe42a50d38f223e4c26f435310247bf1114b1384eb" not in res
        assert REDACTED in res

    def test_redacts_shell_secret_variable(self) -> None:
        from agentscrub.redact import redact_short_text

        text = 'REDIS_PW="b27f91a87b9dce7f0f3dc9fe42a50d38f223e4c26f435310247bf1114b1384eb"'
        res, count = redact_short_text(text)
        assert count == 1
        assert "b27f91a87b9dce7f0f3dc9fe42a50d38f223e4c26f435310247bf1114b1384eb" not in res
        assert REDACTED in res

    def test_redacts_redis_cli_auth(self) -> None:
        from agentscrub.redact import redact_short_text

        text = 'redis-cli -a "mysecretpassword123"'
        res, count = redact_short_text(text)
        assert count == 1
        assert "mysecretpassword123" not in res
        assert REDACTED in res

    def test_redacts_colon_separated_token(self) -> None:
        from agentscrub.redact import redact_short_text

        text = "+AICHE_DEBUG_TOKEN: PjRLVUtHmD5Na2FGpBTC1NmAMkozbyKVVhf_CE5d7Po"
        res, count = redact_short_text(text)
        assert count == 1
        assert "PjRLVUtHmD5Na2FGpBTC1NmAMkozbyKVVhf_CE5d7Po" not in res
        assert REDACTED in res

    def test_redacts_quoted_json_key(self) -> None:
        from agentscrub.redact import redact_short_text

        text = '"AICHE_DEBUG_TOKEN": "PjRLVUtHmD5Na2FGpBTC1NmAMkozbyKVVhf_CE5d7Po"'
        res, count = redact_short_text(text)
        assert count == 1
        assert "PjRLVUtHmD5Na2FGpBTC1NmAMkozbyKVVhf_CE5d7Po" not in res
        assert REDACTED in res

    def test_redacts_long_line_lowercase_key(self) -> None:
        from agentscrub.redact import redact_short_text

        padding = "padding_" * 16
        text = f"{padding}api_key=PjRLVUtHmD5Na2FGpBTC1NmAMkozbyKVVhf_CE5d7Po"
        assert len(text) > 128
        res, count = redact_short_text(text)
        assert count == 1
        assert "PjRLVUtHmD5Na2FGpBTC1NmAMkozbyKVVhf_CE5d7Po" not in res
        assert REDACTED in res

    def test_redacts_lowercase_password_colon(self) -> None:
        from agentscrub.redact import redact_short_text

        text = "password: hunter2secretvalue_abcdefghij"
        res, count = redact_short_text(text)
        assert count == 1
        assert "hunter2secretvalue_abcdefghij" not in res
        assert REDACTED in res

    def test_redacts_bearer_tokens(self) -> None:
        from agentscrub.redact import redact_short_text

        t1 = "Authorization: Bearer PjRLVUtHmD5Na2FGpBTC1NmAMkozbyKVVhf"
        res1, count1 = redact_short_text(t1)
        assert count1 == 1
        assert "PjRLVUtHmD5Na2FGpBTC1NmAMkozbyKVVhf" not in res1
        assert REDACTED in res1

        t2 = "AUTH_TOKEN: Bearer PjRLVUtHmD5Na2FGpBTC1NmAMkozbyKVVhf"
        res2, count2 = redact_short_text(t2)
        assert count2 == 1
        assert "PjRLVUtHmD5Na2FGpBTC1NmAMkozbyKVVhf" not in res2
        assert REDACTED in res2

    def test_prevents_colon_false_positives(self) -> None:
        from agentscrub.redact import redact_short_text

        prose_samples = [
            "API_KEY: not set",
            "PUBLIC_KEY: ssh-rsa AAAA...",
            "KEYWORDS: python, security",
            "AUTH: ok",
        ]
        for line in prose_samples:
            res, count = redact_short_text(line)
            assert count == 0
            assert res == line
