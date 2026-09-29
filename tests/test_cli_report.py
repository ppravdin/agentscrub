"""The numbers shown to the user must mean what their labels say."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from agentscrub import cli
from agentscrub.discover import ScanTarget
from agentscrub.redact import redact_sqlite


def _finding(kind: str, secret: str, hits: int) -> dict[str, object]:
    return {
        "type": kind,
        "proof": f"{kind} · pre…{secret[-2:]} · #{secret}",
        "_secret": secret * 4,
        "secret_hash": secret,
        "hits": hits,
    }


@pytest.fixture
def two_tools(tmp_path: Path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    return (
        ScanTarget(path=a, tool="a", display="Tool A"),
        ScanTarget(path=b, tool="b", display="Tool B"),
    )


class TestRedactionSummary:
    def test_counts_distinct_secrets_not_occurrences(self, two_tools) -> None:
        ta, tb = two_tools
        f1, f2 = ta.path / "s1.jsonl", tb.path / "s2.jsonl"
        findings = {
            f1: [_finding("JWT", "j1", 3), _finding("API Key", "k1", 100_000)],
            f2: [_finding("JWT", "j1", 2)],  # the same JWT, seen by a second tool
        }
        s = cli._redaction_summary([ta, tb], [f1, f2], findings)

        assert s["secrets"] == 2  # j1 and k1, not 100,005
        assert s["files"] == 2
        assert s["occurrences"] == 100_005
        assert dict(s["by_type"]) == {"JWT": 1, "API Key": 1}  # by secret, not by hits
        per = s["per_target"]
        assert (
            len(per[ta]["secrets"]) + len(per[tb]["secrets"]) == 3
        )  # > 2 unique: shown as a footnote

    def test_low_confidence_findings_are_not_counted(self, two_tools) -> None:
        ta, _ = two_tools
        f = ta.path / "x.jsonl"
        findings = {f: [_finding("JWT", "j1", 1), _finding("Password", "p1", 50)]}
        s = cli._redaction_summary(list(two_tools), [f], findings)
        assert s["secrets"] == 1 and s["occurrences"] == 1

    def test_file_outside_every_target_is_ignored(self, two_tools, tmp_path: Path) -> None:
        s = cli._redaction_summary(
            list(two_tools),
            [tmp_path / "elsewhere.log"],
            {tmp_path / "elsewhere.log": [_finding("JWT", "j1", 1)]},
        )
        assert s["files"] == 0 and s["secrets"] == 0


class TestSecretsRemoved:
    def test_only_secrets_from_files_that_were_cleaned_count(self, two_tools) -> None:
        ta, _ = two_tools
        ok, failed = ta.path / "ok.jsonl", ta.path / "failed.jsonl"
        findings = {
            ok: [_finding("JWT", "j1", 1)],
            failed: [_finding("JWT", "j1", 1), _finding("API Key", "k1", 1)],
        }
        # k1 only lives in the file that failed, so it is NOT removed
        assert cli._secrets_removed([ok], findings) == 1


class TestAuditReport:
    def _report(self, tmp_path, monkeypatch, agentscrub_paths, *, mode: str) -> str:
        monkeypatch.setattr(cli, "LOG_DIR", tmp_path / "logs")
        ta = ScanTarget(path=tmp_path / "a", tool="a", display="Tool A")
        (tmp_path / "a").mkdir(exist_ok=True)
        redact_me = ta.path / "redact.jsonl"
        only_reported = ta.path / "noise.jsonl"
        findings = {
            redact_me: [_finding("JWT", "j1", 7)],
            only_reported: [_finding("Password", "p1", 9)],
        }
        path = cli._write_scan_report(
            targets=[ta],
            flagged=[redact_me, only_reported],
            preserved=[],
            findings_by_file=findings,
            source_file_counts=[("Tool A", 1, 2, 500)],
            total_scanned_files=500,
            unique_patterns=1700,
            flagged_redactable_count=1,
            redactable_files={redact_me},
            secrets_to_redact=134,
            files_unchanged=300,
            mode=mode,
        )
        return path.read_text()

    def test_headline_numbers_are_labelled_for_what_they_are(
        self, tmp_path, monkeypatch, agentscrub_paths
    ) -> None:
        text = self._report(tmp_path, monkeypatch, agentscrub_paths, mode="scan")
        assert "Secrets to redact:  134" in text
        assert "Secrets found" not in text  # the old, ambiguous label
        assert "1,566 distinct values, reported only" in text  # 1700 - 134
        assert "300 unchanged since the last run" in text
        assert "Files checked:      500" in text  # not "scanned": 300 were not re-scanned

    def test_by_tool_separates_redact_from_reported_only(
        self, tmp_path, monkeypatch, agentscrub_paths
    ) -> None:
        text = self._report(tmp_path, monkeypatch, agentscrub_paths, mode="scan")
        line = next(ln for ln in text.splitlines() if ln.startswith("Tool A") and "500" in ln)
        cols = line.split()
        assert cols[2:5] == ["1", "1", "500"]  # To redact 1, Reported only 1, Checked 500

    def test_each_file_and_type_says_what_run_does(
        self, tmp_path, monkeypatch, agentscrub_paths
    ) -> None:
        text = self._report(tmp_path, monkeypatch, agentscrub_paths, mode="scan")
        assert "action=redact" in text and "action=report_only" in text
        assert any(
            ln.startswith("JWT") and ln.rstrip().endswith("redact") for ln in text.splitlines()
        )
        assert any(
            ln.startswith("Password") and ln.rstrip().endswith("report only")
            for ln in text.splitlines()
        )

    def test_run_mode_does_not_claim_a_read_only_scan(
        self, tmp_path, monkeypatch, agentscrub_paths
    ) -> None:
        scan = self._report(tmp_path, monkeypatch, agentscrub_paths, mode="scan")
        run = self._report(tmp_path, monkeypatch, agentscrub_paths, mode="run")
        assert "Files changed:      0 (read-only scan)" in scan and "Run next" in scan
        assert "read-only" not in run and "Run next" not in run
        assert "Outcome section" in run

    def test_outcome_is_appended_to_the_audit(self, tmp_path) -> None:
        report = tmp_path / "scan.txt"
        report.write_text("audit\n")
        cli._append_to_report(report, ["Outcome", "=======", "Files changed: 3"])
        assert report.read_text().endswith("Outcome\n=======\nFiles changed: 3\n")
        cli._append_to_report(None, ["ignored"])  # no audit written: must not raise


class TestSqliteExaminedCounts:
    def _db(self, path: Path, body: str) -> None:
        con = sqlite3.connect(path)
        con.execute("CREATE TABLE m (id INTEGER PRIMARY KEY, body TEXT)")
        con.execute("INSERT INTO m(body) VALUES (?)", (body,))
        con.commit()
        con.close()

    def test_databases_with_nothing_to_change_are_still_counted(self, tmp_path: Path) -> None:
        self._db(tmp_path / "a.db", "nothing here")
        self._db(tmp_path / "b.db", "or here")
        target = ScanTarget(path=tmp_path, tool="x", display="X")
        stats: dict[str, int] = {}
        total, results = redact_sqlite({"some-secret-value"}, [target], dry_run=True, stats=stats)
        assert (total, results) == (0, [])
        assert stats == {"checked": 2, "unchanged": 0, "errors": 0}  # not "no databases found"

        stats2: dict[str, int] = {}
        redact_sqlite({"some-secret-value"}, [target], dry_run=True, stats=stats2)
        assert stats2 == {
            "checked": 0,
            "unchanged": 2,
            "errors": 0,
        }  # second pass: skipped as verified


def test_counts_are_pluralized_correctly() -> None:
    assert cli._pl(1, "secret") == "1 secret"
    assert cli._pl(0, "file") == "0 files"
    assert cli._pl(1500, "secret") == "1,500 secrets"
