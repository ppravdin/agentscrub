"""Tests for cache.py — incremental scan cache."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from agentscrub import cache


class TestFileCache:
    def test_miss_then_hit(self, agentscrub_paths: Path, tmp_path: Path) -> None:
        fp = tmp_path / "clean.jsonl"
        fp.write_text("{}\n")

        needs, skipped = cache.filter_uncached([fp])
        assert fp in needs
        assert skipped == 0

        cache.mark_clean([fp])
        needs, skipped = cache.filter_uncached([fp])
        assert fp not in needs
        assert skipped == 1

    def test_mtime_change_invalidates(self, agentscrub_paths: Path, tmp_path: Path) -> None:
        fp = tmp_path / "mutate.jsonl"
        fp.write_text("{}\n")
        cache.mark_clean([fp])

        time.sleep(0.05)
        fp.write_text('{"changed":true}\n')

        needs, skipped = cache.filter_uncached([fp])
        assert fp in needs
        assert skipped == 0

    def test_same_metadata_but_changed_content_invalidates(
        self, agentscrub_paths: Path, tmp_path: Path
    ) -> None:
        fp = tmp_path / "same-stat.jsonl"
        fp.write_text("AAAA\n")
        cache.mark_clean([fp])
        st = fp.stat()
        fp.write_text("BBBB\n")
        os.utime(fp, ns=(st.st_atime_ns, st.st_mtime_ns))

        needs, skipped = cache.filter_uncached([fp])
        assert fp in needs
        assert skipped == 0

    def test_invalidate_forces_rescan(self, agentscrub_paths: Path, tmp_path: Path) -> None:
        fp = tmp_path / "redacted.jsonl"
        fp.write_text("{}\n")
        cache.mark_clean([fp])
        cache.invalidate([fp])

        needs, skipped = cache.filter_uncached([fp])
        assert fp in needs
        assert skipped == 0

    def test_detector_fingerprint_wipe(self, agentscrub_paths: Path, tmp_path: Path) -> None:
        fp = tmp_path / "f.jsonl"
        fp.write_text("{}\n")
        cache.filter_uncached([fp])  # seed detector_fingerprint in meta
        cache.mark_clean([fp])

        con = cache._connect()
        con.execute(
            "UPDATE meta SET value = ? WHERE key = 'detector_fingerprint'",
            (json.dumps({"versions": {"x": "0"}, "installed": {}}),),
        )
        con.commit()
        con.close()

        needs, _ = cache.filter_uncached([fp])
        assert fp in needs


class TestPlanScan:
    def test_hit_reads_no_file_content(
        self, agentscrub_paths: Path, tmp_path: Path, monkeypatch
    ) -> None:
        fp = tmp_path / "quiet.jsonl"
        fp.write_text("{}\n")
        cache.mark_clean([fp])

        def boom(*a, **k):
            raise AssertionError("cache hit must not read the file")

        monkeypatch.setattr(cache, "_sample_digests", boom)
        plan = cache.plan_scan([fp])
        assert plan.n_skipped == 1 and not plan.needs_scan

    def test_chmod_only_still_hits_via_fingerprint(
        self, agentscrub_paths: Path, tmp_path: Path
    ) -> None:
        fp = tmp_path / "chmod.jsonl"
        fp.write_text("{}\n")
        cache.mark_clean([fp])
        os.chmod(fp, 0o600)   # bumps ctime, not content
        plan = cache.plan_scan([fp])
        assert plan.n_skipped == 1

    def test_grown_log_resumes_from_previous_end(
        self, agentscrub_paths: Path, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.setattr(cache, "RESUME_MIN_SIZE", 1024)
        fp = tmp_path / "big.jsonl"
        fp.write_text("x" * 5000 + "\n")
        old_size = fp.stat().st_size
        cache.mark_clean([fp])

        with fp.open("a") as fh:
            fh.write("new line\n")
        plan = cache.plan_scan([fp])
        assert plan.needs_scan == [fp]
        assert plan.offsets == {fp: old_size}

    def test_rewritten_prefix_forces_full_rescan(
        self, agentscrub_paths: Path, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.setattr(cache, "RESUME_MIN_SIZE", 1024)
        fp = tmp_path / "rewritten.jsonl"
        fp.write_text("a" * 5000 + "\n")
        cache.mark_clean([fp])
        fp.write_text("b" * 5000 + "\nmore\n")   # bigger, but the old bytes changed
        plan = cache.plan_scan([fp])
        assert plan.needs_scan == [fp]
        assert plan.offsets == {}

    def test_bytes_appended_during_scan_are_not_claimed_clean(
        self, agentscrub_paths: Path, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.setattr(cache, "RESUME_MIN_SIZE", 1024)
        fp = tmp_path / "live.jsonl"
        fp.write_text("x" * 5000 + "\n")
        scanned_size = fp.stat().st_size

        plan = cache.plan_scan([fp])          # scan starts here
        with fp.open("a") as fh:               # ...the agent keeps writing
            fh.write("secret appended mid-scan\n")
        cache.mark_clean([fp], plan)           # scan finishes

        plan2 = cache.plan_scan([fp])
        assert plan2.needs_scan == [fp]        # NOT treated as clean
        assert plan2.offsets == {fp: scanned_size}

    def test_many_files_do_not_exceed_sql_variable_limit(
        self, agentscrub_paths: Path, tmp_path: Path
    ) -> None:
        files = []
        for i in range(1500):
            f = tmp_path / f"f{i}.jsonl"
            f.write_text("{}\n")
            files.append(f)
        cache.mark_clean(files)
        plan = cache.plan_scan(files)
        assert plan.n_skipped == 1500


class TestDbCache:
    def _db(self, tmp_path: Path) -> Path:
        import sqlite3

        db = tmp_path / "a.db"
        con = sqlite3.connect(db)
        con.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
        con.execute("INSERT INTO t(v) VALUES ('hello')")
        con.commit()
        con.close()
        return db

    def test_verified_db_skipped_until_it_changes_or_new_secret(
        self, agentscrub_paths: Path, tmp_path: Path
    ) -> None:
        db = self._db(tmp_path)
        secrets = {"secret-one-aaaa", "secret-two-bbbb"}
        assert cache.db_unchecked_secrets(db, secrets) == secrets

        cache.mark_db_checked(db, secrets, cache.db_state(db))
        assert cache.db_unchecked_secrets(db, secrets) == set()
        # A secret discovered later is checked alone, not everything again.
        assert cache.db_unchecked_secrets(db, secrets | {"secret-new-cccc"}) == {"secret-new-cccc"}

        time.sleep(0.02)
        with db.open("ab") as fh:
            fh.write(b"\0")
        assert cache.db_unchecked_secrets(db, secrets) == secrets

    def test_plaintext_secrets_are_never_stored(
        self, agentscrub_paths: Path, tmp_path: Path
    ) -> None:
        db = self._db(tmp_path)
        cache.mark_db_checked(db, {"super-secret-value-123"}, cache.db_state(db))
        raw = (agentscrub_paths / "state.db").read_bytes()
        assert b"super-secret-value-123" not in raw
