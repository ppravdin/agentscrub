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
