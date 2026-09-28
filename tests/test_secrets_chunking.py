"""Chunked, bounded-memory staging of large files for the detectors."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentscrub import secrets as S


def _finder(needles: set[str], seen_dirs: list[Path] | None = None):
    """Fake detector: reports every needle found in any staged file."""

    def fn(d: Path) -> dict[str, str]:
        if seen_dirs is not None:
            seen_dirs.append(d)
        out: dict[str, str] = {}
        for f in d.iterdir():
            data = f.read_bytes().decode("utf-8", "ignore")
            for n in needles:
                if n in data:
                    out[n] = "fake"
        return out

    return fn


@pytest.fixture(autouse=True)
def small_chunks(monkeypatch: pytest.MonkeyPatch, agentscrub_paths: Path) -> None:
    monkeypatch.setattr(S, "CHUNK_BYTES", 256)
    monkeypatch.setattr(S, "BATCH_BYTES", 1024)
    monkeypatch.setattr(S, "_FORCED_SPLIT_OVERLAP", 64)


class TestIterChunks:
    def test_chunks_cover_file_and_end_on_newlines(self, tmp_path: Path) -> None:
        fp = tmp_path / "log.jsonl"
        lines = [f"line-{i:05d} " + "x" * (i % 40) + "\n" for i in range(400)]
        fp.write_text("".join(lines))
        chunks = list(S._iter_chunks(fp))
        assert len(chunks) > 5
        assert b"".join(chunks) == fp.read_bytes()
        assert all(c.endswith(b"\n") for c in chunks)
        assert all(len(c) <= 2 * S.CHUNK_BYTES for c in chunks)

    def test_giant_single_line_is_split_with_overlap(self, tmp_path: Path) -> None:
        fp = tmp_path / "blob.jsonl"
        secret = "sk-ant-STRADDLE1234567890"
        # place the secret across the first forced cut (2 * CHUNK_BYTES)
        pos = 2 * S.CHUNK_BYTES - 10
        body = "A" * pos + secret + "B" * 2000
        fp.write_text(body + "\n")
        found = [c for c in S._iter_chunks(fp) if secret.encode() in c]
        assert found, "a secret at a forced split must appear whole in some chunk"


class TestRunOnFiles:
    def test_secret_deep_inside_large_file_is_found(self, tmp_path: Path) -> None:
        secret = "ghp_DEEPINSIDEFILE1234567890"
        fp = tmp_path / "huge.jsonl"
        lines = ["filler " * 8 + "\n"] * 3000
        lines[2100] = f"token {secret}\n"
        fp.write_text("".join(lines))
        assert fp.stat().st_size > 20 * S.CHUNK_BYTES

        assert S._run_on_files([fp], _finder({secret})) == {secret: "fake"}

    def test_batches_are_bounded_and_staging_is_cleaned_up(self, tmp_path: Path) -> None:
        fp = tmp_path / "huge.jsonl"
        fp.write_text(("y" * 100 + "\n") * 2000)  # ~200 KB, batch limit is 1 KB
        dirs: list[Path] = []
        staged_bytes: list[int] = []

        def fn(d: Path) -> dict[str, str]:
            dirs.append(d)
            staged_bytes.append(sum(f.stat().st_size for f in d.iterdir()))
            return {}

        S._run_on_files([fp], fn)
        assert len(dirs) > 10
        assert max(staged_bytes) <= S.BATCH_BYTES + S.CHUNK_BYTES * 2
        assert not any(d.exists() for d in dirs)

    def test_small_files_still_hardlinked_in_one_pass(self, tmp_path: Path) -> None:
        secret = "ghp_SMALLFILE1234567890abcd"
        a = tmp_path / "a.txt"
        a.write_text("nothing\n")
        b = tmp_path / "b.txt"
        b.write_text(f"x {secret}\n")
        dirs: list[Path] = []
        assert S._run_on_files([a, b], _finder({secret}, dirs)) == {secret: "fake"}
        assert len(dirs) == 1

    def test_resume_offset_scans_only_the_appended_tail(self, tmp_path: Path) -> None:
        old = "ghp_ALREADYSCANNED123456789"
        new = "ghp_APPENDEDAFTERWARDS12345"
        fp = tmp_path / "grow.jsonl"
        head = f"old {old}\n" + ("filler line\n" * 3000)  # prefix >> RESUME_OVERLAP
        fp.write_text(head)
        offset = fp.stat().st_size
        with fp.open("a") as fh:
            fh.write(f"new {new}\n")

        found = S._run_on_files([fp], _finder({old, new}), offsets={fp: offset})
        assert new in found
        assert old not in found  # the scanned prefix is not read again

    def test_token_straddling_the_old_end_is_still_seen(self, tmp_path: Path) -> None:
        secret = "ghp_STRADDLESOLDEND1234567"
        fp = tmp_path / "grow.jsonl"
        fp.write_text("filler\n" * 300 + "tok " + secret[:10])  # writer mid-line
        offset = fp.stat().st_size
        with fp.open("a") as fh:
            fh.write(secret[10:] + "\n")

        assert S._run_on_files([fp], _finder({secret}), offsets={fp: offset}) == {secret: "fake"}
