"""Tests for installers.py — checksum parsing and archive extraction."""

from __future__ import annotations

import hashlib
import io
import stat
import tarfile
import zipfile
from pathlib import Path

import pytest

from agentscrub.installers import Detector, _expected_sha256, _extract_binary, _verify_sha256


@pytest.fixture
def dummy_detector() -> Detector:
    return Detector(
        key="test",
        display="Test",
        binary="testbin",
        version="v0.0.0",
        repo="org/repo",
        asset="testbin.tar.gz",
        checksum_asset="checksums.txt",
        archive="tar.gz",
    )


class TestChecksum:
    def test_expected_sha256_parses_line(self, tmp_path: Path, dummy_detector: Detector) -> None:
        digest = hashlib.sha256(b"payload").hexdigest()
        checksums = tmp_path / "checksums.txt"
        checksums.write_text(f"{digest}  {dummy_detector.asset}\n")
        assert _expected_sha256(dummy_detector, checksums) == digest

    def test_missing_asset_raises(self, tmp_path: Path, dummy_detector: Detector) -> None:
        checksums = tmp_path / "checksums.txt"
        checksums.write_text("abc123  other.tar.gz\n")
        with pytest.raises(RuntimeError, match="not found"):
            _expected_sha256(dummy_detector, checksums)

    def test_verify_mismatch(self, tmp_path: Path) -> None:
        p = tmp_path / "bin"
        p.write_bytes(b"data")
        with pytest.raises(RuntimeError, match="checksum mismatch"):
            _verify_sha256(p, "0" * 64)


class TestExtractBinary:
    def test_raw_copy(self, tmp_path: Path, dummy_detector: Detector) -> None:
        raw = tmp_path / "asset"
        out = tmp_path / "out" / "testbin"
        out.parent.mkdir(parents=True)
        raw.write_bytes(b"\x7fELF")
        spec = Detector(
            key="t",
            display="t",
            binary="testbin",
            version="v0",
            repo="r/r",
            asset="a",
            checksum_asset="c",
            archive="raw",
        )
        _extract_binary(spec, raw, out)
        assert out.read_bytes() == b"\x7fELF"
        assert out.stat().st_mode & stat.S_IXUSR

    def test_tar_gz_extract(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "bundle.tar.gz"
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            data = b"binary-content"
            info = tarfile.TarInfo(name="subdir/testbin")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        archive_path.write_bytes(buf.getvalue())

        spec = Detector(
            key="t",
            display="t",
            binary="testbin",
            version="v0",
            repo="r/r",
            asset="bundle.tar.gz",
            checksum_asset="c",
            archive="tar.gz",
        )
        out = tmp_path / "testbin"
        _extract_binary(spec, archive_path, out)
        assert out.read_bytes() == b"binary-content"

    def test_zip_extract(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "bundle.zip"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("folder/testbin", b"zip-content")
        archive_path.write_bytes(buf.getvalue())

        spec = Detector(
            key="t",
            display="t",
            binary="testbin",
            version="v0",
            repo="r/r",
            asset="bundle.zip",
            checksum_asset="c",
            archive="zip",
        )
        out = tmp_path / "testbin"
        _extract_binary(spec, archive_path, out)
        assert out.read_bytes() == b"zip-content"
