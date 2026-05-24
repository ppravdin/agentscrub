"""Tests for backup.py — encryption roundtrip and tar safety."""

from __future__ import annotations

import io
import tarfile
from datetime import datetime
from pathlib import Path

import pytest

from agentscrub.backup import (
    _decrypt_file,
    _encrypt_file,
    _extract_tar,
    _parse_backup_entry,
)


class TestEncryption:
    def test_roundtrip(self, tmp_path: Path, backup_key: bytes) -> None:
        src = tmp_path / "plain.bin"
        enc = tmp_path / "plain.bin.enc"
        out = tmp_path / "plain.out"
        payload = b"agentscrub" * 100_000 + b"\x00\xff"
        src.write_bytes(payload)

        _encrypt_file(src, enc)
        assert enc.exists()
        _decrypt_file(enc, out)
        assert out.read_bytes() == payload

    def test_tampered_mac_fails(self, tmp_path: Path, backup_key: bytes) -> None:
        src = tmp_path / "data.txt"
        enc = tmp_path / "data.txt.enc"
        src.write_text("secret backup payload")
        _encrypt_file(src, enc)
        data = bytearray(enc.read_bytes())
        data[-1] ^= 0xFF
        enc.write_bytes(data)
        with pytest.raises(RuntimeError, match="authentication failed"):
            _decrypt_file(enc, tmp_path / "out.txt")

    def test_truncated_file_fails(self, tmp_path: Path, backup_key: bytes) -> None:
        enc = tmp_path / "tiny.enc"
        enc.write_bytes(b"agentscrub-backup-v1\n" + b"\x00" * 10)
        with pytest.raises(RuntimeError, match="truncated"):
            _decrypt_file(enc, tmp_path / "out.txt")


class TestParseBackupEntry:
    def test_encrypted_file(self, tmp_path: Path) -> None:
        p = tmp_path / "20260101-120000.tar.gz.enc"
        p.touch()
        parsed = _parse_backup_entry(p)
        assert parsed is not None
        created, encrypted, partial = parsed
        assert encrypted is True
        assert partial is False
        assert created == datetime(2026, 1, 1, 12, 0, 0)

    def test_partial_encrypted(self, tmp_path: Path) -> None:
        p = tmp_path / "20260101-120000.partial.tar.gz.enc"
        p.touch()
        parsed = _parse_backup_entry(p)
        assert parsed is not None
        _, encrypted, partial = parsed
        assert encrypted is True
        assert partial is True

    def test_ignores_unknown(self, tmp_path: Path) -> None:
        assert _parse_backup_entry(tmp_path / "readme.txt") is None


class TestExtractTar:
    def test_safe_extract(self, tmp_path: Path) -> None:
        tar_path = tmp_path / "safe.tar.gz"
        dest = tmp_path / "out"
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            data = b"hello"
            info = tarfile.TarInfo(name="nested/file.txt")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        tar_path.write_bytes(buf.getvalue())
        _extract_tar(tar_path, dest)
        assert (dest / "nested" / "file.txt").read_bytes() == b"hello"

    def test_rejects_path_traversal(self, tmp_path: Path) -> None:
        tar_path = tmp_path / "evil.tar.gz"
        dest = tmp_path / "out"
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            info = tarfile.TarInfo(name="../escape.txt")
            info.size = 0
            tf.addfile(info, io.BytesIO(b""))
        tar_path.write_bytes(buf.getvalue())
        with pytest.raises(RuntimeError, match="path traversal"):
            _extract_tar(tar_path, dest)

    def test_rejects_absolute_path(self, tmp_path: Path) -> None:
        tar_path = tmp_path / "abs.tar.gz"
        dest = tmp_path / "out"
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            info = tarfile.TarInfo(name="/etc/passwd")
            info.size = 0
            tf.addfile(info, io.BytesIO(b""))
        tar_path.write_bytes(buf.getvalue())
        with pytest.raises(RuntimeError, match="absolute path"):
            _extract_tar(tar_path, dest)
