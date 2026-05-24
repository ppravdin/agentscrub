"""Tests for backup.py orchestration — backup, list, rollback, rotation."""

from __future__ import annotations

import shutil
import time
from datetime import datetime
from pathlib import Path

import pytest

from agentscrub.backup import (
    _encrypted_path,
    backup,
    list_backups,
    list_restore_points,
    migrate_plaintext_backups,
    rollback,
    rotate_logs,
)
from agentscrub.discover import ScanTarget


def has_rsync() -> bool:
    return shutil.which("rsync") is not None


requires_rsync = pytest.mark.skipif(not has_rsync(), reason="rsync not on PATH")


class TestBackup:
    def test_partial_backup_single_file(
        self,
        scan_target: ScanTarget,
        agentscrub_paths: Path,
        backup_key: bytes,
        claude_tree: Path,
    ) -> None:
        session = next(claude_tree.rglob("session.jsonl"))
        created = backup([scan_target], files=[session])
        assert len(created) == 1
        assert created[0].partial is True
        assert created[0].path.exists()
        assert created[0].path.name.endswith(".partial.tar.gz.enc")

    def test_list_backups_and_restore_points(
        self,
        scan_target: ScanTarget,
        agentscrub_paths: Path,
        backup_key: bytes,
        claude_tree: Path,
    ) -> None:
        session = next(claude_tree.rglob("session.jsonl"))
        backup([scan_target], files=[session])
        listed = list_backups([scan_target])
        assert len(listed) >= 1
        points = list_restore_points([scan_target])
        assert len(points) >= 1
        assert points[0].backups

    def test_rotation_drops_oldest(
        self,
        scan_target: ScanTarget,
        agentscrub_paths: Path,
        backup_key: bytes,
        claude_tree: Path,
    ) -> None:
        session = next(claude_tree.rglob("session.jsonl"))
        for _ in range(4):
            backup([scan_target], max_keep=2, files=[session])
            time.sleep(1.05)
        tool_dir = agentscrub_paths / "backups" / scan_target.tool
        enc = list(tool_dir.glob("*.partial.tar.gz.enc"))
        assert len(enc) <= 2

    @requires_rsync
    def test_rollback_restores_content(
        self,
        scan_target: ScanTarget,
        agentscrub_paths: Path,
        backup_key: bytes,
        claude_tree: Path,
    ) -> None:
        session = next(claude_tree.rglob("session.jsonl"))
        original = session.read_text(encoding="utf-8")
        created = backup([scan_target], files=[session])
        session.write_text("tampered\n", encoding="utf-8")

        ok, msg = rollback(created[0])
        assert ok, msg
        assert session.read_text(encoding="utf-8") == original


class TestMigratePlaintext:
    def test_encrypts_legacy_dir_backup(
        self,
        scan_target: ScanTarget,
        agentscrub_paths: Path,
        backup_key: bytes,
        claude_tree: Path,
    ) -> None:
        tool_dir = agentscrub_paths / "backups" / scan_target.tool
        tool_dir.mkdir(parents=True)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        legacy = tool_dir / ts
        legacy.mkdir()
        (legacy / "session.jsonl").write_text("legacy data\n")

        migrated = migrate_plaintext_backups([scan_target])
        assert migrated == 1
        assert not legacy.exists()
        assert _encrypted_path(tool_dir, ts).exists()


class TestRotateLogs:
    def test_keeps_newest_scan_reports(
        self,
        agentscrub_paths: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import agentscrub.backup as backup_mod

        log_dir = agentscrub_paths / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(backup_mod, "LOG_DIR", log_dir)

        for i in range(5):
            p = log_dir / f"scan-2026010{i}-120000.txt"
            p.write_text("audit")
            time.sleep(0.01)

        rotate_logs(max_keep=2)
        remaining = sorted(log_dir.glob("scan-*.txt"))
        assert len(remaining) == 2
        assert not list(log_dir.glob("scan-*-summary.txt"))
