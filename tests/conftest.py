"""Shared fixtures — isolated fake HOME and agentscrub state paths."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest


@pytest.fixture
def fake_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Redirect Path.home() and HOME to a temp directory."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))  # Windows expanduser
    return home


@pytest.fixture
def agentscrub_paths(fake_home: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point runtime dirs at fake_home/.agentscrub/."""
    import agentscrub.backup as backup
    import agentscrub.cache as cache
    import agentscrub.installers as installers

    root = fake_home / ".agentscrub"
    root.mkdir(parents=True, exist_ok=True)
    (root / "backups").mkdir(exist_ok=True)
    (root / "logs").mkdir(exist_ok=True)
    (root / "bin").mkdir(mode=0o700, exist_ok=True)

    monkeypatch.setattr(backup, "BACKUP_ROOT", root / "backups")
    monkeypatch.setattr(backup, "KEY_PATH", root / "key")
    monkeypatch.setattr(backup, "LOG_DIR", root / "logs")
    monkeypatch.setattr(cache, "_CACHE_DB", root / "state.db")
    monkeypatch.setattr(installers, "BIN_DIR", root / "bin")
    return root


@pytest.fixture
def backup_key(agentscrub_paths: Path, monkeypatch: pytest.MonkeyPatch) -> bytes:
    """Install a fixed 32-byte backup key (avoids random keys across tests)."""
    import agentscrub.backup as backup

    key = b"\x01" * 32
    key_path = agentscrub_paths / "key"
    key_path.write_bytes(key)
    key_path.chmod(0o600)
    monkeypatch.setattr(backup, "_load_or_create_key", lambda: key)
    return key


@pytest.fixture
def claude_tree(fake_home: Path) -> Path:
    """Minimal ~/.claude layout: one session log + credentials (managed)."""
    root = fake_home / ".claude"
    projects = root / "projects" / "demo"
    projects.mkdir(parents=True)
    session = projects / "session.jsonl"
    session.write_text(
        '{"role":"user","content":"token ghp_abcdefghijklmnopqrstuvwxyz1234567890"}\n',
        encoding="utf-8",
    )
    creds = root / ".credentials.json"
    creds.write_text('{"api_key":"ghp_live_credential_do_not_touch"}\n', encoding="utf-8")
    return root


@pytest.fixture
def scan_target(claude_tree: Path):
    from agentscrub.discover import ScanTarget

    return ScanTarget(
        path=claude_tree,
        tool="claude",
        display="Claude Code",
        exclude_dirs=frozenset({"telemetry", "cache"}),
        exclude_files=frozenset({".credentials.json", "settings.json"}),
    )


@pytest.fixture
def sample_secret() -> str:
    return "ghp_abcdefghijklmnopqrstuvwxyz1234567890"


@pytest.fixture
def vscdb_with_secret(tmp_path: Path, sample_secret: str) -> Path:
    """SQLite DB resembling Cursor state.vscdb with a secret in a text column."""
    db = tmp_path / "state.vscdb"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value TEXT)")
    con.execute(
        "INSERT INTO ItemTable (key, value) VALUES (?, ?)",
        ("chat.session", f'{{"text":"Bearer {sample_secret}"}}'),
    )
    con.commit()
    con.close()
    return db


def has_grep() -> bool:
    from shutil import which

    return which("grep") is not None


requires_grep = pytest.mark.skipif(not has_grep(), reason="grep not on PATH")
