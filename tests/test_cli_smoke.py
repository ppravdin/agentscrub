"""Smoke tests for CLI entry points."""

from __future__ import annotations

import os
import subprocess
import sys


def test_list_tools_exits_zero(fake_home) -> None:
    env = {**os.environ, "HOME": str(fake_home)}
    r = subprocess.run(
        [sys.executable, "-m", "agentscrub.cli", "--list-tools"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert r.returncode == 0
    assert "claude" in r.stdout.lower() or "Claude" in r.stdout


def test_main_help(fake_home) -> None:
    env = {**os.environ, "HOME": str(fake_home)}
    r = subprocess.run(
        [sys.executable, "-m", "agentscrub.cli", "--help"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert r.returncode == 0
    assert "scan" in r.stdout
