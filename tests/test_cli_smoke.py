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


def test_redact_text_redacts_stdin(fake_home) -> None:
    env = {**os.environ, "HOME": str(fake_home)}
    token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
    r = subprocess.run(
        [sys.executable, "-m", "agentscrub.cli", "redact-text", "--count"],
        input=f"remote: token={token}",
        capture_output=True,
        text=True,
        env=env,
    )
    assert r.returncode == 0
    assert token not in r.stdout
    assert "[REDACTED]" in r.stdout
    assert r.stderr.strip() == "1"


def test_watch_text_redacts_stream(fake_home) -> None:
    env = {**os.environ, "HOME": str(fake_home)}
    token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
    r = subprocess.run(
        [sys.executable, "-m", "agentscrub.cli", "watch-text", "--alert", "--count"],
        input=f"build ok\nremote: token={token}\ndone\n",
        capture_output=True,
        text=True,
        env=env,
    )
    assert r.returncode == 0
    assert token not in r.stdout
    assert "remote: token=[REDACTED]" in r.stdout
    assert "agentscrub: redacted 1 secret(s)" in r.stderr
    assert r.stderr.strip().endswith("1")


def test_watch_text_exit_on_detect(fake_home) -> None:
    env = {**os.environ, "HOME": str(fake_home)}
    token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
    r = subprocess.run(
        [sys.executable, "-m", "agentscrub.cli", "watch-text", "--exit-on-detect"],
        input=f"remote: token={token}\nthis part is not emitted\n",
        capture_output=True,
        text=True,
        env=env,
    )
    assert r.returncode == 2
    assert token not in r.stdout
    assert "[REDACTED]" in r.stdout
    assert "this part is not emitted" not in r.stdout
