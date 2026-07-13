"""Smoke tests for CLI entry points."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys

import pytest


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
    assert "pii-text" in r.stdout
    assert "pii-detect" in r.stdout
    assert "pip install 'agentscrub[pii]'" not in r.stdout


def test_stream_help_lists_entropy_option(fake_home) -> None:
    env = {**os.environ, "HOME": str(fake_home)}
    r = subprocess.run(
        [sys.executable, "-m", "agentscrub.cli", "watch-text", "--help"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert r.returncode == 0
    assert "--entropy" in r.stdout
    assert "high-entropy token-like strings" in r.stdout


def test_pii_help_lists_optional_install(fake_home) -> None:
    env = {**os.environ, "HOME": str(fake_home)}
    r = subprocess.run(
        [sys.executable, "-m", "agentscrub.cli", "pii-text", "--help"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert r.returncode == 0
    assert "pip install 'agentscrub[pii]'" in r.stdout
    assert "Hugging Face" in r.stdout


@pytest.mark.parametrize("command", ["pii-text", "pii-detect"])
def test_pii_commands_explain_optional_install_when_unavailable(fake_home, command: str) -> None:
    if all(
        importlib.util.find_spec(name)
        for name in ("onnxruntime", "transformers", "huggingface_hub")
    ):
        pytest.skip("PII dependencies are installed")

    env = {**os.environ, "HOME": str(fake_home)}
    r = subprocess.run(
        [sys.executable, "-m", "agentscrub.cli", command],
        input="Contact Alex at alex@example.com",
        capture_output=True,
        text=True,
        env=env,
    )
    assert r.returncode == 1
    assert "pip install 'agentscrub[pii]'" in r.stdout
    assert "pipx inject agentscrub onnxruntime transformers huggingface-hub numpy" in r.stdout
    assert "Hugging Face" in r.stdout


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


def test_redact_text_entropy_mode_redacts_unknown_token(fake_home) -> None:
    env = {**os.environ, "HOME": str(fake_home)}
    token = "ZxPrtgigTMcYHx3@NtXyMMoipkzTrHWfzTY4PsT6gg83xjL3Jxuci@mX7u_32NeN"
    r = subprocess.run(
        [sys.executable, "-m", "agentscrub.cli", "redact-text", "--entropy", "--count"],
        input=f"terminal value={token}",
        capture_output=True,
        text=True,
        env=env,
    )
    assert r.returncode == 0
    assert token not in r.stdout
    assert r.stdout == "terminal value=[REDACTED]"
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


def test_watch_text_redacts_secret_crossing_forced_boundary(fake_home) -> None:
    env = {**os.environ, "HOME": str(fake_home)}
    token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
    text = ("x" * 60) + token + ("!" * 40)
    r = subprocess.run(
        [
            sys.executable,
            "-m",
            "agentscrub.cli",
            "watch-text",
            "--max-buffer",
            "64",
            "--chunk-size",
            "7",
        ],
        input=text,
        capture_output=True,
        text=True,
        env=env,
    )
    assert r.returncode == 0
    assert token not in r.stdout
    assert r.stdout == ("x" * 60) + "[REDACTED]" + ("!" * 40)
