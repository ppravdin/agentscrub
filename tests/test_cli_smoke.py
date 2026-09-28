"""Smoke tests for CLI entry points."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest


def _make_env(fake_home) -> dict[str, str]:
    src_dir = str(Path(__file__).resolve().parent.parent / "src")
    pythonpath = os.environ.get("PYTHONPATH", "")
    new_path = f"{src_dir}{os.pathsep}{pythonpath}" if pythonpath else src_dir
    return {**os.environ, "HOME": str(fake_home), "PYTHONPATH": new_path}


def test_list_tools_exits_zero(fake_home) -> None:
    env = _make_env(fake_home)
    r = subprocess.run(
        [sys.executable, "-m", "agentscrub.cli", "--list-tools"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert r.returncode == 0
    assert "claude" in r.stdout.lower() or "Claude" in r.stdout


def test_main_help(fake_home) -> None:
    env = _make_env(fake_home)
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
    env = _make_env(fake_home)
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
    env = _make_env(fake_home)
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

    env = _make_env(fake_home)
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
    env = _make_env(fake_home)
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
    env = _make_env(fake_home)
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
    env = _make_env(fake_home)
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


def test_watch_alias_works(fake_home) -> None:
    env = _make_env(fake_home)
    token = "AICHE_DEBUG_TOKEN=PjRLVUtHmD5Na2FGpBTC1NmAMkozbyKVVhf_CE5d7Po"
    r = subprocess.run(
        [sys.executable, "-m", "agentscrub.cli", "--watch", "--alert"],
        input=f"+{token}\n",
        capture_output=True,
        text=True,
        env=env,
    )
    assert r.returncode == 0
    assert "PjRLVUtHmD5Na2FGpBTC1NmAMkozbyKVVhf_CE5d7Po" not in r.stdout
    assert "+[REDACTED]" in r.stdout


def test_watch_text_exit_on_detect(fake_home) -> None:
    env = _make_env(fake_home)
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
    env = _make_env(fake_home)
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


_TOKEN = "ghp_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"


def _watch(fake_home, *extra: str) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-m", "agentscrub.cli", "watch-text", *extra],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_make_env(fake_home),
    )


def _read_line_within(proc: subprocess.Popen, seconds: float) -> bytes | None:
    """First stdout line, or None if nothing arrives in time (stream stays open)."""
    import queue
    import threading

    q: queue.Queue[bytes] = queue.Queue()
    threading.Thread(target=lambda: q.put(proc.stdout.readline()), daemon=True).start()
    try:
        return q.get(timeout=seconds)
    except queue.Empty:
        return None


def test_watch_text_emits_a_line_without_waiting_for_more_input(fake_home) -> None:
    """A quiet `tail -f` must not sit on a line until 4096 characters pile up."""
    proc = _watch(fake_home)
    try:
        proc.stdin.write(f"key={_TOKEN}\n".encode())
        proc.stdin.flush()
        line = _read_line_within(proc, 10)  # stdin is still open
        assert line is not None, "no output while the stream was open"
        assert _TOKEN.encode() not in line and b"[REDACTED]" in line
    finally:
        proc.stdin.close()
        proc.wait(timeout=10)


def test_watch_text_survives_invalid_utf8_and_keeps_the_bytes(fake_home) -> None:
    data = b"before \xff\xfe\x80 junk\nkey=" + _TOKEN.encode() + b"\nafter\n"
    proc = _watch(fake_home)
    out, err = proc.communicate(data, timeout=30)
    assert proc.returncode == 0, err
    assert b"before \xff\xfe\x80 junk\n" in out  # untouched, not replaced
    assert _TOKEN.encode() not in out and b"[REDACTED]" in out
    assert out.endswith(b"after\n")


def test_watch_text_multibyte_character_split_across_reads(fake_home) -> None:
    proc = _watch(fake_home)
    try:
        proc.stdin.write(b"caf\xc3")  # first byte of "\u00e9"
        proc.stdin.flush()
        import time

        time.sleep(0.3)
        proc.stdin.write(b"\xa9 ok\n")
        proc.stdin.flush()
        assert _read_line_within(proc, 10) == "caf\u00e9 ok\n".encode()
    finally:
        proc.stdin.close()
        proc.wait(timeout=10)


def test_redact_text_survives_invalid_utf8(fake_home) -> None:
    r = subprocess.run(
        [sys.executable, "-m", "agentscrub.cli", "redact-text"],
        input=b"junk \xff\xfe key=" + _TOKEN.encode() + b"\n",
        capture_output=True,
        env=_make_env(fake_home),
    )
    assert r.returncode == 0, r.stderr
    assert b"junk \xff\xfe" in r.stdout and _TOKEN.encode() not in r.stdout
