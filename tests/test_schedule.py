"""Tests for schedule.py — crontab install/uninstall/status."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from agentscrub import schedule


@pytest.fixture
def mock_bin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(schedule.shutil, "which", lambda name: f"/usr/bin/{name}")


class TestSchedule:
    def test_install_adds_marker_line(self, mock_bin: None) -> None:
        cron_store = {"text": ""}

        def fake_run(cmd, **kwargs):
            if cmd == ["crontab", "-l"]:

                class R:
                    returncode = 0
                    stdout = cron_store["text"]
                    stderr = ""

                return R()
            if cmd == ["crontab", "-"]:
                cron_store["text"] = kwargs.get("input", "")

                class R:
                    returncode = 0
                    stdout = ""
                    stderr = ""

                return R()
            raise AssertionError(cmd)

        with patch.object(schedule.subprocess, "run", fake_run):
            line = schedule.install()
            assert schedule._MARKER in line
            assert schedule._MARKER in cron_store["text"]
            assert schedule.status() == line

    def test_install_twice_raises(self, mock_bin: None) -> None:
        existing = f"0 3 * * * agentscrub run --yes {schedule._MARKER}\n"

        def fake_run(cmd, **kwargs):
            class R:
                returncode = 0
                stdout = existing
                stderr = ""

            return R()

        with patch.object(schedule.subprocess, "run", fake_run):
            with pytest.raises(ValueError, match="already installed"):
                schedule.install()

    def test_uninstall_removes_line(self, mock_bin: None) -> None:
        cron_store = {
            "text": f"0 3 * * * agentscrub run --yes {schedule._MARKER}\n",
        }

        def fake_run(cmd, **kwargs):
            if cmd == ["crontab", "-l"]:

                class R:
                    returncode = 0
                    stdout = cron_store["text"]
                    stderr = ""

                return R()
            if cmd == ["crontab", "-"]:
                cron_store["text"] = kwargs.get("input", "")

                class R:
                    returncode = 0
                    stdout = ""
                    stderr = ""

                return R()
            raise AssertionError(cmd)

        with patch.object(schedule.subprocess, "run", fake_run):
            assert schedule.uninstall() is True
            assert schedule._MARKER not in cron_store["text"]
            assert schedule.status() is None

    def test_uninstall_when_missing_returns_false(self, mock_bin: None) -> None:
        def fake_run(cmd, **kwargs):
            class R:
                returncode = 0
                stdout = ""
                stderr = ""

            return R()

        with patch.object(schedule.subprocess, "run", fake_run):
            assert schedule.uninstall() is False
