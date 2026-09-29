"""Tests for updater.py — checking PyPI and updating agentscrub."""

from __future__ import annotations

import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from packaging.version import Version

from agentscrub.updater import (
    detect_installer,
    fetch_latest_pypi_version,
    parse_version_tuple,
    run_update,
)


def test_parse_version_tuple() -> None:
    assert parse_version_tuple("1.1.34") == Version("1.1.34")
    assert parse_version_tuple("v2.0.1") == Version("2.0.1")
    assert parse_version_tuple("0.9") == Version("0.9")
    assert parse_version_tuple("1.1.10rc1") == Version("1.1.10rc1")
    assert parse_version_tuple("1.1.10rc1") < parse_version_tuple("1.1.36")
    assert parse_version_tuple("1.1.10rc1") < parse_version_tuple("1.1.10")
    assert parse_version_tuple("1.1.10") < parse_version_tuple("1.1.10.post1")


@patch("urllib.request.urlopen")
def test_fetch_latest_pypi_version(mock_urlopen) -> None:
    mock_resp = MagicMock()
    mock_resp.read.return_value = b'{"info": {"version": "1.1.35"}}'
    mock_resp.__enter__.return_value = mock_resp
    mock_urlopen.return_value = mock_resp

    ver = fetch_latest_pypi_version()
    assert ver == "1.1.35"


def test_detect_installer() -> None:
    cmd = detect_installer()
    assert isinstance(cmd, list)
    assert len(cmd) >= 3


@patch("agentscrub.updater.shutil.which", return_value="/usr/bin/pipx")
@patch("agentscrub.updater.sys.prefix", "/opt/acme-pipx-tools/venv")
def test_detect_installer_ignores_unrelated_pipx_path(_mock_which) -> None:
    cmd = detect_installer()
    assert cmd[0:3] == [sys.executable, "-m", "pip"]


@patch("agentscrub.updater.fetch_latest_pypi_version")
def test_run_update_already_up_to_date(mock_fetch) -> None:
    from agentscrub import __version__

    mock_fetch.return_value = __version__
    res = run_update(check_only=False, yes=True)
    assert res == 0


@patch("agentscrub.updater.fetch_latest_pypi_version")
def test_run_update_check_only(mock_fetch) -> None:
    mock_fetch.return_value = "99.99.99"
    res = run_update(check_only=True, yes=True)
    assert res == 0


@patch("subprocess.run")
@patch("agentscrub.updater.fetch_latest_pypi_version")
def test_run_update_executes_installer(mock_fetch, mock_subproc) -> None:
    mock_fetch.return_value = "99.99.99"
    mock_subproc.return_value = MagicMock(returncode=0)

    res = run_update(check_only=False, yes=True)
    assert res == 0
    assert mock_subproc.called


@patch("agentscrub.updater.detect_installer", return_value=[sys.executable, "-m", "pip", "install"])
@patch("agentscrub.updater.fetch_latest_pypi_version", return_value="99.99.99")
@patch("agentscrub.updater._installed_version", return_value="99.99.99")
@patch("subprocess.run")
def test_run_update_retries_only_for_pep668(
    mock_run, _mock_installed, _mock_fetch, _mock_detect
) -> None:
    mock_run.side_effect = [
        SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="error: externally-managed-environment",
        ),
        SimpleNamespace(returncode=0, stdout="", stderr=""),
    ]

    assert run_update(yes=True) == 0
    assert mock_run.call_count == 2
    assert "--break-system-packages" in mock_run.call_args.args[0]


@patch("agentscrub.updater.detect_installer", return_value=[sys.executable, "-m", "pip", "install"])
@patch("agentscrub.updater.fetch_latest_pypi_version", return_value="99.99.99")
@patch("subprocess.run")
def test_run_update_does_not_retry_unrelated_pip_failure(
    mock_run, _mock_fetch, _mock_detect
) -> None:
    mock_run.return_value = SimpleNamespace(
        returncode=1,
        stdout="",
        stderr="Could not find a matching distribution",
    )

    assert run_update(yes=True) == 1
    assert mock_run.call_count == 1


@patch("agentscrub.updater.detect_installer", return_value=[sys.executable, "-m", "pip", "install"])
@patch("agentscrub.updater.fetch_latest_pypi_version", return_value="99.99.99")
@patch("subprocess.run")
def test_run_update_replays_installer_output(mock_run, _mock_fetch, _mock_detect, capsys) -> None:
    mock_run.return_value = SimpleNamespace(
        returncode=1,
        stdout="download details\n",
        stderr="pip failed\n",
    )

    assert run_update(yes=True) == 1
    captured = capsys.readouterr()
    assert "download details" in captured.out
    assert "pip failed" in captured.err


def test_detect_installer_pins_the_version_and_bypasses_pip_cache() -> None:
    cmd = detect_installer(version="1.2.3")
    if cmd[1:3] == ["-m", "pip"]:
        assert "agentscrub==1.2.3" in cmd and "--no-cache-dir" in cmd


@patch("agentscrub.updater._installed_version", return_value="1.0.0")
@patch("agentscrub.updater.fetch_latest_pypi_version", return_value="99.99.99")
@patch("subprocess.run")
def test_run_update_does_not_claim_success_when_the_old_version_is_still_installed(
    mock_run, _mock_fetch, _mock_installed, capsys
) -> None:
    """pip exits 0 with 'Requirement already satisfied' when its index lags."""
    mock_run.return_value = SimpleNamespace(
        returncode=0, stdout="Requirement already satisfied", stderr=""
    )
    assert run_update(yes=True) == 1
    out = capsys.readouterr().out
    assert "Successfully updated" not in out
    assert "still v1.0.0" in out and "v99.99.99" in out


@patch("agentscrub.updater._installed_version", return_value="99.99.99")
@patch("agentscrub.updater.fetch_latest_pypi_version", return_value="99.99.99")
@patch("subprocess.run")
def test_run_update_reports_success_only_when_verified(
    mock_run, _mock_fetch, _mock_installed, capsys
) -> None:
    mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
    assert run_update(yes=True) == 0
    assert "Successfully updated agentscrub to v99.99.99" in capsys.readouterr().out
    assert "agentscrub==99.99.99" in " ".join(mock_run.call_args.args[0])  # exact release pinned


@patch("agentscrub.updater._installed_version", return_value=None)
@patch("agentscrub.updater.fetch_latest_pypi_version", return_value="99.99.99")
@patch("subprocess.run")
def test_run_update_is_honest_when_the_result_cannot_be_verified(
    mock_run, _mock_fetch, _mock_installed, capsys
) -> None:
    mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
    assert run_update(yes=True) == 0
    out = capsys.readouterr().out
    assert "Successfully updated" not in out and "could not confirm" in out


@patch("agentscrub.updater.fetch_latest_pypi_version", return_value="99.99.99")
@patch("subprocess.run")
def test_run_update_explains_index_lag_when_pip_cannot_find_the_release(
    mock_run, _mock_fetch, capsys
) -> None:
    mock_run.return_value = SimpleNamespace(
        returncode=1,
        stdout="",
        stderr="ERROR: No matching distribution found for agentscrub==99.99.99",
    )
    assert run_update(yes=True) == 1
    assert "few minutes" in capsys.readouterr().out
