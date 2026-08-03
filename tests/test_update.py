"""Tests for updater.py — checking PyPI and updating agentscrub."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from agentscrub.updater import (
    detect_installer,
    fetch_latest_pypi_version,
    parse_version_tuple,
    run_update,
)


def test_parse_version_tuple() -> None:
    assert parse_version_tuple("1.1.34") == (1, 1, 34)
    assert parse_version_tuple("v2.0.1") == (2, 0, 1)
    assert parse_version_tuple("0.9") == (0, 9)


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
