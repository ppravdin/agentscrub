"""Install managed detector binaries into ~/.agentscrub/bin."""
from __future__ import annotations

import hashlib
import os
import platform
import shutil
import stat
import tarfile
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

BIN_DIR = Path.home() / ".agentscrub" / "bin"


@dataclass(frozen=True)
class Detector:
    key: str
    display: str
    binary: str
    version: str
    repo: str
    asset: str
    checksum_asset: str
    archive: str

    @property
    def asset_url(self) -> str:
        return f"https://github.com/{self.repo}/releases/download/{self.version}/{self.asset}"

    @property
    def checksum_url(self) -> str:
        return (
            f"https://github.com/{self.repo}/releases/download/"
            f"{self.version}/{self.checksum_asset}"
        )


def _platform_key() -> tuple[str, str]:
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "linux":
        os_key = "linux"
    elif system == "darwin":
        os_key = "darwin"
    elif system == "windows":
        os_key = "windows"
    else:
        raise RuntimeError(f"unsupported OS: {platform.system()}")

    if machine in {"x86_64", "amd64"}:
        arch = "amd64"
    elif machine in {"aarch64", "arm64"}:
        arch = "arm64"
    else:
        raise RuntimeError(f"unsupported CPU architecture: {platform.machine()}")

    return os_key, arch


def _detectors() -> dict[str, Detector]:
    os_key, arch = _platform_key()
    exe = ".exe" if os_key == "windows" else ""

    gitleaks_arch = {"amd64": "x64", "arm64": "arm64"}[arch]
    gitleaks_archive = "zip" if os_key == "windows" else "tar.gz"
    gitleaks_asset = f"gitleaks_8.26.0_{os_key}_{gitleaks_arch}.{gitleaks_archive}"

    trufflehog_arch = {"amd64": "amd64", "arm64": "arm64"}[arch]
    trufflehog_asset = f"trufflehog_3.95.2_{os_key}_{trufflehog_arch}.tar.gz"

    titus_arch = {"amd64": "amd64", "arm64": "arm64"}[arch]
    titus_binary = f"titus-{os_key}-{titus_arch}{exe}"

    return {
        "gitleaks": Detector(
            key="gitleaks",
            display="gitleaks",
            binary=f"gitleaks{exe}",
            version="v8.26.0",
            repo="gitleaks/gitleaks",
            asset=gitleaks_asset,
            checksum_asset="gitleaks_8.26.0_checksums.txt",
            archive=gitleaks_archive,
        ),
        "trufflehog": Detector(
            key="trufflehog",
            display="TruffleHog",
            binary=f"trufflehog{exe}",
            version="v3.95.2",
            repo="trufflesecurity/trufflehog",
            asset=trufflehog_asset,
            checksum_asset="trufflehog_3.95.2_checksums.txt",
            archive="tar.gz",
        ),
        "titus": Detector(
            key="titus",
            display="Titus",
            binary=f"titus{exe}",
            version="v1.1.29",
            repo="praetorian-inc/titus",
            asset=titus_binary,
            checksum_asset="checksums.txt",
            archive="raw",
        ),
    }


def detector_specs() -> dict[str, Detector]:
    return _detectors()


def detector_path(binary: str) -> Path | None:
    managed = BIN_DIR / binary
    if managed.exists():
        return managed
    return None


def _download(url: str, dest: Path) -> None:
    with urllib.request.urlopen(url, timeout=60) as response:
        dest.write_bytes(response.read())


def _expected_sha256(spec: Detector, checksum_file: Path) -> str:
    for line in checksum_file.read_text(errors="ignore").splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and parts[-1].lstrip("*") == spec.asset:
            return parts[0]
    raise RuntimeError(f"checksum for {spec.asset} not found")


def _verify_sha256(path: Path, expected: str) -> None:
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual.lower() != expected.lower():
        raise RuntimeError(f"checksum mismatch for {path.name}")


def _extract_binary(spec: Detector, asset_path: Path, out_path: Path) -> None:
    if spec.archive == "raw":
        shutil.copy2(asset_path, out_path)
    elif spec.archive == "tar.gz":
        with tarfile.open(asset_path, "r:gz") as archive:
            member = next(
                (
                    m for m in archive.getmembers()
                    if Path(m.name).name == spec.binary and m.isfile()
                ),
                None,
            )
            if member is None:
                raise RuntimeError(f"{spec.binary} not found in {spec.asset}")
            extracted = archive.extractfile(member)
            if extracted is None:
                raise RuntimeError(f"could not extract {spec.binary}")
            out_path.write_bytes(extracted.read())
    elif spec.archive == "zip":
        with zipfile.ZipFile(asset_path) as archive:
            member = next(
                (
                    n for n in archive.namelist()
                    if Path(n).name == spec.binary
                ),
                None,
            )
            if member is None:
                raise RuntimeError(f"{spec.binary} not found in {spec.asset}")
            out_path.write_bytes(archive.read(member))
    else:
        raise RuntimeError(f"unsupported archive type: {spec.archive}")

    mode = out_path.stat().st_mode
    out_path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def install_detector(key: str) -> Path:
    spec = _detectors()[key]
    BIN_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(BIN_DIR.parent, 0o700)
    os.chmod(BIN_DIR, 0o700)

    with tempfile.TemporaryDirectory(prefix="agentscrub_install_") as td:
        tmp = Path(td)
        asset_path = tmp / spec.asset
        checksum_path = tmp / spec.checksum_asset

        _download(spec.asset_url, asset_path)
        _download(spec.checksum_url, checksum_path)
        _verify_sha256(asset_path, _expected_sha256(spec, checksum_path))

        out_path = BIN_DIR / spec.binary
        temp_out = tmp / spec.binary
        _extract_binary(spec, asset_path, temp_out)
        shutil.move(str(temp_out), str(out_path))
        out_path.chmod(0o700)
        return out_path


def install_detectors(keys: list[str]) -> list[tuple[str, Path | None, str | None]]:
    results: list[tuple[str, Path | None, str | None]] = []
    for key in keys:
        try:
            results.append((key, install_detector(key), None))
        except Exception as e:
            results.append((key, None, str(e)))
    return results
