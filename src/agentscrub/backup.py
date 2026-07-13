"""Backup rotation and rollback."""
from __future__ import annotations

import hmac
import os
import shutil
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .discover import ScanTarget

BACKUP_ROOT = Path.home() / ".agentscrub" / "backups"
KEY_PATH    = Path.home() / ".agentscrub" / "key"
LOG_DIR     = Path.home() / ".agentscrub" / "logs"
_FMT = "%Y%m%d-%H%M%S"
_ENC_SUFFIX = ".tar.gz.enc"
_PARTIAL_ENC_SUFFIX = ".partial.tar.gz.enc"
_MAGIC = b"agentscrub-backup-v1\n"
_CHUNK = 1024 * 1024
_SQLITE_SUFFIXES = (".sqlite", ".db", ".vscdb")

_RSYNC_PROTECTED = (
    ".credentials.json",
    "mcp.json",
    "mcp_config.json",
    ".mcp.json",
    ".mcp-auth/",
)


def _protected_excludes(target: ScanTarget) -> list[str]:
    args: list[str] = []
    patterns = list(_RSYNC_PROTECTED)
    if target.tool == "codex":
        patterns.extend(("auth.json", "config.toml"))
    for pattern in patterns:
        args.extend(["--exclude", pattern])
    return args


@dataclass
class Backup:
    path: Path       # where the backup lives
    source: Path     # original directory it came from
    tool: str
    display: str
    created: datetime
    encrypted: bool = True
    partial: bool = False

    @property
    def age_str(self) -> str:
        delta = datetime.now() - self.created
        if delta.days == 0:
            return "today"
        if delta.days == 1:
            return "yesterday"
        return f"{delta.days}d ago"

    @property
    def size_str(self) -> str:
        return _du_human([self.path])


@dataclass
class RestorePoint:
    created: datetime
    backups: list[Backup]

    @property
    def age_str(self) -> str:
        delta = datetime.now() - self.created
        if delta.days == 0:
            return "today"
        if delta.days == 1:
            return "yesterday"
        return f"{delta.days}d ago"

    @property
    def size_str(self) -> str:
        return _du_human([b.path for b in self.backups])

    @property
    def displays(self) -> list[str]:
        return [b.display for b in self.backups]


def _du_human(paths: list[Path]) -> str:
    if not paths:
        return "?"
    r = subprocess.run(
        ["du", "-sch", *[str(p) for p in paths]],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        return "?"
    lines = [line.split()[0] for line in r.stdout.splitlines() if line.strip()]
    return lines[-1] if lines else "?"


def _load_or_create_key() -> bytes:
    KEY_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if KEY_PATH.exists():
        key = KEY_PATH.read_bytes()
        if len(key) != 32:
            raise RuntimeError(f"invalid agentscrub backup key: {KEY_PATH}")
        try:
            os.chmod(KEY_PATH, 0o600)
        except OSError:
            pass
        return key

    key = os.urandom(32)
    fd = os.open(KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    return key


def _cipher_keys(key: bytes) -> tuple[bytes, bytes]:
    enc_key = hmac.digest(key, b"agentscrub backup encryption", "sha256")
    mac_key = hmac.digest(key, b"agentscrub backup authentication", "sha256")
    return enc_key, mac_key


def _encrypt_file(src: Path, dst: Path) -> None:
    key = _load_or_create_key()
    enc_key, mac_key = _cipher_keys(key)
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(enc_key), modes.CTR(nonce)).encryptor()
    mac = hmac.new(mac_key, digestmod="sha256")
    dst_tmp = dst.with_suffix(dst.suffix + ".tmp")
    try:
        with src.open("rb") as inp, dst_tmp.open("wb") as out:
            header = _MAGIC + nonce
            out.write(header)
            mac.update(header)
            while True:
                chunk = inp.read(_CHUNK)
                if not chunk:
                    break
                encrypted = cipher.update(chunk)
                out.write(encrypted)
                mac.update(encrypted)
            tail = cipher.finalize()
            if tail:
                out.write(tail)
                mac.update(tail)
            out.write(mac.digest())
        os.chmod(dst_tmp, 0o600)
        shutil.move(str(dst_tmp), str(dst))
    finally:
        dst_tmp.unlink(missing_ok=True)


def _decrypt_file(src: Path, dst: Path) -> None:
    key = _load_or_create_key()
    enc_key, mac_key = _cipher_keys(key)
    size = src.stat().st_size
    min_size = len(_MAGIC) + 16 + 32
    if size < min_size:
        raise RuntimeError("encrypted backup is truncated")

    mac = hmac.new(mac_key, digestmod="sha256")
    with src.open("rb") as inp:
        body_len = size - 32
        remaining = body_len
        while remaining:
            chunk = inp.read(min(_CHUNK, remaining))
            if not chunk:
                raise RuntimeError("encrypted backup is truncated")
            mac.update(chunk)
            remaining -= len(chunk)
        expected = inp.read(32)
    if not hmac.compare_digest(mac.digest(), expected):
        raise RuntimeError("encrypted backup authentication failed")

    with src.open("rb") as inp, dst.open("wb") as out:
        header = inp.read(len(_MAGIC) + 16)
        if not header.startswith(_MAGIC):
            raise RuntimeError("not an agentscrub encrypted backup")
        nonce = header[len(_MAGIC):]
        cipher = Cipher(algorithms.AES(enc_key), modes.CTR(nonce)).decryptor()
        remaining = size - len(header) - 32
        while remaining:
            chunk = inp.read(min(_CHUNK, remaining))
            if not chunk:
                raise RuntimeError("encrypted backup is truncated")
            out.write(cipher.update(chunk))
            remaining -= len(chunk)
        out.write(cipher.finalize())


def _tar_dir_contents(source: Path, tar_path: Path) -> None:
    with tarfile.open(tar_path, "w:gz") as tf:
        for child in sorted(source.iterdir(), key=lambda p: p.name):
            tf.add(child, arcname=child.name)


def _tar_files(source: Path, files: list[Path], tar_path: Path) -> None:
    with tarfile.open(tar_path, "w:gz") as tf:
        for fp in sorted(set(files)):
            try:
                rel = fp.relative_to(source)
            except ValueError:
                continue
            if fp.exists() and fp.is_file():
                tf.add(fp, arcname=rel.as_posix())


def _extract_tar(tar_path: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    dest_root = dest.resolve()
    with tarfile.open(tar_path, "r:gz") as tf:
        safe_members: list[tarfile.TarInfo] = []
        for member in tf.getmembers():
            name = member.name
            if Path(name).is_absolute():
                raise RuntimeError("unsafe backup archive: absolute path")
            target = (dest / name).resolve()
            if target != dest_root and dest_root not in target.parents:
                raise RuntimeError("unsafe backup archive: path traversal")
            if member.isdev():
                raise RuntimeError("unsafe backup archive: device file rejected")
            if member.issym() or member.islnk():
                continue  # skip symlinks — Claude Code recreates them on next run
            safe_members.append(member)
        tf.extractall(dest, members=safe_members)


def _encrypted_path(tool_dir: Path, ts: str, *, partial: bool = False) -> Path:
    suffix = _PARTIAL_ENC_SUFFIX if partial else _ENC_SUFFIX
    return tool_dir / f"{ts}{suffix}"


def _parse_backup_entry(path: Path) -> tuple[datetime, bool, bool] | None:
    if path.is_dir():
        name = path.name
        encrypted = False
        partial = False
    elif path.is_file() and path.name.endswith(_PARTIAL_ENC_SUFFIX):
        name = path.name[:-len(_PARTIAL_ENC_SUFFIX)]
        encrypted = True
        partial = True
    elif path.is_file() and path.name.endswith(_ENC_SUFFIX):
        name = path.name[:-len(_ENC_SUFFIX)]
        encrypted = True
        partial = False
    else:
        return None
    try:
        created = datetime.strptime(name, _FMT)
    except ValueError:
        return None
    return created, encrypted, partial


def _remove_backup_path(path: Path) -> None:
    if path.is_dir():
        shutil.rmtree(path, ignore_errors=True)
    else:
        path.unlink(missing_ok=True)


def _remove_unbacked_sqlite_sidecars(restore_root: Path, source: Path) -> None:
    """Remove live WAL/SHM files absent from a partial database backup."""
    for restored in restore_root.rglob("*"):
        if not restored.is_file() or restored.suffix not in _SQLITE_SUFFIXES:
            continue
        relative = restored.relative_to(restore_root)
        live_db = source / relative
        for suffix in ("-wal", "-shm"):
            sidecar = Path(str(live_db) + suffix)
            if not (restore_root / (str(relative) + suffix)).exists():
                sidecar.unlink(missing_ok=True)


def _encrypt_plaintext_backup(path: Path) -> Path:
    archive = _encrypted_path(path.parent, path.name)
    if archive.exists():
        shutil.rmtree(path, ignore_errors=True)
        return archive

    with tempfile.TemporaryDirectory(prefix="agentscrub_backup_") as td:
        tar_path = Path(td) / "backup.tar.gz"
        _tar_dir_contents(path, tar_path)
        _encrypt_file(tar_path, archive)
    shutil.rmtree(path, ignore_errors=True)
    return archive


def migrate_plaintext_backups(targets: list[ScanTarget]) -> int:
    """Encrypt old plaintext backup directories in-place. Returns count migrated."""
    if not BACKUP_ROOT.exists():
        return 0
    tool_names = {t.tool for t in targets}
    migrated = 0
    for tool_dir in sorted(BACKUP_ROOT.iterdir()):
        if not tool_dir.is_dir() or tool_dir.name not in tool_names:
            continue
        for entry in sorted(tool_dir.iterdir()):
            parsed = _parse_backup_entry(entry)
            if parsed is None:
                continue
            _created, encrypted, _partial = parsed
            if not encrypted and entry.is_dir():
                _encrypt_plaintext_backup(entry)
                migrated += 1
    return migrated


def _backup_entries(tool_dir: Path) -> list[tuple[datetime, Path, bool, bool]]:
    entries: list[tuple[datetime, Path, bool, bool]] = []
    if not tool_dir.exists():
        return entries
    for entry in tool_dir.iterdir():
        parsed = _parse_backup_entry(entry)
        if parsed is None:
            continue
        created, encrypted, partial = parsed
        entries.append((created, entry, encrypted, partial))
    return sorted(entries, key=lambda x: x[0])


def backup(
    targets: list[ScanTarget],
    max_keep: int = 3,
    files: list[Path] | None = None,
) -> list[Backup]:
    """
    Archive and encrypt files before redaction.

    If files is given, only those files are backed up and rollback restores
    them without deleting unrelated files. Without files, archive the whole
    target for backward/internal callers.

    Rotates: keeps only the newest max_keep per tool.
    Returns the newly-created Backup objects.
    """
    BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(BACKUP_ROOT.parent, 0o700)
    ts = datetime.now().strftime(_FMT)
    created: list[Backup] = []
    failures: list[str] = []
    partial = files is not None
    files_by_target: dict[ScanTarget, list[Path]] = {t: [] for t in targets}
    if files is not None:
        for fp in sorted(set(files)):
            for target in targets:
                try:
                    fp.relative_to(target.path)
                    files_by_target[target].append(fp)
                    break
                except ValueError:
                    continue

    for target in targets:
        target_files = files_by_target[target] if files is not None else None
        if files is not None and not target_files:
            continue

        tool_dir = BACKUP_ROOT / target.tool
        tool_dir.mkdir(parents=True, exist_ok=True)
        archive = _encrypted_path(tool_dir, ts, partial=partial)

        try:
            with tempfile.TemporaryDirectory(prefix="agentscrub_backup_") as td:
                tar_path = Path(td) / "backup.tar.gz"
                if target_files is None:
                    _tar_dir_contents(target.path, tar_path)
                else:
                    _tar_files(target.path, target_files, tar_path)
                _encrypt_file(tar_path, archive)
        except Exception as e:
            print(f"  [WARN] backup failed for {target.path}: {str(e)[:200]}", flush=True)
            failures.append(f"{target.display}: {e}")
            continue

        created.append(Backup(
            path=archive,
            source=target.path,
            tool=target.tool,
            display=target.display,
            created=datetime.now(),
            encrypted=True,
            partial=partial,
        ))

        # Rotate: delete oldest beyond max_keep
        all_bups = _backup_entries(tool_dir)
        for _created, old, _encrypted, _partial in all_bups[:-max_keep] if len(all_bups) > max_keep else []:
            _remove_backup_path(old)

    if failures:
        raise RuntimeError("backup failed: " + "; ".join(failures))
    return created


def list_backups(targets: list[ScanTarget]) -> list[Backup]:
    """All backups for the given targets, newest first."""
    if not BACKUP_ROOT.exists():
        return []
    tool_map = {t.tool: t for t in targets}
    result: list[Backup] = []

    for tool_dir in sorted(BACKUP_ROOT.iterdir()):
        tool = tool_dir.name
        target = tool_map.get(tool)
        if target is None:
            continue
        for created, path, encrypted, partial in sorted(_backup_entries(tool_dir), reverse=True):
            result.append(Backup(
                path=path,
                source=target.path,
                tool=tool,
                display=target.display,
                created=created,
                encrypted=encrypted,
                partial=partial,
            ))

    return result


def list_restore_points(targets: list[ScanTarget]) -> list[RestorePoint]:
    """Backups grouped by run timestamp, newest first."""
    groups: dict[str, list[Backup]] = {}
    for b in list_backups(targets):
        groups.setdefault(b.created.strftime(_FMT), []).append(b)

    points: list[RestorePoint] = []
    for ts, backups in groups.items():
        try:
            created = datetime.strptime(ts, _FMT)
        except ValueError:
            continue
        points.append(RestorePoint(
            created=created,
            backups=sorted(backups, key=lambda b: b.display),
        ))
    points.sort(key=lambda p: p.created, reverse=True)
    return points


def rotate_logs(max_keep: int = 30) -> None:
    """Keep logs bounded so scheduled scans do not grow ~/.agentscrub forever.

    Current scan reports are named scan-<timestamp>.txt. Older agentscrub
    versions also wrote scan-<timestamp>-full.txt and scan-<timestamp>-summary.txt.
    Summaries are redundant now that a single audit is linked, so prune them
    aggressively. Keep the newest max_keep scan reports and newest max_keep
    cron stdout logs.
    """
    if not LOG_DIR.exists():
        return

    for stale in LOG_DIR.glob("scan-*-summary.txt"):
        stale.unlink(missing_ok=True)

    reports = [
        p for p in LOG_DIR.glob("scan-*.txt")
        if not p.name.endswith("-summary.txt")
    ]
    reports.sort(key=lambda p: (p.stat().st_mtime, p.name), reverse=True)
    for old in reports[max_keep:]:
        old.unlink(missing_ok=True)

    logs = sorted(
        LOG_DIR.glob("*.log"),
        key=lambda p: (p.stat().st_mtime, p.name),
        reverse=True,
    )
    for old in logs[max_keep:]:
        old.unlink(missing_ok=True)


def rollback(b: Backup) -> tuple[bool, str]:
    """Restore backup b → b.source. Returns (success, diagnostic_message).

    Uses --checksum, NOT the rsync default size+mtime quick-check.

    The redactor rewrites files in place. After a redact, the file mtime is
    updated and the file size often differs only slightly. Empirically,
    rsync's quick-check has been observed to silently skip such files,
    leaving them in a redacted state even though rollback reported success.
    --checksum forces a real content comparison. It's slower but correct.

    Stderr is returned (not swallowed) so callers can surface real
    diagnostics instead of just 'complete / failed'.
    """
    target = ScanTarget(path=b.source, tool=b.tool, display=b.display)
    with tempfile.TemporaryDirectory(prefix="agentscrub_restore_") as td:
        restore_root = Path(td) / "restore"
        try:
            if b.encrypted:
                tar_path = Path(td) / "backup.tar.gz"
                _decrypt_file(b.path, tar_path)
                _extract_tar(tar_path, restore_root)
                src = restore_root
            else:
                src = b.path
        except Exception as e:
            return False, str(e)

        if b.partial and b.encrypted:
            _remove_unbacked_sqlite_sidecars(restore_root, b.source)

        cmd = ["rsync", "-a", "--checksum"]
        if not b.partial:
            cmd.append("--delete")
        cmd.extend([*_protected_excludes(target), str(src) + "/", str(b.source) + "/"])
        r = subprocess.run(cmd, capture_output=True, text=True)
        msg = r.stderr.strip()
        return r.returncode == 0, msg
