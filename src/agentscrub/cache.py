"""Incremental scan cache — skip files whose content hasn't changed since last clean scan."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path

from .backup import BACKUP_ROOT

_CACHE_DB = BACKUP_ROOT.parent / "state.db"   # ~/.agentscrub/state.db
_CACHE_POLICY_VERSION = "3"

# A file is fingerprinted by its first and last _SAMPLE bytes, never by a full
# read: re-reading every cached log on every run defeats the cache. For files
# up to 2 * _SAMPLE the fingerprint covers every byte.
_SAMPLE = 1024 * 1024
# Logs that only grew are resumed from the previous end instead of being
# rescanned. Below this size a full rescan is cheap enough not to bother.
RESUME_MIN_SIZE = 4 * 1024 * 1024
_SQL_BATCH = 500


def _digest(data: bytes) -> str:
    return hashlib.blake2b(data, digest_size=16).hexdigest()


def _sample_digests(fp: Path, size: int) -> tuple[str, str]:
    """(head, tail) fingerprints of the byte range [0, size) of fp.

    Reads at most 2 * _SAMPLE bytes regardless of file size.
    """
    n = min(_SAMPLE, size)
    with fp.open("rb") as fh:
        head = fh.read(n)
        fh.seek(max(0, size - _SAMPLE))
        tail = fh.read(n)
    return _digest(head), _digest(tail)


@dataclass(frozen=True)
class Snapshot:
    """What a file looked like when its scan started (not when it finished)."""
    mtime_ns: int
    size: int
    head: str
    tail: str


@dataclass
class ScanPlan:
    """Which files need scanning, and from which byte."""
    needs_scan: list[Path] = field(default_factory=list)
    n_skipped: int = 0
    # Files that only grew since their last clean scan: bytes already scanned.
    offsets: dict[Path, int] = field(default_factory=dict)
    snapshots: dict[Path, Snapshot] = field(default_factory=dict)


def _connect() -> sqlite3.Connection:
    _CACHE_DB.parent.mkdir(parents=True, exist_ok=True)
    if not _CACHE_DB.exists():
        fd = os.open(str(_CACHE_DB), os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(fd)
    con = sqlite3.connect(str(_CACHE_DB))
    con.execute("""
        CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS file_cache (
            path      TEXT    PRIMARY KEY,
            mtime_ns  INTEGER NOT NULL,
            size      INTEGER NOT NULL,
            digest    TEXT    NOT NULL DEFAULT '',
            cached_at INTEGER NOT NULL
        )
    """)
    columns = {row[1] for row in con.execute("PRAGMA table_info(file_cache)")}
    if "digest" not in columns:
        con.execute("ALTER TABLE file_cache ADD COLUMN digest TEXT NOT NULL DEFAULT ''")
    if "tail_digest" not in columns:
        con.execute("ALTER TABLE file_cache ADD COLUMN tail_digest TEXT NOT NULL DEFAULT ''")
    if "ctime_ns" not in columns:
        con.execute("ALTER TABLE file_cache ADD COLUMN ctime_ns INTEGER NOT NULL DEFAULT 0")
    # Databases (SQLite/vscdb): a DB is skipped when its on-disk state is
    # unchanged AND every current secret was already verified absent from it.
    # Only hashes of secrets are stored, never the secrets themselves.
    con.execute("""
        CREATE TABLE IF NOT EXISTS db_cache (
            path      TEXT    PRIMARY KEY,
            state     TEXT    NOT NULL,
            cached_at INTEGER NOT NULL
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS db_checked (
            path        TEXT NOT NULL,
            secret_hash TEXT NOT NULL,
            PRIMARY KEY (path, secret_hash)
        )
    """)
    con.commit()
    return con


def _detector_fingerprint() -> str:
    """JSON fingerprint of installed detector versions for cache invalidation."""
    from . import __version__
    from .installers import BIN_DIR, detector_specs
    specs = detector_specs()
    versions = {key: spec.version for key, spec in specs.items()}
    # Include which detectors are actually installed
    installed = {key: (BIN_DIR / spec.binary).exists() for key, spec in specs.items()}
    return json.dumps(
        {
            "agentscrub": __version__,
            "policy": _CACHE_POLICY_VERSION,
            "versions": versions,
            "installed": installed,
        },
        sort_keys=True,
    )


def _check_and_wipe_if_stale(con: sqlite3.Connection) -> None:
    """Wipe file_cache if detector versions have changed since last run."""
    current = _detector_fingerprint()
    row = con.execute("SELECT value FROM meta WHERE key = 'detector_fingerprint'").fetchone()
    if row is None:
        con.execute(
            "INSERT INTO meta (key, value) VALUES ('detector_fingerprint', ?)", (current,)
        )
        con.commit()
        return
    if row[0] != current:
        con.execute("DELETE FROM file_cache")
        con.execute("DELETE FROM db_cache")
        con.execute("DELETE FROM db_checked")
        con.execute(
            "UPDATE meta SET value = ? WHERE key = 'detector_fingerprint'", (current,)
        )
        con.commit()


def plan_scan(files: list[Path]) -> ScanPlan:
    """Decide, per file, whether it is clean-and-unchanged, grew, or must be rescanned.

    Cache hit (no read at all): (mtime, size) match and so does ctime. ctime
    cannot be set from user space, so it catches a rewrite whose mtime was
    restored. If only ctime differs (chmod, hardlink, rename) the head/tail
    fingerprints decide, reading at most 2 MiB.

    Grew: the file is larger, and the fingerprints of the previously scanned
    region still match, so only the appended bytes need scanning.
    """
    plan = ScanPlan()
    if not files:
        return plan
    try:
        con = _connect()
        _check_and_wipe_if_stale(con)
    except Exception:
        return _plan_everything(files)   # cache unavailable — scan everything

    try:
        stats: dict[Path, os.stat_result] = {}
        for fp in files:
            try:
                stats[fp] = fp.stat()
            except OSError:
                plan.needs_scan.append(fp)   # vanished / unreadable: let the scanner decide
        cached: dict[str, tuple] = {}
        keys = [str(fp) for fp in stats]
        for i in range(0, len(keys), _SQL_BATCH):
            chunk = keys[i:i + _SQL_BATCH]
            rows = con.execute(
                "SELECT path, mtime_ns, size, digest, tail_digest, ctime_ns FROM file_cache"
                f" WHERE path IN ({','.join('?' * len(chunk))})",
                chunk,
            ).fetchall()
            cached.update({r[0]: r[1:] for r in rows})

        for fp, st in stats.items():
            row = cached.get(str(fp))
            try:
                verdict = _classify(fp, st, row)
            except OSError:
                verdict = ("full", 0)
            kind, offset = verdict
            if kind == "hit":
                plan.n_skipped += 1
                continue
            plan.needs_scan.append(fp)
            if kind == "grew":
                plan.offsets[fp] = offset
            try:
                head, tail = _sample_digests(fp, st.st_size)
                plan.snapshots[fp] = Snapshot(st.st_mtime_ns, st.st_size, head, tail)
            except OSError:
                pass
        return plan
    except Exception:
        return _plan_everything(files)
    finally:
        try:
            con.close()
        except Exception:
            pass


def _plan_everything(files: list[Path]) -> ScanPlan:
    return ScanPlan(needs_scan=list(files))


def _classify(fp: Path, st: os.stat_result, row: tuple | None) -> tuple[str, int]:
    if row is None:
        return "full", 0
    mtime_ns, size, head, tail, ctime_ns = row
    if (st.st_mtime_ns, st.st_size) == (mtime_ns, size):
        if ctime_ns and st.st_ctime_ns == ctime_ns:
            return "hit", 0
        cur_head, cur_tail = _sample_digests(fp, st.st_size)
        if head and (cur_head, cur_tail) == (head, tail):
            return "hit", 0
        return "full", 0
    if st.st_size > size >= RESUME_MIN_SIZE and head:
        # Appended log: verify the region scanned last time is untouched.
        if _sample_digests(fp, size) == (head, tail):
            return "grew", size
    return "full", 0


def filter_uncached(files: list[Path]) -> tuple[list[Path], int]:
    """Split files into (needs_scan, n_skipped). See plan_scan for the rules."""
    plan = plan_scan(files)
    return plan.needs_scan, plan.n_skipped


def mark_clean(files: list[Path], plan: ScanPlan | None = None) -> None:
    """Record files as clean as of the state they had when their scan STARTED.

    With a plan, the recorded (mtime, size, fingerprints) are the pre-scan
    snapshot: bytes appended while detectors ran are not claimed as scanned,
    they are picked up by the next run as an appended tail.
    """
    if not files:
        return
    now = int(time.time())
    rows: list[tuple] = []
    for fp in files:
        try:
            st = fp.stat()
            snap = plan.snapshots.get(fp) if plan else None
            if snap is None:
                head, tail = _sample_digests(fp, st.st_size)
                snap = Snapshot(st.st_mtime_ns, st.st_size, head, tail)
            unchanged = (st.st_mtime_ns, st.st_size) == (snap.mtime_ns, snap.size)
            rows.append((
                str(fp), snap.mtime_ns, snap.size, snap.head, snap.tail,
                st.st_ctime_ns if unchanged else 0, now,
            ))
        except OSError:
            continue
    if not rows:
        return
    try:
        con = _connect()
        con.executemany(
            "INSERT OR REPLACE INTO file_cache"
            " (path, mtime_ns, size, digest, tail_digest, ctime_ns, cached_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        con.commit()
        con.close()
    except Exception:
        pass


def invalidate(files: list[Path]) -> None:
    """Remove files from cache (called after redaction so next run re-scans them)."""
    if not files:
        return
    try:
        con = _connect()
        con.executemany(
            "DELETE FROM file_cache WHERE path = ?",
            [(str(fp),) for fp in files],
        )
        con.commit()
        con.close()
    except Exception:
        pass


# ── database cache ────────────────────────────────────────────────────────────

def _secret_hash(secret: str) -> str:
    return _digest(secret.encode("utf-8", "surrogatepass"))


def db_state(db_path: Path) -> str | None:
    """Stat fingerprint of a DB and its WAL/SHM sidecars; None if unreadable."""
    parts: list[str] = []
    for suffix in ("", "-wal", "-shm"):
        try:
            st = Path(str(db_path) + suffix).stat()
            parts.append(f"{st.st_mtime_ns}:{st.st_size}")
        except FileNotFoundError:
            parts.append("-")
        except OSError:
            return None
    return "|".join(parts)


def db_unchecked_secrets(db_path: Path, secrets: set[str]) -> set[str]:
    """Secrets not yet verified absent from this DB at its current on-disk state.

    Everything, if the DB changed since it was last verified.
    """
    state = db_state(db_path)
    if state is None:
        return set(secrets)
    try:
        con = _connect()
        try:
            _check_and_wipe_if_stale(con)
            row = con.execute(
                "SELECT state FROM db_cache WHERE path = ?", (str(db_path),)
            ).fetchone()
            if row is None or row[0] != state:
                return set(secrets)
            done = {
                r[0] for r in con.execute(
                    "SELECT secret_hash FROM db_checked WHERE path = ?", (str(db_path),)
                )
            }
        finally:
            con.close()
    except Exception:
        return set(secrets)
    return {s for s in secrets if _secret_hash(s) not in done}


def mark_db_checked(db_path: Path, secrets: set[str], state: str | None) -> None:
    """Record that `secrets` are absent from the DB as it was in `state`."""
    if state is None or not secrets:
        return
    try:
        con = _connect()
        try:
            row = con.execute(
                "SELECT state FROM db_cache WHERE path = ?", (str(db_path),)
            ).fetchone()
            if row is None or row[0] != state:
                con.execute("DELETE FROM db_checked WHERE path = ?", (str(db_path),))
            con.execute(
                "INSERT OR REPLACE INTO db_cache (path, state, cached_at) VALUES (?, ?, ?)",
                (str(db_path), state, int(time.time())),
            )
            con.executemany(
                "INSERT OR IGNORE INTO db_checked (path, secret_hash) VALUES (?, ?)",
                [(str(db_path), _secret_hash(s)) for s in secrets],
            )
            con.commit()
        finally:
            con.close()
    except Exception:
        pass


def invalidate_db(db_path: Path) -> None:
    """Forget a DB (called after it was rewritten by redaction)."""
    try:
        con = _connect()
        try:
            con.execute("DELETE FROM db_cache WHERE path = ?", (str(db_path),))
            con.execute("DELETE FROM db_checked WHERE path = ?", (str(db_path),))
            con.commit()
        finally:
            con.close()
    except Exception:
        pass
