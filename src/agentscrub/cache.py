"""Incremental scan cache — skip files whose content hasn't changed since last clean scan."""
from __future__ import annotations
import json
import os
import sqlite3
import time
from pathlib import Path

from .backup import BACKUP_ROOT

_CACHE_DB = BACKUP_ROOT.parent / "state.db"   # ~/.agentscrub/state.db


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
            cached_at INTEGER NOT NULL
        )
    """)
    con.commit()
    return con


def _detector_fingerprint() -> str:
    """JSON fingerprint of installed detector versions for cache invalidation."""
    from .installers import BIN_DIR, detector_specs
    specs = detector_specs()
    versions = {key: spec.version for key, spec in specs.items()}
    # Include which detectors are actually installed
    installed = {key: (BIN_DIR / spec.binary).exists() for key, spec in specs.items()}
    return json.dumps({"versions": versions, "installed": installed}, sort_keys=True)


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
        con.execute(
            "UPDATE meta SET value = ? WHERE key = 'detector_fingerprint'", (current,)
        )
        con.commit()


def filter_uncached(files: list[Path]) -> tuple[list[Path], int]:
    """Split files into (needs_scan, n_skipped).

    A file is a cache hit when its (mtime_ns, size) match the stored row,
    meaning it was previously scanned and found to be clean.
    """
    if not files:
        return [], 0
    try:
        con = _connect()
        _check_and_wipe_if_stale(con)
    except Exception:
        return files, 0   # cache unavailable — scan everything

    try:
        st_map: dict[Path, tuple[int, int]] = {}
        missing: list[Path] = []
        for fp in files:
            try:
                st = fp.stat()
                st_map[fp] = (st.st_mtime_ns, st.st_size)
            except OSError:
                missing.append(fp)

        if not st_map:
            return missing, 0

        placeholders = ",".join("?" * len(st_map))
        rows = con.execute(
            f"SELECT path, mtime_ns, size FROM file_cache WHERE path IN ({placeholders})",
            [str(fp) for fp in st_map],
        ).fetchall()
        cached = {row[0]: (row[1], row[2]) for row in rows}

        needs_scan: list[Path] = list(missing)
        n_skipped = 0
        for fp, (mtime_ns, size) in st_map.items():
            if cached.get(str(fp)) == (mtime_ns, size):
                n_skipped += 1
            else:
                needs_scan.append(fp)
        return needs_scan, n_skipped
    except Exception:
        return files, 0
    finally:
        try:
            con.close()
        except Exception:
            pass


def mark_clean(files: list[Path]) -> None:
    """Record files as clean (no secrets found at current mtime/size)."""
    if not files:
        return
    now = int(time.time())
    rows: list[tuple[str, int, int, int]] = []
    for fp in files:
        try:
            st = fp.stat()
            rows.append((str(fp), st.st_mtime_ns, st.st_size, now))
        except OSError:
            continue
    if not rows:
        return
    try:
        con = _connect()
        con.executemany(
            "INSERT OR REPLACE INTO file_cache (path, mtime_ns, size, cached_at)"
            " VALUES (?, ?, ?, ?)",
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
