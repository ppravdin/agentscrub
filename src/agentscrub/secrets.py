"""Collect secrets via gitleaks, TruffleHog, and Titus (run in parallel)."""
from __future__ import annotations

import base64
import collections
import concurrent.futures
import json
import os
import subprocess
import tempfile
from pathlib import Path

from .discover import ScanTarget
from .installers import BIN_DIR, detector_path, detector_specs

_SPECS = detector_specs()


def _tool_path(key: str) -> Path:
    spec = _SPECS[key]
    return detector_path(spec.binary) or (BIN_DIR / spec.binary)


GITLEAKS   = _tool_path("gitleaks")
TRUFFLEHOG = _tool_path("trufflehog")
TITUS      = _tool_path("titus")

_LOW_SIGNAL_TYPES = frozenset({
    "Coveralls Repo Identifier",
    "Datadog Site Domain",
    "Metabase",
    "Privacy",
    "Supabase Project URL",
    "Uri",
})


def _gitleaks(d: Path) -> dict[str, str]:
    """Returns {secret_value: rule_id}."""
    if not GITLEAKS.exists():
        return {}
    fd, out = tempfile.mkstemp(prefix="agentscrub_gl_", suffix=".json")
    os.close(fd)
    try:
        try:
            result = subprocess.run(
                [str(GITLEAKS), "detect", "--source", str(d),
                 "--no-git", "--report-format", "json", "--report-path", out],
                capture_output=True, text=True, timeout=180,
            )
            if result.returncode not in (0, 1):  # gitleaks uses 1 for findings
                raise RuntimeError(
                    f"gitleaks failed ({result.returncode}): "
                    f"{(result.stderr or '').strip()[:300]}"
                )
        except subprocess.TimeoutExpired:
            raise RuntimeError("gitleaks timed out after 180 seconds") from None
        s: dict[str, str] = {}
        try:
            with open(out) as fh:
                for h in json.load(fh):
                    v = h.get("Secret", "").strip()
                    if v and len(v) >= 8:
                        s[v] = h.get("RuleID", "unknown")
        except (OSError, json.JSONDecodeError) as e:
            raise RuntimeError(f"gitleaks returned an unreadable report: {e}") from e
        return s
    finally:
        try:
            os.unlink(out)
        except OSError:
            pass


def _trufflehog(d: Path) -> dict[str, str]:
    """Returns {secret_value: detector_name}."""
    if not TRUFFLEHOG.exists():
        return {}
    try:
        r = subprocess.run(
            [str(TRUFFLEHOG), "filesystem", str(d), "--json", "--no-verification"],
            capture_output=True, text=True, timeout=180,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("TruffleHog timed out after 180 seconds") from None
    if r.returncode != 0:
        raise RuntimeError(
            f"TruffleHog failed ({r.returncode}): {(r.stderr or '').strip()[:300]}"
        )
    s: dict[str, str] = {}
    for line in r.stdout.splitlines():
        try:
            h = json.loads(line)
            name = h.get("DetectorName", "unknown")
            for field in ("Raw", "RawV2"):
                v = h.get(field, "").strip()
                if v and len(v) >= 8:
                    s[v] = name
        except json.JSONDecodeError as e:
            raise RuntimeError(f"TruffleHog returned invalid JSON: {e}") from e
    return s


def _titus(d: Path) -> dict[str, str]:
    """Returns {secret_value: rule_name}."""
    if not TITUS.exists():
        return {}
    try:
        r = subprocess.run(
            [str(TITUS), "scan", str(d), "--format", "json", "--output", ":memory:"],
            capture_output=True, text=True, timeout=180,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("Titus timed out after 180 seconds") from None
    if r.returncode != 0:
        raise RuntimeError(
            f"Titus failed ({r.returncode}): {(r.stderr or '').strip()[:300]}"
        )
    s: dict[str, str] = {}
    try:
        for hit in json.loads(r.stdout):
            name = (hit.get("rule_name") or hit.get("RuleName") or
                    hit.get("name") or hit.get("Name") or "unknown")
            for g in hit.get("Groups", []):
                try:
                    v = base64.b64decode(g + "==").decode("utf-8", errors="replace").strip()
                    if v and len(v) >= 8 and not v.isspace():
                        s[v] = name
                except Exception:
                    pass
    except (TypeError, json.JSONDecodeError) as e:
        raise RuntimeError(f"Titus returned invalid JSON: {e}") from e
    return s


def _run_on_files(files: list[Path], fn) -> dict[str, str]:
    """Run a directory-scanning detector on a specific file list via a temp dir.

    Hard-links files into a temp dir on the same filesystem so the detector
    scans only the files that actually need scanning (uncached / changed).
    Falls back to shutil.copy2 if hard links are unavailable (cross-device).
    """
    if not files:
        return {}
    import shutil as _shutil

    from .backup import BACKUP_ROOT
    try:
        tmp_parent = BACKUP_ROOT.parent
        tmp_parent.mkdir(parents=True, exist_ok=True)
        td: tempfile.TemporaryDirectory = tempfile.TemporaryDirectory(
            dir=str(tmp_parent), prefix="scan_"
        )
    except OSError:
        td = tempfile.TemporaryDirectory(prefix="agentscrub_scan_")
    with td as tmp:
        tmp_path = Path(tmp)
        linked = 0
        for i, fp in enumerate(files):
            dest = tmp_path / f"{i:08d}{fp.suffix}"
            try:
                os.link(fp, dest)
            except OSError:
                try:
                    _shutil.copy2(str(fp), str(dest))
                except OSError:
                    continue
            linked += 1
        return fn(tmp_path) if linked else {}


def collect(targets: list[ScanTarget]) -> tuple[set[str], dict[str, int]]:
    """
    Run all three tools across all target dirs in parallel.
    Returns (all_secrets, {tool_name: count}).
    """
    by_tool: dict[str, dict[str, str]] = {
        "gitleaks": {}, "trufflehog": {}, "titus": {},
    }
    with concurrent.futures.ThreadPoolExecutor() as ex:
        futs = []
        for t in targets:
            futs += [
                ("gitleaks",   ex.submit(_gitleaks,   t.path)),
                ("trufflehog", ex.submit(_trufflehog, t.path)),
                ("titus",      ex.submit(_titus,      t.path)),
            ]
        for tool, fut in futs:
            by_tool[tool].update(fut.result())

    all_secrets = {
        s for sdict in by_tool.values() for s in sdict
        if len(s) >= 8 and not s.isspace()
    }
    counts = {tool: len(sdict) for tool, sdict in by_tool.items()}
    return all_secrets, counts


def all_typed(by_tool: dict[str, dict[str, str]]) -> dict[str, str]:
    """Merge all per-tool {secret: label} dicts into one map."""
    merged: dict[str, str] = {}
    for d in by_tool.values():
        merged.update(d)
    return merged


def top_types(by_tool: dict[str, dict[str, str]], n: int = 6) -> list[tuple[str, int]]:
    """
    Given the per-tool dicts returned by _gitleaks/_trufflehog/_titus,
    return the n most common type labels (by unique secret count).
    """
    merged: dict[str, str] = {}
    for d in by_tool.values():
        merged.update(d)
    counts: collections.Counter[str] = collections.Counter(
        label for secret, label in merged.items()
        if len(secret) >= 8 and not secret.isspace() and label not in _LOW_SIGNAL_TYPES
    )
    return counts.most_common(n)


def tools_status() -> list[tuple[str, Path, bool]]:
    """Return [(display_name, path, installed)] for each detection tool."""
    return [
        ("gitleaks",   GITLEAKS,   GITLEAKS.exists()),
        ("TruffleHog", TRUFFLEHOG, TRUFFLEHOG.exists()),
        ("Titus",      TITUS,      TITUS.exists()),
    ]
