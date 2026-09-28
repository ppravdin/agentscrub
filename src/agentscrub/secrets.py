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


# Files larger than this are not handed to detectors whole: they are cut into
# newline-aligned chunks so detector memory and staging disk stay bounded no
# matter how large an agent log grows. There is no file size limit.
CHUNK_BYTES = 8 * 1024 * 1024
# Chunk bytes staged per detector invocation (hardlinked small files cost none).
# Titus needs ~11x this in RAM, so it is what bounds detector memory.
BATCH_BYTES = 64 * 1024 * 1024
# Re-scan this many bytes before a resume offset, so a token that straddles the
# old end of the file (a line still being written) is seen whole.
RESUME_OVERLAP = 8192
# When one line exceeds 2 * CHUNK_BYTES it is cut anyway; consecutive pieces
# overlap by this much so a secret at the cut is still seen whole.
_FORCED_SPLIT_OVERLAP = 8192


def _iter_chunks(fp: Path, start: int = 0):
    """Yield fp[start:] as newline-aligned byte chunks of about CHUNK_BYTES.

    Holds at most ~2 chunks in memory. Lines are only cut when a single line
    is longer than 2 * CHUNK_BYTES (then with _FORCED_SPLIT_OVERLAP overlap).
    """
    with fp.open("rb") as fh:
        fh.seek(start)
        carry = b""
        while True:
            block = fh.read(CHUNK_BYTES)
            if not block:
                break
            buf = carry + block
            cut = buf.rfind(b"\n")
            if cut != -1:
                yield buf[:cut + 1]
                carry = buf[cut + 1:]
            elif len(buf) >= 2 * CHUNK_BYTES:
                yield buf
                carry = buf[-_FORCED_SPLIT_OVERLAP:]
            else:
                carry = buf
        if carry:
            yield carry


def _stage_dir():
    from .backup import BACKUP_ROOT
    try:
        tmp_parent = BACKUP_ROOT.parent
        tmp_parent.mkdir(parents=True, exist_ok=True)
        return tempfile.TemporaryDirectory(dir=str(tmp_parent), prefix="scan_")
    except OSError:
        return tempfile.TemporaryDirectory(prefix="agentscrub_scan_")


def _run_on_files(
    files: list[Path],
    fn,
    offsets: dict[Path, int] | None = None,
) -> dict[str, str]:
    """Run a directory-scanning detector on a specific file list via temp dirs.

    Small files are hard-linked (shutil.copy2 if cross-device) into one temp
    dir. Files larger than CHUNK_BYTES, and files with a resume offset (only
    their appended tail needs scanning), are cut into newline-aligned chunks
    that are staged and scanned in batches of at most BATCH_BYTES, so neither
    memory nor scratch disk grows with file size.
    """
    if not files:
        return {}
    import shutil as _shutil
    offsets = offsets or {}

    small: list[Path] = []
    big: list[tuple[Path, int]] = []
    for fp in files:
        start = max(0, offsets.get(fp, 0) - RESUME_OVERLAP) if offsets.get(fp) else 0
        try:
            size = fp.stat().st_size
        except OSError:
            continue
        if start == 0 and size <= CHUNK_BYTES:
            small.append(fp)
        else:
            big.append((fp, start))

    out: dict[str, str] = {}

    if small:
        with _stage_dir() as tmp:
            tmp_path = Path(tmp)
            linked = 0
            for i, fp in enumerate(small):
                dest = tmp_path / f"{i:08d}{fp.suffix}"
                try:
                    os.link(fp, dest)
                except OSError:
                    try:
                        _shutil.copy2(str(fp), str(dest))
                    except OSError:
                        continue
                linked += 1
            if linked:
                out.update(fn(tmp_path))

    if big:
        td = _stage_dir()
        staged = 0
        n_files = 0
        try:
            for i, (fp, start) in enumerate(big):
                try:
                    for k, chunk in enumerate(_iter_chunks(fp, start)):
                        if staged and staged + len(chunk) > BATCH_BYTES:
                            out.update(fn(Path(td.name)))
                            td.cleanup()
                            td = _stage_dir()
                            staged = 0
                            n_files = 0
                        (Path(td.name) / f"{i:08d}_{k:05d}{fp.suffix}").write_bytes(chunk)
                        staged += len(chunk)
                        n_files += 1
                except OSError:
                    continue   # vanished or unreadable mid-scan
            if n_files:
                out.update(fn(Path(td.name)))
        finally:
            td.cleanup()
    return out


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
    """Merge all per-tool {secret: label} dicts into one map.

    When tools disagree, a label the redaction allowlist trusts wins over one
    it does not. Plain last-wins let Titus's "GitHub Personal Access Token"
    override gitleaks's "github-pat", which silently demoted a real token to
    report-only so `run` never redacted it.
    """
    from .redact import _short_label, is_high_precision_label

    def trusted(label: str) -> bool:
        return is_high_precision_label(_short_label(label))

    merged: dict[str, str] = {}
    for d in by_tool.values():
        for secret, label in d.items():
            cur = merged.get(secret)
            if cur is None or trusted(label) or not trusted(cur):
                merged[secret] = label
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
