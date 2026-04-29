"""File redaction workers and SQLite redaction. Top-level functions for multiprocessing."""
from __future__ import annotations
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
from pathlib import Path

from .discover import ScanTarget

REDACTED = "[REDACTED]"

BINARY_EXTS = frozenset({
    ".pyc", ".pyo", ".so", ".dll", ".exe", ".bin", ".dat",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".webp", ".svg",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".wav", ".ogg", ".webm",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".zst", ".rar",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".sqlite", ".db", ".sqlite-shm", ".sqlite-wal",
})

_MANAGED_CREDENTIAL_FILES = frozenset({
    ".claude/.credentials.json",
    ".claude.json",
    ".codex/auth.json",
    ".codex/.credentials.json",
    ".codex/config.toml",
    ".cursor/mcp.json",
    ".gemini/antigravity/mcp_config.json",
})

_MANAGED_CREDENTIAL_SUFFIXES = (
    (".cursor", "mcp.json"),
    (".codex", "config.toml"),
    (".codex", "auth.json"),
    (".codex", ".credentials.json"),
    (".claude", ".credentials.json"),
    (".gemini", "antigravity", "mcp_config.json"),
)


def is_managed_credential_file(path: Path) -> bool:
    """Return true for live auth/MCP credential stores we should preserve by default."""
    p = path.expanduser()
    try:
        rel_home = p.relative_to(Path.home())
        if rel_home.as_posix() in _MANAGED_CREDENTIAL_FILES:
            return True
        if rel_home.parts and rel_home.parts[0] == ".mcp-auth":
            return True
    except ValueError:
        pass

    parts = p.parts
    for suffix in _MANAGED_CREDENTIAL_SUFFIXES:
        if len(parts) >= len(suffix) and parts[-len(suffix):] == suffix:
            return True
    return p.name == ".mcp.json"


def collect_managed_credential_files() -> list[Path]:
    """Known live credential/config files that are not always under scan targets."""
    home = Path.home()
    candidates = [home / rel for rel in _MANAGED_CREDENTIAL_FILES]
    auth_dir = home / ".mcp-auth"
    if auth_dir.exists():
        candidates.extend(p for p in auth_dir.rglob("*") if p.is_file())

    files: list[Path] = []
    for p in candidates:
        if not p.exists() or not p.is_file():
            continue
        if p.suffix in BINARY_EXTS:
            continue
        try:
            if p.stat().st_size > 10 * 1024 * 1024:
                continue
        except OSError:
            continue
        files.append(p)
    return sorted(set(files))


def collect_files(targets: list[ScanTarget]) -> list[Path]:
    files: list[Path] = []
    for target in targets:
        for p in target.path.rglob("*"):
            if not p.is_file() or p.suffix in BINARY_EXTS:
                continue
            if target.excluded(p) and not is_managed_credential_file(p):
                continue
            try:
                if p.stat().st_size > 10 * 1024 * 1024:
                    continue
            except OSError:
                continue
            files.append(p)
    return sorted(set(files))


def grep_filter(secrets: set[str], files: list[Path]) -> list[Path]:
    if not secrets or not files:
        return []
    fd, pf = tempfile.mkstemp(prefix="agentscrub_patterns_", suffix=".txt")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(secrets))
        # Batch to stay under ARG_MAX (~2 MB) on big trees.
        BATCH = 5000
        hits: list[str] = []
        for i in range(0, len(files), BATCH):
            chunk = files[i:i + BATCH]
            r = subprocess.run(
                ["grep", "-lF", f"--file={pf}"] + [str(f) for f in chunk],
                capture_output=True, text=True,
            )
            hits.extend(line for line in r.stdout.splitlines() if line.strip())
        return [Path(x) for x in hits]
    finally:
        try:
            os.unlink(pf)
        except OSError:
            pass


_HIGH_RISK_KEYWORDS = frozenset({
    "jwt", "key", "token", "secret", "oauth", "pat", "bearer",
    "private", "credential", "password", "api",
})

_LABEL_MAP: dict[str, str] = {
    "jwt": "JWT", "json-web-token": "JWT",
    "github-pat": "GitHub PAT", "github-fine-grained-pat": "GitHub PAT",
    "github-oauth": "GitHub OAuth", "github-app-token": "GitHub App",
    "github": "GitHub Token",
    "openai-api-key": "OpenAI Key", "openai": "OpenAI Key",
    "anthropic-api-key": "Anthropic Key",
    "generic-api-key": "API Key", "generic-secret": "Secret",
    "generic api key": "API Key", "generic secret": "Secret",
    "private-key": "Private Key", "privatekey": "Private Key",
    "ssh-private-key": "SSH Key",
    "aws-access-token": "AWS Key", "aws": "AWS Key",
    "gcp-api-key": "GCP Key", "google-api-key": "Google Key",
    "slack-bot-token": "Slack Token", "slack-webhook": "Slack Webhook",
    "stripe-api-key": "Stripe Key", "stripe": "Stripe Key",
    "bearer-token": "Bearer Token", "http bearer token": "Bearer Token",
    "credentials in a url": "URL Credential",
    "credentials in postgresql connection uri": "Postgres URI",
    "database-url": "DB URL",
    "sourcegraph access token": "Sourcegraph",
    "sourcegraph-access-token": "Sourcegraph", "sourcegraph": "Sourcegraph",
    "linkedin access token": "LinkedIn Token",
    "linkedin-access-token": "LinkedIn Token", "linkedin": "LinkedIn Token",
    "dockerhub": "DockerHub",
    "unknown": "Secret",
}

_UPPER_WORDS = frozenset({"jwt", "api", "ssh", "aws", "gcp", "oauth", "pat",
                           "url", "sdk", "http", "ai", "id"})

_LOW_SIGNAL_LABELS = frozenset({
    "Coveralls Repo Identifier",
    "Datadog Site Domain",
    "Metabase",
    "Privacy",
    "Supabase Project URL",
    "Uri",
})


def _short_label(label: str) -> str:
    low = label.lower()
    if low in _LABEL_MAP:
        return _LABEL_MAP[low]
    normalized = label.replace("-", " ").replace("_", " ")
    return " ".join(
        w.upper() if w.lower() in _UPPER_WORDS else w.capitalize()
        for w in normalized.split()
    )


def _proof(secret: str, label: str) -> str:
    """Safe display string for a secret.

    JWT (eyJ prefix) → 'JWT · eyJ… · #hash'         (prefix is diagnostic)
    Other high-risk  → 'Type · #hash'                (no confusing shape hint)
    Low-risk         → value as-is or truncated
    """
    label_low = label.lower()
    is_jwt = secret.startswith("eyJ")
    is_high = (
        any(kw in label_low for kw in _HIGH_RISK_KEYWORDS)
        or is_jwt
        or (len(secret) >= 20 and len(set(secret)) >= 8)
    )
    if not is_high:
        return secret[:8] + "…" + secret[-4:] if len(secret) > 20 else secret
    short = _short_label(label)
    h = hashlib.sha256(secret.encode()).hexdigest()[:8]
    # Only show eyJ prefix when the scanner itself classifies it as JWT —
    # many non-JWT tokens are base64-encoded and also start with eyJ.
    if is_jwt and short == "JWT":
        return f"{short} · eyJ… · #{h}"
    return f"{short} · #{h}"


def file_findings(
    secrets: set[str],
    fp: Path,
    type_map: dict[str, str] | None = None,
) -> list[dict[str, object]]:
    """Safe per-file finding details for reports."""
    type_map = type_map or {}
    try:
        text = fp.read_text(errors="ignore")
    except Exception:
        return []

    findings: list[dict[str, object]] = []
    present = [s for s in secrets if s in text]
    for secret in sorted(present, key=lambda s: (type_map.get(s, "unknown"), hashlib.sha256(s.encode()).hexdigest())):
        label = _short_label(type_map.get(secret, "unknown"))
        findings.append({
            "type": label,
            "proof": _proof(secret, type_map.get(secret, "unknown")),
            "hits": text.count(secret),
        })
    return findings


def top_exposed(
    secrets: set[str],
    flagged: list[Path],
    n: int = 5,
    type_map: dict[str, str] | None = None,
    findings_by_file: dict[Path, list[dict[str, object]]] | None = None,
) -> list[tuple[Path, int, int, str]]:
    """
    Return top-n most-exposed files as (path, unique_patterns, total_hits, proof_str).
    Ranks by unique secret patterns per file first, then total hits.
    """
    results: list[tuple[Path, int, int, str]] = []
    for fp in flagged:
        findings = (
            findings_by_file.get(fp, [])
            if findings_by_file is not None
            else file_findings(secrets, fp, type_map)
        )
        if not findings:
            continue
        unique = len(findings)
        total = sum(int(f["hits"]) for f in findings)
        preferred = [f for f in findings if f["type"] not in _LOW_SIGNAL_LABELS]
        proof = max(preferred or findings, key=lambda f: int(f["hits"]))["proof"]
        results.append((fp, unique, total, proof))
    results.sort(key=lambda x: (-x[1], -x[2]))
    return results[:n]


# ── redact_file: top-level so multiprocessing can pickle it ──────────────────

def _redact_obj(obj: object, secrets: frozenset[str]) -> tuple[object, int]:
    count = 0
    if isinstance(obj, str):
        for s in secrets:
            if s in obj:
                n = obj.count(s)
                obj = obj.replace(s, REDACTED)
                count += n
        return obj, count
    if isinstance(obj, dict):
        for k in obj:
            obj[k], n = _redact_obj(obj[k], secrets)
            count += n
        return obj, count
    if isinstance(obj, list):
        for i, item in enumerate(obj):
            obj[i], n = _redact_obj(item, secrets)
            count += n
        return obj, count
    return obj, count


def redact_file(args: tuple) -> tuple[str, int, str | None]:
    """Worker — must be top-level for multiprocessing.Pool pickling."""
    path_str, secrets, dry_run = args
    path = Path(path_str)
    try:
        lines_out, total = [], 0
        for line in path.read_text(errors="ignore").splitlines(keepends=True):
            stripped = line.rstrip("\n")
            if not stripped.strip() or not any(s in stripped for s in secrets):
                lines_out.append(line)
                continue
            try:
                obj = json.loads(stripped)
                obj, n = _redact_obj(obj, secrets)
                total += n
                lines_out.append(
                    json.dumps(obj, ensure_ascii=False) + ("\n" if line.endswith("\n") else "")
                    if n else line
                )
            except json.JSONDecodeError:
                new, n = stripped, 0
                for s in secrets:
                    if s in new:
                        n += new.count(s)
                        new = new.replace(s, REDACTED)
                total += n
                lines_out.append(new + ("\n" if line.endswith("\n") else ""))
        if total == 0:
            return path_str, 0, None
        if not dry_run:
            suffix = path.suffix or ".tmp"
            tmp = path.with_suffix(suffix + ".agentscrub_tmp")
            tmp.write_text("".join(lines_out))
            shutil.move(str(tmp), str(path))
        return path_str, total, None
    except Exception as e:
        return path_str, 0, str(e)


def redact_sqlite(
    secrets: set[str],
    targets: list[ScanTarget],
    dry_run: bool,
) -> tuple[int, list[tuple[Path, int]]]:
    """Redact text columns in all SQLite DBs. Returns (total, [(path, count)])."""
    results: list[tuple[Path, int]] = []
    for target in targets:
        for db_path in sorted(target.path.rglob("*.sqlite")):
            if target.excluded(db_path):
                continue
            try:
                con = sqlite3.connect(str(db_path))
                tables = con.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
                db_count = 0
                for (tname,) in tables:
                    if tname.startswith("_sqlx"):
                        continue
                    cols = con.execute(f'PRAGMA table_info("{tname}")').fetchall()
                    text_cols = [r[1] for r in cols if "text" in r[2].lower() or r[2] == ""]
                    if not text_cols:
                        continue
                    col_list = ", ".join(f'"{c}"' for c in text_cols)
                    rows = con.execute(
                        f'SELECT rowid, {col_list} FROM "{tname}"'
                    ).fetchall()
                    for row in rows:
                        rowid = row[0]
                        for i, val in enumerate(row[1:]):
                            if not val or not isinstance(val, str):
                                continue
                            if not any(s in val for s in secrets):
                                continue
                            new_val, n = val, 0
                            for s in secrets:
                                if s in new_val:
                                    n += new_val.count(s)
                                    new_val = new_val.replace(s, REDACTED)
                            if n:
                                db_count += n
                                if not dry_run:
                                    con.execute(
                                        f'UPDATE "{tname}" SET "{text_cols[i]}" = ?'
                                        f' WHERE rowid = ?',
                                        (new_val, rowid),
                                    )
                if not dry_run and db_count:
                    con.commit()
                con.close()
                if db_count:
                    results.append((db_path, db_count))
            except Exception as e:
                results.append((db_path, -(1)))  # negative = error
    return sum(c for _, c in results if c > 0), results
