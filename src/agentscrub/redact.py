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
    ".vscdb", ".vscdb-shm", ".vscdb-wal", ".db-shm", ".db-wal",
    ".mdb",  # LMDB binary (Zed Flatpak threads-db.1.mdb) — cannot be redacted in-place
})

# SQLite-family file extensions that the SQLite redaction pass should open.
# Excludes -shm/-wal companions (they're handled implicitly by the main DB).
_SQLITE_GLOBS = ("*.sqlite", "*.db", "*.vscdb")

_MANAGED_CREDENTIAL_FILES = frozenset({
    ".claude/.credentials.json",
    ".claude/settings.json",
    ".claude.json",
    ".codex/auth.json",
    ".codex/.credentials.json",
    ".codex/config.toml",
    ".cursor/mcp.json",
    ".windsurf/mcp.json",
    ".windsurf/mcp_config.json",
    ".codeium/mcp_config.json",
    ".codeium/windsurf/mcp_config.json",
    ".config/Codeium/Windsurf/mcp_config.json",
    ".gemini/antigravity/mcp_config.json",
    ".gemini/oauth_creds.json",
    ".gemini/mcp-oauth-tokens.json",
    ".gemini/settings.json",
    ".gemini/google_accounts.json",
    ".gemini/trustedFolders.json",
    ".gemini/installation_id",
    ".gemini/user_id",
    ".local/share/opencode/auth.json",
    ".local/share/opencode/mcp-auth.json",
    ".config/opencode/opencode.json",
    ".config/opencode/opencode.jsonc",
    ".config/opencode/tui.json",
    ".config/opencode/tui.jsonc",
    ".local/share/crush/mcp.json",
    ".local/share/crush/crush.json",
    ".config/crush/crush.json",
    ".aider.conf.yml",
    ".continue/config.yaml",
    ".continue/config.json",
    ".continue/config.ts",
    ".continue/.env",
    ".cline/data/settings/cline_mcp_settings.json",
    ".cline/data/secrets.json",
    ".cline/data/globalState.json",
})

_MANAGED_CREDENTIAL_SUFFIXES = (
    (".cursor", "mcp.json"),
    (".windsurf", "mcp.json"),
    (".windsurf", "mcp_config.json"),
    (".codex", "config.toml"),
    (".codex", "auth.json"),
    (".codex", ".credentials.json"),
    (".claude", ".credentials.json"),
    (".claude", "settings.json"),
    (".codeium", "mcp_config.json"),
    (".codeium", "windsurf", "mcp_config.json"),
    (".config", "Codeium", "Windsurf", "mcp_config.json"),
    (".gemini", "antigravity", "mcp_config.json"),
    (".gemini", "oauth_creds.json"),
    (".gemini", "mcp-oauth-tokens.json"),
    (".gemini", "settings.json"),
    ("opencode", "auth.json"),
    ("opencode", "mcp-auth.json"),
    (".config", "opencode", "opencode.json"),
    (".config", "opencode", "opencode.jsonc"),
    (".config", "opencode", "tui.json"),
    (".config", "opencode", "tui.jsonc"),
    ("crush", "mcp.json"),
    ("crush", "crush.json"),
    (".config", "crush", "crush.json"),
    (".aider.conf.yml",),
    (".continue", "config.yaml"),
    (".continue", "config.json"),
    (".continue", "config.ts"),
    (".continue", ".env"),
    # Cline VS Code extension — same trailing path on macOS / Linux / Windows
    ("saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
    ("saoudrizwan.claude-dev", "settings", "secrets.json"),
    ("saoudrizwan.claude-dev", "secrets.json"),
    # Cline CLI mode (default ~/.cline; also catches CLINE_DIR override that ends with /.cline)
    (".cline", "data", "settings", "cline_mcp_settings.json"),
    (".cline", "data", "secrets.json"),
    (".cline", "data", "globalState.json"),
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
            if target.excluded_by_dir(p):
                continue
            if target.excluded_by_name(p) and not is_managed_credential_file(p):
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
    "generic password": "Password",
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
    "json web token (base64url encoded)": "JWT",
    "json-web-token-base64url-encoded": "JWT",
    "json web token base64url encoded": "JWT",
    "sourcegraph access token": "Sourcegraph",
    "sourcegraph-access-token": "Sourcegraph", "sourcegraph": "Sourcegraph",
    "linkedin access token": "LinkedIn Token",
    "linkedin-access-token": "LinkedIn Token", "linkedin": "LinkedIn Token",
    "dockerhub": "DockerHub",
    "npmtoken": "NPM Token",
    "npm access token (fine grained)": "NPM Token",
    "npm-access-token-fine-grained": "NPM Token",
    "npm access token fine grained": "NPM Token",
    "github secret key": "GitHub Secret",
    "githuboauth2": "GitHub OAuth",
    "github personal access token (fine grained permissions)": "GitHub PAT",
    "google oauth credentials": "Google OAuth",
    "google oauth client secret": "Google OAuth Secret",
    "cloudflareapitoken": "Cloudflare Token",
    "posthog project api key": "PostHog Key",
    "postmark api token": "Postmark Token",
    "curl basic authentication credentials": "Basic Auth",
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


def is_low_signal_label(label: str) -> bool:
    """Return true for detector labels that are useful but noisy in summaries."""
    return label in _LOW_SIGNAL_LABELS


# Labels we trust enough to RUN actually rewrite text on. Everything else is
# scanned + reported but never modified. Rules are listed here when the
# matching token format has a distinctive prefix / structural validation
# (e.g. AWS keys with AKIA + checksum, GitHub PATs with ghp_ + 36 chars,
# JWT 3-part validation, PEM blocks). Loose patterns ("Generic Secret",
# "Postgres URI", "Sourcegraph", "Bearer Token", "URL Credential") are
# excluded because in practice they false-fire on plugin slugs, beta-flag
# strings, code samples, and JSON dumps inside chat-session logs — and
# rewriting those corrupts user data far worse than missing a real secret.
_HIGH_PRECISION_LABELS = frozenset({
    "JWT",
    "GitHub PAT", "GitHub OAuth", "GitHub App", "GitHub Token",
    "OpenAI Key", "Anthropic Key",
    "AWS Key",
    "GCP Key", "Google Key", "Google OAuth", "Google OAuth Secret",
    "Slack Token", "Slack Webhook",
    "Stripe Key",
    "SSH Key", "Private Key",
    "NpmToken", "Npm Token",
    "Dockerhub",
    "PostHog Key",
    "Postmark Token",
})


def _norm_label(s: str) -> str:
    """Lowercase + strip spaces/dashes/underscores for tolerant comparison."""
    return s.lower().replace(" ", "").replace("-", "").replace("_", "")


_HIGH_PRECISION_NORMALIZED = frozenset(_norm_label(l) for l in _HIGH_PRECISION_LABELS)


def is_high_precision_label(label: str) -> bool:
    """True if `label` (in any of: 'JWT' / 'jwt' / 'NpmToken' / 'npm token' / 'npm-token') is
    in the high-precision allowlist. Normalizes case + spaces + dashes."""
    return _norm_label(label) in _HIGH_PRECISION_NORMALIZED


def partition_secrets_by_precision(
    secrets: set[str],
    type_map: dict[str, str],
) -> tuple[set[str], set[str]]:
    """Split secrets into (redactable, report_only) based on rule precision.

    Returns:
      redactable  — high-precision tokens, safe to rewrite to [REDACTED]
      report_only — everything else; reported in the audit but never written
    """
    redactable: set[str] = set()
    report_only: set[str] = set()
    for s in secrets:
        label = _short_label(type_map.get(s, "unknown"))
        if is_high_precision_label(label):
            redactable.add(s)
        else:
            report_only.add(s)
    return redactable, report_only


def _short_label(label: str) -> str:
    low = label.lower()
    if low in _LABEL_MAP:
        return _LABEL_MAP[low]
    normalized = label.replace("-", " ").replace("_", " ")
    normalized_low = " ".join(normalized.lower().split())
    if normalized_low in _LABEL_MAP:
        return _LABEL_MAP[normalized_low]
    unwrapped_low = normalized_low.replace("(", "").replace(")", "")
    if unwrapped_low in _LABEL_MAP:
        return _LABEL_MAP[unwrapped_low]
    return " ".join(
        w.upper() if w.lower() in _UPPER_WORDS else w.capitalize()
        for w in normalized.split()
    )


def _proof(secret: str, label: str) -> str:
    """Safe display string for a secret: 'Type · prefix…suffix · #hash'.

    The user sees enough of the actual value to recognise whether it's
    real (their own AWS key, postgres URI, etc.) without us printing the
    whole credential. Preview length scales with secret length, and
    leading/trailing whitespace is stripped so newlines don't leak into
    the tail.
    """
    short = _short_label(label)
    h = hashlib.sha256(secret.encode()).hexdigest()[:8]

    s = secret.strip()
    n = len(s)
    if n < 8:
        return f"{short} · #{h}"

    if n >= 40:
        head, tail = 6, 4
    elif n >= 20:
        head, tail = 4, 2
    elif n >= 12:
        head, tail = 3, 1
    else:
        head, tail = 2, 1

    preview = f"{s[:head]}…{s[-tail:]}"
    # Strip any remaining control chars in the preview (rare; defensive).
    preview = "".join(c if c.isprintable() else "·" for c in preview)
    return f"{short} · {preview} · #{h}"


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
            "_secret": secret,
            "secret_hash": hashlib.sha256(secret.encode()).hexdigest(),
            "hits": text.count(secret),
        })
    return findings


# ── Parallel report-build worker ─────────────────────────────────────────────
# Using an initializer to share the secrets/type_map across worker invocations
# avoids re-pickling them N times (would be MBs of redundant data per file).
# We also write the secrets to a per-worker tempfile so each file scan can
# delegate to `grep -oFc` instead of running ~1000 Python substring searches
# in pure Python over a multi-MB session log.

import collections as _collections

_WORKER_SECRETS: set[str] | None = None
_WORKER_TYPE_MAP: dict[str, str] | None = None
_WORKER_PATTERNS_FILE: str | None = None


def _init_findings_worker(secrets: set[str], type_map: dict[str, str]) -> None:
    global _WORKER_SECRETS, _WORKER_TYPE_MAP, _WORKER_PATTERNS_FILE
    _WORKER_SECRETS = secrets
    _WORKER_TYPE_MAP = type_map
    if secrets:
        fd, path = tempfile.mkstemp(prefix="agentscrub_findings_", suffix=".txt")
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(secrets))
        _WORKER_PATTERNS_FILE = path
    else:
        _WORKER_PATTERNS_FILE = None


def _file_findings_grep(
    secrets: set[str],
    type_map: dict[str, str],
    fp: Path,
    patterns_file: str,
) -> list[dict[str, object]]:
    """Fast path: grep -oF prints every match (one per line); we count via Counter."""
    try:
        r = subprocess.run(
            ["grep", "-oF", f"--file={patterns_file}", str(fp)],
            capture_output=True, text=True, timeout=120, errors="ignore",
        )
    except (subprocess.TimeoutExpired, OSError):
        return []
    if r.returncode > 1:
        return []
    counts = _collections.Counter(
        line for line in r.stdout.splitlines() if line and line in secrets
    )
    findings: list[dict[str, object]] = []
    for secret in sorted(
        counts.keys(),
        key=lambda s: (type_map.get(s, "unknown"), hashlib.sha256(s.encode()).hexdigest()),
    ):
        label = _short_label(type_map.get(secret, "unknown"))
        findings.append({
            "type": label,
            "proof": _proof(secret, type_map.get(secret, "unknown")),
            "_secret": secret,
            "secret_hash": hashlib.sha256(secret.encode()).hexdigest(),
            "hits": counts[secret],
        })
    return findings


def file_findings_worker(fp_str: str) -> tuple[str, list[dict[str, object]]]:
    """Pool worker — returns (path_str, findings)."""
    secrets = _WORKER_SECRETS or set()
    type_map = _WORKER_TYPE_MAP or {}
    if _WORKER_PATTERNS_FILE and secrets:
        return fp_str, _file_findings_grep(secrets, type_map, Path(fp_str), _WORKER_PATTERNS_FILE)
    return fp_str, file_findings(secrets, Path(fp_str), type_map)


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


def _redact_raw_line(line: str, secrets: frozenset[str]) -> tuple[str, int]:
    new, count = line, 0
    for s in secrets:
        if s in new:
            n = new.count(s)
            new = new.replace(s, REDACTED)
            count += n
    return new, count


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
                if n == 0:
                    # Detectors scan raw JSONL. A token can be present in the
                    # encoded line as JSON escapes (for example trailing "\\n")
                    # but not match the decoded Python string byte-for-byte.
                    # Fall back to raw-line replacement so the next scan sees
                    # the file as clean.
                    new, n = _redact_raw_line(stripped, secrets)
                    total += n
                    lines_out.append(new + ("\n" if line.endswith("\n") else ""))
                    continue
                total += n
                lines_out.append(
                    json.dumps(obj, ensure_ascii=False) + ("\n" if line.endswith("\n") else "")
                )
            except json.JSONDecodeError:
                new, n = _redact_raw_line(stripped, secrets)
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
) -> tuple[int, list[tuple[Path, int, str | None]]]:
    """Redact text columns in all SQLite DBs. Returns (total, [(path, count, error)])."""
    results: list[tuple[Path, int, str | None]] = []
    for target in targets:
        seen_dbs: set[Path] = set()
        db_paths: list[Path] = []
        for pattern in _SQLITE_GLOBS:
            for p in target.path.rglob(pattern):
                if p in seen_dbs:
                    continue
                seen_dbs.add(p)
                db_paths.append(p)
        for db_path in sorted(db_paths):
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
                    results.append((db_path, db_count, None))
            except Exception as e:
                results.append((db_path, -1, str(e)))  # negative = error
    return sum(c for _, c, _ in results if c > 0), results
