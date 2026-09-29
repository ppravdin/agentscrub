"""File redaction workers and SQLite redaction. Top-level functions for multiprocessing."""
from __future__ import annotations

import atexit
import hashlib
import json
import math
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import urllib.parse
from multiprocessing import util as _mp_util
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
    ".antigravity/mcp.json",
    ".antigravity/mcp_config.json",
    ".config/Antigravity/mcp.json",
    ".config/Antigravity/mcp_config.json",
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
    (".antigravity", "mcp.json"),
    (".antigravity", "mcp_config.json"),
    (".config", "Antigravity", "mcp.json"),
    (".config", "Antigravity", "mcp_config.json"),
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
            # No size limit: large logs are scanned in chunks, not skipped.
            try:
                # Only the head is needed to sniff binary/non-UTF-8 content.
                with p.open("rb") as fh:
                    sample = fh.read(4096)
                if b"\x00" in sample:
                    continue
                sample.decode("utf-8")
            except (OSError, UnicodeDecodeError):
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
    "API Key",
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


_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
# lowercase words joined by hyphens, e.g. a host or slug like "web-3f9a2c1"
_HOSTLIKE_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+){1,4}$")
# a/b/c.py, /home/x/y.json, ~/x/y.ts — needs a file extension so that base64
# secrets containing "/" are not mistaken for paths
_PATHLIKE_RE = re.compile(r"^(?:~/|/)?(?:[\w.@+-]+/)+[\w.@+-]*\.\w{1,6}$")
# Vendor keys that are legitimately lowercase-hyphenated; never treated as hostnames.
_VENDOR_HYPHEN_PREFIXES = (
    "sk-", "pk-", "rk-", "pplx-", "xai-", "fc-", "tly-", "nvapi-", "key-", "gsk-",
)


def looks_like_identifier(value: str) -> str | None:
    """Why `value` is an ID, path or hostname rather than a credential, else None.

    Detector rules that key off context ("host", "id", "npm", "key") also fire
    on session UUIDs, git hashes, file paths and hostnames. Agent logs are full
    of them, and rewriting them corrupts the log (a Claude Code transcript links
    messages by UUID) far more than it protects. They are still reported.
    Deliberately narrow: anything with real key structure stays redactable.
    """
    v = value.strip()
    if _UUID_RE.match(v):
        return "UUID"
    if _GIT_SHA_RE.match(v):
        return "git commit hash"
    if _PATHLIKE_RE.match(v):
        return "file path"
    if len(v) <= 24 and _HOSTLIKE_RE.match(v) and not v.startswith(_VENDOR_HYPHEN_PREFIXES):
        return "hostname or slug"
    return None


def is_redactable_finding(finding: dict[str, object]) -> bool:
    """True if `run` may rewrite this finding: a high-precision label AND a
    value that does not look like an identifier."""
    if not is_high_precision_label(str(finding["type"])):
        return False
    secret = finding.get("_secret")
    return not (isinstance(secret, str) and looks_like_identifier(secret))


def partition_secrets_by_precision(
    secrets: set[str],
    type_map: dict[str, str],
) -> tuple[set[str], set[str]]:
    """Split secrets into (redactable, report_only) based on rule precision.

    Returns:
      redactable  — high-precision tokens, safe to rewrite to [REDACTED]
      report_only — everything else, including values that look like IDs,
                    paths or hostnames; reported in the audit, never written
    """
    redactable: set[str] = set()
    report_only: set[str] = set()
    for s in secrets:
        label = _short_label(type_map.get(s, "unknown"))
        if is_high_precision_label(label) and not looks_like_identifier(s):
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


_FINDINGS_BLOCK_CHARS = 8 * 1024 * 1024


def _count_secrets_streaming(secrets: set[str], fp: Path) -> dict[str, int]:
    """Occurrences of each secret in fp, reading it in bounded blocks.

    The last (longest secret - 1) characters are carried into the next block
    so secrets spanning a block boundary are counted once, not missed.
    """
    counts: dict[str, int] = {}
    keep = max((len(s) for s in secrets), default=1) - 1
    pending = ""
    with fp.open("r", errors="ignore") as fh:
        while True:
            block = fh.read(_FINDINGS_BLOCK_CHARS)
            if not block:
                break
            text = pending + block
            for s in secrets:
                n = text.count(s)
                if pending:
                    n -= pending.count(s)   # matches wholly inside the carry were counted already
                if n > 0:
                    counts[s] = counts.get(s, 0) + n
            pending = text[-keep:] if keep > 0 else ""
    return counts


def file_findings(
    secrets: set[str],
    fp: Path,
    type_map: dict[str, str] | None = None,
) -> list[dict[str, object]]:
    """Safe per-file finding details for reports."""
    type_map = type_map or {}
    try:
        counts = _count_secrets_streaming(secrets, fp)
    except Exception:
        return []

    findings: list[dict[str, object]] = []
    present = list(counts)
    for secret in sorted(present, key=lambda s: (type_map.get(s, "unknown"), hashlib.sha256(s.encode()).hexdigest())):
        label = _short_label(type_map.get(secret, "unknown"))
        findings.append({
            "type": label,
            "proof": _proof(secret, type_map.get(secret, "unknown")),
            "_secret": secret,
            "secret_hash": hashlib.sha256(secret.encode()).hexdigest(),
            "hits": counts[secret],
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
        os.chmod(path, 0o600)
        _WORKER_PATTERNS_FILE = path

        def _cleanup_patterns_file(p: str = path) -> None:
            try:
                os.unlink(p)
            except OSError:
                pass

        atexit.register(_cleanup_patterns_file)
        _mp_util.Finalize(None, _cleanup_patterns_file, exitpriority=10)
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


def _redact_raw_line(line: str, secrets: frozenset[str] | set[str]) -> tuple[str, int]:
    new, count = line, 0
    for s in secrets:
        if s in new:
            n = new.count(s)
            new = new.replace(s, REDACTED)
            count += n
    return new, count


_SHORT_TEXT_MAX_CHARS = 8192
_SHORT_TEXT_MAX_LINES = 8

# In-process hot path for tiny terminal screen updates: redact the most-used
# secret families before output streams anywhere (e.g. to the cloud dashboard).
# Patterns are HIGH-PRECISION token shapes only — distinctive vendor prefixes
# with a minimum length — so the render path stays false-positive-free. Broad
# key=value / high-entropy heuristics belong to the full scanner/report flow
# (gitleaks/trufflehog/titus) where matches can be reviewed before a write.
# Specific prefixes come before generic ones, while the generic assignment
# branch remains a fallback for values that merely resemble those prefixes.
# A period terminates ordinary vendor tokens in prose, but remains a valid
# continuation character for token formats whose grammar contains periods.
_VENDOR_TOKEN_END = r"(?![A-Za-z0-9_-])"
_VENDOR_B64_END = r"(?![A-Za-z0-9+/=-])"
_VENDOR_DOTTED_END = r"(?![A-Za-z0-9_@+/\.\-=])"
_VENDOR_ASSIGNMENT_END = r"(?=[\s;,\]}\"']|$)"
_GENERIC_ASSIGNMENT_EXCLUSION = (
    r"(?!(?:[\"']?)(?i:"
    r"github_pat_[A-Za-z0-9_]{20,}" + _VENDOR_ASSIGNMENT_END + r"|"
    r"gh[opusr]_[A-Za-z0-9_]{20,}" + _VENDOR_ASSIGNMENT_END + r"|"
    r"glpat-[A-Za-z0-9_-]{20,}" + _VENDOR_ASSIGNMENT_END + r"|"
    r"sk-proj-[A-Za-z0-9_-]{20,}" + _VENDOR_ASSIGNMENT_END + r"|"
    r"sk-ant-[A-Za-z0-9_-]{20,}" + _VENDOR_ASSIGNMENT_END + r"|"
    r"sk-[A-Za-z0-9]{32,}" + _VENDOR_ASSIGNMENT_END + r"|"
    r"(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}" + _VENDOR_ASSIGNMENT_END + r"|"
    r"AIza[0-9A-Za-z_-]{35}" + _VENDOR_ASSIGNMENT_END + r"|"
    r"GOCSPX-[A-Za-z0-9_-]{20,}" + _VENDOR_ASSIGNMENT_END + r"|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}" + _VENDOR_ASSIGNMENT_END + r"|"
    r"xapp-[0-9]-[A-Za-z0-9-]{20,}" + _VENDOR_ASSIGNMENT_END + r"|"
    r"(?:AKIA|ASIA)[A-Z0-9]{16}" + _VENDOR_ASSIGNMENT_END + r"|"
    r"npm_[A-Za-z0-9]{20,}" + _VENDOR_ASSIGNMENT_END + r"|"
    r"hf_[A-Za-z0-9]{20,}" + _VENDOR_ASSIGNMENT_END + r"|"
    r"dop_v1_[a-f0-9]{40,}" + _VENDOR_ASSIGNMENT_END + r"|"
    r"dapi[a-f0-9]{32,}" + _VENDOR_ASSIGNMENT_END + r"|"
    r"SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}" + _VENDOR_ASSIGNMENT_END + r"|"
    r"AccountKey=[A-Za-z0-9+/=]{40,}" + _VENDOR_ASSIGNMENT_END + r"))"
)
_SHORT_TEXT_SECRET_RE = re.compile(
    "|".join(
        [
            # Database / Cache connection URIs with passwords (Redis, Postgres, MySQL, MongoDB, AMQP)
            r"(?:redis|rediss|postgres|postgresql|mysql|mongodb(?:\+srv)?|amqp|amqps)://[^:\s]*:[^@\s]+@[^/\s]+",
            # redis-cli -a password pattern
            r"redis-cli\s+-a\s+(?:\"[^\"]+\"|'[^']+'|[^\s;]+)",
            # GitHub / GitLab personal access tokens
            r"github_pat_[A-Za-z0-9_]{20,}" + _VENDOR_TOKEN_END,
            r"gh[opusr]_[A-Za-z0-9_]{20,}" + _VENDOR_TOKEN_END,
            r"glpat-[A-Za-z0-9_-]{20,}" + _VENDOR_TOKEN_END,
            # OpenAI / Anthropic (project + classic) keys
            r"sk-proj-[A-Za-z0-9_-]{20,}" + _VENDOR_TOKEN_END,
            r"sk-ant-[A-Za-z0-9_-]{20,}" + _VENDOR_TOKEN_END,
            r"sk-[A-Za-z0-9]{32,}" + _VENDOR_TOKEN_END,
            # Stripe / Square style live|test keys (underscore delimiter)
            r"(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}" + _VENDOR_TOKEN_END,
            # Google API key + OAuth client secret
            r"AIza[0-9A-Za-z_-]{35}" + _VENDOR_TOKEN_END,
            r"GOCSPX-[A-Za-z0-9_-]{20,}" + _VENDOR_TOKEN_END,
            # Slack bot/app tokens + incoming webhooks
            r"xox[baprs]-[A-Za-z0-9-]{10,}" + _VENDOR_TOKEN_END,
            r"xapp-[0-9]-[A-Za-z0-9-]{20,}" + _VENDOR_TOKEN_END,
            r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}",
            # AWS access key id
            r"(?:AKIA|ASIA)[A-Z0-9]{16}" + _VENDOR_TOKEN_END,
            # npm / HuggingFace / DigitalOcean / Databricks
            r"npm_[A-Za-z0-9]{20,}" + _VENDOR_TOKEN_END,
            r"hf_[A-Za-z0-9]{20,}" + _VENDOR_TOKEN_END,
            r"dop_v1_[a-f0-9]{40,}" + _VENDOR_TOKEN_END,
            r"dapi[a-f0-9]{32,}" + _VENDOR_TOKEN_END,
            # SendGrid
            r"SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}" + _VENDOR_TOKEN_END,
            # Telegram bot token
            r"\d{8,10}:[A-Za-z0-9_-]{35}" + _VENDOR_TOKEN_END,
            # Azure Storage connection string secret
            r"AccountKey=[A-Za-z0-9+/=]{40,}" + _VENDOR_B64_END,
            # JSON Web Token
            r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}" + _VENDOR_TOKEN_END,
            # PEM private key header (flags the block; body is multiline)
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
            # Bearer HTTP header / token pattern
            r"(?:(?i:authorization):\s*)?(?i:bearer)\s+[A-Za-z0-9._~+/-]{16,}={0,2}" + _VENDOR_DOTTED_END,
            # Candidate assignment keys are normalized semantically below;
            # keeping this grammar broad covers snake_case, kebab-case, and
            # camelCase without making the regex responsible for key meaning.
            r"(?P<generic_prefix>(?<![A-Za-z0-9])"
            r"(?P<generic_key>[\"']?[A-Za-z0-9][A-Za-z0-9_-]{0,127}[\"']?)"
            r"\s*(?:=|:)\s*)"
            + _GENERIC_ASSIGNMENT_EXCLUSION
            + r"(?P<generic_value>[\"'][^\"'\r\n\s]{16,}[\"']|[^\s;,\]}]{16,})",
        ]
    )
)

_SHORT_TEXT_VENDOR_RE = re.compile(
    "|".join(
        [
            r"(?:redis|rediss|postgres|postgresql|mysql|mongodb(?:\+srv)?|amqp|amqps)://[^:\s]*:[^@\s]+@[^/\s]+",
            r"redis-cli\s+-a\s+(?:\"[^\"]+\"|'[^']+'|[^\s;]+)",
            r"github_pat_[A-Za-z0-9_]{20,}" + _VENDOR_TOKEN_END,
            r"gh[opusr]_[A-Za-z0-9_]{20,}" + _VENDOR_TOKEN_END,
            r"glpat-[A-Za-z0-9_-]{20,}" + _VENDOR_TOKEN_END,
            r"sk-proj-[A-Za-z0-9_-]{20,}" + _VENDOR_TOKEN_END,
            r"sk-ant-[A-Za-z0-9_-]{20,}" + _VENDOR_TOKEN_END,
            r"sk-[A-Za-z0-9]{32,}" + _VENDOR_TOKEN_END,
            r"(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}" + _VENDOR_TOKEN_END,
            r"AIza[0-9A-Za-z_-]{35}" + _VENDOR_TOKEN_END,
            r"GOCSPX-[A-Za-z0-9_-]{20,}" + _VENDOR_TOKEN_END,
            r"xox[baprs]-[A-Za-z0-9-]{10,}" + _VENDOR_TOKEN_END,
            r"xapp-[0-9]-[A-Za-z0-9-]{20,}" + _VENDOR_TOKEN_END,
            r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}",
            r"(?:AKIA|ASIA)[A-Z0-9]{16}" + _VENDOR_TOKEN_END,
            r"npm_[A-Za-z0-9]{20,}" + _VENDOR_TOKEN_END,
            r"hf_[A-Za-z0-9]{20,}" + _VENDOR_TOKEN_END,
            r"dop_v1_[a-f0-9]{40,}" + _VENDOR_TOKEN_END,
            r"dapi[a-f0-9]{32,}" + _VENDOR_TOKEN_END,
            r"SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}" + _VENDOR_TOKEN_END,
            r"\d{8,10}:[A-Za-z0-9_-]{35}" + _VENDOR_TOKEN_END,
            r"AccountKey=[A-Za-z0-9+/=]{40,}" + _VENDOR_B64_END,
            r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}" + _VENDOR_TOKEN_END,
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
            r"(?:(?i:authorization):\s*)?(?i:bearer)\s+[A-Za-z0-9._~+/-]{16,}={0,2}" + _VENDOR_DOTTED_END,
        ]
    )
)

_HIGH_ENTROPY_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9_@+/.-])"
    r"[A-Za-z0-9][A-Za-z0-9_@+/.-]{30,}[A-Za-z0-9]={0,2}"
    r"(?![A-Za-z0-9_@+/.-])"
)

def _looks_high_entropy(value: str) -> bool:
    """Return true for long, varied token-like strings, not normal prose."""
    if len(value) < 32:
        return False
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    if len(counts) < 12 or len(counts) / len(value) < 0.35:
        return False
    entropy = -sum(
        (count / len(value)) * math.log2(count / len(value))
        for count in counts.values()
    )
    return entropy >= 4.0


_STRONG_KEY_SEGMENTS = frozenset({
    "password", "pw", "secret", "token", "pass", "auth", "credential",
})
_KEY_QUALIFIER_SEGMENTS = frozenset({
    "access", "api", "app", "application", "aws", "client", "database", "db",
    "encryption", "github", "master", "npm", "openai", "private", "redis",
    "refresh", "secret", "session", "signing", "ssh", "stripe",
})
_KEY_METADATA_SUFFIXES = frozenset({
    ("expires",), ("expires", "at"), ("type",), ("name",),
})


def _assignment_key_segments(key: str | None) -> tuple[tuple[str, ...], bool]:
    """Normalize snake, kebab, camel, and acronym-leading key names."""
    raw_key = (key or "").strip("\"'")
    with_acronym_boundary = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", raw_key)
    with_camel_boundary = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", with_acronym_boundary)
    normalized = re.sub(r"[^a-zA-Z0-9]+", "_", with_camel_boundary).lower().strip("_")
    return tuple(segment for segment in normalized.split("_") if segment), bool(
        re.search(r"[_-]", raw_key)
    )


def _is_credential_key(key: str | None) -> bool:
    segments, has_explicit_separator = _assignment_key_segments(key)
    if not segments:
        return False
    if tuple(segments[-2:]) in _KEY_METADATA_SUFFIXES or (segments[-1],) in _KEY_METADATA_SUFFIXES:
        return False
    if "public" in segments and "key" in segments:
        return False
    if _STRONG_KEY_SEGMENTS.intersection(segments):
        return True
    if "key" not in segments:
        return False
    if len(segments) == 1 or has_explicit_separator:
        return True
    return bool(_KEY_QUALIFIER_SEGMENTS.intersection(segments[:-1]))


def _looks_like_assignment_value(value: str | None, key: str | None = None) -> bool:
    """Return true for a plausible generic assignment secret.

    Generic key assignments are intentionally conservative: unlike exact
    vendor token patterns, they must have enough length and character variety
    to avoid replacing ordinary JSON/YAML values such as ``"banana"``.
    """
    if value is None:
        return False
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    if not _is_credential_key(key):
        return False
    normalized_value = re.sub(r"[^a-z0-9]+", "", value.lower())
    if any(
        marker in normalized_value
        for marker in ("placeholder", "changeme", "notset", "dummyvalue", "examplevalue")
    ):
        return False
    if len(value) < 16 or any(char.isspace() for char in value):
        return False
    if len(set(value)) < 8:
        return False
    segments, _ = _assignment_key_segments(key)
    strong_key = bool(_STRONG_KEY_SEGMENTS.intersection(segments))
    if strong_key:
        return True
    classes = sum(
        (
            any(char.islower() for char in value),
            any(char.isupper() for char in value),
            any(char.isdigit() for char in value),
            any(not char.isalnum() for char in value),
        )
    )
    return classes >= 2


def _is_short_secret_match(match: re.Match[str]) -> bool:
    """Return whether a regex match should be replaced."""
    generic_value = match.groupdict().get("generic_value")
    if generic_value is not None:
        return _looks_like_assignment_value(generic_value, match.group("generic_key"))
    return True


def _short_secret_subn(text: str) -> tuple[str, int]:
    count = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal count
        if not _is_short_secret_match(match):
            return match.group()
        count += 1
        return REDACTED

    new = _SHORT_TEXT_SECRET_RE.sub(replace, text)
    new, vendor_count = _SHORT_TEXT_VENDOR_RE.subn(REDACTED, new)
    return new, count + vendor_count


def _high_entropy_subn(text: str) -> tuple[str, int]:
    count = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal count
        if not _looks_high_entropy(match.group()):
            return match.group()
        count += 1
        return REDACTED

    return _HIGH_ENTROPY_CANDIDATE_RE.sub(replace, text), count


def _is_short_text(text: str) -> bool:
    """Return true if text is small enough for per-screen-update redaction."""
    if len(text) > _SHORT_TEXT_MAX_CHARS:
        return False
    # str.count is faster than splitlines and lets exactly N lines through.
    return text.count("\n") < _SHORT_TEXT_MAX_LINES


def redact_short_text(
    text: str,
    secrets: frozenset[str] | set[str] | None = None,
    *,
    high_entropy: bool = False,
) -> tuple[str, int]:
    """Redact a tiny terminal/screen text update without spawning scanners.

    This is intended for a line or a handful of terminal-output lines in a hot
    render path. It does exact replacement for already-known secrets, then a
    bounded set of high-precision token regexes. Larger text returns unchanged;
    callers should send large buffers through the normal scan/redact pipeline.
    """
    if not text or not _is_short_text(text):
        return text, 0

    count = 0
    new = text
    if secrets:
        new, count = _redact_raw_line(new, secrets)

    # The input is bounded by _SHORT_TEXT_MAX_CHARS/_SHORT_TEXT_MAX_LINES, so
    # scanning it is cheap. Do not use a marker gate here: generic assignment
    # keys can have arbitrary prefixes/suffixes and high-entropy mode has no
    # known marker at all. A gate must be a sound superset of every detector.
    new, regex_count = _short_secret_subn(new)
    count += regex_count
    if high_entropy:
        new, entropy_count = _high_entropy_subn(new)
        count += entropy_count
    return new, count


def redact_short_text_prefix(
    text: str, prefix_len: int, *, high_entropy: bool = False
) -> tuple[str, int, int]:
    """Redact a safe prefix while retaining matches that cross its boundary.

    This is used by the streaming watcher when a long, newline-free input must
    be flushed. The returned consumed length can be smaller than ``prefix_len``
    when a token begins in the prefix and ends in the retained suffix.
    """
    prefix_len = max(0, min(prefix_len, len(text)))
    if not text or not prefix_len:
        return "", 0, 0

    matches = [
        match
        for match in _SHORT_TEXT_SECRET_RE.finditer(text)
        if _is_short_secret_match(match)
    ]
    matches.extend(_SHORT_TEXT_VENDOR_RE.finditer(text))
    if high_entropy:
        matches.extend(
            match for match in _HIGH_ENTROPY_CANDIDATE_RE.finditer(text)
            if _looks_high_entropy(match.group())
        )
    matches.sort(key=lambda match: (match.start(), -(match.end() - match.start())))
    non_overlapping: list[re.Match[str]] = []
    for match in matches:
        if not non_overlapping or match.start() >= non_overlapping[-1].end():
            non_overlapping.append(match)
    matches = non_overlapping
    safe_end = prefix_len
    for match in matches:
        if match.start() < prefix_len < match.end():
            safe_end = min(safe_end, match.start())

    out: list[str] = []
    cursor = 0
    count = 0
    for match in matches:
        if match.end() > safe_end:
            break
        out.append(text[cursor:match.start()])
        out.append(REDACTED)
        cursor = match.end()
        count += 1
    out.append(text[cursor:safe_end])
    return "".join(out), safe_end, count


# Lines longer than this skip the JSON parse (which costs ~10x the line in
# RAM) and are redacted as raw text in bounded blocks.
_MAX_JSON_LINE_CHARS = 8 * 1024 * 1024


def _redact_oversized_line(first: str, inp, out, secrets: frozenset[str]) -> int:
    """Raw-redact one line too large to hold whole; returns replacements made.

    `first` is the already-read start of the line; the rest is read from `inp`
    in blocks. The last (longest secret - 1) characters of each block are
    carried into the next one so a secret spanning a block boundary is still
    replaced whole.
    """
    keep = max((len(s) for s in secrets), default=1) - 1
    count = 0
    pending = ""
    piece = first
    while True:
        text = pending + piece
        done = text.endswith("\n")
        if not done:
            nxt = inp.readline(_MAX_JSON_LINE_CHARS)
            if nxt:
                piece_next = nxt
            else:
                done = True   # EOF without a trailing newline
        new, n = _redact_raw_line(text, secrets)
        count += n
        if done:
            if out:
                out.write(new)
            return count
        if keep > 0 and len(new) > keep:
            if out:
                out.write(new[:-keep])
            pending = new[-keep:]
        else:
            pending = new if keep > 0 else ""
            if keep <= 0 and out:
                out.write(new)
        piece = piece_next


def redact_file(args: tuple) -> tuple[str, int, str | None]:
    """Worker — must be top-level for multiprocessing.Pool pickling.

    Streams line-by-line so memory stays proportional to a single line,
    not the whole file.  Session JSONL files can be hundreds of MB;
    reading them entirely into RAM was the main cause of 10-15 GB RSS.
    """
    path_str, secrets, dry_run = args
    path = Path(path_str)
    suffix = path.suffix or ".tmp"
    tmp = path.with_suffix(suffix + ".agentscrub_tmp")
    try:
        original_mode = stat.S_IMODE(path.stat().st_mode)
        total = 0
        out = None
        try:
            if not dry_run:
                out = tmp.open("w", encoding="utf-8")
            with path.open("r", encoding="utf-8") as inp:
                while True:
                    line = inp.readline(_MAX_JSON_LINE_CHARS)
                    if not line:
                        break
                    if len(line) >= _MAX_JSON_LINE_CHARS and not line.endswith("\n"):
                        # One enormous line (e.g. an inlined base64 payload):
                        # stream it in blocks instead of holding it whole.
                        total += _redact_oversized_line(line, inp, out, secrets)
                        continue
                    stripped = line.rstrip("\n")
                    if not stripped.strip() or not any(s in stripped for s in secrets):
                        if out:
                            out.write(line)
                        continue
                    try:
                        obj = json.loads(stripped)
                        obj, n = _redact_obj(obj, secrets)
                        new = json.dumps(obj, ensure_ascii=False) if n else stripped
                        new, raw_n = _redact_raw_line(new, secrets)
                        total += n + raw_n
                    except json.JSONDecodeError:
                        new, n = _redact_raw_line(stripped, secrets)
                        total += n
                    if out:
                        out.write(new + ("\n" if line.endswith("\n") else ""))
        finally:
            if out:
                out.close()
        if total == 0:
            tmp.unlink(missing_ok=True)
            return path_str, 0, None
        if not dry_run:
            os.chmod(tmp, original_mode)
            shutil.move(str(tmp), str(path))
        return path_str, total, None
    except Exception as e:
        tmp.unlink(missing_ok=True)
        return path_str, 0, str(e)


_REDACT_WORKER_SECRETS: frozenset[str] | None = None


def _init_redact_worker(secrets: set[str]) -> None:
    global _REDACT_WORKER_SECRETS
    _REDACT_WORKER_SECRETS = frozenset(secrets)


def redact_file_worker(path_str: str) -> tuple[str, int, str | None]:
    """Pool worker — secrets shared via initializer, always live (not dry_run)."""
    return redact_file((path_str, _REDACT_WORKER_SECRETS, False))


def _sqlite_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _sqlite_unique_columns(con: sqlite3.Connection, table: str) -> set[str]:
    cols: set[str] = set()
    for row in con.execute(f"PRAGMA index_list({_sqlite_ident(table)})").fetchall():
        if not row[2]:
            continue
        index_name = row[1]
        for info in con.execute(f"PRAGMA index_info({_sqlite_ident(index_name)})").fetchall():
            cols.add(info[2])
    return cols


def _open_sqlite(db_path: Path, read_only: bool) -> sqlite3.Connection:
    """Open a DB; read-only when possible so a scan never touches WAL/SHM."""
    if read_only:
        try:
            uri = "file:" + urllib.parse.quote(str(db_path)) + "?mode=ro"
            con = sqlite3.connect(uri, uri=True)
            con.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchall()
            return con
        except sqlite3.Error:
            pass   # e.g. WAL DB without a -shm: fall back to a normal open
    return sqlite3.connect(str(db_path))


def _redact_one_db(db_path: Path, secrets: set[str], dry_run: bool) -> int:
    """Redact (or, if dry_run, count) secrets in one DB. Returns replacements made.

    The connection is always closed, including when an error propagates; an
    uncommitted live pass is rolled back, so a failed DB is left untouched.
    """
    con = _open_sqlite(db_path, read_only=dry_run)
    try:
        tables = con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        db_count = 0
        for (tname,) in tables:
            if tname.startswith("_sqlx"):
                continue
            table_sql = _sqlite_ident(tname)
            cols = con.execute(f"PRAGMA table_info({table_sql})").fetchall()
            protected_cols = {
                r[1] for r in cols if r[5]
            } | _sqlite_unique_columns(con, tname)
            text_cols = [
                r[1] for r in cols
                if ("text" in r[2].lower() or r[2] == "")
                and r[1] not in protected_cols
            ]
            if not text_cols:
                continue
            col_list = ", ".join(_sqlite_ident(c) for c in text_cols)
            # Keyset pagination: each batch is a fresh, fully consumed
            # query, so the UPDATEs below never run while a SELECT on
            # the same table is still open (undefined in SQLite: rows
            # can be skipped) and memory stays bounded by one batch.
            page_sql = (
                f"SELECT rowid, {col_list} FROM {table_sql}"
                " WHERE rowid > ? ORDER BY rowid LIMIT 200"
            )
            last_rowid = -(2 ** 63)
            while True:
                rows = con.execute(page_sql, (last_rowid,)).fetchall()
                if not rows:
                    break
                last_rowid = rows[-1][0]
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
                                    f"UPDATE {table_sql} SET {_sqlite_ident(text_cols[i])} = ?"
                                    " WHERE rowid = ?",
                                    (new_val, rowid),
                                )
        if not dry_run and db_count:
            con.commit()
        return db_count
    finally:
        con.close()


def redact_sqlite(
    secrets: set[str],
    targets: list[ScanTarget],
    dry_run: bool,
    only_paths: set[Path] | None = None,
    use_cache: bool = True,
    stats: dict[str, int] | None = None,
) -> tuple[int, list[tuple[Path, int, str | None]]]:
    """Redact text columns in all SQLite DBs. Returns (total, [(path, count, error)]).

    With use_cache, a DB whose on-disk state is unchanged since it was verified
    free of these secrets is skipped, and only secrets not yet verified against
    it are searched for. only_paths restricts the pass to specific DBs (used to
    redact just the DBs a preview found secrets in).

    If `stats` is given it is filled with how many databases were examined:
    "checked" (read now), "unchanged" (skipped: verified clean and untouched
    since) and "errors". Without it a caller cannot tell "no databases" from
    "databases examined, nothing found".
    """
    from . import cache as _cache

    if stats is not None:
        stats.update(checked=0, unchanged=0, errors=0)

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
            if only_paths is not None and db_path not in only_paths:
                continue
            state_before = _cache.db_state(db_path) if use_cache else None
            todo = _cache.db_unchecked_secrets(db_path, secrets) if use_cache else secrets
            if not todo:
                if stats is not None:
                    stats["unchanged"] += 1
                continue   # unchanged since verified clean for every current secret
            try:
                db_count = _redact_one_db(db_path, todo, dry_run)
            except Exception as e:
                results.append((db_path, -1, str(e)))  # negative = error
                if stats is not None:
                    stats["errors"] += 1
                continue
            if stats is not None:
                stats["checked"] += 1
            if db_count:
                results.append((db_path, db_count, None))
            if not use_cache:
                continue
            if db_count and not dry_run:
                _cache.invalidate_db(db_path)   # rewritten: verify again next time
            elif not db_count and _cache.db_state(db_path) == state_before:
                # Nothing found and nothing changed underneath us while reading.
                _cache.mark_db_checked(db_path, todo, state_before)
    return sum(c for _, c, _ in results if c > 0), results
