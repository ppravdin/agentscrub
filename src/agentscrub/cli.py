"""agentscrub — scrub secrets from AI session logs."""
from __future__ import annotations

import argparse
import concurrent.futures
import re
import sys
import time
from datetime import datetime
from multiprocessing import Pool, cpu_count
from pathlib import Path

try:
    from rich import box
    from rich.console import Console
    from rich.live import Live
    from rich.markup import escape as _rich_escape
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        MofNCompleteColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TimeElapsedColumn,
    )
    from rich.spinner import Spinner
    from rich.table import Table
    _CON = Console(highlight=False)
    RICH = True
except ImportError:
    _CON = None
    _rich_escape = str
    RICH = False

_MARKUP = re.compile(r'\[/?[^\]]*\]')
WORKERS = max(1, cpu_count() - 1)
LOG_DIR = Path.home() / ".agentscrub" / "logs"


def _pl(n: int, word: str) -> str:
    """'1 secret', '3 secrets'."""
    return f"{n:,} {word}" if n == 1 else f"{n:,} {word}s"


def _path_under(fp: Path, parent: Path) -> bool:
    try:
        fp.relative_to(parent)
        return True
    except ValueError:
        return False


def p(msg: object = "", **kw) -> None:
    if RICH:
        _CON.print(msg, **kw)
    else:
        print(_MARKUP.sub("", str(msg)), flush=True)


def _escape_markup(value: object) -> str:
    return _rich_escape(str(value))


def _bars(
    counts: list[tuple[str, int]],
    bar_width: int = 20,
    *,
    total: int | None = None,
    count_label: str = "Count",
) -> None:
    """Horizontal bar chart. If `total` is given, Share = n/total; otherwise Share = n/sum."""
    if not counts:
        return

    def _label(name: str) -> str:
        """Normalize raw detector IDs (jwt, generic-api-key) to display labels."""
        if name != name.lower() and "-" not in name and "_" not in name:
            return name  # already humanized (e.g. "HTTP Bearer Token")
        name = name.replace("-", " ").replace("_", " ")
        UPPER = {"jwt", "api", "http", "url", "oauth", "ssh", "aws", "gcp",
                 "sql", "uri", "id", "cli", "sdk", "npm", "pypi", "hmac"}
        return " ".join(w.upper() if w.lower() in UPPER else w.capitalize()
                        for w in name.split())

    denom   = total if total else sum(n for _, n in counts)
    max_n   = max(n for _, n in counts)
    display = [(_label(name), n) for name, n in counts]
    w       = max(len(name) for name, _ in display)

    if RICH:
        _CON.print(f"  [dim]{'':{w}} {count_label:>5} {'':{bar_width}} Share[/dim]")
    else:
        print(f"  {'':w} {count_label:>5} {'':bar_width} of top", flush=True)

    for name, n in display:
        filled = round(n / max_n * bar_width) if max_n else 0
        bar    = "█" * filled
        pct    = (n / denom * 100) if denom else 0
        if RICH:
            _CON.print(
                f"  [dim]{name:<{w}}[/dim] [bold]{n:>5}[/bold]"
                f" [yellow]{bar:<{bar_width}}[/yellow] [dim]{pct:.0f}%[/dim]"
            )
        else:
            print(f"  {name:<{w}} {n:>5} {bar:<{bar_width}} {pct:.0f}%", flush=True)


def _relative_label(fp: Path, targets: list[object]) -> tuple[str, str]:
    for t in targets:
        try:
            return t.display, str(fp.relative_to(t.path))
        except ValueError:
            pass
    try:
        return "Managed credentials", str(fp.relative_to(Path.home()))
    except ValueError:
        return "?", str(fp)


def _redaction_summary(
    targets: list[object],
    redactable_files: list[Path],
    findings_by_file: dict[Path, list[dict[str, object]]],
) -> dict[str, object]:
    """The numbers shown for what `run` will change, computed in one pass so
    the screen and the audit report cannot disagree.

    secrets      distinct secret values (deduplicated by hash)
    files        files that contain at least one of them
    occurrences  every place one of them appears. A secret pasted once is
                 re-sent with each later turn of an agent session, so this is
                 normally far larger than the number of secrets: it measures
                 how much text gets rewritten, not how many secrets leaked.
    """
    from .redact import is_high_precision_label, is_redactable_finding

    lookalikes: set[str] = set()
    per_target: dict[object, dict[str, object]] = {
        t: {"files": 0, "secrets": set(), "occurrences": 0} for t in targets
    }
    by_type: dict[str, set[str]] = {}
    hashes: set[str] = set()
    values: set[str] = set()
    occurrences = files = 0
    for fp in redactable_files:
        owner = next((t for t in targets if _path_under(fp, t.path)), None)
        if owner is None:
            continue
        files += 1
        per_target[owner]["files"] += 1
        for f in findings_by_file.get(fp, []):
            if not is_redactable_finding(f):
                if is_high_precision_label(str(f["type"])):
                    lookalikes.add(str(f.get("secret_hash") or f.get("proof") or ""))
                continue
            h = str(f.get("secret_hash") or f.get("proof") or "")
            n = int(f.get("hits", 0) or 0)
            per_target[owner]["occurrences"] += n
            occurrences += n
            if h:
                per_target[owner]["secrets"].add(h)
                by_type.setdefault(str(f["type"]), set()).add(h)
                hashes.add(h)
            if isinstance(f.get("_secret"), str):
                values.add(f["_secret"])
    return {
        "per_target": per_target,
        "by_type": sorted(((k, len(v)) for k, v in by_type.items()), key=lambda kv: -kv[1]),
        "secrets": len(hashes),
        "secret_values": values,
        "files": files,
        "occurrences": occurrences,
        "lookalikes": len(lookalikes - {""}),
    }


def _secrets_removed(
    done_files: list[Path],
    findings_by_file: dict[Path, list[dict[str, object]]],
) -> int:
    """Distinct secrets that are gone: every one found in a file that was
    rewritten and re-checked clean. (Not the number planned.)"""
    from .redact import is_redactable_finding

    gone: set[str] = set()
    for fp in done_files:
        for f in findings_by_file.get(fp, []):
            if is_redactable_finding(f):
                h = str(f.get("secret_hash") or f.get("proof") or "")
                if h:
                    gone.add(h)
    return len(gone)


def _append_to_report(report_path: Path | None, lines: list[str]) -> None:
    """Add the run's real outcome to the audit, which is written before any
    file changes and would otherwise still say nothing happened."""
    if report_path is None:
        return
    try:
        with report_path.open("a", encoding="utf-8") as fh:
            fh.write("\n" + "\n".join(lines) + "\n")
    except OSError:
        pass


def _write_scan_report(
    *,
    targets: list[object],
    flagged: list[Path],
    preserved: list[Path],
    findings_by_file: dict[Path, list[dict[str, object]]],
    source_file_counts: list[tuple[str, int, int, int]],
    total_scanned_files: int,
    unique_patterns: int,
    flagged_redactable_count: int = 0,
    redactable_files: set[Path] | None = None,
    secrets_to_redact: int = 0,
    files_unchanged: int = 0,
    mode: str = "scan",
) -> Path:
    from .redact import (
        is_high_precision_label,
        is_low_signal_label,
        is_redactable_finding,
    )

    to_redact = redactable_files or set()
    redactable_labels = {
        str(f["type"])
        for fp in flagged
        for f in findings_by_file.get(fp, [])
        if is_redactable_finding(f)
    }

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    created = datetime.now()
    stamp = created.strftime('%Y%m%d-%H%M%S')
    report_path = LOG_DIR / f"scan-{stamp}.txt"

    def _file_stats(fp: Path) -> tuple[int, int, int, list[dict[str, object]], list[dict[str, object]]]:
        findings = findings_by_file.get(fp, [])
        credential = [f for f in findings if not is_low_signal_label(str(f["type"]))]
        noisy = [f for f in findings if is_low_signal_label(str(f["type"]))]
        hits = sum(int(f["hits"]) for f in findings)
        credential_hits = sum(int(f["hits"]) for f in credential)
        return len(credential), credential_hits, hits, credential, noisy

    stats_by_file = {fp: _file_stats(fp) for fp in [*flagged, *preserved]}

    def _priority(files: list[Path]) -> list[Path]:
        return sorted(
            files,
            key=lambda fp: (
                -stats_by_file.get(fp, (0, 0, 0, [], []))[0],
                -stats_by_file.get(fp, (0, 0, 0, [], []))[1],
                -stats_by_file.get(fp, (0, 0, 0, [], []))[2],
                _relative_label(fp, targets)[1],
            ),
        )

    def _source_counts(files: list[Path]) -> dict[str, tuple[int, int, int]]:
        counts: dict[str, tuple[int, int, int]] = {}
        for fp in files:
            source, _ = _relative_label(fp, targets)
            credential_unique, credential_hits, _, _, _ = stats_by_file.get(fp, (0, 0, 0, [], []))
            old_files, old_unique, old_hits = counts.get(source, (0, 0, 0))
            counts[source] = (
                old_files + 1,
                old_unique + credential_unique,
                old_hits + credential_hits,
            )
        return counts

    def _pattern_counts(files: list[Path]) -> list[tuple[str, int, int]]:
        by_type: dict[str, tuple[set[Path], int]] = {}
        for fp in files:
            for finding in findings_by_file.get(fp, []):
                label = str(finding["type"])
                if is_low_signal_label(label):
                    continue
                files_seen, hits_n = by_type.get(label, (set(), 0))
                files_seen.add(fp)
                by_type[label] = (files_seen, hits_n + int(finding["hits"]))
        return sorted(
            ((label, len(files_seen), hits_n) for label, (files_seen, hits_n) in by_type.items()),
            key=lambda row: (-row[1], -row[2], row[0].lower()),
        )

    def _write_table_line(fh, left: str, middle: str, right: str = "") -> None:
        if right:
            fh.write(f"{left:<30} {middle:>12} {right}\n")
        else:
            fh.write(f"{left:<30} {middle}\n")

    def _write_findings(
        fh,
        findings: list[dict[str, object]],
        *,
        indent: str = "  ",
        limit: int | None = None,
    ) -> None:
        ordered = sorted(findings, key=lambda f: (-int(f["hits"]), str(f["type"]).lower(), str(f["proof"])))
        selected = ordered[:limit] if limit else ordered
        # Each row is column-aligned so the preview sits in its own visual
        # slot and the eye doesn't have to scan past 'proof=Type · ' noise:
        #   - <Type:20>   <hits:>6>×  <preview:24>   <#hash>
        for finding in selected:
            ftype = str(finding["type"])
            hits  = int(finding["hits"])
            proof = str(finding["proof"])
            # proof is either "Type · #hash" (short secret, no preview) or
            # "Type · preview · #hash". Strip the leading 'Type · ' since
            # we print Type in its own column already.
            after_type = proof.split(" · ", 1)[1] if " · " in proof else proof
            if " · " in after_type:
                preview, hash_part = after_type.rsplit(" · ", 1)
            else:
                preview, hash_part = "—", after_type
            note = (
                "  [looks like an ID, path or hostname: reported only]"
                if is_high_precision_label(ftype) and not is_redactable_finding(finding)
                else ""
            )
            fh.write(
                f"{indent}- {ftype:<20}  {hits:>6}×   "
                f"{preview:<24}   {hash_part}{note}\n"
            )
        if limit and len(ordered) > limit:
            fh.write(f"{indent}... {len(ordered) - limit:,} more findings in audit\n")

    def _write_file_block(
        fh,
        fp: Path,
        *,
        credential_limit: int | None = None,
        noisy_limit: int | None = None,
    ) -> None:
        source, rel = _relative_label(fp, targets)
        credential_unique, credential_hits, hits, credential, noisy = _file_stats(fp)
        fh.write(f"\n[{source}] {rel}\n")
        action = "redact" if fp in to_redact else "report_only"
        fh.write(
            f"credential_findings={credential_unique} "
            f"credential_hits={credential_hits} total_hits={hits} action={action}\n"
        )
        if credential:
            _write_findings(fh, credential, limit=credential_limit)
        if noisy:
            fh.write("  low_signal_matches:\n")
            _write_findings(fh, noisy, indent="    ", limit=noisy_limit)

    def _write_group(
        fh,
        title: str,
        files: list[Path],
        *,
        limit: int | None = None,
        credential_limit: int | None = None,
        noisy_limit: int | None = None,
        more_hint: str = "in audit",
    ) -> None:
        fh.write(f"\n{title}\n")
        fh.write("=" * len(title) + "\n")
        if not files:
            fh.write("none\n")
            return
        selected = files[:limit] if limit else files
        for fp in selected:
            _write_file_block(
                fh,
                fp,
                credential_limit=credential_limit,
                noisy_limit=noisy_limit,
            )
        if limit and len(files) > limit:
            fh.write(f"\n... {len(files) - limit:,} more files {more_hint}\n")

    ordered_flagged = _priority(flagged)
    ordered_preserved = _priority(preserved)
    preserved_with_credentials = [fp for fp in ordered_preserved if stats_by_file.get(fp, (0, 0, 0, [], []))[0]]
    preserved_low_signal_only = [fp for fp in ordered_preserved if not stats_by_file.get(fp, (0, 0, 0, [], []))[0]]
    total_hits = sum(stats_by_file.get(fp, (0, 0, 0, [], []))[2] for fp in flagged)
    source_counts = _source_counts(flagged)
    total_credential_unique = sum(unique_n for _, unique_n, _ in source_counts.values())
    total_credential_hits = sum(hits_n for _, _, hits_n in source_counts.values())
    pattern_counts = _pattern_counts(flagged)

    def _write_header(fh, title: str) -> None:
        fh.write(f"{title}\n")
        fh.write(f"created: {created.isoformat(timespec='seconds')}\n")
        fh.write("raw credentials are never printed in reports\n")
        fh.write("credential proof: detector type, optional shape marker, and safe hash; harmless non-credential matches may show verbatim\n")

    def _write_result(fh) -> None:
        other = max(0, unique_patterns - secrets_to_redact)
        fh.write("\nResult\n")
        fh.write("======\n")
        checked = f"{total_scanned_files:,}"
        if files_unchanged:
            checked += f"  ({files_unchanged:,} unchanged since the last run, not re-scanned)"
        fh.write(f"Files checked:      {checked}\n")
        fh.write(f"Files to redact:    {flagged_redactable_count:,}\n")
        if flagged_redactable_count:
            fh.write(f"Secrets to redact:  {secrets_to_redact:,}  (distinct values)\n")
        if other:
            fh.write(
                f"Other matches:      {other:,} distinct values, reported only and never modified\n"
                "                    (low-confidence rules, or found only in preserved login files)\n"
            )
        if preserved:
            fh.write(f"Live auth/MCP files skipped:  {len(preserved):,}\n")
        if mode == "scan":
            fh.write("Files changed:      0 (read-only scan)\n")
            fh.write("\nRun next\n")
            fh.write("========\n")
            fh.write(f"agentscrub run        redact {flagged_redactable_count:,} files after confirmation\n")
            fh.write("agentscrub run --yes  redact immediately, no prompt\n")
        else:
            fh.write("Files changed:      not yet: this audit is written before redaction starts;\n")
            fh.write("                    the real result is in the Outcome section at the end.\n")
        fh.write("\nWhat is protected\n")
        fh.write("=================\n")
        fh.write("- Raw credentials are not printed and there is no report mode that dumps them.\n")
        fh.write("- Proof hashes let you recognize the same secret across files without exposing it.\n")
        if preserved:
            fh.write("- Live auth/MCP credential stores are listed below but skipped by default.\n")
        fh.write("- An encrypted backup of files to be changed is created before redaction; the last 3 backups are kept.\n")

    def _write_by_tool(fh) -> None:
        if not source_file_counts:
            return
        fh.write("\nBy tool\n")
        fh.write("=======\n")
        fh.write("To redact = files run will rewrite. Reported only = files with matches that are never modified.\n")
        fh.write(f"{'Tool':<28} {'To redact':>10} {'Reported only':>14} {'Checked':>9} {'Share':>7}\n")
        fh.write(f"{'-' * 28} {'-' * 10:>10} {'-' * 14:>14} {'-' * 9:>9} {'-' * 7:>7}\n")
        for source, redact_n, match_n, checked_n in source_file_counts:
            pct = (redact_n / checked_n * 100) if checked_n else 0
            fh.write(
                f"{source:<28} {redact_n:>10,} {max(0, match_n - redact_n):>14,} "
                f"{checked_n:>9,} {pct:>6.1f}%\n"
            )

    def _write_source_rollup(fh) -> None:
        if source_counts:
            fh.write("\nAudit counts (every file with a match, including reported-only ones)\n")
            fh.write("====================================================================\n")
            fh.write("finding = one distinct credential-like pattern in one file\n")
            fh.write("occurrence = each place a pattern appears; a secret pasted once is re-sent with\n")
            fh.write("             every later turn of a session, so this is far larger than the number of secrets\n")
            fh.write(f"credential-like findings: {total_credential_unique:,}\n")
            fh.write(f"credential-like occurrences: {total_credential_hits:,}\n")
            if total_hits != total_credential_hits:
                fh.write(f"all occurrences including low-signal matches: {total_hits:,}\n")
            fh.write("\n")
            fh.write(f"{'Source':<28} {'Files':>8} {'Findings':>10} {'Occurrences':>12}\n")
            fh.write(f"{'-' * 28} {'-' * 8:>8} {'-' * 10:>10} {'-' * 12:>12}\n")
            for source, (files_n, unique_n, hits_n) in sorted(source_counts.items(), key=lambda row: (-row[1][0], row[0])):
                fh.write(f"{source:<28} {files_n:>8,} {unique_n:>10,} {hits_n:>12,}\n")

    def _write_pattern_rollup(fh) -> None:
        if pattern_counts:
            fh.write("\nTop credential-like pattern types (all matches)\n")
            fh.write("===============================================\n")
            fh.write("Only types marked 'redact' are ever rewritten; the rest are reported only.\n")
            fh.write("Even under a 'redact' type, values that look like IDs, paths or hostnames are reported only.\n")
            fh.write("Types group detector patterns; use previews and hashes to recognize the actual repeated secret.\n\n")
            fh.write(f"{'Type':<32} {'Files':>8} {'Occurrences':>12}  Action\n")
            fh.write(f"{'-' * 32} {'-' * 8:>8} {'-' * 12:>12}  ------\n")
            for label, files_n, hits_n in pattern_counts[:20]:
                act = "redact" if label in redactable_labels else "report only"
                fh.write(f"{label:<32} {files_n:>8,} {hits_n:>12,}  {act}\n")
            if len(pattern_counts) > 20:
                fh.write(f"... {len(pattern_counts) - 20:,} more pattern types in audit\n")

    def _write_preserved(fh) -> None:
        _write_group(fh, "Live auth/MCP files preserved (with credential-like findings)", preserved_with_credentials)
        _write_group(fh, "Live auth/MCP files preserved (low-signal matches only)", preserved_low_signal_only)

    with report_path.open("w", encoding="utf-8") as fh:
        _write_header(fh, "agentscrub full scan audit")
        _write_result(fh)
        _write_by_tool(fh)
        _write_source_rollup(fh)
        _write_pattern_rollup(fh)
        _write_preserved(fh)
        _write_group(fh, "Full audit: every file with a match (action= says what run does)", ordered_flagged)

    from .backup import rotate_logs
    rotate_logs()

    return report_path


# ── arg parsing ───────────────────────────────────────────────────────────────

def _parse() -> tuple[str, argparse.Namespace]:
    argv = sys.argv[1:]
    subcmd = "run"
    commands = (
        "scan", "run", "rollback", "doctor", "schedule", "update",
        "redact-text", "watch-text", "watch", "--watch", "pii-text", "pii-detect",
    )
    if argv and argv[0] in commands:
        subcmd, argv = argv[0], argv[1:]
        if subcmd in ("watch", "--watch"):
            subcmd = "watch-text"

    if subcmd in ("pii-text", "pii-detect"):
        epilog = """
PII support:
  pip install 'agentscrub[pii]'
  Rampart downloads its public Hugging Face model on first use.
        """
    elif subcmd in ("redact-text", "watch-text"):
        epilog = None
    else:
        epilog = """
commands:
  scan          find and show what's exposed — no writes
  run           redact everything (default)
  rollback      restore a previous backup
  doctor        verify detection tools
  schedule      manage the daily cron job
  update        update agentscrub to latest version
  redact-text   redact short text from stdin
  watch-text    redact streaming text from stdin
  pii-text      redact personal data from stdin
  pii-detect    list PII found in stdin

examples:
  agentscrub scan
  agentscrub run --yes
  agentscrub update
  agentscrub rollback
  agentscrub doctor
  printf 'token=...' | agentscrub redact-text
  tail -f app.log | agentscrub watch-text --alert
  agentscrub schedule install
  agentscrub --list-tools
        """

    ap = argparse.ArgumentParser(
        prog="agentscrub",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Scrub secrets and credentials from AI coding assistant session logs.",
        epilog=epilog,
    )
    ap.add_argument("--version", action="store_true",
                    help="show version and exit")
    ap.add_argument("--list-tools", action="store_true",
                    help="show all known tool IDs (use with --only) and exit")

    if subcmd in ("scan", "run"):
        ap.add_argument("--also", metavar="PATH", action="append", default=[],
                        help="extra directory to scan (auto-detected dirs always included)")
        ap.add_argument("--only", metavar="TOOL", action="append", default=[],
                        help="limit to specific tool(s); repeatable or comma-separated. "
                             "Examples: --only claude   --only claude,codex   "
                             "Run 'agentscrub --list-tools' for available names.")
        ap.add_argument("--max-backups", type=int, default=3, metavar="N",
                        help="backups to keep per tool (default: 3)")
        if subcmd == "run":
            ap.add_argument("--yes", "-y", action="store_true",
                            help="skip confirmation prompt")

    elif subcmd == "rollback":
        ap.add_argument("--list", action="store_true",
                        help="show available backups without restoring")
        ap.add_argument("--by-tool", action="store_true",
                        help="restore one tool backup instead of a full restore point")

    elif subcmd == "schedule":
        ap.add_argument("action", nargs="?",
                        choices=["install", "uninstall", "status"],
                        default="status")

    elif subcmd == "update":
        ap.add_argument("--check", action="store_true",
                        help="check for updates without upgrading")
        ap.add_argument("--yes", "-y", action="store_true",
                        help="skip confirmation prompt")

    elif subcmd == "redact-text":
        ap.add_argument("--count", action="store_true",
                        help="print the number of redactions to stderr")
        ap.add_argument("--entropy", action="store_true",
                        help="also redact long high-entropy token-like strings")

    elif subcmd == "watch-text":
        ap.add_argument("--alert", action="store_true",
                        help="print an alert to stderr whenever a chunk is redacted")
        ap.add_argument("--count", action="store_true",
                        help="print the total number of redactions to stderr at EOF")
        ap.add_argument("--exit-on-detect", action="store_true",
                        help="exit with status 2 after the first detected secret")
        ap.add_argument("--chunk-size", type=int, default=4096, metavar="N",
                        help="stdin read size in characters (default: 4096)")
        ap.add_argument("--max-buffer", type=int, default=8192, metavar="N",
                        help="maximum partial-line buffer before forced redaction (default: 8192)")
        ap.add_argument("--entropy", action="store_true",
                        help="also redact long high-entropy token-like strings")

    elif subcmd == "pii-text":
        ap.add_argument("--count", action="store_true",
                        help="print the number of redactions to stderr")

    elif subcmd == "pii-detect":
        ap.add_argument("--count", action="store_true",
                        help="print the number of findings to stderr")

    return subcmd, ap.parse_args(argv)


def _ver() -> str:
    try:
        from agentscrub import __version__
        return f"agentscrub {__version__}"
    except Exception:
        return "agentscrub"


def _splash_text() -> str | None:
    try:
        from importlib.resources import files
        return files("agentscrub").joinpath("splash.txt").read_text(encoding="utf-8")
    except Exception:
        return None


def _print_splash() -> None:
    txt = _splash_text()
    if not txt:
        return
    if RICH:
        # Render as-is; Rich preserves whitespace and U+2588 blocks.
        # Dim the fake redacted-token lines, leave the brand mark default.
        _CON.print(txt, style="dim", end="")
    else:
        print(txt, end="")




# ── doctor ────────────────────────────────────────────────────────────────────

def cmd_doctor() -> int:
    import shutil
    import subprocess

    from .secrets import GITLEAKS, TITUS, TRUFFLEHOG

    _print_splash()
    p(f"  [dim]{_ver()}[/dim]\n")

    checks = [
        ("gitleaks",   GITLEAKS,   ["version"]),
        ("TruffleHog", TRUFFLEHOG, ["--version"]),
        ("Titus",      TITUS,      ["version"]),
        ("rsync",      Path(shutil.which("rsync") or "rsync"), ["--version"]),
    ]
    p("\n[bold]Detection tools[/bold]\n")
    all_ok = True
    for name, path, args in checks:
        found = Path(path).exists() if Path(path).is_absolute() \
                else bool(shutil.which(str(path)))
        if found:
            r = subprocess.run([str(path)] + args, capture_output=True, text=True, timeout=5)
            ver = (r.stdout + r.stderr).splitlines()[0].strip()[:60]
            p(f"  [bold green]✓[/bold green]  {name:<14} [dim]{ver}[/dim]")
        else:
            p(f"  [bold red]✗[/bold red]  {name:<14} [red]not found[/red]")
            all_ok = False

    p()
    if all_ok:
        p("[bold green]All tools installed.[/bold green]\n")
    else:
        p("[yellow]Missing tools.[/yellow]  Run [bold]agentscrub scan[/bold] and agentscrub will offer to install them.\n")
    return 0 if all_ok else 1


def _install_missing_detectors(missing: list[str], *, assume_yes: bool = False) -> None:
    if not missing:
        return

    from .installers import BIN_DIR, install_detectors

    keys = {
        "gitleaks": "gitleaks",
        "TruffleHog": "trufflehog",
        "Titus": "titus",
    }
    install_keys = [keys[name] for name in missing if name in keys]
    if not install_keys:
        return

    p(f"\n[bold cyan]Installing detectors[/bold cyan]  [dim]{', '.join(missing)}[/dim]")
    p(f"[dim]Install official release binaries to {BIN_DIR}?[/dim]")

    if not assume_yes:
        if not sys.stdin.isatty():
            p("[red]Cannot ask for confirmation in a non-interactive shell.[/red]\n")
            return
        try:
            ans = input("Continue? [Y/n] ").strip().lower()
        except EOFError:
            ans = "n"
        if ans not in ("", "y", "yes"):
            p("[dim]Skipped detector install. Coverage will be reduced.[/dim]\n")
            return

    p()
    failures = 0
    for key, path, err in install_detectors(install_keys):
        label = {"gitleaks": "gitleaks", "trufflehog": "TruffleHog", "titus": "Titus"}[key]
        if err:
            failures += 1
            p(f"  [bold red]✗[/bold red]  {label:<14} [red]{err}[/red]")
        else:
            p(f"  [bold green]✓[/bold green]  {label:<14} [dim]{path}[/dim]")
    if failures:
        p(f"\n[yellow]{len(install_keys) - failures}/{len(install_keys)} detector(s) installed. Coverage will be reduced.[/yellow]")
    else:
        p("\n[bold green]Detectors installed.[/bold green]")
    p()


# ── schedule ──────────────────────────────────────────────────────────────────

def cmd_schedule(action: str) -> int:
    from . import schedule
    if action == "status":
        line = schedule.status()
        if line:
            p(f"\n[bold green]✓[/bold green]  Cron job installed:\n  [dim]{line}[/dim]\n")
        else:
            p("\n[yellow]No cron job installed.[/yellow]")
            p("  Run: [bold]agentscrub schedule install[/bold]\n")

    elif action == "install":
        try:
            line = schedule.install()
            p(f"\n[bold green]✓[/bold green]  Installed:\n  [dim]{line}[/dim]\n")
        except ValueError as e:
            p(f"\n[yellow]{e}[/yellow]\n")
            return 1
        except RuntimeError as e:
            p(f"\n[red]{e}[/red]\n")
            return 1

    elif action == "uninstall":
        removed = schedule.uninstall()
        if removed:
            p("\n[bold green]✓[/bold green]  Cron job removed.\n")
        else:
            p("\n[yellow]No cron job found.[/yellow]\n")
    else:
        p(f"\n[red]Unknown schedule action: {action}[/red]\n")
        return 1
    return 0


def _lossless_stdio() -> None:
    """Pass undecodable bytes through unchanged instead of aborting.

    A single stray byte (binary junk, a truncated multibyte char, a log in
    another encoding) used to kill the whole redaction run.
    """
    for stream in (sys.stdin, sys.stdout):
        try:
            stream.reconfigure(errors="surrogateescape")
        except (AttributeError, ValueError):
            pass   # not a real text stream (e.g. replaced in tests)


def _stdin_chunks(chunk_size: int):
    """Yield stdin text as soon as any of it is available.

    TextIOWrapper.read(n) blocks until n characters have arrived, so a quiet
    `tail -f` produced no output until 4096 characters piled up. read1 returns
    whatever is there; an incremental decoder keeps a multibyte character that
    straddles two reads intact.
    """
    import codecs

    raw = getattr(sys.stdin, "buffer", None)
    if raw is None or not hasattr(raw, "read1"):
        while True:
            piece = sys.stdin.read(chunk_size)
            if not piece:
                return
            yield piece
    decoder = codecs.getincrementaldecoder("utf-8")(errors="surrogateescape")
    while True:
        data = raw.read1(chunk_size)
        if not data:
            tail = decoder.decode(b"", final=True)
            if tail:
                yield tail
            return
        text = decoder.decode(data)
        if text:
            yield text


def cmd_redact_text(ns: argparse.Namespace) -> None:
    from .redact import redact_short_text

    _lossless_stdio()
    text = sys.stdin.read()
    redacted, count = redact_short_text(text, high_entropy=getattr(ns, "entropy", False))
    sys.stdout.write(redacted)
    if getattr(ns, "count", False):
        print(count, file=sys.stderr)


def cmd_pii_text(ns: argparse.Namespace) -> int:
    try:
        from .pii_rampart import redact_pii
    except Exception as e:
        p(f"[red]PII dependencies not installed: {e}[/red]")
        pip_hint = _escape_markup("pip install 'agentscrub[pii]'")
        p(f"[dim]Install PII support with:[/dim] {pip_hint}")
        p("[dim]For pipx:[/dim] pipx inject agentscrub onnxruntime transformers huggingface-hub numpy")
        p("[dim]Rampart downloads its public Hugging Face model on first use and caches it locally.[/dim]")
        return 1

    text = sys.stdin.read()
    result = redact_pii(text)
    sys.stdout.write(result.text)
    if getattr(ns, "count", False):
        print(len(result.spans), file=sys.stderr)
    return 0 if not result.spans else 2


def cmd_pii_detect(ns: argparse.Namespace) -> int:
    try:
        from .pii_rampart import detect_pii
    except Exception as e:
        p(f"[red]PII dependencies not installed: {e}[/red]")
        pip_hint = _escape_markup("pip install 'agentscrub[pii]'")
        p(f"[dim]Install PII support with:[/dim] {pip_hint}")
        p("[dim]For pipx:[/dim] pipx inject agentscrub onnxruntime transformers huggingface-hub numpy")
        p("[dim]Rampart downloads its public Hugging Face model on first use and caches it locally.[/dim]")
        return 1

    text = sys.stdin.read()
    spans = detect_pii(text)
    import hashlib
    for span in spans:
        proof = hashlib.sha256(span.text.encode()).hexdigest()[:8]
        p(f"{span.label:<20} {span.start:>6}:{span.end:<6} #{proof}")
    if getattr(ns, "count", False):
        print(len(spans), file=sys.stderr)
    return 0 if not spans else 2


def cmd_watch_text(ns: argparse.Namespace) -> int:
    from .redact import redact_short_text, redact_short_text_prefix

    _lossless_stdio()
    chunk_size = max(1, int(getattr(ns, "chunk_size", 4096)))
    max_buffer = max(1, min(int(getattr(ns, "max_buffer", 8192)), 8192))
    overlap = min(256, max_buffer)
    flush_threshold = max_buffer + overlap
    total = 0
    pending = ""

    def emit(piece: str, prefix_len: int | None = None) -> tuple[bool, int]:
        nonlocal total
        if not piece:
            return False, 0
        if prefix_len is None:
            redacted, count = redact_short_text(
                piece, high_entropy=getattr(ns, "entropy", False)
            )
            consumed = len(piece)
        else:
            redacted, consumed, count = redact_short_text_prefix(
                piece,
                prefix_len,
                high_entropy=getattr(ns, "entropy", False),
            )
        sys.stdout.write(redacted)
        sys.stdout.flush()
        if not count:
            return False, consumed
        total += count
        if getattr(ns, "alert", False):
            print(f"agentscrub: redacted {count} secret(s)", file=sys.stderr, flush=True)
        return True, consumed

    for chunk in _stdin_chunks(chunk_size):
        pending += chunk
        while pending:
            newline_at = pending.find("\n")
            if newline_at >= 0:
                piece = pending[:newline_at + 1]
                pending = pending[newline_at + 1:]
                detected, _ = emit(piece)
            elif len(pending) >= flush_threshold:
                piece = pending[:flush_threshold]
                detected, consumed = emit(piece, max_buffer)
                if not consumed:
                    break
                pending = pending[consumed:]
            else:
                break
            if detected and getattr(ns, "exit_on_detect", False):
                return 2

    if pending:
        detected, _ = emit(pending, len(pending))
    else:
        detected = False
    if detected and getattr(ns, "exit_on_detect", False):
        return 2
    if getattr(ns, "count", False):
        print(total, file=sys.stderr)
    return 0


# ── rollback ──────────────────────────────────────────────────────────────────

def cmd_rollback(ns: argparse.Namespace) -> int:
    from .backup import list_backups, list_restore_points, rollback
    from .discover import discover

    targets = discover()
    if not targets:
        p("[red]No AI tool directories found.[/red]\n"); return 1

    if getattr(ns, "by_tool", False):
        backups = list_backups(targets)
        if not backups:
            p("[yellow]No backups in ~/.agentscrub/backups/ yet.[/yellow]\n"); return 1

        p("\n[bold]Available tool backups[/bold]\n")
        for i, b in enumerate(backups, 1):
            p(f"  [bold]{i:2d}[/bold]  {b.display:<22} "
              f"{b.created.strftime('%Y-%m-%d %H:%M')}  "
              f"[dim]({b.age_str})  {b.size_str}[/dim]")
        p()

        if ns.list:
            return 0

        try:
            raw = input("Restore tool backup # (or q to quit): ").strip()
        except EOFError:
            return 1
        if not raw.isdigit() or raw.lower() == "q":
            p("[dim]Aborted.[/dim]\n"); return 1
        idx = int(raw) - 1
        if not (0 <= idx < len(backups)):
            p("[red]Invalid selection.[/red]\n"); return 1

        chosen = backups[idx]
        p(f"\n[yellow]Restoring {chosen.path} → {chosen.source} …[/yellow]")
        ok, stderr = rollback(chosen)
        if ok:
            p("[bold green]✓[/bold green]  Rollback complete.\n")
            if stderr:
                p(f"[dim]  rsync notes:\n{stderr}[/dim]\n")
        else:
            p("[bold red]✗[/bold red]  rsync failed:\n")
            if stderr:
                p(f"[red]{stderr}[/red]\n")
            p("[dim]Check manually with the path above.[/dim]\n")
        return 0 if ok else 1

    points = list_restore_points(targets)
    if not points:
        p("[yellow]No backups in ~/.agentscrub/backups/ yet.[/yellow]\n"); return 1

    p("\n[bold]Available restore points[/bold]\n")
    for i, point in enumerate(points, 1):
        tools = ", ".join(point.displays[:4])
        if len(point.displays) > 4:
            tools += f", +{len(point.displays) - 4} more"
        p(f"  [bold]{i:2d}[/bold]  {point.created.strftime('%Y-%m-%d %H:%M')}  "
          f"{len(point.backups):>2} tools  "
          f"[dim]({point.age_str})  {point.size_str}[/dim]")
        p(f"      [dim]{tools}[/dim]")
    p()

    if ns.list:
        return 0

    try:
        raw = input("Restore point # (or q to quit): ").strip()
    except EOFError:
        return 1
    if not raw.isdigit() or raw.lower() == "q":
        p("[dim]Aborted.[/dim]\n"); return 1
    idx = int(raw) - 1
    if not (0 <= idx < len(points)):
        p("[red]Invalid selection.[/red]\n"); return 1

    chosen = points[idx]
    p(f"\n[yellow]Restoring {chosen.created.strftime('%Y-%m-%d %H:%M')} "
      f"restore point ({len(chosen.backups)} tools) …[/yellow]")
    failed = 0
    for b in chosen.backups:
        ok, stderr = rollback(b)
        if ok:
            p(f"  [green]✓[/green]  {b.display:<22} [dim]{b.source}[/dim]")
        else:
            failed += 1
            p(f"  [red]✗[/red]  {b.display:<22} [red]{stderr or 'restore failed'}[/red]")
        if stderr:
            p(f"[dim]  rsync notes:\n{stderr}[/dim]\n")

    if failed:
        p(f"\n[bold red]✗[/bold red]  Rollback completed with {failed} failed tool(s).\n")
    else:
        p("\n[bold green]✓[/bold green]  Rollback complete.\n")
    return 1 if failed else 0


# ── scan & run ────────────────────────────────────────────────────────────────

def cmd_scan_or_run(subcmd: str, ns: argparse.Namespace) -> int | None:
    from .backup import backup
    from .discover import discover
    from .redact import (
        _init_redact_worker,
        collect_files,
        collect_managed_credential_files,
        grep_filter,
        is_managed_credential_file,
        is_redactable_finding,
        partition_secrets_by_precision,
        redact_file_worker,
        redact_sqlite,
        top_exposed,
    )

    dry_run      = subcmd == "scan"
    skip_confirm = getattr(ns, "yes", False)
    extra        = [Path(x).expanduser() for x in getattr(ns, "also", [])]
    only_raw     = getattr(ns, "only", []) or []
    max_backups  = getattr(ns, "max_backups", 3)

    _print_splash()

    only_set: set[str] = set()
    for x in only_raw:
        only_set.update(t.strip().lower() for t in x.split(",") if t.strip())
    if only_set:
        from .discover import _REGISTRY
        valid = {e["tool"] for e in _REGISTRY} | {"custom"}
        bad = only_set - valid
        if bad:
            p(f"[red]Unknown tool ID(s): {', '.join(sorted(bad))}[/red]")
            p("[dim]Run 'agentscrub --list-tools' to see available names.[/dim]\n")
            return 1

    targets = discover(extra)
    if only_set:
        # Keep --also custom paths through the filter — user explicitly added them.
        targets = [t for t in targets if t.tool in only_set or t.tool == "custom"]
    if not targets:
        if only_set:
            p(f"[red]No matching tool directories found for --only {','.join(sorted(only_set))}[/red]")
            p("[dim]Run 'agentscrub --list-tools' to see what's installed.[/dim]\n")
        else:
            p("[red]No AI tool directories found on this machine.[/red]")
            p("[dim]Use --also <path> to specify a directory manually.[/dim]\n")
        return 1

    # Refuse to claim "clean" when no detectors exist — that would be silent failure.
    from .secrets import tools_status
    _status   = tools_status()
    available = [name for name, _, ok in _status if ok]
    missing   = [name for name, _, ok in _status if not ok]
    if missing:
        _install_missing_detectors(missing, assume_yes=bool(getattr(ns, "yes", False)))
        _status   = tools_status()
        available = [name for name, _, ok in _status if ok]
        missing   = [name for name, _, ok in _status if not ok]
    if not available:
        p("\n[bold red]No detection tools installed.[/bold red]")
        p("[dim]agentscrub needs at least one of gitleaks, TruffleHog, or Titus.[/dim]")
        return 1
    if missing:
        p(f"\n[yellow]Only {len(available)}/3 detectors installed "
          f"(missing: {', '.join(missing)}). Coverage will be reduced.[/yellow]")

    # ── header ────────────────────────────────────────────────────────────────
    mode = ("[bold yellow] SCAN READ-ONLY [/bold yellow]" if dry_run
            else "[bold green] LIVE [/bold green]")
    n_tools = len(targets)
    tool_word = "directory" if n_tools == 1 else "directories"
    if RICH:
        g = Table.grid(padding=(0, 2))
        g.add_column(style="dim")
        g.add_column()
        from . import __version__ as _ver_str
        g.add_row("", f"[bold]agentscrub[/bold]  {mode}  [dim]v{_ver_str}[/dim]")
        g.add_row("", f"[dim]{n_tools} agent {tool_word}  ·  {WORKERS} workers[/dim]")
        _CON.print(Panel(g, box=box.ROUNDED, padding=(0, 1), expand=False))
    else:
        print(f"\n=== agentscrub {'[SCAN]' if dry_run else '[LIVE]'} ===", flush=True)
        print(f"  {n_tools} agent {tool_word}, {WORKERS} workers", flush=True)

    all_scan_paths = [t.path for t in targets]

    # Pre-compute file count per target so Phase 1 can show "Files" instead
    # of an internal detector counter. Same data is reused in Phase 2 to
    # build the redactable-files set, so this isn't extra work — just moved
    # earlier.
    _phase1_scanned_files = collect_files(targets)
    _files_per_target_pre = {t: 0 for t in targets}
    for fp in _phase1_scanned_files:
        for t in targets:
            try: fp.relative_to(t.path); _files_per_target_pre[t] += 1; break
            except ValueError: pass

    # ── incremental cache: skip files unchanged since last clean scan ─────────
    from .cache import invalidate as _cache_invalidate
    from .cache import mark_clean, plan_scan
    _plan = plan_scan(_phase1_scanned_files)
    _needs_scan, _n_cached = _plan.needs_scan, _plan.n_skipped
    _n_resumed = len(_plan.offsets)   # grown logs: only the appended tail is scanned
    if not _needs_scan:
        n_total = len(_phase1_scanned_files)
        p(f"\n[bold green]Nothing new: all {n_total:,} files are unchanged since the last check.[/bold green]\n")
        return
    _needs_scan_set = set(_needs_scan)
    # Targets whose files are all cached can skip the expensive detector calls.
    _cached_targets: set = {
        t for t in targets
        if not any(fp in _needs_scan_set for fp in _phase1_scanned_files
                   if _path_under(fp, t.path))
    }
    # Per-target: how many files are actually being scanned vs cached
    _scan_per_target = {
        t: sum(1 for fp in _needs_scan if _path_under(fp, t.path))
        for t in targets
    }

    # ── phase 1: detect credentials ───────────────────────────────────────────
    _p1_cache = (f"  [dim]{_n_cached:,} cached · {len(_needs_scan):,} to scan"
                 + (f" ({_n_resumed:,} appended-only)" if _n_resumed else "")
                 + "[/dim]"
                 if _n_cached else "")
    p(f"\n[bold cyan]Phase 1[/bold cyan]  [bold]Checking agent directories[/bold]{_p1_cache}")
    t1 = time.perf_counter()

    if RICH:
        import threading as _threading

        from .secrets import _gitleaks, _run_on_files, _titus, _trufflehog
        _DETECTORS = ("gitleaks", "trufflehog", "titus")
        _fns       = {"gitleaks": _gitleaks, "trufflehog": _trufflehog, "titus": _titus}
        _sp        = Spinner("dots", style="yellow")
        _t_lock      = _threading.Lock()
        _t_done_n    = {t.path: 0 for t in targets}     # 0..3
        _t_started   = {t.path: time.perf_counter() for t in targets}
        _t_finished  = {t.path: 0.0 for t in targets}
        by_tool: dict[str, dict] = {t: {} for t in _DETECTORS}

        _has_any_cached = _n_cached > 0

        class _Phase1Live:
            def __rich_console__(self, console, options):
                tbl = Table(box=None, show_header=True, padding=(0, 2),
                            header_style="bold cyan")
                tbl.add_column("",          min_width=3)
                tbl.add_column("Tool",      min_width=20)
                tbl.add_column("To Scan",   justify="right")
                if _has_any_cached:
                    tbl.add_column("Cached", justify="right", style="dim")
                tbl.add_column("Done at",   style="dim")
                for t in targets:
                    scan_n  = _scan_per_target[t]
                    total_n = _files_per_target_pre[t]
                    scan_str = "—" if t in _cached_targets else f"{scan_n:,}"
                    cached_str = f"{total_n - scan_n:,}"
                    done_n = _t_done_n[t.path]
                    if done_n >= len(_DETECTORS):
                        elapsed = _t_finished[t.path] - _t_started[t.path]
                        row = ["[bold green]✓[/bold green]", t.display,
                               scan_str]
                        if _has_any_cached:
                            row.append(cached_str)
                        row.append(f"{elapsed:.0f}s")
                        tbl.add_row(*row)
                    else:
                        elapsed = time.perf_counter() - _t_started[t.path]
                        row = [_sp, t.display, scan_str]
                        if _has_any_cached:
                            row.append(cached_str)
                        row.append(f"{elapsed:.0f}s")
                        tbl.add_row(*row)
                yield tbl

        def _run_one(detector_name: str, fn) -> dict[str, str]:
            out: dict[str, str] = {}
            for target in targets:
                if target not in _cached_targets:
                    uncached_here = [fp for fp in _needs_scan
                                     if _path_under(fp, target.path)]
                    result = _run_on_files(uncached_here, fn, offsets=_plan.offsets)
                    out.update(result)
                with _t_lock:
                    _t_done_n[target.path] += 1
                    if _t_done_n[target.path] == len(_DETECTORS):
                        _t_finished[target.path] = time.perf_counter()
            return out

        with concurrent.futures.ThreadPoolExecutor() as ex:
            futs = {ex.submit(_run_one, name, fn): name for name, fn in _fns.items()}
            with Live(_Phase1Live(), console=_CON, refresh_per_second=4):
                for fut in concurrent.futures.as_completed(futs):
                    by_tool[futs[fut]] = fut.result()

        all_secrets = {s for sdict in by_tool.values()
                       for s in sdict if len(s) >= 8 and not s.isspace()}
        counts = {t: len(d) for t, d in by_tool.items()}

        from .secrets import all_typed as _all_typed_fn
        _all_typed   = _all_typed_fn(by_tool)
    else:
        import concurrent.futures as _cf

        from .secrets import _gitleaks, _titus, _trufflehog
        from .secrets import _run_on_files as _rof
        active_targets = [t for t in targets if t not in _cached_targets]
        _all_uncached = [fp for t in active_targets
                         for fp in _needs_scan if _path_under(fp, t.path)]
        _by_tool_plain: dict[str, dict[str, str]] = {
            "gitleaks": {}, "trufflehog": {}, "titus": {},
        }
        with _cf.ThreadPoolExecutor() as _ex:
            _futs2 = [
                ("gitleaks",   _ex.submit(_rof, _all_uncached, _gitleaks, _plan.offsets)),
                ("trufflehog", _ex.submit(_rof, _all_uncached, _trufflehog, _plan.offsets)),
                ("titus",      _ex.submit(_rof, _all_uncached, _titus, _plan.offsets)),
            ]
            for _tool, _fut in _futs2:
                _by_tool_plain[_tool].update(_fut.result())
        all_secrets = {s for d in _by_tool_plain.values()
                       for s in d if len(s) >= 8 and not s.isspace()}
        counts = {t: len(d) for t, d in _by_tool_plain.items()}
        from .secrets import all_typed as _all_typed_fn
        _all_typed: dict[str, str] = _all_typed_fn(_by_tool_plain)
        if _n_cached:
            print(f"  {_n_cached:,} cached · {len(_needs_scan):,} to scan", flush=True)
        for tool, n in counts.items():
            print(f"  detector {tool:<12} {n:,}", flush=True)
        print(f"  {'total unique':<12} {len(all_secrets):,}", flush=True)
        print(f"  {time.perf_counter()-t1:.1f}s", flush=True)

    if not all_secrets:
        mark_clean(_needs_scan, _plan)
        p("\n[bold green]Clean — no credential patterns found.[/bold green]\n")
        return

    # ── phase 2: scan files ───────────────────────────────────────────────────
    p("\n[bold cyan]Phase 2[/bold cyan]  [bold]Mapping findings to affected files[/bold]")
    t2 = time.perf_counter()

    managed = collect_managed_credential_files()
    if only_set:
        # collect_managed_credential_files() returns auth files for every tool
        # (e.g. ~/.codex/auth.json, ~/.gemini/oauth_creds.json). With --only,
        # keep only those that live under one of the chosen targets, plus a
        # small allowlist of well-known home-root files paired to their tool.
        target_paths = [t.path.resolve() for t in targets]
        _HOME_ROOT_OWNERS = {
            ".claude.json": "claude",
            ".aider.conf.yml": "aider",
        }
        home = Path.home()

        def _is_associated(p: Path) -> bool:
            rp = p.resolve()
            for tp in target_paths:
                try:
                    rp.relative_to(tp)
                    return True
                except ValueError:
                    continue
            try:
                rel = p.relative_to(home).as_posix()
            except ValueError:
                return False
            return _HOME_ROOT_OWNERS.get(rel) in only_set

        managed = [p for p in managed if _is_associated(p)]

    scanned_files = sorted(set(_phase1_scanned_files + managed))

    # Grep only files that aren't cached-clean; managed auth files always scanned.
    _managed_set = set(managed)
    _grep_files = [
        fp for fp in scanned_files
        if fp in _needs_scan_set or fp in _managed_set
    ]
    _grep_n = len(_grep_files)
    _skip_msg = (f"[dim]scanning {_grep_n:,} files"
                 + (f"  ·  {_n_cached:,} cached[/dim]" if _n_cached else "[/dim]"))
    if RICH:
        with Progress(
            TextColumn("  "),
            SpinnerColumn(style="yellow"),
            TextColumn(_skip_msg),
            console=_CON, transient=True,
        ) as prog:
            prog.add_task("grep", total=None)
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                flagged_all = ex.submit(grep_filter, all_secrets, _grep_files).result()
    else:
        flagged_all = grep_filter(all_secrets, _grep_files)

    elapsed2 = time.perf_counter() - t2
    preserved = [fp for fp in flagged_all if is_managed_credential_file(fp)]
    flagged = [fp for fp in flagged_all if not is_managed_credential_file(fp)]
    redactable_files = [fp for fp in scanned_files if not is_managed_credential_file(fp)]
    # ── per-target breakdown ──────────────────────────────────────────────────
    files_per_target   = {t: 0 for t in targets}
    flagged_per_target = {t: 0 for t in targets}
    for fp in redactable_files:
        for t in targets:
            try: fp.relative_to(t.path); files_per_target[t] += 1; break
            except ValueError: pass
    for fp in flagged:
        for t in targets:
            try: fp.relative_to(t.path); flagged_per_target[t] += 1; break
            except ValueError: pass

    # Mark newly confirmed clean files in the cache (grep found no secrets).
    _flagged_set = set(flagged_all)
    _clean_now = [fp for fp in _needs_scan if fp not in _flagged_set]
    mark_clean(_clean_now, _plan)

    # ── Phase 2 timing only — the actionable per-tool table needs the
    # precision partition and runs after the report is built. ────────────────
    _cached_suffix = f"  ·  {_n_cached:,} cached" if _n_cached else ""
    if RICH:
        _CON.print(f"  [dim]done in {elapsed2:.1f}s{_cached_suffix}[/dim]")
    else:
        print(f"  done in {elapsed2:.1f}s{_cached_suffix}", flush=True)

    # Preserved live auth/MCP files are not announced on stdout — the
    # exclude_dirs / exclude_files lists silently skip plenty of paths to
    # protect user data, and singling out this one bucket inconsistently
    # makes the run noisier without adding info. The audit report
    # still has dedicated sections listing every preserved file and its
    # matches.

    findings_by_file: dict[Path, list[dict[str, object]]] = {}
    full_report_path: Path | None = None
    if flagged or preserved:
        from .redact import _init_findings_worker, file_findings_worker

        # Sort largest-first so the longest-running files start at t=0 and the
        # tail of the queue is small files. Otherwise the bar reaches
        # near-complete fast and then sits for tens of seconds while one
        # worker grinds through a 6+ MB session JSONL while 14 others idle.
        # chunksize=1 also matters: with chunksize=8, a worker grabs 8 files
        # at once and other workers can't steal a giant file from its batch.
        report_files = [*flagged, *preserved]
        def _size(fp: Path) -> int:
            try:
                return fp.stat().st_size
            except OSError:
                return 0
        report_files.sort(key=_size, reverse=True)
        report_paths = [str(fp) for fp in report_files]

        def _build_findings_parallel(progress_cb=None) -> dict[Path, list]:
            out: dict[Path, list] = {}
            with Pool(
                WORKERS,
                initializer=_init_findings_worker,
                initargs=(all_secrets, _all_typed),
            ) as pool:
                for fp_str, findings in pool.imap_unordered(
                    file_findings_worker, report_paths, chunksize=1
                ):
                    out[Path(fp_str)] = findings
                    if progress_cb:
                        progress_cb()
            return out

        if RICH:
            with Progress(
                TextColumn("  "),
                SpinnerColumn(style="yellow"),
                TextColumn("[dim]building report[/dim]"),
                BarColumn(),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                console=_CON,
                transient=True,
            ) as prog:
                task = prog.add_task("report", total=len(report_paths))
                findings_by_file = _build_findings_parallel(
                    progress_cb=lambda: prog.advance(task)
                )
        else:
            print(f"  building report ({len(report_paths):,} files)...", flush=True)
            findings_by_file = _build_findings_parallel()

        # ── precision split (before report write, since _write_scan_report
        # uses the count) ─────────────────────────────────────────────────────
        # Loose detector rules (Generic Secret, Postgres URI, Sourcegraph,
        # Bearer Token, URL Credential, Privacy, etc.) false-fire on plugin
        # slugs, beta-flag identifiers, code samples, and JSON dumps. Rewriting
        # those corrupts user data far worse than missing a real secret. Only
        # labels in _HIGH_PRECISION_LABELS get redacted; everything else is
        # reported here and in the audit but never modified.
        redactable_secrets, _ = partition_secrets_by_precision(
            all_secrets, _all_typed
        )
        flagged_redactable: list[Path] = []
        flagged_lowconf_only: list[Path] = []
        for fp in flagged:
            f_list = findings_by_file.get(fp, [])
            if any(is_redactable_finding(f) for f in f_list):
                flagged_redactable.append(fp)
            else:
                flagged_lowconf_only.append(fp)

        # Low-confidence-only files are never modified by `run`, so their
        # result cannot change until the file does. Recording them as
        # processed stops every later run from re-scanning them with all
        # three detectors (they were the bulk of the "still to scan" set).
        mark_clean(flagged_lowconf_only, _plan)

        summary = _redaction_summary(targets, flagged_redactable, findings_by_file)
        full_report_path = _write_scan_report(
            targets=targets,
            flagged=flagged,
            preserved=preserved,
            findings_by_file=findings_by_file,
            source_file_counts=[
                (
                    t.display,
                    summary["per_target"][t]["files"],
                    flagged_per_target[t],
                    files_per_target[t],
                )
                for t in targets
            ],
            total_scanned_files=len(redactable_files),
            unique_patterns=len(all_secrets),
            flagged_redactable_count=len(flagged_redactable),
            redactable_files=set(flagged_redactable),
            secrets_to_redact=summary["secrets"],
            files_unchanged=_n_cached,
            mode="scan" if dry_run else "run",
        )

        # Per-target breakdown, from the same summary the audit uses:
        # Files and Secrets lead; Occurrences (every place a secret appears,
        # inflated by sessions re-sending context) is secondary.
        redact_per_target = {t: summary["per_target"][t]["files"] for t in targets}
        secrets_per_target = {t: summary["per_target"][t]["secrets"] for t in targets}
        times_per_target = {t: summary["per_target"][t]["occurrences"] for t in targets}
        actionable_redactable_secrets: set[str] = summary["secret_values"]
        total_hits_redactable = summary["occurrences"]
        type_counts_redactable = summary["by_type"][:6]
        n_secrets = summary["secrets"]
        # One secret can appear in several tools, so per-tool secret counts can
        # add up to more than the unique total. Say so instead of leaving a
        # column that does not sum.
        per_tool_sum = sum(len(v) for v in secrets_per_target.values())

        if RICH:
            _CON.print()
            tbl = Table(box=None, show_header=True, padding=(0, 2),
                        header_style="bold cyan")
            tbl.add_column("Tool",    style="dim", min_width=20)
            tbl.add_column("Files",   justify="right", style="bold yellow")
            tbl.add_column("Secrets", justify="right", style="bold cyan")
            tbl.add_column("Occurrences", justify="right", style="dim")
            for t in targets:
                tbl.add_row(
                    t.display,
                    f"{redact_per_target[t]:,}",
                    f"{len(secrets_per_target[t]):,}",
                    f"{times_per_target[t]:,}",
                )
            tbl.add_row(
                "[bold]Total (unique)[/bold]",
                f"[bold]{len(flagged_redactable):,}[/bold]",
                f"[bold]{n_secrets:,}[/bold]",
                f"{total_hits_redactable:,}",
            )
            _CON.print(tbl)
            if per_tool_sum > n_secrets:
                _CON.print(
                    "  [dim]* Secrets are counted per tool; the same secret can appear "
                    "in several tools, so the column can add up to more than the total.[/dim]"
                )
            if summary["lookalikes"]:
                _CON.print(
                    f"  [dim]{_pl(summary['lookalikes'], 'more value')} matched a secret pattern but "
                    "look like IDs, hostnames or paths (e.g. session UUIDs): reported, never modified.[/dim]"
                )
            _CON.print(
                "  [dim]Occurrences = every place a secret appears. A secret pasted once is "
                "re-sent with each later turn of a session, so this is far larger than the "
                "number of secrets.[/dim]"
            )

            if type_counts_redactable:
                _CON.print()
                _bars(type_counts_redactable,
                      total=n_secrets,
                      count_label="Secrets")
                _CON.print(
                    "  [dim]* Share of distinct secrets by kind. Kinds group detector patterns; "
                    "previews identify the repeated values.[/dim]"
                )
        else:
            for t in targets:
                print(
                    f"  {t.display:<22}  "
                    f"{redact_per_target[t]:>6,} files  "
                    f"{len(secrets_per_target[t]):>6,} secrets  "
                    f"{times_per_target[t]:>6,} occurrences",
                    flush=True,
                )
            print(
                f"  {'Total (unique)':<22}  {len(flagged_redactable):>6,} files  "
                f"{n_secrets:>6,} secrets  {total_hits_redactable:>6,} occurrences",
                flush=True,
            )
            if per_tool_sum > n_secrets:
                print(
                    "  * Secrets are counted per tool; the same secret can appear in "
                    "several tools, so the column can add up to more than the total.",
                    flush=True,
                )
            if summary["lookalikes"]:
                print(
                    f"  {_pl(summary['lookalikes'], 'more value')} matched a secret pattern but look like "
                    "IDs, hostnames or paths: reported, never modified.",
                    flush=True,
                )
            if type_counts_redactable:
                _bars(type_counts_redactable, total=n_secrets, count_label="Secrets")
                print(
                    "  * Share of distinct secrets by kind.",
                    flush=True,
                )

        p(f"\n[bold cyan]Audit[/bold cyan]  [dim]{full_report_path}[/dim]")
    else:
        # No findings at all — nothing to partition; still set defaults
        # so the rest of the function compiles without unbound names.
        redactable_secrets = set()
        flagged_redactable, flagged_lowconf_only = [], []
        actionable_redactable_secrets = set()
        total_hits_redactable = 0

    if not flagged:
        if preserved:
            p("\n[bold green]No redactable files contain credential patterns.[/bold green]\n")
        else:
            p("\n[bold green]Clean — no files contain credential patterns.[/bold green]\n")
        return

    # ── most exposed REDACTABLE files only ────────────────────────────────────
    # Showing files dominated by loose-rule matches here is what made the
    # output contradictory: top-5 listed files we wouldn't actually touch.
    # Build a findings_by_file restricted to high-precision rows, then rank
    # only the files we'll redact.
    findings_redactable_only: dict[Path, list[dict[str, object]]] = {
        fp: [f for f in findings if is_redactable_finding(f)]
        for fp, findings in findings_by_file.items()
    }
    if RICH:
        with Progress(
            TextColumn("  "),
            SpinnerColumn(style="yellow"),
            TextColumn("[dim]ranking files by unique findings…[/dim]"),
            console=_CON,
            transient=True,
        ) as prog:
            prog.add_task("ranking", total=None)
            exposed = top_exposed(redactable_secrets, flagged_redactable, n=5,
                                  type_map=_all_typed,
                                  findings_by_file=findings_redactable_only)
    else:
        print("  ranking files by unique findings...", flush=True)
        exposed = top_exposed(redactable_secrets, flagged_redactable, n=5,
                              type_map=_all_typed,
                              findings_by_file=findings_redactable_only)
    if exposed:
        def _resolve(fp: Path) -> tuple[str, str]:
            for t in targets:
                try:
                    return t.display, str(fp.relative_to(t.path))
                except ValueError:
                    pass
            return "?", str(fp)

        # When all exposed files come from a single tool, name it in the
        # title rather than repeating it as a Source column on every row.
        unique_sources_in_title = {_resolve(fp)[0] for fp, *_ in exposed}
        if len(unique_sources_in_title) == 1:
            only_tool = next(iter(unique_sources_in_title))
            p(f"\n[bold cyan]Top files to redact[/bold cyan]  [dim]·  {only_tool}  ·  e.g. = its most repeated secret[/dim]\n")
        else:
            p("\n[bold cyan]Top files to redact[/bold cyan]  [dim]· e.g. = its most repeated secret[/dim]\n")

        def _trunc_path(s: str, n: int = 48) -> str:
            if len(s) <= n:
                return s

            parts = s.split("/")
            if len(parts) > 1:
                head = parts[0]
                tail = parts[-1]
                fixed = len(head) + len(tail) + 3  # "…/"
                if fixed <= n:
                    return f"{head}/…/{tail}"
                tail_budget = max(12, n - len(head) - 3)
                return f"{head}/…/{tail[-tail_budget:]}"

            keep = max(8, n - 1)
            return "…" + s[-keep:]

        # Parse the glued 'Type · preview · #hash' string into 3 separate
        # columns so each piece sits in its own visual lane.
        def _split_proof(proof: str) -> tuple[str, str, str]:
            parts = proof.split(" · ")
            if len(parts) >= 3:
                return parts[0], " · ".join(parts[1:-1]), parts[-1]
            if len(parts) == 2:
                return parts[0], "—", parts[1]
            return proof, "—", ""

        # Hide the Source column when every exposed file comes from the same
        # tool — repeating "Claude Code" 5 times is just noise.
        unique_sources = {_resolve(fp)[0] for fp, *_ in exposed}
        show_source = len(unique_sources) > 1

        # Adaptive layout: wide-table on >=110 col terminals; 2-line compact
        # 'card' layout on narrower terminals so nothing gets ellipsis-truncated.
        wide_layout = RICH and _CON.width >= 110

        if wide_layout:
            tbl = Table(
                box=box.HORIZONTALS,
                show_header=True,
                header_style="bold cyan",
                padding=(0, 1),
                pad_edge=False,
            )
            if show_source:
                tbl.add_column("Source",   style="dim",                       width=14, no_wrap=True)
            tbl.add_column("File",                                             min_width=32, max_width=56, overflow="ellipsis", no_wrap=True)
            tbl.add_column("Secrets",  justify="right", style="bold yellow",  width=8,  no_wrap=True)
            tbl.add_column("e.g. kind", style="cyan",                         width=14, no_wrap=True)
            tbl.add_column("e.g. preview", style="bold green",                width=20, no_wrap=True)
            for fp, uniq, hits, proof in exposed:
                tool_name, rel = _resolve(fp)
                kind, preview, _h = _split_proof(proof)
                row = []
                if show_source:
                    row.append(tool_name)
                row.extend([
                    _escape_markup(_trunc_path(rel)),
                    str(uniq),
                    _escape_markup(kind),
                    _escape_markup(preview),
                ])
                tbl.add_row(*row)
            _CON.print(tbl)
        elif RICH:
            # Compact 2-line card per file. Line 1 = file path + tool. Line 2 =
            # secrets count, kind, preview, all on one line with bullet
            # separators and color so the eye lands on the key bits.
            for i, (fp, uniq, hits, proof) in enumerate(exposed):
                tool_name, rel = _resolve(fp)
                kind, preview, _h = _split_proof(proof)
                path_w = _CON.width - 4
                _CON.print(
                    f"  [white]{_escape_markup(_trunc_path(rel, path_w))}[/white]"
                    + (f"  [dim]{_escape_markup(tool_name)}[/dim]" if show_source else ""),
                    markup=True,
                )
                _CON.print(
                    f"    [bold yellow]{uniq:>3}[/bold yellow][dim] {'secret' if uniq == 1 else 'secrets'} · e.g. [/dim]"
                    f"[cyan]{_escape_markup(kind)}[/cyan] "
                    f"[dim]·[/dim] [bold green]{_escape_markup(preview)}[/bold green]"
                )
                if i < len(exposed) - 1:
                    _CON.print()  # blank line between cards
        else:
            for fp, uniq, hits, proof in exposed:
                tool_name, rel = _resolve(fp)
                kind, preview, _h = _split_proof(proof)
                src = f"[{tool_name}]  " if show_source else ""
                print(f"  {_trunc_path(rel, 60)}{src}", flush=True)
                print(f"    {uniq:>3} {'secret' if uniq == 1 else 'secrets'} · e.g. {kind} · {preview}", flush=True)

    if dry_run:
        p(f"\n[bold yellow]Scan complete — no files modified.[/bold yellow]\n")
        if RICH:
            _CON.print("[bold]Next steps[/bold]")
            g = Table.grid(padding=(0, 2))
            g.add_column()
            g.add_column()
            g.add_row("  agentscrub run",
                      f"redact {_pl(len(actionable_redactable_secrets), 'secret')} in {_pl(len(flagged_redactable), 'file')} after confirmation")
            g.add_row("",
                      f"[dim]backup created first, last {max_backups} kept[/dim]")
            g.add_row("  agentscrub run --yes",
                      "[dim]redact immediately, no prompt[/dim]")
            _CON.print(g)
        else:
            print(f"\nNext steps:", flush=True)
            print(f"  agentscrub run        redact {_pl(len(actionable_redactable_secrets), 'secret')} in {_pl(len(flagged_redactable), 'file')} after confirmation", flush=True)
            print(f"                        backup created first, last {max_backups} kept", flush=True)
            print( "  agentscrub run --yes  redact without confirmation", flush=True)
        p()
        return

    # ── early-exit: nothing high-precision to redact ──────────────────────────
    if not flagged_redactable:
        if flagged_lowconf_only:
            p(f"\n[bold green]Nothing to redact.[/bold green]  "
              f"[dim]{len(flagged_lowconf_only):,} files have only "
              f"low-confidence patterns; reported in the audit, "
              f"not rewritten.[/dim]\n")
        else:
            p("\n[bold green]Clean — no files contain credential patterns.[/bold green]\n")
        return

    # ── confirm ───────────────────────────────────────────────────────────────
    if not skip_confirm:
        p(f"\n[bold yellow]About to redact {_pl(len(actionable_redactable_secrets), 'secret')} "
          f"across {_pl(len(flagged_redactable), 'file')}.[/bold yellow]")
        p("[dim]An encrypted backup of changed files will be created first "
          f"(keeping last {max_backups}).[/dim]")
        try:
            ans = input("Continue? [y/N] ").strip().lower()
        except EOFError:
            ans = "n"
        if ans != "y":
            _append_to_report(full_report_path, [
                "Outcome", "=======",
                "Aborted at the confirmation prompt: nothing was changed.",
            ])
            p("[dim]Aborted.[/dim]\n"); return

    t_total = time.perf_counter()

    # ── backup + log rotation ─────────────────────────────────────────────────
    from .backup import rotate_logs
    rotate_logs()
    p("\n[bold cyan]Backup[/bold cyan]")

    db_stats: dict[str, int] = {}

    def _db_label(path: Path, n: int, total: int) -> str:
        try:
            gb = path.stat().st_size / 1e9
        except OSError:
            gb = 0.0
        return f"({n}/{total}) {path.name}  {gb:.1f} GB"

    # Reading every database can take minutes and used to print nothing.
    t_db = time.perf_counter()
    if RICH:
        with Progress(
            TextColumn("  "),
            SpinnerColumn(style="yellow"),
            TextColumn("[dim]checking databases {task.description}[/dim]"),
            TimeElapsedColumn(),
            console=_CON,
            transient=True,
        ) as _db_prog:
            _db_task = _db_prog.add_task("", total=None)
            _sqlite_preview_total, sqlite_preview_results = redact_sqlite(
                redactable_secrets, targets, dry_run=True, stats=db_stats,
                progress=lambda path, n, total: _db_prog.update(
                    _db_task, description=_db_label(path, n, total)
                ),
            )
    else:
        def _plain_db_progress(path: Path, n: int, total: int) -> None:
            try:
                big = path.stat().st_size > 100_000_000
            except OSError:
                big = False
            if big:
                print(f"  checking database {_db_label(path, n, total)} ...", flush=True)

        _sqlite_preview_total, sqlite_preview_results = redact_sqlite(
            redactable_secrets, targets, dry_run=True, stats=db_stats,
            progress=_plain_db_progress,
        )
    _n_db = db_stats.get("checked", 0) + db_stats.get("unchanged", 0)
    if _n_db:
        p(f"  [dim]{_pl(_n_db, 'database')} checked in {time.perf_counter() - t_db:.0f}s[/dim]")
    sqlite_backup_files: list[Path] = []
    for db_path, count, _err in sqlite_preview_results:
        if count <= 0:
            continue
        sqlite_backup_files.append(db_path)
        for sidecar in (Path(str(db_path) + "-wal"), Path(str(db_path) + "-shm")):
            if sidecar.is_file():
                sqlite_backup_files.append(sidecar)
    backup_files = [*flagged_redactable, *sqlite_backup_files]

    try:
        if RICH:
            with Progress(
                TextColumn("  "),
                SpinnerColumn(style="yellow"),
                TextColumn(f"[dim]encrypting backup of {_pl(len(backup_files), 'file')}[/dim]"),
                TimeElapsedColumn(),
                console=_CON,
                transient=True,
            ) as _bk_prog:
                _bk_prog.add_task("", total=None)
                backups = backup(targets, max_keep=max_backups, files=backup_files)
        else:
            print(f"  encrypting backup of {_pl(len(backup_files), 'file')} ...", flush=True)
            backups = backup(targets, max_keep=max_backups, files=backup_files)
    except Exception as e:
        p(f"  [red]Backup failed; no files were modified:[/red] {e}")
        _append_to_report(full_report_path, [
            "Outcome", "=======", f"Backup failed, so no files were modified: {e}",
        ])
        return 1
    for b in backups:
        p(f"  [green]✓[/green]  {b.display:<22} [dim]encrypted · {b.path}[/dim]")

    # ── phase 3: redact text ──────────────────────────────────────────────────
    # Only rewrite files containing high-precision tokens; loose-rule matches
    # ride along in the audit report but stay untouched.
    p(f"\n[bold cyan]Phase 3[/bold cyan]  [bold]Redacting {_pl(len(actionable_redactable_secrets), 'secret')} "
      f"in {_pl(len(flagged_redactable), 'file')}[/bold]  "
      f"[dim]({WORKERS} workers)[/dim]")
    t3 = time.perf_counter()
    redact_paths = [str(fp) for fp in flagged_redactable]
    total_redactions = 0
    total_redacted_files = 0
    errors: list[str] = []

    def _label(s: str) -> str:
        for sp in all_scan_paths:
            try: return str(Path(s).relative_to(sp))
            except ValueError: pass
        return s

    if RICH:
        with Progress(
            TextColumn("  [progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=_CON,
        ) as prog:
            task = prog.add_task("redacting", total=len(flagged_redactable))
            with Pool(WORKERS, initializer=_init_redact_worker,
                       initargs=(actionable_redactable_secrets,)) as pool:
                for path_str, count, err in pool.imap_unordered(
                    redact_file_worker, redact_paths
                ):
                    prog.advance(task)
                    if err:
                        errors.append(path_str)
                        prog.console.print(
                            f"  [red]WARN[/red]  {_label(path_str)}: {err}")
                    elif count:
                        total_redactions += count
                        total_redacted_files += 1
                        prog.console.print(
                            f"  [bold green] OK [/bold green]  "
                            f"{_label(path_str)}  [dim]→[/dim]  {count:,} replaced")
    else:
        with Pool(WORKERS, initializer=_init_redact_worker,
                   initargs=(actionable_redactable_secrets,)) as pool:
            for path_str, count, err in pool.imap_unordered(
                redact_file_worker, redact_paths
            ):
                if err:
                    errors.append(path_str)
                    print(f"  WARN  {_label(path_str)}: {err}", flush=True)
                elif count:
                    total_redactions += count
                    total_redacted_files += 1
                    print(f"   OK   {_label(path_str)} → {count} replaced", flush=True)

    p(f"  [dim]{time.perf_counter()-t3:.1f}s[/dim]")

    # Invalidate redacted files from cache — mtime changes anyway, but be explicit.
    _cache_invalidate(flagged_redactable)

    # Verify the files we just rewrote. If anything remains, call it a failed
    # cleanup plainly; the final scan result matters more than write counts.
    still_exposed = grep_filter(actionable_redactable_secrets, flagged_redactable)
    if still_exposed:
        p(
            f"  [red]WARN[/red]  {len(still_exposed):,} redacted file(s) still contain "
            "detected secrets after cleanup"
        )
        p("        [dim]Run agentscrub again; keep the audit if this repeats.[/dim]")
        for fp in still_exposed[:5]:
            p(f"        [dim]{_label(str(fp))}[/dim]")

    # ── phase 4: database history (SQLite/vscdb files) ───────────────────────
    # Phase 4 cleans embedded session/log databases (e.g. ~/.codex/logs_2.sqlite,
    # Cursor's state.vscdb). Users don't think 'SQLite' — they think 'history'.
    p("\n[bold cyan]Phase 4[/bold cyan]  [bold]Cleaning database history[/bold]")
    # Only the databases the preview found secrets in (or failed on) need a live pass.
    sqlite_total, sqlite_results = redact_sqlite(
        redactable_secrets, targets, dry_run=False,
        only_paths={db for db, cnt, _e in sqlite_preview_results if cnt != 0},
    )
    if not sqlite_results:
        n_seen = db_stats.get("checked", 0) + db_stats.get("unchanged", 0)
        if not n_seen:
            p("  [dim]no databases found[/dim]")
        else:
            unchanged = db_stats.get("unchanged", 0)
            p(f"  [dim]{n_seen:,} database(s) examined: no secrets found"
              + (f" ({unchanged:,} unchanged since the last check)" if unchanged else "")
              + "[/dim]")
    sqlite_errors = 0
    for db_path, count, err in sqlite_results:
        label = str(db_path)
        # Find which tool owns this DB so the line reads "Codex CLI · logs_2.sqlite"
        owning = None
        for t in targets:
            try:
                db_path.relative_to(t.path)
                owning = t.display
                label = str(db_path.relative_to(t.path))
                break
            except ValueError:
                continue
        prefix = f"[dim]{owning} ·[/dim] " if owning else ""
        if count < 0:
            sqlite_errors += 1
            p(f"  [red]WARN[/red]  {prefix}{label}: {err or 'error'}")
        else:
            p(f"  [bold green] OK [/bold green]  {prefix}{label}  [dim]→[/dim]  {count:,} replaced")

    # ── summary ───────────────────────────────────────────────────────────────
    elapsed = time.perf_counter() - t_total
    # Real numbers: secrets count only when their files were rewritten and
    # re-checked clean; replacements are what was actually made, not the plan.
    _bad = {str(x) for x in errors} | {str(x) for x in still_exposed}
    n_removed = _secrets_removed(
        [fp for fp in flagged_redactable if str(fp) not in _bad], findings_by_file
    )
    n_planned = len(actionable_redactable_secrets)
    _of = f"  [dim](of {n_planned:,} found)[/dim]" if n_removed < n_planned else ""
    n_db_changed = sum(1 for _d, c, _e in sqlite_results if c > 0)
    _append_to_report(full_report_path, [
        "Outcome", "=======",
        f"Files changed:       {total_redacted_files:,}",
        f"Secrets removed:     {n_removed:,} of {n_planned:,} found (distinct values)",
        f"Replacements made:   {total_redactions:,} in files, {sqlite_total:,} in databases",
        f"Errors:              {len(errors):,} file(s), {sqlite_errors:,} database(s)",
        f"Still contain secrets after cleanup: {len(still_exposed):,} file(s)",
    ])
    if RICH:
        g = Table.grid(padding=(0, 3))
        g.add_column(justify="right", style="bold green")
        g.add_column()
        g.add_row(f"[bold green]✓ Done[/bold green]", f"[dim]redaction took {elapsed:.0f}s[/dim]")
        g.add_row("", "")
        g.add_row(f"[bold green]{n_removed:,}[/bold green]",
                  f"{'secret' if n_removed == 1 else 'secrets'} removed from [bold]{_pl(total_redacted_files, 'file')}[/bold]  "
                  f"[dim]({total_redactions:,} replacements)[/dim]{_of}")
        if sqlite_total:
            g.add_row(f"[bold green]{sqlite_total:,}[/bold green]",
                      f"replacements in database history [dim]({n_db_changed:,} database(s))[/dim]")
        g.add_row("",
                  f"[dim]encrypted backup made first; last {max_backups} kept per tool "
                  f"(~/.agentscrub/backups/)[/dim]")
        if errors:
            g.add_row(f"[red]{len(errors)}[/red]",
                      "[red]files with errors (see above)[/red]")
        if still_exposed:
            g.add_row(f"[red]{len(still_exposed)}[/red]",
                      "[red]files still contain secrets after cleanup[/red]")
        _CON.print(Panel(g, box=box.ROUNDED, padding=(0, 2),
                          border_style="green", expand=False, title="[bold green]Scrub complete[/bold green]"))
    else:
        print(f"\n✓ Done (redaction took {elapsed:.0f}s)", flush=True)
        print(f"  {_pl(n_removed, 'secret')} removed from {_pl(total_redacted_files, 'file')} ({total_redactions:,} replacements)"
              + (f", of {n_planned:,} found" if n_removed < n_planned else ""), flush=True)
        if sqlite_total:
            print(f"  {sqlite_total:,} replacements in database history ({n_db_changed:,} database(s))", flush=True)
        print(f"  encrypted backup made first; last {max_backups} kept per tool (~/.agentscrub/backups/)", flush=True)
        if errors:
            print(f"  {len(errors)} errors", flush=True)
        if still_exposed:
            print(f"  {len(still_exposed)} files still contain secrets after cleanup", flush=True)
        print(flush=True)

    if errors or still_exposed or sqlite_errors:
        return 1
    return 0


# ── entry point ───────────────────────────────────────────────────────────────

def main() -> int:
    try:
        subcmd, ns = _parse()
        if getattr(ns, "version", False):
            _print_splash()
            print(_ver())
            return 0
        if getattr(ns, "list_tools", False):
            cmd_list_tools()
            return 0
        if subcmd == "doctor":
            return cmd_doctor()
        elif subcmd == "schedule":
            return cmd_schedule(getattr(ns, "action", "status"))
        elif subcmd == "rollback":
            return cmd_rollback(ns)
        elif subcmd == "update":
            from .updater import run_update
            return run_update(check_only=getattr(ns, "check", False), yes=getattr(ns, "yes", False))
        elif subcmd == "redact-text":
            cmd_redact_text(ns)
        elif subcmd == "watch-text":
            return cmd_watch_text(ns)
        elif subcmd == "pii-text":
            return cmd_pii_text(ns)
        elif subcmd == "pii-detect":
            return cmd_pii_detect(ns)
        else:
            result = cmd_scan_or_run(subcmd, ns)
            return result if isinstance(result, int) else 0
    except KeyboardInterrupt:
        p("\n[yellow]Aborted.[/yellow]")
        return 130
    except Exception as e:
        p(f"\n[red]Operation failed:[/red] {e}")
        return 1
    return 0


def cmd_list_tools() -> None:
    from .discover import _REGISTRY, discover
    targets = {t.tool: t.path for t in discover()}
    print("Tool IDs (use with --only):", flush=True)
    for spec in _REGISTRY:
        tool = spec["tool"]
        display = spec["display"]
        present = "✓" if tool in targets else " "
        loc = f" -> {targets[tool]}" if tool in targets else ""
        print(f"  {present} {tool:18}  {display}{loc}", flush=True)
    print("\n✓ = directory exists on this machine", flush=True)


if __name__ == "__main__":
    sys.exit(main())
