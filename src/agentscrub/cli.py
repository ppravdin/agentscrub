"""agentscrub — scrub secrets from AI session logs."""
from __future__ import annotations
import argparse
import concurrent.futures
from datetime import datetime
import re
import sys
import time
from multiprocessing import Pool, cpu_count
from pathlib import Path

try:
    from rich.console import Console
    from rich.live import Live
    from rich.spinner import Spinner
    from rich.progress import (
        Progress, BarColumn, MofNCompleteColumn, TimeElapsedColumn,
        TextColumn, SpinnerColumn,
    )
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    _CON = Console(highlight=False)
    RICH = True
except ImportError:
    _CON = None
    RICH = False

_MARKUP = re.compile(r'\[/?[^\]]*\]')
WORKERS = max(1, cpu_count() - 1)
LOG_DIR = Path.home() / ".agentscrub" / "logs"


def p(msg: object = "", **kw) -> None:
    if RICH:
        _CON.print(msg, **kw)
    else:
        print(_MARKUP.sub("", str(msg)), flush=True)


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


def _write_scan_report(
    *,
    targets: list[object],
    flagged: list[Path],
    preserved: list[Path],
    findings_by_file: dict[Path, list[dict[str, object]]],
    source_file_counts: list[tuple[str, int, int]],
    total_scanned_files: int,
    unique_patterns: int,
    flagged_redactable_count: int = 0,
) -> Path:
    from .redact import is_low_signal_label

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    created = datetime.now()
    stamp = created.strftime('%Y%m%d-%H%M%S')
    full_path = LOG_DIR / f"scan-{stamp}-full.txt"

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
            fh.write(
                f"{indent}- {ftype:<20}  {hits:>6}×   "
                f"{preview:<24}   {hash_part}\n"
            )
        if limit and len(ordered) > limit:
            fh.write(f"{indent}... {len(ordered) - limit:,} more findings in full audit\n")

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
        fh.write(
            f"credential_findings={credential_unique} "
            f"credential_hits={credential_hits} total_hits={hits}\n"
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
        more_hint: str = "in full audit",
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
        pct = (len(flagged) / total_scanned_files * 100) if total_scanned_files else 0
        fh.write("\nResult\n")
        fh.write("======\n")
        fh.write(f"Files to redact:              {len(flagged):,} / {total_scanned_files:,} ({pct:.1f}%)\n")
        fh.write(f"Secret-like patterns found:   {unique_patterns:,}\n")
        fh.write(f"Live auth/MCP files skipped:  {len(preserved):,}\n")
        fh.write("Files changed by this scan:   0 (read-only)\n")
        fh.write("\nRun next\n")
        fh.write("========\n")
        fh.write(f"agentscrub run        redact {flagged_redactable_count:,} files after confirmation\n")
        fh.write("agentscrub run --yes  redact immediately, no prompt\n")
        fh.write("\nWhat is protected\n")
        fh.write("=================\n")
        fh.write("- Raw credentials are not printed and there is no report mode that dumps them.\n")
        fh.write("- Proof hashes let you recognize the same secret across files without exposing it.\n")
        if preserved:
            fh.write("- Live auth/MCP credential stores are listed below but skipped by default.\n")
        fh.write("- A backup is created before redaction; the last 5 backups are kept.\n")

    def _write_by_tool(fh) -> None:
        if not source_file_counts:
            return
        fh.write("\nBy tool\n")
        fh.write("=======\n")
        fh.write(f"{'Tool':<28} {'Files to redact':>16} {'Scanned':>10} {'Share':>8}\n")
        fh.write(f"{'-' * 28} {'-' * 16:>16} {'-' * 10:>10} {'-' * 8:>8}\n")
        for source, affected, scanned in source_file_counts:
            pct = (affected / scanned * 100) if scanned else 0
            fh.write(f"{source:<28} {affected:>16,} {scanned:>10,} {pct:>7.1f}%\n")

    def _write_source_rollup(fh) -> None:
        if source_counts:
            fh.write("\nAudit counts\n")
            fh.write("============\n")
            fh.write("finding = one file containing one distinct credential-like pattern\n")
            fh.write("hit = total occurrences of those patterns in files\n")
            fh.write(f"credential-like findings across redactable files: {total_credential_unique:,}\n")
            fh.write(f"credential-like hits across redactable files: {total_credential_hits:,}\n")
            if total_hits != total_credential_hits:
                fh.write(f"all detector hits including low-signal matches: {total_hits:,}\n")
            fh.write("\n")
            fh.write(f"{'Source':<28} {'Files':>8} {'Findings':>10} {'Hits':>10}\n")
            fh.write(f"{'-' * 28} {'-' * 8:>8} {'-' * 10:>10} {'-' * 10:>10}\n")
            for source, (files_n, unique_n, hits_n) in sorted(source_counts.items(), key=lambda row: (-row[1][0], row[0])):
                fh.write(f"{source:<28} {files_n:>8,} {unique_n:>10,} {hits_n:>10,}\n")

    def _write_pattern_rollup(fh) -> None:
        if pattern_counts:
            fh.write("\nTop credential-like pattern types\n")
            fh.write("=================================\n")
            fh.write(f"{'Type':<32} {'Files':>8} {'Hits':>10}\n")
            fh.write(f"{'-' * 32} {'-' * 8:>8} {'-' * 10:>10}\n")
            for label, files_n, hits_n in pattern_counts[:20]:
                fh.write(f"{label:<32} {files_n:>8,} {hits_n:>10,}\n")
            if len(pattern_counts) > 20:
                fh.write(f"... {len(pattern_counts) - 20:,} more pattern types in full audit\n")

    def _write_preserved(fh) -> None:
        _write_group(fh, "Live auth/MCP files preserved (with credential-like findings)", preserved_with_credentials)
        _write_group(fh, "Live auth/MCP files preserved (low-signal matches only)", preserved_low_signal_only)

    with full_path.open("w", encoding="utf-8") as fh:
        _write_header(fh, "agentscrub full scan audit")
        _write_result(fh)
        _write_by_tool(fh)
        _write_source_rollup(fh)
        _write_pattern_rollup(fh)
        _write_preserved(fh)
        _write_group(fh, "Full redactable file audit", ordered_flagged)

    return full_path


# ── arg parsing ───────────────────────────────────────────────────────────────

def _parse() -> tuple[str, argparse.Namespace]:
    argv = sys.argv[1:]
    subcmd = "run"
    commands = ("scan", "run", "rollback", "doctor", "schedule")
    if argv and argv[0] in commands:
        subcmd, argv = argv[0], argv[1:]

    ap = argparse.ArgumentParser(
        prog="agentscrub",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Scrub secrets and credentials from AI coding assistant session logs.",
        epilog="""
commands:
  scan              find & show what's exposed — no writes
  run               redact everything (default)
  rollback          restore a previous backup
  doctor            verify detection tools are installed
  schedule          manage the daily cron job

examples:
  agentscrub scan                      see what's exposed before touching anything
  agentscrub run                       redact (asks for confirmation)
  agentscrub run --yes                 redact without prompt — for cron / CI
  agentscrub rollback                  pick a backup to restore
  agentscrub doctor                    check gitleaks / TruffleHog / Titus
  agentscrub schedule install          add daily 3am cron job
  agentscrub schedule uninstall        remove cron job
  agentscrub schedule status           show current cron entry
  agentscrub run --also ~/my-ai-tool   scan an extra directory
  agentscrub run --only claude         redact only Claude Code session logs
  agentscrub scan --only claude,codex  preview a two-tool scan
  agentscrub --list-tools              list every known tool ID
        """,
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
        ap.add_argument("--max-backups", type=int, default=5, metavar="N",
                        help="backups to keep per tool (default: 5)")
        if subcmd == "run":
            ap.add_argument("--yes", "-y", action="store_true",
                            help="skip confirmation prompt")

    elif subcmd == "rollback":
        ap.add_argument("--list", action="store_true",
                        help="show available backups without restoring")

    elif subcmd == "schedule":
        ap.add_argument("action", nargs="?",
                        choices=["install", "uninstall", "status"],
                        default="status")

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

def cmd_doctor() -> None:
    import shutil, subprocess
    from .secrets import GITLEAKS, TRUFFLEHOG, TITUS

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
        p("[yellow]Missing tools.[/yellow]  See README for install commands.\n")


# ── schedule ──────────────────────────────────────────────────────────────────

def cmd_schedule(action: str) -> None:
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
        except RuntimeError as e:
            p(f"\n[red]{e}[/red]\n")

    elif action == "uninstall":
        removed = schedule.uninstall()
        if removed:
            p("\n[bold green]✓[/bold green]  Cron job removed.\n")
        else:
            p("\n[yellow]No cron job found.[/yellow]\n")


# ── rollback ──────────────────────────────────────────────────────────────────

def cmd_rollback(ns: argparse.Namespace) -> None:
    from .discover import discover
    from .backup import list_backups, rollback

    targets = discover()
    if not targets:
        p("[red]No AI tool directories found.[/red]\n"); return

    backups = list_backups(targets)
    if not backups:
        p("[yellow]No backups in ~/.agentscrub/backups/ yet.[/yellow]\n"); return

    p("\n[bold]Available backups[/bold]\n")
    for i, b in enumerate(backups, 1):
        p(f"  [bold]{i:2d}[/bold]  {b.display:<22} "
          f"{b.created.strftime('%Y-%m-%d %H:%M')}  "
          f"[dim]({b.age_str})  {b.size_str}[/dim]")
    p()

    if ns.list:
        return

    try:
        raw = input("Restore backup # (or q to quit): ").strip()
    except EOFError:
        return
    if not raw.isdigit() or raw.lower() == "q":
        p("[dim]Aborted.[/dim]\n"); return
    idx = int(raw) - 1
    if not (0 <= idx < len(backups)):
        p("[red]Invalid selection.[/red]\n"); return

    chosen = backups[idx]
    p(f"\n[yellow]Restoring {chosen.path} → {chosen.source} …[/yellow]")
    ok = rollback(chosen)
    if ok:
        p("[bold green]✓[/bold green]  Rollback complete.\n")
    else:
        p("[bold red]✗[/bold red]  rsync failed — check manually.\n")


# ── scan & run ────────────────────────────────────────────────────────────────

def cmd_scan_or_run(subcmd: str, ns: argparse.Namespace) -> None:
    from .discover import discover
    from .secrets import collect
    from .redact import (
        collect_files,
        collect_managed_credential_files,
        file_findings,
        grep_filter,
        is_high_precision_label,
        is_managed_credential_file,
        partition_secrets_by_precision,
        redact_file,
        redact_sqlite,
        top_exposed,
        _short_label,
    )
    from .backup import backup

    dry_run      = subcmd == "scan"
    skip_confirm = getattr(ns, "yes", False)
    extra        = [Path(x).expanduser() for x in getattr(ns, "also", [])]
    only_raw     = getattr(ns, "only", []) or []
    max_backups  = getattr(ns, "max_backups", 5)

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
            return

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
        return

    # Refuse to claim "clean" when no detectors exist — that would be silent failure.
    from .secrets import tools_status
    _status   = tools_status()
    available = [name for name, _, ok in _status if ok]
    missing   = [name for name, _, ok in _status if not ok]
    if not available:
        p("\n[bold red]No detection tools installed.[/bold red]")
        p("[dim]agentscrub needs at least one of gitleaks, TruffleHog, or Titus.[/dim]")
        p("[dim]Run [bold]agentscrub doctor[/bold] for install commands.[/dim]\n")
        return
    if missing:
        p(f"\n[yellow]Only {len(available)}/3 detectors installed "
          f"(missing: {', '.join(missing)}). Coverage will be reduced.[/yellow]")
        p("[dim]Run [bold]agentscrub doctor[/bold] for install commands.[/dim]")

    # ── header ────────────────────────────────────────────────────────────────
    mode = ("[bold yellow] SCAN READ-ONLY [/bold yellow]" if dry_run
            else "[bold green] LIVE [/bold green]")
    n_tools = len(targets)
    tool_word = "directory" if n_tools == 1 else "directories"
    if RICH:
        g = Table.grid(padding=(0, 2))
        g.add_column(style="dim")
        g.add_column()
        g.add_row("", f"[bold]agentscrub[/bold]  {mode}")
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

    # ── phase 1: detect credentials ───────────────────────────────────────────
    p("\n[bold]Phase 1[/bold]  Checking agent directories")
    t1 = time.perf_counter()

    if RICH:
        from .secrets import _gitleaks, _trufflehog, _titus
        import threading as _threading
        _DETECTORS = ("gitleaks", "trufflehog", "titus")
        _fns       = {"gitleaks": _gitleaks, "trufflehog": _trufflehog, "titus": _titus}
        _sp        = Spinner("dots", style="yellow")
        _t_lock      = _threading.Lock()
        _t_done_n    = {t.path: 0 for t in targets}     # 0..3
        _t_started   = {t.path: time.perf_counter() for t in targets}
        _t_finished  = {t.path: 0.0 for t in targets}
        by_tool: dict[str, dict] = {t: {} for t in _DETECTORS}

        class _Phase1Live:
            def __rich_console__(self, console, options):
                tbl = Table(box=None, show_header=True, padding=(0, 2),
                            header_style="bold dim")
                tbl.add_column("",        min_width=3)
                tbl.add_column("Tool",    min_width=20)
                tbl.add_column("Files",   justify="right")
                tbl.add_column("Time",    style="dim")
                for t in targets:
                    files_n = f"{_files_per_target_pre[t]:,}"
                    done_n = _t_done_n[t.path]
                    if done_n >= len(_DETECTORS):
                        elapsed = _t_finished[t.path] - _t_started[t.path]
                        tbl.add_row("[bold green]✓[/bold green]", t.display,
                                    files_n, f"{elapsed:.0f}s")
                    else:
                        elapsed = time.perf_counter() - _t_started[t.path]
                        tbl.add_row(_sp, t.display, files_n, f"{elapsed:.0f}s")
                yield tbl

        def _run_one(detector_name: str, fn) -> dict[str, str]:
            out: dict[str, str] = {}
            for target in targets:
                result = fn(target.path)
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

        from .secrets import top_types as _top_types, all_typed as _all_typed_fn
        _type_counts = _top_types(by_tool)
        _all_typed   = _all_typed_fn(by_tool)
    else:
        all_secrets, counts = collect(targets)
        _all_typed: dict[str, str] = {}
        for tool, n in counts.items():
            print(f"  detector {tool:<12} {n:,}", flush=True)
        print(f"  {'total unique':<12} {len(all_secrets):,}", flush=True)
        print(f"  {time.perf_counter()-t1:.1f}s", flush=True)

    if not all_secrets:
        p("\n[bold green]Clean — no credential patterns found.[/bold green]\n")
        return

    # ── phase 2: scan files ───────────────────────────────────────────────────
    p("\n[bold]Phase 2[/bold]  Mapping findings to affected files")
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

    if RICH:
        with Progress(
            TextColumn("  "),
            SpinnerColumn(style="yellow"),
            TextColumn(f"[dim]scanning {len(scanned_files):,} files…[/dim]"),
            console=_CON, transient=True,
        ) as prog:
            prog.add_task("grep", total=None)
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                flagged_all = ex.submit(grep_filter, all_secrets, scanned_files).result()
    else:
        flagged_all = grep_filter(all_secrets, scanned_files)

    elapsed2 = time.perf_counter() - t2
    preserved = [fp for fp in flagged_all if is_managed_credential_file(fp)]
    flagged = [fp for fp in flagged_all if not is_managed_credential_file(fp)]
    redactable_files = [fp for fp in scanned_files if not is_managed_credential_file(fp)]
    pct = len(flagged) / len(redactable_files) * 100 if redactable_files else 0

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

    # ── Phase 2 timing only — the actionable per-tool table needs the
    # precision partition and runs after the report is built. ────────────────
    if RICH:
        _CON.print(f"  [dim]done in {elapsed2:.1f}s[/dim]")
    else:
        print(f"  done in {elapsed2:.1f}s", flush=True)

    # Preserved live auth/MCP files are not announced on stdout — the
    # exclude_dirs / exclude_files lists silently skip plenty of paths to
    # protect user data, and singling out this one bucket inconsistently
    # makes the run noisier without adding info. The full audit report
    # still has dedicated sections listing every preserved file and its
    # matches.

    findings_by_file: dict[Path, list[dict[str, object]]] = {}
    full_report_path: Path | None = None
    if flagged or preserved:
        from .redact import file_findings_worker, _init_findings_worker

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
        redactable_secrets, report_only_secrets = partition_secrets_by_precision(
            all_secrets, _all_typed
        )
        flagged_redactable: list[Path] = []
        flagged_lowconf_only: list[Path] = []
        for fp in flagged:
            f_list = findings_by_file.get(fp, [])
            if any(is_high_precision_label(f["type"]) for f in f_list):
                flagged_redactable.append(fp)
            else:
                flagged_lowconf_only.append(fp)

        full_report_path = _write_scan_report(
            targets=targets,
            flagged=flagged,
            preserved=preserved,
            findings_by_file=findings_by_file,
            source_file_counts=[
                (t.display, flagged_per_target[t], files_per_target[t])
                for t in targets
            ],
            total_scanned_files=len(redactable_files),
            unique_patterns=len(all_secrets),
            flagged_redactable_count=len(flagged_redactable),
        )

        # Per-target breakdown: redactable files only (the actionable count).
        redact_per_target = {t: 0 for t in targets}
        for fp in flagged_redactable:
            for t in targets:
                try: fp.relative_to(t.path); redact_per_target[t] += 1; break
                except ValueError: pass

        # Per-type hits (= occurrences). Sum of the bar values equals the
        # 'hits' number in the headline, so the chart and the headline are in
        # the same unit and add up.
        hits_per_type: dict[str, int] = {}
        for fp in flagged_redactable:
            for f in findings_by_file.get(fp, []):
                if is_high_precision_label(f["type"]):
                    hits_per_type[f["type"]] = (
                        hits_per_type.get(f["type"], 0) + int(f.get("hits", 0) or 0)
                    )
        total_hits_redactable = sum(hits_per_type.values())
        type_counts_redactable = sorted(
            hits_per_type.items(), key=lambda x: -x[1]
        )[:6]

        if RICH:
            _CON.print()
            tbl = Table(box=None, show_header=True, padding=(0, 2),
                        header_style="bold dim")
            tbl.add_column("Tool",     style="dim", min_width=20)
            tbl.add_column("Exposed",  justify="right", style="bold yellow")
            tbl.add_column("Scanned",  justify="right", style="dim")
            tbl.add_column("Pct",      justify="right", style="dim")
            for t in targets:
                r = redact_per_target[t]
                tot = files_per_target[t]
                tbl.add_row(t.display, f"{r:,}", f"{tot:,}",
                            f"{r/tot*100:.1f}%" if tot else "")
            _CON.print(tbl)
            _CON.print(
                f"  [bold]{len(redactable_secrets):,}[/bold] secrets "
                f"[dim]in[/dim] "
                f"[bold]{len(flagged_redactable):,}[/bold] files "
                f"[dim]·[/dim] "
                f"[bold]{total_hits_redactable:,}[/bold] times"
            )

            if type_counts_redactable:
                _CON.print()
                _bars(type_counts_redactable,
                      total=total_hits_redactable,
                      count_label="Hits")
        else:
            for t in targets:
                r = redact_per_target[t]
                tot = files_per_target[t]
                print(f"  {t.display:<22}  redact {r:,} / {tot:,} scanned"
                      f" ({r/tot*100:.1f}%)" if tot else
                      f"  {t.display:<22}  0", flush=True)
            print(f"  {len(flagged_redactable):,} files to redact",
                  flush=True)

        p(f"\n[bold]Full audit[/bold]  [dim]{full_report_path}[/dim]")
    else:
        # No findings at all — nothing to partition; still set defaults
        # so the rest of the function compiles without unbound names.
        redactable_secrets, report_only_secrets = set(), set()
        flagged_redactable, flagged_lowconf_only = [], []

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
        fp: [f for f in findings if is_high_precision_label(f["type"])]
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
        p("\n[bold]Top files to redact[/bold]\n")

        def _resolve(fp: Path) -> tuple[str, str]:
            for t in targets:
                try:
                    return t.display, str(fp.relative_to(t.path))
                except ValueError:
                    pass
            return "?", str(fp)

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

        if RICH:
            if _CON.width < 100:
                source_w = 11
                path_w = max(24, _CON.width - 30)

                def _clip(s: str, n: int) -> str:
                    return s if len(s) <= n else s[:n - 1] + "…"

                _CON.print(f"  {'Source':<{source_w}} {'Secrets':>7} {'Hits':>6}  File")
                _CON.print("  " + "─" * min(_CON.width - 2, source_w + path_w + 18))
                for fp, uniq, hits, proof in exposed:
                    tool_name, rel = _resolve(fp)
                    _CON.print(
                        f"  {_clip(tool_name, source_w):<{source_w}} "
                        f"{uniq:>7} {hits:>6,}  {_trunc_path(rel, path_w)}",
                        markup=False,
                    )
                    _CON.print(
                        f"  {'':<{source_w}} {'':>7} {'':>6}  type: {proof}",
                        markup=False,
                    )
            else:
                tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold dim")
                tbl.add_column("Source",  style="dim",     min_width=12, max_width=18, no_wrap=True)
                tbl.add_column("File",                     min_width=24, max_width=56, overflow="ellipsis", no_wrap=True)
                tbl.add_column("Secrets", justify="right", style="bold yellow", no_wrap=True)
                tbl.add_column("Hits",    justify="right", style="dim", no_wrap=True)
                tbl.add_column("Type",    style="dim",     min_width=24, max_width=44, overflow="ellipsis", no_wrap=True)
                for fp, uniq, hits, proof in exposed:
                    tool_name, rel = _resolve(fp)
                    tbl.add_row(tool_name, _trunc_path(rel), str(uniq), f"{hits:,}", proof)
                _CON.print(tbl)
        else:
            for fp, uniq, hits, proof in exposed:
                tool_name, rel = _resolve(fp)
                print(f"  {uniq:3d} secrets  {hits:6,} hits  [{tool_name}]  {_trunc_path(rel, 48)}  {proof}", flush=True)

    if dry_run:
        p(f"\n[bold yellow]Scan complete — no files modified.[/bold yellow]\n")
        if RICH:
            _CON.print("[bold]Next steps[/bold]")
            g = Table.grid(padding=(0, 2))
            g.add_column()
            g.add_column()
            g.add_row("  agentscrub run",
                      f"redact {len(redactable_secrets):,} secrets in {len(flagged_redactable):,} files after confirmation")
            g.add_row("",
                      f"[dim]backup created first, last {max_backups} kept[/dim]")
            g.add_row("  agentscrub run --yes",
                      "[dim]redact immediately, no prompt[/dim]")
            _CON.print(g)
        else:
            print(f"\nNext steps:", flush=True)
            print(f"  agentscrub run        redact {len(redactable_secrets):,} secrets in {len(flagged_redactable):,} files after confirmation", flush=True)
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
        p(f"\n[bold yellow]About to redact {len(redactable_secrets):,} secrets "
          f"across {len(flagged_redactable):,} files.[/bold yellow]")
        p("[dim]A rotating backup will be created first "
          f"(keeping last {max_backups}).[/dim]")
        try:
            ans = input("Continue? [y/N] ").strip().lower()
        except EOFError:
            ans = "n"
        if ans != "y":
            p("[dim]Aborted.[/dim]\n"); return

    t_total = time.perf_counter()

    # ── backup + log rotation ─────────────────────────────────────────────────
    from .backup import rotate_logs
    rotate_logs()
    p("\n[bold]Backup[/bold]")
    for b in backup(targets, max_keep=max_backups):
        p(f"  [green]✓[/green]  {b.display:<22} [dim]{b.path}[/dim]")

    # ── phase 3: redact text ──────────────────────────────────────────────────
    # Only rewrite files containing high-precision tokens; loose-rule matches
    # ride along in the audit report but stay untouched.
    p(f"\n[bold]Phase 3[/bold]  Redacting {len(redactable_secrets):,} secrets "
      f"in {len(flagged_redactable):,} files  "
      f"[dim]({WORKERS} workers)[/dim]")
    t3 = time.perf_counter()
    worker_args = [(str(fp), redactable_secrets, False) for fp in flagged_redactable]
    total_redactions = 0
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
            with Pool(WORKERS) as pool:
                for path_str, count, err in pool.imap_unordered(redact_file, worker_args):
                    prog.advance(task)
                    if err:
                        errors.append(path_str)
                        prog.console.print(
                            f"  [red]WARN[/red]  {_label(path_str)}: {err}")
                    elif count:
                        total_redactions += count
                        prog.console.print(
                            f"  [bold green] OK [/bold green]  "
                            f"{_label(path_str)}  [dim]→[/dim]  {count:,}")
    else:
        with Pool(WORKERS) as pool:
            for path_str, count, err in pool.imap_unordered(redact_file, worker_args):
                if err:
                    errors.append(path_str)
                    print(f"  WARN  {_label(path_str)}: {err}", flush=True)
                elif count:
                    total_redactions += count
                    print(f"   OK   {_label(path_str)} → {count}", flush=True)

    p(f"  [dim]{time.perf_counter()-t3:.1f}s[/dim]")

    # ── phase 4: sqlite ───────────────────────────────────────────────────────
    p("\n[bold]Phase 4[/bold]  SQLite databases")
    sqlite_total, sqlite_results = redact_sqlite(redactable_secrets, targets, dry_run=False)
    if not sqlite_results:
        p("  [dim]none found[/dim]")
    for db_path, count in sqlite_results:
        label = str(db_path)
        for sp in all_scan_paths:
            try: label = str(db_path.relative_to(sp)); break
            except ValueError: pass
        if count < 0:
            p(f"  [red]WARN[/red]  {label}: error")
        else:
            p(f"  [bold green] OK [/bold green]  {label}  [dim]→[/dim]  {count:,}")

    # ── summary ───────────────────────────────────────────────────────────────
    elapsed = time.perf_counter() - t_total
    if RICH:
        g = Table.grid(padding=(0, 3))
        g.add_column(justify="right", style="bold")
        g.add_column()
        g.add_row(f"Done in {elapsed:.0f}s", "")
        g.add_row(f"{total_redactions:,}", f"replacements in {len(flagged):,} text files")
        if sqlite_total:
            g.add_row(f"{sqlite_total:,}", "SQLite replacements")
        if errors:
            g.add_row(f"[red]{len(errors)}[/red]", "[red]files with errors (see above)[/red]")
        g.add_row(f"{max_backups}", "backups kept  [dim](~/.agentscrub/backups/)[/dim]")
        _CON.print(Panel(g, box=box.ROUNDED, padding=(0, 1)))
    else:
        print(f"\nDone in {elapsed:.0f}s", flush=True)
        print(f"  {total_redactions:,} replacements in {len(flagged):,} files", flush=True)
        if sqlite_total:
            print(f"  {sqlite_total:,} SQLite replacements", flush=True)
        if errors:
            print(f"  {len(errors)} errors", flush=True)
        print(flush=True)


# ── entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    subcmd, ns = _parse()
    if getattr(ns, "version", False):
        _print_splash()
        print(_ver())
        return
    if getattr(ns, "list_tools", False):
        cmd_list_tools()
        return
    if subcmd == "doctor":
        cmd_doctor()
    elif subcmd == "schedule":
        cmd_schedule(getattr(ns, "action", "status"))
    elif subcmd == "rollback":
        cmd_rollback(ns)
    else:
        cmd_scan_or_run(subcmd, ns)


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
    main()
