"""Auto-discover AI coding assistant log directories on this machine."""
from __future__ import annotations
from dataclasses import dataclass, field
from glob import glob
from pathlib import Path


@dataclass(frozen=True)
class ScanTarget:
    path: Path
    tool: str           # short id  e.g. "claude"
    display: str        # human label  e.g. "Claude Code"
    exclude_dirs: frozenset[str] = field(default_factory=frozenset)
    exclude_files: frozenset[str] = field(default_factory=frozenset)
    exclude_suffixes: frozenset[str] = field(default_factory=frozenset)

    def excluded_by_dir(self, p: Path) -> bool:
        return any(part in self.exclude_dirs for part in p.parts)

    def excluded_by_name(self, p: Path) -> bool:
        if p.name in self.exclude_files:
            return True
        if any(p.name.endswith(suffix) for suffix in self.exclude_suffixes):
            return True
        return False

    def excluded(self, p: Path) -> bool:
        return self.excluded_by_dir(p) or self.excluded_by_name(p)


# Registry — add new tools here, no code changes needed elsewhere
_REGISTRY: list[dict] = [
    dict(
        tool="claude",
        display="Claude Code",
        dirs=["~/.claude"],
        # cache/ and marketplaces/ under ~/.claude/plugins/ are downloaded
        # public artifacts (Anthropic's plugin catalog + cached plugin releases).
        # telemetry/ holds Claude Code's local analytics queue (failed-event
        # buffers full of beta-flag identifiers, GUIDs, hyphenated build
        # strings) which detectors heavily false-positive on.
        # All of these are pattern-shape/cache noise with no user history.
        exclude_dirs={
            "backups", "cache", "image-cache", "marketplaces", "statsig", "telemetry",
        },
        exclude_files={".credentials.json", "settings.json"},
    ),
    dict(
        tool="codex",
        display="OpenAI Codex CLI",
        dirs=["~/.codex"],
        # cache/.tmp/tmp/plugins/skills hold downloaded tools, marketplaces,
        # generated images, and installed helper code. Those are not Codex
        # sessions; they are mostly public artifacts and pattern-shape noise.
        # Keep sessions/, memories/, shell_snapshots/, history.jsonl, and
        # SQLite state files in scope.
        exclude_dirs={
            ".git", ".tmp", "cache", "generated_images", "plugins", "skills", "tmp",
        },
        exclude_files={"auth.json", ".credentials.json", "models_cache.json"},
    ),
    dict(
        tool="cursor",
        display="Cursor",
        # ~/.cursor holds IDE chats (projects/), CLI chats (chats/),
        # ACP sessions (acp-sessions/), plus logs/ — all need scanning.
        dirs=["~/.cursor"],
        exclude_dirs={"bin", "extensions", "node_modules", "plugins",
                      "CachedProfilesData", "CachedExtensionVSIXs"},
        exclude_files={"mcp.json"},
    ),
    dict(
        tool="cursor-server",
        display="Cursor (server)",
        dirs=["~/.cursor-server"],
        # CachedProfilesData/CachedExtensionVSIXs are pure VS Code-fork
        # caches; data/logs/ holds extension diagnostic output (Jupyter, LSP)
        # — not user history. cli/ holds the downloaded Cursor-server
        # install tree (Stable-<sha>/server/out/...) — that's bundled
        # Microsoft VS Code JavaScript source, often 20k+ files of
        # minified JS that produce regex-shape collisions but contain
        # zero user data. data/User/History is VS Code local file history
        # snapshots, not Cursor chat/session storage. Keep workspaceStorage in
        # scope because Cursor chat databases live there.
        exclude_dirs={"bin", "extensions", "node_modules", "cli",
                      "CachedProfilesData", "CachedExtensionVSIXs", "History",
                      "Machine", "logs"},
        exclude_files={"languagepacks.json", "machineid", "mcp.json", "settings.json"},
        exclude_suffixes={".log", ".pid", ".token"},
    ),
    dict(
        tool="cursor-app",
        display="Cursor (desktop)",
        # VS Code-fork workspaceStorage holds chat data inside state.vscdb
        # SQLite databases. First-existing wins across OSes.
        dirs=[
            "~/Library/Application Support/Cursor/User/workspaceStorage",
            "~/.config/Cursor/User/workspaceStorage",
            "~/AppData/Roaming/Cursor/User/workspaceStorage",
        ],
        exclude_dirs={"bin", "extensions", "node_modules",
                      "CachedProfilesData", "CachedExtensionVSIXs"},
        exclude_files={"mcp.json"},
    ),
    dict(
        tool="antigravity",
        display="Google Antigravity",
        dirs=["~/.antigravity-server"],
        # Same VS Code-fork cache pattern as Cursor server.
        exclude_dirs={"bin", "extensions", "node_modules",
                      "CachedProfilesData", "CachedExtensionVSIXs", "logs"},
        exclude_files={"mcp.json", "mcp_config.json"},
    ),
    dict(
        tool="aider",
        display="Aider",
        dirs=["~/.aider"],
    ),
    dict(
        tool="continue",
        display="Continue",
        dirs=["~/.continue"],
        exclude_files={"config.yaml", "config.json", "config.ts", ".env"},
    ),
    dict(
        tool="windsurf",
        display="Windsurf",
        dirs=[
            "~/.codeium/windsurf",
            "~/.config/Codeium/Windsurf",
            "~/AppData/Roaming/Codeium/Windsurf",
            "~/.windsurf",
        ],
        exclude_dirs={"extensions"},
        exclude_files={"mcp.json", "mcp_config.json"},
    ),
    dict(
        tool="windsurf-server",
        display="Windsurf (server)",
        dirs=["~/.windsurf-server"],
        exclude_dirs={"bin", "extensions", "node_modules",
                      "CachedProfilesData", "CachedExtensionVSIXs", "logs"},
        exclude_files={"mcp.json", "mcp_config.json"},
    ),
    dict(
        tool="windsurf-app",
        display="Windsurf (desktop)",
        # VS Code-fork User dir; chat data lives in workspaceStorage state.vscdb.
        dirs=[
            "~/Library/Application Support/Windsurf/User/workspaceStorage",
            "~/.config/Windsurf/User/workspaceStorage",
            "~/AppData/Roaming/Windsurf/User/workspaceStorage",
        ],
        exclude_dirs={"bin", "extensions", "node_modules",
                      "CachedProfilesData", "CachedExtensionVSIXs"},
        exclude_files={"mcp.json", "mcp_config.json"},
    ),
    dict(
        tool="zed",
        display="Zed AI",
        # Conversation history moved from ~/.config/zed/conversations (legacy
        # JSON) to ~/.local/share/zed/threads/threads.db (SQLite — handled by
        # the redact_sqlite pass). First-existing wins. Older JSON
        # conversations may still exist.
        # Flatpak install (~/.var/app/dev.zed.Zed/) is intentionally skipped:
        # its threads-db.1.mdb is LMDB, which we cannot safely rewrite, so
        # scanning the rest would give a false sense of completeness.
        dirs=[
            "~/.local/share/zed",
            "~/Library/Application Support/Zed",
            "~/AppData/Roaming/Zed",
            "~/.config/zed/conversations",
        ],
        exclude_files={"settings.json", "keymap.json", "tasks.json"},
    ),
    dict(
        tool="gemini",
        display="Gemini CLI",
        # ~/.gemini also contains the Antigravity brain/skills tree
        dirs=["~/.gemini"],
        # Antigravity's embedded Chromium profile is mostly browser caches,
        # extension resources, Safe Browsing metadata, and live browser state,
        # not Gemini CLI or agent transcript/history data.
        exclude_dirs={"antigravity-browser-profile"},
        exclude_files={
            "oauth_creds.json",
            "mcp-oauth-tokens.json",
            "mcp_config.json",
            "settings.json",
            "google_accounts.json",
            "trustedFolders.json",
            "installation_id",
            "user_id",
        },
    ),
    dict(
        tool="opencode",
        display="OpenCode",
        dirs=["~/.local/share/opencode"],
        exclude_files={"auth.json", "mcp-auth.json"},
    ),
    dict(
        tool="opencode-config",
        display="OpenCode config",
        dirs=["~/.config/opencode"],
        exclude_files={"opencode.json", "opencode.jsonc", "tui.json", "tui.jsonc"},
    ),
    dict(
        tool="crush",
        display="Crush (Charm)",
        dirs=["~/.local/share/crush"],
        exclude_files={"mcp.json", "crush.json"},
    ),
    dict(
        tool="crush-config",
        display="Crush config",
        dirs=["~/.config/crush"],
        exclude_files={"crush.json"},
    ),
    dict(
        tool="cline",
        display="Cline",
        # First-existing wins across OSes (macOS / Linux / Windows / CLI mode)
        dirs=[
            "~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev",
            "~/.config/Code/User/globalStorage/saoudrizwan.claude-dev",
            "~/AppData/Roaming/Code/User/globalStorage/saoudrizwan.claude-dev",
            "~/.cline/data",
        ],
        exclude_files={"cline_mcp_settings.json", "secrets.json"},
    ),
    dict(
        tool="copilot-chat",
        display="GitHub Copilot Chat",
        # Copilot Chat storage inside VS Code workspaceStorage.
        dirs=[
            "~/Library/Application Support/Code/User/workspaceStorage/*/GitHub.copilot-chat",
            "~/Library/Application Support/Code/User/workspaceStorage/*/github.copilot-chat",
            "~/.config/Code/User/workspaceStorage/*/GitHub.copilot-chat",
            "~/.config/Code/User/workspaceStorage/*/github.copilot-chat",
            "~/AppData/Roaming/Code/User/workspaceStorage/*/GitHub.copilot-chat",
            "~/AppData/Roaming/Code/User/workspaceStorage/*/github.copilot-chat",
        ],
    ),
]


def discover(extra: list[Path] | None = None) -> list[ScanTarget]:
    """Return every known AI-tool dir that exists on this machine, plus any extras."""
    targets: list[ScanTarget] = []
    seen: set[Path] = set()

    for spec in _REGISTRY:
        for raw in spec["dirs"]:
            expanded = str(Path(raw).expanduser())
            paths = [Path(p) for p in sorted(glob(expanded))] if any(ch in raw for ch in "*?[") else [Path(expanded)]
            matched = False
            for p in paths:
                p = p.expanduser()
                if not p.exists() or p in seen:
                    continue
                seen.add(p)
                targets.append(ScanTarget(
                    path=p,
                    tool=spec["tool"],
                    display=spec["display"],
                    exclude_dirs=frozenset(spec.get("exclude_dirs", set())),
                    exclude_files=frozenset(spec.get("exclude_files", set())),
                    exclude_suffixes=frozenset(spec.get("exclude_suffixes", set())),
                ))
                matched = True
            if matched:
                break  # only first existing dir per tool

    for p in (extra or []):
        p = p.expanduser().resolve()
        if p.exists() and p not in seen:
            seen.add(p)
            targets.append(ScanTarget(path=p, tool="custom", display=str(p)))

    return targets
