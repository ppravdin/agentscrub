# agentscrub

Scrubs secrets and credentials from your AI coding assistant session logs.

AI tools like Claude Code, Codex CLI, and Cursor store your entire conversation history locally — including any API keys, database passwords, JWTs, and OAuth tokens you've pasted in or that appeared in code. Supply-chain attacks on VS Code extensions or npm packages routinely scan these files. agentscrub finds and removes them.

## What it covers

| Tool | Log location | Notes |
|---|---|---|
| Claude Code | `~/.claude/` | JSONL sessions, file-history snapshots |
| OpenAI Codex CLI | `~/.codex/` | sessions, SQLite trace/state databases |
| Cursor / VSCode Server | `~/.antigravity-server/` | data files only — binaries/extensions excluded |
| Aider | `~/.aider/` | |
| Continue | `~/.continue/` | |
| Windsurf | `~/.windsurf/` | |

All tools are **auto-detected** — no configuration required.

Live auth and MCP credential stores are preserved by design. agentscrub may
report matched patterns in files such as `~/.claude/.credentials.json`,
`~/.codex/auth.json`, `~/.codex/.credentials.json`, `~/.cursor/mcp.json`,
`~/.gemini/antigravity/mcp_config.json`, or `~/.mcp-auth/`, but `run` will not
modify those files. The goal is to remove leaked copies from logs, histories,
and caches without breaking agent logins or MCP connections.

Each scan or run writes a detailed masked report to `~/.agentscrub/logs/`. The
report lists every affected file, detected pattern type, hit count, and proof
hash, but does not include full raw secrets.

## How it finds secrets

Three tools run in parallel (~25s combined):

| Tool | Finds | Coverage |
|---|---|---|
| **gitleaks** | JWTs, generic API keys, npm/GitHub tokens | 8 rule types |
| **TruffleHog** | Postgres, GCP, Dockerhub, OAuth, Stripe, Groq… | 23 detectors |
| **Titus** | Generic username/password pairs, connection URIs, PostHog, LinkedIn… | 487 rules |

Union of all findings → deduplicated. JSON lines are parsed and secrets replaced inside string values only, preserving file structure even when secrets contain `"` or `{}` characters.

## Install

**Requirements:** Python ≥ 3.11, pipx, rsync

```bash
pipx install agentscrub
```

### Detection tools (required)

```bash
# gitleaks
curl -sL https://github.com/gitleaks/gitleaks/releases/download/v8.26.0/gitleaks_8.26.0_linux_x64.tar.gz \
  | tar xz -C ~/.local/bin/ gitleaks && chmod +x ~/.local/bin/gitleaks

# TruffleHog
curl -sL https://github.com/trufflesecurity/trufflehog/releases/download/v3.95.2/trufflehog_3.95.2_linux_amd64.tar.gz \
  | tar xz -C ~/.local/bin/ trufflehog && chmod +x ~/.local/bin/trufflehog

# Titus (NoseyParker successor, 487 rules)
curl -sLo ~/.local/bin/titus \
  https://github.com/praetorian-inc/titus/releases/download/v1.1.29/titus-linux-amd64 \
  && chmod +x ~/.local/bin/titus
```

Verify everything is in place:

```bash
agentscrub doctor
```

## Usage

```bash
# See what's exposed — no writes
agentscrub scan

# Redact (asks for confirmation, creates backup first)
agentscrub run

# Non-interactive (for cron / CI)
agentscrub run --yes

# Restore a previous backup
agentscrub rollback

# Set up daily 3am cron job
agentscrub schedule install
agentscrub schedule status
agentscrub schedule uninstall

# Scan an extra directory not in the auto-detect list
agentscrub run --also ~/my-other-ai-tool

# Keep more backups (default: 5)
agentscrub run --max-backups 10
```

## Backup & rollback

Every live run creates a backup before touching anything:

```
~/.agentscrub/backups/
  claude/
    20260429-030000/    ← newest
    20260428-030000/
    20260427-030000/
  codex/
    20260429-030000/
    ...
```

Oldest backups are rotated out automatically (default: keep 5 per tool).

To restore:

```bash
agentscrub rollback

# Available backups
#   1  Claude Code        2026-04-29 03:00  (today)     1.2G
#   2  Claude Code        2026-04-28 03:00  (yesterday) 1.1G
#   3  OpenAI Codex CLI   2026-04-29 03:00  (today)     240M
#
# Restore backup # (or q to quit): 1
```

## What it does NOT catch

| Gap | Why |
|---|---|
| Plain prose passwords (`my password is hunter2`) | No pattern; indistinguishable from normal text |
| Short secrets < 8 chars | Below minimum length for all three tools |
| Secrets in binary files | Skipped by design |
| PII (names, phones, addresses) | Needs ML model — run `scan_logs.py` separately |

## Adding a new AI tool

Edit `src/agentscrub/discover.py` → `_REGISTRY`:

```python
dict(
    tool="my-tool",
    display="My AI Tool",
    dirs=["~/.my-tool/sessions"],
    exclude_dirs={"cache"},
    exclude_files={"credentials.json"},
),
```

Open a PR — contributions welcome.

## Upgrade / uninstall

```bash
pipx upgrade agentscrub
pipx uninstall agentscrub
```

## License

MIT
