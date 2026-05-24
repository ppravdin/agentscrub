"""Tests for discover.py — registry discovery and exclusions."""

from __future__ import annotations

from pathlib import Path

from agentscrub.discover import ScanTarget, discover


class TestScanTargetExclusions:
    def test_excluded_by_dir(self) -> None:
        t = ScanTarget(
            path=Path("/x"),
            tool="claude",
            display="Claude",
            exclude_dirs=frozenset({"telemetry"}),
        )
        assert t.excluded_by_dir(Path("/x/projects/telemetry/events.json"))
        assert not t.excluded_by_dir(Path("/x/projects/demo/session.jsonl"))

    def test_excluded_by_name(self) -> None:
        t = ScanTarget(
            path=Path("/x"),
            tool="claude",
            display="Claude",
            exclude_files=frozenset({".credentials.json"}),
        )
        assert t.excluded_by_name(Path("/x/.credentials.json"))
        assert not t.excluded_by_name(Path("/x/session.jsonl"))


class TestDiscover:
    def test_finds_existing_claude_dir(self, fake_home: Path, claude_tree: Path) -> None:
        targets = discover()
        tools = {t.tool for t in targets}
        assert "claude" in tools
        assert any(t.path == claude_tree for t in targets)

    def test_extra_custom_path(self, fake_home: Path, tmp_path: Path) -> None:
        custom = tmp_path / "my-tool"
        custom.mkdir()
        (custom / "log.txt").write_text("x")
        targets = discover(extra=[custom])
        custom_targets = [t for t in targets if t.tool == "custom"]
        assert len(custom_targets) == 1
        assert custom_targets[0].path.resolve() == custom.resolve()

    def test_skips_missing_dirs(self, fake_home: Path) -> None:
        # No agent dirs besides what we didn't create
        targets = discover()
        assert all(t.path.exists() for t in targets)

    def test_first_existing_dir_per_tool(self, fake_home: Path) -> None:
        """Only one windsurf-style path should match when multiple exist."""
        w1 = fake_home / ".windsurf"
        w2 = fake_home / ".codeium" / "windsurf"
        w1.mkdir(parents=True)
        (w1 / "sessions").mkdir()
        w2.mkdir(parents=True)
        (w2 / "sessions").mkdir()
        targets = discover()
        windsurf = [t for t in targets if t.tool == "windsurf"]
        assert len(windsurf) <= 1
