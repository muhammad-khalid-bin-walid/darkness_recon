from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from datetime import date

_TYPE_ORDER: dict[str, str] = {
    "feat": "Features",
    "fix": "Bug Fixes",
    "docs": "Documentation",
    "chore": "Maintenance",
    "refactor": "Refactoring",
    "perf": "Performance",
    "test": "Tests",
}


@dataclass
class ChangelogEntry:
    version: str
    date: str
    type: str
    description: str
    breaking_changes: list[str] = field(default_factory=list)


def _git(repo: str, args: list[str]) -> str:
    result = subprocess.run(
        ["git", "-C", repo] + args,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip()


def generate_changelog(
    repo_path: str, from_ref: str | None = None, to_ref: str | None = None
) -> list[ChangelogEntry]:
    """Parse conventional commits between two refs into structured entries."""
    range_spec = ""
    if from_ref and to_ref:
        range_spec = f"{from_ref}..{to_ref}"
    elif from_ref:
        range_spec = f"{from_ref}..HEAD"
    elif to_ref:
        range_spec = to_ref
    else:
        range_spec = "HEAD"
    log = _git(repo_path, ["log", range_spec, "--pretty=format:%s", "--no-merges"])
    if not log:
        return []
    commits = log.splitlines()
    categorized = categorize_commits(commits)
    entries: list[ChangelogEntry] = []
    for commit_type, msgs in categorized.items():
        for msg in msgs:
            breaking = []
            if msg.startswith("BREAKING:"):
                breaking.append(msg)
            entries.append(
                ChangelogEntry(
                    version="unreleased",
                    date=date.today().isoformat(),
                    type=commit_type,
                    description=msg,
                    breaking_changes=breaking,
                )
            )
    return entries


def format_changelog(entries: list[ChangelogEntry]) -> str:
    """Render a list of entries into a Markdown changelog string."""
    groups: dict[str, list[ChangelogEntry]] = {}
    breaking: list[str] = []
    for e in entries:
        groups.setdefault(e.type, []).append(e)
        breaking.extend(e.breaking_changes)
    lines = ["# Changelog\n"]
    for commit_type in ("feat", "fix", "docs", "chore", "refactor", "perf", "test"):
        items = groups.get(commit_type, [])
        if not items:
            continue
        heading = _TYPE_ORDER.get(commit_type, commit_type.capitalize())
        lines.append(f"## {heading}\n")
        for item in items:
            lines.append(f"- {item.description}")
        lines.append("")
    if breaking:
        lines.append("## Breaking Changes\n")
        for b in breaking:
            lines.append(f"- {b}")
        lines.append("")
    return "\n".join(lines)


def categorize_commits(commits: list[str]) -> dict[str, list[str]]:
    """Group commit messages by their conventional-commit type."""
    pattern = re.compile(r"^(?P<type>\w+)(?:\(.*?\))?[!:]?\s+(?P<desc>.+)")
    result: dict[str, list[str]] = {}
    for commit in commits:
        match = pattern.match(commit.strip())
        if match:
            ctype = match.group("type").lower()
            desc = match.group("desc").strip()
        else:
            ctype = "chore"
            desc = commit.strip()
        result.setdefault(ctype, []).append(desc)
    return result
