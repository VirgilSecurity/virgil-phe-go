#!/usr/bin/env python3
# /// script
# dependencies = []
# ///
"""
sync-template.py  —  Apply upstream claude-starter-kit updates locally.

Fetches the upstream template tarball from GitHub, applies variable
substitutions, copies changed files into the project, and updates
the manifest version.  No shell calls, no sed, stdlib only.

Usage (via wrapper):
    ./sync-template.sh              # latest release
    ./sync-template.sh v1.2.0      # specific tag
    ./sync-template.sh master      # tip of master
"""

import json
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import urllib.request
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

def project_root() -> Path:
    return Path(__file__).parent.resolve()


def default_manifest(root: Path) -> dict:
    project_name = root.name
    return {
        "schema_version": "1",
        "upstream_repo": "serpro69/claude-starter-kit",
        "template_version": "unknown",
        "synced_at": "",
        "variables": {
            "PROJECT_NAME": project_name,
            "LANGUAGES": "",
            "CC_MODEL": "default",
            "SERENA_INITIAL_PROMPT": "",
        },
    }


def read_manifest(root: Path) -> dict:
    path = root / ".github" / "template-state.json"
    if not path.exists():
        print(f"  Manifest not found: {path}")
        print(f"  Creating default manifest ...")
        data = default_manifest(root)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2) + "\n")
        return data
    return json.loads(path.read_text())


def write_manifest(root: Path, data: dict, resolved_version: str) -> None:
    data["template_version"] = resolved_version
    data["synced_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    path = root / ".github" / "template-state.json"
    path.write_text(json.dumps(data, indent=2) + "\n")


# ---------------------------------------------------------------------------
# GitHub API helpers
# ---------------------------------------------------------------------------

def _get(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "sync-template/1.0"})
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def resolve_version(version: str, repo: str) -> str:
    base = f"https://api.github.com/repos/{repo}"
    if version == "latest":
        try:
            return _get(f"{base}/releases/latest")["tag_name"]
        except Exception:
            tags = _get(f"{base}/tags")
            if not tags:
                sys.exit("Error: no tags found in upstream repository")
            return tags[0]["name"]
    if version in ("master", "main"):
        return _get(f"{base}/commits/{version}")["sha"]
    return version  # specific tag or SHA — use as-is


def fetch_tarball(repo: str, version: str, dest: Path) -> Path:
    """Download upstream tarball and return path to extracted root directory."""
    url = f"https://api.github.com/repos/{repo}/tarball/{version}"
    req = urllib.request.Request(url, headers={"User-Agent": "sync-template/1.0"})
    dest.mkdir(parents=True, exist_ok=True)

    with urllib.request.urlopen(req) as resp:
        with tarfile.open(fileobj=resp, mode="r|gz") as tar:
            try:
                tar.extractall(dest, filter="data")   # Python 3.12+
            except TypeError:
                tar.extractall(dest)                   # Python < 3.12

    dirs = [d for d in dest.iterdir() if d.is_dir()]
    if not dirs:
        sys.exit("Error: upstream tarball was empty")
    return dirs[0]


# ---------------------------------------------------------------------------
# Substitutions  (pure Python, no sed)
# ---------------------------------------------------------------------------

def substitute_settings_json(text: str, variables: dict) -> str:
    """Apply CC_MODEL and CC_STATUSLINE substitutions to settings.json."""
    data = json.loads(text)

    cc_model = variables.get("CC_MODEL", "default")
    if cc_model == "default":
        data.pop("model", None)
    else:
        data["model"] = cc_model

    cc_statusline = variables.get("CC_STATUSLINE", "enhanced")
    if cc_statusline == "basic":
        # Walk the dict and replace the statusline command string
        if "statusLine" in data and "command" in data["statusLine"]:
            data["statusLine"]["command"] = data["statusLine"]["command"].replace(
                "statusline_enhanced.sh", "statusline.sh"
            )

    return json.dumps(data, indent=2) + "\n"


def substitute_project_yml(text: str, variables: dict) -> str:
    """Apply PROJECT_NAME, LANGUAGES, SERENA_INITIAL_PROMPT to project.yml."""
    project_name = variables.get("PROJECT_NAME", "")
    languages = variables.get("LANGUAGES", "")
    serena_prompt = variables.get("SERENA_INITIAL_PROMPT", "")

    # project_name: "..."
    text = re.sub(
        r'^(project_name:\s*")[^"]*(")',
        rf'\g<1>{project_name}\2',
        text,
        flags=re.MULTILINE,
    )

    # languages: YAML block  (one or more "- item" lines)
    if languages:
        lang_items = "\n".join(
            f"- {lang.strip()}" for lang in languages.split(",") if lang.strip()
        )
        text = re.sub(
            r"^(languages:\s*\n)((?:[ \t]*-[^\n]*\n)+)",
            f"languages:\n{lang_items}\n",
            text,
            flags=re.MULTILINE,
        )

    # initial_prompt: "" — only substitute when a value is configured
    if serena_prompt:
        text = re.sub(
            r'^(initial_prompt:\s*)""',
            rf'\g<1>"{serena_prompt}"',
            text,
            flags=re.MULTILINE,
        )

    return text


def apply_substitutions(templates_dir: Path, output_dir: Path, variables: dict) -> None:
    """Copy .github/templates/* into output_dir, patching the two config files."""
    if not templates_dir.exists():
        sys.exit(f"Error: templates directory not found: {templates_dir}")

    shutil.copytree(templates_dir, output_dir, dirs_exist_ok=True)

    settings = output_dir / "claude" / "settings.json"
    if settings.exists():
        settings.write_text(substitute_settings_json(settings.read_text(), variables))

    project_yml = output_dir / "serena" / "project.yml"
    if project_yml.exists():
        project_yml.write_text(substitute_project_yml(project_yml.read_text(), variables))


# ---------------------------------------------------------------------------
# File comparison & apply
# ---------------------------------------------------------------------------

def is_excluded(path: str, exclusions: list[str]) -> bool:
    return any(fnmatch(path, pat) for pat in exclusions)


def apply_changes(
    substituted: Path,
    upstream_root: Path,
    root: Path,
    exclusions: list[str],
) -> tuple[list[str], list[str], list[str]]:
    """
    Copy staged files into the project tree.
    Returns (added, modified, excluded) lists of project-relative paths.
    """
    added, modified, excluded = [], [], []

    # Template directories: staging subdir -> project dir
    dir_map = {
        substituted / "claude": root / ".claude",
        substituted / "serena": root / ".serena",
    }

    for src_dir, dst_dir in dir_map.items():
        if not src_dir.is_dir():
            continue
        for src_file in sorted(src_dir.rglob("*")):
            if not src_file.is_file():
                continue
            rel = src_file.relative_to(src_dir)
            dst_file = dst_dir / rel
            display = str((dst_dir / rel).relative_to(root))

            if is_excluded(display, exclusions):
                excluded.append(display)
                continue

            dst_file.parent.mkdir(parents=True, exist_ok=True)
            is_new = not dst_file.exists()
            is_changed = not is_new and src_file.read_bytes() != dst_file.read_bytes()

            shutil.copy2(src_file, dst_file)

            if is_new:
                added.append(display)
            elif is_changed:
                modified.append(display)

    # Sync-infrastructure files (workflow + script)
    infra = [
        (
            upstream_root / ".github" / "workflows" / "template-sync.yml",
            root / ".github" / "workflows" / "template-sync.yml",
            ".github/workflows/template-sync.yml",
            False,
        ),
        (
            upstream_root / ".github" / "scripts" / "template-sync.sh",
            root / ".github" / "scripts" / "template-sync.sh",
            ".github/scripts/template-sync.sh",
            True,   # needs +x
        ),
    ]

    for src_file, dst_file, display, executable in infra:
        if is_excluded(display, exclusions):
            excluded.append(display)
            continue
        if not src_file.exists():
            continue

        dst_file.parent.mkdir(parents=True, exist_ok=True)
        is_new = not dst_file.exists()
        is_changed = not is_new and src_file.read_bytes() != dst_file.read_bytes()

        shutil.copy2(src_file, dst_file)
        if executable:
            dst_file.chmod(
                dst_file.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
            )

        if is_new:
            added.append(display)
        elif is_changed:
            modified.append(display)

    return added, modified, excluded


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def print_report(added: list[str], modified: list[str], excluded: list[str]) -> None:
    if not added and not modified and not excluded:
        print("  No changes — already up to date.")
        return
    if added:
        print(f"\n  Added ({len(added)}):")
        for f in added:
            print(f"    + {f}")
    if modified:
        print(f"\n  Modified ({len(modified)}):")
        for f in modified:
            print(f"    ~ {f}")
    if excluded:
        print(f"\n  Excluded ({len(excluded)}):")
        for f in excluded:
            print(f"    ○ {f}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    version_arg = sys.argv[1] if len(sys.argv) > 1 else "latest"
    root = project_root()
    manifest = read_manifest(root)
    repo: str = manifest["upstream_repo"]
    variables: dict = manifest.get("variables", {})
    exclusions: list[str] = manifest.get("sync_exclusions", [])

    # 1. Resolve version
    print(f">>> Resolving version: {version_arg}")
    resolved = resolve_version(version_arg, repo)
    print(f"    → {resolved}")

    with tempfile.TemporaryDirectory(prefix="template-sync-") as tmp:
        tmp_path = Path(tmp)

        # 2. Fetch upstream tarball
        print(f"\n>>> Fetching {repo}@{resolved} ...")
        upstream_root = fetch_tarball(repo, resolved, tmp_path / "upstream")
        print(f"    → {upstream_root.name}")

        # 3. Apply substitutions
        print("\n>>> Applying substitutions ...")
        substituted = tmp_path / "substituted"
        templates_dir = upstream_root / ".github" / "templates"
        apply_substitutions(templates_dir, substituted, variables)
        print("    → done")

        # 4. Copy changed files into project
        print("\n>>> Applying changes ...")
        added, modified, excluded = apply_changes(
            substituted, upstream_root, root, exclusions
        )
        print_report(added, modified, excluded)

        # 5. Update manifest
        write_manifest(root, manifest, resolved)
        print(f"\n    Updated .github/template-state.json → {resolved}")

    total = len(added) + len(modified)
    print(f"\n>>> Sync complete: {len(added)} added, {len(modified)} modified")
    print(f"\n    Review:  git -C '{root}' diff")
    print(f"\n    Commit:")
    print(f"    git -C '{root}' add .claude/ .serena/ .github/")
    print(f"    git -C '{root}' commit -m 'Sync claude-starter-kit template to {resolved} (chore)'")


if __name__ == "__main__":
    main()
