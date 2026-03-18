#!/usr/bin/env bash
exec uv run "$(dirname "$0")/sync-claude-template.py" "$@"
