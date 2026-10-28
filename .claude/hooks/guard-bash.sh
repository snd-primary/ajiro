#!/bin/sh
# PreToolUse hook for Bash (CLAUDE.md guardrails, HANDOFF.md §11).
# Coarse pattern checks against accidents, not against a determined
# adversary: obvious ways around the pre-commit hook, publishing,
# reaching remote hosts, shell edits to guardrail files and shell reads
# of observed data. Exit 2 blocks; any other failure would let the
# command through, so every error path exits 2.
set -eu

command -v jq >/dev/null 2>&1 || {
	echo "guard-bash: jq not found; refusing to run Bash unchecked" >&2
	exit 2
}

cmd=$(jq -r '.tool_input.command // ""') || {
	echo "guard-bash: could not parse hook input; refusing to run Bash unchecked" >&2
	exit 2
}

decide() {
	jq -n --arg d "$1" --arg r "$2" '{hookSpecificOutput: {
		hookEventName: "PreToolUse",
		permissionDecision: $d,
		permissionDecisionReason: $r
	}}' || exit 2
	exit 0
}

has() {
	printf '%s\n' "$cmd" | grep -Eq -- "$1"
}

# Skipping or replacing the pre-commit hook.
has 'git[[:space:]].*--no-verify' &&
	decide deny "--no-verify skips the pre-commit guardrails. Fix the cause instead (CLAUDE.md)."
has 'git[[:space:]]+commit([[:space:]].*)?[[:space:]]-[a-zA-Z]*n[a-zA-Z]*([[:space:]]|$)' &&
	decide deny "git commit -n skips the pre-commit guardrails. Fix the cause instead (CLAUDE.md)."
# Every line that mentions hooksPath must be the read or the default set.
if printf '%s\n' "$cmd" | grep -E 'git[[:space:]].*hooksPath' |
	grep -Evq '^git config (--get )?core\.hooksPath( \.githooks)?$'; then
	decide deny "Changing core.hooksPath disables the pre-commit guardrails (CLAUDE.md)."
fi

# Rewriting or deleting published history.
has 'git[[:space:]].*push.*([[:space:]]-[a-zA-Z]*f|--force|--delete|--mirror|[[:space:]][+:])' &&
	decide deny "Force push or remote deletion is not allowed. Ask the human."

# Making the repository, code or data public (guardrail 4).
has 'gh[[:space:]]+repo[[:space:]]+(edit|create).*(--visibility|--public)' &&
	decide deny "Changing repository visibility is guardrail 4. Ask the human."
has 'gh[[:space:]]+api.*(private[[:space:]]*=[[:space:]]*false|visibility)' &&
	decide deny "Changing repository visibility is guardrail 4. Ask the human."
has 'gh[[:space:]]+gist[[:space:]]+create' &&
	decide deny "Publishing a gist is guardrail 4. Ask the human."

# Remote hosts: deployment and anything on the VPSes needs a human.
has '(^|[;&|(]|-c[[:space:]]+["'"'"'])[[:space:]]*((sudo|env|timeout|nohup|command|exec|sshpass)[[:space:]]+([^[:space:];&|]+[[:space:]]+)*)?(ssh|scp|sftp|rsync)[[:space:]]' &&
	decide ask "Touches a remote host (deployment or VPS work). Confirm with the human."
has 'docker[[:space:]].*((-H|--host)[[:space:]=]*ssh://|context[[:space:]])' &&
	decide ask "Touches a remote Docker host. Confirm with the human."

# Guardrail files are ask for Edit/Write (.claude/settings.json); the
# same applies when the shell writes, moves or removes them.
if has '(\.claude/|\.githooks|internal/guardrail|CLAUDE\.md|\.gitignore)' &&
	has '(>|sed[[:space:]].*-i|perl[[:space:]].*-i|(^|[[:space:];&|(])(tee|rm|mv|cp|ln|chmod|truncate|python3?|git[[:space:]]+(checkout|restore|rm|mv))[[:space:]])'; then
	decide ask "Writes to a guardrail file from the shell (CLAUDE.md). Confirm with the human."
fi

# Observed data is attacker-written text and can carry prompt injection;
# reading it through the shell needs the same confirmation as Read.
has '(^|[[:space:]/"'"'"'=])(data|logs|archive|dl|downloads)/|\.(duckdb|duckdb\.wal|jsonl|jsonl\.gz|parquet|log)([[:space:]"'"'"']|$)' &&
	decide ask "Touches observed data (attacker-written text). Confirm with the human."

exit 0
