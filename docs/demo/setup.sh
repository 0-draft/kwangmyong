#!/usr/bin/env bash
# Builds the demo repositories for a made-up developer in $1.
# shellcheck disable=SC2016 # backticks in the README text are literal Markdown
set -euo pipefail
mkdir -p "$1/repo" && cd "$1/repo"
git init -q -b main
printf '# app\n\nBuild with `make`. Logs go to /Users/tyamada/src/app/log.\n' > README.md
git add . && git commit -q -m init
printf 'Agent memory lives in ~/.claude/projects/-Users-tyamada-src-app/memory.\n' > NOTES.md
printf 'tyamada@Taros-MacBook-Pro app %% make test\nok\n' > test.log
git add . && git commit -q -m "chore: add notes" -m "https://claude.ai/code/session_01AbCdEfGh"
echo "author: 山田 太郎" > AUTHORS && git add . && git commit -q -m "add authors"
git rm -q AUTHORS && git commit -q -m "remove authors"
cat > "$1/config.toml" <<'TOML'
[identity]
names  = ["Taro Yamada", "山田 太郎"]
logins = ["tyamada"]
hosts  = ["Taros-MacBook-Pro"]
TOML
# The tool call Claude Code sends to a PreToolUse hook when an agent opens a PR.
cat > "$1/pr-create.json" <<JSON
{"tool_name":"Bash","cwd":"$1/repo","tool_input":{"command":"gh pr create --title 'Add notes' --body 'Adds notes.\\n\\nhttps://claude.ai/code/session_01AbCdEfGh'"}}
JSON
# A repository with nothing of Taro in it.
mkdir -p "$1/clean" && cd "$1/clean" && git init -q -b main
printf '# app\n\nBuild with `make`. Logs go to ~/src/app/log.\n' > README.md
git add . && git commit -q -m init
