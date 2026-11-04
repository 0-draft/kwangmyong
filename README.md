# kwangmyong

English | [日本語](README.ja.md)

Finds you in git repositories: your name, login, email, hostname and home paths, in files, history, commit metadata and on GitHub. Secret scanners look for keys. This looks for you.

![gitleaks finds nothing in a repo full of a made-up developer's home paths, hostname, name and a Claude Code session link; kwangmyong's interactive view walks all six, its Claude Code hook blocks a gh pr create, and a clean repo comes back TARGET DARK](docs/demo/demo.gif)

The developer in the demo is made up. `vhs docs/demo/demo.tape` re-records it.

Coding agents write what they see, and what they see is your machine: `/Users/you/...` in a README, `you@your-laptop ~ %` in a pasted log, a `claude.ai/code/session_...` link at the bottom of a PR. None of it is a secret, so gitleaks stays quiet. kwangmyong starts from who you are and looks everywhere that goes public.

## Install

```sh
go install github.com/kanywst/kwangmyong/cmd/kwangmyong@latest
```

Or take a binary from [releases](https://github.com/kanywst/kwangmyong/releases).

## Start

```sh
kwangmyong init               # write your profile, filled in from this machine
kwangmyong scan --history .   # sweep this repository, deleted files included
kwangmyong hook install       # check every commit and push from now on
```

## Next to a secret scanner

Keep your secret scanner. It answers a different question.

| | Secret scanners (gitleaks, TruffleHog, GitHub secret scanning) | kwangmyong |
| --- | --- | --- |
| Looks for | credentials: keys, tokens, passwords | you: your name in every spelling, logins, emails, hostnames, home paths, agent session links |
| Knows who you are | no; a custom regex can match one spelling | a profile filled in from this machine and expanded (`Taro Yamada`, `tyamada`, `t.yamada`, `山田 太郎`, `-Users-tyamada-`) |
| Commit author, committer, tagger | not findings | findings, counted per value |
| A hit in history | rotate the secret | a name cannot be rotated: `plan` drafts the rewrite and lists what it cannot reach |
| Output | the secret, or a redacted form | masked everywhere by default, hook messages to agents included |
| Runs as | CLI, pre-commit, CI | interactive view, git hooks, CI (Action, SARIF), pre-tool hooks for eight coding agents |

On the demo repository, gitleaks 8.30.1 says `no leaks found`.

## Commands

```sh
kwangmyong scan [path]             # files, file names, commit and tag metadata
kwangmyong scan --history [path]   # plus every deleted blob still reachable
kwangmyong scan --staged           # only what the next commit adds
kwangmyong github <owner>[/repo]   # issues, PRs, comments, reviews, releases, gists
kwangmyong plan [path]             # git filter-repo inputs and a checklist
kwangmyong identity                # who is being looked for, masked
kwangmyong init                    # write the profile
kwangmyong hook <name>             # see Hooks
```

Exit status: `0` nothing certain, `1` found, `2` error. `--strict` also fails on warnings.

### On a terminal

`scan` and `github` open a full-screen view. The sweep runs with a live count; then each place you were found sits next to the masked line, what leaks, why it matters, where else the same value turns up, and the fix.

| Key | |
| --- | --- |
| `↑` `↓` `j` `k` | move |
| `←` `→` `tab` `1`-`5` | all, files, history, metadata, GitHub |
| `/` | search; it only sees masked text, so it cannot reveal a value |
| `r` | show values on this screen only |
| `e` | open the file at that line in `$VISUAL` or `$EDITOR` |
| `p` | draft the history rewrite |
| `q` | quit; the verdict stays in the scrollback |

A clean sweep closes by itself.

### Everywhere else

Piped output, `CI`, `--no-tui`, `KWANGMYONG_NO_TUI`, and `--format json` or `sarif` print a report: each place with the masked line underlined, an intel report of what kinds of information leak and where, and a verdict box. `TARGET EXPOSED` comes with a threat level, how many finds a file edit fixes and how many are baked into history, and the next command. `TARGET DARK` says what was swept and what was looked for.

Values are shown as a prefix and a fingerprint (`ta…[27fc08b6]`). `--reveal` shows them raw; SARIF stays masked regardless. Color is on in a terminal and off when piped or with `NO_COLOR`.

## Profile

```toml
# ~/.config/kwangmyong/config.toml
[identity]
names    = ["Taro Yamada", "山田 太郎"]
logins   = ["tyamada", "old-github-handle"]
emails   = ["taro@example.com"]
hosts    = ["Taros-MacBook-Pro"]
literals = []
```

This machine's login, home directory, full name, hostname and global git identity are added on every run (`--no-auto` turns that off). Each entry also matches the forms it shows up in:

| Kind | Also matches |
| --- | --- |
| Latin name | swapped, `.` `_` `-` or no separator, any case, `tyamada`, `t.yamada` |
| CJK name | swapped, with or without half-width, full-width or `・` separators |
| Login | `/Users/x`, `/home/x`, `C:\Users\x`, `-Users-x-`, `x@host`; the bare word from 5 characters |
| Email | URL-encoded |
| Host | spaced and possessive (`Taro's MacBook Pro`) |

GitHub noreply addresses are never reported. In CI, put the same TOML in `KWANGMYONG_IDENTITY`.

A repository can allowlist paths and values in `.kwangmyong.toml`. It cannot hold an `[identity]`.

```toml
[allow]
paths  = ["testdata/**", "**/*_test.go"]
values = ["^example$"]
```

## Rules

| Rule | Severity |
| --- | --- |
| `identity.name`, `.login`, `.email`, `.host`, `.literal` | high |
| `generic.autogen-email` (`user@Host.local`) | high |
| `generic.agent-session-url` (Claude Code and Codex session links) | high |
| `generic.home-path` (anyone's home path) | warn |
| `github.unclaimed-handle` (an old login anyone can register) | warn |

## GitHub

`kwangmyong github` reads `GH_TOKEN`, `GITHUB_TOKEN` or `gh auth token`. Forks are skipped unless `--forks`; `--reviews=false` skips review bodies, which cost one request per PR.

## Rewriting history

`kwangmyong plan` writes `replacements.txt`, `mailmap` and `PLAN.md` to a private temp directory (`--out` picks one). They hold the raw values, so keep them out of every repository.

```sh
git filter-repo --sensitive-data-removal \
  --replace-text replacements.txt --replace-message replacements.txt --mailmap mailmap
```

`PLAN.md` starts with what a rewrite cannot fix (forks, clones, caches, signatures, closed PR diffs), then the first changed commit, the tags that move and the force-push steps. For a Go module with released tags in range, a fix commit is usually the better trade.

## Hooks

### git

```sh
kwangmyong hook install   # pre-commit, commit-msg and pre-push for this repository
```

| Hook | Checks |
| --- | --- |
| `kwangmyong hook pre-commit` | the staged diff and the identity the commit will carry |
| `kwangmyong hook commit-msg <file>` | the message, without comments or the verbose diff |
| `kwangmyong hook pre-push` | every commit being pushed: metadata and contents |

[pre-commit](https://pre-commit.com):

```yaml
repos:
  - repo: https://github.com/kanywst/kwangmyong
    rev: v0.4.0
    hooks:
      - id: kwangmyong
      - id: kwangmyong-commit-msg
      - id: kwangmyong-pre-push
```

lefthook:

```yaml
pre-commit:
  commands:
    kwangmyong:
      run: kwangmyong hook pre-commit
commit-msg:
  commands:
    kwangmyong:
      run: kwangmyong hook commit-msg {1}
pre-push:
  commands:
    kwangmyong:
      run: kwangmyong hook pre-push
      use_stdin: true
```

### Coding agents

Each agent's pre-tool hook sends the tool call on stdin; kwangmyong checks shell commands (`git commit`, `git push`, `gh` bodies and body files), file writes into the repository, and GitHub MCP writes, and exits `2` to block with the reason on stderr.

| Agent | Config | Entry |
| --- | --- | --- |
| Claude Code | `.claude/settings.json` | `PreToolUse`, matcher `Bash\|Write\|Edit\|MultiEdit\|NotebookEdit\|mcp__github__.*`, `kwangmyong hook claude` |
| Codex CLI | `.codex/hooks.json` | `PreToolUse`, matcher `Bash\|apply_patch\|mcp__github__.*`, `kwangmyong hook codex` |
| Gemini CLI | `.gemini/settings.json` | `BeforeTool`, matcher `run_shell_command\|write_file\|replace\|mcp_github_.*`, `kwangmyong hook gemini` |
| Cursor | `.cursor/hooks.json` | `beforeShellExecution`, `beforeMCPExecution`, `preToolUse`: `kwangmyong hook cursor` |
| GitHub Copilot | `.github/hooks/kwangmyong.json` | `preToolUse`: `kwangmyong hook copilot` |
| Windsurf | `.windsurf/hooks.json` | `pre_run_command`, `pre_write_code`, `pre_mcp_tool_use`: `kwangmyong hook windsurf` |
| Kiro | `.kiro/hooks/kwangmyong.json` | `PreToolUse`, matcher `shell\|write\|@mcp`: `kwangmyong hook kiro` |
| Devin | `.devin/hooks.v1.json` | `PreToolUse`: `kwangmyong hook devin` |

Claude Code:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash|Write|Edit|MultiEdit|NotebookEdit|mcp__github__.*", "hooks": [{ "type": "command", "command": "kwangmyong hook claude" }] }
    ]
  }
}
```

Cursor:

```json
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [{ "command": "kwangmyong hook cursor" }],
    "beforeMCPExecution": [{ "command": "kwangmyong hook cursor" }],
    "preToolUse": [{ "command": "kwangmyong hook cursor", "matcher": "Write" }]
  }
}
```

The adapters follow each agent's published hook format; fields that differ between versions are probed rather than assumed.

## CI

```yaml
- uses: actions/checkout@v7
  with:
    fetch-depth: 0 # --history needs every commit
- uses: kanywst/kwangmyong@v0.4.0
  with:
    identity: ${{ secrets.KWANGMYONG_IDENTITY }}
    sarif: kwangmyong.sarif
- uses: github/codeql-action/upload-sarif@v4
  if: always()
  with:
    sarif_file: kwangmyong.sarif
```

The action installs the release binary after checking it against `checksums.txt` and runs `scan --history --strict .` (change it with `args`). The identity comes from a secret in TOML, the same keys as the `[identity]` table:

```toml
names  = ["Taro Yamada", "山田 太郎"]
logins = ["tyamada"]
emails = ["taro@example.com"]
```

Anywhere else, set `KWANGMYONG_IDENTITY` to the same TOML. A malformed value fails without echoing it. Output is masked in logs, and `--format sarif` is always masked whatever `--reveal` says.

## Verifying a release

From v0.2.0, each archive ships an SBOM (`.sbom.json`), and `checksums.txt` is signed by the release workflow with cosign keyless:

```sh
cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/(kanywst|0-draft)/kwangmyong/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --ignore-missing -c checksums.txt
```

Releases before v0.4.0 were published from `0-draft/kwangmyong`, which the regexp also accepts.

## Not covered

- Wikis (scan the wiki repository directly)
- Actions logs and artifacts
- Discussions

## License

MIT
