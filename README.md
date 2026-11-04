# kwangmyong

Finds your own identity in git repositories: real name, login, personal email, hostname and home paths, in files, file names, commit and tag metadata, history, and on GitHub.

Secret scanners look for credentials. This looks for you.

A secret scanner matches things shaped like credentials, so `/Users/tyamada` in a README or `Taro Yamada` in a deleted file is not a finding for it (gitleaks 8.30.1 on the demo repository below: `no leaks found`). kwangmyong starts from who you are, expands it into the spellings it shows up in, and reads the places a scanner for keys has no reason to: commit and tag metadata, deleted blobs, file names, and GitHub issues, reviews and gists.

![gitleaks finds nothing in a repo full of a made-up developer's home paths, hostname, name and a Claude Code session link; kwangmyong finds all six and its Claude Code hook blocks a gh pr create](docs/demo/demo.gif)

The demo identity is made up. To re-record it: `vhs docs/demo/demo.tape`.

## Install

```sh
go install github.com/0-draft/kwangmyong/cmd/kwangmyong@latest
```

Binaries are on the [releases](https://github.com/0-draft/kwangmyong/releases) page.

From v0.2.0, each archive has an SBOM (`.sbom.json`), and `checksums.txt` is signed with cosign keyless by the release workflow:

```sh
cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/0-draft/kwangmyong/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --ignore-missing -c checksums.txt
```

## Usage

```sh
kwangmyong init                  # write ~/.config/kwangmyong/config.toml from this machine
kwangmyong identity              # what will be searched for, redacted
kwangmyong scan .                # files, file names, commit and tag metadata
kwangmyong scan --history .      # plus every blob reachable from any ref
kwangmyong scan --staged         # the next commit only
kwangmyong github kanywst        # issues, PRs, comments, reviews, releases, gists, repo metadata
kwangmyong github kanywst/repo
kwangmyong plan .                # git filter-repo inputs and a rewrite checklist
```

Exit status: `0` clean, `1` leaks, `2` error.

The text report has three parts:

- each place you were found: the line, with the value masked to a prefix and a fingerprint (`ta…[27fc08b6]`) and underlined with what it gives away
- an intel report: each kind of information about you, how often and where
- a verdict: `TARGET EXPOSED` with a threat level, how many finds need only a file edit and how many are baked into history, and the next command; or `TARGET DARK` with what was swept and searched for

`--reveal` prints raw values; `--format json` is for machines. Color is on in a terminal and off when piped or with `NO_COLOR`.

## Identity

```toml
# ~/.config/kwangmyong/config.toml
[identity]
names    = ["Taro Yamada", "山田 太郎"]
logins   = ["tyamada", "old-github-handle"]
emails   = ["taro@example.com"]
hosts    = ["Taros-MacBook-Pro"]
literals = []
```

The login, home directory, full name, hostname and global git identity of the current machine are added automatically (`--no-auto` to disable). Each entry is expanded:

| Kind | Also matches |
| --- | --- |
| Latin name | swapped order, `.` `_` `-` or no separator, any case, `tyamada`, `t.yamada` |
| CJK name | swapped order, with or without half-width, full-width or `・` separators |
| Login | `/Users/x`, `/home/x`, `C:\Users\x`, `-Users-x-`, `x@host`; the bare word from 5 characters |
| Email | URL-encoded |
| Host | spaced and possessive (`Taro's MacBook Pro`) |

GitHub noreply addresses are never reported.

A repository can allowlist paths and values in `.kwangmyong.toml`. It cannot declare `[identity]`.

```toml
[allow]
paths  = ["testdata/**", "**/*_test.go"]
values = ["^example$"]
```

## Rules

| Rule | Severity |
| --- | --- |
| `identity.email`, `.name`, `.login`, `.host`, `.literal` | high |
| `generic.autogen-email` (`user@Host.local`) | high |
| `generic.agent-session-url` (Claude Code and Codex session links) | high |
| `generic.home-path` (anyone's home path) | warn |
| `github.unclaimed-handle` (a declared login free to register) | warn |

`--strict` fails on warn.

## GitHub

`kwangmyong github` uses `GH_TOKEN`, `GITHUB_TOKEN` or `gh auth token`. Forks are skipped unless `--forks`; `--reviews=false` skips review bodies (one request per PR).

## Plans

`kwangmyong plan` writes `replacements.txt`, `mailmap` and `PLAN.md` to a private temp directory (`--out` to choose). They hold the raw values; keep them out of the repository.

```sh
git filter-repo --sensitive-data-removal \
  --replace-text replacements.txt --replace-message replacements.txt --mailmap mailmap
```

`PLAN.md` lists the first changed commit, the tags that move, and the force-push steps. For a Go module with released tags in range, a fix commit is usually better than a rewrite.

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
  - repo: https://github.com/0-draft/kwangmyong
    rev: v0.3.0
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
- uses: 0-draft/kwangmyong@v0.3.0
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

## Not covered

- Wikis (scan the wiki repository directly)
- Actions logs and artifacts
- Discussions

## License

MIT
