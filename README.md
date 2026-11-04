# kwangmyong

Finds your own identity in git repositories: real name, login, personal email, hostname and home paths, in files, file names, commit and tag metadata, history, and on GitHub.

Secret scanners look for credentials. This looks for you.

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

Matched values are never printed, only a prefix and a fingerprint (`ta…[27fc08b6]`). `--reveal` prints them; `--format json` is available.

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

| Hook | Command |
| --- | --- |
| git pre-commit | `kwangmyong hook pre-commit` |
| git pre-push | `kwangmyong hook pre-push` |
| Claude Code `PreToolUse` | `kwangmyong hook claude` |

The Claude Code hook checks writes into a repository, `git commit`, `git push`, `gh` bodies and GitHub MCP writes, and exits `2` to block.

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash|Write|Edit|MultiEdit|NotebookEdit|mcp__github__.*", "hooks": [{ "type": "command", "command": "kwangmyong hook claude" }] }
    ]
  }
}
```

[pre-commit](https://pre-commit.com):

```yaml
repos:
  - repo: https://github.com/0-draft/kwangmyong
    rev: v0.1.2
    hooks:
      - id: kwangmyong
      - id: kwangmyong-pre-push
```

lefthook:

```yaml
pre-commit:
  commands:
    kwangmyong:
      run: kwangmyong hook pre-commit
pre-push:
  commands:
    kwangmyong:
      run: kwangmyong hook pre-push
      use_stdin: true
```

## Not covered

- Wikis (scan the wiki repository directly)
- Actions logs and artifacts
- Discussions

## License

MIT
