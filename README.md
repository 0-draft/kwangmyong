# kwangmyong

Keep your identity inside.

`kwangmyong` finds **your own** identity leaking from git repositories: your real name, login, personal email, hostname and home-directory paths, in tracked files, file names, commit and tag metadata, and every blob in history. Secret scanners look for credentials; this looks for you.

The usual source is mundane. A global `user.email` set to a personal address signs every commit. An AI coding agent writes `/Users/<you>/...` into a design note, a `verify.log`, a lockfile or a `.patch` header. A shell prompt lands in a README. None of that is a secret, so none of it trips a secret scanner.

## Install

```sh
go install github.com/0-draft/kwangmyong/cmd/kwangmyong@latest
```

## Use

```sh
kwangmyong init                 # write ~/.config/kwangmyong/config.toml from what this machine reveals
kwangmyong identity             # show what will be searched for (redacted)
kwangmyong scan .               # tracked files, file names, commit and tag metadata
kwangmyong scan --history .     # plus every blob reachable from any ref
kwangmyong scan --history path/to/mirror.git   # bare mirrors: metadata and history
kwangmyong scan --staged        # only what the next commit adds, plus the pending author/committer
kwangmyong github kanywst       # issues, PRs, comments, reviews, releases, gists, repo metadata of an owner
kwangmyong github kanywst/repo  # one repository
kwangmyong plan .               # git filter-repo inputs and a force-push checklist for leaks in history
```

Exit status is `0` when clean, `1` when leaks are found, `2` on error, so it drops into a pre-commit hook, a pre-push hook, an agent hook or CI as is.

## GitHub

`kwangmyong github <owner>[/repo]` reads what a clone never contains: repository descriptions, homepages and topics, issue and pull request titles and bodies, issue comments, review comments, review bodies, release names and notes, and the owner's gists (secret ones too when the owner is you). It authenticates with `GH_TOKEN`, `GITHUB_TOKEN` or `gh auth token`. Archived repositories are included and forks are not by default (`--archived`, `--forks`); `--reviews=false` skips the one-request-per-PR review fetch.

It also checks every declared login against GitHub. A renamed account's old username keeps redirecting until someone registers it; from then on every `github.com/<old>/...` link, clone URL and Go module path points at them. A free former handle is reported as `github.unclaimed-handle`.

## Remediation plans

`kwangmyong plan [path]` scans contents, metadata and history, then writes three files to a new private temp directory (or `--out`), outside the repository because they hold the raw values:

- `replacements.txt` for `git filter-repo --replace-text` and `--replace-message`, with path-shaped rewrites (`/Users/x` → `~`, `-Users-x-` → `-HOME-`) ordered before bare values
- `mailmap` for `--mailmap`, mapping every leaking author, committer and tagger pair to `--to "Name <noreply>"` (default: the repository's resolved identity when it is a noreply address)
- `PLAN.md`: the first changed commit, how many commits get new SHAs, which tags move, a Go-module checksum warning when released tags are in range, and the backup, rewrite, verify, force-push and GitHub Support steps

When the leak is already public and the repository ships tagged releases, a content-only fix commit is often the better trade; the plan says so.

## Hooks

| Hook | Command | Checks |
| --- | --- | --- |
| git pre-commit | `kwangmyong hook pre-commit` | added lines and paths of the staged diff, the pending author and committer |
| git pre-push | `kwangmyong hook pre-push` | metadata and blobs of the commits being pushed |
| Claude Code `PreToolUse` | `kwangmyong hook claude` | `Write`/`Edit` content headed into a repository, `git commit` (including `git add -A && git commit`), `git push`, `gh` bodies and `--body-file` contents, GitHub MCP writes |

The Claude Code hook exits `2` to block the tool call and tells the agent why, with fingerprints only. File paths in a command are not treated as leaks (a scratch `--body-file` path contains your home directory by nature); the file's content is checked instead. Writes to ignored files and to files outside any repository pass.

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash|Write|Edit|MultiEdit|NotebookEdit|mcp__github__.*", "hooks": [{ "type": "command", "command": "kwangmyong hook claude" }] }
    ]
  }
}
```

With the [pre-commit](https://pre-commit.com) framework:

```yaml
repos:
  - repo: https://github.com/0-draft/kwangmyong
    rev: v0.1.0
    hooks:
      - id: kwangmyong
      - id: kwangmyong-pre-push
```

With lefthook:

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

Output never prints the matched value. It shows two leading characters and a fingerprint (`ta…[27fc08b6]`) so repeated hits of the same value line up, and `--reveal` prints raw values on your own terminal. `--format json` is available for tooling.

## Identity

Declare yourself once in the user config. Detection adds the login, home directory name, account full name, non-default hostname and global git identity of the current machine (`--no-auto` turns that off).

```toml
[identity]
names    = ["Taro Yamada", "山田 太郎", "やまだ たろう"]
logins   = ["tyamada", "old-github-handle"]
emails   = ["taro@example.com"]
hosts    = ["Taros-MacBook-Pro"]
literals = ["anything else that is you"]
```

Each entry expands into the spellings it leaks under:

| Kind | Expanded to |
| --- | --- |
| Latin name | both token orders; no, space, `.`, `_` or `-` separator; any case; initial forms (`tyamada`, `t.yamada`) |
| CJK name | both orders, with or without half-width, full-width or `・` separators |
| Login | `/Users/x`, `/home/x`, `C:\Users\x` (escaped too), `-Users-x-` agent slugs, `x@host`; as a bare word when 5+ characters |
| Email | plain and URL-encoded |
| Host | hyphenated and spaced, with the possessive form (`Taro's MacBook Pro`) |

GitHub noreply addresses are never reported.

The identity lives outside every repository on purpose. A repo-level `.kwangmyong.toml` may only carry `[allow]`; one with `[identity]` is rejected, because committing it would publish the thing it protects.

```toml
# .kwangmyong.toml
[allow]
paths  = ["testdata/**", "**/*_test.go"]
values = ["^example$"]
```

## Rules

| Rule | Severity | Finds |
| --- | --- | --- |
| `identity.email`, `.name`, `.login`, `.host`, `.literal` | high | your declared identity in any expanded spelling |
| `generic.autogen-email` | high | git-generated `user@Host.local` addresses |
| `generic.home-path` | warn | anyone's home path; CI runner and placeholder names are skipped |
| `github.unclaimed-handle` | warn | a declared login that is free to register on GitHub |

High findings fail the scan. `--strict` fails on warn too.

## How it differs

| | secret scanners (gitleaks, trufflehog, betterleaks, GitHub secret scanning) | PII frameworks (Presidio) | kwangmyong |
| --- | --- | --- | --- |
| Looks for | credentials | generic PII in text | *your* identity, from a declaration |
| Commit author/committer, trailers, tagger | reported as context, not scanned | no | scanned and aggregated |
| Name spellings | no | NER, weak on Japanese | declared and expanded deterministically |
| Agent-written paths and slugs | no | no | yes |
| Non-code GitHub surfaces | fetched, secrets only | no | fetched, identity rules |
| Remediation | no | redaction of text | filter-repo inputs and a rewrite checklist |
| Report leaks the value | often | n/a | no, fingerprints only |

## Not yet covered

- Wiki repositories and GitHub Pages builds outside the default branch (scan their git repositories directly)
- GitHub Actions logs and artifacts
- Discussions

## License

MIT
