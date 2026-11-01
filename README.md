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
```

Exit status is `0` when clean, `1` when leaks are found, `2` on error, so it drops into a pre-commit hook, a pre-push hook, an agent hook or CI as is.

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

High findings fail the scan. `--strict` fails on warn too.

## How it differs

| | secret scanners (gitleaks, trufflehog, betterleaks, GitHub secret scanning) | PII frameworks (Presidio) | kwangmyong |
| --- | --- | --- | --- |
| Looks for | credentials | generic PII in text | *your* identity, from a declaration |
| Commit author/committer, trailers, tagger | reported as context, not scanned | no | scanned and aggregated |
| Name spellings | no | NER, weak on Japanese | declared and expanded deterministically |
| Agent-written paths and slugs | no | no | yes |
| Report leaks the value | often | n/a | no, fingerprints only |

## Roadmap

- GitHub surfaces: issues, PR bodies and review comments, releases, wiki, gists, repository descriptions, Actions logs, org-wide
- Former-username takeover check (a renamed account's old name being free to register)
- Remediation plans: `git filter-repo --replace-text` and `--mailmap` inputs, plus the force-push checklist
- Hook adapters: pre-commit, lefthook and Claude Code `PreToolUse`

## License

MIT
