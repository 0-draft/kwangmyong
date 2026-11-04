<img src="docs/logo.png" width="160" alt="kwangmyong: 虫眼鏡で身分証をのぞき込む泥棒">

# kwangmyong

[English](README.md) | 日本語

git リポジトリの中からあなたを探します。名前、ログイン名、メールアドレス、ホスト名、ホームディレクトリのパスを、ファイル、履歴、commit のメタデータ、GitHub 上から見つけます。secret scanner が探すのは鍵で、これが探すのはあなたです。

![架空の開発者のホームパス、ホスト名、名前、Claude Code のセッションリンクが入ったリポジトリで、gitleaks は何も見つけず、kwangmyong の対話画面が 6 件をたどり、Claude Code の hook が gh pr create を止め、きれいなリポジトリは TARGET DARK になる](docs/demo/demo.gif)

デモの開発者は架空の人物です。`vhs docs/demo/demo.tape` で撮り直せます。

コーディングエージェントは見たものを書きます。見えているのはあなたのマシンです。README に入る `/Users/you/...`、貼り付けたログの `you@your-laptop ~ %`、PR 本文の末尾に付く `claude.ai/code/session_...`。どれも秘密情報ではないので gitleaks は反応しません。kwangmyong はあなたが誰かを起点に、公開されるところを全部見ます。

## インストール

```sh
brew install --cask kanywst/tap/kwangmyong
```

Go からなら:

```sh
go install github.com/kanywst/kwangmyong/cmd/kwangmyong@latest
```

バイナリは [releases](https://github.com/kanywst/kwangmyong/releases) にあります。

## はじめかた

```sh
kwangmyong init               # このマシンの情報からプロファイルを書く
kwangmyong scan --history .   # 削除済みファイルも含めてこのリポジトリを調べる
kwangmyong hook install       # 以後の commit と push を毎回チェックする
```

## secret scanner との違い

secret scanner はそのまま使ってください。答えている問いが違います。

| | secret scanner (gitleaks、TruffleHog、GitHub secret scanning) | kwangmyong |
| --- | --- | --- |
| 探すもの | 認証情報: 鍵、トークン、パスワード | あなた: あらゆる表記の名前、ログイン名、メール、ホスト名、ホームパス、エージェントのセッションリンク |
| あなたを知っているか | 知らない。カスタム正規表現なら表記を 1 つ拾える | このマシンから埋めたプロファイルを表記揺れごと展開する (`Taro Yamada`、`tyamada`、`t.yamada`、`山田 太郎`、`-Users-tyamada-`) |
| commit の author、committer、tagger | 検出対象ではない | 値ごとに件数をまとめて検出する |
| 履歴に見つかったら | secret をローテートする | 名前はローテートできない。`plan` が書き換え手順を作り、書き換えでは消せない場所も挙げる |
| 出力 | secret そのもの、または伏せた形 | 既定で全部マスクする。エージェントに返す hook のメッセージも同じ |
| 動く場所 | CLI、pre-commit、CI | 対話画面、git hook、CI (Action、SARIF)、8 種類のコーディングエージェントの pre-tool hook |

デモのリポジトリに gitleaks 8.30.1 をかけると `no leaks found` になります。

## コマンド

```sh
kwangmyong scan [path]             # ファイル、ファイル名、commit と tag のメタデータ
kwangmyong scan --history [path]   # 加えて、まだ辿れる削除済み blob すべて
kwangmyong scan --staged           # 次の commit で増える分だけ
kwangmyong github <owner>[/repo]   # issue、PR、コメント、レビュー、release、gist
kwangmyong plan [path]             # git filter-repo の入力とチェックリスト
kwangmyong identity                # 何を探すか (マスク済み)
kwangmyong init                    # プロファイルを書く
kwangmyong hook <name>             # 下の「hook」を参照
```

終了コードは `0` が確実なものなし、`1` が検出あり、`2` がエラーです。`--strict` を付けると warn でも失敗します。

### 端末で動かしたとき

`scan` と `github` は全画面の対話ビューを開きます。調べている間は読んだ件数が動き、終わると見つかった場所ごとに、マスクした行、何が漏れているか、なぜまずいか、同じ値が他にどこにあるか、直し方を並べます。

| キー | |
| --- | --- |
| `↑` `↓` `j` `k` | 移動 |
| `←` `→` `tab` `1`-`5` | すべて、ファイル、履歴、メタデータ、GitHub |
| `/` | 検索。マスク後の文字列だけを見るので、検索で値が漏れることはない |
| `r` | この画面にだけ値を表示 |
| `e` | `$VISUAL` か `$EDITOR` でその行を開く |
| `p` | 履歴の書き換え手順を作る |
| `q` | 終了。判定はスクロールバックに残る |

何も見つからなければ自動で閉じます。

### それ以外

パイプ出力、`CI`、`--no-tui`、`KWANGMYONG_NO_TUI`、`--format json` や `sarif` ではレポートを出力します。場所ごとにマスクした行と下線、漏れている情報の種類と場所をまとめた intel report、判定のボックスの 3 部構成です。`TARGET EXPOSED` には threat level、ファイルを直せば済む件数と履歴に残っている件数、次に打つコマンドが付きます。`TARGET DARK` には何を調べて何を探したかが付きます。

値は先頭の数文字と fingerprint (`ta…[27fc08b6]`) で表示します。`--reveal` で生の値を出します。SARIF は `--reveal` に関係なく常にマスクします。色は端末では付き、パイプや `NO_COLOR` では付きません。

## プロファイル

```toml
# ~/.config/kwangmyong/config.toml
[identity]
names    = ["Taro Yamada", "山田 太郎"]
logins   = ["tyamada", "old-github-handle"]
emails   = ["taro@example.com"]
hosts    = ["Taros-MacBook-Pro"]
literals = []
```

このマシンのログイン名、ホームディレクトリ、フルネーム、ホスト名、global の git identity は毎回自動で加わります (`--no-auto` で外せます)。各項目は、実際に現れる形にも展開して照合します。

| 種類 | 加えて照合するもの |
| --- | --- |
| ラテン文字の名前 | 姓名の入れ替え、`.` `_` `-` 区切りか区切りなし、大文字小文字、`tyamada`、`t.yamada` |
| CJK の名前 | 姓名の入れ替え、半角・全角・`・` の区切りの有無 |
| ログイン名 | `/Users/x`、`/home/x`、`C:\Users\x`、`-Users-x-`、`x@host`。5 文字以上なら単語単体も |
| メール | URL エンコードした形 |
| ホスト名 | スペース区切りと所有格 (`Taro's MacBook Pro`) |

GitHub の noreply アドレスは報告しません。CI では同じ TOML を `KWANGMYONG_IDENTITY` に入れます。

リポジトリの `.kwangmyong.toml` ではパスと値の allowlist を書けます。`[identity]` は書けません。

```toml
[allow]
paths  = ["testdata/**", "**/*_test.go"]
values = ["^example$"]
```

## ルール

| ルール | 重大度 |
| --- | --- |
| `identity.name`、`.login`、`.email`、`.host`、`.literal` | high |
| `generic.autogen-email` (`user@Host.local`) | high |
| `generic.agent-session-url` (Claude Code と Codex のセッションリンク) | high |
| `generic.home-path` (誰かのホームパス) | warn |
| `github.unclaimed-handle` (誰でも取得できる昔のログイン名) | warn |

## GitHub

`kwangmyong github` は `GH_TOKEN`、`GITHUB_TOKEN`、`gh auth token` の順に token を読みます。fork は `--forks` を付けない限り飛ばします。レビュー本文は PR ごとに 1 リクエストかかるので、`--reviews=false` で省けます。

## 履歴の書き換え

`kwangmyong plan` は `replacements.txt`、`mailmap`、`PLAN.md` を非公開の一時ディレクトリに書きます (`--out` で場所を指定)。中身は生の値なので、どのリポジトリにも入れないでください。

```sh
git filter-repo --sensitive-data-removal \
  --replace-text replacements.txt --replace-message replacements.txt --mailmap mailmap
```

`PLAN.md` は、書き換えでは消せないもの (fork、clone、キャッシュ、署名、閉じた PR の diff) から始まり、最初に変わる commit、動く tag、force push の手順と続きます。リリース済みの tag を含む Go module なら、書き換えより修正 commit のほうが割に合うことが多いです。

## hook

### git

```sh
kwangmyong hook install   # このリポジトリに pre-commit、commit-msg、pre-push を入れる
```

| hook | 見るもの |
| --- | --- |
| `kwangmyong hook pre-commit` | stage した差分と、その commit が載せる identity |
| `kwangmyong hook commit-msg <file>` | コメントと verbose の diff を除いた commit メッセージ |
| `kwangmyong hook pre-push` | push する全 commit のメタデータと中身 |

[pre-commit](https://pre-commit.com):

```yaml
repos:
  - repo: https://github.com/kanywst/kwangmyong
    rev: v0
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

### コーディングエージェント

各エージェントの pre-tool hook は、ツール呼び出しを stdin に JSON で渡します。kwangmyong は shell コマンド (`git commit`、`git push`、`gh` の本文と本文ファイル)、リポジトリ内へのファイル書き込み、GitHub MCP への書き込みを調べ、止めるときは理由を stderr に出して `2` で終了します。

| エージェント | 設定 | 登録するもの |
| --- | --- | --- |
| Claude Code | `.claude/settings.json` | `PreToolUse`、matcher `Bash\|Write\|Edit\|MultiEdit\|NotebookEdit\|mcp__github__.*`、`kwangmyong hook claude` |
| Codex CLI | `.codex/hooks.json` | `PreToolUse`、matcher `Bash\|apply_patch\|mcp__github__.*`、`kwangmyong hook codex` |
| Gemini CLI | `.gemini/settings.json` | `BeforeTool`、matcher `run_shell_command\|write_file\|replace\|mcp_github_.*`、`kwangmyong hook gemini` |
| Cursor | `.cursor/hooks.json` | `beforeShellExecution`、`beforeMCPExecution`、`preToolUse`: `kwangmyong hook cursor` |
| GitHub Copilot | `.github/hooks/kwangmyong.json` | `preToolUse`: `kwangmyong hook copilot` |
| Windsurf | `.windsurf/hooks.json` | `pre_run_command`、`pre_write_code`、`pre_mcp_tool_use`: `kwangmyong hook windsurf` |
| Kiro | `.kiro/hooks/kwangmyong.json` | `PreToolUse`、matcher `shell\|write\|@mcp`: `kwangmyong hook kiro` |
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

各アダプタは、それぞれのエージェントが公開している hook の仕様に合わせています。バージョンで名前が変わるフィールドは、決め打ちせずに複数の候補を見ます。

## CI

```yaml
- uses: actions/checkout@v7
  with:
    fetch-depth: 0 # --history には全 commit が要る
- uses: kanywst/kwangmyong@v0
  with:
    identity: ${{ secrets.KWANGMYONG_IDENTITY }}
    sarif: kwangmyong.sarif
- uses: github/codeql-action/upload-sarif@v4
  if: always()
  with:
    sarif_file: kwangmyong.sarif
```

Action は release のバイナリを `checksums.txt` と照合してから入れ、`scan --history --strict .` を実行します (`args` で変えられます)。identity は secret に入れた TOML から読みます。キーは `[identity]` と同じです。

```toml
names  = ["Taro Yamada", "山田 太郎"]
logins = ["tyamada"]
emails = ["taro@example.com"]
```

GitHub Actions 以外では、同じ TOML を `KWANGMYONG_IDENTITY` に入れます。書式が壊れていても中身は出力せずに失敗します。ログの出力はマスク済みで、`--format sarif` は `--reveal` に関係なく常にマスクします。

## release の検証

v0.2.0 以降、各アーカイブには SBOM (`.sbom.json`) が付き、`checksums.txt` には release workflow が cosign keyless で署名しています。

```sh
cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/(kanywst|0-draft)/kwangmyong/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --ignore-missing -c checksums.txt
```

v0.4.0 より前の release は `0-draft/kwangmyong` から出ていたので、正規表現はそちらも通します。

## 対象外

- wiki (wiki のリポジトリを直接 scan してください)
- Actions のログと artifact
- Discussions

## ライセンス

MIT
