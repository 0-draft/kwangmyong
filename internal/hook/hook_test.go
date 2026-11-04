package hook

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kanywst/kwangmyong/internal/identity"
	"github.com/kanywst/kwangmyong/internal/rules"
)

// The fixture identity is fictional.
func env(t *testing.T) Env {
	t.Helper()
	m, err := rules.New(identity.Expand(identity.Identity{
		Names: []string{"Taro Yamada"}, Logins: []string{"tyamada"}, Emails: []string{"taro@example.com"},
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	return Env{Matcher: m}
}

func gitEnv(name, email string) []string {
	return append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME="+name, "GIT_AUTHOR_EMAIL="+email, "GIT_COMMITTER_NAME="+name, "GIT_COMMITTER_EMAIL="+email)
}

func repo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	run(t, dir, gitEnv("kt", "1+kt@users.noreply.github.com"), "init", "-q")
	write(t, filepath.Join(dir, ".gitignore"), "scratch/\n")
	run(t, dir, gitEnv("kt", "1+kt@users.noreply.github.com"), "add", "-A")
	run(t, dir, gitEnv("kt", "1+kt@users.noreply.github.com"), "commit", "-q", "-m", "init")
	return dir
}

func run(t *testing.T, dir string, env []string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func write(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func claude(t *testing.T, e Env, tool, cwd string, input map[string]any) Result {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"tool_name": tool, "cwd": cwd, "tool_input": input})
	r, err := Claude(e, strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestClaudeWrite(t *testing.T) {
	dir, e := repo(t), env(t)
	if r := claude(t, e, "Write", dir, map[string]any{"file_path": filepath.Join(dir, "notes.md"), "content": "built at /Users/tyamada/src"}); !r.Block {
		t.Error("write of a tracked-to-be file with a home path must block")
	}
	if strings.Contains(claude(t, e, "Write", dir, map[string]any{"file_path": filepath.Join(dir, "notes.md"), "content": "built at /Users/tyamada/src"}).Reason, "tyamada") {
		t.Error("reason must not print the raw value")
	}
	if r := claude(t, e, "Write", dir, map[string]any{"file_path": filepath.Join(dir, "scratch", "log.txt"), "content": "/Users/tyamada"}); r.Block {
		t.Error("ignored file must not block")
	}
	if r := claude(t, e, "Edit", dir, map[string]any{"file_path": filepath.Join(dir, "a.md"), "new_string": "see ~/src"}); r.Block {
		t.Error("clean edit must not block")
	}
	outside := t.TempDir()
	if r := claude(t, e, "Write", outside, map[string]any{"file_path": filepath.Join(outside, "x.md"), "content": "Taro Yamada"}); r.Block {
		t.Error("write outside any repo must not block")
	}
}

func TestClaudeBashGh(t *testing.T) {
	dir, e := repo(t), env(t)
	// A body file whose *path* contains the login (like a scratchpad under a
	// -Users-<login>- slug) but whose content is clean must pass.
	clean := filepath.Join(t.TempDir(), "-Users-tyamada-proj", "body.md")
	write(t, clean, "Fixes the parser.\n")
	if r := claude(t, e, "Bash", dir, map[string]any{"command": "gh pr create --title fix --body-file " + clean + "; echo done"}); r.Block {
		t.Errorf("clean body file blocked: %s", r.Reason)
	}
	leaky := filepath.Join(t.TempDir(), "body.md")
	write(t, leaky, "repro on Taro's laptop: taro@example.com\n")
	if r := claude(t, e, "Bash", dir, map[string]any{"command": "gh issue create --body-file " + leaky}); !r.Block {
		t.Error("leaky body file must block")
	}
	if r := claude(t, e, "Bash", dir, map[string]any{"command": `gh issue comment 3 --body "thanks, Taro Yamada"`}); !r.Block {
		t.Error("inline body leak must block")
	}
}

func TestClaudeBashCommit(t *testing.T) {
	dir, e := repo(t), env(t)
	write(t, filepath.Join(dir, "x.go"), "// generated in /Users/tyamada/x\n")
	if r := claude(t, e, "Bash", dir, map[string]any{"command": "git add -A && git commit -m wip"}); !r.Block {
		t.Error("add+commit of a leaking untracked file must block")
	}
	if r := claude(t, e, "Bash", dir, map[string]any{"command": "git commit -m wip"}); r.Block {
		t.Errorf("plain commit with nothing staged should not inspect the worktree: %s", r.Reason)
	}
	if r := claude(t, e, "Bash", dir, map[string]any{"command": "git status"}); r.Block {
		t.Error("git status must pass")
	}
}

func TestPrePush(t *testing.T) {
	dir, e := repo(t), env(t)
	base := strings.TrimSpace(gitOut(t, dir, "rev-parse", "HEAD"))
	write(t, filepath.Join(dir, "a.txt"), "ok\n")
	run(t, dir, gitEnv("Taro Yamada", "taro@example.com"), "add", "-A")
	run(t, dir, gitEnv("Taro Yamada", "taro@example.com"), "commit", "-q", "-m", "x")
	head := strings.TrimSpace(gitOut(t, dir, "rev-parse", "HEAD"))
	r, err := PrePush(e, dir, strings.NewReader("refs/heads/main "+head+" refs/heads/main "+base+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !r.Block {
		t.Error("pushing a commit authored with a personal identity must block")
	}
	r, err = PrePush(e, dir, strings.NewReader("refs/heads/main "+base+" refs/heads/main "+base+"\n"))
	if err != nil || r.Block {
		t.Errorf("empty range must pass: %v %v", r, err)
	}
}

func gitOut(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).Output()
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}
