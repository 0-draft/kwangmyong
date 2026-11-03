package plan

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0-draft/kwangmyong/internal/identity"
	"github.com/0-draft/kwangmyong/internal/rules"
	"github.com/0-draft/kwangmyong/internal/scan"
)

func gitRun(t *testing.T, dir string, env []string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1"), env...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func as(name, email string) []string {
	return []string{"GIT_AUTHOR_NAME=" + name, "GIT_AUTHOR_EMAIL=" + email, "GIT_COMMITTER_NAME=" + name, "GIT_COMMITTER_EMAIL=" + email}
}

func TestBuild(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	clean := as("kt", "1+kt@users.noreply.github.com")
	gitRun(t, dir, clean, "init", "-q")
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, clean, "add", "-A")
	gitRun(t, dir, clean, "commit", "-q", "-m", "clean start")
	gitRun(t, dir, clean, "tag", "v0.1.0")
	if err := os.WriteFile(filepath.Join(dir, "notes.md"), []byte("in /Users/tyamada/src\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, as("Taro Yamada", "taro@example.com"), "add", "-A")
	gitRun(t, dir, as("Taro Yamada", "taro@example.com"), "commit", "-q", "-m", "leak")
	gitRun(t, dir, clean, "tag", "v0.2.0")

	m, err := rules.New(identity.Expand(identity.Identity{Names: []string{"Taro Yamada"}, Logins: []string{"tyamada"}, Emails: []string{"taro@example.com"}}), nil)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := scan.Run(m, scan.Options{Root: dir, Tree: true, Meta: true, History: true})
	if err != nil {
		t.Fatal(err)
	}
	p, err := Build(dir, m, fs, Target{Name: "kt", Email: "1+kt@users.noreply.github.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Mailmap) != 1 || !strings.HasPrefix(p.Mailmap[0], "kt <1+kt@users.noreply.github.com> Taro Yamada <taro@example.com>") {
		t.Errorf("mailmap = %v", p.Mailmap)
	}
	if p.FirstChanged == "" || p.Commits != 1 {
		t.Errorf("first changed = %q commits = %d", p.FirstChanged, p.Commits)
	}
	if strings.Join(p.Tags, ",") != "v0.2.0" {
		t.Errorf("tags = %v (v0.1.0 predates the leak)", p.Tags)
	}
	joined := strings.Join(p.Replacements, "\n")
	pathIdx := strings.Index(joined, "literal:/Users/")
	plainIdx := strings.Index(joined, "literal:tyamada==>")
	if pathIdx < 0 || plainIdx < 0 || pathIdx > plainIdx {
		t.Errorf("path rewrites must precede the bare login:\n%s", joined)
	}

	out := filepath.Join(t.TempDir(), "plan")
	if err := p.Write(out); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(out, "replacements.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("replacements.txt must be owner-only, got %v", fi.Mode().Perm())
	}
	md, _ := os.ReadFile(filepath.Join(out, "PLAN.md"))
	if !strings.Contains(string(md), "--sensitive-data-removal") || !strings.Contains(string(md), p.FirstChanged) {
		t.Errorf("PLAN.md missing commands:\n%s", md)
	}
}

func TestParseTarget(t *testing.T) {
	tg, err := ParseTarget("kt <1+kt@users.noreply.github.com>")
	if err != nil || tg.Name != "kt" || tg.Email != "1+kt@users.noreply.github.com" {
		t.Errorf("%+v %v", tg, err)
	}
	if _, err := ParseTarget("no email"); err == nil {
		t.Error("want error")
	}
}
