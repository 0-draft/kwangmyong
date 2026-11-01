package scan

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0-draft/kwangmyong/internal/identity"
	"github.com/0-draft/kwangmyong/internal/rules"
)

// The fixture identity is fictional.
var fixture = identity.Identity{
	Names:  []string{"Taro Yamada"},
	Logins: []string{"tyamada"},
	Emails: []string{"taro@example.com"},
}

func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=Taro Yamada", "GIT_AUTHOR_EMAIL=taro@example.com",
		"GIT_COMMITTER_NAME=Taro Yamada", "GIT_COMMITTER_EMAIL=taro@example.com",
	)
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

func newMatcher(t *testing.T) *rules.Matcher {
	t.Helper()
	m, err := rules.New(identity.Expand(fixture), nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func bySurface(fs []Finding) map[string][]Finding {
	out := map[string][]Finding{}
	for _, f := range fs {
		out[f.Surface] = append(out[f.Surface], f)
	}
	return out
}

func TestRunGitRepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q")
	write(t, filepath.Join(dir, "notes.md"), "built in /Users/tyamada/src\n")
	write(t, filepath.Join(dir, "testdata", "fixture.txt"), "/Users/tyamada\n")
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "first", "-m", "Signed-off-by: Taro Yamada <taro@example.com>")
	write(t, filepath.Join(dir, "notes.md"), "built in ~/src\n")
	gitRun(t, dir, "commit", "-q", "-am", "scrub")
	gitRun(t, dir, "tag", "-a", "v0.1.0", "-m", "release by tyamada")

	write(t, filepath.Join(dir, "untracked.md"), "draft by Taro Yamada\n")
	write(t, filepath.Join(dir, ".gitignore"), "ignored.md\n")
	write(t, filepath.Join(dir, "ignored.md"), "Taro Yamada\n")

	got, err := Run(newMatcher(t), Options{Root: dir, Tree: true, Meta: true, History: true, AllowPaths: []string{"testdata/**"}})
	if err != nil {
		t.Fatal(err)
	}
	s := bySurface(got)
	if len(s[SurfaceFile]) != 1 || s[SurfaceFile][0].Location != "untracked.md" {
		t.Errorf("tree: want only the untracked, non-ignored file, got %+v", s[SurfaceFile])
	}
	if len(s[SurfaceHistory]) != 1 || !strings.HasPrefix(s[SurfaceHistory][0].RuleID, "identity.") {
		t.Errorf("history: %+v", s[SurfaceHistory])
	}
	var authorEmail *Finding
	for i, f := range s[SurfaceCommit] {
		if f.Field == "author.email" {
			authorEmail = &s[SurfaceCommit][i]
		}
	}
	if authorEmail == nil || authorEmail.Count != 2 {
		t.Errorf("author email should aggregate over 2 commits: %+v", s[SurfaceCommit])
	}
	if len(s[SurfaceTag]) == 0 {
		t.Error("tag message leak not found")
	}
	for _, f := range got {
		if f.Redacted == f.Value {
			t.Errorf("value not redacted: %+v", f)
		}
	}
}

func TestRunPlainDir(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "a.txt"), "hello\ncontact taro@example.com\n")
	write(t, filepath.Join(dir, "tyamada-notes.txt"), "nothing\n")
	got, err := Run(newMatcher(t), Options{Root: dir, Tree: true, Meta: true, History: true})
	if err != nil {
		t.Fatal(err)
	}
	s := bySurface(got)
	if len(s[SurfaceFile]) != 1 || s[SurfaceFile][0].Line != 2 {
		t.Errorf("file: %+v", s[SurfaceFile])
	}
	if len(s[SurfacePath]) != 1 {
		t.Errorf("path: %+v", s[SurfacePath])
	}
}

func TestMatchGlob(t *testing.T) {
	for _, c := range []struct {
		g, p string
		want bool
	}{
		{"testdata/**", "testdata/a/b.txt", true},
		{"**/*_test.go", "internal/scan/scan_test.go", true},
		{"**/*_test.go", "scan_test.go", true},
		{"*.md", "docs/a.md", false},
		{"docs/*.md", "docs/a.md", true},
	} {
		if got := matchGlob(c.g, c.p); got != c.want {
			t.Errorf("matchGlob(%q,%q)=%v", c.g, c.p, got)
		}
	}
}
