// Package plan turns a repository's identity leaks into a history-rewrite
// plan: git filter-repo inputs plus the checklist around a force-push.
package plan

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/0-draft/kwangmyong/internal/rules"
	"github.com/0-draft/kwangmyong/internal/scan"
)

var loginShaped = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// Target is the identity history is rewritten to.
type Target struct {
	Name  string
	Email string
}

// ParseTarget parses "Name <email>".
func ParseTarget(s string) (Target, error) {
	i, j := strings.LastIndex(s, "<"), strings.LastIndex(s, ">")
	if i <= 0 || j < i {
		return Target{}, fmt.Errorf("want \"Name <email>\", got %q", s)
	}
	return Target{Name: strings.TrimSpace(s[:i]), Email: strings.TrimSpace(s[i+1 : j])}, nil
}

// Plan is the computed remediation.
type Plan struct {
	Repo          string
	Remote        string
	Replacements  []string // git filter-repo --replace-text / --replace-message lines
	Mailmap       []string
	Idents        int
	Values        int
	FirstChanged  string
	FirstDate     string
	Commits       int // commits from FirstChanged on, which all get new SHAs
	Tags          []string
	GoModule      bool
	OpenPRWarning bool
}

// Build computes a plan for the repository at dir from scan findings.
func Build(dir string, m *rules.Matcher, fs []scan.Finding, to Target) (*Plan, error) {
	top, ok, _ := scan.TopLevel(dir)
	if !ok {
		return nil, fmt.Errorf("%s is not a git repository", dir)
	}
	p := &Plan{Repo: filepath.Base(top), OpenPRWarning: true}
	if out, err := git(top, "remote", "get-url", "origin"); err == nil {
		p.Remote = strings.TrimSpace(out)
	}

	values := map[string]string{} // raw value -> rule
	paths := map[string]bool{}
	for _, f := range fs {
		if f.Severity != "high" && f.RuleID != "generic.home-path" {
			continue
		}
		values[f.Value] = f.RuleID
		switch f.Surface {
		case scan.SurfaceFile, scan.SurfacePath:
			paths[f.Location] = true
		case scan.SurfaceHistory:
			if i := strings.LastIndex(f.Location, "@"); i > 0 {
				paths[f.Location[:i]] = true
			}
		}
	}
	p.Values = len(values)
	p.Replacements = replacements(values, to)

	// Mailmap: every (name, email) pair in commits or tags where either half leaks.
	idents, err := identPairs(top)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, id := range idents {
		if !leaks(m, id.name) && !leaks(m, id.email) {
			continue
		}
		line := fmt.Sprintf("%s <%s> %s <%s>", to.Name, to.Email, id.name, id.email)
		if !seen[line] {
			seen[line] = true
			p.Mailmap = append(p.Mailmap, line)
		}
	}
	sort.Strings(p.Mailmap)
	p.Idents = len(p.Mailmap)

	if err := p.firstChanged(top, m, paths); err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(top, "go.mod")); err == nil {
		p.GoModule = true
	}
	return p, nil
}

func leaks(m *rules.Matcher, s string) bool {
	for _, mt := range m.Find(s) {
		if mt.Severity == rules.High {
			return true
		}
	}
	return false
}

// replacements orders path-shaped rewrites before bare values, and longer
// values before their substrings, so "/Users/x/..." becomes "~/..." rather
// than "/Users/user/...".
func replacements(values map[string]string, to Target) []string {
	type kv struct{ v, rule string }
	var list []kv
	for v, r := range values {
		list = append(list, kv{v, r})
	}
	sort.Slice(list, func(i, j int) bool {
		if len(list[i].v) != len(list[j].v) {
			return len(list[i].v) > len(list[j].v)
		}
		return list[i].v < list[j].v
	})
	var paths, plain []string
	for _, e := range list {
		v := e.v
		// Any single-token value can sit in a home path ("tyamada" matched as a
		// name initial form is also the login): rewrite the path shape first.
		if loginShaped.MatchString(v) {
			paths = append(paths,
				"literal:/Users/"+v+"==>~",
				"literal:/home/"+v+"==>~",
				`literal:C:\Users\`+v+`==>%USERPROFILE%`,
				`literal:C:\\Users\\`+v+`==>%USERPROFILE%`,
				"literal:-Users-"+v+"-==>-HOME-",
			)
		}
		switch e.rule {
		case "generic.home-path":
			// someone's home path: rewrite the path, leave the bare word alone
		case "identity.login":
			plain = append(plain, "literal:"+v+"==>user")
		case "identity.email", "generic.autogen-email":
			plain = append(plain, "literal:"+v+"==>"+to.Email)
		case "identity.name":
			plain = append(plain, "literal:"+v+"==>"+to.Name)
		case "identity.host":
			plain = append(plain, "literal:"+v+"==>host")
		default:
			plain = append(plain, "literal:"+v+"==>REDACTED")
		}
	}
	return append(paths, plain...)
}

type ident struct{ name, email string }

func identPairs(top string) ([]ident, error) {
	if _, err := git(top, "rev-parse", "-q", "--verify", "HEAD"); err != nil {
		return nil, nil
	}
	out, err := git(top, "log", "--all", "--format=%an%x00%ae%n%cn%x00%ce")
	if err != nil {
		return nil, err
	}
	tags, err := git(top, "for-each-ref", "refs/tags", "--format=%(taggername)%00%(taggeremail:trim)")
	if err != nil {
		return nil, err
	}
	seen := map[ident]bool{}
	var res []ident
	sc := bufio.NewScanner(strings.NewReader(out + "\n" + tags))
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		name, email, ok := strings.Cut(sc.Text(), "\x00")
		if !ok || email == "" {
			continue
		}
		id := ident{name, email}
		if !seen[id] {
			seen[id] = true
			res = append(res, id)
		}
	}
	return res, sc.Err()
}

// firstChanged finds the oldest commit a rewrite would touch: one whose
// identity or message leaks, or that touches a file that leaks. Every commit
// after it in topological order gets a new SHA.
func (p *Plan) firstChanged(top string, m *rules.Matcher, paths map[string]bool) error {
	if _, err := git(top, "rev-parse", "-q", "--verify", "HEAD"); err != nil {
		return nil
	}
	out, err := git(top, "log", "--all", "--topo-order", "--reverse", "--format=%x1e%H%x00%cs%x00%an%x00%ae%x00%cn%x00%ce%x00%B%x00", "--name-only")
	if err != nil {
		return err
	}
	total := strings.Count(out, "\x1e")
	idx := 0
	for _, rec := range strings.Split(out, "\x1e") {
		if rec == "" {
			continue
		}
		idx++
		parts := strings.SplitN(rec, "\x00", 8)
		if len(parts) < 8 {
			continue
		}
		hit := false
		for _, f := range parts[2:7] {
			if leaks(m, f) {
				hit = true
			}
		}
		for _, f := range strings.Split(strings.TrimSpace(parts[7]), "\n") {
			if paths[strings.TrimSpace(f)] {
				hit = true
			}
		}
		if hit {
			p.FirstChanged, p.FirstDate = parts[0], parts[1]
			p.Commits = total - idx + 1
			break
		}
	}
	if p.FirstChanged == "" {
		return nil
	}
	tags, err := git(top, "tag", "--contains", p.FirstChanged)
	if err != nil {
		return err
	}
	p.Tags = append(p.Tags, strings.Fields(tags)...)
	return nil
}

// Write stores the plan in dir with owner-only permissions: the replacement
// file and mailmap hold the raw values being removed.
func (p *Plan) Write(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	files := map[string]string{
		"replacements.txt": strings.Join(p.Replacements, "\n") + "\n",
		"mailmap":          strings.Join(p.Mailmap, "\n") + "\n",
		"PLAN.md":          p.Markdown(dir),
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			return err
		}
	}
	return nil
}

// Markdown renders the checklist.
func (p *Plan) Markdown(dir string) string {
	var b bytes.Buffer
	remote := p.Remote
	if remote == "" {
		remote = "<remote-url>"
	}
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	w("# Remediation plan: %s", p.Repo)
	w("")
	w("This directory holds the raw values being removed. Keep it out of every repository and delete it when done.")
	w("")
	w("## Scope")
	w("")
	w("- %d leaking value(s) in contents and messages, %d leaking commit identity pair(s)", p.Values, p.Idents)
	if p.FirstChanged == "" {
		w("- No commit needs rewriting. Fix the working tree with a normal commit instead.")
		return b.String()
	}
	w("- First changed commit: `%s` (%s). It and the %d commit(s) after it get new SHAs.", p.FirstChanged, p.FirstDate, p.Commits-1)
	if len(p.Tags) > 0 {
		w("- Tags that move: %s", strings.Join(p.Tags, ", "))
	}
	w("")
	w("## Decide first")
	w("")
	if p.GoModule && len(p.Tags) > 0 {
		w("- This is a Go module with tags in the rewritten range. proxy.golang.org and sum.golang.org keep the old tag hashes, so `go get` of those versions fails checksum verification after the rewrite. Prefer a content-only fix commit, or never reuse the old tag names.")
	}
	w("- Public history has likely been cloned, forked and cached. A rewrite removes it from this repository, not from forks, clones or archives. If the values are already public, weigh switching to new ones (noreply email) against the cost of a rewrite.")
	w("- Signed commits lose their signatures. Closed pull requests lose their diffs; open ones must be merged or closed first.")
	w("")
	w("## Rewrite")
	w("")
	w("Needs git-filter-repo 2.47 or newer for `--sensitive-data-removal`.")
	w("")
	w("```sh")
	w("git clone --mirror %s %s.backup.git   # keep until the rewrite is verified", remote, p.Repo)
	w("git clone --mirror %s %s.git && cd %s.git", remote, p.Repo, p.Repo)
	w("git filter-repo --sensitive-data-removal \\")
	w("  --replace-text %s \\", filepath.Join(dir, "replacements.txt"))
	w("  --replace-message %s \\", filepath.Join(dir, "replacements.txt"))
	w("  --mailmap %s", filepath.Join(dir, "mailmap"))
	w("kwangmyong scan --history .   # must report no high findings")
	w("```")
	w("")
	w("## Publish")
	w("")
	w("1. Temporarily allow force-pushes on protected branches.")
	w("2. `git push --force --mirror origin` (refs/pull/* are read-only and will be rejected; that is expected).")
	w("3. Re-protect the branches. Re-create releases whose tags moved.")
	w("4. Ask GitHub Support to remove cached views and dereference the old commits; give them the first changed commit `%s` and the list of affected pull requests.", p.FirstChanged)
	w("5. Everyone with a clone re-clones; old clones must not be pushed back.")
	return b.String()
}

func git(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}
