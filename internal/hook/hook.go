// Package hook runs kwangmyong from git hooks and Claude Code's PreToolUse.
package hook

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/0-draft/kwangmyong/internal/report"
	"github.com/0-draft/kwangmyong/internal/rules"
	"github.com/0-draft/kwangmyong/internal/scan"
)

// Result is a hook decision.
type Result struct {
	Block    bool
	What     string // what was stopped, "this commit"
	Reason   string
	Findings []scan.Finding
}

// Env is the matcher and allowlist a hook runs with.
type Env struct {
	Matcher    *rules.Matcher
	AllowPaths []string
}

func high(fs []scan.Finding) []scan.Finding {
	var out []scan.Finding
	for _, f := range fs {
		if f.Severity == "high" {
			out = append(out, f)
		}
	}
	return out
}

func decide(what string, fs []scan.Finding) Result {
	fs = high(fs)
	if len(fs) == 0 {
		return Result{}
	}
	var b strings.Builder
	_ = report.Blocked(&b, what, fs, report.Style{})
	return Result{Block: true, What: what, Reason: b.String(), Findings: fs}
}

// PreCommit checks the staged diff and the pending identity. pending adds
// unstaged and untracked changes, for `git add -A && git commit`.
func PreCommit(env Env, dir string, pending bool) (Result, error) {
	fs, err := scan.Run(env.Matcher, scan.Options{Root: dir, Staged: true, Pending: pending, AllowPaths: env.AllowPaths})
	if err != nil {
		return Result{}, err
	}
	return decide("this commit", fs), nil
}

const zeroSHA = "0000000000000000000000000000000000000000"

// PrePush checks the commits being pushed, read from git's pre-push stdin or
// from pre-commit's PRE_COMMIT_FROM_REF / PRE_COMMIT_TO_REF.
func PrePush(env Env, dir string, stdin io.Reader) (Result, error) {
	var ranges [][]string
	if from, to := os.Getenv("PRE_COMMIT_FROM_REF"), os.Getenv("PRE_COMMIT_TO_REF"); to != "" {
		if from == "" || strings.Trim(from, "0") == "" {
			ranges = append(ranges, []string{to, "--not", "--remotes"})
		} else {
			ranges = append(ranges, []string{from + ".." + to})
		}
	} else {
		sc := bufio.NewScanner(stdin)
		for sc.Scan() {
			f := strings.Fields(sc.Text())
			if len(f) != 4 || f[1] == zeroSHA { // deleting a remote ref pushes nothing
				continue
			}
			if f[3] == zeroSHA {
				ranges = append(ranges, []string{f[1], "--not", "--remotes"})
			} else {
				ranges = append(ranges, []string{f[3] + ".." + f[1]})
			}
		}
		if err := sc.Err(); err != nil {
			return Result{}, err
		}
	}
	var all []scan.Finding
	for _, r := range ranges {
		fs, err := scan.Run(env.Matcher, scan.Options{Root: dir, Meta: true, History: true, Revs: r, AllowPaths: env.AllowPaths})
		if err != nil {
			return Result{}, err
		}
		all = append(all, fs...)
	}
	return decide("this push", all), nil
}

type claudePayload struct {
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
	Cwd       string          `json:"cwd"`
}

type toolInput struct {
	Command   string `json:"command"`
	FilePath  string `json:"file_path"`
	Content   string `json:"content"`
	NewString string `json:"new_string"`
	NewSource string `json:"new_source"`
	Edits     []struct {
		NewString string `json:"new_string"`
	} `json:"edits"`
}

var (
	gitCommitRe = regexp.MustCompile(`(?:^|[;&|(]\s*|\s)git(?:\s+-C\s+(\S+))?(?:\s+-c\s+\S+)*\s+commit(?:\s|$)`)
	gitPushRe   = regexp.MustCompile(`(?:^|[;&|(]\s*|\s)git(?:\s+-C\s+(\S+))?(?:\s+-c\s+\S+)*\s+push(?:\s|$)`)
	gitAddRe    = regexp.MustCompile(`(?:^|[;&|(]\s*|\s)git(?:\s+-C\s+\S+)?\s+add(?:\s|$)`)
	commitAllRe = regexp.MustCompile(`\scommit\s(?:[^;&|]*\s)?(?:-a|-am|--all)\b`)
	ghPostRe    = regexp.MustCompile(`(?:^|[;&|(]\s*|\s)gh\s+(?:pr|issue|api|release|gist|repo)(?:\s|$)`)
)

// Claude checks a Claude Code PreToolUse payload.
func Claude(env Env, payload io.Reader) (Result, error) {
	var p claudePayload
	if err := json.NewDecoder(payload).Decode(&p); err != nil {
		return Result{}, fmt.Errorf("hook payload: %w", err)
	}
	var in toolInput
	_ = json.Unmarshal(p.ToolInput, &in) // unknown tools carry other shapes
	cwd := p.Cwd
	if cwd == "" {
		cwd = "."
	}

	switch {
	case p.ToolName == "Bash":
		return claudeBash(env, cwd, in.Command)
	case p.ToolName == "Write" || p.ToolName == "Edit" || p.ToolName == "MultiEdit" || p.ToolName == "NotebookEdit":
		texts := []string{in.Content, in.NewString, in.NewSource}
		for _, e := range in.Edits {
			texts = append(texts, e.NewString)
		}
		if !inRepo(in.FilePath, cwd) || pathAllowed(env, in.FilePath, cwd) {
			return Result{}, nil // scratch and ignored files never reach git
		}
		return decide("this write to "+filepath.Base(in.FilePath), textFindings(env, "write", filepath.Base(in.FilePath), texts...)), nil
	case strings.HasPrefix(p.ToolName, "mcp__github__"):
		var v any
		_ = json.Unmarshal(p.ToolInput, &v)
		return decide("this GitHub write", textFindings(env, "github", p.ToolName, strings.Join(stringsIn(v), "\n"))), nil
	}
	return Result{}, nil
}

func claudeBash(env Env, cwd, cmd string) (Result, error) {
	var all []scan.Finding
	if m := gitCommitRe.FindStringSubmatch(cmd); m != nil {
		dir := resolveDir(cwd, m[1])
		r, err := PreCommit(env, dir, gitAddRe.MatchString(cmd) || commitAllRe.MatchString(cmd))
		if err != nil {
			return Result{}, nil // not a repo or nothing staged: let git report it
		}
		all = append(all, r.Findings...)
		all = append(all, textFindings(env, "command", "git commit", stripPaths(cmd, cwd))...)
	}
	if m := gitPushRe.FindStringSubmatch(cmd); m != nil {
		dir := resolveDir(cwd, m[1])
		fs, err := scan.Run(env.Matcher, scan.Options{Root: dir, Meta: true, History: true, Revs: []string{"HEAD", "--not", "--remotes"}, AllowPaths: env.AllowPaths})
		if err == nil {
			all = append(all, fs...)
		}
	}
	if ghPostRe.MatchString(cmd) {
		all = append(all, textFindings(env, "command", "gh", stripPaths(cmd, cwd))...)
		for _, f := range pathTokens(cmd, cwd) {
			if data, err := os.ReadFile(f); err == nil {
				all = append(all, textFindings(env, "body-file", filepath.Base(f), string(data))...)
			}
		}
	}
	return decide("this command", all), nil
}

func textFindings(env Env, surface, location string, texts ...string) []scan.Finding {
	var out []scan.Finding
	for _, t := range texts {
		for i, line := range strings.Split(t, "\n") {
			for _, mt := range env.Matcher.Find(line) {
				out = append(out, scan.Finding{RuleID: mt.RuleID, Severity: mt.Severity.String(), Surface: surface, Location: location, Line: i + 1, Count: 1, Value: mt.Value, Redacted: rules.Redact(mt.Value)}.At(line, mt))
			}
		}
	}
	return out
}

// pathTokens returns the existing files named in cmd.
func pathTokens(cmd, cwd string) []string {
	var out []string
	for _, tok := range strings.Fields(cmd) {
		if p := tokenPath(tok, cwd); p != "" {
			if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
				out = append(out, p)
			}
		}
	}
	return out
}

// stripPaths drops tokens that name existing paths; those contain $HOME by
// nature and their contents are checked instead.
func stripPaths(cmd, cwd string) string {
	out := cmd
	for _, tok := range strings.Fields(cmd) {
		if p := tokenPath(tok, cwd); p != "" {
			if _, err := os.Stat(p); err == nil {
				out = strings.ReplaceAll(out, tok, "")
			}
		}
	}
	return out
}

func tokenPath(tok, cwd string) string {
	if i := strings.Index(tok, "="); i >= 0 {
		tok = tok[i+1:]
	}
	tok = strings.TrimRight(tok, ";&|)")
	tok = strings.TrimLeft(tok, "(")
	tok = strings.TrimPrefix(tok, "@")
	tok = strings.Trim(tok, `"'`)
	if tok == "" || strings.HasPrefix(tok, "-") {
		return ""
	}
	if strings.HasPrefix(tok, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			tok = filepath.Join(h, tok[2:])
		}
	}
	if !filepath.IsAbs(tok) {
		tok = filepath.Join(cwd, tok)
	}
	return tok
}

func resolveDir(cwd, dashC string) string {
	if dashC == "" {
		return cwd
	}
	dashC = strings.Trim(dashC, `"'`)
	if filepath.IsAbs(dashC) {
		return dashC
	}
	return filepath.Join(cwd, dashC)
}

// inRepo reports whether path is inside a git work tree and not ignored.
func inRepo(path, cwd string) bool {
	if path == "" {
		return false
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(cwd, path)
	}
	if resolved, err := filepath.EvalSymlinks(filepath.Dir(path)); err == nil {
		path = filepath.Join(resolved, filepath.Base(path))
	}
	dir := filepath.Dir(path)
	for {
		if _, err := os.Stat(dir); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
	if err := exec.Command("git", "-C", dir, "rev-parse", "--is-inside-work-tree").Run(); err != nil {
		return false
	}
	return exec.Command("git", "-C", dir, "check-ignore", "-q", path).Run() != nil
}

func pathAllowed(env Env, path, cwd string) bool {
	if !filepath.IsAbs(path) {
		path = filepath.Join(cwd, path)
	}
	top, ok, _ := scan.TopLevel(filepath.Dir(path))
	if !ok {
		return false
	}
	rel, err := filepath.Rel(top, path)
	if err != nil {
		return false
	}
	return scan.PathAllowed(env.AllowPaths, rel)
}

func stringsIn(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, e := range t {
			out = append(out, stringsIn(e)...)
		}
		return out
	case map[string]any:
		var out []string
		for _, e := range t {
			out = append(out, stringsIn(e)...)
		}
		return out
	}
	return nil
}
