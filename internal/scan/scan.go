// Package scan walks a repository's surfaces — tracked files, commit and tag
// metadata, and every historical blob — and reports identity leaks.
package scan

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/0-draft/kwangmyong/internal/rules"
)

// Finding is one reported leak. Value is never serialised; Redacted is.
type Finding struct {
	RuleID   string `json:"rule"`
	Severity string `json:"severity"`
	Surface  string `json:"surface"`
	Location string `json:"location"`
	Field    string `json:"field,omitempty"`
	Line     int    `json:"line,omitempty"`
	Count    int    `json:"count"`
	Redacted string `json:"value"`
	Value    string `json:"-"`
}

// Surfaces.
const (
	SurfaceFile    = "file"
	SurfacePath    = "path"
	SurfaceCommit  = "commit"
	SurfaceTag     = "tag"
	SurfaceHistory = "history"
)

// Options selects what to scan.
type Options struct {
	Root        string
	Tree        bool
	Meta        bool
	History     bool
	MaxFileSize int64
	AllowPaths  []string
}

// Run scans Root. Outside a git repository only the file tree is scanned.
func Run(m *rules.Matcher, opt Options) ([]Finding, error) {
	if opt.MaxFileSize <= 0 {
		opt.MaxFileSize = 5 << 20
	}
	s := &scanner{m: m, opt: opt, agg: map[string]*Finding{}}
	top, isGit, bare := gitTop(opt.Root)
	s.bare = bare
	if opt.Tree && !bare {
		var err error
		if isGit {
			err = s.gitTree(top)
		} else {
			err = s.walkTree(opt.Root)
		}
		if err != nil {
			return nil, err
		}
	}
	if isGit && opt.Meta {
		if err := s.commits(top); err != nil {
			return nil, err
		}
		if err := s.tags(top); err != nil {
			return nil, err
		}
	}
	if isGit && opt.History {
		if err := s.history(top); err != nil {
			return nil, err
		}
	}
	return s.result(), nil
}

type scanner struct {
	bare  bool
	m     *rules.Matcher
	opt   Options
	out   []Finding
	agg   map[string]*Finding
	order []string
}

func (s *scanner) pathAllowed(p string) bool {
	p = filepath.ToSlash(p)
	for _, g := range s.opt.AllowPaths {
		if matchGlob(g, p) {
			return true
		}
	}
	return false
}

// matchGlob supports path.Match patterns plus "**/" (any leading directories)
// and a trailing "/**" (everything below a directory).
func matchGlob(g, p string) bool {
	if strings.HasSuffix(g, "/**") && (p == strings.TrimSuffix(g, "/**") || strings.HasPrefix(p, strings.TrimSuffix(g, "**"))) {
		return true
	}
	if strings.HasPrefix(g, "**/") {
		rest := strings.TrimPrefix(g, "**/")
		for q := p; ; {
			if ok, _ := path.Match(rest, q); ok {
				return true
			}
			i := strings.IndexByte(q, '/')
			if i < 0 {
				return false
			}
			q = q[i+1:]
		}
	}
	ok, _ := path.Match(g, p)
	return ok
}

func (s *scanner) add(f Finding) {
	f.Count = 1
	f.Redacted = rules.Redact(f.Value)
	s.out = append(s.out, f)
}

// aggregate folds repeated hits (the same email on 20k commits) into one
// finding with a count.
func (s *scanner) aggregate(key string, f Finding) {
	if a, ok := s.agg[key]; ok {
		a.Count++
		return
	}
	f.Count = 1
	f.Redacted = rules.Redact(f.Value)
	s.agg[key] = &f
	s.order = append(s.order, key)
}

func (s *scanner) result() []Finding {
	out := append([]Finding{}, s.out...)
	for _, k := range s.order {
		out = append(out, *s.agg[k])
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Severity == "high" && out[j].Severity != "high" })
	return out
}

func (s *scanner) text(surface, location string, data []byte) {
	line := 1
	for len(data) > 0 {
		i := bytes.IndexByte(data, '\n')
		var l []byte
		if i < 0 {
			l, data = data, nil
		} else {
			l, data = data[:i], data[i+1:]
		}
		for _, mt := range s.m.Find(string(l)) {
			f := Finding{RuleID: mt.RuleID, Severity: mt.Severity.String(), Surface: surface, Location: location, Line: line, Value: mt.Value}
			if surface == SurfaceHistory {
				s.aggregate(strings.Join([]string{surface, location, mt.RuleID, strings.ToLower(mt.Value)}, "\x00"), f)
			} else {
				s.add(f)
			}
		}
		line++
	}
}

func (s *scanner) file(rel, abs string) error {
	if s.pathAllowed(rel) {
		return nil
	}
	for _, mt := range s.m.Find(filepath.ToSlash(rel)) {
		s.add(Finding{RuleID: mt.RuleID, Severity: mt.Severity.String(), Surface: SurfacePath, Location: filepath.ToSlash(rel), Value: mt.Value})
	}
	fi, err := os.Lstat(abs)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil // tracked but deleted in the worktree
		}
		return err
	}
	if !fi.Mode().IsRegular() || fi.Size() > s.opt.MaxFileSize {
		return nil
	}
	data, err := os.ReadFile(abs) //nolint:gosec // reading the user's own repo is the point
	if err != nil {
		return err
	}
	if isBinary(data) {
		return nil
	}
	s.text(SurfaceFile, filepath.ToSlash(rel), data)
	return nil
}

func isBinary(b []byte) bool {
	if len(b) > 8000 {
		b = b[:8000]
	}
	return bytes.IndexByte(b, 0) >= 0
}

func (s *scanner) walkTree(root string) error {
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		return s.file(rel, p)
	})
}

func (s *scanner) gitTree(top string) error {
	seen := map[string]bool{}
	// Tracked files plus untracked, non-ignored ones: those are what the next
	// `git add -A` would commit.
	out, err := git(top, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	if err != nil {
		return err
	}
	for _, rel := range strings.Split(string(out), "\x00") {
		if rel == "" || seen[rel] {
			continue
		}
		seen[rel] = true
		if err := s.file(rel, filepath.Join(top, filepath.FromSlash(rel))); err != nil {
			return err
		}
	}
	return nil
}

func (s *scanner) commits(top string) error {
	if _, err := git(top, "rev-parse", "-q", "--verify", "HEAD"); err != nil {
		return nil // no commits yet
	}
	cmd := exec.Command("git", "-C", top, "log", "--all", "--format=%H%x00%an%x00%ae%x00%cn%x00%ce%x00%B%x1e")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	sc.Split(splitOn(0x1e))
	for sc.Scan() {
		rec := strings.TrimLeft(sc.Text(), "\n")
		parts := strings.SplitN(rec, "\x00", 6)
		if len(parts) < 6 {
			continue
		}
		sha := parts[0]
		for i, field := range []string{"author.name", "author.email", "committer.name", "committer.email", "message"} {
			s.meta(SurfaceCommit, sha, field, parts[i+1])
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return cmd.Wait()
}

func (s *scanner) tags(top string) error {
	out, err := git(top, "for-each-ref", "refs/tags", "--format=%(refname:short)%00%(taggername)%00%(taggeremail:trim)%00%(contents)%1e")
	if err != nil {
		return err
	}
	for _, rec := range strings.Split(string(out), "\x1e") {
		parts := strings.SplitN(strings.TrimLeft(rec, "\n"), "\x00", 4)
		if len(parts) < 4 {
			continue
		}
		for i, field := range []string{"tagger.name", "tagger.email", "message"} {
			s.meta(SurfaceTag, parts[0], field, parts[i+1])
		}
	}
	return nil
}

func (s *scanner) meta(surface, ref, field, text string) {
	for _, mt := range s.m.Find(text) {
		key := strings.Join([]string{surface, field, mt.RuleID, strings.ToLower(mt.Value)}, "\x00")
		loc := ref
		if surface == SurfaceCommit && len(loc) > 7 {
			loc = loc[:7]
		}
		s.aggregate(key, Finding{RuleID: mt.RuleID, Severity: mt.Severity.String(), Surface: surface, Location: loc, Field: field, Value: mt.Value})
	}
}

// history scans every blob reachable from any ref that is not also in HEAD
// (those are covered by the tree scan).
func (s *scanner) history(top string) error {
	if _, err := git(top, "rev-parse", "-q", "--verify", "HEAD"); err != nil {
		return nil
	}
	head := map[string]bool{}
	if out, err := git(top, "ls-tree", "-r", "-z", "HEAD"); err == nil && !s.bare {
		for _, ent := range strings.Split(string(out), "\x00") {
			if f := strings.Fields(ent); len(f) >= 3 {
				head[f[2]] = true
			}
		}
	}
	out, err := git(top, "rev-list", "--all", "--objects", "--filter=object:type=blob")
	if err != nil {
		return err
	}
	type blob struct{ sha, path string }
	var blobs []blob
	seen := map[string]bool{}
	for _, l := range strings.Split(string(out), "\n") {
		sha, p, ok := strings.Cut(l, " ")
		if !ok || seen[sha] || head[sha] {
			continue // commits have no path; HEAD blobs are covered by the tree scan
		}
		seen[sha] = true
		if !s.pathAllowed(p) {
			blobs = append(blobs, blob{sha, p})
		}
	}
	if len(blobs) == 0 {
		return nil
	}
	cmd := exec.Command("git", "-C", top, "cat-file", "--batch")
	var in bytes.Buffer
	for _, b := range blobs {
		in.WriteString(b.sha + "\n")
	}
	cmd.Stdin = &in
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	r := bufio.NewReaderSize(stdout, 1<<20)
	for _, b := range blobs {
		hdr, err := r.ReadString('\n')
		if err != nil {
			return fmt.Errorf("cat-file: %w", err)
		}
		f := strings.Fields(hdr)
		if len(f) != 3 { // "<sha> missing"
			continue
		}
		size, err := strconv.ParseInt(f[2], 10, 64)
		if err != nil {
			return fmt.Errorf("cat-file header %q: %w", hdr, err)
		}
		// rev-list --objects also lists annotated tag objects under their name;
		// tag metadata is covered by the tag scan.
		if f[1] != "blob" || size > s.opt.MaxFileSize {
			if _, err := io.CopyN(io.Discard, r, size+1); err != nil {
				return err
			}
			continue
		}
		data := make([]byte, size+1)
		if _, err := io.ReadFull(r, data); err != nil {
			return err
		}
		data = data[:size]
		if !isBinary(data) {
			s.text(SurfaceHistory, b.path+"@"+b.sha[:7], data)
		}
	}
	return cmd.Wait()
}

// gitTop resolves the repository root. Bare repositories (mirror clones of a
// whole org) have no worktree: only metadata and history are scanned there.
func gitTop(root string) (top string, isGit, bare bool) {
	out, err := git(root, "rev-parse", "--is-bare-repository")
	if err != nil {
		return "", false, false
	}
	if strings.TrimSpace(string(out)) == "true" {
		return root, true, true
	}
	out, err = git(root, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", false, false
	}
	return strings.TrimSpace(string(out)), true, false
}

func git(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

func splitOn(sep byte) bufio.SplitFunc {
	return func(data []byte, atEOF bool) (int, []byte, error) {
		if i := bytes.IndexByte(data, sep); i >= 0 {
			return i + 1, data[:i], nil
		}
		if atEOF && len(data) > 0 {
			return len(data), data, nil
		}
		return 0, nil, nil
	}
}
