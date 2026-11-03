// Command kwangmyong finds your own identity — real name, login, personal
// email, hostname, home paths — leaking from git repositories.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/0-draft/kwangmyong/internal/github"
	"github.com/0-draft/kwangmyong/internal/hook"
	"github.com/0-draft/kwangmyong/internal/identity"
	"github.com/0-draft/kwangmyong/internal/plan"
	"github.com/0-draft/kwangmyong/internal/report"
	"github.com/0-draft/kwangmyong/internal/rules"
	"github.com/0-draft/kwangmyong/internal/scan"
)

// version is set by goreleaser; `go install ...@vX` builds fall back to the
// module version recorded in the binary.
var version = "dev"

func currentVersion() string {
	if version != "dev" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return version
}

const usage = `kwangmyong — keep your identity inside.

Usage:
  kwangmyong scan [flags] [path]          scan a repository (default ".")
  kwangmyong github [flags] <owner>[/repo] scan issues, PRs, comments, reviews, releases, gists
  kwangmyong plan [flags] [path]          write a git filter-repo plan for the leaks in history
  kwangmyong hook <claude|pre-commit|pre-push>
                                          run as a hook (reads the hook payload on stdin)
  kwangmyong init                         write a user config pre-filled with detected identity
  kwangmyong identity                     show what will be searched for (redacted)
  kwangmyong version

Exit status: 0 clean, 1 leaks found (2 for "hook claude", which blocks the tool call), 2 error.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	var err error
	code := 0
	switch args[0] {
	case "scan":
		code, err = cmdScan(args[1:], stdout, stderr)
	case "github":
		code, err = cmdGitHub(args[1:], stdout, stderr)
	case "plan":
		err = cmdPlan(args[1:], stdout, stderr)
	case "hook":
		code, err = cmdHook(args[1:], os.Stdin, stderr)
	case "init":
		err = cmdInit(stdout)
	case "identity":
		err = cmdIdentity(args[1:], stdout, stderr)
	case "version", "--version":
		fmt.Fprintln(stdout, currentVersion())
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return 2
	}
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, "kwangmyong:", err)
		}
		return 2
	}
	return code
}

type common struct {
	config string
	noAuto bool
}

func (c *common) register(fs *flag.FlagSet) {
	fs.StringVar(&c.config, "config", "", "user config path (default $KWANGMYONG_CONFIG or ~/.config/kwangmyong/config.toml)")
	fs.BoolVar(&c.noAuto, "no-auto", false, "do not add the identity detected from this machine")
}

func (c *common) load() (identity.Identity, identity.Allow, error) {
	p := c.config
	if p == "" {
		var err error
		if p, err = identity.UserConfigPath(); err != nil {
			return identity.Identity{}, identity.Allow{}, err
		}
	}
	cfg, _, err := identity.LoadFile(p)
	if err != nil {
		return identity.Identity{}, identity.Allow{}, err
	}
	id := cfg.Identity
	if !c.noAuto {
		id = identity.Merge(id, identity.Detect())
	}
	return id.Normalize(), cfg.Allow, nil
}

func cmdScan(args []string, stdout, stderr io.Writer) (int, error) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c common
	c.register(fs)
	history := fs.Bool("history", false, "also scan every blob in git history")
	noTree := fs.Bool("no-tree", false, "skip tracked files")
	noMeta := fs.Bool("no-meta", false, "skip commit and tag metadata")
	format := fs.String("format", "text", "output format: text or json")
	reveal := fs.Bool("reveal", false, "print raw matched values (local terminal only)")
	strict := fs.Bool("strict", false, "fail on warn findings too")
	maxSize := fs.Int64("max-file-size", 5<<20, "skip files larger than this many bytes")
	staged := fs.Bool("staged", false, "scan only what the next commit adds (staged diff and pending identity)")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	root := "."
	if fs.NArg() > 0 {
		root = fs.Arg(0)
	}
	if *format != "text" && *format != "json" {
		return 2, fmt.Errorf("unknown format %q", *format)
	}

	id, allow, err := c.load()
	if err != nil {
		return 2, err
	}
	repoAllow, err := identity.LoadRepo(root)
	if err != nil {
		return 2, err
	}
	if id.Empty() {
		fmt.Fprintln(stderr, "kwangmyong: no identity declared or detected; only generic rules are active (run `kwangmyong init`)")
	}
	m, err := rules.New(identity.Expand(id), append(allow.Values, repoAllow.Values...))
	if err != nil {
		return 2, err
	}
	findings, err := scan.Run(m, scan.Options{
		Root:        root,
		Tree:        !*noTree,
		Meta:        !*noMeta,
		History:     *history,
		MaxFileSize: *maxSize,
		AllowPaths:  append(allow.Paths, repoAllow.Paths...),
		Staged:      *staged,
	})
	if err != nil {
		return 2, err
	}
	if *format == "json" {
		err = report.JSON(stdout, findings, *reveal)
	} else {
		err = report.Text(stdout, findings, *reveal)
	}
	if err != nil {
		return 2, err
	}
	s := report.Summarize(findings)
	if s.High > 0 || (*strict && s.Warn > 0) {
		return 1, nil
	}
	return 0, nil
}

func cmdInit(stdout io.Writer) error {
	p, err := identity.UserConfigPath()
	if err != nil {
		return err
	}
	if _, err := os.Stat(p); err == nil {
		return fmt.Errorf("%s already exists", p)
	}
	d := identity.Detect()
	var b strings.Builder
	b.WriteString("# kwangmyong user config. Keep this file out of every repository.\n")
	b.WriteString("# Detected values are pre-filled; add the spellings detection cannot know\n")
	b.WriteString("# (kanji/kana names, old usernames, other personal emails).\n\n[identity]\n")
	list := func(key string, vs []string) {
		q := make([]string, len(vs))
		for i, v := range vs {
			q[i] = fmt.Sprintf("%q", v)
		}
		fmt.Fprintf(&b, "%s = [%s]\n", key, strings.Join(q, ", "))
	}
	list("names", d.Names)
	list("logins", d.Logins)
	list("emails", d.Emails)
	list("hosts", d.Hosts)
	list("literals", nil)
	b.WriteString("\n[allow]\n# paths = [\"testdata/**\"]\n# values = [\"^example$\"]\n")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "wrote", p)
	return nil
}

func cmdIdentity(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("identity", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c common
	c.register(fs)
	reveal := fs.Bool("reveal", false, "print raw values")
	if err := fs.Parse(args); err != nil {
		return err
	}
	id, _, err := c.load()
	if err != nil {
		return err
	}
	p := identity.Expand(id)
	show := func(kind string, vs []string, n int) {
		out := make([]string, len(vs))
		for i, v := range vs {
			out[i] = rules.Redact(v)
			if *reveal {
				out[i] = v
			}
		}
		fmt.Fprintf(stdout, "%-8s %d declared, %d patterns: %s\n", kind, len(vs), n, strings.Join(out, ", "))
	}
	show("names", id.Names, len(p.Name))
	show("logins", id.Logins, len(p.Login))
	show("emails", id.Emails, len(p.Email))
	show("hosts", id.Hosts, len(p.Host))
	show("literals", id.Literals, len(p.Literal))
	return nil
}

// matcher loads identity and allow settings for root and builds the matcher.
func (c *common) matcher(root string, stderr io.Writer) (*rules.Matcher, identity.Identity, []string, error) {
	id, allow, err := c.load()
	if err != nil {
		return nil, id, nil, err
	}
	repoAllow, err := identity.LoadRepo(root)
	if err != nil {
		return nil, id, nil, err
	}
	if id.Empty() {
		fmt.Fprintln(stderr, "kwangmyong: no identity declared or detected; only generic rules are active (run `kwangmyong init`)")
	}
	m, err := rules.New(identity.Expand(id), append(allow.Values, repoAllow.Values...))
	return m, id, append(allow.Paths, repoAllow.Paths...), err
}

func output(stdout io.Writer, format string, reveal bool, findings []scan.Finding) error {
	if format == "json" {
		return report.JSON(stdout, findings, reveal)
	}
	return report.Text(stdout, findings, reveal)
}

func cmdGitHub(args []string, stdout, stderr io.Writer) (int, error) {
	fs := flag.NewFlagSet("github", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c common
	c.register(fs)
	forks := fs.Bool("forks", false, "include forks")
	archived := fs.Bool("archived", true, "include archived repositories")
	reviews := fs.Bool("reviews", true, "scan pull request review bodies (one request per PR)")
	gists := fs.Bool("gists", true, "scan the owner's gists")
	format := fs.String("format", "text", "output format: text or json")
	reveal := fs.Bool("reveal", false, "print raw matched values (local terminal only)")
	strict := fs.Bool("strict", false, "fail on warn findings too")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if fs.NArg() != 1 {
		return 2, errors.New("usage: kwangmyong github [flags] <owner>[/repo]")
	}
	owner, repo, _ := strings.Cut(fs.Arg(0), "/")
	m, id, _, err := c.matcher(".", stderr)
	if err != nil {
		return 2, err
	}
	client, err := github.NewClient()
	if err != nil {
		return 2, err
	}
	s := &github.Scanner{C: client, M: m}
	findings, err := s.Run(context.Background(), github.Options{
		Owner: owner, Repo: repo, IncludeForks: *forks, IncludeArchived: *archived,
		Reviews: *reviews, Gists: *gists, Handles: id.Logins,
	})
	if err != nil {
		return 2, err
	}
	if err := output(stdout, *format, *reveal, findings); err != nil {
		return 2, err
	}
	sum := report.Summarize(findings)
	if sum.High > 0 || (*strict && sum.Warn > 0) {
		return 1, nil
	}
	return 0, nil
}

func cmdPlan(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c common
	c.register(fs)
	to := fs.String("to", "", `identity to rewrite to, "Name <email>" (default: the repo's resolved git identity if it is a noreply address)`)
	out := fs.String("out", "", "directory for the plan (default: a new private temp dir, outside the repository)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	root := "."
	if fs.NArg() > 0 {
		root = fs.Arg(0)
	}
	target, err := resolveTarget(root, *to)
	if err != nil {
		return err
	}
	m, _, allowPaths, err := c.matcher(root, stderr)
	if err != nil {
		return err
	}
	findings, err := scan.Run(m, scan.Options{Root: root, Tree: true, Meta: true, History: true, AllowPaths: allowPaths})
	if err != nil {
		return err
	}
	p, err := plan.Build(root, m, findings, target)
	if err != nil {
		return err
	}
	dir := *out
	if dir == "" {
		if dir, err = os.MkdirTemp("", "kwangmyong-plan-"); err != nil {
			return err
		}
	}
	if err := p.Write(dir); err != nil {
		return err
	}
	if p.FirstChanged == "" {
		fmt.Fprintf(stdout, "no commit needs rewriting (%d value(s) in the working tree only)\n", p.Values)
	} else {
		fmt.Fprintf(stdout, "%d commit(s) from %s would be rewritten, %d tag(s) move\n", p.Commits, p.FirstChanged[:12], len(p.Tags))
	}
	fmt.Fprintf(stdout, "plan written to %s (holds raw values: keep it out of every repository)\n", dir)
	return nil
}

func resolveTarget(root, flagValue string) (plan.Target, error) {
	if flagValue != "" {
		return plan.ParseTarget(flagValue)
	}
	get := func(k string) string {
		out, err := exec.Command("git", "-C", root, "config", "--get", k).Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	}
	name, email := get("user.name"), get("user.email")
	if name == "" || !identity.IsNoreply(email) {
		return plan.Target{}, errors.New(`pass --to "Name <id+login@users.noreply.github.com>": the resolved git identity is not a noreply address`)
	}
	return plan.Target{Name: name, Email: email}, nil
}

func cmdHook(args []string, stdin io.Reader, stderr io.Writer) (int, error) {
	if len(args) == 0 {
		return 2, errors.New("usage: kwangmyong hook <claude|pre-commit|pre-push>")
	}
	fs := flag.NewFlagSet("hook", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c common
	c.register(fs)
	if err := fs.Parse(args[1:]); err != nil {
		return 2, err
	}
	root := "."
	m, _, allowPaths, err := c.matcher(root, io.Discard)
	if err != nil {
		return 2, err
	}
	env := hook.Env{Matcher: m, AllowPaths: allowPaths}
	var r hook.Result
	blockCode := 1
	switch args[0] {
	case "claude":
		// Claude Code: exit 2 blocks the tool call and feeds stderr back to Claude.
		blockCode = 2
		r, err = hook.Claude(env, stdin)
	case "pre-commit":
		r, err = hook.PreCommit(env, root, false)
	case "pre-push":
		r, err = hook.PrePush(env, root, stdin)
	default:
		return 2, fmt.Errorf("unknown hook %q", args[0])
	}
	if err != nil {
		return 2, err
	}
	if r.Block {
		fmt.Fprintln(stderr, r.Reason)
		return blockCode, nil
	}
	return 0, nil
}
