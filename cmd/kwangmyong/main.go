// Command kwangmyong finds your own identity leaking from git repositories.
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
	"sync"

	"github.com/0-draft/kwangmyong/internal/github"
	"github.com/0-draft/kwangmyong/internal/hook"
	"github.com/0-draft/kwangmyong/internal/identity"
	"github.com/0-draft/kwangmyong/internal/plan"
	"github.com/0-draft/kwangmyong/internal/report"
	"github.com/0-draft/kwangmyong/internal/rules"
	"github.com/0-draft/kwangmyong/internal/scan"
	"github.com/0-draft/kwangmyong/internal/ui"
)

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

type helpLine struct{ cmd, what string }

var helpSections = []struct {
	title string
	lines []helpLine
}{
	{"RECON", []helpLine{
		{"scan [path]", "files, file names, commit and tag metadata"},
		{"scan --history [path]", "plus every deleted blob still in history"},
		{"scan --staged", "only what the next commit adds"},
		{"github <owner>[/repo]", "issues, PRs, comments, reviews, releases, gists"},
	}},
	{"CLEANUP", []helpLine{
		{"plan [path]", "draft a git filter-repo rewrite and a checklist"},
	}},
	{"GUARD", []helpLine{
		{"hook pre-commit", "stop a commit that carries you"},
		{"hook pre-push", "stop a push that carries you"},
		{"hook claude", "Claude Code PreToolUse: stop the agent"},
	}},
	{"SETUP", []helpLine{
		{"init", "write your target profile, pre-filled from this machine"},
		{"identity", "show the target profile (masked)"},
		{"version", ""},
	}},
}

func printUsage(w io.Writer) {
	s := ui.For(w)
	var b strings.Builder
	b.WriteString(report.Banner(s, ""))
	b.WriteString(s.Paint(ui.Bold, "Secret scanners look for keys. This looks for you.") + "\n")
	b.WriteString("Your name, login, email, hostname, home paths and agent session links,\n")
	b.WriteString("in files, history, commit metadata and on GitHub.\n")
	cw := 0
	for _, sec := range helpSections {
		for _, l := range sec.lines {
			cw = max(cw, len(l.cmd))
		}
	}
	for _, sec := range helpSections {
		b.WriteString("\n" + s.Paint(ui.Bold+ui.Red, sec.title) + "\n")
		for _, l := range sec.lines {
			fmt.Fprintf(&b, "  %s %s%s  %s\n", s.Paint(ui.Dim, "kwangmyong"), s.Paint(ui.Cyan, l.cmd), strings.Repeat(" ", cw-len(l.cmd)), l.what)
		}
	}
	b.WriteString("\n" + s.Paint(ui.Cyan, "first run ▸ ") + "kwangmyong init && kwangmyong scan --history .\n")
	b.WriteString(s.Paint(ui.Dim, "exit 0 dark · 1 exposed · 2 error (hook claude exits 2 to block)") + "\n")
	b.WriteString(s.Paint(ui.Dim, "kwangmyong <command> -h shows its flags") + "\n")
	_, _ = io.WriteString(w, b.String())
}

// usageFor gives a subcommand a synopsis and a sentence above its flags.
func usageFor(fs *flag.FlagSet, w io.Writer, synopsis, what string) {
	fs.Usage = func() {
		s := ui.For(w)
		fmt.Fprintf(w, "%s %s\n\n%s\n\n%s\n", s.Paint(ui.Bold, "usage:"), "kwangmyong "+synopsis, what, s.Paint(ui.Bold, "flags:"))
		fs.PrintDefaults()
	}
}

// fail prints an error the same way everywhere.
func fail(w io.Writer, msg string) {
	s := ui.For(w)
	fmt.Fprintf(w, "%s %s\n", s.Paint(ui.Bold+ui.Red, "✗ kwangmyong:"), msg)
}

// tilde shows paths under the home directory as ~/..., so the output never
// prints the login it is protecting.
func tilde(p string) string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		if p == home {
			return "~"
		}
		if strings.HasPrefix(p, home+string(filepath.Separator)) {
			return "~" + p[len(home):]
		}
	}
	return p
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
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
		printUsage(stdout)
	default:
		fail(stderr, fmt.Sprintf("unknown command %q", args[0]))
		fmt.Fprintln(stderr)
		printUsage(stderr)
		return 2
	}
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fail(stderr, err.Error())
		}
		return 2
	}
	return code
}

type common struct {
	config string
	noAuto bool
}

// style colors output that goes to a terminal.
func (c *common) style(w io.Writer, reveal bool) report.Style {
	return report.Style{Style: ui.For(w), Reveal: reveal}
}

// looked says what a scan searches for, without the values.
func looked(id identity.Identity) string {
	var parts []string
	add := func(n int, one, many string) {
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, ui.Plural(n, one, many)))
		}
	}
	add(len(id.Names), "name", "names")
	add(len(id.Logins), "login", "logins")
	add(len(id.Emails), "email", "emails")
	add(len(id.Hosts), "host", "hosts")
	add(len(id.Literals), "literal", "literals")
	if len(parts) == 0 {
		return "home paths and agent session links only (no target profile: kwangmyong init)"
	}
	return strings.Join(parts, " · ") + " · home paths · agent session links"
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
	env, err := identity.LoadEnv()
	if err != nil {
		return identity.Identity{}, identity.Allow{}, err
	}
	id := identity.Merge(cfg.Identity, env.Identity)
	cfg.Allow.Paths = append(cfg.Allow.Paths, env.Allow.Paths...)
	cfg.Allow.Values = append(cfg.Allow.Values, env.Allow.Values...)
	if !c.noAuto {
		id = identity.Merge(id, identity.Detect())
	}
	return id.Normalize(), cfg.Allow, nil
}

func cmdScan(args []string, stdout, stderr io.Writer) (int, error) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	usageFor(fs, stderr, "scan [flags] [path]", "Sweep a repository for you: files, file names, commit and tag metadata,\nand with --history every deleted blob still reachable.")
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

	m, id, allowPaths, err := c.matcher(root, stderr)
	if err != nil {
		return 2, err
	}
	findings, stats, err := scan.RunStats(m, scan.Options{
		Root:        root,
		Tree:        !*noTree,
		Meta:        !*noMeta,
		History:     *history,
		MaxFileSize: *maxSize,
		AllowPaths:  allowPaths,
		Staged:      *staged,
	})
	if err != nil {
		return 2, err
	}
	target := root
	if *staged {
		target = "the next commit"
	}
	return finish(stdout, *format, c.style(stdout, *reveal), *strict, findings, report.Meta{Target: tilde(target), Stats: &stats, Looked: looked(id)})
}

func cmdInit(stdout io.Writer) error {
	p, err := identity.UserConfigPath()
	if err != nil {
		return err
	}
	if _, err := os.Stat(p); err == nil {
		return fmt.Errorf("a target profile already exists at %s: edit it, or delete it to start over", tilde(p))
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
	st := ui.For(stdout)
	var parts []string
	for _, k := range []struct {
		n         int
		one, many string
	}{{len(d.Names), "name", "names"}, {len(d.Logins), "login", "logins"}, {len(d.Emails), "email", "emails"}, {len(d.Hosts), "host", "hosts"}} {
		if k.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", k.n, ui.Plural(k.n, k.one, k.many)))
		}
	}
	found := "nothing detected; fill it in by hand"
	if len(parts) > 0 {
		found = "pre-filled from this machine: " + strings.Join(parts, " · ")
	}
	fmt.Fprint(stdout, report.Banner(st, "")+st.Box(ui.Green, []string{
		st.Paint(ui.Bold+ui.Green, "✓ TARGET PROFILE WRITTEN") + "  " + st.Paint(ui.Bold, tilde(p)),
		"  " + found,
		st.Paint(ui.Dim, "  add what detection cannot know: kanji or kana names, old handles, other emails"),
		st.Paint(ui.Dim, "  keep this file out of every repository"),
		"  " + st.Paint(ui.Cyan, "next ▸ ") + "kwangmyong identity · kwangmyong scan --history .",
	}))
	return nil
}

func cmdIdentity(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("identity", flag.ContinueOnError)
	fs.SetOutput(stderr)
	usageFor(fs, stderr, "identity [flags]", "Show the target profile: what kwangmyong searches for, masked.")
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
	st := ui.For(stdout)
	var b strings.Builder
	b.WriteString(report.Banner(st, ""))
	b.WriteString(st.Paint(ui.Bold, "TARGET PROFILE"))
	if !*reveal {
		b.WriteString(st.Paint(ui.Dim, "  values masked · --reveal shows them"))
	}
	b.WriteString("\n\n")
	show := func(kind string, vs []string, n int) {
		out := make([]string, len(vs))
		for i, v := range vs {
			out[i] = rules.Redact(v)
			if *reveal {
				out[i] = v
			}
		}
		vals := st.Paint(ui.Dim, "none")
		if len(out) > 0 {
			vals = st.Paint(ui.Bold+ui.Red, strings.Join(out, "  "))
		}
		spell := ""
		if n > 0 {
			spell = st.Paint(ui.Dim, fmt.Sprintf("  → %d %s searched", n, ui.Plural(n, "spelling", "spellings")))
		}
		fmt.Fprintf(&b, "  %s %s%s\n", st.Paint(ui.Cyan, fmt.Sprintf("%-8s", kind)), vals, spell)
	}
	show("names", id.Names, len(p.Name))
	show("logins", id.Logins, len(p.Login))
	show("emails", id.Emails, len(p.Email))
	show("hosts", id.Hosts, len(p.Host))
	show("literals", id.Literals, len(p.Literal))
	b.WriteString("\n")
	if c.noAuto {
		b.WriteString(st.Paint(ui.Dim, "  from the config only (--no-auto)") + "\n")
	} else {
		b.WriteString(st.Paint(ui.Dim, "  includes this machine's login, name, hostname and git identity (--no-auto drops them)") + "\n")
	}
	b.WriteString(st.Paint(ui.Dim, "  always on: anyone's home path, agent session links · never reported: GitHub noreply addresses") + "\n")
	if id.Empty() {
		b.WriteString("\n  " + st.Paint(ui.Cyan, "next ▸ ") + "kwangmyong init\n")
	}
	_, err = io.WriteString(stdout, b.String())
	return err
}

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
		st := ui.For(stderr)
		fmt.Fprintf(stderr, "%s no target profile: only generic rules run. %s sets one up.\n", st.Paint(ui.Bold+ui.Yellow, "! kwangmyong:"), st.Paint(ui.Cyan, "kwangmyong init"))
	}
	m, err := rules.New(identity.Expand(id), append(allow.Values, repoAllow.Values...))
	return m, id, append(allow.Paths, repoAllow.Paths...), err
}

func finish(stdout io.Writer, format string, st report.Style, strict bool, findings []scan.Finding, meta report.Meta) (int, error) {
	var err error
	if format == "json" {
		err = report.JSON(stdout, findings, meta.Stats, st.Reveal)
	} else {
		err = report.Text(stdout, findings, meta, st)
	}
	if err != nil {
		return 2, err
	}
	sum := report.Summarize(findings)
	if sum.High > 0 || (strict && sum.Warn > 0) {
		return 1, nil
	}
	return 0, nil
}

func cmdGitHub(args []string, stdout, stderr io.Writer) (int, error) {
	fs := flag.NewFlagSet("github", flag.ContinueOnError)
	fs.SetOutput(stderr)
	usageFor(fs, stderr, "github [flags] <owner>[/repo]", "Sweep what git filter-repo cannot reach: issues, PRs, comments, reviews,\nreleases, gists and repository metadata on GitHub.")
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
	if *format != "text" && *format != "json" {
		return 2, fmt.Errorf("unknown format %q", *format)
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
	var progress func(done, total int)
	if st := ui.For(stderr); st.Color {
		var mu sync.Mutex
		shown := 0
		progress = func(done, total int) {
			mu.Lock()
			defer mu.Unlock()
			if done < shown { // a later repo's callback won the race
				return
			}
			shown = done
			fmt.Fprintf(stderr, "\r\x1b[K%s sweeping github.com/%s  %d/%d %s", st.Paint(ui.Red, "★"), fs.Arg(0), done, total, ui.Plural(total, "repo", "repos"))
		}
	}
	findings, err := s.Run(context.Background(), github.Options{
		Owner: owner, Repo: repo, IncludeForks: *forks, IncludeArchived: *archived,
		Reviews: *reviews, Gists: *gists, Handles: id.Logins, Progress: progress,
	})
	if progress != nil {
		fmt.Fprint(stderr, "\r\x1b[K")
	}
	if err != nil {
		return 2, err
	}
	return finish(stdout, *format, c.style(stdout, *reveal), *strict, findings, report.Meta{Target: "github.com/" + fs.Arg(0), Looked: looked(id)})
}

func cmdPlan(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	usageFor(fs, stderr, "plan [flags] [path]", "Draft a git filter-repo rewrite (replacements.txt, mailmap, PLAN.md) for\nwhat scan --history finds. Writes outside the repository; changes nothing.")
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
	st := ui.For(stdout)
	lines := []string{}
	if p.FirstChanged == "" {
		lines = append(lines,
			st.Paint(ui.Bold+ui.Green, "✓ NOTHING TO REWRITE")+"  "+st.Paint(ui.Bold, "history is dark"),
			fmt.Sprintf("  %d %s in the working tree only: fix them in a normal commit", p.Values, ui.Plural(p.Values, "value", "values")))
	} else {
		lines = append(lines,
			st.Paint(ui.Bold+ui.Yellow, "✎ OPERATION CLEANUP")+"  "+st.Paint(ui.Bold, fmt.Sprintf("%d %s from %s get new SHAs", p.Commits, ui.Plural(p.Commits, "commit", "commits"), p.FirstChanged[:12])),
			"  "+planCounts(p))
	}
	lines = append(lines,
		"  wrote PLAN.md · replacements.txt · mailmap to "+st.Paint(ui.Bold, tilde(dir)),
		st.Paint(ui.Yellow, "  ! these files hold the raw values: keep them out of every repository"))
	if p.FirstChanged != "" {
		lines = append(lines, "  "+st.Paint(ui.Cyan, "next ▸ ")+"read PLAN.md, then run the git filter-repo command in it")
	}
	color := ui.Yellow
	if p.FirstChanged == "" {
		color = ui.Green
	}
	fmt.Fprint(stdout, report.Banner(st, "")+st.Box(color, lines))
	return nil
}

func planCounts(p *plan.Plan) string {
	var parts []string
	if p.Values > 0 {
		parts = append(parts, fmt.Sprintf("%d %s to replace", p.Values, ui.Plural(p.Values, "value", "values")))
	}
	if p.Idents > 0 {
		parts = append(parts, fmt.Sprintf("%d commit %s to remap", p.Idents, ui.Plural(p.Idents, "identity", "identities")))
	}
	if n := len(p.Tags); n > 0 {
		parts = append(parts, fmt.Sprintf("%d %s move", n, ui.Plural(n, "tag", "tags")))
	}
	return strings.Join(parts, " · ")
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
	usageFor(fs, stderr, "hook <claude|pre-commit|pre-push> [flags]", "Run as a guard. Reads the hook payload on stdin. Blocks with exit 1\n(exit 2 for claude, which Claude Code treats as a block).")
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
		if err := report.Blocked(stderr, r.What, r.Findings, r.All, c.style(stderr, false)); err != nil {
			return 2, err
		}
		return blockCode, nil
	}
	return 0, nil
}
