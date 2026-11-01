// Command kwangmyong finds your own identity — real name, login, personal
// email, hostname, home paths — leaking from git repositories.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/0-draft/kwangmyong/internal/identity"
	"github.com/0-draft/kwangmyong/internal/report"
	"github.com/0-draft/kwangmyong/internal/rules"
	"github.com/0-draft/kwangmyong/internal/scan"
)

var version = "dev"

const usage = `kwangmyong — keep your identity inside.

Usage:
  kwangmyong scan [flags] [path]   scan a repository (default ".")
  kwangmyong init                  write a user config pre-filled with detected identity
  kwangmyong identity              show what will be searched for (redacted)
  kwangmyong version

Exit status: 0 clean, 1 leaks found, 2 error.
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
	case "init":
		err = cmdInit(stdout)
	case "identity":
		err = cmdIdentity(args[1:], stdout, stderr)
	case "version", "--version":
		fmt.Fprintln(stdout, version)
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
