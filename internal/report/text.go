package report

import (
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/0-draft/kwangmyong/internal/scan"
	"github.com/0-draft/kwangmyong/internal/ui"
)

// Style controls the text renderer.
type Style struct {
	ui.Style
	Reveal bool // raw values instead of prefix + fingerprint

	others *regexp.Regexp // every value found, to mask wherever it appears
	redact map[string]string
}

// withOthers arms s to mask every value in fs inside any context line, not
// only the span its own finding points at: a line shown for one finding can
// hold a value whose finding was counted somewhere else.
func (s Style) withOthers(fs []scan.Finding) Style {
	if s.Reveal {
		return s
	}
	s.redact = map[string]string{}
	var alts []string
	for _, f := range fs {
		k := strings.ToLower(f.Value)
		if f.Value == "" || s.redact[k] != "" {
			continue
		}
		s.redact[k] = f.Redacted
		alt := regexp.QuoteMeta(f.Value)
		if len([]rune(f.Value)) < 4 { // short values only as whole words, as the rules match them
			alt = `\b` + alt + `\b`
		}
		alts = append(alts, alt)
	}
	if len(alts) == 0 {
		return s
	}
	sort.Slice(alts, func(i, j int) bool { return len(alts[i]) > len(alts[j]) })
	s.others = regexp.MustCompile("(?i)" + strings.Join(alts, "|"))
	return s
}

// scrub masks any found value left in plain text.
func (s Style) scrub(t string) string {
	if s.others == nil {
		return t
	}
	return s.others.ReplaceAllStringFunc(t, func(v string) string {
		if r, ok := s.redact[strings.ToLower(v)]; ok {
			return r
		}
		return v
	})
}

// Meta is what the verdict can say about the scan itself.
type Meta struct {
	Target string // what was swept, "." or "owner/repo"
	Stats  *scan.Stats
	Looked string // what was searched for, "2 names, 1 login"
}

// Banner is the header line every report starts with.
func Banner(s ui.Style, target string) string {
	b := s.Paint(ui.Bold+ui.Red, "★ 광명 KWANGMYONG ★")
	if target != "" {
		b += s.Paint(ui.Dim, "  recon on ") + s.Paint(ui.Bold, target) + s.Paint(ui.Dim, " · target: you")
	}
	return b + "\n\n"
}

// What each rule found, from the side of whoever reads it.
var labels = map[string]string{
	"identity.name":             "your name",
	"identity.login":            "your login",
	"identity.email":            "your email",
	"identity.host":             "your machine's name",
	"identity.literal":          "something on your list",
	"generic.autogen-email":     "an email your machine made up",
	"generic.home-path":         "someone's home directory",
	"generic.agent-session-url": "your agent's session link",
	"github.unclaimed-handle":   "a login anyone can still register",
}

// Label names what a rule found.
func Label(rule string) string {
	if l, ok := labels[rule]; ok {
		return l
	}
	return rule
}

func (s Style) sevColor(sev string) string {
	if sev == "high" {
		return ui.Red
	}
	return ui.Yellow
}

func (s Style) badge(sev string) string {
	if sev == "high" {
		return s.Badge("97", "41", "HIGH")
	}
	return s.Badge("30", "43", "WARN")
}

type fix int

const (
	fixFile    fix = iota // edit the file
	fixHistory            // needs a history rewrite
	fixRemote             // lives on GitHub or in a command
	fixIdent              // the identity git will commit with
	nFix
)

func fixOf(f scan.Finding) fix {
	if f.Location == "pending" && f.Surface == scan.SurfaceCommit {
		return fixIdent
	}
	switch f.Surface {
	case scan.SurfaceFile, scan.SurfacePath, scan.SurfaceStaged:
		return fixFile
	case scan.SurfaceHistory, scan.SurfaceCommit, scan.SurfaceTag:
		return fixHistory
	}
	return fixRemote
}

type group struct {
	head  scan.Finding
	items []scan.Finding
}

func groups(fs []scan.Finding) []*group {
	var out []*group
	idx := map[string]*group{}
	for _, f := range fs {
		k := strings.Join([]string{f.Surface, f.Location, f.Field, fmt.Sprint(f.Line), f.Context}, "\x00")
		g, ok := idx[k]
		if !ok {
			g = &group{head: f}
			idx[k] = g
			out = append(out, g)
		}
		if f.Severity == "high" {
			g.head.Severity = "high"
		}
		g.items = append(g.items, f)
	}
	return out
}

// place is a short where; note says what kind of place it is.
func place(f scan.Finding) (where, note string) {
	line := ""
	if f.Line > 0 {
		line = fmt.Sprintf(":%d", f.Line)
	}
	switch f.Surface {
	case scan.SurfaceFile:
		return f.Location + line, ""
	case scan.SurfaceStaged:
		return f.Location + line, "staged"
	case scan.SurfacePath:
		return f.Location, "in the file name"
	case scan.SurfaceHistory:
		p, blob := f.Location, ""
		if i := strings.LastIndexByte(f.Location, '@'); i >= 0 {
			p, blob = f.Location[:i], f.Location[i+1:]
		}
		return p + line, "deleted, but still in history (blob " + blob + ")"
	case scan.SurfaceCommit, scan.SurfaceTag:
		if f.Location == "pending" {
			return "your git identity", "what the next commit will carry as " + f.Field
		}
		return f.Surface + " " + f.Location, f.Field
	}
	return f.Surface + " " + f.Location + line, f.Field
}

// Text renders findings as masked, underlined lines, what they give away,
// and a verdict.
func Text(w io.Writer, fs []scan.Finding, meta Meta, s Style) error {
	s = s.withOthers(fs)
	var b strings.Builder
	b.WriteString(Banner(s.Style, s.scrub(meta.Target)))
	gs := groups(fs)
	gw := gutterWidth(gs)
	for _, g := range gs {
		s.frame(&b, g, gw)
	}
	if len(fs) > 0 {
		s.dossier(&b, fs)
	}
	s.verdict(&b, fs, len(gs), meta)
	_, err := io.WriteString(w, b.String())
	return err
}

// Blocked renders what a hook prints when it stops what.
// Only shown are framed; every value in all is masked wherever it appears.
func Blocked(w io.Writer, what string, shown, all []scan.Finding, s Style) error {
	s = s.withOthers(append(append([]scan.Finding{}, shown...), all...))
	fs := shown
	what = s.scrub(what)
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\n\n", s.Paint(ui.Bold+ui.Red, "✗ TRANSMISSION BLOCKED."), s.Paint(ui.Bold, "kwangmyong stopped "+what+": it would hand out intel on you."))
	gs := groups(fs)
	gw := gutterWidth(gs)
	for i, g := range gs {
		if i == 10 {
			fmt.Fprintf(&b, "  … and %d more\n\n", len(gs)-i)
			break
		}
		s.frame(&b, g, gw)
	}
	b.WriteString(s.Paint(ui.Cyan, "fix ▸") + " use ~/ or repo-relative paths, your public handle instead of a real name,\n")
	b.WriteString("      the GitHub noreply address as the commit email, and no agent session links.\n")
	_, err := io.WriteString(w, b.String())
	return err
}

func gutterWidth(gs []*group) int {
	w := 1
	for _, g := range gs {
		w = max(w, len(fmt.Sprint(g.head.Line)))
	}
	return w
}

func (s Style) frame(b *strings.Builder, g *group, gw int) {
	where, note := place(g.head)
	where = s.scrub(where)
	b.WriteString(s.badge(g.head.Severity) + " " + s.Paint(ui.Bold, where))
	if note != "" {
		b.WriteString(s.Paint(ui.Dim, "  "+note))
	}
	if n := g.head.Count; n > 1 {
		b.WriteString(s.Paint(ui.Dim, fmt.Sprintf("  ×%d", n)))
	}
	b.WriteString("\n")

	gutter := ""
	if g.head.Line > 0 {
		gutter = fmt.Sprint(g.head.Line)
	}
	gutter = fmt.Sprintf("%*s", gw, gutter)
	pad := strings.Repeat(" ", gw)
	line, marks := s.mask(g.items)
	if line != "" {
		fmt.Fprintf(b, "  %s %s %s\n", s.Paint(ui.Dim, gutter), s.Paint(ui.Dim, "│"), line)
	}
	for _, m := range marks {
		ch := "━"
		if !s.Color {
			ch = "^"
		}
		under := strings.Repeat(" ", m.col) + s.Paint(s.sevColor(m.sev), strings.Repeat(ch, max(m.w, 1))+" "+Label(m.rule))
		fmt.Fprintf(b, "  %s %s %s\n", pad, s.Paint(ui.Dim, "│"), under)
	}
	b.WriteString("\n")
}

type mark struct {
	col, w    int
	sev, rule string
}

const maxCols = 96

// mask returns the context line with every reported value replaced by its
// redacted form (raw with Reveal), trimmed to fit, and where each value
// landed.
func (s Style) mask(items []scan.Finding) (string, []mark) {
	ctx := items[0].Context
	var spans []scan.Finding
	for _, f := range items {
		if f.End > f.Start && f.End <= len(ctx) {
			spans = append(spans, f)
		}
	}
	if len(spans) == 0 {
		return "", nil
	}
	sort.SliceStable(spans, func(i, j int) bool { return spans[i].Start < spans[j].Start })

	type piece struct {
		text string
		f    *scan.Finding
	}
	var ps []piece
	at := 0
	for i := range spans {
		f := &spans[i]
		if f.Start < at {
			continue
		}
		ps = append(ps, piece{text: plain(s.scrub(ctx[at:f.Start]))})
		v := f.Redacted
		if s.Reveal {
			v = f.Value
		}
		ps = append(ps, piece{text: plain(v), f: f})
		at = f.End
	}
	ps = append(ps, piece{text: plain(s.scrub(ctx[at:]))})

	total := 0
	for _, p := range ps {
		total += ui.Width(p.text)
	}
	if total > maxCols {
		lead := &ps[0].text
		if over := total - maxCols; ui.Width(*lead) > 24 {
			cut := min(over, ui.Width(*lead)-24)
			*lead = "…" + ui.DropCols(*lead, cut+1)
			total -= cut
		}
		if total > maxCols {
			tail := &ps[len(ps)-1].text
			keep := max(ui.Width(*tail)-(total-maxCols)-1, 0)
			*tail = ui.KeepCols(*tail, keep) + "…"
		}
	}

	var out strings.Builder
	var marks []mark
	col := 0
	for _, p := range ps {
		if p.f == nil {
			out.WriteString(p.text)
		} else {
			out.WriteString(s.Paint(ui.Bold+s.sevColor(p.f.Severity), p.text))
			marks = append(marks, mark{col: col, w: ui.Width(p.text), sev: p.f.Severity, rule: p.f.RuleID})
		}
		col += ui.Width(p.text)
	}
	return out.String(), marks
}

// dossier lists what the findings give away, one line per kind.
func (s Style) dossier(b *strings.Builder, fs []scan.Finding) {
	type kind struct {
		rule, sev string
		n         int
		places    []string
		seen      map[string]bool
		values    []string
		seenV     map[string]bool
	}
	var kinds []*kind
	idx := map[string]*kind{}
	for _, f := range fs {
		k, ok := idx[f.RuleID]
		if !ok {
			k = &kind{rule: f.RuleID, sev: f.Severity, seen: map[string]bool{}, seenV: map[string]bool{}}
			idx[f.RuleID] = k
			kinds = append(kinds, k)
		}
		k.n += max(f.Count, 1)
		if p, _ := place(f); !k.seen[p] {
			p = s.scrub(p)
			k.seen[p] = true
			k.places = append(k.places, p)
		}
		v := f.Redacted
		if s.Reveal {
			v = f.Value
		}
		if key := strings.ToLower(f.Value); !k.seenV[key] {
			k.seenV[key] = true
			k.values = append(k.values, plain(v))
		}
	}
	sort.SliceStable(kinds, func(i, j int) bool {
		if (kinds[i].sev == "high") != (kinds[j].sev == "high") {
			return kinds[i].sev == "high"
		}
		return kinds[i].n > kinds[j].n
	})
	lw, nw, vw := 0, 0, 0
	vals := map[*kind]string{}
	for _, k := range kinds {
		lw = max(lw, ui.Width(Label(k.rule)))
		nw = max(nw, len(fmt.Sprint(k.n)))
		v := k.values
		if len(v) > 2 {
			v = append(v[:2:2], fmt.Sprintf("+%d", len(k.values)-2))
		}
		vals[k] = strings.Join(v, " ")
		vw = max(vw, ui.Width(vals[k]))
	}
	b.WriteString(s.Paint(ui.Bold, "INTEL REPORT"+s.Paint(ui.Dim, "  what anyone doing recon on you gets from this")) + "\n")
	for _, k := range kinds {
		where := k.places
		more := ""
		if len(where) > 3 {
			more = s.Paint(ui.Dim, fmt.Sprintf(" +%d more", len(where)-3))
			where = where[:3]
		}
		l := Label(k.rule)
		fmt.Fprintf(b, "  %s %s%s  %s%s  %s  %s%s\n",
			s.Paint(s.sevColor(k.sev), "●"),
			s.Paint(ui.Bold, l), strings.Repeat(" ", lw-ui.Width(l)),
			s.Paint(ui.Bold+s.sevColor(k.sev), vals[k]), strings.Repeat(" ", vw-ui.Width(vals[k])),
			s.Paint(s.sevColor(k.sev), fmt.Sprintf("%*d×", nw, k.n)),
			s.Paint(ui.Dim, strings.Join(where, " · ")), more)
	}
	b.WriteString("\n")
}

func (s Style) verdict(b *strings.Builder, fs []scan.Finding, places int, meta Meta) {
	sum := Summarize(fs)
	var lines []string
	next := ""
	color := ui.Green
	switch {
	case sum.High > 0:
		color = ui.Red
		total := 0
		var byFix [nFix]int
		for _, f := range fs {
			n := max(f.Count, 1)
			total += n
			if f.Severity == "high" {
				byFix[fixOf(f)] += n
			}
		}
		lines = append(lines, s.Paint(ui.Bold+ui.Red, "✗ TARGET EXPOSED")+"  "+
			s.Paint(ui.Bold, fmt.Sprintf("%d %s of intel on you, from %d %s", total, ui.Plural(total, "piece", "pieces"), places, ui.Plural(places, "place", "places"))))
		var parts []string
		if n := byFix[fixFile]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d to fix in files", n))
		}
		if n := byFix[fixHistory]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d baked into history", n))
		}
		if n := byFix[fixRemote]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d already out on GitHub", n))
		}
		if n := byFix[fixIdent]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d in the identity you commit with", n))
		}
		if sum.Warn > 0 {
			parts = append(parts, fmt.Sprintf("%d suspicious", sum.Warn))
		}
		lines = append(lines, "  "+strings.Join(parts, " · "), "  "+s.threat(fs))
		next = hint(byFix, meta.Target)
	case sum.Warn > 0:
		color = ui.Yellow
		lines = append(lines,
			s.Paint(ui.Bold+ui.Yellow, "? WEAK SIGNAL")+"  "+s.Paint(ui.Bold, fmt.Sprintf("%d %s that could be anyone's", sum.Warn, ui.Plural(sum.Warn, "thing", "things"))),
			"  nothing that is certainly you · --strict fails on these")
	default:
		lines = append(lines, s.Paint(ui.Bold+ui.Green, "✓ TARGET DARK")+"  "+s.Paint(ui.Bold, "No intel on you here."))
	}
	if r := readLine(meta.Stats); r != "" {
		lines = append(lines, s.Paint(ui.Dim, "  swept "+r))
	}
	if meta.Looked != "" {
		lines = append(lines, s.Paint(ui.Dim, "  looked for "+meta.Looked))
	}
	if len(fs) > 0 && !s.Reveal {
		lines = append(lines, s.Paint(ui.Dim, "  values are masked · --reveal shows them"))
	}
	if next != "" {
		lines = append(lines, "  "+s.Paint(ui.Cyan, "next ▸ ")+next)
	}
	b.WriteString(s.Box(color, lines))
}

var threatNames = [...]string{"", "low", "guarded", "elevated", "high", "severe"}

// threat rates exposure 1-5: one point per kind of intel that is certainly
// you, one more when it is baked into history.
func (s Style) threat(fs []scan.Finding) string {
	kinds := map[string]bool{}
	past := false
	for _, f := range fs {
		if f.Severity != "high" {
			continue
		}
		kinds[f.RuleID] = true
		past = past || fixOf(f) == fixHistory
	}
	n := len(kinds)
	if past {
		n++
	}
	n = min(max(n, 1), 5)
	meter := s.Paint(ui.Red, strings.Repeat("■", n)) + s.Paint(ui.Dim, strings.Repeat("□", 5-n))
	return "threat level " + meter + " " + s.Paint(ui.Bold+ui.Red, strings.ToUpper(threatNames[n]))
}

func readLine(st *scan.Stats) string {
	if st == nil {
		return ""
	}
	var parts []string
	add := func(n int, one, many string) {
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, ui.Plural(n, one, many)))
		}
	}
	add(st.Files, "file", "files")
	add(st.Commits, "commit", "commits")
	add(st.Tags, "tag", "tags")
	add(st.Blobs, "deleted blob", "deleted blobs")
	add(st.Repos, "repository", "repositories")
	return strings.Join(parts, " · ")
}

func hint(byFix [nFix]int, target string) string {
	if target == "" || target == "the next commit" {
		target = "."
	}
	switch {
	case byFix[fixIdent] > 0:
		return "commit as your GitHub noreply address and a public handle"
	case byFix[fixHistory] > 0:
		return "kwangmyong plan " + target + "  drafts the history rewrite for you to review"
	case byFix[fixFile] > 0:
		return "fix the lines above · kwangmyong hook pre-commit guards the next one"
	case byFix[fixRemote] > 0:
		return "edit or delete those on GitHub · a history rewrite does not reach them"
	}
	return ""
}

// plain makes text safe to print on one terminal line.
func plain(t string) string {
	var b strings.Builder
	for _, r := range t {
		switch {
		case r == '\t':
			b.WriteString("    ")
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			b.WriteRune('·')
		case r == utf8.RuneError:
			b.WriteRune('?')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
