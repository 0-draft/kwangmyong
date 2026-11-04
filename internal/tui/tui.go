// Package tui is the interactive view: it runs the sweep with a live
// readout, then lets you walk every place you were found.
package tui

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/0-draft/kwangmyong/internal/report"
	"github.com/0-draft/kwangmyong/internal/scan"
	"github.com/0-draft/kwangmyong/internal/ui"
)

// Options configures a run.
type Options struct {
	Target string // shown in the header
	Looked string // what is searched for, without values
	Reveal bool   // start with values shown
	Root   string // where file locations are relative to, for opening them
	// Sweep runs the scan, reporting what it has read so far.
	Sweep func(progress func(scan.Stats)) ([]scan.Finding, scan.Stats, error)
	// Plan drafts the history rewrite and returns lines to show, if offered.
	Plan func() ([]string, error)
}

// Result is what the run found.
type Result struct {
	Findings []scan.Finding
	Stats    scan.Stats
	Browsed  bool // the findings were shown interactively
}

// Run takes over the terminal until the user quits.
func Run(in io.Reader, out io.Writer, opt Options) (Result, error) {
	m := newModel(opt)
	p := tea.NewProgram(m, tea.WithInput(in), tea.WithOutput(out))
	final, err := p.Run()
	if err != nil {
		return Result{}, err
	}
	fm := final.(*model)
	if fm.err != nil {
		return Result{}, fm.err
	}
	return Result{Findings: fm.fs, Stats: fm.stats, Browsed: len(fm.fs) > 0}, nil
}

type phase int

const (
	sweeping phase = iota
	browsing
)

type tab int

const (
	tabAll tab = iota
	tabFiles
	tabHistory
	tabMeta
	tabRemote
	nTabs
)

var tabNames = [nTabs]string{"ALL", "FILES", "HISTORY", "METADATA", "GITHUB"}

func tabOf(f scan.Finding) tab {
	switch f.Surface {
	case scan.SurfaceFile, scan.SurfacePath, scan.SurfaceStaged:
		return tabFiles
	case scan.SurfaceHistory:
		return tabHistory
	case scan.SurfaceCommit, scan.SurfaceTag:
		return tabMeta
	}
	return tabRemote
}

type (
	tickMsg struct{}
	doneMsg struct {
		fs    []scan.Finding
		stats scan.Stats
		err   error
	}
	editedMsg struct{ err error }
	planMsg   struct {
		lines []string
		err   error
	}
)

type model struct {
	opt   Options
	st    ui.Style
	w, h  int
	phase phase
	frame int

	mu   sync.Mutex
	live scan.Stats

	fs     []scan.Finding
	stats  scan.Stats
	err    error
	groups []report.Group

	tab      tab
	sel      int
	top      int
	reveal   bool
	query    string
	typing   bool
	note     string   // one-line message under the detail
	planOut  []string // plan summary shown in the detail pane
	planBusy bool
}

func newModel(opt Options) *model {
	return &model{opt: opt, st: ui.Style{Color: true}, w: 100, h: 30, reveal: opt.Reveal}
}

func tick() tea.Cmd {
	return tea.Tick(80*time.Millisecond, func(time.Time) tea.Msg { return tickMsg{} })
}

func (m *model) Init() tea.Cmd {
	sweep := func() tea.Msg {
		fs, st, err := m.opt.Sweep(func(s scan.Stats) {
			m.mu.Lock()
			m.live = s
			m.mu.Unlock()
		})
		return doneMsg{fs, st, err}
	}
	return tea.Batch(sweep, tick())
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
	case tickMsg:
		m.frame++
		if m.phase == sweeping {
			return m, tick()
		}
	case doneMsg:
		m.fs, m.stats, m.err = msg.fs, msg.stats, msg.err
		if m.err != nil || len(m.fs) == 0 {
			return m, tea.Quit
		}
		sort.SliceStable(m.fs, func(i, j int) bool { return m.fs[i].Severity == "high" && m.fs[j].Severity != "high" })
		m.groups = report.Groups(m.fs)
		m.phase = browsing
	case editedMsg:
		if msg.err != nil {
			m.note = "editor: " + msg.err.Error()
		}
	case planMsg:
		m.planBusy = false
		if msg.err != nil {
			m.planOut = []string{m.st.Paint(ui.Red, "plan failed: "+msg.err.Error())}
		} else {
			m.planOut = msg.lines
		}
	case tea.KeyPressMsg:
		return m.key(msg)
	}
	return m, nil
}

func (m *model) key(k tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	s := k.String()
	if s == "ctrl+c" {
		return m, tea.Quit
	}
	if m.phase == sweeping {
		if s == "q" || s == "esc" {
			return m, tea.Quit
		}
		return m, nil
	}
	if m.typing {
		switch s {
		case "enter":
			m.typing = false
		case "esc":
			m.typing, m.query = false, ""
		case "backspace":
			if r := []rune(m.query); len(r) > 0 {
				m.query = string(r[:len(r)-1])
			}
		default:
			if k.Text != "" {
				m.query += k.Text
			}
		}
		m.sel, m.top = 0, 0
		return m, nil
	}
	if m.planOut != nil && s != "q" {
		m.planOut = nil
		return m, nil
	}
	m.note = ""
	vis := m.visible()
	switch s {
	case "q", "esc":
		return m, tea.Quit
	case "down", "j":
		if m.sel < len(vis)-1 {
			m.sel++
		}
	case "up", "k":
		if m.sel > 0 {
			m.sel--
		}
	case "pgdown", "ctrl+d":
		m.sel = min(len(vis)-1, m.sel+m.listHeight()/2)
	case "pgup", "ctrl+u":
		m.sel = max(0, m.sel-m.listHeight()/2)
	case "home", "g":
		m.sel = 0
	case "end", "G":
		m.sel = max(0, len(vis)-1)
	case "tab", "right", "l":
		m.switchTab(1)
	case "shift+tab", "left", "h":
		m.switchTab(-1)
	case "1", "2", "3", "4", "5":
		m.tab, m.sel, m.top = tab(s[0]-'1'), 0, 0
	case "/":
		m.typing = true
	case "r":
		m.reveal = !m.reveal
	case "e":
		return m, m.edit(vis)
	case "p":
		if m.opt.Plan != nil && !m.planBusy {
			m.planBusy = true
			plan := m.opt.Plan
			return m, func() tea.Msg {
				lines, err := plan()
				return planMsg{lines, err}
			}
		}
	}
	return m, nil
}

func (m *model) switchTab(d int) {
	m.tab = tab((int(m.tab) + d + int(nTabs)) % int(nTabs))
	m.sel, m.top = 0, 0
}

// visible is the groups on the current tab that match the query. The query
// matches masked text only, so searching cannot reveal a value.
func (m *model) visible() []report.Group {
	st := report.Style{Style: m.st}.Masker(m.fs)
	q := strings.ToLower(m.query)
	var out []report.Group
	for _, g := range m.groups {
		if m.tab != tabAll && tabOf(g.Head) != m.tab {
			continue
		}
		if q != "" {
			where, note := st.Place(g.Head)
			hay := strings.ToLower(where + " " + note)
			for _, f := range g.Items {
				hay += " " + strings.ToLower(report.Label(f.RuleID)+" "+f.RuleID)
			}
			if !strings.Contains(hay, q) {
				continue
			}
		}
		out = append(out, g)
	}
	return out
}

func (m *model) edit(vis []report.Group) tea.Cmd {
	if len(vis) == 0 {
		return nil
	}
	f := vis[m.sel].Head
	if f.Surface != scan.SurfaceFile && f.Surface != scan.SurfaceStaged {
		m.note = "only files in the working tree open in an editor"
		return nil
	}
	editor := os.Getenv("VISUAL")
	if editor == "" {
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		editor = "vi"
	}
	args := strings.Fields(editor)
	if f.Line > 0 {
		args = append(args, fmt.Sprintf("+%d", f.Line))
	}
	args = append(args, filepath.Join(m.opt.Root, filepath.FromSlash(f.Location)))
	c := exec.Command(args[0], args[1:]...) //nolint:gosec // the user's own editor on their own file
	return tea.ExecProcess(c, func(err error) tea.Msg { return editedMsg{err} })
}

func (m *model) listHeight() int { return max(3, m.h-7) }

func (m *model) View() tea.View {
	var body string
	if m.phase == sweeping {
		body = m.viewSweep()
	} else {
		body = m.viewBrowse()
	}
	v := tea.NewView(body)
	v.AltScreen = true
	v.WindowTitle = "kwangmyong · recon on " + m.opt.Target
	return v
}

var spin = []string{"⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"}

func (m *model) viewSweep() string {
	m.mu.Lock()
	live := m.live
	m.mu.Unlock()
	st := m.st
	bar := ""
	for i := 0; i < 24; i++ {
		if (i+m.frame)%24 < 8 {
			bar += st.Paint(ui.Red, "▰")
		} else {
			bar += st.Paint(ui.Dim, "▱")
		}
	}
	noise := ""
	for i := 0; i < 8; i++ {
		noise += fmt.Sprintf("%02x ", (m.frame*37+i*91)%256)
	}
	lines := []string{
		report.Banner(st, m.opt.Target),
		st.Paint(ui.Bold+ui.Red, spin[m.frame%len(spin)]+" SWEEPING") + "  " + bar,
		"",
		readout(st, live),
		st.Paint(ui.Dim, "  looking for "+m.opt.Looked),
		"",
		st.Paint(ui.Dim, "  intercept "+noise),
		"",
		st.Paint(ui.Dim, "  q abort"),
	}
	return strings.Join(lines, "\n")
}

func readout(st ui.Style, live scan.Stats) string {
	n := func(v int, what string) string { return st.Paint(ui.Bold, fmt.Sprint(v)) + " " + what }
	if live.Repos > 0 {
		return "  " + n(live.Repos, "repositories swept")
	}
	return "  " + strings.Join([]string{n(live.Files, "files"), n(live.Commits, "commits"), n(live.Tags, "tags"), n(live.Blobs, "deleted blobs")}, "   ")
}

func (m *model) viewBrowse() string {
	st := m.st
	rs := report.Style{Style: st, Reveal: m.reveal}.Masker(m.fs)
	vis := m.visible()
	if m.sel >= len(vis) {
		m.sel = max(0, len(vis)-1)
	}

	// Header.
	total := 0
	for _, f := range m.fs {
		total += max(f.Count, 1)
	}
	left := strings.TrimRight(report.Banner(st, rs.Scrub(m.opt.Target)), "\n")
	right := rs.Threat(m.fs) + st.Paint(ui.Dim, fmt.Sprintf("  %d intel · %d places", total, len(m.groups)))
	header := pad(left, m.w-ansi.StringWidth(right)-1) + right

	// Tabs.
	var counts [nTabs]int
	for _, g := range m.groups {
		counts[tabAll]++
		counts[tabOf(g.Head)]++
	}
	var tabs []string
	for i := tab(0); i < nTabs; i++ {
		label := fmt.Sprintf(" %s %d ", tabNames[i], counts[i])
		switch {
		case i == m.tab:
			tabs = append(tabs, st.Paint("\x1b[1;97;41m", label))
		case counts[i] == 0:
			tabs = append(tabs, st.Paint(ui.Dim, label))
		default:
			tabs = append(tabs, label)
		}
	}
	tabLine := strings.Join(tabs, " ")
	if m.typing || m.query != "" {
		cursor := ""
		if m.typing {
			cursor = "▏"
		}
		tabLine += "   " + st.Paint(ui.Cyan, "/"+m.query+cursor)
	}
	if m.reveal {
		tabLine += "   " + st.Badge("97", "41", "REVEALED ON THIS SCREEN")
	}

	// Body.
	bh := m.listHeight()
	lw := min(max(m.w*36/100, 30), 56)
	rw := max(m.w-lw-3, 20)
	list := m.viewList(rs, vis, lw, bh)
	detail := m.viewDetail(rs, vis, rw, bh)
	var body []string
	for i := 0; i < bh; i++ {
		body = append(body, pad(at(list, i), lw)+" "+st.Paint(ui.Dim, "│")+" "+at(detail, i))
	}

	intel := st.Paint(ui.Bold, "INTEL ")
	for _, k := range kinds(m.fs) {
		intel += st.Paint(sevColor(k.sev), " ●") + " " + report.Label(k.rule) + st.Paint(ui.Dim, fmt.Sprintf(" %d×", k.n))
	}
	keys := st.Paint(ui.Dim, "↑↓ move  ←→ tab  / search  r reveal  e edit  ")
	if m.opt.Plan != nil {
		keys += st.Paint(ui.Dim, "p plan  ")
	}
	keys += st.Paint(ui.Dim, "q quit")
	if m.note != "" {
		keys = st.Paint(ui.Yellow, m.note)
	}
	rule := st.Paint(ui.Dim, strings.Repeat("─", max(m.w, 1)))
	out := []string{header, tabLine, rule}
	out = append(out, body...)
	out = append(out, rule, ansi.Truncate(intel, m.w, "…"), keys)
	for i := range out {
		out[i] = ansi.Truncate(out[i], m.w, "")
	}
	return strings.Join(out, "\n")
}

func (m *model) viewList(rs report.Style, vis []report.Group, w, h int) []string {
	if len(vis) == 0 {
		return []string{rs.Paint(ui.Dim, "nothing here")}
	}
	if m.sel < m.top {
		m.top = m.sel
	}
	if m.sel >= m.top+h {
		m.top = m.sel - h + 1
	}
	var out []string
	for i := m.top; i < len(vis) && len(out) < h; i++ {
		g := vis[i]
		where, note := rs.Place(g.Head)
		dot := rs.Paint(sevColor(g.Head.Severity), "●")
		line := " " + dot + " " + where
		if n := g.Head.Count; n > 1 {
			line += rs.Paint(ui.Dim, fmt.Sprintf(" ×%d", n))
		}
		var what []string
		seen := map[string]bool{}
		for _, f := range g.Items {
			if l := report.Label(f.RuleID); !seen[l] {
				seen[l] = true
				what = append(what, strings.TrimPrefix(l, "your "))
			}
		}
		if g.Head.Surface == scan.SurfaceHistory {
			note = "deleted"
		}
		tail := strings.Join(what, ", ")
		if note != "" {
			tail = note + " · " + tail
		}
		line += "  " + rs.Paint(ui.Dim, tail)
		line = ansi.Truncate(line, w-1, "…")
		if i == m.sel {
			line = rs.Paint(ui.Bold+ui.Red, "▸") + rs.Paint("\x1b[1;7m", pad(ansi.Strip(line), w-1))
		} else {
			line = " " + line
		}
		out = append(out, line)
	}
	return out
}

func (m *model) viewDetail(rs report.Style, vis []report.Group, w, h int) []string {
	if m.planBusy {
		return []string{rs.Paint(ui.Yellow, spin[m.frame%len(spin)]+" drafting the rewrite…")}
	}
	if m.planOut != nil {
		var out []string
		for _, l := range m.planOut {
			out = append(out, strings.Split(ansi.Hardwrap(l, w, true), "\n")...)
		}
		return append(out, "", rs.Paint(ui.Dim, "any key: back"))
	}
	if len(vis) == 0 {
		return nil
	}
	g := vis[m.sel]
	var out []string
	for _, l := range strings.Split(rs.Frame(g), "\n") {
		out = append(out, ansi.Truncate(l, w, "…"))
	}
	out = append(out, "")
	seen := map[string]bool{}
	for _, f := range g.Items {
		if seen[f.RuleID] {
			continue
		}
		seen[f.RuleID] = true
		v := f.Redacted
		if m.reveal {
			v = f.Value
		}
		out = append(out, rs.Paint(ui.Bold+ui.Red, "LEAKS ")+" "+rs.Paint(ui.Bold, report.Label(f.RuleID))+"  "+rs.Paint(sevColor(f.Severity), v))
		for i, l := range strings.Split(ansi.Wordwrap(report.Why(f.RuleID), w-7, " "), "\n") {
			label := "      "
			if i == 0 {
				label = rs.Paint(ui.Dim, "WHY   ")
			}
			out = append(out, label+" "+l)
		}
		if also := m.alsoIn(rs, g, f); also != "" {
			for i, l := range strings.Split(ansi.Wordwrap(also, w-7, " "), "\n") {
				label := "      "
				if i == 0 {
					label = rs.Paint(ui.Yellow, "ALSO  ")
				}
				out = append(out, label+" "+rs.Paint(ui.Dim, l))
			}
		}
	}
	kind := report.KindOf(g.Head)
	fix := report.Fix(kind, m.opt.Target)
	if kind == report.KindHistory && m.opt.Plan != nil {
		fix = "It is in history: a file edit does not remove it. Press p to draft the rewrite."
	}
	for i, l := range strings.Split(ansi.Wordwrap(fix, w-7, " "), "\n") {
		label := "      "
		if i == 0 {
			label = rs.Paint(ui.Cyan, "FIX   ")
		}
		out = append(out, label+" "+l)
	}
	if g.Head.Count > 1 {
		out = append(out, "", rs.Paint(ui.Dim, fmt.Sprintf("seen %d times; the first is shown", g.Head.Count)))
	}
	if len(out) > h {
		out = out[:h]
	}
	return out
}

// alsoIn lists the other places the same value was found.
func (m *model) alsoIn(rs report.Style, g report.Group, f scan.Finding) string {
	var places []string
	seen := map[string]bool{}
	here, _ := rs.Place(g.Head)
	for _, o := range m.fs {
		if !strings.EqualFold(o.Value, f.Value) {
			continue
		}
		p, _ := rs.Place(o)
		if p == here || seen[p] {
			continue
		}
		seen[p] = true
		places = append(places, p)
	}
	if len(places) == 0 {
		return ""
	}
	if len(places) > 6 {
		places = append(places[:6], fmt.Sprintf("+%d more", len(places)-6))
	}
	return "the same value is in " + strings.Join(places, ", ")
}

type kindCount struct {
	rule, sev string
	n         int
}

func kinds(fs []scan.Finding) []kindCount {
	idx := map[string]int{}
	var out []kindCount
	for _, f := range fs {
		i, ok := idx[f.RuleID]
		if !ok {
			i = len(out)
			idx[f.RuleID] = i
			out = append(out, kindCount{rule: f.RuleID, sev: f.Severity})
		}
		out[i].n += max(f.Count, 1)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].n > out[j].n })
	return out
}

func sevColor(sev string) string {
	if sev == "high" {
		return ui.Red
	}
	return ui.Yellow
}

func at(lines []string, i int) string {
	if i < len(lines) {
		return lines[i]
	}
	return ""
}

// pad fills s with spaces to w columns, or truncates it.
func pad(s string, w int) string {
	if n := ansi.StringWidth(s); n < w {
		return s + strings.Repeat(" ", w-n)
	}
	return ansi.Truncate(s, w, "")
}
