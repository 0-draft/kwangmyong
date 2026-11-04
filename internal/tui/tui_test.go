package tui

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/kanywst/kwangmyong/internal/identity"
	"github.com/kanywst/kwangmyong/internal/rules"
	"github.com/kanywst/kwangmyong/internal/scan"
)

// The fixture identity is fictional.
func fixture(t *testing.T) []scan.Finding {
	t.Helper()
	m, err := rules.New(identity.Expand(identity.Identity{Names: []string{"Taro Yamada"}, Logins: []string{"tyamada"}, Hosts: []string{"Taros-MacBook-Pro"}}), nil)
	if err != nil {
		t.Fatal(err)
	}
	var out []scan.Finding
	add := func(surface, loc string, line int, text string) {
		for _, mt := range m.Find(text) {
			out = append(out, scan.Finding{RuleID: mt.RuleID, Severity: mt.Severity.String(), Surface: surface, Location: loc, Line: line, Count: 1, Value: mt.Value, Redacted: rules.Redact(mt.Value)}.At(text, mt))
		}
	}
	add(scan.SurfaceFile, "test.log", 1, "tyamada@Taros-MacBook-Pro app % make test")
	add(scan.SurfaceFile, "README.md", 3, "Logs go to /Users/tyamada/src")
	add(scan.SurfaceHistory, "AUTHORS@686ce61", 1, "author: Taro Yamada")
	add(scan.SurfaceCommit, "4be81b9", 0, "https://claude.ai/code/session_01AbCdEfGh")
	return out
}

func browse(t *testing.T, fs []scan.Finding) *model {
	t.Helper()
	m := newModel(Options{Target: ".", Looked: "1 name"})
	m.Update(tea.WindowSizeMsg{Width: 140, Height: 40})
	m.Update(doneMsg{fs: fs})
	if m.phase != browsing {
		t.Fatal("findings should open the browser")
	}
	return m
}

func screen(m *model) string { return ansi.Strip(m.View().Content) }

func press(m *model, keys ...string) {
	for _, k := range keys {
		var msg tea.KeyPressMsg
		switch k {
		case "down":
			msg = tea.KeyPressMsg{Code: tea.KeyDown}
		case "tab":
			msg = tea.KeyPressMsg{Code: tea.KeyTab}
		case "enter":
			msg = tea.KeyPressMsg{Code: tea.KeyEnter}
		case "esc":
			msg = tea.KeyPressMsg{Code: tea.KeyEscape}
		default:
			r := []rune(k)[0]
			msg = tea.KeyPressMsg{Code: r, Text: k}
		}
		m.Update(msg)
	}
}

func TestBrowserMasksUntilRevealed(t *testing.T) {
	m := browse(t, fixture(t))
	for i := 0; i < 4; i++ {
		if out := screen(m); strings.Contains(out, "tyamada") || strings.Contains(out, "Taros-MacBook") || strings.Contains(out, "Taro Yamada") || strings.Contains(out, "session_01") {
			t.Fatalf("raw value on screen without reveal:\n%s", out)
		}
		press(m, "down")
	}
	press(m, "r")
	if out := screen(m); !strings.Contains(out, "REVEALED ON THIS SCREEN") || !strings.Contains(out, "session_01AbCdEfGh") {
		t.Errorf("reveal should show values and say so:\n%s", out)
	}
}

func TestTabsAndSearch(t *testing.T) {
	m := browse(t, fixture(t))
	press(m, "3") // HISTORY
	vis := m.visible()
	if len(vis) != 1 || vis[0].Head.Surface != scan.SurfaceHistory {
		t.Fatalf("history tab: %+v", vis)
	}
	if !strings.Contains(screen(m), "Press p") && m.opt.Plan != nil {
		t.Error("history fix should point at p")
	}
	press(m, "1", "/", "s", "e", "s", "s", "i", "o", "n", "enter")
	vis = m.visible()
	if len(vis) != 1 || vis[0].Head.Surface != scan.SurfaceCommit {
		t.Fatalf("search for session: %+v", vis)
	}
	// Searching for the raw value finds nothing: the query only sees masked text.
	press(m, "/", "esc", "/", "t", "y", "a", "m", "a", "d", "a", "enter")
	if len(m.visible()) != 0 {
		t.Error("search matched a raw value")
	}
}

func TestAlsoIn(t *testing.T) {
	m := browse(t, fixture(t))
	out := screen(m)
	if !strings.Contains(out, "the same value is in") {
		t.Errorf("cross-reference missing:\n%s", out)
	}
}

func TestCleanSweepQuits(t *testing.T) {
	m := newModel(Options{Target: "."})
	_, cmd := m.Update(doneMsg{})
	if cmd == nil || m.phase != sweeping {
		t.Fatal("a clean sweep should quit without browsing")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Error("expected quit")
	}
}

func TestSweepScreen(t *testing.T) {
	m := newModel(Options{Target: ".", Looked: "2 names"})
	m.live = scan.Stats{Files: 12, Commits: 3}
	out := screen(m)
	for _, want := range []string{"KWANGMYONG", "SWEEPING", "12 files", "3 commits", "looking for 2 names"} {
		if !strings.Contains(out, want) {
			t.Errorf("sweep screen missing %q:\n%s", want, out)
		}
	}
}

func TestSmallTerminalDoesNotPanic(t *testing.T) {
	m := browse(t, fixture(t))
	for _, sz := range [][2]int{{20, 5}, {1, 1}, {300, 80}} {
		m.Update(tea.WindowSizeMsg{Width: sz[0], Height: sz[1]})
		_ = m.View()
		press(m, "down", "tab", "r")
	}
}
