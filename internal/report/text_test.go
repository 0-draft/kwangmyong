package report

import (
	"strings"
	"testing"

	"github.com/0-draft/kwangmyong/internal/identity"
	"github.com/0-draft/kwangmyong/internal/rules"
	"github.com/0-draft/kwangmyong/internal/scan"
	"github.com/0-draft/kwangmyong/internal/ui"
)

func findings(t *testing.T, surface, location, text string) []scan.Finding {
	t.Helper()
	m, err := rules.New(identity.Expand(identity.Identity{Names: []string{"Taro Yamada", "山田 太郎"}, Hosts: []string{"Taros-MacBook-Pro"}}), nil)
	if err != nil {
		t.Fatal(err)
	}
	var out []scan.Finding
	for _, mt := range m.Find(text) {
		out = append(out, scan.Finding{RuleID: mt.RuleID, Severity: mt.Severity.String(), Surface: surface, Location: location, Line: 3, Count: 1, Value: mt.Value, Redacted: rules.Redact(mt.Value)}.At(text, mt))
	}
	return out
}

func render(t *testing.T, fs []scan.Finding, st *scan.Stats, s Style) string {
	t.Helper()
	return renderMeta(t, fs, Meta{Stats: st}, s)
}

func renderMeta(t *testing.T, fs []scan.Finding, meta Meta, s Style) string {
	t.Helper()
	var b strings.Builder
	if err := Text(&b, fs, meta, s); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestTextMasksEveryValue(t *testing.T) {
	fs := findings(t, scan.SurfaceFile, "test.log", "tyamada@Taros-MacBook-Pro app % make test")
	if len(fs) != 2 {
		t.Fatalf("want 2 findings, got %d", len(fs))
	}
	for _, s := range []Style{{}, {Style: ui.Style{Color: true}}} {
		out := render(t, fs, nil, s)
		if strings.Contains(out, "tyamada") || strings.Contains(out, "Taros-MacBook") {
			t.Errorf("raw value printed without --reveal:\n%s", out)
		}
	}
	out := render(t, fs, nil, Style{Reveal: true})
	if !strings.Contains(out, "tyamada@Taros-MacBook-Pro app % make test") {
		t.Errorf("--reveal should show the line as is:\n%s", out)
	}
}

func TestTextUnderlinesUnderTheValue(t *testing.T) {
	fs := findings(t, scan.SurfaceFile, "AUTHORS", "作者: 山田 太郎 です")
	out := render(t, fs, nil, Style{})
	lines := strings.Split(out, "\n")
	var ctx, under string
	for i, l := range lines {
		if strings.Contains(l, "│ 作者") {
			ctx, under = l, lines[i+1]
		}
	}
	if ctx == "" {
		t.Fatalf("no context line:\n%s", out)
	}
	tok := rules.Redact("山田 太郎")
	ti, xi := strings.Index(ctx, tok), strings.Index(under, "^")
	if ti < 0 || xi < 0 {
		t.Fatalf("value or underline missing:\n%s\n%s", ctx, under)
	}
	if ui.Width(ctx[:ti]) != ui.Width(under[:xi]) {
		t.Errorf("underline is not under the value:\n%s\n%s", ctx, under)
	}
	if !strings.Contains(under, "your name") {
		t.Errorf("label missing: %q", under)
	}
}

func TestTextColorOnlyWhenAsked(t *testing.T) {
	fs := findings(t, scan.SurfaceFile, "README.md", "by Taro Yamada")
	if out := render(t, fs, nil, Style{}); strings.Contains(out, "\x1b[") {
		t.Errorf("escape codes without color:\n%q", out)
	}
	if out := render(t, fs, nil, Style{Style: ui.Style{Color: true}}); !strings.Contains(out, "\x1b[") {
		t.Errorf("no escape codes with color")
	}
}

func TestTextVerdicts(t *testing.T) {
	st := &scan.Stats{Files: 3, Commits: 1}
	if out := render(t, nil, st, Style{}); !strings.Contains(out, "✓ TARGET DARK") || !strings.Contains(out, "swept 3 files · 1 commit") {
		t.Errorf("clean verdict:\n%s", out)
	}
	high := findings(t, scan.SurfaceHistory, "AUTHORS@686ce61", "by Taro Yamada")
	out := render(t, high, st, Style{})
	for _, want := range []string{"✗ TARGET EXPOSED", "1 piece of intel on you, from 1 place", "still in history", "1 baked into history", "kwangmyong plan .", "INTEL REPORT"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	warn := []scan.Finding{{RuleID: "generic.home-path", Severity: "warn", Surface: scan.SurfaceFile, Location: "x", Count: 1, Value: "hanako", Redacted: rules.Redact("hanako")}}
	if out := render(t, warn, nil, Style{}); !strings.Contains(out, "? WEAK SIGNAL") {
		t.Errorf("warn verdict:\n%s", out)
	}
}

func TestTextTrimsLongLines(t *testing.T) {
	long := strings.Repeat("a", 300) + " Taro Yamada " + strings.Repeat("b", 300)
	out := render(t, findings(t, scan.SurfaceFile, "big.txt", long), nil, Style{})
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "│") && !strings.HasPrefix(l, "│") && ui.Width(l) > maxCols+12 {
			t.Errorf("line not trimmed (%d cols): %s", ui.Width(l), l)
		}
	}
	if !strings.Contains(out, "…") {
		t.Errorf("no ellipsis:\n%s", out)
	}
}

func TestBlocked(t *testing.T) {
	var b strings.Builder
	if err := Blocked(&b, "this commit", findings(t, scan.SurfaceStaged, "notes.md", "Taro Yamada"), Style{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.HasPrefix(out, "✗ TRANSMISSION BLOCKED. kwangmyong stopped this commit") || strings.Contains(out, "Taro") {
		t.Errorf("blocked message:\n%s", out)
	}
}
