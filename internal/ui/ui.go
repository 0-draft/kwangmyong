// Package ui is the terminal look shared by every command: colors that turn
// off off-terminal, display widths that count East Asian runes as two, and
// boxes.
package ui

import (
	"io"
	"os"
	"strings"
)

// Style decides whether to emit ANSI color.
type Style struct{ Color bool }

// For colors w when it is a terminal, unless NO_COLOR is set or TERM=dumb.
// CLICOLOR_FORCE or FORCE_COLOR turn color on anywhere.
func For(w io.Writer) Style {
	if os.Getenv("NO_COLOR") != "" {
		return Style{}
	}
	if os.Getenv("CLICOLOR_FORCE") != "" || os.Getenv("FORCE_COLOR") != "" {
		return Style{Color: true}
	}
	if os.Getenv("TERM") == "dumb" {
		return Style{}
	}
	f, ok := w.(*os.File)
	if !ok {
		return Style{}
	}
	fi, err := f.Stat()
	return Style{Color: err == nil && fi.Mode()&os.ModeCharDevice != 0}
}

// SGR codes.
const (
	Reset   = "\x1b[0m"
	Bold    = "\x1b[1m"
	Dim     = "\x1b[2m"
	Italic  = "\x1b[3m"
	Red     = "\x1b[31m"
	Green   = "\x1b[32m"
	Yellow  = "\x1b[33m"
	Blue    = "\x1b[34m"
	Magenta = "\x1b[35m"
	Cyan    = "\x1b[36m"
)

// Paint wraps text in codes when color is on.
func (s Style) Paint(codes, text string) string {
	if !s.Color || text == "" || codes == "" {
		return text
	}
	return codes + text + Reset
}

// Badge is a solid label such as " HIGH ".
func (s Style) Badge(fg, bg, text string) string {
	if !s.Color {
		return "[" + text + "]"
	}
	return "\x1b[1;" + fg + ";" + bg + "m " + text + " " + Reset
}

// Box draws lines inside a rounded border in color.
func (s Style) Box(color string, lines []string) string {
	w := 0
	for _, l := range lines {
		w = max(w, Width(l))
	}
	var b strings.Builder
	edge := strings.Repeat("─", w+2)
	side := s.Paint(color, "│")
	b.WriteString(s.Paint(color, "╭"+edge+"╮"))
	b.WriteString("\n")
	for _, l := range lines {
		b.WriteString(side)
		b.WriteString(" ")
		b.WriteString(l)
		b.WriteString(strings.Repeat(" ", w-Width(l)+1))
		b.WriteString(side)
		b.WriteString("\n")
	}
	b.WriteString(s.Paint(color, "╰"+edge+"╯"))
	b.WriteString("\n")
	return b.String()
}

// Width is the terminal column width of t, ignoring ANSI escapes.
func Width(t string) int {
	n := 0
	esc := false
	for _, r := range t {
		switch {
		case esc:
			if r >= '@' && r <= '~' && r != '[' {
				esc = false
			}
		case r == 0x1b:
			esc = true
		default:
			n += RuneWidth(r)
		}
	}
	return n
}

// RuneWidth is 2 for East Asian wide runes and wide emoji, else 1.
func RuneWidth(r rune) int {
	switch {
	case r >= 0x1100 && r <= 0x115f,
		r >= 0x2e80 && r <= 0xa4cf && r != 0x303f,
		r >= 0xac00 && r <= 0xd7a3,
		r >= 0xf900 && r <= 0xfaff,
		r >= 0xfe30 && r <= 0xfe4f,
		r >= 0xff00 && r <= 0xff60,
		r >= 0xffe0 && r <= 0xffe6,
		r >= 0x1f300 && r <= 0x1f64f,
		r >= 0x1f900 && r <= 0x1f9ff,
		r >= 0x20000 && r <= 0x3fffd:
		return 2
	}
	return 1
}

// DropCols removes at least n leading columns of plain text.
func DropCols(t string, n int) string {
	for i, r := range t {
		if n <= 0 {
			return t[i:]
		}
		n -= RuneWidth(r)
	}
	return ""
}

// KeepCols keeps at most n leading columns of plain text.
func KeepCols(t string, n int) string {
	for i, r := range t {
		if n -= RuneWidth(r); n < 0 {
			return t[:i]
		}
	}
	return t
}

// Plural picks one or many by n.
func Plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
