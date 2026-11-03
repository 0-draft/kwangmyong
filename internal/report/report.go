// Package report renders findings as text or JSON.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/0-draft/kwangmyong/internal/scan"
)

// Summary counts findings by severity.
type Summary struct {
	High int `json:"high"`
	Warn int `json:"warn"`
}

// Summarize counts findings.
func Summarize(fs []scan.Finding) Summary {
	var s Summary
	for _, f := range fs {
		if f.Severity == "high" {
			s.High++
		} else {
			s.Warn++
		}
	}
	return s
}

// Text writes a table. reveal prints raw values.
func Text(w io.Writer, fs []scan.Finding, reveal bool) error {
	if len(fs) == 0 {
		_, err := fmt.Fprintln(w, "no identity leaks found")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, f := range fs {
		v := f.Redacted
		if reveal {
			v = f.Value
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", strings.ToUpper(f.Severity), f.RuleID, location(f), v)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	s := Summarize(fs)
	_, err := fmt.Fprintf(w, "\n%d findings (%d high, %d warn)\n", len(fs), s.High, s.Warn)
	return err
}

func location(f scan.Finding) string {
	loc := f.Surface + " " + f.Location
	if f.Line > 0 {
		loc += fmt.Sprintf(":%d", f.Line)
	}
	if f.Field != "" {
		loc += " " + f.Field
	}
	if f.Count > 1 {
		loc += fmt.Sprintf(" (x%d)", f.Count)
	}
	return loc
}

// JSON writes the summary and findings. reveal adds raw values.
func JSON(w io.Writer, fs []scan.Finding, reveal bool) error {
	type out struct {
		scan.Finding
		Raw string `json:"raw,omitempty"`
	}
	items := make([]out, 0, len(fs))
	for _, f := range fs {
		o := out{Finding: f}
		if reveal {
			o.Raw = f.Value
		}
		items = append(items, o)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		Summary  Summary `json:"summary"`
		Findings []out   `json:"findings"`
	}{Summarize(fs), items})
}
