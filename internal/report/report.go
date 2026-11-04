// Package report renders findings as text or JSON.
package report

import (
	"encoding/json"
	"io"

	"github.com/kanywst/kwangmyong/internal/scan"
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

// JSON writes the summary and findings. reveal adds raw values.
func JSON(w io.Writer, fs []scan.Finding, st *scan.Stats, reveal bool) error {
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
		Summary  Summary     `json:"summary"`
		Stats    *scan.Stats `json:"stats,omitempty"`
		Findings []out       `json:"findings"`
	}{Summarize(fs), st, items})
}
