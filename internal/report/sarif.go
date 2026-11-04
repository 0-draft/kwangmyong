package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/kanywst/kwangmyong/internal/scan"
)

// SARIF writes findings as SARIF 2.1.0 for code scanning. Values are always
// masked: a SARIF file is made to be uploaded.
func SARIF(w io.Writer, fs []scan.Finding, version string) error {
	type text struct {
		Text string `json:"text"`
	}
	type rule struct {
		ID               string            `json:"id"`
		Name             string            `json:"name"`
		ShortDescription text              `json:"shortDescription"`
		HelpURI          string            `json:"helpUri"`
		Default          map[string]string `json:"defaultConfiguration"`
	}
	type artifact struct {
		URI string `json:"uri"`
	}
	type region struct {
		StartLine int `json:"startLine"`
	}
	type physical struct {
		Artifact artifact `json:"artifactLocation"`
		Region   *region  `json:"region,omitempty"`
	}
	type logical struct {
		Name string `json:"name"`
		Kind string `json:"kind"`
	}
	type location struct {
		Physical *physical `json:"physicalLocation,omitempty"`
		Logical  []logical `json:"logicalLocations,omitempty"`
	}
	type result struct {
		RuleID       string            `json:"ruleId"`
		Level        string            `json:"level"`
		Message      text              `json:"message"`
		Locations    []location        `json:"locations"`
		Fingerprints map[string]string `json:"partialFingerprints"`
	}

	rules := []rule{}
	seen := map[string]bool{}
	results := make([]result, 0, len(fs))
	for _, f := range fs {
		level := "warning"
		if f.Severity == "high" {
			level = "error"
		}
		if !seen[f.RuleID] {
			seen[f.RuleID] = true
			rules = append(rules, rule{
				ID: f.RuleID, Name: f.RuleID, ShortDescription: text{"Leaks " + Label(f.RuleID)},
				HelpURI: "https://github.com/kanywst/kwangmyong#rules", Default: map[string]string{"level": level},
			})
		}
		where, note := place(f)
		msg := fmt.Sprintf("%s (%s) in %s", strings.ToUpper(Label(f.RuleID)[:1])+Label(f.RuleID)[1:], f.Redacted, where)
		if note != "" {
			msg += ", " + note
		}
		if f.Count > 1 {
			msg += fmt.Sprintf(" (%d times)", f.Count)
		}
		var loc location
		if p := filePath(f); p != "" {
			loc.Physical = &physical{Artifact: artifact{URI: p}}
			if f.Line > 0 {
				loc.Physical.Region = &region{StartLine: f.Line}
			}
		} else {
			loc.Logical = []logical{{Name: strings.TrimSpace(f.Surface + " " + f.Location + " " + f.Field), Kind: "object"}}
		}
		sum := sha256.Sum256([]byte(strings.Join([]string{f.RuleID, f.Surface, f.Location, f.Field, fmt.Sprint(f.Line), f.Redacted}, "\x00")))
		results = append(results, result{
			RuleID: f.RuleID, Level: level, Message: text{msg}, Locations: []location{loc},
			Fingerprints: map[string]string{"kwangmyong/v1": hex.EncodeToString(sum[:16])},
		})
	}
	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{
				"name": "kwangmyong", "informationUri": "https://github.com/kanywst/kwangmyong",
				"version": version, "rules": rules,
			}},
			"results": results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// filePath is the repository path a finding points at, if it has one.
func filePath(f scan.Finding) string {
	switch f.Surface {
	case scan.SurfaceFile, scan.SurfaceStaged, scan.SurfacePath:
		return f.Location
	case scan.SurfaceHistory:
		p, _, _ := strings.Cut(f.Location, "@")
		return p
	}
	return ""
}
