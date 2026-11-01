// Package rules turns identity patterns and built-in generic detectors into a
// matcher over text.
package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/0-draft/kwangmyong/internal/identity"
)

// Severity orders findings. High findings fail a scan by default.
type Severity int

// Severities.
const (
	Warn Severity = iota
	High
)

func (s Severity) String() string {
	if s == High {
		return "high"
	}
	return "warn"
}

// Rule is one detector.
type Rule struct {
	ID       string
	Severity Severity
	re       *regexp.Regexp
	// skip is checked against the first non-empty capture group.
	skip func(value string) bool
	// whole reports the full match instead of the capture group.
	whole bool
}

// Match is one hit inside a string.
type Match struct {
	RuleID   string
	Severity Severity
	Value    string
	Start    int
	End      int
}

// Matcher runs rules in priority order (identity first, generic last).
type Matcher struct {
	rules []Rule
	allow []*regexp.Regexp
}

// DefaultAllowValues are values never reported.
var DefaultAllowValues = []string{`(?i)@users\.noreply\.github\.com$`}

// New builds a matcher. allowValues are regexps matched against a hit's value.
func New(p identity.Patterns, allowValues []string) (*Matcher, error) {
	m := &Matcher{}
	add := func(id string, sev Severity, frags []string) error {
		if len(frags) == 0 {
			return nil
		}
		re, err := regexp.Compile(`(?i)(?:` + strings.Join(frags, "|") + `)`)
		if err != nil {
			return fmt.Errorf("rule %s: %w", id, err)
		}
		m.rules = append(m.rules, Rule{ID: id, Severity: sev, re: re})
		return nil
	}
	for _, r := range []struct {
		id    string
		frags []string
	}{
		{"identity.email", p.Email},
		{"identity.name", p.Name},
		{"identity.login", p.Login},
		{"identity.host", p.Host},
		{"identity.literal", p.Literal},
	} {
		if err := add(r.id, High, r.frags); err != nil {
			return nil, err
		}
	}
	m.rules = append(m.rules, generic()...)
	for _, v := range append(append([]string{}, DefaultAllowValues...), allowValues...) {
		re, err := regexp.Compile(v)
		if err != nil {
			return nil, fmt.Errorf("allow value %q: %w", v, err)
		}
		m.allow = append(m.allow, re)
	}
	return m, nil
}

func generic() []Rule {
	return []Rule{
		{
			// A git-generated address (user@Host.local) carries login and hostname.
			ID:       "generic.autogen-email",
			Severity: High,
			re:       regexp.MustCompile(`(?i)\b([a-z0-9._%+-]+)@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:local|lan|localdomain)\b`),
			skip:     identity.IsPlaceholderLogin,
			whole:    true,
		},
		{
			// Any user's home directory: the leak shape AI agents produce most.
			ID:       "generic.home-path",
			Severity: Warn,
			re:       regexp.MustCompile(`(?:/Users/|/home/|[A-Za-z]:(?:\\\\|\\|/)Users(?:\\\\|\\|/))([A-Za-z0-9][A-Za-z0-9._-]*)|-Users-([A-Za-z0-9][A-Za-z0-9._]*)-`),
			skip:     identity.IsPlaceholderLogin,
		},
	}
}

// Find returns non-overlapping matches in s. Where rules overlap, the earlier
// (more specific) rule wins.
func (m *Matcher) Find(s string) []Match {
	var kept []Match
	for _, r := range m.rules {
		for _, loc := range r.re.FindAllStringSubmatchIndex(s, -1) {
			value := s[loc[0]:loc[1]]
			group := value
			for g := 1; g*2 < len(loc); g++ {
				if loc[g*2] >= 0 {
					group = s[loc[g*2]:loc[g*2+1]]
					break
				}
			}
			if !r.whole {
				value = group
			}
			if (r.skip != nil && r.skip(group)) || m.allowed(value) {
				continue
			}
			mt := Match{RuleID: r.ID, Severity: r.Severity, Value: value, Start: loc[0], End: loc[1]}
			if !overlaps(kept, mt) {
				kept = append(kept, mt)
			}
		}
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].Start < kept[j].Start })
	return kept
}

func (m *Matcher) allowed(v string) bool {
	for _, re := range m.allow {
		if re.MatchString(v) {
			return true
		}
	}
	return false
}

func overlaps(kept []Match, m Match) bool {
	for _, k := range kept {
		if m.Start < k.End && k.Start < m.End {
			return true
		}
	}
	return false
}

// Redact renders a value without revealing it: two leading runes and a short
// fingerprint, so repeated hits of the same value are recognisable.
func Redact(v string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(v)))
	r := []rune(v)
	head := 2
	if len(r) < 6 {
		head = 1
	}
	if len(r) < head {
		head = len(r)
	}
	return string(r[:head]) + "…[" + hex.EncodeToString(sum[:])[:8] + "]"
}
