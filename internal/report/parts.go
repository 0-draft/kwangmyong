package report

import (
	"strings"

	"github.com/0-draft/kwangmyong/internal/scan"
)

// Group is the findings on one line of one place, shown as one frame.
type Group struct {
	Head  scan.Finding
	Items []scan.Finding
}

// Groups folds findings into frames, in report order.
func Groups(fs []scan.Finding) []Group {
	gs := groups(fs)
	out := make([]Group, len(gs))
	for i, g := range gs {
		out[i] = Group{Head: g.head, Items: g.items}
	}
	return out
}

// Masker returns s armed to mask every value in fs wherever it appears.
func (s Style) Masker(fs []scan.Finding) Style { return s.withOthers(fs) }

// Frame renders one group as the report does.
func (s Style) Frame(g Group) string {
	var b strings.Builder
	s.frame(&b, &group{head: g.Head, items: g.Items}, max(1, len(itoa(g.Head.Line))))
	return strings.TrimRight(b.String(), "\n")
}

// Place says where a finding is and what kind of place that is, masked.
func (s Style) Place(f scan.Finding) (where, note string) {
	where, note = place(f)
	return s.scrub(where), note
}

// Threat is the threat-level meter.
func (s Style) Threat(fs []scan.Finding) string { return s.threat(fs) }

// Verdict renders only the verdict box.
func (s Style) Verdict(fs []scan.Finding, meta Meta) string {
	s = s.withOthers(fs)
	var b strings.Builder
	s.verdict(&b, fs, len(groups(fs)), meta)
	return b.String()
}

// Dossier renders the intel report.
func (s Style) Dossier(fs []scan.Finding) string {
	s = s.withOthers(fs)
	var b strings.Builder
	s.dossier(&b, fs)
	return strings.TrimRight(b.String(), "\n")
}

// Kind is where a finding has to be fixed.
type Kind int

// Kinds.
const (
	KindFile Kind = iota
	KindHistory
	KindRemote
	KindIdentity
)

// KindOf classifies a finding by what fixing it takes.
func KindOf(f scan.Finding) Kind { return Kind(fixOf(f)) }

// Why says why a kind of leak matters.
func Why(rule string) string {
	switch rule {
	case "identity.name":
		return "Your real name ties this repository, and everything else written under the same handle, to you."
	case "identity.login":
		return "Your login is the account name on your machine; with a path or a hostname it fingerprints you across repos and logs."
	case "identity.email":
		return "A personal address links your other accounts and is a target for phishing and account recovery."
	case "identity.host":
		return "Your machine's name says whose laptop this was, and often your employer's naming scheme."
	case "identity.literal":
		return "Something you told kwangmyong is yours."
	case "generic.autogen-email":
		return "git built this address from your login and hostname because no email was set."
	case "generic.home-path":
		return "Someone's home directory: whose machine built or wrote this."
	case "generic.agent-session-url":
		return "A link to the agent session that wrote this. It belongs to your account and can be shared."
	case "github.unclaimed-handle":
		return "A login you used to have. Anyone can register it now and be you in old links."
	}
	return ""
}

// Fix says how to fix a finding of this kind.
func Fix(k Kind, target string) string {
	if target == "" || target == "the next commit" {
		target = "."
	}
	switch k {
	case KindFile:
		return "Edit the line. kwangmyong hook install stops the next one at commit time."
	case KindHistory:
		return "It is in history: a file edit does not remove it. kwangmyong plan " + target + " drafts the rewrite."
	case KindRemote:
		return "Edit or delete it on GitHub. A history rewrite does not reach it."
	case KindIdentity:
		return "Commit as your GitHub noreply address and a public handle."
	}
	return ""
}

func itoa(n int) string {
	if n == 0 {
		return ""
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// Scrub masks any found value in t (after Masker).
func (s Style) Scrub(t string) string { return s.scrub(t) }
