package identity

import (
	"regexp"
	"strings"
	"unicode"
)

// Patterns are escaped regexp fragments per identity kind.
type Patterns struct {
	Name    []string
	Login   []string
	Email   []string
	Host    []string
	Literal []string
}

// Expand turns declared identity strings into the spellings they leak under.
func Expand(id Identity) Patterns {
	id = id.Normalize()
	var p Patterns
	for _, n := range id.Names {
		p.Name = append(p.Name, NameVariants(n)...)
	}
	for _, l := range id.Logins {
		p.Login = append(p.Login, LoginVariants(l)...)
	}
	for _, e := range id.Emails {
		p.Email = append(p.Email, EmailVariants(e)...)
	}
	for _, h := range id.Hosts {
		p.Host = append(p.Host, HostVariants(h)...)
	}
	for _, s := range id.Literals {
		p.Literal = append(p.Literal, regexp.QuoteMeta(s))
	}
	p.Name, p.Login, p.Email, p.Host, p.Literal = uniq(p.Name), uniq(p.Login), uniq(p.Email), uniq(p.Host), uniq(p.Literal)
	return p
}

var tokenSep = regexp.MustCompile(`[\s\x{3000}._\-・]+`)

// NameVariants covers order, separator and initial forms ("yamada_taro",
// "t.yamada") and CJK spacing ("山田太郎", "太郎　山田").
func NameVariants(name string) []string {
	toks := tokenSep.Split(strings.TrimSpace(name), -1)
	toks = nonEmpty(toks)
	if len(toks) == 0 {
		return nil
	}
	q := quoteAll(toks)
	if isCJK(name) {
		sep := `[\s\x{3000}・]*`
		return uniq([]string{strings.Join(q, sep), strings.Join(reversed(q), sep)})
	}
	if len(toks) == 1 {
		return []string{`\b` + q[0] + `\b`}
	}
	sep := `[\s._-]?`
	out := []string{strings.Join(q, sep), strings.Join(reversed(q), sep)}
	first, last := toks[0], toks[len(toks)-1]
	if len([]rune(last)) >= 3 {
		fi := regexp.QuoteMeta(string([]rune(first)[:1]))
		ql := regexp.QuoteMeta(last)
		out = append(out, `\b`+fi+`[._-]?`+ql+`\b`)
	}
	return uniq(out)
}

// homePrefixes precede a login in home paths and -Users-<login>- slugs.
const homePrefixes = `(?:/Users/|/home/|[A-Za-z]:(?:\\\\|\\|/)Users(?:\\\\|\\|/)|-Users-|-home-)`

// LoginVariants matches the login in paths, and as a word from 5 characters.
func LoginVariants(login string) []string {
	q := regexp.QuoteMeta(login)
	out := []string{homePrefixes + q + `\b`, `\b` + q + `@`}
	if len(login) >= 5 {
		out = append(out, `\b`+q+`\b`)
	}
	return out
}

// EmailVariants matches the address plainly and URL-encoded.
func EmailVariants(email string) []string {
	email = strings.TrimSpace(email)
	out := []string{regexp.QuoteMeta(email)}
	if i := strings.LastIndex(email, "@"); i > 0 {
		out = append(out, regexp.QuoteMeta(email[:i])+`%40`+regexp.QuoteMeta(email[i+1:]))
	}
	return out
}

// HostVariants also matches the spaced form ("Taro's MacBook Pro").
func HostVariants(host string) []string {
	parts := strings.Split(host, "-")
	q := make([]string, len(parts))
	for i, part := range parts {
		q[i] = regexp.QuoteMeta(part)
		if len(part) > 2 && strings.HasSuffix(part, "s") { // "Taros" is the hyphenated "Taro's"
			q[i] = regexp.QuoteMeta(part[:len(part)-1]) + `'?s`
		}
	}
	return []string{`\b` + strings.Join(q, `[-\s]`) + `\b`}
}

func isCJK(s string) bool {
	for _, r := range s {
		if unicode.In(r, unicode.Han, unicode.Hiragana, unicode.Katakana, unicode.Hangul) {
			return true
		}
	}
	return false
}

func quoteAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = regexp.QuoteMeta(s)
	}
	return out
}

func reversed(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[len(in)-1-i] = s
	}
	return out
}

func nonEmpty(in []string) []string {
	var out []string
	for _, s := range in {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
