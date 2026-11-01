package rules

import (
	"strings"
	"testing"

	"github.com/0-draft/kwangmyong/internal/identity"
)

func matcher(t *testing.T, id identity.Identity) *Matcher {
	t.Helper()
	m, err := New(identity.Expand(id), nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func ids(ms []Match) []string {
	var out []string
	for _, m := range ms {
		out = append(out, m.RuleID+"="+m.Value)
	}
	return out
}

func TestGenericHomePath(t *testing.T) {
	m := matcher(t, identity.Identity{})
	got := ids(m.Find(`see /Users/hanako/src and /home/runner/work and C:\Users\jiro\x and -Users-saburo-repo`))
	want := []string{"generic.home-path=hanako", "generic.home-path=jiro", "generic.home-path=saburo"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestIdentityBeatsGeneric(t *testing.T) {
	m := matcher(t, identity.Identity{Logins: []string{"tyamada"}})
	got := m.Find("/Users/tyamada/src")
	if len(got) != 1 || got[0].RuleID != "identity.login" || got[0].Severity != High {
		t.Errorf("got %v", ids(got))
	}
}

func TestAutogenEmailAndAllow(t *testing.T) {
	m := matcher(t, identity.Identity{Emails: []string{"taro@example.com"}})
	got := ids(m.Find("Taro <tyamada@Taros-MacBook-Pro.local> 1+taro@users.noreply.github.com taro@example.com"))
	want := []string{"generic.autogen-email=tyamada@Taros-MacBook-Pro.local", "identity.email=taro@example.com"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestAllowValues(t *testing.T) {
	m, err := New(identity.Expand(identity.Identity{}), []string{`^hanako$`})
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Find("/Users/hanako/x"); len(got) != 0 {
		t.Errorf("allowed value reported: %v", ids(got))
	}
}

func TestRedact(t *testing.T) {
	r := Redact("tyamada@example.com")
	if strings.Contains(r, "yamada") || !strings.HasPrefix(r, "ty…[") {
		t.Errorf("redact leaked: %q", r)
	}
	fp := func(s string) string { _, after, _ := strings.Cut(s, "["); return after }
	if fp(Redact("Taro")) != fp(Redact("taro")) {
		t.Errorf("fingerprint should be case-insensitive: %q %q", Redact("Taro"), Redact("taro"))
	}
}
