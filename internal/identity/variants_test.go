package identity

import (
	"regexp"
	"strings"
	"testing"
)

func compile(t *testing.T, frags []string) *regexp.Regexp {
	t.Helper()
	return regexp.MustCompile(`(?i)(?:` + strings.Join(frags, "|") + `)`)
}

func TestNameVariantsLatin(t *testing.T) {
	re := compile(t, NameVariants("Taro Yamada"))
	for _, s := range []string{
		"Taro Yamada", "taro.yamada", "yamada_taro", "YamadaTaro", "TAROYAMADA",
		"tyamada", "t.yamada", "/Users/tyamada/src", "by yamada-taro",
	} {
		if !re.MatchString(s) {
			t.Errorf("want match: %q", s)
		}
	}
	for _, s := range []string{"Taro", "Yamada", "tyamadax", "otyamada"} {
		if re.MatchString(s) {
			t.Errorf("unexpected match: %q", s)
		}
	}
}

func TestNameVariantsCJK(t *testing.T) {
	re := compile(t, NameVariants("山田 太郎"))
	for _, s := range []string{"山田太郎", "山田 太郎", "太郎　山田", "山田・太郎"} {
		if !re.MatchString(s) {
			t.Errorf("want match: %q", s)
		}
	}
	if re.MatchString("山田花子") {
		t.Error("unexpected match on a different given name")
	}
}

func TestLoginVariants(t *testing.T) {
	short := compile(t, LoginVariants("tyam"))
	for _, s := range []string{"/Users/tyam/x", "/home/tyam", `C:\Users\tyam\x`, `C:\\Users\\tyam`, "-Users-tyam-repo", "tyam@host"} {
		if !short.MatchString(s) {
			t.Errorf("want match: %q", s)
		}
	}
	if short.MatchString("a tyam word") {
		t.Error("short login must only match in path/login contexts")
	}
	long := compile(t, LoginVariants("tyamada"))
	if !long.MatchString("owner tyamada said") {
		t.Error("long login should match as a word")
	}
}

func TestEmailAndHostVariants(t *testing.T) {
	e := compile(t, EmailVariants("taro@example.com"))
	if !e.MatchString("mailto:taro%40example.com") || !e.MatchString("<Taro@Example.com>") {
		t.Error("email variants")
	}
	h := compile(t, HostVariants("Taros-MacBook-Pro"))
	for _, s := range []string{"taro@Taros-MacBook-Pro.local", "Taro's MacBook Pro"} {
		if !h.MatchString(s) {
			t.Errorf("want host match: %q", s)
		}
	}
}

func TestNormalize(t *testing.T) {
	id := Identity{
		Logins: []string{"runner", "tyamada", "TYAMADA", " "},
		Emails: []string{"1+x@users.noreply.github.com", "taro@example.com"},
		Hosts:  []string{"Taros-MacBook-Pro.local", "localhost"},
	}.Normalize()
	if len(id.Logins) != 1 || id.Logins[0] != "tyamada" {
		t.Errorf("logins = %v", id.Logins)
	}
	if len(id.Emails) != 1 {
		t.Errorf("noreply must be dropped: %v", id.Emails)
	}
	if len(id.Hosts) != 1 || id.Hosts[0] != "Taros-MacBook-Pro" {
		t.Errorf("hosts = %v", id.Hosts)
	}
}
