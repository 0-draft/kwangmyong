// Package identity loads, detects and expands the identity being protected.
package identity

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// Identity is who the scan protects. It lives in the user config only.
type Identity struct {
	Names    []string `toml:"names"`
	Logins   []string `toml:"logins"`
	Emails   []string `toml:"emails"`
	Hosts    []string `toml:"hosts"`
	Literals []string `toml:"literals"`
}

// Allow suppresses findings by path glob or by value regex.
type Allow struct {
	Paths  []string `toml:"paths"`
	Values []string `toml:"values"`
}

// Config is the on-disk configuration.
type Config struct {
	Identity Identity `toml:"identity"`
	Allow    Allow    `toml:"allow"`
}

// RepoConfigName is the per-repository config; it may only carry [allow].
const RepoConfigName = ".kwangmyong.toml"

// ErrIdentityInRepo is returned when a repo-level config declares [identity].
var ErrIdentityInRepo = errors.New("refusing " + RepoConfigName + " with an [identity] table: it would commit the identity it protects; move it to the user config")

// UserConfigPath resolves the user config file location.
func UserConfigPath() (string, error) {
	if p := os.Getenv("KWANGMYONG_CONFIG"); p != "" {
		return p, nil
	}
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "kwangmyong", "config.toml"), nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, ".config", "kwangmyong", "config.toml"), nil
}

// LoadFile reads a config file. A missing file is not an error.
func LoadFile(path string) (Config, toml.MetaData, error) {
	var c Config
	md, err := toml.DecodeFile(path, &c)
	if errors.Is(err, os.ErrNotExist) {
		return Config{}, toml.MetaData{}, nil
	}
	if err != nil {
		return Config{}, md, fmt.Errorf("%s: %w", path, err)
	}
	return c, md, nil
}

// LoadRepo reads <root>/.kwangmyong.toml and rejects an [identity] table.
func LoadRepo(root string) (Allow, error) {
	c, md, err := LoadFile(filepath.Join(root, RepoConfigName))
	if err != nil {
		return Allow{}, err
	}
	if md.IsDefined("identity") {
		return Allow{}, ErrIdentityInRepo
	}
	return c.Allow, nil
}

// Merge returns the union of a and b with duplicates removed.
func Merge(a, b Identity) Identity {
	return Identity{
		Names:    append(append([]string{}, a.Names...), b.Names...),
		Logins:   append(append([]string{}, a.Logins...), b.Logins...),
		Emails:   append(append([]string{}, a.Emails...), b.Emails...),
		Hosts:    append(append([]string{}, a.Hosts...), b.Hosts...),
		Literals: append(append([]string{}, a.Literals...), b.Literals...),
	}.Normalize()
}

// Empty reports whether no identity strings are declared.
func (id Identity) Empty() bool {
	return len(id.Names)+len(id.Logins)+len(id.Emails)+len(id.Hosts)+len(id.Literals) == 0
}

// Normalize trims, drops placeholders and noreply addresses, and dedupes.
func (id Identity) Normalize() Identity {
	return Identity{
		Names:    clean(id.Names, func(s string) bool { return len([]rune(s)) >= 2 }),
		Logins:   clean(id.Logins, func(s string) bool { return len(s) >= 2 && !IsPlaceholderLogin(s) }),
		Emails:   clean(id.Emails, func(s string) bool { return strings.Contains(s, "@") && !IsNoreply(s) }),
		Hosts:    clean(stripLocal(id.Hosts), func(s string) bool { return len(s) >= 4 && !strings.EqualFold(s, "localhost") }),
		Literals: clean(id.Literals, func(s string) bool { return len([]rune(s)) >= 3 }),
	}
}

func clean(in []string, keep func(string) bool) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		k := strings.ToLower(s)
		if s == "" || seen[k] || !keep(s) {
			continue
		}
		seen[k] = true
		out = append(out, s)
	}
	return out
}

func stripLocal(hosts []string) []string {
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		for _, suf := range []string{".local", ".lan", ".localdomain"} {
			if len(h) > len(suf) && strings.EqualFold(h[len(h)-len(suf):], suf) {
				h = h[:len(h)-len(suf)]
			}
		}
		out = append(out, h)
	}
	return out
}

// IsNoreply reports whether email is a GitHub noreply address.
func IsNoreply(email string) bool {
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(email)), "@users.noreply.github.com")
}

var placeholderLogins = map[string]bool{
	"admin": true, "administrator": true, "app": true, "bob": true, "alice": true,
	"build": true, "builder": true, "ci": true, "circleci": true, "default": true,
	"dev": true, "developer": true, "ec2-user": true, "example": true, "foo": true,
	"bar": true, "guest": true, "jane": true, "jenkins": true, "john": true,
	"linuxbrew": true, "me": true, "name": true, "node": true, "public": true,
	"root": true, "runner": true, "runneradmin": true, "shared": true, "travis": true,
	"ubuntu": true, "user": true, "username": true, "vagrant": true, "you": true,
	"yourname": true, "your-name": true, "your_name": true, "x": true,
}

// IsPlaceholderLogin reports whether s is a generic account name.
func IsPlaceholderLogin(s string) bool {
	return placeholderLogins[strings.ToLower(s)]
}
