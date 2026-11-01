package identity

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
)

// Detect collects the identity this machine already reveals: the login name,
// the home directory's base name, the account's full name, the hostname, and
// the global git identity.
func Detect() Identity {
	var id Identity
	if u, err := user.Current(); err == nil {
		login := u.Username
		if i := strings.LastIndexAny(login, `\/`); i >= 0 { // DOMAIN\user on Windows
			login = login[i+1:]
		}
		id.Logins = append(id.Logins, login)
		if u.Name != "" && !strings.EqualFold(u.Name, login) {
			id.Names = append(id.Names, u.Name)
		}
	}
	if h, err := os.UserHomeDir(); err == nil {
		id.Logins = append(id.Logins, filepath.Base(h))
	}
	if h, err := os.Hostname(); err == nil && !genericHost.MatchString(h) {
		id.Hosts = append(id.Hosts, h)
	}
	// A single-token user.name is a public handle, not a real name.
	if v := gitGlobal("user.name"); strings.ContainsAny(strings.TrimSpace(v), " \u3000") {
		id.Names = append(id.Names, v)
	}
	if v := gitGlobal("user.email"); v != "" {
		id.Emails = append(id.Emails, v)
	}
	return id.Normalize()
}

// genericHost matches factory-default Mac hostnames, which name the hardware,
// not the person, and would flag every mention of "MacBook Pro".
var genericHost = regexp.MustCompile(`(?i)^(?:macbook(?:-pro|-air)?|imac|mac-?mini|mac-?studio|mac-?pro)(?:-\d+)?(?:\.local)?$`)

func gitGlobal(key string) string {
	out, err := exec.Command("git", "config", "--global", "--get", key).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
