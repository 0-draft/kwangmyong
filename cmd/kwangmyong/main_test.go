package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runCLI(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String() + errb.String()
}

func TestScanExitCodes(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfg, []byte("[identity]\nemails = [\"taro@example.com\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(dir, "repo")
	if err := os.MkdirAll(repo, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "a.md"), []byte("path /Users/hanako/x\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if code, out := runCLI(t, "scan", "--no-auto", "--config", cfg, repo); code != 0 {
		t.Errorf("warn-only scan should exit 0, got %d: %s", code, out)
	}
	if code, _ := runCLI(t, "scan", "--no-auto", "--config", cfg, "--strict", repo); code != 1 {
		t.Errorf("--strict should fail on warn, got %d", code)
	}

	if err := os.WriteFile(filepath.Join(repo, "b.md"), []byte("mail taro@example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out := runCLI(t, "scan", "--no-auto", "--config", cfg, repo)
	if code != 1 {
		t.Errorf("identity leak should exit 1, got %d", code)
	}
	if strings.Contains(out, "taro@example.com") {
		t.Errorf("output leaked the raw value:\n%s", out)
	}
}

func TestRepoConfigRejectsIdentity(t *testing.T) {
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, ".kwangmyong.toml"), []byte("[identity]\nnames=[\"x y\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out := runCLI(t, "scan", "--no-auto", "--config", filepath.Join(repo, "none.toml"), repo); code != 2 || !strings.Contains(out, "refusing") {
		t.Errorf("got %d %s", code, out)
	}
}

func TestUnknownCommand(t *testing.T) {
	if code, _ := runCLI(t, "nope"); code != 2 {
		t.Errorf("got %d", code)
	}
}
