package main

import (
	"bytes"
	"os"
	"os/exec"
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

func TestHookInstall(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	if out, err := exec.Command("git", "init", "-q", dir).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	t.Chdir(dir)
	foreign := filepath.Join(dir, ".git", "hooks", "pre-push")
	if err := os.WriteFile(foreign, []byte("#!/bin/sh\necho mine\n"), 0o755); err != nil { //nolint:gosec // test hook
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if code, out := runCLI(t, "hook", "install"); code != 0 {
			t.Fatalf("install: %d %s", code, out)
		}
	}
	for _, h := range []string{"pre-commit", "commit-msg"} {
		b, err := os.ReadFile(filepath.Join(dir, ".git", "hooks", h))
		if err != nil || !strings.Contains(string(b), "kwangmyong hook "+h) {
			t.Errorf("%s not installed: %q %v", h, b, err)
		}
	}
	if b, _ := os.ReadFile(foreign); !strings.Contains(string(b), "echo mine") {
		t.Error("a foreign hook was replaced without --force")
	}
	if code, _ := runCLI(t, "hook", "install", "--force"); code != 0 {
		t.Fatal("install --force failed")
	}
	if b, _ := os.ReadFile(foreign); !strings.Contains(string(b), "kwangmyong hook pre-push") {
		t.Error("--force did not replace the hook")
	}
}

func TestHookAgentsExitTwo(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(cfg, []byte("[identity]\nnames = [\"Taro Yamada\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KWANGMYONG_CONFIG", cfg)
	for _, a := range []string{"codex", "gemini", "cursor", "copilot", "windsurf", "kiro", "devin"} {
		var out, errb bytes.Buffer
		code, _ := cmdHook([]string{a, "--no-auto"}, strings.NewReader(`{"cwd":".","command":"gh issue create --body 'Taro Yamada'","tool_name":"run_shell_command","tool_input":{"command":"gh issue create --body 'Taro Yamada'"}}`), &out, &errb)
		if code != 2 || strings.Contains(errb.String(), "Taro") {
			t.Errorf("%s: code %d, stderr %q", a, code, errb.String())
		}
	}
}
