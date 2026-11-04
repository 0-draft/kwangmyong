package hook

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func agent(t *testing.T, e Env, payload map[string]any) Result {
	t.Helper()
	b, _ := json.Marshal(payload)
	r, err := Agent(e, strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestAgentPayloads(t *testing.T) {
	dir, e := repo(t), env(t)
	file := filepath.Join(dir, "notes.md")
	leak := "built at /Users/tyamada/src"
	gh := `gh pr create --title x --body "by Taro Yamada"`
	argsJSON, _ := json.Marshal(map[string]any{"command": gh})
	cases := []struct {
		name    string
		payload map[string]any
	}{
		{"codex bash", map[string]any{"cwd": dir, "tool_name": "Bash", "tool_input": map[string]any{"command": gh}}},
		{"codex apply_patch", map[string]any{"cwd": dir, "tool_name": "apply_patch", "tool_input": map[string]any{
			"command": "*** Begin Patch\n*** Add File: notes.md\n+" + leak + "\n*** End Patch"}}},
		{"gemini shell", map[string]any{"cwd": dir, "tool_name": "run_shell_command", "tool_input": map[string]any{"command": gh}}},
		{"gemini write_file", map[string]any{"cwd": dir, "tool_name": "write_file", "tool_input": map[string]any{"file_path": file, "content": leak}}},
		{"gemini replace", map[string]any{"cwd": dir, "tool_name": "replace", "tool_input": map[string]any{"file_path": file, "new_string": leak}}},
		{"gemini mcp", map[string]any{"cwd": dir, "tool_name": "mcp_github_create_issue", "tool_input": map[string]any{"body": "Taro Yamada"}}},
		{"cursor shell", map[string]any{"cwd": dir, "command": gh}},
		{"cursor mcp", map[string]any{"cwd": dir, "mcp_server_name": "github", "tool_name": "create_issue", "tool_input": map[string]any{"body": "Taro Yamada"}}},
		{"cursor write", map[string]any{"cwd": dir, "tool_name": "Write", "tool_input": map[string]any{"file_path": file, "content": leak}}},
		{"copilot camel, args as a string", map[string]any{"cwd": dir, "toolName": "bash", "toolArgs": string(argsJSON)}},
		{"copilot create", map[string]any{"cwd": dir, "toolName": "create", "toolArgs": map[string]any{"path": file, "file_text": leak}}},
		{"copilot edit", map[string]any{"cwd": dir, "toolName": "edit", "toolArgs": map[string]any{"path": file, "new_str": leak}}},
		{"windsurf command", map[string]any{"agent_action_name": "pre_run_command", "tool_info": map[string]any{"command_line": gh, "cwd": dir}}},
		{"windsurf write", map[string]any{"agent_action_name": "pre_write_code", "tool_info": map[string]any{"file_path": file, "cwd": dir, "edits": []any{map[string]any{"old_string": "", "new_string": leak}}}}},
		{"windsurf mcp", map[string]any{"agent_action_name": "pre_mcp_tool_use", "tool_info": map[string]any{"mcp_server_name": "github", "mcp_tool_name": "create_issue", "mcp_tool_arguments": map[string]any{"body": "Taro Yamada"}}}},
		{"kiro shell", map[string]any{"cwd": dir, "tool_name": "shell", "tool_input": map[string]any{"command": gh}}},
		{"kiro fs_write", map[string]any{"cwd": dir, "tool_name": "fs_write", "tool_input": map[string]any{"path": file, "file_text": leak}}},
		{"devin exec", map[string]any{"cwd": dir, "tool_name": "exec", "tool_input": map[string]any{"command": gh}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := agent(t, e, c.payload)
			if !r.Block {
				t.Fatalf("not blocked: %+v", c.payload)
			}
			if strings.Contains(r.Reason, "tyamada") || strings.Contains(r.Reason, "Taro") {
				t.Errorf("reason leaks the value:\n%s", r.Reason)
			}
		})
	}
}

func TestAgentLetsCleanCallsThrough(t *testing.T) {
	dir, e := repo(t), env(t)
	for _, p := range []map[string]any{
		{"cwd": dir, "tool_name": "run_shell_command", "tool_input": map[string]any{"command": "ls -la"}},
		{"cwd": dir, "command": `gh pr create --title x --body "fix the parser"`},
		{"cwd": dir, "tool_name": "read_file", "tool_input": map[string]any{"file_path": filepath.Join(dir, "README.md")}},
		{"cwd": dir, "tool_name": "write_file", "tool_input": map[string]any{"file_path": "/tmp/scratch.md", "content": "Taro Yamada"}},
	} {
		if r := agent(t, e, p); r.Block {
			t.Errorf("blocked a clean call %+v:\n%s", p, r.Reason)
		}
	}
}

func TestPatchCalls(t *testing.T) {
	calls := patchCalls("*** Begin Patch\n*** Update File: a.go\n@@\n-old\n+new one\n context\n*** Add File: b.md\n+hello\n+world\n*** Delete File: c.txt\n*** End Patch")
	if len(calls) != 2 || calls[0].in.FilePath != "a.go" || calls[0].in.Content != "new one" || calls[1].in.Content != "hello\nworld" {
		t.Errorf("calls: %+v", calls)
	}
}

func TestCommitMsg(t *testing.T) {
	e := env(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "COMMIT_EDITMSG")
	write(t, p, "fix: parser\n\nhttps://claude.ai/code/session_01AbCdEfGh\n# Please enter the commit message for Taro Yamada\n")
	r, err := CommitMsg(e, p)
	if err != nil || !r.Block || len(r.Findings) != 1 || r.Findings[0].RuleID != "generic.agent-session-url" {
		t.Fatalf("session link in the message should block, comments ignored: %+v %v", r.Findings, err)
	}
	write(t, p, "fix: parser\n# by Taro Yamada\n# ------------------------ >8 ------------------------\n+Taro Yamada\n")
	if r, _ := CommitMsg(e, p); r.Block {
		t.Errorf("comments and the verbose diff are not the message:\n%s", r.Reason)
	}
}
