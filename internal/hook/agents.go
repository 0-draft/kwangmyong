package hook

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Agents lists the coding agents `hook <agent>` understands besides claude.
// Each sends a pre-tool JSON payload on stdin and treats exit 2 as a block
// with the reason read from stderr.
var Agents = []string{"codex", "gemini", "cursor", "copilot", "windsurf", "kiro", "devin"}

// Agent checks a pre-tool payload from another coding agent by translating
// it into Claude Code's terms. Shapes differ per agent, so fields are probed
// rather than assumed.
func Agent(env Env, payload io.Reader) (Result, error) {
	var m map[string]any
	if err := json.NewDecoder(payload).Decode(&m); err != nil {
		return Result{}, fmt.Errorf("hook payload: %w", err)
	}
	cwd, calls := normalize(m)
	var all Result
	for _, c := range calls {
		r, err := check(env, cwd, c.name, c.in, c.raw)
		if err != nil {
			return Result{}, err
		}
		if r.Block && !all.Block {
			all = r
		} else if r.Block {
			all.Findings = append(all.Findings, r.Findings...)
		}
	}
	if all.Block {
		return decide(all.What, all.Findings), nil
	}
	return Result{}, nil
}

type call struct {
	name string
	in   toolInput
	raw  any
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func obj(v any) map[string]any {
	switch t := v.(type) {
	case map[string]any:
		return t
	case string: // Copilot has sent tool arguments as a JSON string
		var m map[string]any
		if json.Unmarshal([]byte(t), &m) == nil {
			return m
		}
	}
	return nil
}

func first(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s := str(m[k]); s != "" {
			return s
		}
	}
	return ""
}

// normalize finds the working directory and the tool calls in a payload.
func normalize(m map[string]any) (string, []call) {
	cwd := first(m, "cwd", "workingDirectory")

	// Windsurf / Cascade: agent_action_name + tool_info.
	if info := obj(m["tool_info"]); info != nil {
		if c := first(info, "cwd"); c != "" {
			cwd = c
		}
		switch str(m["agent_action_name"]) {
		case "pre_run_command":
			return cwd, []call{{name: "Bash", in: toolInput{Command: first(info, "command_line", "command")}}}
		case "pre_write_code":
			return cwd, []call{fileCall("Edit", info)}
		case "pre_mcp_tool_use":
			name := "mcp__" + str(info["mcp_server_name"]) + "__" + str(info["mcp_tool_name"])
			return cwd, []call{{name: name, raw: info["mcp_tool_arguments"]}}
		}
		return cwd, nil
	}

	name := first(m, "tool_name", "toolName")
	input := obj(m["tool_input"])
	if input == nil {
		input = obj(m["toolArgs"])
	}

	// Cursor beforeShellExecution: the command is top level.
	if name == "" {
		if c := str(m["command"]); c != "" {
			return cwd, []call{{name: "Bash", in: toolInput{Command: c}}}
		}
		return cwd, nil
	}
	// Cursor beforeMCPExecution names the server separately.
	if srv := str(m["mcp_server_name"]); srv != "" && !strings.HasPrefix(name, "mcp") {
		return cwd, []call{{name: "mcp__" + srv + "__" + name, raw: input}}
	}
	if input == nil {
		input = map[string]any{}
	}

	switch n := strings.ToLower(name); {
	case n == "bash" || n == "shell" || n == "exec" || n == "run_shell_command" || n == "shell_command" ||
		n == "execute_command" || n == "run_command" || n == "run_terminal_cmd":
		return cwd, []call{{name: "Bash", in: toolInput{Command: first(input, "command", "command_line", "cmd")}}}
	case n == "apply_patch":
		return cwd, patchCalls(first(input, "command", "patch", "input"))
	case n == "write" || n == "write_file" || n == "create" || n == "create_file" || n == "fs_write":
		return cwd, []call{fileCall("Write", input)}
	case n == "edit" || n == "multiedit" || n == "replace" || n == "str_replace" || n == "edit_file" ||
		n == "search_replace" || n == "fs_edit" || n == "notebookedit":
		return cwd, []call{fileCall("Edit", input)}
	case strings.HasPrefix(name, "mcp__"):
		return cwd, []call{{name: name, raw: input}}
	case strings.HasPrefix(n, "mcp_github_"): // Gemini: mcp_<server>_<tool>
		return cwd, []call{{name: "mcp__github__" + name[len("mcp_github_"):], raw: input}}
	}
	return cwd, nil
}

// fileCall maps the many spellings of path and new text onto a write.
func fileCall(kind string, m map[string]any) call {
	in := toolInput{
		FilePath:  first(m, "file_path", "path", "filePath", "target_file", "filename"),
		Content:   first(m, "content", "file_text", "contents", "text", "code_edit"),
		NewString: first(m, "new_string", "new_str", "newText", "replacement", "new_content"),
	}
	if edits, ok := m["edits"].([]any); ok {
		for _, e := range edits {
			if em := obj(e); em != nil {
				in.Edits = append(in.Edits, struct {
					NewString string `json:"new_string"`
				}{first(em, "new_string", "new_str", "newText", "replacement")})
			}
		}
	}
	return call{name: kind, in: in}
}

// patchCalls turns a Codex apply_patch body into one write per file, made of
// the lines it adds.
func patchCalls(patch string) []call {
	var calls []call
	var cur *call
	var added []string
	flush := func() {
		if cur != nil {
			cur.in.Content = strings.Join(added, "\n")
			calls = append(calls, *cur)
		}
		cur, added = nil, nil
	}
	for _, l := range strings.Split(patch, "\n") {
		switch {
		case strings.HasPrefix(l, "*** Add File: "), strings.HasPrefix(l, "*** Update File: "):
			flush()
			p := l[strings.Index(l, ": ")+2:]
			cur = &call{name: "Write", in: toolInput{FilePath: strings.TrimSpace(p)}}
		case strings.HasPrefix(l, "*** Move to: ") && cur != nil:
			cur.in.FilePath = strings.TrimSpace(strings.TrimPrefix(l, "*** Move to: "))
		case strings.HasPrefix(l, "*** "):
			flush()
		case strings.HasPrefix(l, "+") && cur != nil:
			added = append(added, l[1:])
		}
	}
	flush()
	return calls
}
