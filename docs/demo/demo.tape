# Regenerate from the repository root: vhs docs/demo/demo.tape (needs gitleaks)
Output docs/demo/demo.gif
Set Shell bash
Set FontSize 16
Set Width 1300
Set Height 1120
Set Padding 24
Set Theme "Dracula"
Set TypingSpeed 25ms

# --no-auto keeps the recording machine's own identity out of the demo.
Hide
Type `export D=$(mktemp -d) && go build -o $D/kwangmyong ./cmd/kwangmyong && docs/demo/setup.sh $D >/dev/null && export PATH=$D:$PATH KWANGMYONG_CONFIG=$D/config.toml PS1='\[\e[2m\]$\[\e[0m\] ' && kwangmyong() { if [ "$1" = hook ]; then command kwangmyong hook "$2" --no-auto "${@:3}"; else command kwangmyong "$1" --no-auto "${@:2}"; fi; } && cd $D/repo && clear`
Enter
Sleep 10s
Show

Type "# a repo a coding agent has been working in. any secrets?"
Enter
Type "gitleaks git . --no-banner 2>&1 | grep -o 'no leaks found'"
Enter
Sleep 2s
Type "# no secrets. but what does it say about its author?"
Enter
Type "kwangmyong scan --history ."
Enter
Sleep 9s

Hide
Type "clear"
Enter
Show
Type "# the agent opens a PR with its session link in the body"
Enter
Type "kwangmyong hook claude < ../pr-create.json; echo exit=$?"
Enter
Sleep 4s
Type "# and a repo the author kept clean"
Enter
Type "kwangmyong scan --history ../clean"
Enter
Sleep 6s
