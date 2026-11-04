# Regenerate from the repository root: vhs docs/demo/demo.tape (needs gitleaks)
Output docs/demo/demo.gif
Set Shell bash
Set FontSize 17
Set Width 1780
Set Height 740
Set Padding 24
Set Theme "Dracula"
Set TypingSpeed 35ms
Hide
Type `export D=$(mktemp -d) && go build -o $D/kwangmyong ./cmd/kwangmyong && docs/demo/setup.sh $D >/dev/null && export PATH=$D:$PATH KWANGMYONG_CONFIG=$D/config.toml PS1='$ ' && cd $D/repo && clear`
Enter
Sleep 10s
Show
Type "# A repo an agent has been committing to"
Enter
Type "cat README.md NOTES.md test.log"
Enter
Sleep 2.5s
Enter
Type "# A secret scanner has nothing to say"
Enter
Type "gitleaks git . --no-banner 2>&1 | grep -o 'no leaks found'"
Enter
Sleep 2.5s
Enter
Type "# kwangmyong looks for you (--reveal: these are made-up values)"
Enter
Type "kwangmyong scan --no-auto --history --reveal ."
Enter
Sleep 4s
Enter
Type "# As a Claude Code hook, it stops the agent's gh pr create"
Enter
Type "kwangmyong hook claude --no-auto < ../pr-create.json; echo exit=$?"
Enter
Sleep 5s
