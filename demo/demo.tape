# BouncerFox CLI Demo
# Generate with: vhs demo/demo.tape

Require bouncerfox

Output demo/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 800
Set Padding 20
Set Theme "Catppuccin Mocha"
Set WindowBar "Colorful"
Set BorderRadius 8
Set LoopOffset 60%
Set PlaybackSpeed 1
Set TypingSpeed 40ms

Sleep 500ms

Type "# BouncerFox: scan AI agent configs for security issues"
Enter
Sleep 1s

Type "bouncerfox scan demo/compact/"
Enter
Sleep 6s

Type "clear"
Enter
Sleep 500ms

Type "# Group findings by severity to triage critical issues first"
Enter
Sleep 1s

Type "bouncerfox scan demo/compact/ --group-by severity"
Enter
Sleep 6s

Type "clear"
Enter
Sleep 500ms

Type "# Show code context with -v"
Enter
Sleep 1s

Type "bouncerfox scan demo/compact/ -v 2>/dev/null | head -25"
Enter
Sleep 6s
