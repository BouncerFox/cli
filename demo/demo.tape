# BouncerFox CLI Demo
# Generate with: vhs demo/demo.tape

Output demo/demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 900
Set Padding 20
Set Theme "Catppuccin Mocha"
Set TypingSpeed 50ms

Sleep 1s

Type "# BouncerFox: scan AI agent configs for security issues"
Enter
Sleep 1.5s

Type "bouncerfox scan demo/compact/"
Enter
Sleep 4s

Type "# Group by severity to triage critical issues first"
Enter
Sleep 1.5s

Type "bouncerfox scan demo/compact/ --group-by severity"
Enter
Sleep 5s

Type "# Show remediation advice with -v"
Enter
Sleep 1.5s

Type "bouncerfox scan demo/compact/ -v 2>/dev/null | head -20"
Enter
Sleep 5s

Sleep 2s
