# VHS tape script to generate terminal animation demo
# Requirements: vhs (https://github.com/charmbracelet/vhs)
# Run: vhs demo.tape

Output docs/assets/sentris_demo.gif

Set FontSize 16
Set Width 1200
Set Height 675
Set Theme "Catppuccin Mocha"
Set Padding 20

# 1. Setup prompt and banner
Type "sentris --version"
Sleep 500ms
Enter
Sleep 1s

# 2. Fast scan demonstration
Type "sentris scan ."
Sleep 500ms
Enter
Sleep 2s

# 3. Pre-commit install
Type "sentris install"
Sleep 500ms
Enter
Sleep 1.5s

# 4. Deep Git History Scan
Type "sentris scan --git-history"
Sleep 500ms
Enter
Sleep 2.5s

# 5. Autonomous Dual-Key Remediation (The Holy Sh*t Factor)
Type "sentris remediate --dry-run"
Sleep 500ms
Enter
Sleep 4s

# 6. Conclusion
Sleep 2s
