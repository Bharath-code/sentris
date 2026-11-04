# VHS tape script to generate the Sentris Launch & CTO Demo GIF
# Requirements: vhs (https://github.com/charmbracelet/vhs)
# Run: vhs demo.tape

Output docs/assets/sentris_demo.gif

Set FontSize 15
Set Width 1280
Set Height 720
Set Theme "Catppuccin Mocha"
Set Padding 20

# 1. Instant Multi-Stack Scan (<20ms across TypeScript, GitHub Actions, Terraform, Docker)
Type "sentris scan ."
Sleep 400ms
Enter
Sleep 2s

# 2. The "Holy Sh*t" Moment: 1-Command Polyglot & IaC Self-Healing
Type "sentris fix . --all --yes"
Sleep 400ms
Enter
Sleep 3.5s

# 3. AI Coding Agent Firewall: Scrub .mcp.json & Claude Code .jsonl Transcripts
Type "sentris fix --workstation --all --yes"
Sleep 400ms
Enter
Sleep 2.5s

# 4. Zero-Knowledge 50-Repo Blast Radius (0 Bytes of Source Uploaded)
Type "sentris team"
Sleep 400ms
Enter
Sleep 2.5s

# 5. 10-Second Vanta / Drata SOC 2, ISO 27001, OWASP NHI & PCI-DSS v4.0 Evidence Pack
Type "sentris audit --verify --export-vanta vanta-evidence.json"
Sleep 400ms
Enter
Sleep 2.5s

# 6. 1-Click Byte-Exact Atomic Rollback
Type "sentris rollback"
Sleep 400ms
Enter
Sleep 2s
