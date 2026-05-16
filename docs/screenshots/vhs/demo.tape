# Short demo recording stitched into a single webm for the README hero
# block. Intentionally smaller / faster framing than tui.tape.

Output docs/screenshots/out/terminal_ui.webm

Set FontSize 18
Set Width 1440
Set Height 820
Set Padding 18
Set Theme '{"name":"PicosnitchDark","background":"#24283b","foreground":"#c0caf5","cursor":"#c0caf5","selection":"#364a82","black":"#1d202f","red":"#f7768e","green":"#9ece6a","yellow":"#e0af68","blue":"#1f3a7a","magenta":"#bb9af7","cyan":"#7dcfff","white":"#a9b1d6","brightBlack":"#414868","brightRed":"#f7768e","brightGreen":"#9ece6a","brightYellow":"#e0af68","brightBlue":"#7aa2f7","brightMagenta":"#bb9af7","brightCyan":"#7dcfff","brightWhite":"#ffffff"}'
Set Shell "bash"
Set TypingSpeed 50ms
Set PlaybackSpeed 1.0

Hide
Type "PICOSNITCH_TEST=1 PYTHONUNBUFFERED=1 .venv/bin/python -m picosnitch tui"
Enter
Sleep 3s
Show

Sleep 2s
# Cycle through Process / Parent / Grandparent / Network sections, with
# enough breathing room between presses to read each view change.
Right@900ms 3
Sleep 1.5s
Right@900ms 4
Sleep 1.5s
Right@900ms 5
Sleep 1.5s
Right@900ms 5
Sleep 2s
# Hop to the live feed for the finale.
Type "l"
Sleep 6s

Hide
Type "q"
Sleep 0.5s
