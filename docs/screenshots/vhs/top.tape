# picosnitch top screenshot recording.
# Wrapper script must start mock_feed.py before invoking VHS so the
# events.sock exists -- top.py refuses to spawn its own monitor as
# non-root.

Output docs/screenshots/out/top.webm

Set FontSize 20
Set Width 1800
Set Height 1100
Set Padding 24
# Custom theme: TokyoNight Storm with a darker `blue` so the curses
# CP_CHROME pair (white-on-blue header / help popup) doesn't wash out.
Set Theme '{"name":"PicosnitchDark","background":"#24283b","foreground":"#c0caf5","cursor":"#c0caf5","selection":"#364a82","black":"#1d202f","red":"#f7768e","green":"#9ece6a","yellow":"#e0af68","blue":"#1f3a7a","magenta":"#bb9af7","cyan":"#7dcfff","white":"#a9b1d6","brightBlack":"#414868","brightRed":"#f7768e","brightGreen":"#9ece6a","brightYellow":"#e0af68","brightBlue":"#7aa2f7","brightMagenta":"#bb9af7","brightCyan":"#7dcfff","brightWhite":"#ffffff"}'
Set Shell "bash"
Set TypingSpeed 60ms
Set Framerate 20

Hide
Type "PICOSNITCH_TEST=1 PYTHONUNBUFFERED=1 .venv/bin/python -m picosnitch top"
Enter
Sleep 5s
Show

Screenshot docs/screenshots/out/top-default.png
Sleep 4s

# Toggle sort to recv
Type "s"
Sleep 3s
Screenshot docs/screenshots/out/top-sort-recv.png
Sleep 2.5s

# Cycle sort once more to show it rotates through columns
Type "s"
Sleep 3s

# Show help
Type "?"
Sleep 3s
Screenshot docs/screenshots/out/top-help.png
Sleep 2.5s
Type "?"
Sleep 2s

# Pause
Type "p"
Sleep 3s
Screenshot docs/screenshots/out/top-paused.png
Sleep 2.5s

# Resume
Type "p"
Sleep 3s

# Reset counters
Type "r"
Sleep 3s

# quit (hidden so the trailing bash prompt with the typed command
# doesn't appear in the final video)
Hide
Type "q"
Sleep 1s
