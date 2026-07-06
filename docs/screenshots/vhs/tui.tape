# picosnitch TUI screenshot recording.
# Run via VHS: `vhs docs/screenshots/vhs/tui.tape`.
# The wrapper script ensures the seeded DB exists and starts mock_feed.py
# so the "Live" tab has data.
#
# The TUI sidebar lists 19 views in 4 sections (Process, Parent,
# Grandparent, Network). RIGHT/LEFT cycle through them in display order;
# 'l' jumps to the live feed; '/' opens the find filter.

Output docs/screenshots/out/tui.webm

Set FontSize 20
Set Width 1800
Set Height 1100
Set Padding 24
Set TypingSpeed 60ms
Set PlaybackSpeed 1.0
Set Framerate 20
# Custom theme: TokyoNight Storm with a darker `blue` so the curses
# CP_CHROME pair (white-on-blue header / help popup) doesn't wash out.
Set Theme '{"name":"PicosnitchDark","background":"#24283b","foreground":"#c0caf5","cursor":"#c0caf5","selection":"#364a82","black":"#1d202f","red":"#f7768e","green":"#9ece6a","yellow":"#e0af68","blue":"#1f3a7a","magenta":"#bb9af7","cyan":"#7dcfff","white":"#a9b1d6","brightBlack":"#414868","brightRed":"#f7768e","brightGreen":"#9ece6a","brightYellow":"#e0af68","brightBlue":"#7aa2f7","brightMagenta":"#bb9af7","brightCyan":"#7dcfff","brightWhite":"#ffffff"}'
Set Shell "bash"

Hide
Type "PICOSNITCH_TEST=1 PYTHONUNBUFFERED=1 .venv/bin/python -m picosnitch tui"
Enter
# Wait for the splash to clear
Wait+Screen@60s /Executable/
# Brief settle for the query thread to populate the rows
Sleep 1s
Show

# view 0: Process > Executable
Screenshot docs/screenshots/out/tui-executables.png
Sleep 2s

# view 0 -> 1: Process > Name
Right
Sleep 2s
Screenshot docs/screenshots/out/tui-process-names.png
Sleep 1s

# views 2-5: cycle through the rest of Process and into Parent > Name.
# Stop on each tab for ~1.5s so the view is readable.
Right
Sleep 1.5s
Right
Sleep 1.5s
Right
Sleep 1.5s
Right
Sleep 1.5s
Screenshot docs/screenshots/out/tui-parent-names.png
Sleep 1s

# views 6-17: cycle through the remaining Parent / Grandparent /
# Network views, ending on Network > Domain.
Right
Sleep 1.5s
Right
Sleep 1.5s
Right
Sleep 1.5s
Right
Sleep 1.5s
Right
Sleep 1.5s
Right
Sleep 1.5s
Right
Sleep 1.5s
Right
Sleep 1.5s
Right
Sleep 1.5s
Right
Sleep 1.5s
Right
Sleep 1.5s
Right
Sleep 2s
Screenshot docs/screenshots/out/tui-domains.png
Sleep 1.5s

# Find filter on the Domain view
Type@250ms "/"
Sleep 1s
Type@180ms "fastmail"
Sleep 2s
Screenshot docs/screenshots/out/tui-find.png
Sleep 1.2s
Escape
Sleep 1.2s

# Switch from Domain to Remote Address (one row up in the sidebar)
# to showcase GeoIP country-code annotations on each remote IP.
Up
Sleep 2s
Screenshot docs/screenshots/out/tui-remote-addresses.png
Sleep 1.2s

# Jump to the live feed (global 'l' shortcut)
Type "l"
Sleep 5s
Screenshot docs/screenshots/out/tui-live.png
Sleep 1.5s

# quit (hidden so the trailing bash prompt with the typed command
# doesn't appear in the final video)
Hide
Type "q"
Sleep 1s
