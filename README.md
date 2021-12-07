[![GitHub release](https://img.shields.io/github/v/release/elesiuta/picosnitch?color=00a0a0)](https://github.com/elesiuta/picosnitch/releases)
[![PyPI release](https://img.shields.io/pypi/v/picosnitch?color=00a0a0)](https://pypi.org/project/picosnitch)
[![GitHub commits since latest release](https://img.shields.io/github/commits-since/elesiuta/picosnitch/latest/master?color=00a0a0)](https://github.com/elesiuta/picosnitch/commits/master)
[![GitHub contributors](https://img.shields.io/github/contributors/elesiuta/picosnitch?color=00a0a0)](https://github.com/elesiuta/picosnitch/graphs/contributors)
[![File size](https://img.shields.io/github/size/elesiuta/picosnitch/picosnitch.py?color=00a0a0)](https://github.com/elesiuta/picosnitch/blob/master/picosnitch.py)
[![Monthly downloads (without mirrors)](https://img.shields.io/pypi/dm/picosnitch?color=00a0a0&label=downloads%20%28pypistats%29)](https://pypistats.org/packages/picosnitch)
[![Total downloads](https://img.shields.io/badge/dynamic/json?color=00a0a0&label=downloads%20%28pepy%29&query=total_downloads&url=https%3A%2F%2Fapi.pepy.tech%2Fapi%2Fprojects%2Fpicosnitch)](https://pepy.tech/project/picosnitch)

# picosnitch
- An extremely simple, reliable, and lightweight program for linux to help protect your privacy
  - It monitors your system and notifies you whenever it sees a new program that connects to the network
  - Or when the sha256 changes for one of those programs (can also check [VirusTotal](https://www.virustotal.com))
  - And features a curses based UI for browsing past connections
- For advanced users who know what should be running on their system and when they should be making network connections
  - Only you can decide which programs to trust, so picosnitch leaves this decision up to you and just focusses on doing one thing well
  - A program you can't trust to make network connections also can't be trusted not to negate any firewall rules, so blocking or sandboxing these programs is out of scope for picosnitch (also beware of programs running as root that may try to stop/modify picosnitch)
- Inspired by programs such as GlassWire, Little Snitch, and OpenSnitch

# getting started

## installation
- install from PyPI with  
`pip3 install picosnitch[full] --upgrade --user`
- depends on the [BPF Compiler Collection](https://github.com/iovisor/bcc/blob/master/INSTALL.md) (e.g. for Ubuntu)  
`sudo apt install python3-bpfcc`

## usage
- you can run picosnitch either as a standalone daemon, or with systemd
  - use the same method to stop picosnitch as you used to start it
- run as a standalone daemon
  - start|stop|restart with `picosnitch start|stop|restart`
- run with systemd
  - setup with `picosnitch systemd`
  - enable|disable autostart on reboot with `systemctl enable|disable picosnitch`
  - start|stop|restart with `systemctl start|stop|restart picosnitch`
  - show detailed status with `systemctl status picosnitch`
- user interface for browsing past connection
  - start with `picosnitch view`
  - `space/enter`: filter on entry `backspace`: remove filter `h/H`: cycle through history `t/T`: cycle time range `r`: refresh view `q`: quit
- other commands
  - show basic status `picosnitch status`
  - show version info `picosnitch version`
  - show help `picosnitch help`

## configuration
- config is stored in `~/.config/picosnitch/config.json`
  - restart picosnitch if it is currently running for any changes to take effect

```python
{
  "DB retention (days)": 365, # How many days to keep connection logs
  "DB write limit (seconds)": 1, # Minimum time between writing logs to snitch.db
  # increasing it decreases disk writes by grouping connections into larger time windows
  # reducing time precision, decreasing database size, and increasing hash latency
  # values too large could cause processes to fall out of cache before hashing, see NOFILE
  "Desktop notifications": True, # Try connecting to dbus for creating system notifications
  "Log addresses": True, # Log remote addresses for each executable
  "Log commands": True, # Log command line args for each executable
  "Log ignore": [], # List of process names (str) or ports (int)
  # will omit connections that match any of these from the connection log (snitch.db)
  # the process and executable will still be recorded in summary.json
  "Set RLIMIT_NOFILE": None, # Set the maximum number of open file descriptors (int)
  # increasing it allows more processes to be cached (typical system default is 1024)
  # improving the performance and reliability of hashing processes (also caches hash)
  # e.g. short lived processes that may terminate before they can be hashed will live in cache
  "VT API key": "", # API key for VirusTotal, leave blank to disable (str)
  "VT file upload": False, # Upload file if hash not found, only hashes are used by default
  "VT request limit (seconds)": 15 # Number of seconds between requests (free tier quota)
}
```

## logging
- a short summary of seen processes is stored in `~/.config/picosnitch/summary.json`
  - this is used for determining whether to create a notification

```python
{
  "Latest Entries": [], # Log of entries by time
  "Names": {}, # Log of processes by name containing respective executable(s)
  "Processes": {}, # Log of processes by executable containing respective name(s)
  "SHA256": {} # Log of processes by executable containing sha256 hash(es) and VirusTotal results
}
```
- the full connection log is stored in `~/.config/picosnitch/snitch.db`
  - this is used for `picosnitch view`
- the error log is stored in `~/.config/picosnitch/error.log`
  - errors will also trigger a notification and are usually caused by far too many processes/connections
  - for most people in most cases, this should raise suspicion that some other program may be misbehaving

# building from source
- install from source using python 3 with  
`python setup.py install --user`
- dependencies installed automatically from PyPI on setup if not already present  
`dbus-python psutil vt-py`
- additional dependency, [requires manual installation](https://github.com/iovisor/bcc/blob/master/INSTALL.md)  
`bcc`
