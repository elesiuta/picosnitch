# picosnitch
- An extremely simple, reliable, and lightweight program for linux to help protect your privacy
  - It monitors your system and notifies you whenever it sees a new program that connects to the network
  - Or when the sha256 changes for one of those programs (can also check [VirusTotal](https://www.virustotal.com))
  - And features a curses based UI for browsing past connections
- For advanced users who know what should be running on their system and can make network connections
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
- run daemon with  
`picosnitch start`
- stop daemon with  
`picosnitch stop`
- view past connections with  
`picosnitch view`
## configuration
- config is stored in `~/.config/picosnitch/snitch_config.json`
- use `picosnitch restart` if daemon is currently running for any changes to take effect
```python
{
  "DB write (sec)": 1, # Minimum time (seconds) between writing logs to snitch.db
  # increasing it decreases disk writes by grouping connections into larger time buckets
  # reducing time precision, decreasing database size, and increasing hash latency
  # values too large could cause processes to fall out of cache before hashing, see NOFILE
  "Keep logs (days)": 365, # How many days to keep connection logs
  "Log command lines": True, # Log command line args for each executable
  "Log remote address": True, # Log remote addresses for each executable
  "Log ignore": [80, "chrome", "firefox"], # List of process names (str) or ports (int)
  # will omit connections that match any of these from the connection log (snitch.db)
  # the process and executable will still be recorded in snitch.json
  "NOFILE": None, # Set the maximum number of open file descriptors (int)
  # increasing it allows more processes to be cached (typical system default is 1024)
  # improving the performance and reliability of hashing processes (also caches hash)
  # e.g. short lived processes that may terminate before they can be hashed will live in cache
  "VT API key": "", # API key for VirusTotal, leave blank to disable
  "VT file upload": False, # Only hashes are uploaded by default
  "VT limit request": 15 # Number of seconds between requests
}
```
- a short summary of seen processes is stored in `~/.config/picosnitch/snitch_summary.json`
```python
{
  "Latest Entries": [], # Log of entries by time
  "Names": {}, # Log of processes by name containing respective executable(s)
  "Processes": {}, # Log of processes by executable containing respective name(s)
  "SHA256": {} # Log of processes by executable containing sha256 hash(es) and VirusTotal results
}
```
- the connection log is stored in `~/.config/picosnitch/snitch.db`
- the error log is stored in `~/.config/picosnitch/error.log`
# building from source
- install from source using python 3 with  
`python setup.py install --user`
- dependencies installed automatically from PyPI on setup if not already present  
`dbus-python psutil vt-py`
- additional dependency, [requires manual installation](https://github.com/iovisor/bcc/blob/master/INSTALL.md)  
`bcc`
