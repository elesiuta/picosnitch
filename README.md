# picosnitch
- An ultra lightweight program for linux that monitors your system and notifies you whenever it sees a new program that connects to the network
- Or when the sha256 changes for one of those programs (can also check VirtusTotal)
- And features a curses based UI for browsing past connections
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
- config and list of seen processes are stored in `~/.config/picosnitch/snitch.json`
- stop picosnitch if it is currently running before making any edits otherwise your changes will be lost
```python
{
  "Config": {
    "DB write min (sec)": 1, # Minimum time (seconds) between writing logs to snitch.db
    "Keep logs (days)": 365, # How many days to keep connection logs
    "Log command lines": True, # Log command line args for each executable
    "Log remote address": True, # Log remote addresses for each executable
    "Log ignore": [80, "chrome", "firefox"], # List of process names (str) or ports (int)
    # will omit connections that match any of these from the connection log (snitch.db)
    # the process and executable will still be recorded in snitch.json
    "VT API key": "", # API key for VirusTotal, leave blank to disable
    "VT file upload": False, # Only hashes are uploaded by default
    "VT limit request": 15 # Number of seconds between requests
  },
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
- required dependencies (installed automatically from PyPI on setup if not already present)  
`plyer psutil vt-py`
- additional dependency ([requires manual installation]((https://github.com/iovisor/bcc/blob/master/INSTALL.md)))  
`bcc`
