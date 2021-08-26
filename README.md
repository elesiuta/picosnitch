# picosnitch
- Monitors your system to notify you whenever a program makes its first remote network connection (while picosnitch has been running)
- Or when the sha256 changes for one of these programs
- Connection logs and config are stored in ~/.config/picosnitch/snitch.json
- Error log is stored in ~/.config/picosnitch/error.log
- Inspired by programs such as:
  - GlassWire
  - Little Snitch
  - OpenSnitch
  - simplewall
  - tinysnitch
- picosnitch only provides monitoring and notification capabilities, see the above programs for features such as a GUI, bandwidth tracking, firewall configuration, or filtering
# getting started
## linux
- install from PyPI with  
`pip3 install picosnitch[full] --upgrade --user`
- depends on the [BPF Compiler Collection](https://github.com/iovisor/bcc/blob/master/INSTALL.md)  
`sudo apt install python3-bpfcc`
- run daemon with  
`picosnitch start`
- stop daemon with  
`picosnitch stop`
## windows
- no longer supported for now, use a version <= v0.2.5
## building from source
- install from source using python 3 with  
`python setup.py install --user`
- required dependencies (installed automatically from PyPI on setup if not already present)  
`plyer psutil vt-py`
- additional dependency (requires manual installation)  
`bcc`
# configuration
- stored in ~/.config/picosnitch/snitch.json
- terminate picosnitch if it is currently running before making any edits otherwise your changes will be lost
```python
{
  "Config": {
    "Log command lines": True, # Log command line args for each executable
    "Log remote address": True, # Log remote addresses for each executable
    "Only log connections": True, # Only log processes that make remote network connections
    # otherwise log every new process from exec()
    "Remote address unlog": [80, "chrome", "firefox"], # List of process names (str) or ports (int)
    # will omit connections that match any of these from the log of remote addresses to avoid clutter
    # the process and executable will still be logged if it has not been already
    "VT API key": "", # API key for VirusTotal, leave blank to disable
    "VT file upload": False, # Only hashes are uploaded by default
    "VT limit request": 15 # Number of seconds between requests
  },
  "Latest Entries": [], # Log of entries by time
  "Names": {}, # Log of processes by name containing respective executable(s)
  "Processes": {}, # Log of processes by executable containing:
  # cmdlines, days seen, first seen, last seen, name, ports, remote addresses, results
  # some cmdlines are consolidated using * as a wildcard, results are obtained from VirusTotal
  "Remote Addresses": {} # Log of remote addresses containing respective executable(s)
}
```
