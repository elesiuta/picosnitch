
# picosnitch
- Monitors your system to notify you whenever a program makes its first remote network connection (while picosnitch has been running)
- Logs and config are stored in ~/.config/picosnitch/snitch.json
- Polls connections and processes at 0.2s intervals by default
- Optionally sniff all traffic for new connections using Scapy for improved reliability
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
`pip3 install picosnitch --upgrade --user`
- optionally install Scapy
  - you should be able to just install scapy or python3-scapy using your distribution's package manager
  - [https://scapy.readthedocs.io/en/latest/installation.html](https://scapy.readthedocs.io/en/latest/installation.html)
- run daemon with  
`picosnitch`
- or run daemon as root to use Scapy  
`sudo -E python3 -m picosnitch`
## windows
- install from PyPI with  
`pip install picosnitch --upgrade`
- optionally install Scapy
  - [https://scapy.readthedocs.io/en/latest/installation.html](https://scapy.readthedocs.io/en/latest/installation.html)
- run with  
`picosnitch`
- you'll probably need to run it as an administrator if using Scapy
## building from source
- install from source using python 3 with  
`python setup.py install --user`
- required dependencies (installed automatically from PyPI on setup if not already present)  
`filelock plyer psutil python-daemon`
- optional dependency (requires manual installation)  
`scapy`
- picosnitch.py can also be run directly
# configuration
- stored in ~/.config/picosnitch/snitch.json
- terminate picosnitch if it is currently running before making any edits otherwise your changes will be lost
```python
{
  "Config": {
    "Enable pcap": false, # bool, use Scapy to sniff traffic
    "Polling interval": 0.2, # float in seconds
    "Remote address unlog": [80, "firefox"] # list of process names (str) or remote ports (int)
    # will omit connections that match any of these from the log of remote addresses to avoid clutter
    # the process and executable will still be logged if it has not been already
  },
  "Errors": [], # Log of errors by time
  "Latest Entries": [], # Log of entries by time
  "Names": {}, # Log of processes by name containing respective executable(s)
  "Processes": {}, # Log of processes by executable containing:
  # cmdlines, days seen, first seen, last seen, name, ports, remote addresses
  # some cmdlines are consolidated using * as a wildcard, ports are remote ports
  "Remote Addresses": {} # Log of remote addresses containing respective executable(s)
  # and packet summaries if pcap is enabled and process was too short lived for detection via polling
  # some packet summaries are consolidated using * as a wildcard
}
```
