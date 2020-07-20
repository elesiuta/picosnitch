
# picosnitch
- See which processes make remote network connections
- Logs and config are stored in ~/.config/picosnitch/snitch.json and updated every 10 minutes or on SIGTERM
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
  - you should be able to just install scapy or python3-scapy from your distribution
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
- make sure you're running as an administrator if using Scapy
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
    "Polling interval": 0.2, # float in seconds
    "Remote address unlog": [80, "firefox"], # list of process names (str) or ports (int) to omit addresses
    "Use pcap": false, # bool, requires Scapy to be installed
    "Write interval": 600 # how often to write this file in seconds
  },
  "Errors": [], # Log of errors by time
  "Latest Entries": [], # Log of entries by time
  "Names": {}, # Log of process names and respective executable(s)
  "Processes": {}, # Log of processes by executable
  "Remote Addresses": {} # Log of remote addresses
}
```
