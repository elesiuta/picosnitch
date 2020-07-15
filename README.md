# microsnitch
- See which processes make remote network connections  
- Logs and config are stored in ~/.config/microsnitch/snitch.json and updated every 10 minutes or on sigterm  
- Do not rely on this for security or anything remotely critical (only checks connections at 1s intervals since there's no per process network io counter, would need a network driver to provide any sort of reliability)   
- Quick experiment inspired by programs such as:  
  - Little Snitch
  - OpenSnitch
  - GlassWire
  - simplewall
# run
- run as a daemon with  
`python microsnitch.py`
- or install with  
`python setup.py install`
- then run as a daemon with  
`microsnitch`
