# MIT License

# Copyright (c) 2020 Eric Lesiuta

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import ipaddress
import json
import os
import setuptools
import signal
import sys
import textwrap
import time


def setup():
    setuptools.setup(
        name="microsnitch",
        version="0.0.1",
        description="See which processes make remote network connections",
        long_description=textwrap.dedent('''\
            See which processes make remote network connections  
            Logs and config are stored in ~/.config/microsnitch/snitch.json  
            Do not rely on this for security or anything remotely critical  
            Quick experiment inspired by programs such as:  
            - Little Snitch
            - OpenSnitch
            - GlassWire
            - simplewall
            '''),
        long_description_content_type="text/markdown",
        url="https://github.com/elesiuta/microsnitch",
        py_modules=["microsnitch"],
        entry_points={"console_scripts": ["microsnitch = microsnitch:main"]},
        install_requires=["psutil", "python-daemon"],
        classifiers=[
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: MIT License",
            "Operating System :: OS Independent",
            "Topic :: System :: Networking :: Monitoring",
        ],
    )


def read() -> dict:
    file_path = os.path.join(os.path.expanduser("~"), ".config", "microsnitch", "snitch.json")
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8", errors="surrogateescape") as json_file:
            data = json.load(json_file)
        return data
    return {
        "Config": {"Refresh period": 1.0, "Write counter": 600},
        "Executables": [],
        "Processes": {}
        }


def write(snitch: dict):
    file_path = os.path.join(os.path.expanduser("~"), ".config", "microsnitch", "snitch.json")
    if not os.path.isdir(os.path.dirname(file_path)):
        os.makedirs(os.path.dirname(file_path))
    try:
        with open(file_path, "w", encoding="utf-8", errors="surrogateescape") as json_file:
            json.dump(snitch, json_file, indent=2, separators=(',', ': '), sort_keys=True, ensure_ascii=False)
    except Exception:
        print("microsnitch write error", file=sys.stderr)


def terminate(snitch: dict):
    write(snitch)
    sys.exit(0)


def update(snitch: dict):
    ctime = time.ctime()
    for conn in psutil.net_connections(kind='inet'):
        try:
            if conn.raddr and not ipaddress.ip_address(conn.raddr.ip).is_private:
                proc = psutil.Process(conn.pid)
                if proc.exe() not in snitch["Processes"]:
                    snitch["Executables"].append(proc.exe())
                    snitch["Processes"][proc.exe()] = {
                        "name": proc.name(),
                        "cmdlines": [str(proc.cmdline())],
                        "first seen": ctime,
                        "last seen": ctime,
                        "days seen": 1,
                    }
                else:
                    entry = snitch["Processes"][proc.exe()]
                    if str(proc.cmdline()) not in entry["cmdlines"]:
                        entry["cmdlines"].apppend(str(proc.cmdline()))
                    if ctime.split()[:3] != entry["last seen"].split()[:3]:
                        entry["days seen"] += 1
                    entry["last seen"] = ctime
        except Exception:
            print("microsnitch update error", file=sys.stderr)


def loop():
    snitch = read()
    signal.signal(signal.SIGTERM, lambda *args: terminate(snitch))
    signal.signal(signal.SIGINT, lambda *args: terminate(snitch))
    counter = 0
    while True:
        update(snitch)
        time.sleep(snitch["Config"]["Refresh period"])
        if counter >= snitch["Config"]["Write counter"]:
            write(snitch)
            counter = 0
        else:
            counter += 1


def main():
    with daemon.DaemonContext():
        loop()


if __name__ == "__main__":
    if len(sys.argv) >= 2 and "setup" in sys.argv[1]:
        _ = sys.argv.pop(1)
        sys.exit(setup())

import daemon
import psutil
main()
