#!/usr/bin/env python3
# picosnitch
# Copyright (C) 2020-2023 Eric Lesiuta

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# https://github.com/elesiuta/picosnitch

import multiprocessing
import os
import pickle
import signal
import sys
import threading
import time
import typing

from .event_structures import BpfEvent
from .notifcation_manager import NotificationManager
from .utils import write_snitch


def primary_subprocess_helper(snitch: dict, new_processes: typing.List[bytes]) -> None:
    """iterate over the list of process/connection data to update the snitch dictionary and create notifications on new entries"""
    datetime_now = time.strftime("%Y-%m-%d %H:%M:%S")
    for proc_pickle in new_processes:
        proc: BpfEvent = pickle.loads(proc_pickle)
        proc_name, proc_exe, snitch_names, snitch_executables, parent = proc["name"], proc["exe"], snitch["Names"], snitch["Executables"], ""
        for i in range(2):
            notification = []
            if proc_name in snitch_names:
                if proc_exe not in snitch_names[proc_name]:
                    snitch_names[proc_name].append(proc_exe)
            else:
                snitch_names[proc_name] = [proc_exe]
                notification.append("name")
            if proc_exe in snitch_executables:
                if proc_name not in snitch_executables[proc_exe]:
                    snitch_executables[proc_exe].append(proc_name)
            else:
                snitch_executables[proc_exe] = [proc_name]
                notification.append("exe")
                if proc_exe not in snitch["SHA256"]:
                    snitch["SHA256"][proc_exe] = {}
            if notification:
                snitch["Exe Log"].append(f"{datetime_now} {proc_name:<16.16} {proc_exe} (new {', '.join(notification)}){parent}")
                NotificationManager().toast(f"picosnitch: {proc_name} {proc_exe}")
            proc_name, proc_exe, snitch_names, snitch_executables, parent = proc["pname"], proc["pexe"], snitch["Parent Names"], snitch["Parent Executables"], " (parent)"


def primary_subprocess(snitch, snitch_pipes, secondary_pipe, q_error, q_in, _q_out):
    """first to receive connection data from monitor, more responsive than secondary, creates notifications and writes exe.log, error.log, and record.json"""
    try:
        os.nice(-20)
    except Exception:
        pass
    # init variables for loop
    parent_process = multiprocessing.parent_process()
    snitch_record = pickle.dumps([snitch["Executables"], snitch["Names"], snitch["Parent Executables"], snitch["Parent Names"], snitch["SHA256"]])
    last_write = 0
    write_record = False
    processes_to_send = []
    # init notifications
    if snitch["Config"]["Desktop notifications"]:
        NotificationManager().enable_notifications()
    # init signal handlers
    def write_snitch_and_exit(snitch: dict, q_error: multiprocessing.Queue, snitch_pipes):
        while not q_error.empty():
            error = q_error.get()
            snitch["Error Log"].append(time.strftime("%Y-%m-%d %H:%M:%S") + " " + error)
            # shorten some common error messages before displaying them and after writing them to error.log
            error = error.replace("FD Read Error and PID Read Error and FUSE Read Error for", "Read Error for")
            if len(error) > 50:
                error = error[:47] + "..."
            NotificationManager().toast(error, file=sys.stderr)
        write_snitch(snitch)
        for snitch_pipe in snitch_pipes:
            snitch_pipe.close()
        sys.exit(0)
    signal.signal(signal.SIGTERM, lambda *args: write_snitch_and_exit(snitch, q_error, snitch_pipes))
    signal.signal(signal.SIGINT, lambda *args: write_snitch_and_exit(snitch, q_error, snitch_pipes))
    # init thread to receive new connection data over pipe
    def snitch_pipe_thread(snitch_pipes, pipe_data: list, listen: threading.Event, ready: threading.Event):
        while True:
            listen.wait()
            new_processes = pipe_data[0]
            while listen.is_set():
                for i in range(5):
                    if any(snitch_pipe.poll() for snitch_pipe in snitch_pipes):
                        break
                    time.sleep(1)
                for snitch_pipe in snitch_pipes:
                    while snitch_pipe.poll():
                        new_processes.append(snitch_pipe.recv_bytes())
            ready.set()
    listen, ready = threading.Event(), threading.Event()
    pipe_data = [[]]
    thread = threading.Thread(target=snitch_pipe_thread, args=(snitch_pipes, pipe_data, listen, ready,), daemon=True)
    thread.start()
    listen.set()
    # main loop
    while True:
        if not parent_process.is_alive():
            q_error.put("picosnitch has stopped")
            write_snitch_and_exit(snitch, q_error, snitch_pipes)
        try:
            # check for errors
            while not q_error.empty():
                error = q_error.get()
                snitch["Error Log"].append(time.strftime("%Y-%m-%d %H:%M:%S") + " " + error)
                # shorten some common error messages before displaying them and after writing them to error.log
                error = error.replace("FD Read Error and PID Read Error and FUSE Read Error for", "Read Error for")
                if len(error) > 50:
                    error = error[:47] + "..."
                # don't need to toast fallback success messages
                if error.startswith("Fallback to FUSE hash successful on ") or error.startswith("Fallback to PID hash successful on "):
                    continue
                NotificationManager().toast(error, file=sys.stderr)
            # get list of new processes and connections since last update
            listen.clear()
            if not ready.wait(timeout=300):
                q_error.put("thread timeout error for primary subprocess")
                write_snitch_and_exit(snitch, q_error, snitch_pipes)
            new_processes = pipe_data[0]
            pipe_data[0] = []
            ready.clear()
            listen.set()
            # process the list and update snitch, send new process/connection data to secondary subprocess if ready
            primary_subprocess_helper(snitch, new_processes)
            processes_to_send += new_processes
            while not q_in.empty():
                msg: dict = pickle.loads(q_in.get())
                if msg["type"] == "ready":
                    secondary_pipe.send_bytes(pickle.dumps(len(processes_to_send)))
                    for proc_pickle in processes_to_send:
                        secondary_pipe.send_bytes(proc_pickle)
                    secondary_pipe.send_bytes(pickle.dumps("done"))
                    processes_to_send = []
                    break
                elif msg["type"] == "sha256":
                    if msg["exe"] in snitch["SHA256"]:
                        if msg["sha256"] not in snitch["SHA256"][msg["exe"]]:
                            snitch["SHA256"][msg["exe"]][msg["sha256"]] = "VT Pending"
                            snitch["Exe Log"].append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg['sha256']:<16.16} {msg['exe']} (new hash)")
                            NotificationManager().toast(f"New sha256: {msg['exe']}")
                    else:
                        snitch["SHA256"][msg["exe"]] = {msg["sha256"]: "VT Pending"}
                elif msg["type"] == "vt_result":
                    if msg["exe"] in snitch["SHA256"]:
                        if msg["sha256"] not in snitch["SHA256"][msg["exe"]]:
                            snitch["Exe Log"].append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg['sha256']:<16.16} {msg['exe']} (new hash)")
                            NotificationManager().toast(f"New sha256: {msg['exe']}")
                        snitch["SHA256"][msg["exe"]][msg["sha256"]] = msg["result"]
                    else:
                        snitch["SHA256"][msg["exe"]] = {msg["sha256"]: msg["result"]}
                    if msg["suspicious"]:
                        snitch["Exe Log"].append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg['sha256']:<16.16} {msg['exe']} (suspicious)")
                        NotificationManager().toast(f"Suspicious VT results: {msg['exe']}")
                    else:
                        snitch["Exe Log"].append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg['sha256']:<16.16} {msg['exe']} (clean)")
            # write the snitch dictionary to record.json, error.log, and exe.log (limit writes to reduce disk wear)
            if snitch["Error Log"] or snitch["Exe Log"] or time.time() - last_write > 30:
                new_record = pickle.dumps([snitch["Executables"], snitch["Names"], snitch["Parent Executables"], snitch["Parent Names"], snitch["SHA256"]])
                if new_record != snitch_record:
                    snitch_record = new_record
                    write_record = True
                write_snitch(snitch, write_record=write_record)
                last_write = time.time()
                write_record = False
        except Exception as e:
            q_error.put("primary subprocess %s%s on line %s" % (type(e).__name__, str(e.args), sys.exc_info()[2].tb_lineno))
