#!/usr/bin/env python3
# picosnitch
# Copyright (C) 2020 Eric Lesiuta

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

import logging
import multiprocessing
import os
import pickle
import signal
import sys
import threading
import time
import typing

from ..types import BpfEvent
from ..utils import save_state


def _toast(q_notify: multiprocessing.Queue, msg: str, level=logging.INFO) -> None:
    """send notification message to the notification subprocess"""
    try:
        q_notify.put_nowait(msg)
    except Exception:
        logging.log(level, msg)


def handle_new_processes(state: dict, new_processes: typing.List[bytes], q_notify: multiprocessing.Queue) -> None:
    """iterate over the list of process/connection data to update the state dictionary and create notifications on new entries"""
    datetime_now = time.strftime("%Y-%m-%d %H:%M:%S")
    for proc_pickle in new_processes:
        proc: BpfEvent = pickle.loads(proc_pickle)
        proc_name, proc_exe, state_names, state_executables, parent = proc["name"], proc["exe"], state["Names"], state["Executables"], ""
        for i in range(2):
            notification = []
            if proc_name in state_names:
                if proc_exe not in state_names[proc_name]:
                    state_names[proc_name].append(proc_exe)
            else:
                state_names[proc_name] = [proc_exe]
                notification.append("name")
            if proc_exe in state_executables:
                if proc_name not in state_executables[proc_exe]:
                    state_executables[proc_exe].append(proc_name)
            else:
                state_executables[proc_exe] = [proc_name]
                notification.append("exe")
                if proc_exe not in state["SHA256"]:
                    state["SHA256"][proc_exe] = {}
            if notification:
                state["Exe Log"].append(f"{datetime_now} {proc_name:<16.16} {proc_exe} (new {', '.join(notification)}){parent}")
                _toast(q_notify, f"picosnitch: {proc_name} {proc_exe}")
            proc_name, proc_exe, state_names, state_executables, parent = proc["pname"], proc["pexe"], state["Parent Names"], state["Parent Executables"], " (parent)"


def run_primary(state, event_pipes, secondary_pipe, q_error, q_notify, q_in, _q_out):
    """first to receive connection data from monitor, more responsive than secondary, creates notifications and writes exe.log, error.log, and state.json"""
    try:
        os.nice(-20)
    except Exception:
        pass
    # init variables for loop
    parent_process = multiprocessing.parent_process()
    state_record = pickle.dumps([state["Executables"], state["Names"], state["Parent Executables"], state["Parent Names"], state["SHA256"]])
    last_write = 0
    write_record = False
    processes_to_send = []

    # init signal handlers
    def save_state_and_exit(state: dict, q_error: multiprocessing.Queue, event_pipes):
        while not q_error.empty():
            error = q_error.get()
            state["Error Log"].append(time.strftime("%Y-%m-%d %H:%M:%S") + " " + error)
            # shorten some common error messages before displaying them and after writing them to error.log
            error = error.replace("FD Read Error and PID Read Error and FUSE Read Error for", "Read Error for")
            if len(error) > 50:
                error = error[:47] + "..."
            _toast(q_notify, error, level=logging.WARNING)
        save_state(state)
        for event_pipe in event_pipes:
            event_pipe.close()
        sys.exit(0)

    signal.signal(signal.SIGTERM, lambda *args: save_state_and_exit(state, q_error, event_pipes))
    signal.signal(signal.SIGINT, lambda *args: save_state_and_exit(state, q_error, event_pipes))

    # init thread to receive new connection data over pipe
    def event_pipe_thread(event_pipes, pipe_data: list, listen: threading.Event, ready: threading.Event):
        while True:
            listen.wait()
            new_processes = pipe_data[0]
            while listen.is_set():
                for i in range(5):
                    if any(event_pipe.poll() for event_pipe in event_pipes):
                        break
                    time.sleep(1)
                for event_pipe in event_pipes:
                    while event_pipe.poll():
                        new_processes.append(event_pipe.recv_bytes())
            ready.set()

    listen, ready = threading.Event(), threading.Event()
    pipe_data = [[]]
    thread = threading.Thread(
        target=event_pipe_thread,
        args=(
            event_pipes,
            pipe_data,
            listen,
            ready,
        ),
        daemon=True,
    )
    thread.start()
    listen.set()
    # main loop
    while True:
        if not parent_process.is_alive():
            q_error.put("picosnitch has stopped")
            save_state_and_exit(state, q_error, event_pipes)
        try:
            # check for errors
            while not q_error.empty():
                error = q_error.get()
                state["Error Log"].append(time.strftime("%Y-%m-%d %H:%M:%S") + " " + error)
                # shorten some common error messages before displaying them and after writing them to error.log
                error = error.replace("FD Read Error and PID Read Error and FUSE Read Error for", "Read Error for")
                if len(error) > 50:
                    error = error[:47] + "..."
                # don't need to toast fallback success messages
                if error.startswith("Fallback to FUSE hash successful on ") or error.startswith("Fallback to PID hash successful on "):
                    continue
                _toast(q_notify, error, level=logging.WARNING)
            # get list of new processes and connections since last update
            listen.clear()
            if not ready.wait(timeout=300):
                q_error.put("thread timeout error for primary subprocess")
                save_state_and_exit(state, q_error, event_pipes)
            new_processes = pipe_data[0]
            pipe_data[0] = []
            ready.clear()
            listen.set()
            # process the list and update state, send new process/connection data to secondary subprocess if ready
            handle_new_processes(state, new_processes, q_notify)
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
                    if msg["exe"] in state["SHA256"]:
                        if msg["sha256"] not in state["SHA256"][msg["exe"]]:
                            state["SHA256"][msg["exe"]][msg["sha256"]] = "VT Pending"
                            state["Exe Log"].append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg['sha256']:<16.16} {msg['exe']} (new hash)")
                            _toast(q_notify, f"New sha256: {msg['exe']}")
                    else:
                        state["SHA256"][msg["exe"]] = {msg["sha256"]: "VT Pending"}
                elif msg["type"] == "vt_result":
                    if msg["exe"] in state["SHA256"]:
                        if msg["sha256"] not in state["SHA256"][msg["exe"]]:
                            state["Exe Log"].append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg['sha256']:<16.16} {msg['exe']} (new hash)")
                            _toast(q_notify, f"New sha256: {msg['exe']}")
                        state["SHA256"][msg["exe"]][msg["sha256"]] = msg["result"]
                    else:
                        state["SHA256"][msg["exe"]] = {msg["sha256"]: msg["result"]}
                    if msg["suspicious"]:
                        state["Exe Log"].append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg['sha256']:<16.16} {msg['exe']} (suspicious)")
                        _toast(q_notify, f"Suspicious VT results: {msg['exe']}")
                    else:
                        state["Exe Log"].append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg['sha256']:<16.16} {msg['exe']} (clean)")
            # write the state dictionary to state.json, error.log, and exe.log (limit writes to reduce disk wear)
            if state["Error Log"] or state["Exe Log"] or time.time() - last_write > 30:
                new_record = pickle.dumps([state["Executables"], state["Names"], state["Parent Executables"], state["Parent Names"], state["SHA256"]])
                if new_record != state_record:
                    state_record = new_record
                    write_record = True
                save_state(state, write_record=write_record)
                last_write = time.time()
                write_record = False
        except Exception as e:
            q_error.put("primary subprocess %s%s on line %s" % (type(e).__name__, str(e.args), sys.exc_info()[2].tb_lineno))
