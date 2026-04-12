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

import collections
import datetime
import ipaddress
import math
import os
import pwd
import signal
import sqlite3

from ..config import load_config
from ..constants import DATA_DIR, RUN_DIR, VERSION
from .tui import init_geoip


def web_dashboard():
    """gui with plotly dash"""
    import pandas as pd
    import pandas.io.sql as psql
    import plotly.express as px
    from dash import Dash, callback_context, dcc, html, no_update
    from dash.dependencies import Input, Output, State
    from dash.exceptions import PreventUpdate

    config = load_config()
    file_path = DATA_DIR / "picosnitch.db"
    all_dims = ["exe", "name", "cmdline", "sha256", "uid", "lport", "rport", "laddr", "raddr", "domain", "pexe", "pname", "pcmdline", "psha256"]
    dim_labels = {
        "exe": "Executable",
        "name": "Process Name",
        "cmdline": "Command",
        "sha256": "SHA256",
        "uid": "User",
        "lport": "Local Port",
        "rport": "Remote Port",
        "laddr": "Local Address",
        "raddr": "Remote Address",
        "domain": "Domain",
        "pexe": "Parent Executable",
        "pname": "Parent Name",
        "pcmdline": "Parent Command",
        "psha256": "Parent SHA256",
    }
    time_period = [
        "all",
        "1 minute",
        "3 minutes",
        "5 minutes",
        "10 minutes",
        "15 minutes",
        "30 minutes",
        "1 hour",
        "3 hours",
        "6 hours",
        "12 hours",
        "1 day",
        "3 days",
        "7 days",
        "30 days",
        "365 days",
    ]
    time_minutes = [0, 1, 3, 5, 10, 15, 30, 60, 180, 360, 720, 1440, 4320, 10080, 43200, 525600]
    time_deltas = [datetime.timedelta(minutes=x) for x in time_minutes]
    time_round_units = ["second"] + ["minute"] * 6 + ["hour"] * 4 + ["day"] * 3 + ["month"] + ["year"]
    time_round_functions = collections.OrderedDict(
        {
            "second": lambda x: x.replace(microsecond=0),
            "minute": lambda x: x.replace(microsecond=0, second=0),
            "hour": lambda x: x.replace(microsecond=0, second=0, minute=0),
            "day": lambda x: x.replace(microsecond=0, second=0, minute=0, hour=0),
            "month": lambda x: x.replace(microsecond=0, second=0, minute=0, hour=0, day=1),
            "year": lambda x: x.replace(microsecond=0, second=0, minute=0, hour=0, day=1, month=1),
        }
    )

    def time_round_func(resolution_index, time):
        return time_round_functions[time_round_units[resolution_index]](time)

    geoip_reader = init_geoip()

    def get_user(uid) -> str:
        try:
            return f"{pwd.getpwuid(uid).pw_name} ({uid})"
        except Exception:
            return f"??? ({uid})"

    def get_totals(df_sum, dim) -> str:
        size = df_sum[dim]
        if size > 10**9:
            return f"{dim} ({round(size / 10**9, 2)!s} GB)"
        elif size > 10**6:
            return f"{dim} ({round(size / 10**6, 2)!s} MB)"
        elif size > 10**3:
            return f"{dim} ({round(size / 10**3, 2)!s} kB)"
        else:
            return f"{dim} ({size!s} B)"

    def get_geoip(ip: str) -> str:
        try:
            country_code = geoip_reader.country(ip).country.iso_code
            base = 0x1F1E6 - ord("A")
            country_flag = chr(base + ord(country_code[0].upper())) + chr(base + ord(country_code[1].upper()))
            return f"{ip} ({country_flag}{country_code})"
        except Exception:
            try:
                if ipaddress.ip_address(ip).is_private:
                    return f"{ip} ({chr(0x1F3E0)})"  # home emoji
                else:
                    return f"{ip} ({chr(0x1F310)})"  # globe emoji
            except Exception:
                return f"{ip} ({chr(0x2753)})"  # question emoji

    def trim_label(label, trim) -> str:
        if trim and len(label) > 64:
            return f"{label[:32]}...{label[-29:]}"
        return label

    def serve_layout():
        try:
            with open(RUN_DIR / "picosnitch.pid", "r") as f:
                run_status = "pid: " + f.read().strip()
        except Exception:
            run_status = "not running"
        return html.Div(
            [
                dcc.Interval(
                    id="interval-component",
                    interval=10000,
                    disabled=True,
                ),
                html.Div(html.Button("Stop Dash", id="exit", className="btn btn-primary btn-sm mt-1"), style={"float": "right"}),
                html.Div(
                    [
                        dcc.Dropdown(
                            id="resampling",
                            options=[
                                {"label": "Resampling (100 points)", "value": 100},
                                {"label": "Resampling (500 points)", "value": 500},
                                {"label": "Resampling (1000 points)", "value": 1000},
                                {"label": "Resampling (2000 points)", "value": 2000},
                                {"label": "Resampling (3000 points)", "value": 3000},
                                {"label": "Resampling (4000 points)", "value": 4000},
                                {"label": "Resampling (5000 points)", "value": 5000},
                                {"label": "Resampling (10000 points)", "value": 10000},
                                {"label": "Resampling (None)", "value": False},
                            ],
                            value=2000,
                            clearable=False,
                        ),
                    ],
                    style={"display": "inline-block", "width": "15%"},
                ),
                html.Div(
                    [
                        dcc.Dropdown(
                            id="smoothing",
                            options=[
                                {"label": "Rolling Window (2 points)", "value": 2},
                                {"label": "Rolling Window (4 points)", "value": 4},
                                {"label": "Rolling Window (8 points)", "value": 8},
                                {"label": "Rolling Window (None)", "value": False},
                            ],
                            value=4,
                            clearable=False,
                        ),
                    ],
                    style={"display": "inline-block", "width": "15%"},
                ),
                html.Div(
                    [
                        dcc.Dropdown(
                            id="trim-labels",
                            options=[
                                {"label": "Trim Long Labels (64 chars)", "value": True},
                                {"label": "Show Full Labels", "value": False},
                            ],
                            value=True,
                            clearable=False,
                        ),
                    ],
                    style={"display": "inline-block", "width": "15%"},
                ),
                html.Div(
                    [
                        dcc.Dropdown(
                            id="auto-refresh",
                            options=[
                                {"label": "Disable Auto-Refresh", "value": 0},
                                {"label": "Auto-Refresh (1 second)", "value": 1},
                                {"label": "Auto-Refresh (5 seconds)", "value": 5},
                                {"label": "Auto-Refresh (10 seconds)", "value": 10},
                                {"label": "Auto-Refresh (30 seconds)", "value": 30},
                                {"label": "Auto-Refresh (1 minute)", "value": 60},
                                {"label": "Auto-Refresh (5 minutes)", "value": 300},
                                {"label": "Auto-Refresh (10 minutes)", "value": 600},
                            ],
                            value=0,
                            clearable=False,
                        ),
                    ],
                    style={"display": "inline-block", "width": "15%"},
                ),
                html.Div(),
                html.Div(
                    [
                        dcc.Dropdown(
                            id="select",
                            options=[{"label": f"Select {dim_labels[x]}", "value": x} for x in all_dims],
                            value="exe",
                            clearable=False,
                        ),
                    ],
                    style={"display": "inline-block", "width": "33%"},
                ),
                html.Div(
                    [
                        dcc.Dropdown(
                            id="where",
                            options=[{"label": f"Where {dim_labels[x]}", "value": x} for x in all_dims],
                            placeholder="Where...",
                        ),
                    ],
                    style={"display": "inline-block", "width": "33%"},
                ),
                html.Div(
                    [
                        dcc.Dropdown(
                            id="whereis",
                            placeholder="Is...",
                        ),
                    ],
                    style={"display": "inline-block", "width": "33%"},
                ),
                html.Div(
                    [
                        dcc.RadioItems(
                            id="time_i",
                            options=[{"label": time_period[i], "value": i} for i in range(len(time_period))],
                            value=8,
                            inline=True,
                        ),
                    ]
                ),
                html.Div(
                    [
                        dcc.Slider(
                            id="time_j",
                            min=0,
                            max=100,
                            step=1,
                            value=0,
                            included=False,
                        ),
                        html.Div(id="selected_time_range", style={"border": "1px solid #ccc", "padding": "5px", "text-align": "center"}),
                    ]
                ),
                dcc.Store(id="store_time", data={"time_i": 8}),
                dcc.Store(id="store_send", data={"rev": 0, "visible": {}}),
                dcc.Store(id="store_recv", data={"rev": 0, "visible": {}}),
                dcc.Graph(id="send", config={"scrollZoom": config.dash.scroll_zoom}),
                dcc.Graph(id="recv", config={"scrollZoom": config.dash.scroll_zoom}),
                html.Footer(f"picosnitch v{VERSION} ({run_status}) (using {file_path})"),
            ]
        )

    try:
        # try to use dash-bootstrap-components if available and theme exists
        import dash_bootstrap_components as dbc
        from dash_bootstrap_templates import load_figure_template

        load_figure_template(config.dash.theme.lower())
        app = Dash(__name__, external_stylesheets=[getattr(dbc.themes, config.dash.theme.upper())])
    except Exception:
        app = Dash(__name__)
    app.layout = serve_layout

    @app.callback(Output("interval-component", "disabled"), Output("interval-component", "interval"), Input("auto-refresh", "value"))
    def toggle_refresh(value):
        return value == 0, 1000 * value

    @app.callback(Output("time_j", "value"), Output("store_time", "data"), Input("time_i", "value"), Input("time_j", "value"), Input("store_time", "data"))
    def update_time_slider_pos(time_i, time_j, store_time):
        # only trigger on time_i change
        if not callback_context.triggered:
            raise PreventUpdate
        elif time_i == 0 or time_j == 0:
            # time_i is "all", so time_j should be current, or time_j is current so time_i store just needs updating
            return 0, {"time_i": time_i}
        elif store_time["time_i"] == 0:
            # time_i was "all", so don't change time_j
            return no_update, {"time_i": time_i}
        elif time_j != 0 and time_i != store_time["time_i"]:
            # time_i changed and time_j is not current time, so scale time_j to new time_i
            # get the old time end offset (smaller value, closer to present time) in minutes, and use to scale to new time_j
            old_minute_end_offset = (time_j - 2) * time_minutes[store_time["time_i"]]
            if store_time["time_i"] > time_i:
                # new time_i is smaller, time_j is larger, and should be slightly after the old time_j to fall between start (earlier) and end (later)
                new_time_j = math.ceil(old_minute_end_offset / time_minutes[time_i]) + 2
            else:
                # new time_i is larger, ..., should be slightly before the old time_j so the entire old period is mostly within the new period
                new_time_j = math.floor(old_minute_end_offset / time_minutes[time_i]) + 2
            return max(0, min(100, new_time_j)), {"time_i": time_i}
        raise PreventUpdate

    @app.callback(Output("time_j", "marks"), Input("time_i", "value"), Input("time_j", "value"), Input("interval-component", "n_intervals"))
    def update_time_slider_marks(time_i, time_j, _):
        return {x: time_round_func(time_i, datetime.datetime.now() - time_deltas[time_i] * (x - 2)).strftime("%Y-%m-%d T %H:%M:%S") for x in range(2, 100, 10)}

    @app.callback(Output("selected_time_range", "children"), Input("time_i", "value"), Input("time_j", "value"), Input("interval-component", "n_intervals"))
    def display_time_range(time_i, time_j, _):
        # may switch later to handleLabel with dash-daq https://dash.plotly.com/dash-core-components/slider https://dash.plotly.com/dash-daq/slider#handle-label
        # time_i is the index of the time period, time_j is the number of time period steps to go back
        # time_i=0 means all records and time_j=0 means current time (no rounding), due to rounding for time_j>0, time_j=1 may extend partially into the future
        if time_j == 0 and time_i != 0:
            time_history_start = (datetime.datetime.now() - time_deltas[time_i]).strftime("%a. %b. %d, %Y at %H:%M:%S")
            time_history_end = datetime.datetime.now().strftime("%a. %b. %d, %Y at %H:%M:%S")
        elif time_i != 0:
            time_history_start = time_round_func(time_i, datetime.datetime.now() - time_deltas[time_i] * (time_j - 1)).strftime("%a. %b. %d, %Y at %H:%M:%S")
            time_history_end = time_round_func(time_i, datetime.datetime.now() - time_deltas[time_i] * (time_j - 2)).strftime("%a. %b. %d, %Y at %H:%M:%S")
        else:
            return "all records"
        return f"{time_history_start} to {time_history_end}"

    @app.callback(
        Output("send", "figure"),
        Output("recv", "figure"),
        Output("whereis", "options"),
        Output("store_send", "data"),
        Output("store_recv", "data"),
        Input("smoothing", "value"),
        Input("trim-labels", "value"),
        Input("resampling", "value"),
        Input("select", "value"),
        Input("where", "value"),
        Input("whereis", "value"),
        Input("time_i", "value"),
        Input("time_j", "value"),
        Input("send", "relayoutData"),
        Input("recv", "relayoutData"),
        Input("send", "restyleData"),
        Input("recv", "restyleData"),
        Input("interval-component", "n_intervals"),
        State("store_send", "data"),
        State("store_recv", "data"),
        State("send", "figure"),
        State("recv", "figure"),
        prevent_initial_call=True,
    )
    def update(smoothing, trim, resampling, dim, where, whereis, time_i, time_j, relayout_send, relayout_recv, restyle_send, restyle_recv, _, store_send, store_recv, fig_send, fig_recv):
        if not callback_context.triggered or (callback_context.triggered[0]["prop_id"] == "time_j.value" and time_i == 0):
            raise PreventUpdate
        input_id = callback_context.triggered[0]["prop_id"]
        # sync zoom level between figs and prevent zooming outside of the data range
        if input_id == "send.relayoutData" and relayout_send is not None and "xaxis.range[0]" in relayout_send:
            # update fig_recv to match fig_send zoom
            store_recv["rev"] += 1
            fig_recv["layout"]["xaxis"]["range"] = [max(relayout_send["xaxis.range[0]"], store_recv["min_x"]), min(relayout_send["xaxis.range[1]"], store_recv["max_x"])]
            fig_recv["layout"]["uirevision"] = store_recv["rev"]
            # prevent zooming outside of the data range
            if store_send["min_x"] > relayout_send["xaxis.range[0]"] or store_send["max_x"] < relayout_send["xaxis.range[1]"]:
                store_send["rev"] += 1
                fig_send["layout"]["xaxis"]["range"] = [max(relayout_send["xaxis.range[0]"], store_send["min_x"]), min(relayout_send["xaxis.range[1]"], store_send["max_x"])]
                fig_send["layout"]["uirevision"] = store_send["rev"]
                return fig_send, fig_recv, no_update, store_send, store_recv
            return no_update, fig_recv, no_update, no_update, store_recv
        if input_id == "recv.relayoutData" and relayout_recv is not None and "xaxis.range[0]" in relayout_recv:
            # update fig_send to match fig_recv zoom
            store_send["rev"] += 1
            fig_send["layout"]["xaxis"]["range"] = [max(relayout_recv["xaxis.range[0]"], store_send["min_x"]), min(relayout_recv["xaxis.range[1]"], store_send["max_x"])]
            fig_send["layout"]["uirevision"] = store_send["rev"]
            # prevent zooming outside of the data range
            if store_recv["min_x"] > relayout_recv["xaxis.range[0]"] or store_recv["max_x"] < relayout_recv["xaxis.range[1]"]:
                store_recv["rev"] += 1
                fig_recv["layout"]["xaxis"]["range"] = [max(relayout_recv["xaxis.range[0]"], store_recv["min_x"]), min(relayout_recv["xaxis.range[1]"], store_recv["max_x"])]
                fig_recv["layout"]["uirevision"] = store_recv["rev"]
                return fig_send, fig_recv, no_update, store_send, store_recv
            return fig_send, no_update, no_update, store_send, no_update
        # get visibility of legend items (traces)
        if input_id == "send.restyleData" and restyle_send is not None and "visible" in restyle_send[0]:
            for visible, index in zip(restyle_send[0]["visible"], restyle_send[1]):
                store_send["visible"][store_send["columns"][index]] = visible
                # update recv fig to match
                store_recv["visible"][store_recv["columns"][index]] = visible
                fig_recv["data"][index]["visible"] = visible
            return no_update, fig_recv, no_update, store_send, store_recv
        if input_id == "recv.restyleData" and restyle_recv is not None and "visible" in restyle_recv[0]:
            for visible, index in zip(restyle_recv[0]["visible"], restyle_recv[1]):
                store_recv["visible"][store_recv["columns"][index]] = visible
                # update send fig to match
                store_send["visible"][store_send["columns"][index]] = visible
                fig_send["data"][index]["visible"] = visible
            return fig_send, no_update, no_update, store_send, store_recv
        # generate the query string using the selected options (time_i is the index of the time period, time_j is the number of time period steps to go back)
        if time_j == 0:
            time_history_start = (datetime.datetime.now() - time_deltas[time_i]).strftime("%Y-%m-%d %H:%M:%S")
            time_history_end = "now"
        elif time_i != 0:
            time_history_start = time_round_func(time_i, datetime.datetime.now() - time_deltas[time_i] * (time_j - 1)).strftime("%Y-%m-%d %H:%M:%S")
            time_history_end = time_round_func(time_i, datetime.datetime.now() - time_deltas[time_i] * (time_j - 2)).strftime("%Y-%m-%d %H:%M:%S")
        if time_i == 0:
            time_query = ""
        else:
            if where and whereis:
                time_query = f' AND contime > datetime("{time_history_start}") AND contime < datetime("{time_history_end}")'
            else:
                time_query = f' WHERE contime > datetime("{time_history_start}") AND contime < datetime("{time_history_end}")'
        if where and whereis:
            query = f'SELECT {dim}, contime, send, recv FROM connections WHERE {where} IS "{whereis}"{time_query}'
        else:
            query = f"SELECT {dim}, contime, send, recv FROM connections{time_query}"
        # run query and populate whereis options
        con = sqlite3.connect(file_path)
        df = psql.read_sql(query, con)
        whereis_options = []
        if where:
            if time_query.startswith(" AND"):
                time_query = time_query.replace(" AND", " WHERE", 1)
            query = f"SELECT DISTINCT {where} FROM connections{time_query}"
            cur = con.cursor()
            cur.execute(query)
            whereis_values = cur.fetchall()
            if where == "uid":
                whereis_options = [{"label": f"is {get_user(x[0])}", "value": x[0]} for x in whereis_values]
            else:
                whereis_options = [{"label": f"is {trim_label(x[0], trim)}", "value": x[0]} for x in whereis_values]
        con.close()
        # structure the data for plotting
        df_send = df.groupby(["contime", dim])["send"].sum().unstack(dim, fill_value=0)
        df_recv = df.groupby(["contime", dim])["recv"].sum().unstack(dim, fill_value=0)
        # store column names before renaming
        store_send["columns"] = df_send.columns
        store_recv["columns"] = df_recv.columns
        # rename columns with nicer labels (add data totals, username, geoip lookup, and trim if requested)
        df_send_total = df_send.sum()
        df_recv_total = df_recv.sum()
        df_send_new_columns = [get_totals(df_send_total, col) for col in df_send.columns]
        df_recv_new_columns = [get_totals(df_recv_total, col) for col in df_recv.columns]
        if dim == "uid":
            df_send_new_columns = [col.replace(str(uid), get_user(uid), 1) for col, uid in zip(df_send_new_columns, df_send.columns)]
            df_recv_new_columns = [col.replace(str(uid), get_user(uid), 1) for col, uid in zip(df_recv_new_columns, df_recv.columns)]
        elif dim == "raddr" and geoip_reader is not None:
            df_send_new_columns = [col.replace(str(ip), get_geoip(ip), 1) for col, ip in zip(df_send_new_columns, df_send.columns)]
            df_recv_new_columns = [col.replace(str(ip), get_geoip(ip), 1) for col, ip in zip(df_recv_new_columns, df_recv.columns)]
        df_send_new_columns = [trim_label(col, trim) for col in df_send_new_columns]
        df_recv_new_columns = [trim_label(col, trim) for col in df_recv_new_columns]
        df_send.columns = df_send_new_columns
        df_recv.columns = df_recv_new_columns
        # resample the data if it is too large for performance, and smooth if requested
        if resampling:
            if len(df_send) > resampling:
                df_send.index = pd.to_datetime(df_send.index)
                n = len(df_send) // resampling
                df_send = df_send.resample(f"{n}T").mean().fillna(0)
            if len(df_recv) > resampling:
                df_recv.index = pd.to_datetime(df_recv.index)
                n = len(df_recv) // resampling
                df_recv = df_recv.resample(f"{n}T").mean().fillna(0)
        if smoothing:
            df_send = df_send.rolling(smoothing, center=True, closed="both", min_periods=smoothing // 2).mean()
            df_recv = df_recv.rolling(smoothing, center=True, closed="both", min_periods=smoothing // 2).mean()
        # update the store and figure
        store_send["min_x"] = df_send.index.min()
        store_send["max_x"] = df_send.index.max()
        store_recv["min_x"] = df_recv.index.min()
        store_recv["max_x"] = df_recv.index.max()
        store_send["rev"] += 1
        store_recv["rev"] += 1
        fig_send = px.line(df_send, line_shape="linear", render_mode="svg", labels={"contime": "", "value": "Data Sent (bytes)", dim: dim_labels[dim]})
        fig_send.update_layout(uirevision=store_send["rev"])
        fig_send.update_xaxes(range=[store_send["min_x"], store_send["max_x"]])
        fig_send.update_yaxes(fixedrange=True)
        fig_send.update_traces(fill="tozeroy", line_simplify=True)
        fig_recv = px.line(df_recv, line_shape="linear", render_mode="svg", labels={"contime": "", "value": "Data Received (bytes)", dim: dim_labels[dim]})
        fig_recv.update_layout(uirevision=store_recv["rev"])
        fig_recv.update_xaxes(range=[store_recv["min_x"], store_recv["max_x"]])
        fig_recv.update_yaxes(fixedrange=True)
        fig_recv.update_traces(fill="tozeroy", line_simplify=True)
        # carry over visibility settings manually (instead keeping uirevision fixed) since column indices may not line up
        for i in range(len(fig_send.data)):
            fig_send.data[i].visible = True
            if store_send["columns"][i] in store_send["visible"]:
                fig_send.data[i].visible = store_send["visible"][store_send["columns"][i]]
        for i in range(len(fig_recv.data)):
            fig_recv.data[i].visible = True
            if store_recv["columns"][i] in store_recv["visible"]:
                fig_recv.data[i].visible = store_recv["visible"][store_recv["columns"][i]]
        for column in list(store_send["visible"].keys()):
            if column not in store_send["columns"]:
                _ = store_send["visible"].pop(column)
        for column in list(store_recv["visible"].keys()):
            if column not in store_recv["columns"]:
                _ = store_recv["visible"].pop(column)
        return fig_send, fig_recv, whereis_options, store_send, store_recv

    @app.callback(Output("exit", "n_clicks"), Input("exit", "n_clicks"))
    def exit(clicks):
        if clicks:
            os.kill(os.getpid(), signal.SIGTERM)
        return 0

    app.run(host=os.getenv("HOST", "localhost"), port=os.getenv("PORT", "5100"), debug=bool(eval(os.getenv("DASH_DEBUG", "False"))))
