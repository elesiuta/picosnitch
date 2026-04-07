#!/usr/bin/env python3
import os

import pyan

# generate call graph using pyan3==2.3.1
print("Generating call graph for picosnitch")
os.chdir(os.path.dirname(__file__))
dot: str = pyan.create_callgraph(
    filenames=["../picosnitch/**/*.py"],
    root="..",
    format="dot",
    rankdir="TB",
    nested_groups=True,
    draw_defines=False,
    draw_uses=True,
    colored=True,
    grouped_alt=True,
    concentrate=True,
    depth=2,
    exclude=[
        "__init__.py",
        "__main__.py",
        "cli.py",
        "constants.py",
        "daemon.py",
        "event_structures.py",
        "user_interface.py",
    ],
)

# sort dot file edges so output is deterministic
new_dot: list[str] = []
new_edges: list[str] = []
edge_start: bool = False
edge_end: bool = False
for line in dot.splitlines(keepends=True):
    if "->" in line and not edge_end:
        edge_start = True
        new_edges.append(line)
    elif edge_start and not edge_end:
        edge_end = True
        new_dot += sorted(new_edges)
        new_dot.append(line)
    else:
        new_dot.append(line)
with open("callgraph.dot", "w") as f:
    f.writelines(new_dot)

# create svg with graphviz
os.system("dot -Tsvg callgraph.dot > callgraph.svg")
print("Done")
