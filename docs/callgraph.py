#!/usr/bin/env python3
import os

# generate call graph using pyan3
print("Generating call graph for picosnitch")
os.chdir(os.path.dirname(__file__))
os.system("pyan3 ../picosnitch.py --no-defines --uses --colored --nested-groups --dot > callgraph.dot")

# sort edges so output is deterministic
with open("callgraph.dot", "r") as f:
    dot = f.readlines()
new_dot = []
new_edges = []
edge_start = False
edge_end = False
for line in dot:
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
