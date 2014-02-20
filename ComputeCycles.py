import sys
sys.path.append('..')
sys.path.append('/usr/lib/graphviz/python/')
sys.path.append('/usr/lib64/graphviz/python/')
import gv

# Import pygraph
from pygraph.classes.graph import graph
from pygraph.classes.digraph import digraph
from pygraph.algorithms.searching import breadth_first_search
from pygraph.algorithms.cycles import find_cycle
from pygraph.readwrite.dot import write

from DynamicCFG import build_dynamic_cfg
from TraceEntries import *

"""
find_all_cycles contributed by Mathias Laurin <Mathias Laurin AT gmail com>
"""

def find_cycle_to_ancestor(spanning_tree, node, ancestor):
    """
    Find a cycle containing both node and ancestor.
    """
    path = []
    while (node != ancestor):
        if node is None:
            return []
        path.append(node)
        node = spanning_tree[node]
    path.append(node)
    path.reverse()
    return path

def find_all_cycles(graph):
    """
    Find all cycles in the given graph.

    This function will return a list of lists of nodes, which form cycles in the
    graph or an empty list if no cycle exists.
    """

    def dfs(node):
        """
        Depth-first search subfunction.
        """
        visited.add(node)
        # Explore recursively the connected component
        for each in graph[node]:
            if each not in visited:
                spanning_tree[each] = node
                dfs(each)
            else:
                if (spanning_tree[node] != each):
                    cycle = find_cycle_to_ancestor(spanning_tree, node, each)
                    if cycle:
                        cycles.append(cycle)

    visited = set()         # List for marking visited and non-visited nodes
    spanning_tree = {}      # Spanning tree
    cycles = []

    # Algorithm outer-loop
    for each in graph:
        # Select a non-visited node
        if each not in visited:
            spanning_tree[each] = None
            # Explore node's connected component
            dfs(each)

    return cycles

if __name__ == '__main__':
    gr = build_dynamic_cfg(TraceFile(sys.argv[1]), sys.argv[2])
    print("Done building dynamic cfg")
    dot = write(gr)
    gvv = gv.readstring(dot)
    gv.layout(gvv,'dot')
    gv.render(gvv,'ps','/tmp/o.ps')
    cycles = find_all_cycles(gr)
    print("found %d cycles" % len(cycles))
    for cycle in cycles:
        for bb in cycle:
            print("@0x%08x->" % bb.start),
        print("")
