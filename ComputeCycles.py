import sys
sys.path.append('..')
sys.path.append('/usr/lib/graphviz/python/')
sys.path.append('/usr/lib64/graphviz/python/')

import logging

# Import pygraph
from pygraph.classes.graph import graph
from pygraph.classes.digraph import digraph
from pygraph.algorithms.searching import breadth_first_search
from pygraph.algorithms.cycles import find_cycle
from pygraph.readwrite.dot import write

from DynamicCFG import build_dynamic_cfg
from TraceEntries import *

log = logging.getLogger(__name__)

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
                if (spanning_tree[each] != node):
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

def get_escape_bbs(basic_blocks):
    """
    From a list of BBS that form a cycle some of the basic blocks can break the
    cycle. We want to find these basic blocks and, later, mark the data that is
    used by the conditional jump as being symbolic such that we can "escape"
    from this loop.
    """
    ret = []
    start_pcs = {}
    for bb in basic_blocks:
        start_pcs[bb.start] = bb
    for bb in basic_blocks:
        bb_points_outside = False
        for _, target_pc in bb.control_flow:
            # XXX: asume that we're jumping only at the begin of a basic block
            if target_pc not in start_pcs:
                bb_points_outside = True
                break
        if bb_points_outside:
            ret += [bb]
    return ret

if __name__ == '__main__':
    gr = build_dynamic_cfg(TraceFile(sys.argv[1]), sys.argv[2])
    log.info("Done building dynamic cfg")
    dot = write(gr)
    
    try:
        import gv
        gvv = gv.readstring(dot)
        gv.layout(gvv,'dot')
        gv.render(gvv,'svg','/tmp/o.svg')
    except ImportError as err:
        with open("cfg.dot", 'w') as file:
            file.write(dot)

    cycles = find_all_cycles(gr)
    log.info("found %d cycles" % len(cycles))
    for cycle in cycles:
        log.info("cycle [%d]: %s" % (len(cycle), cycle))
        #for bb in cycle:
        #    #print("@0x%08x(%s)->" % (bb.start, repr(bb.control_flow))),
        #print("")
        escape_bbs = get_escape_bbs(cycle)
        log.info("Escape bbs [%d]: %s" % (len(escape_bbs), escape_bbs))
