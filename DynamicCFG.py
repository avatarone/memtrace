from TraceEntries import *
from BasicBlocks import *
from pygraph.classes.exceptions import AdditionError
import sys
import logging

log = logging.getLogger(__name__)

def build_dynamic_cfg(trace_file, basic_blocks_path):
    all_bbs = []
    bbs_start_pos = {}
    for bb in get_basic_blocks(basic_blocks_path):
        all_bbs += [bb]
        bbs_start_pos[bb.start] = bb
    graph, unexplored_bbs = \
            build_static_cfg(
                    get_outgoing(all_bbs))

    # extend the dictionary with unexplored bbs
    for bb in unexplored_bbs:
        bbs_start_pos[bb.start] = bb

    log.info("static analysis done")
    log.info("explored bbs=%d, unexplored bbs=%d" % (len(all_bbs), len(unexplored_bbs)))
    total = 0
    last_bb = None
    added_edges = 0
    last_bbs = []
    L = 30
    for h, e in trace_file.generate_elements():
        # this should be ExecutionTraceInstr, but we dont have this data
        # another experiment is needed
        #if e.__class__ == ExecutionTraceMemory:
        if e.__class__ == ExecutionTraceInstr:
            total += 1
            # is this pc corresponding to a basic block?
            try:
                this_bb = bbs_start_pos[e._data['pc']]
            except KeyError:
                # not a start
                continue

            # is this the first bb that we encounter
            if last_bb is None:
                last_bb = this_bb
                graph.node_attr[this_bb] = [("style","filled"), ("fillcolor","green")]
                log.debug("Found entry node at %s" % (str(this_bb)))
                continue

            # we have two basic blocks, the current one (this_bb) and
            # the previos one (last_bb). We can try to add edges

            # add and edge from this_bb to the basic block that is pointing to
            # the target bb can be any basic block (explored or not)
            for cf_type, target_pc in this_bb.control_flow:
                if cf_type in [CF_REGULAR, CF_UNCONDITIONAL_BRANCH,
                        CF_CONDITIONAL_BRANCH, CF_INDIRECT]:
                    try:
                        target_bb = bbs_start_pos[target_pc]
                    except KeyError:
                        if target_pc is None:
                            target_pc = -1
                        log.debug("target BB not found 0x@%08x" % target_pc)
                    try:
                        graph.add_edge((this_bb, target_bb))
                        added_edges += 1
                    except AdditionError:
                        # ignore this edge, already added
                        pass

                # we want to mark the target basic block as an entry point to a function
                if cf_type in [CF_CALL, CF_INDIRECT_CALL]:
                    try:
                        target_bb = bbs_start_pos[target_pc]
                    except KeyError:
                        continue
                    # mark target node as a start BB of a function
                    # we should test if this node is explored or not
                    graph.node_attr[target_bb] = \
                            [("style","filled"), ("color","\"#2AE5E8\"" )]

            exit_ins = [cf[0] for cf in last_bb.control_flow]

            # add an edge from last_bb to this_bb only if the instruction was
            # not a call instruciton or a return instruction
            # in other words: we want to ignore function calls and returns
            if CF_CALL not in exit_ins and \
                    CF_INDIRECT_CALL not in exit_ins and \
                    CF_RETURN not in exit_ins:

                try:
                    graph.add_edge((last_bb, this_bb))
                    added_edges += 1
                except AdditionError:
                    # ignore this edge, already added
                    pass
            else:
                pass
            last_bb = this_bb
            last_bbs += [last_bb]
            last_bbs = last_bbs[-L:]
    for i in range(len(last_bbs)):
        graph.node_attr[last_bbs[i]] = \
                [("style","filled"),
                        ("color","\"#%02x0000\"" % int(100+(i+1)*150/len(last_bbs)))]
    log.info("total = %d, added_edges = %d" % (total, added_edges))
    return graph

if __name__ == "__main__":
    build_dynamic_cfg(TraceFile(sys.argv[1]), sys.argv[2])
