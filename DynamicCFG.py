from TraceEntries import *
from BasicBlocks import *
from pygraph.classes.exceptions import AdditionError
import sys

def build_dynamic_cfg(trace_file, basic_blocks_path):
    all_bbs = []
    bbs_start_pos = {}
    for bb in get_basic_blocks(basic_blocks_path):
        all_bbs += [bb]
        bbs_start_pos[bb.start] = bb
    graph = \
            build_static_cfg(
                    get_outgoing(all_bbs))
    print("static analysis done, bbs=%d" % len(all_bbs))
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
            try:
                try:
                    this_bb = bbs_start_pos[e._data['pc']]
                    if e._data['pc'] == 0x0100afb8:
                        print("TS = %s" % str(h._data['timeStamp']))
                except:
                    # not a start
                    continue
                if last_bb is None:
                    last_bb = this_bb
                    graph.node_attr[this_bb] = [("style","filled"), ("fillcolor","green")]
                    continue
                try:
                    # add edge from last_bb to this_bb, only if doesn't exist
                    try:
                        for cf_type, target_pc in this_bb.control_flow:
                            if cf_type in [CF_REGULAR, CF_UNCONDITIONAL_BRANCH,
                                    CF_CONDITIONAL_BRANCH, CF_INDIRECT]:
                                try:
                                    target_bb = bbs_start_pos[target_pc]
                                except KeyError:
                                    if target_pc is None:
                                        target_pc = -1
                                    print("target BB not found 0x@%08x" % target_pc)
                                try:
                                    graph.add_edge((this_bb, target_bb))
                                    added_edges += 1
                                except AdditionError:
                                    # ignore this edge, already added
                                    pass
                        exit_ins = [cf[0] for cf in last_bb.control_flow]
                        if CF_CALL not in exit_ins and \
                                CF_INDIRECT_CALL not in exit_ins and \
                                CF_RETURN not in exit_ins:
                            if last_bb == this_bb:
                                if last_bb.start == 0x0100afb8:
                                    print("DYNAMIC")
                                    pass

                            graph.add_edge((last_bb, this_bb))
                            added_edges += 1
                        else:
                            #last_bb = None
                            #continue
                            pass
                    except AdditionError:
                        pass
                except KeyError:
                    pass
                last_bb = this_bb
                last_bbs += [last_bb]
                last_bbs = last_bbs[-L:]
            except KeyError:
                continue
    for i in range(L):
        graph.node_attr[last_bbs[i]] = [("style","filled"), ("color","\"#%02x0000\"" % int(100+(i+1)*150/L))]
    print("total = %d, added_edges = %d" % (total, added_edges))
    return graph

if __name__ == "__main__":
    build_dynamic_cfg(TraceFile(sys.argv[1]), sys.argv[2])
