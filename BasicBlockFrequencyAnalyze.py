from TraceEntries import *
from BasicBlocks import *
import sys

def get_bb_frequency(trace_file, basic_blocks_path):
    # get most frequent bbs (i.e. the bbs that were executed most often
    # 30s on 400MB ExecTrace.dat
    all_bbs = []
    exec_freq = {}
    for bb in get_basic_blocks(basic_blocks_path):
        all_bbs += [bb]
        exec_freq[bb.start] = 0

    # the number of basic block is pretty small (usually)
    # sort basic block by addresses
    #all_bbs.sort(key=lambda t:t[0])
    print("we have %d basic blocks" % (len(all_bbs)))

    total = 1
    all_accesses = []
    for h, e in trace_file.generate_elements():
        if e.__class__ == ExecutionTraceMemory:
            try:
                c = exec_freq[e._data['pc']]
                exec_freq[e._data['pc']] = c+1
            except:
                pass
            total += 1
    bb_and_freq = []
    for c in range(len(all_bbs)):
        bb_and_freq += [(all_bbs[c].start, exec_freq[all_bbs[c].start])]
    #bb_and_freq = [for c in range(len(all_bbs)) (all_bbs[c], exec_freq[all_bbs[c]])]
    bb_and_freq.sort(key=lambda t:-t[1])

    return bb_and_freq[:20]

    # count how many times the PC was in a certain bb
def main(trace_file, basic_blocks):
    bb_and_freq = get_bb_frequency(trace_file, basic_blocks)
    print("got most frequent bbs")

    for bb in bb_and_freq:
        print("Basic block @0x%08x was executed 0x%08x times" 
                % (bb[0], bb[1]))

if __name__ == "__main__":
    main(TraceFile(sys.argv[1]), sys.argv[2])
