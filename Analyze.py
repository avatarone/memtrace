from TraceEntries import *
import sys

def count_accesses(accesses, intervals):
    ret = []
    for addr, size in intervals:
        # O(N^2)
        count = 0
        for e_address, e_size in accesses:
            # XXX: hack we should count twice
            a = e_address+int(e_size/2)
            if a >= addr and a < addr+size:
                count += 1
        ret += [(count, addr, size)]
    return ret

def join_accesses(accesses):
    # get a list of tuples and access them
    o = []
    current_addr = None
    current_size = None
    for addr, size in accesses:
        if current_addr is None or current_size is None:
            current_addr = addr
            current_size = size
            continue
        if addr <= current_addr+current_size and addr >= current_addr:
            if addr+size >= current_addr+current_size:
                current_size = addr+size-current_addr
        else:
            o += [(current_addr, current_size)]
            current_addr = addr
            current_size = size
    return o

def main(trace_file):
    frequency_analysis(trace_file)

def frequency_analysis(trace_file):
    print("Frequency analysis")
    total = 0
    cnt_w = 0
    cnt_r = 0
    w = []
    r = []
    for h, e in trace_file.generate_elements():
        if total == 0:
            min_ts = h._data['timeStamp']
        if e.__class__ == ExecutionTraceMemory:
            if ExecutionTraceMemory.EXECTRACE_MEM_WRITE & e._data['flags']:
                w += [(e._data['address'], e._data['size'])]
                cnt_w += 1
            else:
                r += [(e._data['address'], e._data['size'])]
                cnt_r += 1
        total += 1

    print("total = %d w = %d r = %d" % (total, cnt_w, cnt_r))
    max_ts = h._data['timeStamp']
    #timestamp is in usec
    print("executed instructions per seconds: %0.2f" % (total/((max_ts-min_ts)/10e6)))

    w.sort(key=lambda t:t[0])
    r.sort(key=lambda t:t[0])
    #print("write: %d : %d" % (len(w), len(r)))

    jw = join_accesses(w)
    jr = join_accesses(r)
    jw.sort(key=lambda t:-t[1])
    jr.sort(key=lambda t:-t[1])
    print("write-agg: %d read-agg: %d" % (len(jw), len(jr)))

    w_acc = count_accesses(w, jw[:10])
    r_acc = count_accesses(r, jr[:10])

    #assert(len(w_acc) == len(w_acc))
    #assert(len(r_acc) == len(r_acc))

    print("Write intervals: ")
    w_acc.sort(key=lambda t:-t[0])
    for c in range(len(w_acc)):
        count, addr, size = w_acc[c][0], w_acc[c][1], w_acc[c][2]
        print("0x%08x-0x%08x %d" % (addr, addr+size, count))

    print("Read intervals: ")
    r_acc.sort(key=lambda t:-t[0])
    for c in range(len(r_acc)):
        count, addr, size = r_acc[c][0], r_acc[c][1], r_acc[c][2]
        print("0x%08x-0x%08x %d" % (addr, addr+size, count))


if __name__ == "__main__":
    main(TraceFile(sys.argv[1]))
