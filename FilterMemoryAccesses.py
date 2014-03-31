import sys
from SearchMemoryEntries import touches_any
from TraceEntries import *


ranges=[0x10000]

size = 0x1000

if __name__ == "__main__":
    tf = TraceFile(sys.argv[1])
    of = open(sys.argv[2], 'wb')

    for h, p in tf.generate_elements():
        if h._data['type'] == ExecutionTraceType.TRACE_MEMORY:
            addr = p._data['address']
            if touches_any(addr, ranges, size):
            #if True:
                d = 'W' if ExecutionTraceMemory.EXECTRACE_MEM_WRITE & p._data['flags'] else 'R'
                print("[%c]: @0x%0x [0x%08x] -> 0x%08x" % (d, p._data['pc'], addr, p._data['value']))
                of.write(h.dumps()+p.dumps())
        elif h._data['type'] == ExecutionTraceType.TRACE_INSTR_START:
            # do nothing, we don't care about this entry
            pass
    of.close()
