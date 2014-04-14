import sys
from TraceEntries import *

if __name__ == "__main__":
    tf = TraceFile(sys.argv[1])

    for h, p in tf.generate_elements():
        if h._data['type'] == ExecutionTraceType.TRACE_MEMORY:
            print("MemoryAccess: address = 0x%08x, size = %d, value = 0x%x" % (p._data['address'], p._data['size'], p._data['value']))
        elif h._data['type'] == ExecutionTraceType.TRACE_CONCOLIC_FORK_KILL:
            print("ConcolicFork: address = 0x%08x, size = %d, value = 0x%x" % (p._data['address'], p._data['size'], p._data['value']))
        
