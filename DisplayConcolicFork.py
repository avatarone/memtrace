import sys
from TraceEntries import *

if __name__ == "__main__":
    tf = TraceFile(sys.argv[1])
    string_db = open(sys.argv[2], 'rb')

    for h, p in tf.generate_elements():
        if h._data['type'] == ExecutionTraceType.TRACE_CONCOLIC_FORK_KILL:
            print(hex(p._data['pc']))
            #print(hex(p._data['value'])),
            #print(hex(p._data['size']))
