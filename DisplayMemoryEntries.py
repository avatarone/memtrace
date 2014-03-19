import sys
from TraceEntries import *

if __name__ == "__main__":
    tf = TraceFile(sys.argv[1])

    for h, p in tf.generate_elements():
        if h._data['type'] == ExecutionTraceType.TRACE_MEMORY:
            print(hex(p._data['address'])),
            print(hex(p._data['value'])),
            print(hex(p._data['size']))
