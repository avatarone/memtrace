import sys
from TraceEntries import *

if __name__ == "__main__":
    tf = TraceFile(sys.argv[1])
    string_db = open_file(sys.argv[2], 'rb')

    for h, p in tf.generate_elements():
        if h._data['type'] == ExecutionTraceType.TRACE_CONCOLIC_FORK_KILL:
            print(hex(p._data['pc'])),
            #print(hex(p._data['condition_offset'])),
            offset = p._data['condition_offset']
            size = p._data['condition_size']
            string_db.seek(offset)
            print(str(string_db.read(size)))
            #print(hex(p._data['size']))
    string_db.close()
