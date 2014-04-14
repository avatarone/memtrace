import sys
from TraceEntries import *
import argparse

def open_file(filename, flags):
    if filename.endswith(".gz"):
        return gzip.GzipFile(filename, flags)
    else:
        return open(filename, flags)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("trace_file", type = str, help = "Trace file")
    parser.add_argument("--concolic", type = str, default = None, dest = "concolic", help = "Concolic Fork trace file")
    
    args = parser.parse_args()
    tf = TraceFile(args.trace_file)
    
    ctf = None
    if args .concolic:
        ctf = open_file(args.concolic, "rb")

    for h, p in tf.generate_elements():
        if h._data['type'] == ExecutionTraceType.TRACE_MEMORY:
            print("MemoryAccess: address = 0x%08x, size = %d, value = 0x%x" % (p._data['address'], p._data['size'], p._data['value']))
        elif h._data['type'] == ExecutionTraceType.TRACE_CONCOLIC_FORK_KILL:
            if ctf:
                ctf.seek(p._data['condition_offset'])
                condition = ctf.read(p._data['condition_size']).decode(encoding = 'iso-8859-1')
            else:
                condition = "<unable to load condition>"
            print("ConcolicFork: pc = 0x%08x, state_id = % 4d, condition = %s" % (p._data['pc'], p._data['killed_state_id'], condition))
        elif h._data['type'] == ExecutionTraceType.TRACE_INSTR_START:
            print("Instruction: pc = 0x%08x, symbolic = %s" % (p._data['pc'], p._data['isSymbolic'] and 'yes' or 'no'))
        
