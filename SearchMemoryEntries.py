import argparse
from ast import literal_eval
from TraceEntries import *

# rtc-timer, integrator_pit, serial
DEFAULT_RANGES = [(0x15000000, 0x10), (0x13000000, 0x10), (0x16000000, 0x10)]

def touches_one(addr, base, size):
    return (addr < (base + size)) and (addr >= base)

def touches_any(addr, my_ranges=DEFAULT_RANGES):
    for b in my_ranges:
        if touches_one(addr, b[0], b[1]):
            return True
    return False
    
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("tracefile", metavar = "FILE", type = str, help = "Trace file")
    parser.add_argument("-r", "--range", dest = "ranges", action = "append", type = str, help = "A memory range, e.g., 0x1000-0x2000")
    
    args = parser.parse_args()
    
    ranges = []
    if args.ranges:
        for r in args.ranges:
            tmp = r.split("-")
            assert(len(tmp) == 2) #start and end must be provided
            start = literal_eval(tmp[0])
            end = literal_eval(tmp[1])
        
            ranges.append((start, end - start))
        
    if not ranges:
        ranges = DEFAULT_RANGES

    tf = TraceFile(args.tracefile)

    for h, p in tf.generate_elements():
        if h._data['type'] == ExecutionTraceType.TRACE_MEMORY:
            addr = p._data['address']
            if touches_any(addr, ranges):
                d = 'W' if ExecutionTraceMemory.EXECTRACE_MEM_WRITE & p._data['flags'] else 'R'
                print("[%c]: @0x%0x [0x%08x] -> 0x%08x" % (d, p._data['pc'], addr, p._data['value']))
                #print(hex(p._data['address'])),
                #print(hex(p._data['value'])),
                #print(hex(p._data['size']))
        elif h._data['type'] == ExecutionTraceType.TRACE_INSTR_START:
            # do nothing, we don't care about this entry
            pass

if __name__ == "__main__":
    main()