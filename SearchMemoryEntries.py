import sys
from TraceEntries import *

# rtc-timer, integrator_pit, serial
ranges=[0x15000000, 0x13000000, 0x16000000]
#ranges=[0x00000000]
#page=   0x1000
page=   0x10

def touches_one(addr, base):
    return (addr < (base + page)) and (addr >= base)

def touches_any(addr):
    for b in ranges:
        if touches_one(addr, b):
            return True
    return False

if __name__ == "__main__":
    tf = TraceFile(sys.argv[1])

    for h, p in tf.generate_elements():
        if h._data['type'] == ExecutionTraceType.TRACE_MEMORY:
            addr = p._data['address']
            if touches_any(addr):
                d = 'W' if ExecutionTraceMemory.EXECTRACE_MEM_WRITE & p._data['flags'] else 'R'
                print("[%c]: @0x%0x [0x%08x] -> 0x%08x" % (d, p._data['pc'], addr, p._data['value']))
                #print(hex(p._data['address'])),
                #print(hex(p._data['value'])),
                #print(hex(p._data['size']))
        elif h._data['type'] == ExecutionTraceType.TRACE_INSTR_START:
            # do nothing, we don't care about this entry
            pass
