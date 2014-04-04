# This script remove the loop of waiting for a character on the serial
# This is useful to speed the replay up
import sys
#from SearchMemoryEntries import touches_any
from TraceEntries import *


#ranges=[0x16000000]
#
#size = 0x1000

if __name__ == "__main__":
    tf = TraceFile(sys.argv[1])
    of = open(sys.argv[2], 'wb')

    last_entry = None
    l = 0
    for h, p in tf.generate_elements():
        #print(hex(h._data['type']))
        if h._data['type'] == ExecutionTraceType.TRACE_MEMORY:
            addr = p._data['address']
            if addr == 0x16000018 and \
                    p._data['value'] == 0x90 and \
                    not (p._data['flags'] & ExecutionTraceMemory.EXECTRACE_MEM_WRITE) and \
                    int(h._data['timeStamp']) >= 449836202137180 and \
                    int(h._data['timeStamp']) <= 449836204765388:
                    #l >= 300 * 1024 * 1024:
            #if True:
                curr_entry = (p._data['pc'], p._data['address'], p._data['value'])
                if last_entry is None:
                    last_entry = curr_entry
                elif last_entry == curr_entry:
                    #print("skip")
                    continue
                last_entry = curr_entry
                d = 'W' if ExecutionTraceMemory.EXECTRACE_MEM_WRITE & p._data['flags'] else 'R'
                print("[%c]: @0x%0x [0x%08x] -> 0x%08x" % \
                        (d, p._data['pc'], addr, p._data['value']))
        s = h.dumps()+p.dumps()
        l += len(s)
        of.write(s)
        #print("%d" % int(h._data['timeStamp']))
    of.close()
