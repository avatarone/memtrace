import argparse
from TraceEntries import *
from collections import defaultdict, OrderedDict
import logging
import json

ARM_REG_SP = 13

BIN_TYPE_CODE = "code"
BIN_TYPE_STACK = "stack"
BIN_TYPE_IO = "io"
BIN_TYPE_DATA = "data"
BIN_TYPE_RODATA = "rodata"
BIN_TYPE_WODATA = "wodata"

log = logging.getLogger("BuildMemoryMap")

class ShadowMemory(object):
    ENDIAN_LITTLE = 0
    ENDIAN_BIG = 1
    def __init__(self, endianness = ENDIAN_LITTLE):
        self._mem = {}
        self._endianness = endianness
        
    def write(self, address, size, value):
        for i in range(0, size):
            if self._endianness == ShadowMemory.ENDIAN_LITTLE:
                self._mem[address + i] = (value >> (i * 8)) & 0xff
            elif self._endianness == ShadowMemory.ENDIAN_BIG:
                self._mem[address + size - 1 - i] =  (value >> (i * 8)) & 0xff
            else:
                assert(False) #Unknown endianness
      
    #Notify shadow memory of read access
    #Returns False if the value was as expected, True if the value is different          
    def read(self, address, size, value):
        different = False
        for i in range(0, size):
            if self._endianness == ShadowMemory.ENDIAN_LITTLE:
                if (address + i) in self._mem and self._mem[address + i] != (value >> (i * 8)) & 0xff:
                    different = True
                self._mem[address + i] = (value >> (i * 8)) & 0xff
            elif self._endianness == ShadowMemory.ENDIAN_BIG:
                if (address + size - 1 - i) in self._mem and self._mem[address + size - 1 - i] != (value >> (i * 8)) & 0xff:
                    different = True
                self._mem[address + size - 1 - i] =  (value >> (i * 8)) & 0xff
            else:
                assert(False) #Unknown endianness              
        return different
        
            

class MemoryMap(object):
    def __init__(self, binsize = 64, endianness = ShadowMemory.ENDIAN_LITTLE):
        self._binsize = binsize
        self._read = defaultdict(lambda: 0)
        self._write = defaultdict(lambda: 0)
        self._execute = defaultdict(lambda: 0)
        self._stack = defaultdict(lambda: 0)
        self._io = defaultdict(lambda: 0)
        self._shadow_mem = ShadowMemory(endianness)
        
    def add_memory_access(self, access):
        if access['flags'] & ExecutionTraceMemory.EXECTRACE_MEM_CODE != 0:
            self._execute[access['address'] / self._binsize] += 1
        elif access['flags'] & ExecutionTraceMemory.EXECTRACE_MEM_WRITE != 0:
            self._write[access['address'] / self._binsize] += 1
            self._shadow_mem.write(access['address'], access['size'], access['value'])
        else:
            self._read[access['address'] / self._binsize] += 1
            is_io = self._shadow_mem.read(access['address'], access['size'], access['value'])
            if is_io:
                self._io[access['address'] / self._binsize] += 1
            
    def add_execute_instruction(self, instr):
        if instr['arm_registers'][ARM_REG_SP] != 0:
            self._stack[(instr['arm_registers'][ARM_REG_SP] - 1) / self._binsize] += 1
            
    def get_raw_bins(self):
        raw_bins = defaultdict(dict)
        dictionaries = [("io", self._io), ("read", self._read), ("write", self._write), \
            ("execute", self._execute), ("stack", self._stack)]
        for (name, dictionary) in dictionaries:
            for (key, value) in dictionary.items():
                raw_bins[key * self._binsize][name] = value
                
        return raw_bins 
        
        
    def __str__(self):
        raw_bins = self.get_raw_bins()
        keys = sorted(raw_bins.keys())
        result = []
        for key in keys:
            r = "read" in raw_bins[key] and raw_bins[key]["read"] or 0
            w = "write" in raw_bins[key] and raw_bins[key]["write"] or 0
            x = "execute" in raw_bins[key] and raw_bins[key]["execute"] or 0
            s = "stack" in raw_bins[key] and raw_bins[key]["stack"] or 0
            i = "io" in raw_bins[key] and raw_bins[key]["io"] or 0
            result.append("0x%08x: read = %d, write = %d, execute = %d, stack = %d, io = %d" % (key,r,w,x,s,i))
        return "\n".join(result)
        
    def get_memory_map(self):
        seen_ranges = sorted(set(self._read.keys() + self._write.keys() + self._execute.keys() + \
            self._stack.keys() + self._io.keys()))
        classified_bins = OrderedDict()
        for r in seen_ranges:
            if self._execute[r] > 0:
                classified_bins[r] = BIN_TYPE_CODE
            elif self._stack[r] > 0 and (self._read[r] > 0 or self._write[r] > 0):
                classified_bins[r] = BIN_TYPE_STACK
            elif self._io[r] > 0:
                classified_bins[r] = BIN_TYPE_IO
            elif self._write[r] > 0 and self._read[r] == 0:
                classified_bins[r] = BIN_TYPE_WODATA
            elif self._write[r] > 0:
                classified_bins[r] = BIN_TYPE_DATA
            else:
                classified_bins[r] = BIN_TYPE_RODATA
                
        #Now unify adjacent ranges
        cur_range = None
        unified_ranges = []
        for (bucket, kind) in classified_bins.items():
            if cur_range is None:
                cur_range = {"start": bucket, "end": bucket, "type": kind}
            elif cur_range["end"] == bucket - 1 and cur_range["type"] == kind:
                cur_range["end"] = bucket
            else:
                unified_ranges.append(cur_range)
                cur_range = {"start": bucket, "end": bucket, "type": kind}
        if not cur_range in unified_ranges:
            unified_ranges.append(cur_range)
                
        for r in unified_ranges:
            r["start"] = r["start"] * self._binsize
            r["end"] = r["end"] * self._binsize + self._binsize - 1
            r['size'] = r["end"] - r["start"] + 1
                
        return unified_ranges
            
            
        
def buildMemoryMap(filename, binsize = 256, endianness = ShadowMemory.ENDIAN_LITTLE):
    tf = TraceFile(filename)
    mm = MemoryMap(binsize, endianness)

    try:
        for h, p in tf.generate_elements():
            if h._data['type'] == ExecutionTraceType.TRACE_MEMORY:
                mm.add_memory_access(p._data)
            elif h._data['type'] == ExecutionTraceType.TRACE_INSTR_START:
                mm.add_execute_instruction(p._data)
            else:
                log.debug("Unknown trace entry type in trace file: %d", h._data['type'])
    except KeyboardInterrupt:
        log.warn("\nMemory map generation interrupted, displayed map is incomplete.")
            
#        if idx > 100000:
#            break
            
    return mm.get_memory_map()
        
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("tracefile", type = str, metavar =  "FILE", help = "Trace file used as input")
    parser.add_argument("-v", "--verbose", action = "store_true", default = False, help = "Verbose output")
    parser.add_argument("-j", "--dump-json", type = str, dest = "json", default = None, 
        help = "Dump memory map as JSON to this file")
    parser.add_argument("-b", "--binsize", type = int, default = 256, dest = "binsize",
        help = "Bin size used for memory bins to group memory accesses")
    parser.add_argument("--big-endian", action = "store_true", dest = "big_endian", default = False,
        help = "Memory trace stems from a big endian device")
    args = parser.parse_args()
    
    if (args.verbose):
        logging.basicConfig(level = logging.INFO)
    else:
        logging.basicConfig(level = logging.WARN)
        
    if args.big_endian:
        endianness = ShadowMemory.ENDIAN_BIG
    else:
        endianness = ShadowMemory.ENDIAN_LITTLE
        
    mm = buildMemoryMap(args.tracefile, binsize = args.binsize, endianness = endianness)
    
    if not args.json is None:
        with open(args.json, 'w') as file:
            json.dump(mm, file, sort_keys=True, indent=4, separators=(',', ': '))
            
    for elem in mm:
        print("start: 0x%08x, end: 0x%08x, type: %s" % tuple(map(lambda x: elem[x], ["start", "end", "type"])))
    
if __name__ == "__main__":
    main()
