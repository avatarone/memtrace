import argparse
from TraceEntries import *
from collections import defaultdict, OrderedDict
import logging
import json
from ast import literal_eval

ARM_REG_SP = 13

BIN_TYPE_CODE = "code"
BIN_TYPE_STACK = "stack"
BIN_TYPE_IO = "io"
BIN_TYPE_DATA = "data"
BIN_TYPE_RODATA = "rodata"

log = logging.getLogger("GroupHWDevices")

class MemoryRange(dict):
    def __init__(self, start, size = None, end = None):
        assert(not (size is None and end is None))
        
        self["start"] = start
        if not size is None:
            self["size"] = size
        elif not end is None:
            self["size"] = end - start
        else:
            assert(False) #Either size or end must be given
            
        super(MemoryRange, self).__init__()
            
    def contains(self, address):
        return address >= self["start"] and address < self["start"] + self["size"]
        
class MemoryRanges(list):
    def contains(self, address):
        for mem_range in self:
            if mem_range.contains(address):
                return True
        return False
        
class Devices(object):
    def __init__(self):
        self._devices = {}
    def add_memory_access(self, address, size, value, is_write):
        log.debug("add_memory_access(0x%08x, %d, 0x%08x, %s)" % (address, size, value, is_write and "write" or "read"))
        base_address = address & ~0xfff
        
        if not base_address in self._devices:
            self._devices[base_address] = {"base": base_address, "size": 0x1000}
            
    def get_devices(self):
        return self._devices
        
    def __str__(self):
        result = []

        for (dev, idx) in zip(self._devices.values(), xrange(1, 10000)):
            result.append("Device % 2d: base 0x%08x size 0x%x" % (idx, dev["base"], dev["size"]))
            
        return "\n".join(result)
        
def groupDevices(filename, ranges):
    tf = TraceFile(filename)
    dev = Devices()
    
    try:
        for h, p in tf.generate_elements():
            if h._data['type'] == ExecutionTraceType.TRACE_MEMORY and \
                    ranges.contains(p._data['address']) and \
                    (p._data['flags'] & ExecutionTraceMemory.EXECTRACE_MEM_CODE) == 0:
                dev.add_memory_access(
                        p._data['address'], 
                        p._data['size'], 
                        p._data['value'], 
                        p._data['flags'] & ExecutionTraceMemory.EXECTRACE_MEM_WRITE != 0)
    except KeyboardInterrupt:
        log.warn("\nDevice grouping interrupted, displayed map is incomplete.")
            
    return dev
        
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("tracefile", type = str, metavar =  "FILE", help = "Trace file used as input")
    parser.add_argument("-v", "--verbose", action = "store_true", default = False, help = "Verbose output")
    parser.add_argument("-j", "--dump-json", type = str, dest = "json", default = None, help = "Dump results to JSON file")
    
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-r", "--iorange", type = str, dest = "io_ranges", action = "append", help = "IO memory range")
    group.add_argument("-m", "--memmap", type = str, metavar = "FILE", dest = "memmap", help = "JSON file with memory map")
    args = parser.parse_args()
    
    if (args.verbose):
        logging.basicConfig(level = logging.INFO)
    else:
        logging.basicConfig(level = logging.WARN)
        
    ranges = MemoryRanges()
    if args.io_ranges:
        for r in args.io_ranges:
            tmp = r.split("-")
            assert(len(tmp) == 2) #start and end must be provided
            start = literal_eval(tmp[0])
            end = literal_eval(tmp[1])
        
            ranges.append(MemoryRange(start = start, end = end))
    else:
        with open(args.memmap, 'r') as file:
            memmap = json.load(file)
            for entry in memmap:
                if entry["type"] == "io":
                    ranges.append(MemoryRange(start = entry["start"], end = entry["end"]))
    if not ranges:
        log.warn("No IO ranges specified. Calling this program with no ranges makes no sense.")
        
    devices = groupDevices(args.tracefile, ranges)
    
    print(devices)
    
    if not args.json is None:
        with open(args.json, 'w') as file:
            
            json.dump(devices.get_devices().values(), file, sort_keys=True, indent=4, separators=(',', ': '))
    
if __name__ == "__main__":
    main()
