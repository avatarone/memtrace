import os
import sys
import logging
import argparse

from TraceEntries import TraceFile, ExecutionTraceType, ExecutionTraceMemory
from collections import defaultdict

APPLICATION_NAME = "IdentifyDevice"


log = logging.getLogger(APPLICATION_NAME)


def loop_analysis(tracefile):
    for header, record in tracefile.generate_elements():
        if header._data["type"] == ExecutionTraceType.TRACE_INSTRUCTION:
            pc = record._data["pc"]
            


def guess_size(val):
    """Guess the minimum number of bytes that this value could be stored in"""
    for i in [1, 2, 4, 8]:
        if val & ((1 << (i * 8)) - 1) == val:
            return i
    
    
    if (val & 0xff) == val:
        return 1
   
def main(args, env):
    dev_regs = defaultdict(lambda: defaultdict(list)) # identified device registers
    for header, record in TraceFile(args.trace_file).generate_elements():
        if header._data["type"] == ExecutionTraceType.TRACE_MEMORY:
            #TODO: Filter memory range for just one device
            
            #Filter out code loads
            if record._data['flags'] & ExecutionTraceMemory.EXECTRACE_MEM_CODE:
                continue
            
            is_write = record._data['flags'] & ExecutionTraceMemory.EXECTRACE_MEM_WRITE != 0
            address = record._data['address']
            size = record._data['size']
            value = record._data['value']
            pc = record._data['pc']
            
            dev_regs[address]["size"].append(size)
            dev_regs[address]["guessed_size"].append(guess_size(value))
            dev_regs[address]["pc"].append(pc)
            dev_regs[address]["values"].append(value)
            dev_regs[address]["mode"].append(is_write)
            if not dev_regs[address]["num_accesses"]:
                dev_regs[address]["num_accesses"] = 1
            else:
                dev_regs[address]["num_accesses"] += 1
            
            
    for addr, reg in dev_regs.items():
        #Try to reconciliate sizes
        size_bins = defaultdict(lambda: 0)
        for size in reg["size"]:
            size_bins[size] += 1
        #TODO: Need to somehow reconciliate the different sizes
        reg["size"] = size_bins.keys()
        
        guessed_size = 0
        for gsize in reg["guessed_size"]:
            guessed_size = max(guessed_size, gsize)
       
        if reduce(lambda r, x: r and x, reg["mode"], True):
            reg["mode"] = "w"
        elif reduce(lambda r, x: r or x, reg["mode"], False):
            reg["mode"] = "r"
        else:
            reg["mode"] = "rw"
        reg["guessed_size"] = guessed_size
        reg["pc"] = list(set(reg["pc"]))
        reg["values"] = list(set(reg["values"]))
        
    for addr, reg in dev_regs.items():
        print("Register 0x%08x: size = %s, guessed size = %d, mode = %s, # accesses = %d, pcs = %s, values = %s" % (
            addr,
            ", ".join(["%d" % x for x in reg["size"]]), 
            reg["guessed_size"], 
            reg["mode"],
            reg["num_accesses"],
            ", ".join(["0x%08x" % x for x in reg["pc"]]), 
            ", ".join(["0x%x" % x for x in reg["values"]])))
    
        
    


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", action = "count", dest = "verbosity", default = 0,
        help = "Increase output verbosity (specify several times for more verbose output)")
    parser.add_argument("trace_file", type = str, help = "S2E ExecutionTracer.dat trace file")
    
    args = parser.parse_args()
    logging.basicConfig(level = {0: logging.ERROR, 1: logging.WARNING, 2: logging.INFO, 3: logging.DEBUG}[min(args.verbosity, 3)])
    return args
  

if __name__ == "__main__":
    result = main(parse_args(), os.environ)
    if not result is None:
        sys.exit(result)