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
    parser.add_argument("--terse", action = "store_true", default = False, dest = "terse", help = "Terse output format")
    parser.add_argument("--color", action = "store_true", default = False, dest = "color", help = "Use colors")
    
    args = parser.parse_args()
    tf = TraceFile(args.trace_file)
    last_registers = None
    
    ctf = None
    if args .concolic:
        ctf = open_file(args.concolic, "rb")

    for h, p in tf.generate_elements():
        if h._data['type'] == ExecutionTraceType.TRACE_MEMORY:
            if args.terse:
                #Do not display instruction loads
                if p._data['flags'] & ExecutionTraceMemory.EXECTRACE_MEM_CODE:
                    continue
                format_string = "[M] %%08x: 0x%%08x[%%d] %%s 0x%%0%dx" % (2 * p._data['size'])
                if p._data['flags'] & ExecutionTraceMemory.EXECTRACE_MEM_WRITE:
                    read_write = 'w'
                else:
                    read_write = 'r'
                print(format_string % (p._data['pc'], p._data['address'], p._data['size'], read_write, p._data['value']))
            else:
                print("MemoryAccess: address = 0x%08x, size = %d, value = 0x%x" % (p._data['address'], p._data['size'], p._data['value']))
        elif h._data['type'] == ExecutionTraceType.TRACE_CONCOLIC_FORK_KILL:
            if ctf:
                ctf.seek(p._data['condition_offset'])
                condition = ctf.read(p._data['condition_size']).decode(encoding = 'iso-8859-1')
            else:
                condition = "<unable to load condition>"
            print("ConcolicFork: pc = 0x%08x, state_id = % 4d, condition = %s" % (p._data['pc'], p._data['killed_state_id'], condition))
        elif h._data['type'] == ExecutionTraceType.TRACE_INSTR_START:
            if args.terse:
                if p._data['isSymbolic'] == 0:
                    symbolic_concrete = 'c'
                else:
                    symbolic_concrete = 's'
                registers = []
                for (reg, regnr) in zip(p._data['arm_registers'], range(0, 16)):
                    #registers.append("r%d: %08x" % (regnr, reg))
                    if args.color and last_registers and last_registers[regnr] != reg:
                        registers.append("\x1b[31m%08x\x1b[30m" % reg)
                    else:
                        registers.append("%08x" % (reg))
                    if regnr in [3, 7, 11]:
                        registers.append("#")
                print("[I] %08x: %s %s" % (p._data['pc'], symbolic_concrete, " ".join(registers)))
                last_registers = p._data['arm_registers']
            else:
                print("Instruction: pc = 0x%08x, symbolic = %s" % (p._data['pc'], p._data['isSymbolic'] and 'yes' or 'no'))
        elif h._data['type'] == ExecutionTraceType.TRACE_TB_START:
            if args.terse:
                if p._data['isSymbolic'] == 0:
                    symbolic_concrete = 'c'
                else:
                    symbolic_concrete = 's'
                registers = []
                for (reg, regnr) in zip(p._data['arm_registers'], range(0, 16)):
                    #registers.append("r%d: %08x" % (regnr, reg))
                    if args.color and last_registers and last_registers[regnr] != reg:
                        registers.append("\x1b[31m%08x\x1b[30m" % reg)
                    else:
                        registers.append("%08x" % (reg))
                    if regnr in [3, 7, 11]:
                        registers.append("#")
                print("[S] %08x: %s %s" % (p._data['pc'], symbolic_concrete, " ".join(registers)))
                last_registers = p._data['arm_registers']
            else:
                print("Instruction: pc = 0x%08x, symbolic = %s" % (p._data['pc'], p._data['isSymbolic'] and 'yes' or 'no'))
        elif h._data['type'] == ExecutionTraceType.TRACE_TB_END:
            if args.terse:
                if p._data['isSymbolic'] == 0:
                    symbolic_concrete = 'c'
                else:
                    symbolic_concrete = 's'
                registers = []
                for (reg, regnr) in zip(p._data['arm_registers'], range(0, 16)):
                    #registers.append("r%d: %08x" % (regnr, reg))
                    if args.color and last_registers and last_registers[regnr] != reg:
                        registers.append("\x1b[31m%08x\x1b[30m" % reg)
                    else:
                        registers.append("%08x" % (reg))
                    if regnr in [3, 7, 11]:
                        registers.append("#")
                print("[E] %08x: %s %s" % (p._data['pc'], symbolic_concrete, " ".join(registers)))
                last_registers = p._data['arm_registers']
            else:
                print("Instruction: pc = 0x%08x, symbolic = %s" % (p._data['pc'], p._data['isSymbolic'] and 'yes' or 'no'))
        
