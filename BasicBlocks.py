import re

STATE_BEFORE_BEGINNING = 0
STATE_INSIDE = 1
STATE_AFTER = 2

class BasicBlocks():
    def __init__(self, qemu_trace_file):
        self._qemu_trace_file = qemu_trace_file
        
    def get_basic_blocks(self):
        RE_PC = re.compile("^(0x[0-9a-f]{8}):.*")
        
        with open(self._qemu_trace_file, 'r') as file:
            state = STATE_AFTER
            for line in file.readlines():
                line = line.strip()
                match = RE_PC.match(line)
            
                if line.startswith("IN:"):
                    state = STATE_BEFORE_BEGINNING
                elif state == STATE_BEFORE_BEGINNING and match:
                    start_pc = int(match.group(1), 16)
                    end_pc = start_pc
                    state = STATE_INSIDE
                elif state == STATE_INSIDE:
                    if match:
                        end_pc = int(match.group(1), 16)
                    else:
                        yield (start_pc, end_pc)
                        state = STATE_AFTER
                        
    
                    
if __name__ == "__main__":
    import sys
    for bb in BasicBlocks(sys.argv[1]).get_basic_blocks():
        print("Basic block: 0x%08x - 0x%08x" % (bb[0], bb[1]))
    
                
                