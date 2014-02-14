import struct
from collections import namedtuple

class ExecutionTraceEntry(object):
    def __init__(self):
        self._data  = {}
        for field, size in self._fields:
            if type(size) == list:
                empty_list = [0 for i in range(len(size))]
                setattr(self, field, empty_list)
            else:
                setattr(self, field, 0)

    def __len__(self):
        s = 0
        for _, size in self._fields:
            if type(size) == list:
                s += len(size)
            else:
                s += size
        # len in bytes
        return int(s/8)

    def __str__(self):
        s = ''
        for field, size in self._fields:
            if type(size) == list:
                s += 'uint%d_t %s = [' % (size[0], field)
                for v in getattr(self, field, []):
                    s += '%08x, ' % v
                s += ']'
            else:
                s += 'uint%d_t %s = %s, ' % (size, field, hex(getattr(self, field, 0)))
        return s

    def dumps(self):
        ret = ''
        for field, size in self._fields:
            if type(size) == list:
                ret += struct.pack('<'+self.get_field_descr_for_pack(size[0])*
                        len(size), *getattr(self, field, []))
            else:
                ret += struct.pack('<'+self.get_field_descr_for_pack(size),
                        getattr(self, field, 0))
        return ret

    def loads(self, data):
        s = '<'
        total_size = len(self)
        for _, size in self._fields:
            if type(size) == list:
                s += self.get_field_descr_for_pack(size[0]) * len(size)
            else:
                s += self.get_field_descr_for_pack(size)
        try:
            values = struct.unpack(s, data[:total_size])
        except struct.error:
            raise Exception("Failed to unpack: %s[%s]" % (repr(data), s))

        c = 0
        for field, size in self._fields:
            if type(size) == list:
                new_list = []
                for i in range(len(size)):
                    new_list += [values[c]]
                    c += 1
                setattr(self, field, new_list)
            else:
                setattr(self, field, values[c])
                c += 1

    def get_field_descr_for_pack(self, size):
        try:
            return {64:'Q', 32:'L', 16:'H', 8:'B'}[size]
        except KeyError:
            return 'B' * (int(size/8))

class ExecutionTraceMemory(ExecutionTraceEntry):
    def __init__(self):
        self._fields = [('pc',64), ('address',64), ('value',64), ('size',8), ('flags',8)]
        super(ExecutionTraceMemory, self).__init__()

class ExecutionTraceItemHeader(ExecutionTraceEntry):
    def __init__(self):
        self._fields = [("timeStamp", 64), ("size", 32 ), ("type", 8 ), ("stateId", 32), ("pid", 64)]
        super(ExecutionTraceItemHeader, self).__init__()

class ExecutionTraceModuleLoad(ExecutionTraceEntry):
    def __init__(self):
        self._fields = [("name", 256), ("loadBase", 64), ("nativeBase", 64), ("size", 64)]
        super(ExecutionTraceModuleLoad, self).__init__()

class ExecutionTraceModuleUnload(ExecutionTraceEntry):
    def __init__(self):
        self._fields = [("loadBase", 64)]
        super(ExecutionTraceModuleUnload, self).__init__()

class ExecutionTraceCall(ExecutionTraceEntry):
    def __init__(self):
        self._fields = [("source", 64), ("target", 64)]
        super(ExecutionTraceCall, self).__init__()

class ExecutionTraceFork(ExecutionTraceEntry):
    def __init__(self):
        self._fields = [("pc", 64), ("stateCount", 32), ("children", 32)]
        super(ExecutionTraceFork, self).__init__()

class ExecutionTraceBranchCoverage(ExecutionTraceEntry):
    def __init__(self):
        self._fields = [("pc", 64), ("destPc", 64)]
        super(ExecutionTraceBranchCoverage, self).__init__()

class ExecutionTraceCacheSimParams(ExecutionTraceEntry):
    def __init__(self):
        self._fields = [("type", 8), ("cacheId", 32), ("size", 32), ("lineSize", 32), ("associativity", 32), ("upperCacheId", 32)]
        super(ExecutionTraceCacheSimParams, self).__init__()

class ExecutionTraceTb(ExecutionTraceEntry):
    def __init__(self):
        self._fields = [("pc", 64), ("targetPc", 64), ("size", 32), ("tbType",
            8), ("symbMask", 32), ("registers", [64] * 16)]
        super(ExecutionTraceTb, self).__init__()

class ExecutionTraceInstr(ExecutionTraceEntry):
    def __init__(self):
        self._fields = [("isSymbolic", 8), ("arch", 32), ("pc", 64), ("symbMask", 32), ("flags", 64), ("arm_registers", [32] * 15)]
        super(ExecutionTraceInstr, self).__init__()


if __name__ == "__main__":
    m = ExecutionTraceMemory()
    print(m)
    print(len(m))
    print(repr(m.dumps()))
    m.loads('\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\x00')
    print(repr(m.dumps()))
    print(str(m))
    t = ExecutionTraceTb()
    print(str(t))
    t.registers[0] = 0x99999999
    print(str(t))
    print(repr(t.dumps()))
    t = ExecutionTraceInstr()
    print(str(t))
    t.arm_registers[0] = 0x99999999
    print(str(t))
    print(repr(t.dumps()))
