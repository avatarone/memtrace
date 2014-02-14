import struct
from collections import namedtuple

class ExecutionTraceEntry:
    def __init__(self):
        self._fields = []
        self._data  = {}
    def __len__(self):
        s = 0
        for _, size in self._fields:
            s += size
        # len in bytes
        return int(s/8)
    def __str__(self):
        s = ''
        for field, size in self._fields:
            s += 'uint%d_t %s = %s, ' % (size, field, hex(getattr(self, field, 0)))
        return s

    def dumps(self):
        ret = ''
        for field, size in self._fields:
            ret += struct.pack('<'+self.get_field_descr_for_pack(size),
                    getattr(self, field, 0))
        return ret

    def loads(self, data):
        s = '<'
        total_size = len(self)
        for _, size in self._fields:
            s += self.get_field_descr_for_pack(size)
        try:
            values = struct.unpack(s, data[:total_size])
        except struct.error:
            raise Exception("Failed to unpack: %s" % (repr(data)))

        c = 0
        for field, _ in self._fields:
            setattr(self, field, values[c])
            c += 1

    def get_field_descr_for_pack(self, size):
        return {64:'Q', 32:'L', 16:'H', 8:'B'}[size]

class ExecutionTraceMemory(ExecutionTraceEntry):
    def __init__(self):
        self._fields = [('pc',64), ('address',64), ('value',64), ('size',8), ('flags',8)]

if __name__ == "__main__":
    m = ExecutionTraceMemory()
    print(m)
    print(len(m))
    print(repr(m.dumps()))
    m.loads('\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\x00')
    print(repr(m.dumps()))
    print(str(m))
