import struct
from collections import namedtuple
import datetime
import sys

class ExecutionTraceEntry(object):
    _cached_unpacked_strings = {}
    _cached_lens = {}
    def __init__(self):
        self._data  = {}
        self._cached_len = None
        self._cached_unpack_string = None
        self._cached_packed_string = None
        #pass
        for field, size in self._fields:
            if type(size) == list:
                empty_list = [0 for i in range(len(size))]
                setattr(self, field, empty_list)
            else:
                setattr(self, field, 0)

    def __len__(self):
        if self._cached_len is None:
            try:
                self._cached_len = ExecutionTraceEntry._cached_lens[self.__class__.__name__]
            except KeyError:
                print("len not in cache")
                s = 0
                for _, size in self._fields:
                    if type(size) == list:
                        s += len(size) * size[0]
                    else:
                        s += size
                # len in bytes
                ExecutionTraceEntry._cached_lens[self.__class__.__name__] = int(s/8)
                self._cached_len = ExecutionTraceEntry._cached_lens[self.__class__.__name__]
        return self._cached_len

    def __str__(self):
        s = '%s: ' % (self.__class__.__name__)
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

    def _get_unpack_string(self):
        if self._cached_unpack_string is None:
            try:
                self._cached_unpack_string = ExecutionTraceEntry._cached_unpacked_strings[self.__class__.__name__]
            except KeyError:
                s = '<'
                for _, size in self._fields:
                    if type(size) == list:
                        s += self.get_field_descr_for_pack(size[0]) * len(size)
                    else:
                        s += self.get_field_descr_for_pack(size)
                ExecutionTraceEntry._cached_unpacked_strings[self.__class__.__name__] = s
                self._cached_unpack_string = ExecutionTraceEntry._cached_unpacked_strings[self.__class__.__name__]
                print("added to cache %s" % (self._cached_unpack_string))
        return self._cached_unpack_string

    def loads(self, data):
        total_size = len(self)
        #values = struct.unpack(self._get_unpack_string(), data[:total_size])
        try:
            values = struct.unpack(self._get_unpack_string(), data[:total_size])
        except struct.error:
            raise Exception("Failed to unpack: %s-%s-%s" % (self._cached_unpack_string, len(data[:total_size]), self.__class__.__name__))

        c = 0
        for field, size in self._fields:
            if type(size) == list:
                new_list = []
                for i in range(len(size)):
                    new_list += [values[c]]
                    c += 1
                self._data[field] = new_list
                setattr(self, field, new_list)
            else:
                self._data[field] = values[c]
                setattr(self, field, values[c])
                c += 1

    def get_field_descr_for_pack(self, size):
        try:
            return {64:'Q', 32:'L', 16:'H', 8:'B'}[size]
        except KeyError:
            return 'B' * (int(size/8))

class ExecutionTraceMemory(ExecutionTraceEntry):
    EXECTRACE_MEM_WRITE = 1
    EXECTRACE_MEM_IO = 2
    EXECTRACE_MEM_SYMBVAL = 4
    EXECTRACE_MEM_SYMBADDR = 8
    EXECTRACE_MEM_HASHOSTADDR = 16
    EXECTRACE_MEM_SYMBHOSTADDR = 32
    EXECTRACE_MEM_CODE = 64
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

class ExecutionTraceType(object):
    TRACE_MOD_LOAD     = 0
    TRACE_MOD_UNLOAD   = 1
    TRACE_PROC_UNLOAD  = 2
    TRACE_CALL         = 3
    TRACE_RET          = 4
    TRACE_TB_START     = 5
    TRACE_TB_END       = 6
    TRACE_MODULE_DESC  = 7
    TRACE_FORK         = 8
    TRACE_CACHESIM     = 9
    TRACE_TESTCASE     = 10
    TRACE_BRANCHCOV    = 11
    TRACE_MEMORY       = 12
    TRACE_PAGEFAULT    = 13
    TRACE_TLBMISS      = 14
    TRACE_ICOUNT       = 15
    TRACE_MEM_CHECKER  = 16
    TRACE_INSTR_START  = 17
    TRACE_MAX          = 18
    types = [
            ('TRACE_MOD_LOAD',   None),
            ('TRACE_MOD_UNLOAD', None),
            ('TRACE_PROC_UNLOAD',None),
            ('TRACE_CALL',       None),
            ('TRACE_RET',        None),
            ('TRACE_TB_START',   None),
            ('TRACE_TB_END',     None),
            ('TRACE_MODULE_DESC',None),
            ('TRACE_FORK',       ExecutionTraceFork),
            ('TRACE_CACHESIM',   None),
            ('TRACE_TESTCASE',   None),
            ('TRACE_BRANCHCOV',  None),
            ('TRACE_MEMORY',     ExecutionTraceMemory),
            ('TRACE_PAGEFAULT',  None),
            ('TRACE_TLBMISS',    None),
            ('TRACE_ICOUNT',     None),
            ('TRACE_MEM_CHECKER',None),
            ('TRACE_INSTR_START',ExecutionTraceInstr),
            ('TRACE_MAX',        None)
    ]
    @staticmethod
    def get_type_from_val(val):
        if val >= len(ExecutionTraceType.types):
            return None
        else:
            return ExecutionTraceType.types[val][1]

class TraceFile(object):
    def __init__(self, path):
        self._path = path
        self._data = None

    def load(self):
        with open(self._path, 'r') as f:
            self._data = self.loads(f.read())

    def loads(self, data_in):
        parsed_len = 0
        total_len = len(data_in)
        ret = []
        while parsed_len < total_len:
            hdr = ExecutionTraceItemHeader()
            ret += [hdr]
            try:
                hdr.loads(data_in[parsed_len:])
            except:
                break
            parsed_len += len(hdr)
            #print(str(hdr))
            #print(datetime.datetime.fromtimestamp(hdr.timeStamp).strftime('%Y-%m-%d %H:%M:%S'))
            #hdr.type = hdr._data['type']
            next_type = (ExecutionTraceType.get_type_from_val(hdr._data['type']))
            if next_type == None:
                print("Unknown type: 0x%x" % hdr._data['type'])
            else:
                payload = next_type()
                try:
                    payload.loads(data_in[parsed_len:])
                except:
                    break
                if next_type == ExecutionTraceMemory:
                    print(str(payload))
                #print(str(payload))
                #print(hex(payload.arm_registers[1]))
                #print(hex(payload.pc))
                ret += [payload]
            parsed_len += hdr.size
        return ret

    def get_entries_ok(self):
        if not self._data:
            self.load()
        return self._data


if __name__ == "__main__":
    f = TraceFile('/tmp/s2e_output/s2e-last/ExecutionTracer.dat')
    #f = TraceFile('../s2e-arm-testsuite/tests/arm-bigendian/s2e-out-46/ExecutionTracer.dat')
    print('Processed: %d entries' % len(f.get_entries_ok()))

if __name__ == "__main__1":
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
