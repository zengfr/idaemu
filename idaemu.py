from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
#from unicorn.x64_const import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from unicorn.mips_const import *
from struct import unpack, pack, unpack_from, calcsize
from idaapi import get_func
#from idc import Qword, GetManyBytes, SelStart, SelEnd, here, ItemSize
from idautils import XrefsTo
import idc
import sys
PAGE_ALIGN = 0x1000  # 4k

COMPILE_GCC = 1
COMPILE_MSVC = 2

TRACE_OFF = 0
TRACE_DATA_READ = 1
TRACE_DATA_WRITE = 2
TRACE_CODE = 4
TRACE_INTR = 8

class Emu(object):
    def __init__(self, arch, mode, compiler=COMPILE_GCC, stack=0xf000000, \
                 ssize=3):
        assert (arch in [UC_ARCH_X86, UC_ARCH_ARM, UC_ARCH_ARM64])
        self.arch = arch
        self.mode = mode
        self.compiler = compiler
        self.stack = self._alignAddr(stack)
        self.ssize = ssize
        self.data = []
        self.regs = []
        self.curUC = None
        self.traceOption = TRACE_OFF
        self.logBuffer = []
        self.inst_skip_list=[]
        self.altFunc = {}
        self._init()

    def _addTrace(self, logInfo):
        self.logBuffer.append(logInfo)

    # callback for tracing invalid memory access (READ or WRITE, FETCH)
    def _hook_mem_invalid(self, uc, access, address, size, value, user_data):
        addr = self._alignAddr(address)
        uc.mem_map(addr, PAGE_ALIGN)
        data = self._getOriginData(addr, PAGE_ALIGN)
        uc.mem_write(addr, data)
        return True

    def _hook_mem_access(self, uc, access, address, size, value, user_data):
        if access == UC_MEM_WRITE and self.traceOption & TRACE_DATA_WRITE:
            self._addTrace("### Mem W:0x%08x, size = %u, value = 0x%08x" \
                           % (address, size, value))
        elif access == UC_MEM_READ and self.traceOption & TRACE_DATA_READ:
            self._addTrace("### Mem R:0x%08x, size = %u" \
                           % (address, size))
    def _hook_code(self, uc, address, size, user_data):
        if self.traceOption & TRACE_CODE:
            self._addTrace("### Trace:0x%08x, size = %u" % (address, size))
            #self._showRegs(self.curUC)
            self.printRegs(self.REG_ARGS)
        if address in self.altFunc.keys():
            func, argc, balance = self.altFunc[address]
            try:
                sp = uc.reg_read(self.REG_SP)
                if self.REG_RA == 0:
                    RA = unpack(self.pack_fmt, str(uc.mem_read(sp, self.step)))[0]
                    sp += self.step
                else:
                    RA = uc.reg_read(self.REG_RA)

                args = []
                i = 0
                while i < argc and i < len(self.REG_ARGS):
                    args.append(uc.reg_read(self.REG_ARGS[i]))
                    i += 1
                sp2 = sp
                while i < argc:
                    args.append(unpack(self.pack_fmt, str(uc.mem_read(sp2, self.step)))[0])
                    sp2 += self.step
                    i += 1

                res = func(uc, self.logBuffer, args)
                if type(res) != int: res = 0
                uc.reg_write(self.REG_RES, res)
                uc.reg_write(self.REG_PC, RA)
                if balance:
                    uc.reg_write(self.REG_SP, sp2)
                else:
                    uc.reg_write(self.REG_SP, sp)
            except Exception as e:
                self._addTrace("alt exception: %s" % e)
        if address in self.inst_skip_list:
          uc.reg_write(self.REG_PC, address+size)
    def _alignAddr(self, addr):
        return addr // PAGE_ALIGN * PAGE_ALIGN

    def _getOriginData(self, address, size):
        res = []
        for offset in range(0, size, 64):
            tmp = idc.get_bytes(address + offset, 64)
            if tmp == None:
                res.extend([pack("<Q", idc.create_qword(address + offset + i)) for i in range(0, 64, 8)])
            else:
                res.append(tmp)
        res = b''.join(res)
        return res[:size]

    def _init(self):
        if self.arch == UC_ARCH_X86:
            if self.mode == UC_MODE_16:
                self.step = 2
                self.pack_fmt = '<H'
                self.REG_PC = UC_X86_REG_IP
                self.REG_SP = UC_X86_REG_SP
                self.REG_RA = 0
                self.REG_RES = UC_X86_REG_AX
                self.REG_ARGS = []
            elif self.mode == UC_MODE_32:
                self.step = 4
                self.pack_fmt = '<I'
                self.REG_PC = UC_X86_REG_EIP
                self.REG_SP = UC_X86_REG_ESP
                self.REG_RA = 0
                self.REG_RES = UC_X86_REG_EAX
                self.REG_ARGS = []
            elif self.mode == UC_MODE_64:
                self.step = 8
                self.pack_fmt = '<Q'
                self.REG_PC = UC_X86_REG_RIP
                self.REG_SP = UC_X86_REG_RSP
                self.REG_RA = 0
                self.REG_RES = UC_X86_REG_RAX
                if self.compiler == COMPILE_GCC:
                    self.REG_ARGS = [UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX,
                                     UC_X86_REG_R8, UC_X86_REG_R9]
                elif self.compiler == COMPILE_MSVC:
                    self.REG_ARGS = [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9]
        elif self.arch == UC_ARCH_ARM:
            if self.mode == UC_MODE_ARM:
                self.step = 4
                self.pack_fmt = '<I'
            elif self.mode == UC_MODE_THUMB:
                self.step = 2
                self.pack_fmt = '<H'
            self.REG_PC = UC_ARM_REG_PC
            self.REG_SP = UC_ARM_REG_SP
            self.REG_RA = UC_ARM_REG_LR
            self.REG_RES = UC_ARM_REG_R0
            self.REG_ARGS = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3]
        elif self.arch == UC_ARCH_ARM64:
            self.step = 8
            self.pack_fmt = '<Q'
            self.REG_PC = UC_ARM64_REG_PC
            self.REG_SP = UC_ARM64_REG_SP
            self.REG_RA = UC_ARM64_REG_LR
            self.REG_RES = UC_ARM64_REG_X0
            self.REG_ARGS = [UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
                             UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7]

    def _initStackAndArgs(self, uc, RA, args,map=True):
        if map:
          uc.mem_map(self.stack, (self.ssize + 1) * PAGE_ALIGN)
        sp = self.stack + self.ssize * PAGE_ALIGN
        uc.reg_write(self.REG_SP, sp)

        if self.REG_RA == 0:
            uc.mem_write(sp, pack(self.pack_fmt, RA))
            self._addTrace("mem_write: %s %s" % (sp, pack(self.pack_fmt, RA)))
        else:
            uc.reg_write(self.REG_RA, RA)
            self._addTrace("reg_write: %s %s" % (self.REG_RA, RA))
        ## init the arguments
        i = 0
        while i < len(self.REG_ARGS) and i < len(args):
            uc.reg_write(self.REG_ARGS[i], args[i])
            self._addTrace("reg_write: %s %s" % (self.REG_ARGS[i], args[i]))
            i += 1
        while i < len(args):
            sp += self.step
            uc.mem_write(sp, pack(self.pack_fmt, args[i]))
            self._addTrace("mem_write: %s %s" % (sp, pack(self.pack_fmt, args[i])))
            i += 1

    def _getBit(self, value, offset):
        mask = 1 << offset
        return 1 if (value & mask) > 0 else 0

    def _showRegs(self, uc):
        print(">>> regs:")
        try:
            if self.mode == UC_MODE_16:
                ax = uc.reg_read(UC_X86_REG_AX)
                bx = uc.reg_read(UC_X86_REG_BX)
                cx = uc.reg_read(UC_X86_REG_CX)
                dx = uc.reg_read(UC_X86_REG_DX)
                di = uc.reg_read(UC_X86_REG_SI)
                si = uc.reg_read(UC_X86_REG_DI)
                bp = uc.reg_read(UC_X86_REG_BP)
                sp = uc.reg_read(UC_X86_REG_SP)
                ip = uc.reg_read(UC_X86_REG_IP)
                eflags = uc.reg_read(UC_X86_REG_EFLAGS)

                print("    AX = 0x%x BX = 0x%x CX = 0x%x DX = 0x%x" % (ax, bx, cx, dx))
                print("    DI = 0x%x SI = 0x%x BP = 0x%x SP = 0x%x" % (di, si, bp, sp))
                print("    IP = 0x%x" % ip)
            elif self.mode == UC_MODE_32:
                eax = uc.reg_read(UC_X86_REG_EAX)
                ebx = uc.reg_read(UC_X86_REG_EBX)
                ecx = uc.reg_read(UC_X86_REG_ECX)
                edx = uc.reg_read(UC_X86_REG_EDX)
                edi = uc.reg_read(UC_X86_REG_ESI)
                esi = uc.reg_read(UC_X86_REG_EDI)
                ebp = uc.reg_read(UC_X86_REG_EBP)
                esp = uc.reg_read(UC_X86_REG_ESP)
                eip = uc.reg_read(UC_X86_REG_EIP)
                eflags = uc.reg_read(UC_X86_REG_EFLAGS)

                print("    EAX = 0x%x EBX = 0x%x ECX = 0x%x EDX = 0x%x" % (eax, ebx, ecx, edx))
                print("    EDI = 0x%x ESI = 0x%x EBP = 0x%x ESP = 0x%x" % (edi, esi, ebp, esp))
                print("    EIP = 0x%x" % eip)
            elif self.mode == UC_MODE_64:
                rax = uc.reg_read(UC_X86_REG_RAX)
                rbx = uc.reg_read(UC_X86_REG_RBX)
                rcx = uc.reg_read(UC_X86_REG_RCX)
                rdx = uc.reg_read(UC_X86_REG_RDX)
                rdi = uc.reg_read(UC_X86_REG_RSI)
                rsi = uc.reg_read(UC_X86_REG_RDI)
                rbp = uc.reg_read(UC_X86_REG_RBP)
                rsp = uc.reg_read(UC_X86_REG_RSP)
                rip = uc.reg_read(UC_X86_REG_RIP)
                r8 = uc.reg_read(UC_X86_REG_R8)
                r9 = uc.reg_read(UC_X86_REG_R9)
                r10 = uc.reg_read(UC_X86_REG_R10)
                r11 = uc.reg_read(UC_X86_REG_R11)
                r12 = uc.reg_read(UC_X86_REG_R12)
                r13 = uc.reg_read(UC_X86_REG_R13)
                r14 = uc.reg_read(UC_X86_REG_R14)
                r15 = uc.reg_read(UC_X86_REG_R15)
                eflags = uc.reg_read(UC_X86_REG_EFLAGS)

                print("    RAX = 0x%x RBX = 0x%x RCX = 0x%x RDX = 0x%x" % (rax, rbx, rcx, rdx))
                print("    RDI = 0x%x RSI = 0x%x RBP = 0x%x RSP = 0x%x" % (rdi, rsi, rbp, rsp))
                print("    R8 = 0x%x R9 = 0x%x R10 = 0x%x R11 = 0x%x R12 = 0x%x " \
                      "R13 = 0x%x R14 = 0x%x R15 = 0x%x" % (r8, r9, r10, r11, r12, r13, r14, r15))
                print("    RIP = 0x%x" % rip)
            if eflags:
                print("    EFLAGS:")
                print("    CF=%d PF=%d AF=%d ZF=%d SF=%d TF=%d IF=%d DF=%d OF=%d IOPL=%d " \
                      "NT=%d RF=%d VM=%d AC=%d VIF=%d VIP=%d ID=%d"
                      % (self._getBit(eflags, 0),
                         self._getBit(eflags, 2),
                         self._getBit(eflags, 4),
                         self._getBit(eflags, 6),
                         self._getBit(eflags, 7),
                         self._getBit(eflags, 8),
                         self._getBit(eflags, 9),
                         self._getBit(eflags, 10),
                         self._getBit(eflags, 11),
                         self._getBit(eflags, 12) + self._getBit(eflags, 13) * 2,
                         self._getBit(eflags, 14),
                         self._getBit(eflags, 16),
                         self._getBit(eflags, 17),
                         self._getBit(eflags, 18),
                         self._getBit(eflags, 19),
                         self._getBit(eflags, 20),
                         self._getBit(eflags, 21)))
        except UcError as e:
            print("#ERROR: %s" % e)

    def _initData(self, uc):
        for address, data, init in self.data:
            addr = self._alignAddr(address)
            size = PAGE_ALIGN
            while size < len(data): size += PAGE_ALIGN
            uc.mem_map(addr, size)
            if init:
              uc.mem_write(addr, self._getOriginData(addr, size))
            else:
              uc.mem_write(address, data)

    def _initRegs(self, uc):
        for reg, value in self.regs:
            uc.reg_write(reg, value)

    def _emulate(self, startAddr, stopAddr, args=[], TimeOut=0, Count=0):
        try:
            self.logBuffer = []
            uc=self.curUC
            if not uc:
              uc = Uc(self.arch, self.mode)
              self.curUC = uc
              # add the invalid memory access hook
              uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | \
                          UC_HOOK_MEM_FETCH_UNMAPPED, self._hook_mem_invalid)
              
              # add the trace hook
              if self.traceOption & (TRACE_DATA_READ | TRACE_DATA_WRITE):
                  uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self._hook_mem_access)
              if self.traceOption & TRACE_INTR:
                  uc.hook_add(UC_HOOK_INTR, self.hook_interrupt)
              uc.hook_add(UC_HOOK_CODE, self._hook_code)
              self._initStackAndArgs(uc, stopAddr, args,True)
              self._initData(uc)
              self._initRegs(uc)
            else:
              self._initStackAndArgs(uc, stopAddr, args,False)
            # start emulate
            uc.emu_start(startAddr, stopAddr, timeout=TimeOut, count=Count)
        except UcError as e:
            print("#ERROR: %s" % e)

    # set the data before emulation
    def setData(self, address, data, init=False):
        self.data.append((address, data, init))

    def setReg(self, reg, value):
        self.regs.append((reg, value))

    def showRegs(self, *regs):
        if self.curUC == None:
            print("current uc is none.")
            return
        for reg in regs:
            print("0x%x" % self.curUC.reg_read(reg))

    def readStack(self, fmt, count):
        if self.curUC == None:
            print("current uc is none.")
            return
        stackData = []
        stackPointer = self.curUC.reg_read(self.REG_SP)
        for i in range(count):
            dataSize = calcsize(fmt)
            data = self.curUC.mem_read(stackPointer + i * dataSize, dataSize)
            st = unpack_from(fmt, data)
            stackData.append((stackPointer + i * dataSize, st[0]))
        return stackData

    def showData(self, fmt, addr, count=1):
        if self.curUC == None:
            print("current uc is none.")
            return
        if count > 1: print('[')
        for i in range(count):
            dataSize = calcsize(fmt)
            data = self.curUC.mem_read(addr + i * dataSize, dataSize)
            if count > 1: print('    ', end='')
            st = unpack_from(fmt, data)
            if count > 1: print(',')
        print(']') if count > 1 else print('')

    def setTrace(self, opt):
        if opt != TRACE_OFF:
            self.traceOption |= opt
        else:
            self.traceOption = TRACE_OFF

    def showTrace(self):
        logs = "\n".join(self.logBuffer)
        print(logs)
    def alt(self, address, func, argc, balance=False):
        """
        If call the address, will call the func instead.
        the arguments of func : func(uc, consoleouput, args)
        """
        assert (callable(func))
        self.altFunc[address] = (func, argc, balance)

    def eFunc(self, address=None, retAddr=None, args=[]):
        if address == None: address = here()
        func = get_func(address)
        if retAddr == None:
            refs = [ref.frm for ref in XrefsTo(func.start_ea, 0)]
            if len(refs) != 0:
                retAddr = refs[0] + idc.get_item_size(refs[0])
            else:
                print("Please offer the return address.")
                return
        self._emulate(func.start_ea, retAddr, args)
        res = self.curUC.reg_read(self.REG_RES)
        return res

    def eBlock(self, codeStart=None, codeEnd=None):
        if codeStart == None: codeStart = read_selection_start()
        if codeEnd == None: codeEnd = read_selection_end()
        self._emulate(codeStart, codeEnd)
        self._showRegs(self.curUC)

    def eUntilAddress(self, startAddr, stopAddr, args=[], TimeOut=0, Count=0):
        self._emulate(startAddr=startAddr, stopAddr=stopAddr, args=args, TimeOut=TimeOut, Count=Count)
        self._showRegs(self.curUC)
    def hook_interrupt(self, emu, intno, data):
        self._addTrace("Triggering interrupt #{:d}".format(intno))
        return
    def eFunc2(self, address=None, retAddr=None, args=[], TimeOut=0, Count=0):
        if address == None: address = here()
        func = get_func(address)
        if retAddr == None:
            refs = [ref.frm for ref in XrefsTo(func.start_ea, 0)]
            if len(refs) != 0:
                retAddr = refs[0] + idc.get_item_size(refs[0])
            else:
                print("Please offer the return address.")
                return
        self.logBuffer = []
        uc=self.curUC
        self._initStackAndArgs(uc, retAddr, args,False)
        uc.emu_start(func.start_ea, retAddr, timeout=TimeOut, count=Count)
    def getAndsetAll(self,arch):
        uc=self.curUC
        if uc:
          for address, data, init in self.data:
            size=len(data)
            data2=uc.mem_read(address,size)
            #self.setData(address,data2,True)
            print("%08x:%04d %s"%(address,size,data2))
          for it in self.get_register_map(arch):
            v=uc.reg_read(it[1])
            #self.setReg(it[1],v)
            print("%s:%s"%(it[0],v))
    def setInstSkip(self, address):
        self.inst_skip_list.append(address)
    def showLine(self,len=128):
        print("-"*len)
    def printRegs(self,regs):
        s='\t'*6
        idx=0
        for reg in regs:
            s=s+"r%s:0x%x "%(idx,self.curUC.reg_read(reg))
            idx=idx+1
        self._addTrace(s)
    def get_register_map(self,arch):
        if arch.startswith("arm64"):
            arch = "arm64"
        elif arch.startswith("arm"):
            arch = "arm"
        elif arch.startswith("mips"):
            arch = "mips"
        registers = {
            "x64" : [
                [ "rax",    UC_X86_REG_RAX  ],
                [ "rbx",    UC_X86_REG_RBX  ],
                [ "rcx",    UC_X86_REG_RCX  ],
                [ "rdx",    UC_X86_REG_RDX  ],
                [ "rsi",    UC_X86_REG_RSI  ],
                [ "rdi",    UC_X86_REG_RDI  ],
                [ "rbp",    UC_X86_REG_RBP  ],
                [ "rsp",    UC_X86_REG_RSP  ],
                [ "r8",     UC_X86_REG_R8   ],
                [ "r9",     UC_X86_REG_R9   ],
                [ "r10",    UC_X86_REG_R10  ],
                [ "r11",    UC_X86_REG_R11  ],
                [ "r12",    UC_X86_REG_R12  ],
                [ "r13",    UC_X86_REG_R13  ],
                [ "r14",    UC_X86_REG_R14  ],
                [ "r15",    UC_X86_REG_R15  ],
                [ "rip",    UC_X86_REG_RIP  ],
                [ "sp",     UC_X86_REG_SP   ],
            ],
            "x86" : [
                [ "eax",    UC_X86_REG_EAX  ],
                [ "ebx",    UC_X86_REG_EBX  ],
                [ "ecx",    UC_X86_REG_ECX  ],
                [ "edx",    UC_X86_REG_EDX  ],
                [ "esi",    UC_X86_REG_ESI  ],
                [ "edi",    UC_X86_REG_EDI  ],
                [ "ebp",    UC_X86_REG_EBP  ],
                [ "esp",    UC_X86_REG_ESP  ],
                [ "eip",    UC_X86_REG_EIP  ],
                [ "sp",     UC_X86_REG_SP   ],
            ],        
            "arm" : [
                [ "R0",     UC_ARM_REG_R0  ],
                [ "R1",     UC_ARM_REG_R1  ],
                [ "R2",     UC_ARM_REG_R2  ],
                [ "R3",     UC_ARM_REG_R3  ],
                [ "R4",     UC_ARM_REG_R4  ],
                [ "R5",     UC_ARM_REG_R5  ],
                [ "R6",     UC_ARM_REG_R6  ],
                [ "R7",     UC_ARM_REG_R7  ],
                [ "R8",     UC_ARM_REG_R8  ],
                [ "R9",     UC_ARM_REG_R9  ],
                [ "R10",    UC_ARM_REG_R10 ],
                [ "R11",    UC_ARM_REG_R11 ],
                [ "R12",    UC_ARM_REG_R12 ],
                [ "PC",     UC_ARM_REG_PC  ],
                [ "SP",     UC_ARM_REG_SP  ],
                [ "LR",     UC_ARM_REG_LR  ],
                [ "CPSR",   UC_ARM_REG_CPSR ]
            ],
            "arm64" : [
                [ "X0",     UC_ARM64_REG_X0  ],
                [ "X1",     UC_ARM64_REG_X1  ],
                [ "X2",     UC_ARM64_REG_X2  ],
                [ "X3",     UC_ARM64_REG_X3  ],
                [ "X4",     UC_ARM64_REG_X4  ],
                [ "X5",     UC_ARM64_REG_X5  ],
                [ "X6",     UC_ARM64_REG_X6  ],
                [ "X7",     UC_ARM64_REG_X7  ],
                [ "X8",     UC_ARM64_REG_X8  ],
                [ "X9",     UC_ARM64_REG_X9  ],
                [ "X10",    UC_ARM64_REG_X10 ],
                [ "X11",    UC_ARM64_REG_X11 ],
                [ "X12",    UC_ARM64_REG_X12 ],
                [ "X13",    UC_ARM64_REG_X13 ],
                [ "X14",    UC_ARM64_REG_X14 ],
                [ "X15",    UC_ARM64_REG_X15 ],
                [ "X16",    UC_ARM64_REG_X16 ],
                [ "X17",    UC_ARM64_REG_X17 ],
                [ "X18",    UC_ARM64_REG_X18 ],
                [ "X19",    UC_ARM64_REG_X19 ],
                [ "X20",    UC_ARM64_REG_X20 ],
                [ "X21",    UC_ARM64_REG_X21 ],
                [ "X22",    UC_ARM64_REG_X22 ],
                [ "X23",    UC_ARM64_REG_X23 ],
                [ "X24",    UC_ARM64_REG_X24 ],
                [ "X25",    UC_ARM64_REG_X25 ],
                [ "X26",    UC_ARM64_REG_X26 ],
                [ "X27",    UC_ARM64_REG_X27 ],
                [ "X28",    UC_ARM64_REG_X28 ],
                [ "PC",     UC_ARM64_REG_PC  ],
                [ "SP",     UC_ARM64_REG_SP  ],
                [ "FP",     UC_ARM64_REG_FP  ],
                [ "LR",     UC_ARM64_REG_LR  ],
                [ "NZCV",   UC_ARM64_REG_NZCV ]
            ],
            "mips" : [
                [ "zero",   UC_MIPS_REG_0   ],
                [ "at",     UC_MIPS_REG_1   ],
                [ "v0",     UC_MIPS_REG_2   ],
                [ "v1",     UC_MIPS_REG_3   ],
                [ "a0",     UC_MIPS_REG_4   ],
                [ "a1",     UC_MIPS_REG_5   ],
                [ "a2",     UC_MIPS_REG_6   ],
                [ "a3",     UC_MIPS_REG_7   ],
                [ "t0",     UC_MIPS_REG_8   ],
                [ "t1",     UC_MIPS_REG_9   ],
                [ "t2",     UC_MIPS_REG_10  ],
                [ "t3",     UC_MIPS_REG_11  ],
                [ "t4",     UC_MIPS_REG_12  ],
                [ "t5",     UC_MIPS_REG_13  ],
                [ "t6",     UC_MIPS_REG_14  ],
                [ "t7",     UC_MIPS_REG_15  ],
                [ "s0",     UC_MIPS_REG_16  ],
                [ "s1",     UC_MIPS_REG_17  ],
                [ "s2",     UC_MIPS_REG_18  ],
                [ "s3",     UC_MIPS_REG_19  ],
                [ "s4",     UC_MIPS_REG_20  ],
                [ "s5",     UC_MIPS_REG_21  ],
                [ "s6",     UC_MIPS_REG_22  ],
                [ "s7",     UC_MIPS_REG_23  ],
                [ "t8",     UC_MIPS_REG_24  ],
                [ "t9",     UC_MIPS_REG_25  ],
                [ "k0",     UC_MIPS_REG_26  ],
                [ "k1",     UC_MIPS_REG_27  ],
                [ "gp",     UC_MIPS_REG_28  ],
                [ "sp",     UC_MIPS_REG_29  ],
                [ "fp",     UC_MIPS_REG_30  ],
                [ "ra",     UC_MIPS_REG_31  ],
                [ "pc",     UC_MIPS_REG_PC  ],
            ]
        }
        return registers[arch]