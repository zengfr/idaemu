from idaemu import *
from unicorn import *
from unicorn.x86_const import *
from unicorn.arm_const import *
from unicorn.arm64_const import *

def myprint(uc, out, args):
    out.append("hook args: %s" % args)
    return args[0]

buf_md5_addr = 0x00bfba8
hex2str_addr=0x00b6334


aa=[n for n in range(0, 128)]
print(aa)
e = Emu(UC_ARCH_ARM64, UC_MODE_ARM)
str='40397\/A2PA31473'
str_addr=0x8120000

res_addr=0x8120000+0x1000

fmt="%02hhx"
fmt_addr=0x8120000+0x2000
e.setTrace(TRACE_CODE|TRACE_DATA_READ|TRACE_DATA_WRITE)
e.setData(str_addr,str,True)
e.setData(res_addr,aa,True)
e.setData(fmt_addr,fmt,True)

printf_addr = 0x38e6d0 
e.alt(printf_addr, myprint, 4, False)
e.eFunc(buf_md5_addr, None, [str_addr, 16,res_addr])
print('-'*222)
e.showTrace()

e.getAndsetAll('arm64')
e.eFunc(hex2str_addr, None, [res_addr, 16,fmt_addr])
#n_hex2str((__int64)v21, 16LL, "%02hhx");
print('-'*222)
print("---- below is the trace ----")
e.showTrace()