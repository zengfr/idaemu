# idaemu
idaemu is an IDA Pro Plugin - use for emulating code in IDA Pro.update for ida pro 7.7
### about Plugin 
- fork from : https://github.com/36hours/idaemu
- sync to   : https://gitee.com/zengfr/idaemu
- update for ida pro 7.7
- optimization improvements and fix
### contact group
- qq group: 1群 143824179 (IDA汇编逆向分析)
- qq group: 2群 26318788 (romhacking)
### ida pro plugin for recommends
- XrefsExt https://github.com/zengfr/XrefsExt
- idaemu https://github.com/zengfr/idaemu
- ida_all_xrefs_from_viewer https://github.com/zengfr/ida_all_xrefs_from_viewer-plugin-for-ida-pro
- ida_all_xrefs_to_viewer https://github.com/zengfr/ida_all_xrefs_to_viewer-plugin-for-ida-pro
- winhex_diff_viewer-plugin https://github.com/zengfr/winhex_diff_viewer-plugin-for-ida-pro
- HexRaysCodeXplorer for ida pro 7.7 https://github.com/zengfr/HexRaysCodeXplorer_plugin_for_ida_pro

### ida pro idb database files
- site: https://github.com/zengfr/ida-pro-idb-database
### code Test Example 1 
~~~python
from idaemu import *
from unicorn import *
from unicorn.x86_const import *
from unicorn.arm_const import *
from unicorn.arm64_const import *

def myprint(uc, out, args):
    out.append("hook args: %s" % args)
    return args[0]
aa=[n for n in range(0, 128)]
print(aa)

e = Emu(UC_ARCH_ARM64, UC_MODE_ARM)
e.setTrace(TRACE_CODE|TRACE_DATA_READ|TRACE_DATA_WRITE)
#e.setTrace(TRACE_INTR)
e.setInstSkip(0x01234)
buf_md5_addr = 0x00bfba8
hex2str_addr=0x00b6334

str='40397\/A2PA31473'
str_addr=0x8120000

res_addr=0x8120000+0x1000

fmt="%02hhx"
fmt_addr=0x8120000+0x2000

e.setData(str_addr,str,True)
e.setData(res_addr,aa,True)
e.setData(fmt_addr,fmt,True)

printf_addr = 0x38e6d0 
e.alt(printf_addr, myprint, 4, False)

e.eFunc(buf_md5_addr, None, [str_addr, 16,res_addr])
e.showTrace()
e.showLine()
#e.getAndsetAll('arm64')
e.eFunc(hex2str_addr, None, [res_addr, 16,fmt_addr])
#n_hex2str((__int64)v21, 16LL, "%02hhx");
e.showTrace()
e.showLine()
~~~
### screenshot
![ idaemu plugin Screenshot 1](https://raw.githubusercontent.com/zengfr/idaemu/main/screenshot/idemu_tracelog.JPG)
![ idaemu plugin Screenshot 2](https://raw.githubusercontent.com/zengfr/idaemu/main/screenshot/idemu_tracelog2.JPG)
