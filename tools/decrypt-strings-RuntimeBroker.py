# 只解密字符串，不执行任何恶意逻辑：单函数沙箱，无网络/无文件/无 API
import pefile, capstone, struct, collections
from unicorn import *
from unicorn.x86_const import *

import sys as _sys, os as _os
# Path to the sample: pass as argv[1], set RB_SAMPLE, or place the file
# beside this script as RuntimeBroker.exe.sample
PATH = (_sys.argv[1] if len(_sys.argv) > 1
     else _os.environ.get("RB_SAMPLE")
     or _os.path.join(_os.path.dirname(_os.path.abspath(__file__)),
                      "RuntimeBroker.exe.sample"))
pe = pefile.PE(PATH); IB = pe.OPTIONAL_HEADER.ImageBase
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

IMGSZ = 0xA0000
STACK  = 0x200000000
TEB    = 0x300000000
TLSARR = 0x300010000
TLSBLK = 0x300020000
OUTBUF = 0x310000000
RETMAGIC = 0x1F0000000

txt = [s for s in pe.sections if s.Name.rstrip(b'\0') == b'.text'][0]
base = IB + txt.VirtualAddress; tdata = txt.get_data()
RD_LO, RD_HI = 0x14002d000, 0x14002d000 + 0x3c8a
DA_LO, DA_HI = 0x140031000, 0x140031000 + 0x18e50

pairs = []; last = None
for i in md.disasm(tdata, base):
    if i.mnemonic == 'lea' and 'rip' in i.op_str and i.op_str.split(',')[0] in ('rcx','rdx'):
        try:
            off = int(i.op_str.split('rip + ')[1].split(']')[0], 16)
            p = i.address + i.size + off
            last = (i.address, p, i.op_str.split(',')[0]) if (RD_LO<=p<RD_HI or DA_LO<=p<DA_HI) else None
        except Exception: last = None
    elif i.mnemonic == 'call' and last and i.address - last[0] < 40:
        try: pairs.append((last[0], last[1], last[2], int(i.op_str, 16)))
        except Exception: pass
        last = None

def fresh():
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(IB, IMGSZ)
    uc.mem_write(IB, pe.header)
    for s in pe.sections:
        dd = s.get_data()
        if dd: uc.mem_write(IB + s.VirtualAddress, dd)
    uc.mem_map(STACK - 0x100000, 0x200000)
    uc.mem_map(TEB, 0x1000); uc.mem_map(TLSARR, 0x1000); uc.mem_map(TLSBLK, 0x10000)
    uc.mem_map(OUTBUF, 0x10000)
    uc.mem_write(TEB + 0x58, struct.pack('<Q', TLSARR))
    for k in range(64): uc.mem_write(TLSARR + k*8, struct.pack('<Q', TLSBLK))
    uc.reg_write(UC_X86_REG_GS_BASE, TEB)
    return uc

def readstr(uc, a, n=200):
    try: b = bytes(uc.mem_read(a, n))
    except Exception: return None, None
    ansi = b.split(b'\0')[0]
    try: wide = b.decode('utf-16-le','ignore').split('\0')[0]
    except Exception: wide = ''
    a1 = ansi.decode('latin1') if ansi and all(32<=x<127 for x in ansi) else None
    w1 = wide if wide and len(wide)>=3 and all(32<=ord(c)<127 for c in wide) else None
    return a1, w1

seen = collections.OrderedDict(); fails = 0
for site, sp, reg, fn in pairs:
    uc = fresh()
    try:
        uc.mem_write(STACK, struct.pack('<Q', RETMAGIC))
        uc.reg_write(UC_X86_REG_RSP, STACK)
        uc.reg_write(UC_X86_REG_RCX, sp if reg=='rcx' else OUTBUF)
        uc.reg_write(UC_X86_REG_RDX, OUTBUF if reg=='rcx' else sp)
        uc.reg_write(UC_X86_REG_R8, 0x200); uc.reg_write(UC_X86_REG_R9, 0)
        uc.emu_start(fn, RETMAGIC, timeout=5_000_000, count=300000)
    except Exception:
        fails += 1
    for probe in (sp, OUTBUF):
        a1, w1 = readstr(uc, probe)
        for v in (a1, w1):
            if v and len(v) >= 4 and v not in seen:
                seen[v] = (site, sp, fn)
    uc = None

print("解密站点 %d 个，失败 %d 个，得到 %d 条不重复明文" % (len(pairs), fails, len(seen)))
print("=" * 74)
for v, (site, sp, fn) in seen.items():
    print("  [0x%x] %r" % (sp, v))
