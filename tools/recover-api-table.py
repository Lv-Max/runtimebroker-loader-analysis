# 还原动态 API 表：只调用"名字解密"小函数，不执行任何主体逻辑
import pefile, capstone, struct, collections
from unicorn import *
from unicorn.x86_const import *
import sys as _sys, os as _os
# Path to the sample: pass as argv[1], set RB_SAMPLE, or place the file
# beside this script as RuntimeBroker.exe.sample
P = (_sys.argv[1] if len(_sys.argv) > 1
     else _os.environ.get("RB_SAMPLE")
     or _os.path.join(_os.path.dirname(_os.path.abspath(__file__)),
                      "RuntimeBroker.exe.sample"))
pe=pefile.PE(P); IB=pe.OPTIONAL_HEADER.ImageBase
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
txt=[s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text'][0]
TL=IB+txt.VirtualAddress; TH=TL+txt.Misc_VirtualSize; tdata=txt.get_data()
DA=(0x140031000,0x140049e50)
insns=list(md.disasm(tdata,TL))
idx={i.address:k for k,i in enumerate(insns)}

# 找：mov [rip+slot], rax   前面最近的  call 0x<thunk>
pairs=[]
for k,i in enumerate(insns):
    if i.mnemonic!='mov' or 'rip' not in i.op_str or not i.op_str.endswith(', rax'): continue
    try:
        off=int(i.op_str.split('rip + ')[1].split(']')[0],16); slot=i.address+i.size+off
    except Exception: continue
    if not (DA[0]<=slot<DA[1]): continue
    thunk=None
    for j in range(k-1,max(0,k-12),-1):
        p=insns[j]
        if p.mnemonic=='call' and p.op_str.startswith('0x'):
            try:
                t=int(p.op_str,16)
                if TL<=t<TH: thunk=t; break
            except Exception: pass
    if thunk: pairs.append((slot,thunk,i.address))
print("待解析槽位 %d 个" % len(pairs))

IMGSZ=0xA0000; STACK=0x200000000; TEB=0x300000000
TLSARR=0x300010000; TLSBLK=0x300020000; OUT=0x310000000; RET=0x1F0000000
def fresh():
    uc=Uc(UC_ARCH_X86,UC_MODE_64); uc.mem_map(IB,IMGSZ); uc.mem_write(IB,pe.header)
    for s in pe.sections:
        dd=s.get_data()
        if dd: uc.mem_write(IB+s.VirtualAddress,dd)
    uc.mem_map(STACK-0x100000,0x200000); uc.mem_map(TEB,0x1000)
    uc.mem_map(TLSARR,0x1000); uc.mem_map(TLSBLK,0x10000); uc.mem_map(OUT,0x10000)
    uc.mem_write(TEB+0x58,struct.pack('<Q',TLSARR))
    for k in range(64): uc.mem_write(TLSARR+k*8,struct.pack('<Q',TLSBLK))
    uc.reg_write(UC_X86_REG_GS_BASE,TEB); return uc
def run(thunk):
    uc=fresh()
    try:
        uc.mem_write(STACK,struct.pack('<Q',RET)); uc.reg_write(UC_X86_REG_RSP,STACK)
        uc.reg_write(UC_X86_REG_RCX,OUT); uc.reg_write(UC_X86_REG_RDX,OUT+0x800)
        uc.reg_write(UC_X86_REG_R8,0x200)
        uc.emu_start(thunk,RET,timeout=5_000_000,count=400000)
        rax=uc.reg_read(UC_X86_REG_RAX)
    except Exception: return None
    for probe in (rax,OUT):
        try: b=bytes(uc.mem_read(probe,120))
        except Exception: continue
        a=b.split(b'\0')[0]
        if 3<len(a)<80 and all(32<=x<127 for x in a): return a.decode()
    return None
res={}
for slot,thunk,site in pairs:
    res[slot]=(run(thunk),thunk,site)
print()
print("="*70); print("动态 API 表（.data 槽位 -> API 名）"); print("="*70)
for s in sorted(res):
    n,t,site=res[s]
    print("  0x%-11x  %-30s  (thunk 0x%x)" % (s, n or "<解不出>", t))
ok=sum(1 for s in res if res[s][0])
print()
print("成功 %d / %d" % (ok,len(res)))
