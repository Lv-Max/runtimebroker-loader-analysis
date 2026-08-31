# 第二轮：加入 TLS 块探测（thunk 把明文写进 TLS 槽，而非原地解密）
import pefile, capstone, struct, collections, re
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
TL=IB+txt.VirtualAddress; tdata=txt.get_data()
RD=(0x14002d000,0x14002d000+0x3c8a); DA=(0x140031000,0x140031000+0x18e50)
pairs=[]; last=None
for i in md.disasm(tdata,TL):
    if i.mnemonic=='lea' and 'rip' in i.op_str and i.op_str.split(',')[0] in ('rcx','rdx'):
        try:
            off=int(i.op_str.split('rip + ')[1].split(']')[0],16); p=i.address+i.size+off
            last=(i.address,p,i.op_str.split(',')[0]) if (RD[0]<=p<RD[1] or DA[0]<=p<DA[1]) else None
        except Exception: last=None
    elif i.mnemonic=='call' and last and i.address-last[0]<40:
        try: pairs.append((last[1],last[2],int(i.op_str,16)))
        except Exception: pass
        last=None
# 补上诊断里发现的、以 TLS 为目标的 thunk 起点（直接按函数入口跑）
starts=set()
for i in md.disasm(tdata,TL):
    if i.mnemonic=='call' and i.op_str.startswith('0x'):
        try: starts.add(int(i.op_str,16))
        except Exception: pass
IMGSZ=0xA0000; STACK=0x200000000; TEB=0x300000000
TLSARR=0x300010000; TLSBLK=0x300020000; OUT=0x310000000; RET=0x1F0000000
def fresh():
    uc=Uc(UC_ARCH_X86,UC_MODE_64); uc.mem_map(IB,IMGSZ); uc.mem_write(IB,pe.header)
    for s in pe.sections:
        dd=s.get_data()
        if dd: uc.mem_write(IB+s.VirtualAddress,dd)
    uc.mem_map(STACK-0x100000,0x200000); uc.mem_map(TEB,0x1000)
    uc.mem_map(TLSARR,0x1000); uc.mem_map(TLSBLK,0x20000); uc.mem_map(OUT,0x10000)
    uc.mem_write(TEB+0x58,struct.pack('<Q',TLSARR))
    for k in range(64): uc.mem_write(TLSARR+k*8,struct.pack('<Q',TLSBLK))
    uc.reg_write(UC_X86_REG_GS_BASE,TEB); return uc
found=collections.OrderedDict()
def harvest(uc,tag):
    for base,size in ((TLSBLK,0x20000),(OUT,0x2000)):
        try: b=bytes(uc.mem_read(base,size))
        except Exception: continue
        # 允许 CR/LF/TAB，并且不要求紧接 NUL。
        #
        # 原先是 rb"[\x20-\x7e]{4,120}\x00" —— 两个缺陷叠加：
        #   1) 字符类不含 CR(0x0D)/LF(0x0A)，含 CRLF 的串会被切成碎片
        #   2) 尾部 \x00 锚点又要求可打印段紧挨着 NUL
        # 结果是这个二进制里所有 HTTP 形状的字符串对收集器完全不可见。
        # WebSocket 握手模板（152 字节，含 6 处 CRLF）就是这样被静默丢弃的：
        # 常量 A 只漏出 "Host: "，常量 B 一条都不剩。串一直被正确解密着，
        # 是收集器在丢数据。2026-08-31 修复。
        for m in re.finditer(rb"[\x20-\x7e\r\n\t]{4,400}", b):
            raw=m.group()
            if len(raw.strip())<4: continue
            try: v=raw.decode()
            except UnicodeDecodeError: continue
            if v not in found: found[v]=tag
        try: u=b.decode('utf-16-le','ignore')
        except Exception: u=''
        for m in re.finditer(r"[\x20-\x7e]{4,120}", u):
            v=m.group()
            if v not in found: found[v]="%s [W]"%tag
cand=[(sp,reg,fn) for sp,reg,fn in pairs]
for a in sorted(starts):
    if 0x140001000<=a<0x14002c236: cand.append((None,'rcx',a))
seen=set(); n=0
for sp,reg,fn in cand:
    key=(sp,fn)
    if key in seen: continue
    seen.add(key); n+=1
    uc=fresh()
    try:
        uc.mem_write(STACK,struct.pack('<Q',RET)); uc.reg_write(UC_X86_REG_RSP,STACK)
        uc.reg_write(UC_X86_REG_RCX, sp if (sp and reg=='rcx') else OUT)
        uc.reg_write(UC_X86_REG_RDX, OUT+0x800 if (sp and reg=='rcx') else (sp or OUT))
        uc.reg_write(UC_X86_REG_R8,0x200); uc.reg_write(UC_X86_REG_R9,0)
        uc.emu_start(fn,RET,timeout=4_000_000,count=200000)
    except Exception: pass
    harvest(uc,"0x%x"%fn)
print("跑了 %d 个入口，收获 %d 条不重复明文" % (n,len(found)))
print("="*72)
for v,t in found.items(): print("  [%s] %r" % (t,v))
