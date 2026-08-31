# -*- coding: utf-8 -*-
"""静态模拟脱壳 —— 纯 CPU 模拟，无操作系统，无 I/O 通路"""
import sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import pefile, struct, collections
from unicorn import *
from unicorn.x86_const import *

import sys as _sys, os as _os
# Path to the sample: pass as argv[1], set RB_SAMPLE, or place the file
# beside this script as RuntimeBroker.exe.sample
P = (_sys.argv[1] if len(_sys.argv) > 1
     else _os.environ.get("RB_SAMPLE")
     or _os.path.join(_os.path.dirname(_os.path.abspath(__file__)),
                      "RuntimeBroker.exe.sample"))
pe = pefile.PE(P)
IB = pe.OPTIONAL_HEADER.ImageBase
EP = IB + pe.OPTIONAL_HEADER.AddressOfEntryPoint
PAGE = 0x1000
def align(x, a=PAGE): return (x + a - 1) & ~(a - 1)

uc = Uc(UC_ARCH_X86, UC_MODE_64)

# ---- 映射镜像 ----
img_size = align(pe.OPTIONAL_HEADER.SizeOfImage)
uc.mem_map(IB, img_size)
uc.mem_write(IB, pe.header)
for s in pe.sections:
    d = s.get_data()
    if d: uc.mem_write(IB + s.VirtualAddress, d)
print("镜像映射 0x%x  大小 0x%x" % (IB, img_size))

# ---- 栈 ----
STACK = 0x200000000; STACK_SZ = 0x100000
uc.mem_map(STACK, STACK_SZ)
uc.reg_write(UC_X86_REG_RSP, STACK + STACK_SZ - 0x2000)
uc.reg_write(UC_X86_REG_RBP, STACK + STACK_SZ - 0x2000)
SENTINEL = 0x1F0000000
uc.mem_map(SENTINEL & ~0xFFF, 0x1000)
rsp0 = uc.reg_read(UC_X86_REG_RSP)
uc.mem_write(rsp0, struct.pack('<Q', SENTINEL))

# ---- 伪造 TEB/PEB（很多壳会读 PEB 做反调试）----
TEB = 0x300000000
uc.mem_map(TEB, 0x20000)
PEB = TEB + 0x2000
uc.mem_write(TEB + 0x60, struct.pack('<Q', PEB))     # TEB->ProcessEnvironmentBlock
uc.mem_write(PEB + 0x02, b'\x00')                    # BeingDebugged = 0
uc.mem_write(PEB + 0x10, struct.pack('<Q', IB))      # PEB->ImageBaseAddress
uc.mem_write(TEB + 0x08, struct.pack('<Q', STACK + STACK_SZ))   # StackBase
uc.mem_write(TEB + 0x10, struct.pack('<Q', STACK))              # StackLimit
uc.mem_write(TEB + 0x30, struct.pack('<Q', TEB))                # Self
uc.mem_write(TEB + 0x40, struct.pack('<I', 0x1234))             # ClientId.Process
uc.mem_write(TEB + 0x48, struct.pack('<I', 0x5678))             # ClientId.Thread
# TLS：分配数组 + 每个槽指向一块内存
TLSARR = TEB + 0x4000
TLSDAT = TEB + 0x6000
for k in range(256):
    uc.mem_write(TLSARR + k*8, struct.pack('<Q', TLSDAT + k*0x40))
uc.mem_write(TEB + 0x58, struct.pack('<Q', TLSARR))             # ThreadLocalStoragePointer
uc.mem_write(TEB + 0x1480, struct.pack('<Q', TLSARR))           # TlsExpansionSlots 附近
uc.reg_write(UC_X86_REG_GS_BASE, TEB)

# ---- 伪造 API 区：每个导入函数一个地址 ----
API = 0x7FF000000000
uc.mem_map(API, 0x100000)
api_map = {}
try:
    pe.parse_data_directories()
    for e in pe.DIRECTORY_ENTRY_IMPORT:
        dll = e.dll.decode()
        for imp in e.imports:
            if not imp.name: continue
            addr = API + len(api_map) * 0x10
            api_map[addr] = "%s!%s" % (dll, imp.name.decode())
            uc.mem_write(imp.address, struct.pack('<Q', addr))   # 改写 IAT
except Exception as ex:
    print("IAT 处理:", ex)
print("伪造 API 桩 %d 个" % len(api_map))
for a in sorted(api_map)[:6]:
    print("   0x%x -> %s" % (a, api_map[a]))


# ---- 伪造 COM 对象（IDirect3D9 等）----
COM_OBJ  = API + 0x80000      # 对象地址
COM_VTBL = API + 0x81000      # vtable
COM_METH = API + 0x82000      # 方法桩起始，每个 0x10
uc.mem_write(COM_OBJ, struct.pack('<Q', COM_VTBL))
for k in range(64):
    m = COM_METH + k * 0x10
    uc.mem_write(COM_VTBL + k*8, struct.pack('<Q', m))
    api_map[m] = 'COM!method_%d' % k

# ---- 堆（给 VirtualAlloc 用）----
HEAP = 0x400000000; HEAP_SZ = 0x2000000
uc.mem_map(HEAP, HEAP_SZ)

# ---- 修补运行时未初始化的字符串指针数组 ----
# 0x1400311A0 处是 8 个模式串指针，运行时才填充；模拟里为 0 导致
# 子串搜索把"空模式"当成命中，从而误判为虚拟机。填入不会匹配的占位串。
DUMMY = API + 0x90000
uc.mem_write(DUMMY, b'__NOMATCH_PLACEHOLDER__' + bytes([0]))
for _i in range(16):
    uc.mem_write(0x1400311A0 + _i*8, struct.pack('<Q', DUMMY))
print("已修补 0x1400311A0 处的 16 个字符串指针")

state = {'heap': HEAP, 'calls': collections.Counter(), 'log': [], 'count': 0, 'api_args': [], 'vm_checks': [], 'cpuid': [], 'files': [], 'com': [], 'lazy': [], 'ring': [], 'cov': {}, 'threads': [], 'com_monikers': [], 'shellexec': [], 'clsids': []}



VM_MODULES = [
 'vbox','vmware','vmhgfs','vmci','vmmemctl','vmmouse','vmrawdsk','vmusbmouse','vmx_svga',
 'vmxnet','vmtools','vmguestlib','vm3dgl','vmwareuser','vmwaretray','vmwareservice',
 'sbiedll','api_log','dir_watch','pstorec','vmcheck','wpespy','cmdvrt','snxhk','sxin',
 'qemu','balloon','netkvm','vioserial','virtio','xen','prl_','parallels','sandboxie',
 'dbghelp','avghook','deviceapi','aswhook','sf2.dll','cuckoo',
]
def is_vm_mod(nm):
    l = (nm or '').lower()
    if any(k in l for k in VM_MODULES): return True
    # 任何 vbox*/vm*/prl*/xen*/qemu*/vio* 的驱动或库一律当作不存在
    if l.startswith(('vbox','vm','prl','xen','qemu','virtio','vio','vpc','hgfs'))        and l.endswith(('.sys','.dll','.exe')):
        return True
    return False

def rd_str(uc, addr, wide=False, n=260):
    if not addr: return "<NULL>"
    try:
        b = uc.mem_read(addr, n*(2 if wide else 1))
    except Exception:
        return "<不可读 0x%x>" % addr
    if wide:
        out = bytearray()
        for k in range(0, len(b), 2):
            if b[k] == 0 and b[k+1] == 0: break
            out.append(b[k])
        return out.decode('latin1', 'ignore')
    e = b.find(bytes([0]))
    return b[:e if e >= 0 else n].decode('latin1', 'ignore')

def hook_code(uc, addr, size, ud):
    state['count'] += 1
    state['ring'].append(addr)
    if len(state['ring']) > 260: state['ring'].pop(0)
    if addr == SENTINEL:
        state['log'].append((state['count'], ">>> 返回到哨兵：入口函数已结束"))
        uc.emu_stop(); return
    r = addr >> 12
    state['cov'][r] = state['cov'].get(r, 0) + 1
    if API <= addr < API + 0x100000:
        name = api_map.get(addr & ~0xF, "API@0x%x" % addr)
        state['calls'][name] += 1
        rcx = uc.reg_read(UC_X86_REG_RCX); rdx = uc.reg_read(UC_X86_REG_RDX)
        detail = ""
        W = name.endswith('W')
        if any(k in name for k in ('LoadLibrary','GetModuleHandle','CreateFile','DeleteFile',
                                   'CreateDirectory','GetFileAttributes','CreateMutex',
                                   'SetFileAttributes','CopyFile','lstrlen','lstrcpy','lstrcat')):
            detail = " arg1=" + repr(rd_str(uc, rcx, W))
        if 'CreateProcess' in name:
            detail = " app=%r cmd=%r" % (rd_str(uc, rcx, W), rd_str(uc, rdx, W))
        if 'GetProcAddress' in name:
            detail = " proc=" + repr(rd_str(uc, rdx, False))
        if 'CopyFile' in name:
            detail += " -> " + repr(rd_str(uc, rdx, W))
        if detail: state['api_args'].append((state['count'], name, detail))
        if len(state['log']) < 600: state['log'].append((state['count'], name + detail))
        if name.endswith('ExitProcess'):
            state['log'].append((state['count'], ">>> ExitProcess 被调用，停止模拟"))
            uc.emu_stop(); return
        # 简单返回：RAX=1，然后 ret
        rsp = uc.reg_read(UC_X86_REG_RSP)
        ret = struct.unpack('<Q', uc.mem_read(rsp, 8))[0]
        if name.endswith('VirtualAlloc'):
            sz = uc.reg_read(UC_X86_REG_R8)
            p = state['heap']; state['heap'] += align(max(sz, PAGE), PAGE)
            uc.reg_write(UC_X86_REG_RAX, p)
        elif name.endswith(('LoadLibraryA','LoadLibraryW','GetModuleHandleA','GetModuleHandleW')):
            mn = rd_str(uc, rcx, W)
            if is_vm_mod(mn):
                state['vm_checks'].append((state['count'], name, mn))
                uc.reg_write(UC_X86_REG_RAX, 0)          # 不存在 -> 不是虚拟机
            else:
                uc.reg_write(UC_X86_REG_RAX, 0x180000000)
        elif name.endswith('GetProcAddress'):
            pname = rd_str(uc, rdx, False)
            a = state.get('dyn', {}).get(pname)
            if a is None:
                a = API + (0x8000 + len(state.setdefault('dyn', {}))) * 0x10
                state['dyn'][pname] = a
                api_map[a] = 'DYN!' + pname
            uc.reg_write(UC_X86_REG_RAX, a)
        elif name.startswith('COM!'):
            idx = int(name.split('_')[1])
            state['com'].append((state['count'], idx))
            # IDirect3D9::GetAdapterIdentifier 是第 5 号方法
            if idx == 9:      # ICMLuaUtil::ShellExec(pszFile, pszParameters, pszDirectory, fMask, nShow)
                r8v = uc.reg_read(UC_X86_REG_R8); r9v = uc.reg_read(UC_X86_REG_R9)
                state['shellexec'].append((state['count'],
                    rd_str(uc, rdx, True), rd_str(uc, r8v, True), rd_str(uc, r9v, True)))
            if idx == 5:
                pid = uc.reg_read(UC_X86_REG_R9)
                if pid:
                    uc.mem_write(pid, bytes(1100))
                    uc.mem_write(pid, b'nvd3dumx.dll,nvwgf2umx.dll' + bytes([0]))
                    uc.mem_write(pid + 512, b'NVIDIA GeForce RTX 4070' + bytes([0]))
                    uc.mem_write(pid + 1024, bytes([92,92,46,92,68,73,83,80,76,65,89,49,0]))
                    uc.mem_write(pid + 1056, struct.pack('<Q', 0x0020001E00230A00))  # DriverVersion
                    uc.mem_write(pid + 1064, struct.pack('<I', 0x10DE))              # VendorId NVIDIA
                    uc.mem_write(pid + 1068, struct.pack('<I', 0x2786))              # DeviceId
                    uc.mem_write(pid + 1072, struct.pack('<I', 0x40BF1043))          # SubSysId
                    uc.mem_write(pid + 1076, struct.pack('<I', 0xA1))                # Revision
                    uc.mem_write(pid + 1096, struct.pack('<I', 1))                   # WHQLLevel
            uc.reg_write(UC_X86_REG_RAX, 0)      # S_OK
        elif 'Direct3DCreate' in name:
            uc.reg_write(UC_X86_REG_RAX, COM_OBJ)
        elif 'CheckTokenMembership' in name:
            r8v = uc.reg_read(UC_X86_REG_R8)
            if r8v: uc.mem_write(r8v, struct.pack('<I', 1))   # IsMember = TRUE -> 已是管理员
            uc.reg_write(UC_X86_REG_RAX, 1)
        elif 'GetTokenInformation' in name:
            r8v = uc.reg_read(UC_X86_REG_R8)
            if r8v:
                try: uc.mem_write(r8v, struct.pack('<I', 2))   # TokenElevationType = Full
                except Exception: pass
            uc.reg_write(UC_X86_REG_RAX, 1)
        elif 'GetUserName' in name:
            if rcx: uc.mem_write(rcx, 'Lv'.encode('utf-16-le') + bytes([0,0]))
            if rdx: uc.mem_write(rdx, struct.pack('<I', 3))
            uc.reg_write(UC_X86_REG_RAX, 1)
        elif 'ConvertSidToStringSid' in name:
            sidstr = 'S-1-5-21-2316409263-245055156-2441819879-1001'
            buf = state['heap']; state['heap'] += 0x1000
            uc.mem_write(buf, sidstr.encode('utf-16-le') + bytes([0,0]))
            if rdx: uc.mem_write(rdx, struct.pack('<Q', buf))
            uc.reg_write(UC_X86_REG_RAX, 1)
        elif 'CoCreateInstance' in name:
            def _guid(a):
                try:
                    b = bytes(uc.mem_read(a, 16))
                    return "{%08X-%04X-%04X-%s-%s}" % (
                        struct.unpack('<I', b[0:4])[0], struct.unpack('<H', b[4:6])[0],
                        struct.unpack('<H', b[6:8])[0], b[8:10].hex().upper(), b[10:16].hex().upper())
                except Exception: return "<?>"
            r9v = uc.reg_read(UC_X86_REG_R9)
            state['clsids'].append((state['count'], _guid(rcx), _guid(r9v)))
            rsp_ = uc.reg_read(UC_X86_REG_RSP)
            try:
                ppv = struct.unpack('<Q', uc.mem_read(rsp_ + 0x28, 8))[0]
                if ppv: uc.mem_write(ppv, struct.pack('<Q', COM_OBJ))
            except Exception: pass
            uc.reg_write(UC_X86_REG_RAX, 0)
        elif 'CoGetObject' in name or 'BindMoniker' in name:
            mk = rd_str(uc, rcx, True)
            state['com_monikers'].append((state['count'], name, mk))
            r9v = uc.reg_read(UC_X86_REG_R9)
            if r9v:
                try: uc.mem_write(r9v, struct.pack('<Q', COM_OBJ))
                except Exception: pass
            uc.reg_write(UC_X86_REG_RAX, 0)          # S_OK
        elif 'CoInitialize' in name:
            uc.reg_write(UC_X86_REG_RAX, 0)
        elif name.endswith('CreateThread'):
            ent = uc.reg_read(UC_X86_REG_R8); par = uc.reg_read(UC_X86_REG_R9)
            state['threads'].append((state['count'], ent, par))
            state['hnd'] = state.get('hnd', 0x100) + 4
            uc.reg_write(UC_X86_REG_RAX, state['hnd'])
        elif 'NtCreateThreadEx' in name:
            r9 = uc.reg_read(UC_X86_REG_R9)
            rsp_ = uc.reg_read(UC_X86_REG_RSP)
            try:
                ent = struct.unpack('<Q', uc.mem_read(rsp_ + 0x30, 8))[0]
            except Exception:
                ent = r9
            state['threads'].append((state['count'], ent, 0))
            uc.reg_write(UC_X86_REG_RAX, 0)
        elif 'GetModuleFileName' in name:
            # 谎称自己已经安装在目标位置 -> 走"已安装"分支，进入真正的载荷
            path = 'C:' + chr(92) + 'ProgramData' + chr(92) + 'Windows' + chr(92) + 'Microsoft' + chr(92) + 'RuntimeBroker.exe'
            buf = rdx
            if buf:
                uc.mem_write(buf, path.encode('utf-16-le') + bytes([0,0]))
            uc.reg_write(UC_X86_REG_RAX, len(path))
        elif 'CompareStringOrdinal' in name:
            uc.reg_write(UC_X86_REG_RAX, 2)      # CSTR_EQUAL
        elif 'CreateFile' in name:
            fn = rd_str(uc, rcx, W)
            if is_vm_mod(fn) or any(k in fn.lower() for k in
                   ('vbox','vmware','hgfs','vmci','qemu','virtio','sandbox','cuckoo','\\.\pipe\vm')):
                state['vm_checks'].append((state['count'], name, fn))
                uc.reg_write(UC_X86_REG_RAX, 0xFFFFFFFFFFFFFFFF)   # INVALID_HANDLE_VALUE
            else:
                state['files'].append((state['count'], name, fn))
                state['hnd'] = state.get('hnd', 0x100) + 4
                uc.reg_write(UC_X86_REG_RAX, state['hnd'])
        elif 'GetFileAttributes' in name or 'FindFirstFile' in name:
            fn = rd_str(uc, rcx, W)
            state['files'].append((state['count'], name, fn))
            uc.reg_write(UC_X86_REG_RAX, 0x80)                     # FILE_ATTRIBUTE_NORMAL
        elif 'EnumDisplaySettings' in name:
            dm = uc.reg_read(UC_X86_REG_R8)
            if dm:
                uc.mem_write(dm + 0xA8, struct.pack('<I', 32))     # dmBitsPerPel
                uc.mem_write(dm + 0xAC, struct.pack('<I', 2560))   # dmPelsWidth
                uc.mem_write(dm + 0xB0, struct.pack('<I', 1440))   # dmPelsHeight
                uc.mem_write(dm + 0xB8, struct.pack('<I', 144))    # dmDisplayFrequency
                uc.mem_write(dm + 0x44, struct.pack('<H', 220))    # dmSize
            uc.reg_write(UC_X86_REG_RAX, 1)
        elif 'GetSystemMetrics' in name:
            uc.reg_write(UC_X86_REG_RAX, 2560)
        elif 'GetTickCount' in name:
            state['tick'] = state.get('tick', 4000000) + 1500
            uc.reg_write(UC_X86_REG_RAX, state['tick'])
        elif 'QueryPerformanceCounter' in name:
            state['pc'] = state.get('pc', 10**9) + 3*10**6
            if rcx: uc.mem_write(rcx, struct.pack('<Q', state['pc']))
            uc.reg_write(UC_X86_REG_RAX, 1)
        elif 'QueryPerformanceFrequency' in name:
            if rcx: uc.mem_write(rcx, struct.pack('<Q', 10**7))
            uc.reg_write(UC_X86_REG_RAX, 1)
        elif 'GetVolumeInformation' in name:
            if rdx: uc.mem_write(rdx, b'OS' + bytes([0]))
            r8 = uc.reg_read(UC_X86_REG_R8)
            uc.reg_write(UC_X86_REG_RAX, 1)
        else:
            uc.reg_write(UC_X86_REG_RAX, 1)
        if ret < 0x10000 or ret > 0x7FFFFFFFFFFF:
            state['log'].append((state['count'], "!! %s 的返回地址异常 0x%x (rsp=0x%x)" % (name, ret, rsp)))
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(UC_X86_REG_RIP, ret)

def hook_unmapped(uc, access, addr, size, value, ud):
    """惰性映射：遇到未映射内存就分配并填零，让模拟继续"""
    if len(state['lazy']) > 600:
        state['log'].append((state['count'], "!! 惰性映射超限，停止"))
        return False
    pg = addr & ~0xFFF
    try:
        uc.mem_map(pg, 0x10000)
        uc.mem_write(pg, bytes(0x10000))
    except Exception:
        try:
            uc.mem_map(pg, 0x1000); uc.mem_write(pg, bytes(0x1000))
        except Exception:
            return False
    state['lazy'].append((state['count'], addr, size, access))
    return True


def hook_cpuid(uc, ud):
    eax = uc.reg_read(UC_X86_REG_EAX); ecx_in = uc.reg_read(UC_X86_REG_ECX)
    state['cpuid'].append((state['count'], eax, ecx_in))
    if eax == 0:
        uc.reg_write(UC_X86_REG_EAX, 0x16)
        uc.reg_write(UC_X86_REG_EBX, 0x756e6547)   # Genu
        uc.reg_write(UC_X86_REG_EDX, 0x49656e69)   # ineI
        uc.reg_write(UC_X86_REG_ECX, 0x6c65746e)   # ntel
    elif eax == 1:
        uc.reg_write(UC_X86_REG_EAX, 0x000906EA)
        uc.reg_write(UC_X86_REG_EBX, 0x00100800)
        uc.reg_write(UC_X86_REG_ECX, 0x7FFAFBBF)   # bit31=0 -> 无 hypervisor
        uc.reg_write(UC_X86_REG_EDX, 0xBFEBFBFF)
    elif eax == 0x40000000:                         # hypervisor 厂商叶：返回全 0
        for r in (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX):
            uc.reg_write(r, 0)
    elif eax == 0x80000000:
        uc.reg_write(UC_X86_REG_EAX, 0x80000008)
        for r in (UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX): uc.reg_write(r, 0)
    elif eax in (0x80000002, 0x80000003, 0x80000004):
        brand = b"Intel(R) Core(TM) i7-14700K CPU @ 3.40GHz" + bytes(48)
        blk = brand[(eax - 0x80000002)*16:(eax - 0x80000002)*16 + 16]
        vals = struct.unpack('<IIII', blk[:16])
        for r, v in zip((UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX), vals):
            uc.reg_write(r, v)
    else:
        for r in (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX):
            uc.reg_write(r, 0)
    return True

uc.hook_add(UC_HOOK_INSN, hook_cpuid, None, 1, 0, UC_X86_INS_CPUID)

uc.hook_add(UC_HOOK_CODE, hook_code)
uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_unmapped)

print("\n开始模拟，入口 0x%x" % EP)
try:
    uc.emu_start(EP, 0, timeout=0, count=60_000_000)
    print("模拟正常结束")
except UcError as e:
    print("模拟停止: %s   RIP=0x%x  已执行 %d 条指令" % (e, uc.reg_read(UC_X86_REG_RIP), state['count']))
print("\n执行指令总数: %d" % state['count'])
print("\nAPI 调用统计:")
for k, v in state['calls'].most_common(30): print("   %-42s %d" % (k, v))
print("\n执行轨迹（前 30 条事件）:")
for c, e in state['log'][:60]: print("   #%-8d %s" % (c, e))

print("")
print("=== 带参数的 API 调用（关键情报）===")
for c, n, dtl in state["api_args"][:80]:
    print("   #%-8d %-34s %s" % (c, n, dtl))

print("")
print("=== 被拦下的虚拟机/沙箱检测 (%d 次) ===" % len(state["vm_checks"]))
for c, n, m in state["vm_checks"][:60]:
    print("   #%-8d %-28s %s" % (c, n, m))

print("")
print("=== CPUID 查询 (%d 次) ===" % len(state["cpuid"]))
for c, a, cx in state["cpuid"][:20]:
    print("   #%-8d leaf=0x%x subleaf=0x%x" % (c, a, cx))

print("")
print("=== 尝试访问的文件/路径 (%d 次) —— 这是载荷目标 ===" % len(state["files"]))
seen = set()
for c, n, f in state["files"]:
    if f in seen: continue
    seen.add(f)
    print("   #%-8d %-24s %s" % (c, n, f))

print("")
print("=== COM 方法调用 (%d 次) ===" % len(state["com"]))
for c, i in state["com"][:25]:
    print("   #%-8d vtable[%d]" % (c, i))

print("")
print("=== 惰性映射的内存区域 (%d 次) ===" % len(state["lazy"]))
for c, a, sz, ac in state["lazy"][:30]:
    print("   #%-9d 0x%-14x size=%-3d access=%d" % (c, a, sz, ac))

print("")
print("=== 结束前最后 40 条指令地址 ===")
def where(a):
    for sec in pe.sections:
        lo = IB + sec.VirtualAddress; hi = lo + max(sec.Misc_VirtualSize, sec.SizeOfRawData)
        if lo <= a < hi: return sec.Name.rstrip(bytes([0])).decode("latin1") or "(空名)"
    if API <= a < API + 0x100000: return "API桩"
    return "?"
for a in state["ring"]:
    print("   0x%-12x %s" % (a, where(a)))
print("")
print("=== 代码覆盖：执行最多的 16 个页 ===")
for r, n in sorted(state["cov"].items(), key=lambda x: -x[1])[:16]:
    print("   0x%-12x %-10s %d 次" % (r << 12, where(r << 12), n))

print("")
print("=== ExitProcess 之前的执行流（反汇编最后 60 条）===")
import capstone as _cs
_md = _cs.Cs(_cs.CS_ARCH_X86, _cs.CS_MODE_64)
for a in state["ring"][-60:]:
    try:
        code = bytes(uc.mem_read(a, 16))
        ins = next(_md.disasm(code, a), None)
        txt = ("%-9s %s" % (ins.mnemonic, ins.op_str)) if ins else "??"
    except Exception:
        txt = "<读不到>"
    print("   0x%-12x %-10s %s" % (a, where(a), txt))

print("")
print("=== CoCreateInstance 创建的 COM 组件 ===")
for c, cls, iid in state["clsids"]:
    print("   #%-8d CLSID=%s  IID=%s" % (c, cls, iid))
print("")
print("=== ICMLuaUtil::ShellExec 调用（提权后执行的内容）===")
for c, f, a, dd_ in state["shellexec"]:
    print("   #%-8d file=%r" % (c, f))
    print("              args=%r" % (a,))
    print("              dir =%r" % (dd_,))
print("")
print("=== COM moniker / CLSID（UAC 绕过的关键）===")
for c, n, mk in state["com_monikers"]:
    print("   #%-8d %-22s %r" % (c, n, mk))
print("")
print("=== 捕获到的线程入口 ===")
for c, ent, par in state["threads"]:
    print("   #%-8d entry=0x%-12x param=0x%x  (%s)" % (c, ent, par, where(ent)))

TSTACK = 0x260000000
for ti, (c, ent, par) in enumerate(state["threads"]):
    if not ent: continue
    print("")
    print("######## 从线程 %d 入口 0x%x 继续模拟 ########" % (ti, ent))
    try:
        uc.mem_map(TSTACK + ti*0x200000, 0x100000)
    except Exception: pass
    sp = TSTACK + ti*0x200000 + 0x80000
    uc.reg_write(UC_X86_REG_RSP, sp)
    uc.reg_write(UC_X86_REG_RBP, sp)
    uc.mem_write(sp, struct.pack('<Q', SENTINEL))
    uc.reg_write(UC_X86_REG_RCX, par)
    before = state["count"]; state["log"] = []
    try:
        uc.emu_start(ent, 0, timeout=0, count=20_000_000)
        print("   正常结束")
    except UcError as e:
        print("   停止: %s  RIP=0x%x" % (e, uc.reg_read(UC_X86_REG_RIP)))
    print("   执行 %d 条指令" % (state["count"] - before))
    for cc, ev in state["log"][:45]:
        print("      #%-9d %s" % (cc, ev))
