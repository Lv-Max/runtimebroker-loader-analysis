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

state = {'heap': HEAP, 'calls': collections.Counter(), 'log': [], 'count': 0, 'api_args': [], 'vm_checks': [], 'cpuid': [], 'files': [], 'com': [], 'lazy': [], 'ring': [], 'cov': {}, 'threads': [], 'com_monikers': [], 'shellexec': [], 'clsids': [], 'uniq': set(), 'bytes': {}, 'c2': [], 'sent': [], 'recvd': []}
state.setdefault('cmps', [])
state.setdefault('bstr', [])
state.setdefault('com_args', [])
state.setdefault('recv_callers', {})
state.setdefault('recv_args', [])
state.setdefault('hostwrite', [])
state.setdefault('watch', [])



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


CMPFN = 0x140002fb0
TRACE_TARGETS = {0x140015870, 0x14000F7A0, 0x14000B770, 0x1400148C0}

def _cstr(a, n=64):
    if not a or a < 0x1000: return None
    try:
        b = bytes(uc.mem_read(a, n))
    except Exception:
        return None
    e = b.find(bytes([0]))
    b = b[:e if e >= 0 else n]
    return b.decode('latin1', 'ignore') if b else ''

def hook_code(uc, addr, size, ud):
    state['count'] += 1
    state['ring'].append(addr)
    if len(state['ring']) > 260: state['ring'].pop(0)
    if addr == SENTINEL:
        state['log'].append((state['count'], ">>> 返回到哨兵：入口函数已结束"))
        uc.emu_stop(); return
    if addr == CMPFN:
        _s1 = _cstr(uc.reg_read(UC_X86_REG_RCX))
        _s2 = _cstr(uc.reg_read(UC_X86_REG_RDX))
        _n  = uc.reg_read(UC_X86_REG_R8)
        _rsp = uc.reg_read(UC_X86_REG_RSP)
        try: _ret = struct.unpack('<Q', uc.mem_read(_rsp, 8))[0]
        except Exception: _ret = 0
        state['cmps'].append((state['count'], _ret, _s1, _s2, _n))
    if addr in TRACE_TARGETS:
        _t = state.setdefault('trace', [])
        if len(_t) < 40:
            _rsp2 = uc.reg_read(UC_X86_REG_RSP)
            try: _ret2 = struct.unpack('<Q', uc.mem_read(_rsp2, 8))[0]
            except Exception: _ret2 = 0
            _args = {}
            for _rn, _r in (('rcx', UC_X86_REG_RCX), ('rdx', UC_X86_REG_RDX),
                            ('r8', UC_X86_REG_R8), ('r9', UC_X86_REG_R9)):
                _v = uc.reg_read(_r)
                _s = ''
                try:
                    _raw = uc.mem_read(_v, 64)
                    _z = _raw.split(bytes([0]))[0]
                    if len(_z) >= 2 and all(32 <= _c < 127 for _c in _z): _s = _z.decode('latin1')
                except Exception: pass
                _args[_rn] = (_v, _s)
            _stk = []
            try:
                for _off in range(0, 0x300, 8):
                    _w = struct.unpack('<Q', uc.mem_read(_rsp2 + _off, 8))[0]
                    if 0x140001000 <= _w < 0x14002c400: _stk.append((_off, _w))
            except Exception: pass
            _hex = {}
            for _rn2, _r2 in (('rcx', UC_X86_REG_RCX), ('rdx', UC_X86_REG_RDX)):
                try: _hex[_rn2] = (uc.reg_read(_r2), bytes(uc.mem_read(uc.reg_read(_r2), 32)))
                except Exception: pass
            _slots = []
            for _sa in (0x1400310B0, 0x1400310B8, 0x140031108, 0x140031110,
                        0x140031118, 0x140031120, 0x140031128):
                try:
                    _sv = struct.unpack('<Q', uc.mem_read(_sa, 8))[0]
                    _slots.append((_sa, _sv))
                except Exception: pass
            _t.append((state['count'], addr, _ret2, list(state['ring'][-26:]), _args,
                       _stk[:12], _hex, _slots))

    state['uniq'].add(addr)
    state['bytes'][addr] = size
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
        elif 'SysAllocStringLen' in name:
            _n = uc.reg_read(UC_X86_REG_RDX) * 2
            _b = state['heap']; state['heap'] += ((_n + 32) & ~15)
            try:
                _src = bytes(uc.mem_read(rcx, _n)) if rcx else bytes(_n)
            except Exception:
                _src = bytes(_n)
            uc.mem_write(_b, struct.pack('<I', _n))
            uc.mem_write(_b + 4, _src + bytes([0, 0]))
            uc.reg_write(UC_X86_REG_RAX, _b + 4)
        elif 'SysAllocString' in name:
            _t = rd_str(uc, rcx, True) if rcx else ''
            _enc = _t.encode('utf-16-le')
            _b = state['heap']; state['heap'] += ((len(_enc) + 32) & ~15)
            uc.mem_write(_b, struct.pack('<I', len(_enc)))
            uc.mem_write(_b + 4, _enc + bytes([0, 0]))
            state['bstr'].append((state['count'], _t[:180]))
            uc.reg_write(UC_X86_REG_RAX, _b + 4)
        elif 'SysFreeString' in name or 'VariantClear' in name or 'VariantInit' in name:
            uc.reg_write(UC_X86_REG_RAX, 0)
        elif name.startswith('COM!'):
            def _bstr(a):
                if not a or a < 0x1000: return None
                try:
                    _l = struct.unpack('<I', uc.mem_read(a - 4, 4))[0]
                    if 0 < _l < 4096:
                        _t = bytes(uc.mem_read(a, _l)).decode('utf-16-le', 'ignore')
                        if _t.strip(): return _t
                except Exception: pass
                try:
                    _t = rd_str(uc, a, True)
                    return _t if _t and len(_t) > 1 else None
                except Exception: return None
            _aa = []
            for _rn, _rv in (('a1', rdx), ('a2', uc.reg_read(UC_X86_REG_R8)),
                             ('a3', uc.reg_read(UC_X86_REG_R9))):
                _t = _bstr(_rv)
                if _t: _aa.append('%s=%r' % (_rn, _t[:180]))
            if _aa:
                state['com_args'].append((state['count'], int(name.split('_')[1]), ' '.join(_aa)))
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
        elif 'WSAStartup' in name:
            uc.reg_write(UC_X86_REG_RAX, 0)
        elif name.endswith(('!getaddrinfo','!GetAddrInfoW','!GetAddrInfoA')):
            def _dump(a, n=72):
                if not a: return 'NULL指针'
                try: raw = bytes(uc.mem_read(a, n))
                except Exception: return '不可读 0x%x' % a
                hx = ' '.join('%02x' % x for x in raw[:32])
                asc = ''.join(chr(x) if 32<=x<127 else '.' for x in raw)
                w = raw.decode('utf-16-le','ignore').split(chr(0))[0]
                return ('addr=0x%x' % a) + chr(10) + ('        hex: %s' % hx) + chr(10) + ('        ansi: %r' % asc) + chr(10) + ('        wide: %r' % w)



            if len(state['c2']) < 6: state['c2'].append((state['count'], 'getaddrinfo-RCX', _dump(rcx), ''))
            if len(state['c2']) < 6: state['c2'].append((state['count'], 'getaddrinfo-RDX', _dump(rdx), ''))
            host = rd_str(uc, rcx, False); svc = rd_str(uc, rdx, False)
            ai = state['heap']; state['heap'] += 0x200
            sa = ai + 0x80
            uc.mem_write(sa, struct.pack('<HH4s8s', 2, 0x9601, bytes([45,91,202,146]), bytes(8)))
            uc.mem_write(ai, struct.pack('<iiiiQQQQ', 0, 2, 1, 6, 16, 0, sa, 0))
            r9v = uc.reg_read(UC_X86_REG_R9)
            if r9v: uc.mem_write(r9v, struct.pack('<Q', ai))
            uc.reg_write(UC_X86_REG_RAX, 0)
        elif name.endswith('!socket') or name.endswith('!WSASocketW'):
            state['sock'] = state.get('sock', 100) + 1
            uc.reg_write(UC_X86_REG_RAX, state['sock'])
        elif name.endswith('!connect') or name.endswith('!WSAConnect'):
            try:
                sa = bytes(uc.mem_read(rdx, 16))
                fam, port = struct.unpack('<HH', sa[:4])
                ip = '.'.join(str(b) for b in sa[4:8])
                port = ((port & 0xFF) << 8) | (port >> 8)
                state['c2'].append((state['count'], 'connect', '%s:%d' % (ip, port), 'family=%d' % fam))
            except Exception: pass
            uc.reg_write(UC_X86_REG_RAX, 0)
        elif name.endswith('!send') or name.endswith('!WSASend'):
            ln = uc.reg_read(UC_X86_REG_R8)
            try: data = bytes(uc.mem_read(rdx, min(ln, 0x20000)))
            except Exception: data = b''
            state['sent'].append((state['count'], ln, data))
            uc.reg_write(UC_X86_REG_RAX, ln)
        elif name.endswith('!recv') or name.endswith('!WSARecv'):
            _rsp = uc.reg_read(UC_X86_REG_RSP)
            try: _ret = struct.unpack('<Q', uc.mem_read(_rsp, 8))[0]
            except Exception: _ret = 0
            state['recv_callers'][_ret] = state['recv_callers'].get(_ret, 0) + 1
            state['recv_args'].append((state['count'], rdx, uc.reg_read(UC_X86_REG_R8)))
            ln = uc.reg_read(UC_X86_REG_R8)
            state['recv_n'] = state.get('recv_n', 0) + 1
            # 按破解出的协议构造应答：2字节头 + 4字节XOR密钥 + 密文
            KEY = bytes([0x12, 0x34, 0x56, 0x78])
            if state['recv_n'] == 1:
                pt = b'<WebSocket 101 handshake>'
                pkt = (b'HTTP/1.1 101 Switching Protocols' + bytes([13,10]) +
                       b'Upgrade: websocket' + bytes([13,10]) +
                       b'Connection: Upgrade' + bytes([13,10]) +
                       b'Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=' +
                       bytes([13,10,13,10]))
            else:
                cmds = [b'getinfo',
                        b'task;T001;task_id;T001;type;createtask;version;1.0.0;param;test',
                        b'ping',
                        b'task;T001;task_id;T001;type;update;version;1.0.0;param;x',
                        b'ok;']
                pt = cmds[(state['recv_n'] - 2) % len(cmds)]
                # 服务端 -> 客户端：WebSocket 帧不加掩码（RFC 6455）
                pkt = bytes([0x82, len(pt)]) + pt
            n = min(ln, len(pkt))
            try: uc.mem_write(rdx, pkt[:n])
            except Exception: pass
            state['recvd'].append((state['count'], ln, pt))
            uc.reg_write(UC_X86_REG_RAX, n if state['recv_n'] < 200 else 0)
        elif name.endswith(('!select','!setsockopt','!getsockopt','!ioctlsocket',
                            '!closesocket','!shutdown','!freeaddrinfo','!WSACleanup')):
            uc.reg_write(UC_X86_REG_RAX, 1 if name.endswith('!select') else 0)
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


WATCH = [(0x300006f80, 26, ".duckdns.org"), (0x30000609c, 4, "port 406"),
         (0x3000060a0, 4, "port 408"), (0x3000060a4, 9, "campaign 63203572"),
         (0x300006080, 28, "IP 45.91.202.146"), (0x3000060c4, 5, "cmd ping"),
         (0x3000060c9, 5, "cmd pong"), (0x3000060ce, 8, "cmd getinfo"),
         (0x3000060dc, 5, "cmd task")]
def hook_mem_read(uc, access, addr, size, value, ud):
    for w, wl, tag in WATCH:
        if w <= addr < w + wl:
            rip = uc.reg_read(UC_X86_REG_RIP)
            state['watch'].append((state['count'], rip, addr, tag))
            break
uc.hook_add(UC_HOOK_MEM_READ, hook_mem_read)

HOSTBUF = 0x2000fcb00
def hook_mem_write(uc, access, addr, size, value, ud):
    if HOSTBUF <= addr < HOSTBUF + 0x100:
        rip = uc.reg_read(UC_X86_REG_RIP)
        state['hostwrite'].append((state['count'], rip, addr, size, value))
uc.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)


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

print("")
print("=" * 62)
print("代码覆盖率统计")
print("=" * 62)
print("执行指令次数(含重复) : %d" % state["count"])
print("唯一指令地址数       : %d" % len(state["uniq"]))
print("覆盖字节数           : %d" % sum(state["bytes"].values()))
print("")
print("%-10s %10s %10s %8s" % ("节区", "代码字节", "已覆盖", "覆盖率"))
print("-" * 44)
for sec in pe.sections:
    nm = sec.Name.rstrip(bytes([0])).decode("latin1") or "(无名)"
    lo = IB + sec.VirtualAddress
    hi = lo + max(sec.Misc_VirtualSize, sec.SizeOfRawData)
    tot = hi - lo
    cov = sum(sz for a, sz in state["bytes"].items() if lo <= a < hi)
    if sec.Characteristics & 0x20000000:
        print("%-10s %10d %10d %7.2f%%" % (nm, tot, cov, 100.0*cov/tot if tot else 0))
print("")
print("=" * 62)
print("C2 通信")
print("=" * 62)
for c, kind, a, b in state["c2"]:
    print("   #%-9d %-14s %s   %s" % (c, kind, a, b))
print("")
print("send() 调用 %d 次" % len(state["sent"]))
import os as _os
_dir = _os.path.dirname(_os.path.abspath(__file__))
for _i, (_c, _ln, _data) in enumerate(state["sent"]):
    print("")
    print("--- send #%d  @指令 %d  长度 %d  读到 %d 字节 ---" % (_i, _c, _ln, len(_data)))
    _fn = _os.path.join(_dir, "beacon_%d.bin" % _i)
    open(_fn, "wb").write(_data)
    print("   已保存 beacon_%d.bin" % _i)
    for _off in range(0, min(128, len(_data)), 16):
        _ck = _data[_off:_off+16]
        _hx = " ".join("%02x" % x for x in _ck)
        _as = "".join(chr(x) if 32 <= x < 127 else "." for x in _ck)
        print("     %04x  %-47s  %s" % (_off, _hx, _as))
print("")
print("=" * 66)
print("运行时解密出的字符串池")
print("=" * 66)
import re as _re
_seen = set(); _out = []
for _lo, _hi, _perm in uc.mem_regions():
    _sz = _hi - _lo + 1
    if _sz > 0x400000: continue
    try: _blk = bytes(uc.mem_read(_lo, _sz))
    except Exception: continue
    for _m in _re.finditer(rb"[ -~]{4,}", _blk):
        _t = _m.group().decode("latin1")
        if _t not in _seen:
            _seen.add(_t); _out.append((_lo + _m.start(), _t))
print("共 %d 条唯一字符串" % len(_out))
_KEY = ['http', '://', '.exe', '.dll', '.dat', 'Global', 'Local', 'Mutex', 'ready', 'cmd', 'Chrome', 'Login', 'wallet', 'AppData', 'Roaming', 'ProgramData', 'SOFTWARE', 'Users', 'sql', 'profile', 'token', 'pass', 'User-Agent', 'Mozilla', 'POST', 'GET', 'Content', 'Host:', '406', '408']
print("")
print("--- 关键词命中 ---")
for _a, _t in _out:
    if any(_k.lower() in _t.lower() for _k in _KEY):
        print("   0x%-12x %s" % (_a, _t[:150]))
print("")
print("--- 其余长度>=6（前 100 条）---")
_n = 0
for _a, _t in _out:
    if len(_t) >= 6 and not any(_k.lower() in _t.lower() for _k in _KEY):
        print("   0x%-12x %s" % (_a, _t[:150])); _n += 1
        if _n >= 100: break

print("")
print("=" * 70)
print("解密后配置区原始内存 dump")
print("=" * 70)
for _base, _len, _tag in [(0x300006000, 0x180, "配置块 A"),
                          (0x300006f60, 0x80, "duckdns 附近"),
                          (0x2000fc880, 0x80, "组装好的报文附近")]:
    try:
        _m = bytes(uc.mem_read(_base, _len))
    except Exception as _e:
        print("%s 读不到: %s" % (_tag, _e)); continue
    print("")
    print("--- %s  @0x%x ---" % (_tag, _base))
    for _o in range(0, _len, 16):
        _c = _m[_o:_o+16]
        _a = "".join(chr(x) if 32 <= x < 127 else "." for x in _c)
        print("  %012x  %-47s  %s" % (_base+_o, " ".join("%02x" % x for x in _c), _a))
print("")
print("=" * 70)
print("全内存搜索 duckdns / 域名样式")
print("=" * 70)
import re as _re
_pat = _re.compile(rb"[A-Za-z0-9_-]{1,40}\.(duckdns|no-ip|ddns|hopto|myftp|serveo|ngrok)\.[a-z]{2,6}", _re.I)
_patw = _re.compile((r"[A-Za-z0-9_-]{1,40}\.(duckdns|no-ip|ddns|hopto)\.[a-z]{2,6}").encode("utf-16-le"), _re.I)
for _r in uc.mem_regions():
    _b, _e, _pm = _r
    _sz = _e - _b + 1
    if _sz > 0x4000000: continue
    try: _m = bytes(uc.mem_read(_b, _sz))
    except Exception: continue
    for _mt in _pat.finditer(_m):
        print("  ASCII  0x%x  %r" % (_b + _mt.start(), _mt.group().decode()))
    _u = _m.decode("utf-16-le", "ignore")
    for _mt in _re.finditer(r"[A-Za-z0-9_-]{1,40}\.(duckdns|no-ip|ddns|hopto)\.[a-z]{2,6}", _u, _re.I):
        print("  UTF16  0x%x  %r" % (_b + _mt.start()*2, _mt.group()))

print("")
print("=" * 70)
print("配置字符串的引用点")
print("=" * 70)
_seen = set()
for _c, _rip, _a, _tag in state["watch"]:
    _k = (_rip, _tag)
    if _k in _seen: continue
    _seen.add(_k)
    print("   #%-9d RIP=0x%-12x 读取 0x%-12x  %s   [%s]" % (_c, _rip, _a, _tag, where(_rip)))
print("")
print("共 %d 次读取，%d 个不同引用点" % (len(state["watch"]), len(_seen)))

print("")
print("=" * 70)
print("主机名缓冲区的写入者")
print("=" * 70)
_pts = {}
for _c, _rip, _a, _sz, _v in state["hostwrite"]:
    _pts.setdefault(_rip, []).append((_a, _sz, _v))
print("写入次数 %d，不同代码位置 %d 个" % (len(state["hostwrite"]), len(_pts)))
for _rip, _ws in list(_pts.items())[:14]:
    _chars = "".join(chr(v & 0xFF) if 32 <= (v & 0xFF) < 127 else "." for _, _, v in _ws[:40])
    print("   RIP=0x%-12x [%s]  %d 次   写入字节: %r" % (_rip, where(_rip), len(_ws), _chars))
print("")
try:
    _fin = bytes(uc.mem_read(0x2000fcb48, 80))
    print("缓冲区最终内容:")
    print("   ansi: %r" % "".join(chr(x) if 32<=x<127 else "." for x in _fin))
    print("   wide: %r" % _fin.decode("utf-16-le","ignore").split(chr(0))[0])
except Exception as _e:
    print("读不到:", _e)

print("")
print("=" * 70)
print("recv 的调用点（返回地址）")
print("=" * 70)
for _r, _n in sorted(state["recv_callers"].items(), key=lambda x: -x[1])[:8]:
    print("   0x%-14x  %-10s  %d 次" % (_r, where(_r), _n))
print("")
print("recv 缓冲区/长度（前 5 次）:")
for _c, _b, _l in state["recv_args"][:5]:
    print("   #%-9d buf=0x%-14x len=%d" % (_c, _b, _l))
print("")
print("=" * 70)
print("recv 返回后的代码（应答解析器）")
print("=" * 70)
import capstone as _cs
_md2 = _cs.Cs(_cs.CS_ARCH_X86, _cs.CS_MODE_64)
for _r in sorted(state["recv_callers"], key=lambda x: -state["recv_callers"][x])[:2]:
    print("")
    print("--- 从 0x%x 开始 ---" % _r)
    try:
        _code = bytes(uc.mem_read(_r, 260))
    except Exception as _e:
        print("   读不到:", _e); continue
    for _i in _md2.disasm(_code, _r):
        print("   0x%-12x %-9s %s" % (_i.address, _i.mnemonic, _i.op_str))

print("")
print("=" * 70)
print("COM 方法调用的字符串参数（WMI 查询等）")
print("=" * 70)
_sn = set()
for _c, _i, _a in state["com_args"]:
    if _a in _sn: continue
    _sn.add(_a)
    print("   #%-9d vtable[%-2d]  %s" % (_c, _i, _a))
print("")
print("共 %d 次带字符串参数的 COM 调用，%d 条不重复" % (len(state["com_args"]), len(_sn)))

print("")
print("=" * 70)
print("SysAllocString 创建的字符串（WMI 命名空间 / WQL 查询 / 属性名）")
print("=" * 70)
_sb = []
for _c, _t in state["bstr"]:
    if _t and _t not in [x[1] for x in _sb]:
        _sb.append((_c, _t))
for _c, _t in _sb[:60]:
    print("   #%-9d %r" % (_c, _t))
print("")
print("共 %d 次调用，%d 条不重复" % (len(state["bstr"]), len(_sb)))

print("")
print("=" * 74)
print("字符串比较函数的全部调用（协议解析逻辑）")
print("=" * 74)
_u = []
for _c, _ret, _a, _b, _n in state["cmps"]:
    _k = (_a, _b, _n)
    if _k in [x[0] for x in _u]: continue
    _u.append((_k, _c, _ret))
print("共 %d 次比较，%d 组不重复" % (len(state["cmps"]), len(_u)))
print("")
for (_a, _b, _n), _c, _ret in _u[:60]:
    print("   #%-9d 调用者=0x%-12x  len=%-4d" % (_c, _ret, _n))
    print("        输入 = %r" % (_a[:70] if _a is not None else None))
    print("        模式 = %r" % (_b[:70] if _b is not None else None))

print("")
print("=" * 70)
print("task handler 引用的模式串（从解密后内存读取）")
print("=" * 70)
for _a, _tag in [(0x14002E131, "task 比较模式 @0x14000fa90"),
                 (0x14002E0EB, "strstr 模式 @0x14000fbcb"),
                 (0x14002E0C0, "附近区域"), (0x14002E100, "附近区域"),
                 (0x14002E160, "附近区域")]:
    try:
        _m = bytes(uc.mem_read(_a, 64))
    except Exception as _e:
        print("  %s 0x%x 读不到" % (_tag, _a)); continue
    _asc = "".join(chr(x) if 32 <= x < 127 else "." for x in _m)
    _w = _m.decode("utf-16-le", "ignore").split(chr(0))[0]
    print("  --- %s @0x%x ---" % (_tag, _a))
    print("      hex : %s" % _m[:32].hex(" "))
    print("      ansi: %r" % _asc)
    if _w.strip(): print("      wide: %r" % _w)
print("")
print("=" * 70)
print(".rdata 解密后的可读字符串")
print("=" * 70)
import re as _re2
try:
    _rd = bytes(uc.mem_read(0x14002d000, 0x3e00))
    for _m2 in _re2.finditer(rb"[ -~]{4,90}", _rd):
        print("   0x%x  %r" % (0x14002d000 + _m2.start(), _m2.group().decode()))
    _u2 = _rd.decode("utf-16-le", "ignore")
    for _m2 in _re2.finditer(r"[ -~]{4,90}", _u2):
        print("   0x%x  [W] %r" % (0x14002d000 + _m2.start()*2, _m2.group()))
except Exception as _e:
    print("  读取失败:", _e)

# COVDUMP
import json as _json, os as _os
_cv = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), 'coverage.json')
with open(_cv, 'w') as _fh:
    _json.dump({'%d' % _a: _n for _a, _n in state['bytes'].items()}, _fh)
print('覆盖地址已导出: %s (%d 条)' % (_cv, len(state['bytes'])))

# SLOTDUMP  —— .data 里的动态 API 指针表反查
print("")
print("=" * 74)
print(".data 动态 API 指针表（槽位 -> 实际 API）")
print("=" * 74)
_rev = {}
for _nm, _ad in state.get('dyn', {}).items(): _rev[_ad] = _nm
for _ad, _nm in api_map.items(): _rev.setdefault(_ad, _nm)
_hits = []
for _a in range(0x140031000, 0x140049e50, 8):
    try: _v = struct.unpack('<Q', uc.mem_read(_a, 8))[0]
    except Exception: continue
    _n = _rev.get(_v) or _rev.get(_v & ~0xF)
    if _n: _hits.append((_a, _v, _n))
print("命中 %d 个槽位" % len(_hits))
for _a, _v, _n in _hits:
    print("   0x%x  ->  %s" % (_a, _n))


# ---- TRACE DUMP ----
print("")
print("=" * 74)
print("追踪目标的实际调用者（模拟运行期证据）")
print("=" * 74)
_tr = state.get('trace', [])
if not _tr:
    print("  目标函数在本次模拟中均未被执行")
for _rec in _tr:
    _n, _a, _ret, _ring = _rec[0], _rec[1], _rec[2], _rec[3]
    _args = _rec[4] if len(_rec) > 4 else {}
    _stk = _rec[5] if len(_rec) > 5 else []
    _hex = _rec[6] if len(_rec) > 6 else {}
    _slots = _rec[7] if len(_rec) > 7 else []
    print("")
    print("  第 %d 条指令  进入 0x%x   栈顶返回地址 = 0x%x" % (_n, _a, _ret))
    _path = [x for x in _ring[:-1]][-14:]
    print("       路径: " + " -> ".join("0x%x" % x for x in _path))
    for _k in ('rcx', 'rdx', 'r8', 'r9'):
        if _k in _args:
            _v, _s = _args[_k]
            print("       %-4s = 0x%-16x %s" % (_k, _v, ('-> "%s"' % _s) if _s else ''))
    if _stk:
        print("       栈上落在 .text 的返回地址（逻辑调用链）:")
        for _off, _w in _stk:
            print("           [rsp+0x%03x] = 0x%x" % (_off, _w))
    for _k2 in ('rcx', 'rdx'):
        if _k2 in _hex:
            _p, _b = _hex[_k2]
            print("       %s 内存 0x%x: %s  |  %s" % (_k2, _p, _b.hex(),
                  ''.join(chr(c) if 32 <= c < 127 else '.' for c in _b)))
    if _slots:
        print("       此刻 .data 配置槽位的指针值:")
        for _sa, _sv in _slots:
            _tag = ''
            for _k3 in ('rcx', 'rdx'):
                if _k3 in _hex and _hex[_k3][0] == _sv: _tag = '   <<<< 即 %s' % _k3
            print("           [0x%x] = 0x%-14x%s" % (_sa, _sv, _tag))
