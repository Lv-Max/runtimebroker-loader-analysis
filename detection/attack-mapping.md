# MITRE ATT&CK mapping

Scope: the stage-2 loader `cf0d4b38…`, plus the stage-1 dropper where noted.
Every row cites the evidence it rests on. Techniques belonging to the
**second-stage payload** are excluded — that DLL was never obtained, and
attributing behaviour to it would be speculation.

ATT&CK Enterprise v15.

## Execution

| ID | Technique | Evidence |
|---|---|---|
| T1204.002 | User Execution: Malicious File | Stage 1 was a trojanised game trainer, run by the user |
| T1106 | Native API | Injection uses `NtAllocateVirtualMemory` / `NtWriteVirtualMemory` / `NtCreateThreadEx` directly, bypassing the kernel32 wrappers |
| T1047 | Windows Management Instrumentation | `0x1400084C0`: `IWbemLocator::ConnectServer`, `ROOT\SecurityCenter2` |

## Persistence

| ID | Technique | Evidence |
|---|---|---|
| T1053.005 | Scheduled Task/Job: Scheduled Task | 4 tasks via COM `ITaskService` (`0x140013340`, `0x140011E80`), `PT0S` repetition |
| T1112 | Modify Registry | Payload chunks under `HKCU\Software\WinRAR\Libs`; C2 hostname cached in `HKCU\Software\Microsoft\EventSystem` value `System` |

## Privilege Escalation

| ID | Technique | Evidence |
|---|---|---|
| T1548.002 | Bypass User Account Control | `CheckTokenMembership` → not admin → `CoGetObject("Elevation:Administrator!new:{3E5FC7F9-…}")` → `ICMLuaUtil::ShellExec(own path)`, no prompt. This is the loader's own code, not the dropper's |
| T1134.001 | Access Token Manipulation: Token Impersonation/Theft | Targets `winlogon`, `smartscreen`, `explorer.exe`; `OpenProcessToken` → `AdjustTokenPrivileges` at `0x14000D330` |
| T1134.002 | Create Process with Token | `SeAssignPrimaryTokenPrivilege`, `SeIncreaseQuotaPrivilege` requested alongside `SeDebugPrivilege` |

## Defense Evasion

| ID | Technique | Evidence |
|---|---|---|
| T1027.002 | Obfuscated Files or Information: Software Packing | VMProtect in mutation mode; unnamed 320 KB executable section |
| T1027 | Obfuscated Files or Information | Per-string encryption: 204 call sites, 63 distinct decryption routines |
| T1140 | Deobfuscate/Decode Files or Information | Strings decrypted lazily at point of use, into `.rdata` or a TLS slot |
| T1562.001 | Impair Defenses: Disable or Modify Tools | `Add-MpPreference -ExclusionPath` for its own directory plus a real Windows directory; `amsi.dll!AmsiOpenSession` patched in memory (`0x140011B70`) |
| T1055.002 | Process Injection: Portable Executable Injection | Reflective PE image written into a suspended `cmd.exe` (`0x14000E970`, `0x14000AA10`) |
| T1620 | Reflective Code Loading | The injected stub resolves imports itself from `LoadLibraryA`/`GetProcAddress` addresses passed in; `RtlAddFunctionTable` registers SEH data for the manually mapped image |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Binary named `RuntimeBroker.exe`; scheduled tasks named after stock Windows tasks; payload hidden under a `WinRAR` key; Defender exclusion points at a genuine system directory |
| T1497.001 | Virtualization/Sandbox Evasion: System Checks | VM driver/device probes, CPUID hypervisor bit and brand strings, D3D9 adapter blacklist (explicitly including `anyrun GPU`), CPU-model filter for cloud sandboxes |
| T1497.003 | Virtualization/Sandbox Evasion: Time Based Evasion | Timing watchdog thread |
| T1622 | Debugger Evasion | `NtQueryInformationProcess`, plus a debugger-polling watchdog |
| T1112 | Modify Registry | Payload staged as registry binary values rather than files — evades filesystem scanning entirely |
| T1070.004 | Indicator Removal: File Deletion | `RegDeleteValueA` clears `tempchunk` values after commit (registry analogue) |

## Discovery

| ID | Technique | Evidence |
|---|---|---|
| T1518.001 | Software Discovery: Security Software Discovery | `SELECT displayName FROM AntiVirusProduct` / `AntiSpywareProduct` — the `getinfo` command |
| T1082 | System Information Discovery | `RtlGetVersion` + `GetVersionExW`, OS version string built at `0x140009470` |
| T1033 | System Owner/User Discovery | `GetUserNameW`, `ConvertSidToStringSidW` |
| T1057 | Process Discovery | Locating token-theft targets by process name |

## Command and Control

| ID | Technique | Evidence |
|---|---|---|
| T1071 | Application Layer Protocol | Hand-written RFC 6455 WebSocket client over raw sockets |
| T1571 | Non-Standard Port | TCP 406 and 408 |
| T1105 | Ingress Tool Transfer | Separate cleartext HTTP download channel (`0x14000B770`), 3 MB receive buffer |
| T1008 | Fallback Channels | Two independent retry loops: hard-coded IP first, then a registry-cached hostname plus `.duckdns.org` (`0x140015870`) |
| T1568 | Dynamic Resolution | Fallback hostname resolved at runtime and cached; the subdomain is not present in the binary |

## Impact / Not mapped

`RtlSetProcessIsCritical` is set on the loader process, so force-terminating it
bugchecks the host. This is self-protection rather than a deliberate
availability attack, and ATT&CK has no clean match — noted here rather than
mapped to T1499 or T1529.

Credential theft (T1555.003 and related) was observed in the incident but is
**not** implemented in this sample. It belongs to the second-stage DLL, which
was not recovered. It is deliberately left unmapped.