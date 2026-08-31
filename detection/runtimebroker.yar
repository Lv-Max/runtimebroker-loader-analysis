/*
    RuntimeBroker.exe loader  --  YARA rules

    Reference : https://github.com/Lv-Max/runtimebroker-loader-analysis
    Sample : cf0d4b3837b9a23fb46cbb0a90f5ecae6b7dcd5b1f13b9d4a5fe0de7cec85041
    Date   : 2026-08-31
    License: MIT

    Rule 1  file-based, this family/build        high confidence
    Rule 2  structural hunting, VMProtect-like   medium confidence, baseline before use
    Rule 3  decrypted config, memory scan only   high confidence
*/

import "pe"

rule RuntimeBroker_Loader_VMProtect
{
    meta:
        description  = "C2-controlled loader, VMProtect mutation, registry-chunked payload staging"
        author       = "Lv-Max"
        reference    = "https://github.com/Lv-Max/runtimebroker-loader-analysis"
        date         = "2026-08-31"
        hash         = "cf0d4b3837b9a23fb46cbb0a90f5ecae6b7dcd5b1f13b9d4a5fe0de7cec85041"
        malware_type = "loader"
        confidence   = "high"
        scan_context = "file"

    strings:
        // IsValidPE() at 0x140005FB0 -- runs directly on the freshly recv'd
        // buffer before it is chunked into the registry. The IMAGE_FILE_DLL
        // test is why the second stage must be a DLL.
        $val_mz  = { 3D 4D 5A 00 00 }          // cmp eax, 0x5A4D           'MZ'
        $val_pe  = { 81 38 50 45 00 00 }       // cmp dword ptr [rax], 0x4550
        $val_dll = { 25 00 20 00 00 }          // and eax, 0x2000           IMAGE_FILE_DLL

        // VMProtect mutation-engine constant folding: two 64-bit immediates
        // used to obscure trivial arithmetic in the recv-loop copy helper
        // at 0x140010FB0.
        $vmp_k1  = { 39 21 84 0E 1C D1 A1 E5 } // 0xE5A1D11C0E842139
        $vmp_k2  = { A2 B8 2B AC 0C A9 7F 2D } // 0x2D7FA90CAC2BB8A2

        // Per-string decryption thunks reach their output slot through the TLS
        // array. 434 occurrences in the reference sample; ordinary binaries do
        // not read gs:[0x58] hundreds of times.
        $tls_thunk = { 65 48 8B 04 25 58 00 00 00 }

        // Plaintext in .rdata. Unlike the C2 address / registry keys / mutex,
        // these particular strings are NOT encrypted -- verified by scanning
        // the on-disk file. The chunk format strings are the distinctive ones:
        // they name the registry values the payload is staged in.
        $s_chunk1 = "%s_%s_chunk_%d" ascii
        $s_chunk2 = "%s_%s_tempchunk_%d" ascii
        $s_done   = "task_done;" ascii
        $s_create = "createtask" ascii
        $s_close  = "closetask" ascii

    condition:
        uint16(0) == 0x5A4D
        and pe.machine == pe.MACHINE_AMD64
        and all of ($val_*)
        and any of ($vmp_k*)
        and #tls_thunk > 200
        and for any i in (0 .. pe.number_of_sections - 1) : (
                pe.sections[i].name == ""
                and (pe.sections[i].characteristics & pe.SECTION_MEM_EXECUTE)
            )
        and 3 of ($s_*)
}

rule VMProtect_Loader_FakePdata_Structural
{
    meta:
        description  = "Structural: unnamed executable section + near-empty static import table"
        author       = "Lv-Max"
        reference    = "https://github.com/Lv-Max/runtimebroker-loader-analysis"
        date         = "2026-08-31"
        confidence   = "medium"
        scan_context = "file"
        note         = "Hunting rule. Also matches legitimately packed software. Baseline before enabling."

    condition:
        uint16(0) == 0x5A4D
        and pe.machine == pe.MACHINE_AMD64
        and pe.number_of_sections >= 6
        // everything sensitive is resolved through LoadLibrary/GetProcAddress,
        // so the static import table carries a single DLL
        and pe.number_of_imported_functions < 100
        and for any i in (0 .. pe.number_of_sections - 1) : (
                pe.sections[i].name == ""
                and (pe.sections[i].characteristics & pe.SECTION_MEM_EXECUTE)
                and pe.sections[i].raw_data_size > 0x30000
            )
}

rule RuntimeBroker_Loader_Config_Memory
{
    meta:
        description  = "Decrypted configuration of the RuntimeBroker loader"
        author       = "Lv-Max"
        reference    = "https://github.com/Lv-Max/runtimebroker-loader-analysis"
        date         = "2026-08-31"
        confidence   = "high"
        scan_context = "memory"
        note         = "These specific strings are encrypted on disk and appear only after runtime decryption. Will NOT match the packed file -- scan process memory or an unpacked dump. Plaintext strings are covered by rule 1."

    strings:
        $c2     = "45.91.202.146" ascii wide
        $path   = "\\ProgramData\\Windows\\Microsoft\\RuntimeBroker.exe" ascii wide
        $reg1   = "Software\\WinRAR\\Libs" ascii wide
        $reg2   = "Software\\Microsoft\\EventSystem" ascii wide
        $mutex  = "Global\\RuntimeBrokerAds" ascii wide
        $ws     = "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" ascii
        $p1     = "checkserver;" ascii
        $vm     = "anyrun GPU" ascii wide

    condition:
        2 of ($c2, $path, $reg1, $reg2, $mutex, $ws)
        or ($p1 and 1 of ($c2, $path, $reg1, $reg2, $mutex, $ws))
        or ($vm and 1 of ($c2, $path, $reg1, $reg2))
}