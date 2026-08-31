# RuntimeBroker.exe — VMProtect loader with registry-staged payload delivery

Reverse engineering of the second-stage loader from a commodity infostealer
infection (August 2026), recovered during incident response on a compromised
personal workstation.

**[Full analysis →](analysis.md)**

```
SHA-256   cf0d4b3837b9a23fb46cbb0a90f5ecae6b7dcd5b1f13b9d4a5fe0de7cec85041
Size      527,872 bytes   PE32+ (x64)
C2        45.91.202.146:406, :408
Packer    VMProtect (mutation mode)
Role      loader — no credential-theft code in this file
```

## Key findings

**The payload is staged in the registry, never on disk.** Chunks are written
under `HKCU\Software\WinRAR\Libs` as `<id>_<name>_chunk_<n>`, using a
`tempchunk` → `chunk` atomic-commit scheme that survives reboot and supports
resume. The only executable ever written to the filesystem is the loader itself;
the stealer exists solely as registry binary values and as memory inside a
windowless `cmd.exe`. Filesystem scanning does not see it at any point.

**The download channel carries a plaintext PE.** The C2 control channel is a
masked WebSocket, but payload delivery is a separate cleartext HTTP transfer. A
`MZ` / `PE\0\0` validator runs directly on the received socket buffer — so there
cannot be an encryption layer on the wire. The validator also requires
`IMAGE_FILE_DLL`, which proves the second stage is a DLL. This permits a
decryption-free network signature.

**The WebSocket handshake key is the RFC 6455 example value.** The hand-written
client sends `Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==` on every connection.
A conforming client generates this randomly per connection, so it is a
near-zero-false-positive fingerprint that survives recompilation and
infrastructure changes.

## Highest-value host indicators

Two registry values. Both keys are legitimate paths that exist on clean systems,
which is exactly why they were chosen — **test for the values, not the keys**:

```
HKCU\Software\WinRAR\Libs
    values named <id>_<name>_chunk_<n>          staged payload
    (conclusive if WinRAR is not installed)

HKCU\Software\Microsoft\EventSystem
    value named "System" containing a hostname   cached C2 for the fallback channel
```

Both present = confirmed infection.

## Repository layout

```
analysis.md               full technical write-up
detection/
    runtimebroker.yar     3 YARA rules — tested, see below
    suricata.rules        5 network rules, each with a false-positive rating
    attack-mapping.md     MITRE ATT&CK mapping
iocs/
    iocs.txt              plain text, one per line
    iocs.json             structured
tools/                    analysis harness (Unicorn emulator, string decryptors)
samples/                  hashes only — no binaries in this repo
```

## Detection artifacts

**YARA** — 3 rules, verified before publication:

| Rule | Scope | Result |
|---|---|---|
| `RuntimeBroker_Loader_VMProtect` | file | matches the sample |
| `VMProtect_Loader_FakePdata_Structural` | file, hunting | matches the sample; medium confidence, baseline before enabling |
| `RuntimeBroker_Loader_Config_Memory` | memory only | correctly does **not** match the packed file |

Tested against 400 clean `C:\Windows\System32` binaries: **0 false positives.**
The stage-1 dropper does not match (different family), as expected.

**Suricata/Snort** — 5 rules, each annotated with a false-positive rating and a
deployment recommendation. Two are safe to run always; one is scoped to the C2
ports; two are hunting-only and one of those ships commented out.

> The network rules have **not** been validated with `suricata -T`. Test before
> deploying.

## Analysis method

Static reverse engineering plus CPU emulation under Unicorn Engine. **The sample
was never executed on a real system.** The harness maps the PE, builds a
synthetic TEB/PEB/TLS, stubs the IAT, and returns plausible values for each
anti-analysis probe. Obfuscated strings were recovered by invoking each of the
63 decryption thunks in an isolated emulator instance rather than running the
sample body.

Dynamic coverage reached `.text` 50.37%; the rest is static reconstruction.
The two sources are labelled separately throughout the write-up, and the limits
of the function inventory are stated explicitly in
[§10](analysis.md#10-coverage-and-limits) — including why the function count is
a lower bound rather than a total.

## Samples

Not distributed here. See [`samples/README.md`](samples/README.md) for hashes
and where to obtain them.

## License

MIT for the tooling and rules. The write-up is CC BY 4.0.

## Disclaimer

Published for defensive purposes: detection engineering, threat hunting, and
incident response. The analysis tooling emulates the sample; it does not
weaponise it. No second-stage payload, C2 implementation, or builder is included
or reconstructed here.