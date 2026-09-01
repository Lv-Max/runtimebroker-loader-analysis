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

## Campaign status

Not an isolated sample. VirusTotal associates 21 files with `45.91.202.146`,
mostly named `RuntimeBroker.exe` at 519–536 KB — recompiles of the same loader,
first submitted between **2026-08-21 and 2026-08-31**, with new builds appearing
on most days up to the date of writing.

**Treat this C2 as potentially live.** Its reachability was not tested, but a
campaign shipping daily builds is not pointed at a dead server. Correspondingly,
**file hashes are near-useless** for this family — every build differs. The
durable indicators are the two registry values below and the hardcoded RFC 6455
handshake key, neither of which changes between builds.

## The second stage

Retrieved from the live C2 on 2026-08-31 by speaking the protocol with a
purpose-built client — the sample itself was never run.

```
SHA-256   fd779b73082ed7c7d98d076f863562a6cb8d2297077a3e093305051be040bd29
Size      1,452,032 bytes   PE32+ DLL x64
Family    Redhive Stealer (its own branding)
          CryptBot per Microsoft, TrendMicro, Antiy, alibabacloud
Compiled  2026-08-21, one day before the loader
```

It brands itself in its own log template, including a `%worker%` affiliate
identifier — this is malware-as-a-service, sold to resellers.

**Not a first capture.** The same payload has been on VirusTotal since
2026-08-23, uploaded as `Stealer_1.0.1_chunk_0_export.bin` — someone else had
already exported it from the registry chunks.

Three things about it are worth flagging beyond the usual credential theft:

- **Chrome App-Bound Encryption is defeated**, via
  `NCryptOpenKey("Google Chromekey1")` plus token impersonation. Chrome 127+
  cookie protection does not stop it.
- **Browser `Web Data` is copied wholesale**, which includes the
  `local_stored_cvc` / `server_stored_cvc` tables. Stored card CVCs go with it.
- **Wallet extensions are copied, not cracked** — there is no vault-decryption
  code at all. Locking a wallet does not protect it: the encrypted vault sits on
  disk regardless, and cracking happens offline, often with the password taken
  from the same haul.

It also targets **AI CLI credentials** — `~/.claude/auth.json`,
`.codex/oauth_creds.json`, `.gemini/google_accounts.json`. Any host running
those CLIs at infection time had those sessions taken.

Conversely, it has **no send capability** and imports no HTTP or TLS library, so
it cannot post messages itself. Scam messages sent from a victim's accounts come
from the operator replaying stolen tokens server-side — which reinstalling the
host does not remedy.

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
    suricata.rules        8 network rules, each with a false-positive rating
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

**Suricata/Snort** — 8 rules, each annotated with a false-positive rating and a
deployment recommendation. Five are safe to run always (the hardcoded RFC 6455
handshake key, its strict 152-byte form, the C2 address, the `GET /task/`
payload request, and the stealer's exfiltration greeting); one is scoped to the
C2 ports; two are hunting-only and one of those ships commented out.

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