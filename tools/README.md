# Tools

Analysis harness used to produce [`../analysis.md`](../analysis.md).

Everything here is **static analysis or CPU emulation**. The sample is never
executed natively. Unicorn is a CPU emulator with no operating system beneath
it: `syscall` has nowhere to dispatch and every API call lands on a stub
address inside the emulator's own memory map.

No script imports `socket`, `subprocess`, `ctypes`, `winreg`, `requests` or
`urllib`. `os` is used only for path joining. Output is written to the working
directory (`beacon_*.bin`, `coverage.json`).

## Requirements

```
python 3.11
pip install unicorn capstone pefile
```

## Sample path

None of the scripts hardcode a path. Each resolves the sample in this order:

```
python <script>.py /path/to/RuntimeBroker.exe.sample     # argv[1]
RB_SAMPLE=/path/to/sample python <script>.py             # environment
                                                          # else: ./RuntimeBroker.exe.sample
```

The sample is not in this repository — see [`../samples/`](../samples/).

## Scripts

| Script | What it does | Analysis section |
|---|---|---|
| `emu-unpack-RuntimeBroker.py` | Main harness. Maps the PE, builds a synthetic TEB/PEB/TLS, stubs the IAT, answers every anti-analysis probe with a plausible value, fakes the socket layer to capture C2 traffic, dumps coverage. | 2, 4, 5 |
| `emu-trace-callers.py` | Same harness plus entry hooks that record the stack-top return address and register arguments for chosen functions. This is how the VMProtect-dissolved call site of `0x140015870` was identified. | 4.1, 10 |
| `decrypt-strings-RuntimeBroker.py` | Invokes each of the 63 string-decryption thunks in an isolated Unicorn instance (300k instruction cap, 5s timeout, no API stubs) and collects the plaintext. Does not run the sample body. | 1 |
| `decrypt-strings-pass2-TLS.py` | Second pass. Some thunks write their output into a TLS slot rather than `.rdata`; this adds TLS differential probing and recovers the config strings the first pass missed. | 4.1 |
| `recover-api-table.py` | Statically reconstructs the dynamic API table by running each resolver's name thunks, mapping `.data` slots to API names. | 9 |
| `verify-wire-format.py` | Standalone, static only, no Unicorn. Reproduces the two proofs that the wire format is an unencrypted PE. Exits 0 on success. | 7 |

`verify-wire-format.py` is the quickest way to sanity-check the headline claim:

```
$ python verify-wire-format.py RuntimeBroker.exe.sample
...
Conclusion: plain memcpy -- the wire carries an unmodified PE (DLL).
```

## A note on language

`verify-wire-format.py` is documented in English. The larger emulation scripts
carry their original Chinese inline comments and console output; they were
written as working analysis tools, not as a library. Behaviour is unaffected.

## Residual risk

Unicorn is C code parsing an attacker-controlled instruction stream. A
memory-safety bug in Unicorn is theoretically exploitable by a sample crafted
for it. The probability is low — this sample targets Windows, not Unicorn — but
it is not zero, and it is the only genuine exposure in this workflow. Run these
in a VM if that matters to you.