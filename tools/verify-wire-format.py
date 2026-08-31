#!/usr/bin/env python3
"""
verify-wire-format.py -- prove that the payload travels the wire as a raw,
unencrypted PE (specifically a DLL). Supports section 7 of analysis.md.

Two independent lines of evidence:

  1) 0x140005FB0 is a PE format validator (MZ / PE\0\0 / IMAGE_FILE_DLL).
     In the download routine it is called after closesocket() and before
     RegCreateKeyA() -- i.e. directly on the freshly received buffer.
     If the magic values match there, nothing encrypted the stream.

  2) 0x140010FB0, the helper called inside the recv loop, is a plain memcpy:
     zero real xor, zero bit-rotation instructions. Nothing decrypts on the
     receive path either.

Static analysis only. Reads the sample as bytes; executes nothing.

Usage:  python verify-wire-format.py [path-to-sample]
        RB_SAMPLE=... python verify-wire-format.py
"""
import os
import sys

import capstone
import pefile

SAMPLE = (sys.argv[1] if len(sys.argv) > 1
          else os.environ.get("RB_SAMPLE")
          or os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "RuntimeBroker.exe.sample"))

pe = pefile.PE(SAMPLE)
IB = pe.OPTIONAL_HEADER.ImageBase
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)


def read_va(va, n):
    """Read n bytes at a virtual address."""
    for s in pe.sections:
        lo = IB + s.VirtualAddress
        hi = lo + max(s.Misc_VirtualSize, s.SizeOfRawData)
        if lo <= va < hi:
            return s.get_data()[va - lo:va - lo + n]
    return b""


def disasm_fn(start, window=0x400, min_len=0x60):
    """Disassemble until the ret that ends the function."""
    ins = list(md.disasm(read_va(start, window), start))
    end = None
    for i in ins:
        if i.mnemonic == "ret":
            end = i.address
            if i.address > start + min_len:
                break
    return [i for i in ins if end is None or i.address <= end]


print("=" * 68)
print("Evidence 1  0x140005FB0 -- PE format validator (not a decryptor)")
print("=" * 68)
MAGIC = {
    "0x40":   "sizeof(IMAGE_DOS_HEADER)   minimum length",
    "0x5a4d": "'MZ'     IMAGE_DOS_SIGNATURE",
    "0x4550": "'PE\\0\\0'  IMAGE_NT_SIGNATURE",
    "0x2000": "IMAGE_FILE_DLL            <- payload must be a DLL",
}
for i in disasm_fn(0x140005FB0):
    if i.mnemonic in ("cmp", "and", "test"):
        for k, v in MAGIC.items():
            if k in i.op_str.lower():
                print("  0x%-11x %-5s %-32s  <- %s"
                      % (i.address, i.mnemonic, i.op_str, v))

print()
print("=" * 68)
print("Evidence 2  0x140010FB0 -- helper called inside the recv loop")
print("=" * 68)
body = disasm_fn(0x140010FB0, window=0x200, min_len=0x90)
size = body[-1].address + body[-1].size - 0x140010FB0
print("  extent 0x%x .. 0x%x   (%d instructions / %d bytes)"
      % (0x140010FB0, body[-1].address, len(body), size))

BITOPS = ("rol", "ror", "shl", "shr", "sar", "not", "neg", "pxor", "bswap", "xorps")
real_xor, zero_xor, bitops, byteops = [], [], [], []
for i in body:
    if i.mnemonic == "xor":
        ops = [o.strip() for o in i.op_str.split(",")]
        (zero_xor if len(ops) == 2 and ops[0] == ops[1] else real_xor).append(i)
    elif i.mnemonic in BITOPS:
        bitops.append(i)
    if "byte ptr" in i.op_str:
        byteops.append(i)

print("    xor reg,reg (zeroing idiom) : %d" % len(zero_xor))
print("    real xor                    : %d   <- 0 means no decryption on the recv path"
      % len(real_xor))
print("    rol/ror/shl/shr/not/neg     : %d" % len(bitops))
print("    byte-level memory accesses  : %d   %s"
      % (len(byteops),
         ["0x%x %s %s" % (i.address, i.mnemonic, i.op_str) for i in byteops]))

ok = not real_xor and not bitops and len(byteops) == 2
print()
print("Conclusion: " + ("plain memcpy -- the wire carries an unmodified PE (DLL)."
                        if ok else "transform instructions present; review manually."))
sys.exit(0 if ok else 1)