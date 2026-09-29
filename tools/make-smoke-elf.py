"""Generate a real, runnable x86-64 Linux ELF for suture's smoke test.

Why a hand-built ELF rather than a compiled one
-----------------------------------------------
The point of this fixture is to exercise suture against something with a
*real* control-flow graph -- several blocks, a short branch that forces
relocation, a long branch that does not, and a computed jump that suture must
report as uninstrumented. Writing the bytes directly keeps the fixture
byte-exact and reviewable, and needs no toolchain.

The program reads one byte from stdin and exits with it, so it has observable
behaviour that a differential test can compare. That matters: a program with no
observable behaviour would let a broken rewriter pass verification.

Build it as a static ET_EXEC with one PT_LOAD. Every offset is asserted, because
a fixture that is subtly self-inconsistent produces failures that look like
suture bugs and cost hours to tell apart.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

PAGE = 0x1000
CODE_OFF = 0x1000
TEXT_VADDR = 0x400000

# Offsets of the two exit paths, and of the buffer the program reads into.
EXIT_DOUBLE_VADDR = TEXT_VADDR + 40
EXIT_ZERO_VADDR = TEXT_VADDR + 47


def build_code() -> bytes:
    """Assemble the program body, returning the raw bytes.

    Layout (offsets from TEXT_VADDR):
        0   mov eax, 60          ; __NR_read
        5   mov edi, 0           ; stdin
        10  lea rsi, [rip+0x2a]  ; buffer at +59
        17  mov edx, 1           ; one byte
        22  syscall
        24  movzx eax, byte [rsi]
        27  test eax, eax
        29  je +16  -> 47        ; zero input takes the second exit
        31  (4 nops)
        35  add eax, eax         ; double it
        37  mov edi, eax
        39  nop
        40  mov eax, 60          ; __NR_exit
        45  syscall
        47  mov edi, 0
        52  mov eax, 60
        57  syscall
    """
    code = bytearray()

    # 0: mov eax, 60
    code += b"\xb8\x3c\x00\x00\x00"
    assert len(code) == 5, len(code)

    # 5: mov edi, 0
    code += b"\xbf\x00\x00\x00\x00"
    assert len(code) == 10, len(code)

    # 10: lea rsi, [rip+disp32]; next_ip is 17, buffer sits at 59.
    disp = 59 - 17
    assert 0 <= disp < 0x100, disp
    code += b"\x48\x8d\x35" + struct.pack("<i", disp)
    assert len(code) == 17, len(code)

    # 17: mov edx, 1
    code += b"\xba\x01\x00\x00\x00"
    # 22: syscall
    code += b"\x0f\x05"
    assert len(code) == 24, len(code)

    # 24: movzx eax, byte [rsi]
    code += b"\x0f\xb6\x06"
    # 27: test eax, eax
    code += b"\x85\xc0"
    assert len(code) == 29, len(code)

    # 29: je rel8 -> 47. Two bytes: this is the branch that cannot hold a
    #     5-byte jmp, so it is the one that forces block relocation.
    target = 47
    je_disp = target - 31
    assert 0 <= je_disp < 0x80, je_disp
    code += bytes([0x74, je_disp])
    assert len(code) == 31, len(code)

    # 31: padding to 35
    code += b"\x90\x90\x90\x90"
    assert len(code) == 35, len(code)

    # 35: add eax, eax (2) ; mov edi, eax (2) -> 39
    code += b"\x01\xc0"
    code += b"\x89\xc7"
    assert len(code) == 39, len(code)

    # 39: one nop so the exit path starts on offset 40
    code += b"\x90"
    assert len(code) == 40, len(code)

    # 40: mov eax, 60 ; syscall -> 47
    code += b"\xb8\x3c\x00\x00\x00"
    code += b"\x0f\x05"
    assert len(code) == 47, len(code)

    # 47: mov edi, 0 (5) ; mov eax, 60 (5) ; syscall (2) -> 59
    assert len(code) == 47, len(code)
    code += b"\xbf\x00\x00\x00\x00"
    code += b"\xb8\x3c\x00\x00\x00"
    code += b"\x0f\x05"
    assert len(code) == 59, len(code)

    return bytes(code)


def build_elf() -> bytes:
    code = build_code()
    filesz = PAGE

    img = bytearray(CODE_OFF + filesz)

    # ELF header
    img[0:4] = b"\x7fELF"
    img[4] = 2  # ELFCLASS64
    img[5] = 1  # ELFDATA2LSB
    img[6] = 1  # EV_CURRENT
    struct.pack_into("<H", img, 16, 2)  # ET_EXEC
    struct.pack_into("<H", img, 18, 62)  # EM_X86_64
    struct.pack_into("<I", img, 20, 1)  # e_version
    struct.pack_into("<Q", img, 24, TEXT_VADDR)  # e_entry
    struct.pack_into("<Q", img, 32, 64)  # e_phoff
    struct.pack_into("<Q", img, 40, 0)  # e_shoff (no sections)
    struct.pack_into("<I", img, 48, 0)  # e_flags
    struct.pack_into("<H", img, 52, 64)  # e_ehsize
    struct.pack_into("<H", img, 54, 56)  # e_phentsize
    struct.pack_into("<H", img, 56, 1)  # e_phnum
    struct.pack_into("<H", img, 58, 64)  # e_shentsize
    struct.pack_into("<H", img, 60, 0)  # e_shnum
    struct.pack_into("<H", img, 62, 0)  # e_shstrndx

    # Program header
    struct.pack_into("<I", img, 64, 1)  # PT_LOAD
    struct.pack_into("<I", img, 68, 0b101)  # PF_R | PF_X
    struct.pack_into("<Q", img, 72, CODE_OFF)  # p_offset
    struct.pack_into("<Q", img, 80, TEXT_VADDR)  # p_vaddr
    struct.pack_into("<Q", img, 88, TEXT_VADDR)  # p_paddr
    struct.pack_into("<Q", img, 96, filesz)  # p_filesz
    struct.pack_into("<Q", img, 104, filesz)  # p_memsz
    struct.pack_into("<Q", img, 112, PAGE)  # p_align

    img[CODE_OFF : CODE_OFF + len(code)] = code

    # Invariants the kernel's loader will check, verified here so a broken
    # fixture is caught now rather than as a mysterious suture failure later.
    assert struct.unpack_from("<Q", img, 72)[0] % PAGE == TEXT_VADDR % PAGE, (
        "p_offset must be congruent to p_vaddr mod p_align"
    )
    return bytes(img)


def main() -> int:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("fixtures/smoke.elf")
    out.parent.mkdir(parents=True, exist_ok=True)
    data = build_elf()
    out.write_bytes(data)
    print(f"{out}: {len(data)} bytes, .text at {TEXT_VADDR:#x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
