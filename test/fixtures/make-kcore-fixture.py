#!/usr/bin/env python3
"""Build a minimal /proc/kcore-shaped ELF for the self-test.

This is a test-fixture generator, not part of kernel-check.sh.  It wraps a
chunk of real kernel text in an ELF64 with one PT_LOAD program header whose
p_vaddr is the runtime address of reqsk_timer_handler and whose p_offset
points at the bytes.  kernel-check.sh's map_vaddr() then reads it exactly the
way it reads a real /proc/kcore.

usage: make-kcore-fixture.py <function.bin> <vaddr> <out.elf>
"""
import struct
import sys

raw = open(sys.argv[1], "rb").read()
vaddr = int(sys.argv[2], 0)
out = sys.argv[3]

phoff = 64
phentsize = 56
textoff = phoff + phentsize

ehdr = bytearray(64)
struct.pack_into("<4sBBBBB7x", ehdr, 0, b"\x7fELF", 2, 1, 1, 0, 0)
# e_type=ET_EXEC, e_machine=x86-64, e_version=1, e_entry=0, e_phoff, e_shoff=0,
# e_flags=0, e_ehsize=64, e_phentsize=56, e_phnum=1, e_shentsize=64, e_shnum=0,
# e_shstrndx=0
struct.pack_into("<HHIQQQIHHHHHH", ehdr, 16, 2, 62, 1, 0, phoff, 0, 0, 64, phentsize, 1, 64, 0, 0)

ph = bytearray(phentsize)
# p_type=PT_LOAD, p_flags=R|X, p_offset=textoff, p_vaddr=vaddr,
# p_paddr=vaddr, p_filesz=len(raw), p_memsz=len(raw), p_align=0x1000
struct.pack_into("<IIQQQQQQ", ph, 0, 1, 5, textoff, vaddr, vaddr, len(raw), len(raw), 0x1000)

with open(out, "wb") as f:
    f.write(ehdr)
    f.write(ph)
    f.write(raw)
print("wrote", out, textoff + len(raw))
