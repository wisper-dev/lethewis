#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
# SPDX-License-Identifier: AGPL-3.0-only

"""The comparison of key identifiers runs straight through on every target below: no branch, no call
and no write of the program counter.

The core is compiled to assembly as a library, optimised, before any link-time optimisation, for
each target, and the body of `KeyId::is` is read out of it. Every instruction in the body has to be
one of a set known not to move control, and on every target but WebAssembly, whose functions end
without one, the last has to be an unconditional return. An instruction outside that set fails the
check, whatever it does, as do a directive other than those that only describe the code and a body
that cannot be found or holds no instruction. Before that, the rules are run on known instructions.
This shows how this compiler laid out the code; it says nothing about how long each instruction
takes on a given processor, nor, for WebAssembly, about the code a runtime makes of it. It reads
instructions, not the data they move, so a return to an address the body itself changed passes.
"""

import re
import subprocess
import sys
from pathlib import Path

SYMBOL = re.compile(r"^(_RNv\S*13lethewis_core6derive\S*5KeyId2is):\s*$")
# A name of that shape, for the listings the rules are run on.
NAME = "_RNvMNtCs0_13lethewis_core6deriveNtB2_5KeyId2is"
END = re.compile(r"^\s*(\.Lfunc_end\d+:|end_function\b|\.size\b)")

X86 = "x86_64-unknown-linux-gnu"
AARCH64 = "aarch64-unknown-linux-gnu"
THUMB = "thumbv7em-none-eabihf"
WASM = "wasm32-unknown-unknown"
TARGETS = (X86, AARCH64, THUMB, WASM)

COMMENTS = {X86: "#", AARCH64: "//", THUMB: "@", WASM: "#"}
# Directives that describe the code, for unwinding or as the signature and locals of a WebAssembly
# function, and emit none of it.
ANNOTATIONS = re.compile(r"^\.(cfi_[a-z_]+|fnstart|fnend|cantunwind|save|vsave|pad|setfp|functype"
                         r"|local)$")
CONDITIONS = "eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al"
# Mnemonics that never move control. A Thumb instruction from this set can still write the program
# counter, which is checked apart.
STRAIGHT = {
    X86: re.compile(
        r"^(v?mov[a-z0-9]*|cmov[a-z]+|set[a-z]+|lea[a-z]?|(xor|or|and|andn|not|neg|add|adc|sub"
        r"|sbb|cmp|test|shl|shr|sar|rol|ror|inc|dec|push|pop|bswap|nop)[bwlq]?|v?p[a-z0-9]+"
        r"|vzeroupper)$"),
    AARCH64: re.compile(
        r"^(adds?|subs?|ands?|orr|orn|eor|eon|bics?|mvn|negs?|mov[knz]?|cmp|cmn|tst|cs(el|inc|inv"
        r"|neg|et|etm)|cin[cv]|cneg|ccmp|ccmn|ldu?r[bh]?|ldrs[bhw]|ldp|stu?r[bh]?|stp|lsl|lsr|asr"
        r"|ror|[su]bfx|ubfiz|bfi|bfxil|extr|[su]xt[bhw]|rev(16|32)?|clz|adrp?|mul|madd|msub|fmov"
        r"|dup|ins|umov|cmeq|u(min|max)v|addv|ld1|st1|nop)$"),
    THUMB: re.compile(
        rf"^(it[te]{{0,3}}|(adc|add|sbc|sub|rsb|and|orr|orn|eor|bic|mvn|mov|movw|movt|cmp|cmn|tst"
        rf"|teq|lsl|lsr|asr|ror|rrx|ldr|ldrb|ldrh|ldrsb|ldrsh|ldrd|ldm|ldmia|ldmdb|str|strb|strh"
        rf"|strd|stm|stmia|stmdb|push|pop|[su]bfx|bfi|bfc|[su]xt[bh]|rev|clz|mul|mla|mls|[su]mull"
        rf"|sel|uadd8|usub8|nop|adr)s?({CONDITIONS})?(\.[nw])?)$"),
    WASM: re.compile(
        r"^(local\.(get|set|tee)|global\.(get|set)|select|drop|nop|i(32|64)\.(const|add|sub|mul"
        r"|and|or|xor|shl|shr_[su]|rotl|rotr|eqz?|ne|[lg][te]_[su]|clz|ctz|popcnt"
        r"|load(8_[su]|16_[su]|32_[su])?|store(8|16|32)?|extend(8|16|32)_s|extend_i32_[su]"
        r"|wrap_i64))$"),
}
# The unconditional return a body has to end in.
RETURNS = {X86: {"ret", "retq"}, AARCH64: {"ret"}, THUMB: {"bx lr"}, WASM: set()}

# Known instructions: whether the rules let each through, in the middle of a body.
KNOWN = {
    X86: {"cmovneq %rax, %rcx": True, "vpxor %xmm0, %xmm1, %xmm1": True, "nop": True,
          ".cfi_startproc": True, "jne .LBB0_1": False, "jmp f": False, "callq f": False,
          "loop .LBB0_1": False, "jrcxz .LBB0_1": False, "notrack jmpq *%rax": False,
          "data16 callq f": False, "xbegin .LBB0_1": False, "ljmpq *(%rax)": False, "retq": False,
          ".byte 0x75, 0x02": False, "xorl %eax, %eax; jne f": False, "JNE f": False},
    AARCH64: {"csel x0, x1, x2, ne": True, "ldrb w8, [x0]": True, ".cfi_def_cfa_offset 16": True,
              "b.ne .LBB0_1": False, "b f": False, "bl f": False, "br x0": False, "blr x0": False,
              "cbgt x0, #1, .LBB0_1": False, "braa x0, x1": False, "tbz w0, #0, .LBB0_1": False,
              "ret": False, ".inst 0x54000041": False},
    THUMB: {"rsbs.w r12, r2, #0": True, "movne r0, #1": True, "ldr r0, [pc, #8]": True,
            "it ne": True, "pop {r4, r5}": True, "bne .LBB0_1": False, "b .LBB0_1": False,
            "b.w f": False, "bxne lr": False, "pophi {r4, pc}": False, "ldr pc, [r0]": False,
            "mov pc, lr": False, "add pc, r0": False, "ldmea r0, {r1, pc}": False,
            "tbb [pc, r0]": False, "pop {r4, r15}": False, "bl f": False,
            "cbz r0, .LBB0_1": False, ".save {r7, lr}": True, ".word 0xd1004770": False,
            "movs r0, #0; bne f": False, "ldr PC, [r0]": False},
    WASM: {"i32.xor": True, "local.get 0": True, ".local i32": True, "br 0": False,
           "br_if 0": False, "br_table 0, 1": False, "if i32": False, "call f": False,
           "call_indirect 0": False,
           "return_call f": False, "call_ref 0": False, "i32.div_u": False, "return": False},
}
# Known last instructions: whether a body may end in each.
KNOWN_ENDS = {
    X86: {"retq": True, "ret": True, "jmp f": False, "retq $8": False},
    AARCH64: {"ret": True, "ret x1": False, "b f": False, "retaa": False},
    THUMB: {"bx lr": True, "pop {r7, pc}": True, "pop.w {r4, r5, r6, pc}": True,
            "pop {r4, r5}": False, "popne {r7, pc}": False, "bx r1": False, "b f": False},
}


def body(target: str, assembly: str) -> list[str]:
    lines = assembly.split("\n")
    for start, line in enumerate(lines):
        if SYMBOL.match(line):
            break
    else:
        return []
    instructions = []
    for line in lines[start + 1:]:
        if END.match(line):
            break
        for statement in line.split(COMMENTS[target], 1)[0].lower().split(";"):
            text = " ".join(statement.split())
            if text and not text.endswith(":") and not ANNOTATIONS.match(text.split()[0]):
                instructions.append(text)
    return instructions


def writes_pc(name: str, operands: str) -> bool:
    """Whether a Thumb instruction writes the program counter: as its first operand, or in a list of
    registers it loads."""
    pc = r"\b(pc|r15)\b"
    if re.match(r"(pop|ldm)", name):
        return re.search(r"\{[^}]*" + pc, operands) is not None
    return re.match(pc, operands) is not None


def returns(target: str, instruction: str) -> bool:
    name, _, operands = instruction.partition(" ")
    if target == THUMB and name in ("pop", "pop.w"):
        return writes_pc(name, operands)
    return instruction in RETURNS[target]


def refused(target: str, instructions: list[str]) -> list[str]:
    """Every instruction not known to run straight through, apart from the return at the end, and a
    missing return."""
    found = []
    for index, instruction in enumerate(instructions):
        if index == len(instructions) - 1 and returns(target, instruction):
            continue
        name, _, operands = instruction.partition(" ")
        if not STRAIGHT[target].match(name) or target == THUMB and writes_pc(name, operands):
            found.append(instruction)
    if RETURNS[target] and instructions and not returns(target, instructions[-1]):
        found.append(f"no return at the end: {instructions[-1]}")
    return found


def listing(lines: list[str]) -> str:
    return "\n".join([f"{NAME}:", *(f"\t{line}" for line in lines), ".Lfunc_end0:"])


def rules_hold() -> list[str]:
    wrong = []
    for target, known in KNOWN.items():
        end = sorted(RETURNS[target])[:1]
        for instruction, through in known.items():
            if (not refused(target, body(target, listing([instruction] + end)))) != through:
                verdict = "refused" if through else "let through"
                wrong.append(f"{target}: {instruction} is {verdict}")
    for target, known in KNOWN_ENDS.items():
        for instruction, ends in known.items():
            if (not refused(target, body(target, listing(["nop", instruction])))) != ends:
                wrong.append(f"{target}: a body ending in {instruction} is "
                             f"{'refused' if ends else 'let through'}")
    return wrong


def main() -> int:
    root = Path(subprocess.run(["git", "rev-parse", "--show-toplevel"], check=True,
                               capture_output=True, text=True).stdout.strip())
    problems = rules_hold()
    if problems:
        for problem in problems:
            print(f"constant-time: the rules are wrong: {problem}", file=sys.stderr)
        return 1
    out = root / "target" / "constant-time"
    out.mkdir(parents=True, exist_ok=True)
    for target in TARGETS:
        assembly = out / f"{target}.s"
        assembly.unlink(missing_ok=True)
        # A build Cargo counts as fresh would not write the assembly again.
        subprocess.run(["cargo", "clean", "-p", "lethewis-core", "--release", "--target", target],
                       cwd=root, check=True, capture_output=True)
        subprocess.run(["cargo", "rustc", "-p", "lethewis-core", "--lib", "--release", "--locked",
                        "--target", target, "--", "--emit", f"asm={assembly}",
                        "-C", "codegen-units=1"], cwd=root, check=True)
        if not assembly.is_file():
            problems.append(f"{target}: no assembly was written")
            continue
        instructions = body(target, assembly.read_text())
        if not instructions:
            problems.append(f"{target}: the comparison of key identifiers is not in the assembly")
            continue
        found = sorted(set(refused(target, instructions)))
        problems.extend(f"{target}: {instruction}" for instruction in found)
        print(f"constant-time: {target}: {len(instructions)} instructions, "
              f"{len(found) or 'none'} refused")
    for problem in problems:
        print(f"constant-time: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
