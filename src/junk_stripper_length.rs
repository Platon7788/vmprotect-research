//! Instruction-length decoder used by `junk_stripper`.
//!
//! Split out of `junk_stripper.rs` via `#[path]` include so the
//! stripper impl file stays under the project's 500-line ceiling
//! (see `CLAUDE.md`).
//!
//! Scope: enough of the x86 / x86-64 encoding to walk past the
//! instructions handler bodies contain (arithmetic and logic with
//! ModR/M, push/pop reg, immediates, near JMP/CALL, `FF /*` group,
//! and a handful of two-byte 0F escapes). Unknown opcodes return
//! None so the caller can fall back to byte-by-byte advancement —
//! never guessed lengths, since a wrong length would misalign every
//! subsequent junk-pattern check.

use crate::Bitness;

/// Read an optional REX prefix. Returns `(Some(rex), pos+1)` on a REX
/// prefix in x64 mode, `(None, pos)` otherwise (crucially: on x86,
/// 0x40..0x4F are INC/DEC r32 — real instructions, not prefixes).
pub(super) fn read_rex(bytecode: &[u8], pos: usize, bitness: Bitness) -> (Option<u8>, usize) {
    match bytecode.get(pos).copied() {
        Some(b @ 0x40..=0x4F) if bitness == Bitness::X64 => (Some(b), pos + 1),
        _ => (None, pos),
    }
}

/// Determine the encoded length of the instruction starting at `pos`.
/// Returns None for opcodes not in the recognised set — the caller
/// falls back to byte-by-byte advancement.
pub(super) fn instruction_length(bytecode: &[u8], pos: usize, bitness: Bitness) -> Option<usize> {
    let start = pos;
    let mut p = pos;

    // Consume "outer" prefixes that don't affect length beyond their own byte.
    let mut has_66 = false;
    loop {
        match bytecode.get(p).copied() {
            Some(0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 | 0x67 | 0xF0 | 0xF2 | 0xF3) => p += 1,
            Some(0x66) => {
                has_66 = true;
                p += 1;
            }
            _ => break,
        }
    }

    // REX (x64 only). We remember whether we consumed one so the
    // MOV EAX, imm branch can pick imm64 vs imm32 correctly.
    let rex_start = p;
    if bitness == Bitness::X64 {
        if let Some(0x40..=0x4F) = bytecode.get(p).copied() {
            p += 1;
        }
    }
    let rex_end = p;

    let op = bytecode.get(p).copied()?;
    p += 1;

    if op == 0x0F {
        return length_two_byte(bytecode, start, p);
    }

    match op {
        // Single-byte no-operand ops.
        0x90..=0x97 | 0x98 | 0x99 | 0x9C | 0x9D | 0xC3 | 0xCB | 0xF4 | 0x60 | 0x61 | 0xCE | 0xCC | 0xCF => {
            Some(p - start)
        }

        // PUSH/POP reg.
        0x50..=0x5F => Some(p - start),

        // INC/DEC r32 on x86 only (already handled as REX on x64 above).
        0x40..=0x4F if bitness == Bitness::X86 => Some(p - start),

        // Group ops with ModR/M and no immediate.
        0x00..=0x03
        | 0x08..=0x0B
        | 0x10..=0x13
        | 0x18..=0x1B
        | 0x20..=0x23
        | 0x28..=0x2B
        | 0x30..=0x33
        | 0x38..=0x3B
        | 0x84..=0x8B
        | 0x8D
        | 0x8F
        | 0x63 => {
            let m = parse_modrm_length(bytecode, p)?;
            Some(p + m - start)
        }

        // Group 1: 83 /n imm8.
        0x83 => {
            let m = parse_modrm_length(bytecode, p)?;
            Some(p + m + 1 - start)
        }

        // Group 1: 81 /n imm16/imm32.
        0x81 => {
            let m = parse_modrm_length(bytecode, p)?;
            Some(p + m + if has_66 { 2 } else { 4 } - start)
        }

        // 69 /r imm32, 6B /r imm8 — IMUL with immediate.
        0x69 => {
            let m = parse_modrm_length(bytecode, p)?;
            Some(p + m + if has_66 { 2 } else { 4 } - start)
        }
        0x6B => {
            let m = parse_modrm_length(bytecode, p)?;
            Some(p + m + 1 - start)
        }

        // MOV r/m8, imm8 / MOV r/m, imm16/32.
        0xC6 => {
            let m = parse_modrm_length(bytecode, p)?;
            Some(p + m + 1 - start)
        }
        0xC7 => {
            let m = parse_modrm_length(bytecode, p)?;
            Some(p + m + if has_66 { 2 } else { 4 } - start)
        }

        // MOV AL/AX/EAX, imm.
        0xB0..=0xB7 => Some(p + 1 - start),
        0xB8..=0xBF => {
            // With REX.W the immediate becomes 8 bytes; otherwise it
            // follows the operand-size (66h halves 32 to 16).
            let rex_w = (rex_start..rex_end).any(|k| matches!(bytecode.get(k).copied(), Some(0x48..=0x4F)));
            let imm = if rex_w {
                8
            } else if has_66 {
                2
            } else {
                4
            };
            Some(p + imm - start)
        }

        // Immediate arithmetic against AL/AX/EAX (ADD/OR/ADC/SBB/AND/SUB/XOR/CMP AL, imm8 / EAX, imm32).
        0x04 | 0x0C | 0x14 | 0x1C | 0x24 | 0x2C | 0x34 | 0x3C => Some(p + 1 - start),
        0x05 | 0x0D | 0x15 | 0x1D | 0x25 | 0x2D | 0x35 | 0x3D => Some(p + if has_66 { 2 } else { 4 } - start),

        // TEST/NOT/NEG/MUL/IMUL/DIV/IDIV — F6/F7 groups.
        0xF6 => {
            let modrm = *bytecode.get(p)?;
            let subop = (modrm >> 3) & 0x07;
            let m = parse_modrm_length(bytecode, p)?;
            // TEST (/0 /1) has imm8; others take no immediate.
            let imm = if subop <= 1 { 1 } else { 0 };
            Some(p + m + imm - start)
        }
        0xF7 => {
            let modrm = *bytecode.get(p)?;
            let subop = (modrm >> 3) & 0x07;
            let m = parse_modrm_length(bytecode, p)?;
            let imm_bytes = if has_66 { 2 } else { 4 };
            let imm = if subop <= 1 { imm_bytes } else { 0 };
            Some(p + m + imm - start)
        }

        // JCC rel8 / short-jump / loop.
        0x70..=0x7F | 0xE0..=0xE3 | 0xEB => Some(p + 1 - start),

        // JMP/CALL rel32.
        0xE8 | 0xE9 => Some(p + 4 - start),

        // JMP/CALL/PUSH/INC/DEC — FF group.
        0xFF => {
            let m = parse_modrm_length(bytecode, p)?;
            Some(p + m - start)
        }

        // RET imm16.
        0xC2 | 0xCA => Some(p + 2 - start),

        // INT imm8.
        0xCD => Some(p + 1 - start),

        _ => None,
    }
}

fn length_two_byte(bytecode: &[u8], start: usize, p_after_0f: usize) -> Option<usize> {
    let mut p = p_after_0f;
    let op2 = bytecode.get(p).copied()?;
    p += 1;
    match op2 {
        // NOP r/m, PREFETCH, fences — all take ModR/M.
        0x1F | 0x18..=0x1E | 0xAE => {
            let m = parse_modrm_length(bytecode, p)?;
            Some(p + m - start)
        }
        // RDTSC / CPUID — no ModR/M.
        0x31 | 0xA2 => Some(p - start),
        // JCC rel32.
        0x80..=0x8F => Some(p + 4 - start),
        // MOVZX / MOVSX r, r/m8|r/m16 — ModR/M.
        0xB6 | 0xB7 | 0xBE | 0xBF => {
            let m = parse_modrm_length(bytecode, p)?;
            Some(p + m - start)
        }
        _ => None,
    }
}

/// Length of ModR/M byte plus SIB and displacement bytes. `pos`
/// points at the ModR/M byte itself.
pub(super) fn parse_modrm_length(bytecode: &[u8], pos: usize) -> Option<usize> {
    let modrm = *bytecode.get(pos)?;
    let mode = (modrm >> 6) & 0x03;
    let rm = modrm & 0x07;
    let mut len = 1usize;

    if mode == 0b11 {
        return Some(len);
    }

    // SIB byte present when rm==4 in mem-form modes.
    let has_sib = rm == 4;
    if has_sib {
        len += 1;
    }

    match mode {
        0b00 => {
            if rm == 5 {
                // disp32 (x86 absolute; x64 RIP-relative)
                len += 4;
            } else if has_sib {
                let sib = *bytecode.get(pos + 1)?;
                if (sib & 0x07) == 5 {
                    len += 4;
                }
            }
        }
        0b01 => len += 1, // disp8
        0b10 => len += 4, // disp32
        _ => unreachable!(),
    }

    Some(len)
}
