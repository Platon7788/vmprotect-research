//! Instruction-effect decoder used by Groups E/F/G of `junk_stripper`.
//!
//! Split out of `junk_stripper.rs` via `#[path]` include so the impl
//! file stays under the project's 500-line ceiling (see `CLAUDE.md`),
//! same convention as `junk_stripper_length.rs`. Per-opcode decoding
//! bodies live in the sibling `junk_stripper_effects_helpers.rs` for
//! the same reason.
//!
//! Scope: enough decoding to compute a (writes, reads) GPR bitmap and
//! identify the small set of shapes Groups E/F need for pair
//! cancellation and dead-store elimination. Anything we can't fully
//! classify falls through to a length-only advance with conservative
//! `writes = reads = R_ALL`, which the callers treat as "blocks all
//! folds crossing it" — safe by construction, at the cost of missing a
//! few folds that would need a full disassembler to prove.

use super::length::{instruction_length, read_rex};
use crate::Bitness;

// Per-opcode decoding helpers. Package-private, only reached via the
// top-level `decode` below.
#[path = "junk_stripper_effects_helpers.rs"]
mod helpers;
use helpers::{
    decode_f7_group, decode_ff_group, decode_group1_imm, decode_lea, decode_mov_89, decode_mov_8b, decode_mov_c7,
    nop_insn,
};

/// GPR bitmap covering both x86 (r0..=r7) and x64 (r0..=r15).
pub(super) const R_ALL: u16 = 0xFFFF;
/// Empty bitmap constant — spelled out so grep-for-`R_NONE` finds the
/// intended "no reg touched" call sites over a bare `0`.
pub(super) const R_NONE: u16 = 0;

/// Kind of instruction, precise enough for pair-cancel matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    /// `add reg, imm` — imm sign-extended into i32 (imm8 forms live in
    /// the -128..=127 window; imm32 forms use the full range).
    AddRegImm { reg: u8, imm: i32 },
    /// `sub reg, imm`.
    SubRegImm { reg: u8, imm: i32 },
    /// `xor reg, imm`.
    XorRegImm { reg: u8, imm: i32 },
    /// `inc reg` — FF /0 or (x86-only) 0x40..=0x47.
    IncReg(u8),
    /// `dec reg` — FF /1 or (x86-only) 0x48..=0x4F.
    DecReg(u8),
    /// `neg reg` — F7 /3.
    NegReg(u8),
    /// `not reg` — F7 /2.
    NotReg(u8),
    /// `mov reg, ...` where the destination is a GPR (no memory store).
    /// Group F/G use this to spot dead writes.
    MovRegDst(u8),
    /// `lea reg, [...]` — dst GPR, source memory operand computed
    /// arithmetically only. No memory is touched.
    LeaRegDst(u8),
    /// Anything else we could decode length for but not classify.
    Other,
}

/// Fully-decoded instruction effect record.
#[derive(Debug, Clone, Copy)]
pub(super) struct Insn {
    /// Bytes consumed by this instruction, including prefixes.
    pub len: usize,
    pub kind: Kind,
    /// GPR bitmap of registers written (`bit i = reg i`).
    pub writes: u16,
    /// GPR bitmap of registers read (including memory base/index for
    /// loads, LEA sources, and stores).
    pub reads: u16,
    /// True: this instruction writes to memory (store side effect).
    pub memory_store: bool,
    /// True: this instruction reads from memory (load side effect).
    /// Group E treats any memory touch as a barrier.
    pub memory_load: bool,
    /// True: EFLAGS is meaningfully modified. Blocks Group G removal
    /// even when the reg output is dead — a downstream flag consumer
    /// may exist that we can't cheaply prove absent.
    pub touches_flags: bool,
    /// True: jmp / call / ret / int / loop / jcc. Reads all regs and
    /// terminates every forward/backward analysis window.
    pub is_control_flow: bool,
    /// True: we could not classify this instruction. Callers treat as
    /// `writes = reads = R_ALL` and refuse to fold across it.
    pub is_opaque: bool,
}

impl Insn {
    pub(super) fn opaque(len: usize) -> Self {
        Insn {
            len: len.max(1),
            kind: Kind::Other,
            writes: R_ALL,
            reads: R_ALL,
            memory_store: false,
            memory_load: false,
            touches_flags: true,
            is_control_flow: false,
            is_opaque: true,
        }
    }
}

/// Decode the instruction at `pos` in `bytecode` for `bitness`.
///
/// Returns None only when `pos` is past end. The caller then stops
/// the walk. Every recognised shape returns a full [`Insn`] record;
/// anything else falls back to an [`Insn::opaque`] with a best-effort
/// length so the caller's walk keeps making forward progress.
pub(super) fn decode(bytecode: &[u8], pos: usize, bitness: Bitness) -> Option<Insn> {
    if pos >= bytecode.len() {
        return None;
    }
    // Length is always taken from the shared decoder — never guessed
    // from the classifier below, so a shape we classify with the wrong
    // number of bytes can never silently misalign the caller's walk.
    let len_via_decoder = instruction_length(bytecode, pos, bitness);

    // Peel legacy prefixes; we only care about which ones appeared for
    // operand-size (66h) resolution.
    let mut p = pos;
    let mut has_66 = false;
    loop {
        match bytecode.get(p).copied() {
            Some(0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65) => p += 1,
            Some(0x67 | 0xF0 | 0xF2 | 0xF3) => p += 1,
            Some(0x66) => {
                has_66 = true;
                p += 1;
            }
            _ => break,
        }
    }
    let (rex, opos) = read_rex(bytecode, p, bitness);
    let rex_b = rex.map(|r| (r & 1) * 8).unwrap_or(0);
    let rex_r = rex.map(|r| ((r >> 2) & 1) * 8).unwrap_or(0);
    let rex_x = rex.map(|r| ((r >> 1) & 1) * 8).unwrap_or(0);

    let op = *bytecode.get(opos).unwrap_or(&0);
    let modrm_pos = opos + 1;

    // -----------------------------------------------------------------
    // Control flow: JMP/CALL/RET/JCC/LOOP/INT.
    // -----------------------------------------------------------------
    if matches!(
        op,
        0xC2 | 0xC3 | 0xCA | 0xCB | 0xCC | 0xCD | 0xCE | 0xCF | 0xE0..=0xE3 | 0xE8 | 0xE9 | 0xEB | 0x70..=0x7F
    ) {
        return Some(control_flow_insn(len_via_decoder.unwrap_or(1).max(1)));
    }
    // Two-byte 0F escapes.
    if op == 0x0F {
        if let Some(0x80..=0x8F) = bytecode.get(opos + 1).copied() {
            return Some(control_flow_insn(len_via_decoder.unwrap_or(1).max(1)));
        }
        if let Some(0x1F) = bytecode.get(opos + 1).copied() {
            return Some(nop_insn(len_via_decoder.unwrap_or(3).max(1)));
        }
        return Some(Insn::opaque(len_via_decoder.unwrap_or(1)));
    }
    // FF group — JMP/CALL indirect + INC/DEC/PUSH r/m.
    if op == 0xFF {
        let modrm = *bytecode.get(modrm_pos).unwrap_or(&0);
        let subop = (modrm >> 3) & 0x07;
        if matches!(subop, 2..=5) {
            return Some(control_flow_insn(len_via_decoder.unwrap_or(2).max(1)));
        }
        return Some(decode_ff_group(bytecode, pos, opos, modrm_pos, rex_b, len_via_decoder));
    }

    // -----------------------------------------------------------------
    // Single-byte NOP (0x90) and PUSH/POP reg (0x50..=0x5F).
    // -----------------------------------------------------------------
    if op == 0x90 && rex.is_none() {
        return Some(nop_insn(opos + 1 - pos));
    }
    if (0x50..=0x57).contains(&op) {
        let reg = (op - 0x50) | rex_b;
        return Some(Insn {
            len: opos + 1 - pos,
            kind: Kind::Other,
            writes: 1 << 4, // rsp
            reads: (1u16 << reg) | (1u16 << 4),
            memory_store: true,
            memory_load: false,
            touches_flags: false,
            is_control_flow: false,
            is_opaque: false,
        });
    }
    if (0x58..=0x5F).contains(&op) {
        let reg = (op - 0x58) | rex_b;
        return Some(Insn {
            len: opos + 1 - pos,
            kind: Kind::Other,
            writes: (1u16 << reg) | (1u16 << 4),
            reads: 1u16 << 4,
            memory_store: false,
            memory_load: true,
            touches_flags: false,
            is_control_flow: false,
            is_opaque: false,
        });
    }

    // -----------------------------------------------------------------
    // Group 1 imm — 0x83 /n imm8, 0x81 /n imm16/32.
    // -----------------------------------------------------------------
    if op == 0x83 || op == 0x81 {
        return Some(decode_group1_imm(
            bytecode,
            pos,
            opos,
            modrm_pos,
            rex_b,
            has_66,
            op == 0x83,
            len_via_decoder,
        ));
    }

    // -----------------------------------------------------------------
    // F6 / F7 group — TEST/NOT/NEG/MUL/IMUL/DIV/IDIV.
    // -----------------------------------------------------------------
    if op == 0xF7 {
        return Some(decode_f7_group(bytecode, pos, modrm_pos, rex_b, len_via_decoder));
    }
    if op == 0xF6 {
        return Some(Insn::opaque(len_via_decoder.unwrap_or(2)));
    }

    // -----------------------------------------------------------------
    // MOV forms.
    // -----------------------------------------------------------------
    if op == 0x89 {
        return Some(decode_mov_89(
            bytecode,
            pos,
            modrm_pos,
            rex_r,
            rex_b,
            rex_x,
            len_via_decoder,
        ));
    }
    if op == 0x8B {
        return Some(decode_mov_8b(
            bytecode,
            pos,
            modrm_pos,
            rex_r,
            rex_b,
            rex_x,
            len_via_decoder,
        ));
    }
    if (0xB8..=0xBF).contains(&op) {
        let reg = (op - 0xB8) | rex_b;
        return Some(Insn {
            len: len_via_decoder.unwrap_or(2).max(1),
            kind: Kind::MovRegDst(reg),
            writes: 1u16 << reg,
            reads: R_NONE,
            memory_store: false,
            memory_load: false,
            touches_flags: false,
            is_control_flow: false,
            is_opaque: false,
        });
    }
    if op == 0xC7 {
        return Some(decode_mov_c7(bytecode, pos, modrm_pos, rex_b, has_66, len_via_decoder));
    }

    // -----------------------------------------------------------------
    // LEA r, [mem].
    // -----------------------------------------------------------------
    if op == 0x8D {
        return Some(decode_lea(
            bytecode,
            pos,
            modrm_pos,
            rex_r,
            rex_b,
            rex_x,
            len_via_decoder,
        ));
    }

    // Fallback: opaque with best-effort length.
    Some(Insn::opaque(len_via_decoder.unwrap_or(1)))
}

/// Common `Insn` shape for a control-flow terminator: reads/writes all
/// GPRs (conservatively — we can't cheaply prove which are live at the
/// jump target), and terminates every forward/backward analysis window.
fn control_flow_insn(len: usize) -> Insn {
    Insn {
        len,
        kind: Kind::Other,
        writes: R_ALL,
        reads: R_ALL,
        memory_store: false,
        memory_load: false,
        touches_flags: false,
        is_control_flow: true,
        is_opaque: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mov_reg_reg_x64_writes_dst_reads_src() {
        // mov rax, rcx = 48 89 C8 (0x89 rm=0 reg=1)
        let insn = decode(&[0x48, 0x89, 0xC8], 0, Bitness::X64).unwrap();
        assert!(matches!(insn.kind, Kind::MovRegDst(0)));
        assert_eq!(insn.writes, 1 << 0);
        assert_eq!(insn.reads, 1 << 1);
        assert!(!insn.memory_load && !insn.memory_store);
    }

    #[test]
    fn mov_reg_mem_marks_memory_load() {
        // mov rax, [rbx] = 48 8B 03
        let insn = decode(&[0x48, 0x8B, 0x03], 0, Bitness::X64).unwrap();
        assert!(matches!(insn.kind, Kind::MovRegDst(0)));
        assert_eq!(insn.reads, 1 << 3); // rbx
        assert!(insn.memory_load);
    }

    #[test]
    fn mov_mem_reg_marks_memory_store() {
        // mov [rbx], rax = 48 89 03
        let insn = decode(&[0x48, 0x89, 0x03], 0, Bitness::X64).unwrap();
        assert!(insn.memory_store);
        assert_eq!(insn.writes, R_NONE);
    }

    #[test]
    fn add_reg_imm8_decodes_imm() {
        // add rax, 5 = 48 83 C0 05
        let insn = decode(&[0x48, 0x83, 0xC0, 0x05], 0, Bitness::X64).unwrap();
        assert!(matches!(insn.kind, Kind::AddRegImm { reg: 0, imm: 5 }));
    }

    #[test]
    fn add_reg_imm8_negative_sign_extends() {
        // add rax, -5 = 48 83 C0 FB
        let insn = decode(&[0x48, 0x83, 0xC0, 0xFB], 0, Bitness::X64).unwrap();
        assert!(matches!(insn.kind, Kind::AddRegImm { reg: 0, imm: -5 }));
    }

    #[test]
    fn ret_marks_control_flow() {
        let insn = decode(&[0xC3], 0, Bitness::X64).unwrap();
        assert!(insn.is_control_flow);
    }

    #[test]
    fn inc_reg_ff_form_writes_and_reads_reg() {
        // inc rax = 48 FF C0
        let insn = decode(&[0x48, 0xFF, 0xC0], 0, Bitness::X64).unwrap();
        assert!(matches!(insn.kind, Kind::IncReg(0)));
        assert_eq!(insn.writes, 1);
        assert_eq!(insn.reads, 1);
    }
}
