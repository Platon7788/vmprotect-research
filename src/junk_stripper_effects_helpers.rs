//! Per-opcode decoding helpers for `junk_stripper_effects`.
//!
//! Split out via `#[path]` include (see `mod helpers` in
//! `junk_stripper_effects.rs`) purely so the parent file stays under
//! the project's 500-line ceiling. All helpers are `pub(super)`
//! because their only caller is the top-level `decode` function in
//! the parent.
//!
//! Each helper takes a `bytecode` slice, the offsets `_pos` / `opos`
//! / `modrm_pos` already peeled off legacy prefixes and REX, the
//! relevant REX-bit extensions, and a `len_hint` from the shared
//! `instruction_length` decoder. `len_hint == None` means the shared
//! decoder didn't recognise this opcode: helpers still produce a
//! best-effort length so the caller never stalls, but tag the result
//! `is_opaque = true` for the memory-form / unhandled subop paths.

use super::{Insn, Kind, R_ALL, R_NONE};

pub(super) fn nop_insn(len: usize) -> Insn {
    Insn {
        len: len.max(1),
        kind: Kind::Other,
        writes: R_NONE,
        reads: R_NONE,
        memory_store: false,
        memory_load: false,
        touches_flags: false,
        is_control_flow: false,
        is_opaque: false,
    }
}

pub(super) fn decode_ff_group(
    bytecode: &[u8],
    _pos: usize,
    _opos: usize,
    modrm_pos: usize,
    rex_b: u8,
    len_hint: Option<usize>,
) -> Insn {
    let modrm = match bytecode.get(modrm_pos).copied() {
        Some(m) => m,
        None => return Insn::opaque(len_hint.unwrap_or(2)),
    };
    let subop = (modrm >> 3) & 0x07;
    let mode = (modrm >> 6) & 0x03;
    let rm = modrm & 0x07;
    let l = len_hint.unwrap_or(2).max(1);
    // Only mod=11 shapes give clean per-reg effects; mem forms bail.
    if mode != 0b11 {
        return Insn {
            len: l,
            kind: Kind::Other,
            writes: R_ALL,
            reads: R_ALL,
            memory_store: matches!(subop, 0 | 1 | 6),
            memory_load: true,
            touches_flags: true,
            is_control_flow: false,
            is_opaque: true,
        };
    }
    let reg = rm | rex_b;
    let bit = 1u16 << reg;
    match subop {
        0 => Insn {
            len: l,
            kind: Kind::IncReg(reg),
            writes: bit,
            reads: bit,
            memory_store: false,
            memory_load: false,
            touches_flags: true,
            is_control_flow: false,
            is_opaque: false,
        },
        1 => Insn {
            len: l,
            kind: Kind::DecReg(reg),
            writes: bit,
            reads: bit,
            memory_store: false,
            memory_load: false,
            touches_flags: true,
            is_control_flow: false,
            is_opaque: false,
        },
        6 => Insn {
            // PUSH reg (mod=11 form) — reads reg + rsp, writes rsp,
            // touches memory (store).
            len: l,
            kind: Kind::Other,
            writes: 1u16 << 4,
            reads: bit | (1u16 << 4),
            memory_store: true,
            memory_load: false,
            touches_flags: false,
            is_control_flow: false,
            is_opaque: false,
        },
        _ => Insn::opaque(l),
    }
}

pub(super) fn decode_group1_imm(
    bytecode: &[u8],
    _pos: usize,
    opos: usize,
    modrm_pos: usize,
    rex_b: u8,
    has_66: bool,
    is_imm8: bool,
    len_hint: Option<usize>,
) -> Insn {
    let modrm = match bytecode.get(modrm_pos).copied() {
        Some(m) => m,
        None => return Insn::opaque(len_hint.unwrap_or(3)),
    };
    let mode = (modrm >> 6) & 0x03;
    let subop = (modrm >> 3) & 0x07;
    let rm = modrm & 0x07;
    let l = len_hint.unwrap_or(if is_imm8 {
        3
    } else if has_66 {
        5
    } else {
        7
    });
    if mode != 0b11 {
        return Insn {
            len: l.max(1),
            kind: Kind::Other,
            writes: R_ALL,
            reads: R_ALL,
            memory_store: subop != 7,
            memory_load: true,
            touches_flags: true,
            is_control_flow: false,
            is_opaque: true,
        };
    }
    let reg = rm | rex_b;
    let bit = 1u16 << reg;
    let imm: i32 = if is_imm8 {
        (*bytecode.get(opos + 2).unwrap_or(&0) as i8) as i32
    } else if has_66 {
        let b0 = *bytecode.get(opos + 2).unwrap_or(&0) as i32;
        let b1 = *bytecode.get(opos + 3).unwrap_or(&0) as i32;
        ((b1 << 8) | b0) as i16 as i32
    } else {
        let mut v: i32 = 0;
        for k in 0..4 {
            v |= (*bytecode.get(opos + 2 + k).unwrap_or(&0) as i32) << (k * 8);
        }
        v
    };
    let kind = match subop {
        0 => Kind::AddRegImm { reg, imm },
        5 => Kind::SubRegImm { reg, imm },
        6 => Kind::XorRegImm { reg, imm },
        _ => Kind::Other,
    };
    // subop 7 = CMP: reads the reg but writes nothing (only EFLAGS).
    let (writes, reads) = if subop == 7 { (R_NONE, bit) } else { (bit, bit) };
    Insn {
        len: l.max(1),
        kind,
        writes,
        reads,
        memory_store: false,
        memory_load: false,
        touches_flags: true,
        is_control_flow: false,
        is_opaque: false,
    }
}

pub(super) fn decode_f7_group(
    bytecode: &[u8],
    _pos: usize,
    modrm_pos: usize,
    rex_b: u8,
    len_hint: Option<usize>,
) -> Insn {
    let modrm = match bytecode.get(modrm_pos).copied() {
        Some(m) => m,
        None => return Insn::opaque(len_hint.unwrap_or(2)),
    };
    let subop = (modrm >> 3) & 0x07;
    let mode = (modrm >> 6) & 0x03;
    let rm = modrm & 0x07;
    let l = len_hint.unwrap_or(2).max(1);
    if mode != 0b11 {
        return Insn::opaque(l);
    }
    let reg = rm | rex_b;
    let bit = 1u16 << reg;
    match subop {
        2 => Insn {
            // NOT r — bit-flip, no flag touch.
            len: l,
            kind: Kind::NotReg(reg),
            writes: bit,
            reads: bit,
            memory_store: false,
            memory_load: false,
            touches_flags: false,
            is_control_flow: false,
            is_opaque: false,
        },
        3 => Insn {
            // NEG r — writes reg + flags.
            len: l,
            kind: Kind::NegReg(reg),
            writes: bit,
            reads: bit,
            memory_store: false,
            memory_load: false,
            touches_flags: true,
            is_control_flow: false,
            is_opaque: false,
        },
        _ => Insn::opaque(l),
    }
}

pub(super) fn decode_mov_89(
    bytecode: &[u8],
    _pos: usize,
    modrm_pos: usize,
    rex_r: u8,
    rex_b: u8,
    rex_x: u8,
    len_hint: Option<usize>,
) -> Insn {
    let modrm = match bytecode.get(modrm_pos).copied() {
        Some(m) => m,
        None => return Insn::opaque(len_hint.unwrap_or(2)),
    };
    let mode = (modrm >> 6) & 0x03;
    let reg_field = ((modrm >> 3) & 0x07) | rex_r;
    let rm_field = (modrm & 0x07) | rex_b;
    let l = len_hint.unwrap_or(2).max(1);
    if mode == 0b11 {
        return Insn {
            len: l,
            kind: Kind::MovRegDst(rm_field),
            writes: 1u16 << rm_field,
            reads: 1u16 << reg_field,
            memory_store: false,
            memory_load: false,
            touches_flags: false,
            is_control_flow: false,
            is_opaque: false,
        };
    }
    let mem_reads = mem_operand_regs(bytecode, modrm_pos, rex_b, rex_x);
    Insn {
        len: l,
        kind: Kind::Other,
        writes: R_NONE,
        reads: (1u16 << reg_field) | mem_reads,
        memory_store: true,
        memory_load: false,
        touches_flags: false,
        is_control_flow: false,
        is_opaque: false,
    }
}

pub(super) fn decode_mov_8b(
    bytecode: &[u8],
    _pos: usize,
    modrm_pos: usize,
    rex_r: u8,
    rex_b: u8,
    rex_x: u8,
    len_hint: Option<usize>,
) -> Insn {
    let modrm = match bytecode.get(modrm_pos).copied() {
        Some(m) => m,
        None => return Insn::opaque(len_hint.unwrap_or(2)),
    };
    let mode = (modrm >> 6) & 0x03;
    let reg_field = ((modrm >> 3) & 0x07) | rex_r;
    let rm_field = (modrm & 0x07) | rex_b;
    let l = len_hint.unwrap_or(2).max(1);
    if mode == 0b11 {
        return Insn {
            len: l,
            kind: Kind::MovRegDst(reg_field),
            writes: 1u16 << reg_field,
            reads: 1u16 << rm_field,
            memory_store: false,
            memory_load: false,
            touches_flags: false,
            is_control_flow: false,
            is_opaque: false,
        };
    }
    let mem_reads = mem_operand_regs(bytecode, modrm_pos, rex_b, rex_x);
    Insn {
        len: l,
        kind: Kind::MovRegDst(reg_field),
        writes: 1u16 << reg_field,
        reads: mem_reads,
        memory_store: false,
        memory_load: true,
        touches_flags: false,
        is_control_flow: false,
        is_opaque: false,
    }
}

pub(super) fn decode_mov_c7(
    bytecode: &[u8],
    _pos: usize,
    modrm_pos: usize,
    rex_b: u8,
    _has_66: bool,
    len_hint: Option<usize>,
) -> Insn {
    let modrm = match bytecode.get(modrm_pos).copied() {
        Some(m) => m,
        None => return Insn::opaque(len_hint.unwrap_or(6)),
    };
    let mode = (modrm >> 6) & 0x03;
    let rm_field = (modrm & 0x07) | rex_b;
    let l = len_hint.unwrap_or(6).max(1);
    if mode == 0b11 {
        return Insn {
            len: l,
            kind: Kind::MovRegDst(rm_field),
            writes: 1u16 << rm_field,
            reads: R_NONE,
            memory_store: false,
            memory_load: false,
            touches_flags: false,
            is_control_flow: false,
            is_opaque: false,
        };
    }
    Insn {
        len: l,
        kind: Kind::Other,
        writes: R_NONE,
        reads: R_ALL,
        memory_store: true,
        memory_load: false,
        touches_flags: false,
        is_control_flow: false,
        is_opaque: true,
    }
}

pub(super) fn decode_lea(
    bytecode: &[u8],
    _pos: usize,
    modrm_pos: usize,
    rex_r: u8,
    rex_b: u8,
    rex_x: u8,
    len_hint: Option<usize>,
) -> Insn {
    let modrm = match bytecode.get(modrm_pos).copied() {
        Some(m) => m,
        None => return Insn::opaque(len_hint.unwrap_or(2)),
    };
    let mode = (modrm >> 6) & 0x03;
    let reg_field = ((modrm >> 3) & 0x07) | rex_r;
    let l = len_hint.unwrap_or(2).max(1);
    if mode == 0b11 {
        return Insn::opaque(l);
    }
    let mem_reads = mem_operand_regs(bytecode, modrm_pos, rex_b, rex_x);
    Insn {
        len: l,
        kind: Kind::LeaRegDst(reg_field),
        writes: 1u16 << reg_field,
        reads: mem_reads,
        // LEA computes an address only — never touches memory. This
        // is exactly the property that makes it a Group F candidate.
        memory_store: false,
        memory_load: false,
        touches_flags: false,
        is_control_flow: false,
        is_opaque: false,
    }
}

/// Extract base+index register bitmap from a ModR/M memory operand
/// (mode != 11). Returns R_NONE when the operand has no register base
/// (RIP-relative on x64, disp32-abs on x86, or SIB with base=none).
fn mem_operand_regs(bytecode: &[u8], modrm_pos: usize, rex_b: u8, rex_x: u8) -> u16 {
    let modrm = match bytecode.get(modrm_pos).copied() {
        Some(m) => m,
        None => return R_NONE,
    };
    let mode = (modrm >> 6) & 0x03;
    let rm = modrm & 0x07;
    if mode == 0b11 {
        return R_NONE;
    }
    if rm != 4 {
        if mode == 0b00 && rm == 5 {
            return R_NONE;
        }
        return 1u16 << (rm | rex_b);
    }
    let sib = match bytecode.get(modrm_pos + 1).copied() {
        Some(s) => s,
        None => return R_NONE,
    };
    let base_field = sib & 0x07;
    let index_field = (sib >> 3) & 0x07;
    let mut regs = R_NONE;
    let base_absent = mode == 0b00 && base_field == 5;
    if !base_absent {
        regs |= 1u16 << (base_field | rex_b);
    }
    if index_field != 4 {
        regs |= 1u16 << (index_field | rex_x);
    }
    regs
}
