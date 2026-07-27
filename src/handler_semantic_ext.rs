//! Extended VMP-semantic matchers -- Commit L additions.
//!
//! Split out of `handler_semantic.rs` via `#[path]` include so the impl
//! file stays under the project's 500-line ceiling (see `CLAUDE.md`),
//! same convention as `junk_stripper.rs` / `junk_stripper_length.rs`.
//! The submodule is private (`pub(super)` at its edges) -- it exists
//! only to serve `SemanticMatcher::classify`.
//!
//! Covers the arithmetic-base (`Mul`/`Imul`/`Div`/`Idiv`), shift/rotate
//! (`Shl`/`Shr`/`Shld`/`Shrd`/`Rcl`/`Rcr`), and system/escape
//! (`Lockor`/`VpushCr0`/`VpushCr3`/`Vnop`) families from
//! `AUDIT_REPORT.md` Q2 / `RESEARCH_GAPS.md` §3.1.
//!
//! Skipped in this commit (see `handler_semantic.rs` module doc for
//! the full rationale): `Vemit` and `Vexec` -- both need cross-handler
//! data-flow (is the indirect jump target a VIP-stream literal, or does
//! this handler recurse into a nested VM context) that a stateless,
//! single-handler-body matcher can't establish without false positives
//! against the existing `Vjmp`/`Ldd` shapes.

use super::*;

// ---------------------------------------------------------------------
// Group A: arithmetic base -- `0xF7 /n`, mod=11 (register direct).
//
// Group-3 opcode extension (`/n` = ModR/M reg field): /4 = MUL, /5 =
// IMUL, /6 = DIV, /7 = IDIV. /2 = NOT is already handled by
// `count_not_ops` in the parent module and never overlaps these
// ranges, so no extra guard is needed against the NAND/NOR matchers.
// ---------------------------------------------------------------------

/// Presence of `0xF7 /n` (register-direct, `mod=11`) with the ModR/M
/// byte's reg field selecting one of `[lo, hi]` -- both ends inclusive
/// and always 8-wide (one `rm` byte per fixed `reg` value).
fn has_f7_reg(bytecode: &[u8], lo: u8, hi: u8) -> bool {
    (0..bytecode.len()).any(|i| {
        let p = skip_rex(bytecode, i);
        bytecode.get(p).copied() == Some(0xF7) && matches!(bytecode.get(p + 1).copied(), Some(b) if b >= lo && b <= hi)
    })
}

fn has_mul_op(bytecode: &[u8]) -> bool {
    has_f7_reg(bytecode, 0xE0, 0xE7)
}

fn has_imul_op(bytecode: &[u8]) -> bool {
    has_f7_reg(bytecode, 0xE8, 0xEF)
}

fn has_div_op(bytecode: &[u8]) -> bool {
    has_f7_reg(bytecode, 0xF0, 0xF7)
}

fn has_idiv_op(bytecode: &[u8]) -> bool {
    has_f7_reg(bytecode, 0xF8, 0xFF)
}

/// Mul/Imul/Div/Idiv share the load-VSP -> `F7 /n` -> store-VSP shape;
/// only the ModR/M reg field distinguishes which one fired.
pub(super) fn is_mul_shape(bytecode: &[u8]) -> bool {
    has_load_indirect(bytecode) && has_mul_op(bytecode) && has_store_indirect(bytecode)
}

pub(super) fn is_imul_shape(bytecode: &[u8]) -> bool {
    has_load_indirect(bytecode) && has_imul_op(bytecode) && has_store_indirect(bytecode)
}

pub(super) fn is_div_shape(bytecode: &[u8]) -> bool {
    has_load_indirect(bytecode) && has_div_op(bytecode) && has_store_indirect(bytecode)
}

pub(super) fn is_idiv_shape(bytecode: &[u8]) -> bool {
    has_load_indirect(bytecode) && has_idiv_op(bytecode) && has_store_indirect(bytecode)
}

// ---------------------------------------------------------------------
// Group B: shifts / rotates -- `0xD3 /n` (by CL) or `0xC1 /n imm8`,
// plus the two-byte `SHLD`/`SHRD` pair which has no `/n` subcode.
// ---------------------------------------------------------------------

/// Presence of `0xD3 /n` or `0xC1 /n` (register-direct) with the
/// ModR/M reg field selecting `[lo, hi]`. Both opcodes share the same
/// `/n` layout for SHL/SHR/RCL/RCR; `0xC1` additionally carries a
/// trailing imm8 we don't need to skip over since we only check for
/// presence, not walk past it.
fn has_shift_op(bytecode: &[u8], lo: u8, hi: u8) -> bool {
    (0..bytecode.len()).any(|i| {
        let p = skip_rex(bytecode, i);
        match bytecode.get(p).copied() {
            Some(0xD3) | Some(0xC1) => {
                matches!(bytecode.get(p + 1).copied(), Some(b) if b >= lo && b <= hi)
            }
            _ => false,
        }
    })
}

fn has_rcl_op(bytecode: &[u8]) -> bool {
    has_shift_op(bytecode, 0xD0, 0xD7)
}

fn has_rcr_op(bytecode: &[u8]) -> bool {
    has_shift_op(bytecode, 0xD8, 0xDF)
}

fn has_shl_op(bytecode: &[u8]) -> bool {
    has_shift_op(bytecode, 0xE0, 0xE7)
}

fn has_shr_op(bytecode: &[u8]) -> bool {
    has_shift_op(bytecode, 0xE8, 0xEF)
}

fn has_shld_op(bytecode: &[u8]) -> bool {
    contains_pair(bytecode, 0x0F, 0xA4) || contains_pair(bytecode, 0x0F, 0xA5)
}

fn has_shrd_op(bytecode: &[u8]) -> bool {
    contains_pair(bytecode, 0x0F, 0xAC) || contains_pair(bytecode, 0x0F, 0xAD)
}

/// Shifts/rotates share load-VSP -> op -> PUSHFQ (flags affected) ->
/// store-VSP. The PUSHFQ requirement is what keeps these from
/// over-firing on an unrelated `Ldd`/`Pop` body that happens to
/// contain a stray `0xD3`/`0xC1` byte pair from an unrelated operand.
pub(super) fn is_shl_shape(bytecode: &[u8]) -> bool {
    has_load_indirect(bytecode) && has_shl_op(bytecode) && has_pushfq(bytecode) && has_store_indirect(bytecode)
}

pub(super) fn is_shr_shape(bytecode: &[u8]) -> bool {
    has_load_indirect(bytecode) && has_shr_op(bytecode) && has_pushfq(bytecode) && has_store_indirect(bytecode)
}

pub(super) fn is_shld_shape(bytecode: &[u8]) -> bool {
    has_load_indirect(bytecode) && has_shld_op(bytecode) && has_pushfq(bytecode) && has_store_indirect(bytecode)
}

pub(super) fn is_shrd_shape(bytecode: &[u8]) -> bool {
    has_load_indirect(bytecode) && has_shrd_op(bytecode) && has_pushfq(bytecode) && has_store_indirect(bytecode)
}

pub(super) fn is_rcl_shape(bytecode: &[u8]) -> bool {
    has_load_indirect(bytecode) && has_rcl_op(bytecode) && has_pushfq(bytecode) && has_store_indirect(bytecode)
}

pub(super) fn is_rcr_shape(bytecode: &[u8]) -> bool {
    has_load_indirect(bytecode) && has_rcr_op(bytecode) && has_pushfq(bytecode) && has_store_indirect(bytecode)
}

// ---------------------------------------------------------------------
// Group C: system / escape.
// ---------------------------------------------------------------------

/// `LOCK OR`: the `0xF0` LOCK prefix directly ahead of either
/// `OR reg, reg` (`0x09`/`0x0B`, mod=11) or `OR reg, imm8`
/// (`0x83 /1`, mod=11, reg field = 1 -> ModR/M in `0xC8..=0xCF`). A
/// REX byte may sit between the LOCK prefix and the opcode (x64
/// prefix ordering: LOCK, then REX, then opcode).
pub(super) fn is_lockor_shape(bytecode: &[u8]) -> bool {
    (0..bytecode.len()).any(|i| {
        if bytecode.get(i).copied() != Some(0xF0) {
            return false;
        }
        let p = skip_rex(bytecode, i + 1);
        match bytecode.get(p).copied() {
            Some(0x09) | Some(0x0B) => bytecode
                .get(p + 1)
                .copied()
                .map(|m| (m & 0xC0) == 0xC0)
                .unwrap_or(false),
            Some(0x83) => bytecode
                .get(p + 1)
                .copied()
                .map(|m| (m & 0xC0) == 0xC0 && (m & 0x38) == 0x08)
                .unwrap_or(false),
            _ => false,
        }
    })
}

/// `MOV reg, cr0` = `0x0F 0x20` with ModR/M `mod=11, reg=0`
/// (control-register-move ModR/M always uses mod=11 regardless of
/// the encoded bits -- Intel SDM Vol 2A, MOV--Move to/from Control
/// Registers -- so we still gate on it to avoid matching an unrelated
/// coincidental `0F 20` pair from a differently-decoded stream).
fn has_mov_from_cr(bytecode: &[u8], cr_reg_field: u8) -> bool {
    bytecode
        .windows(3)
        .any(|w| w[0] == 0x0F && w[1] == 0x20 && (w[2] & 0xC0) == 0xC0 && (w[2] & 0x38) == (cr_reg_field << 3))
}

/// Distinctive 3-byte opcode -- no load/store shape needed, same
/// single-fingerprint tier as `Rdtsc`/`Cpuid` in the parent module.
pub(super) fn is_vpush_cr0_shape(bytecode: &[u8]) -> bool {
    has_mov_from_cr(bytecode, 0)
}

pub(super) fn is_vpush_cr3_shape(bytecode: &[u8]) -> bool {
    has_mov_from_cr(bytecode, 3)
}

/// Vnop: the dispatcher tail JMP and NOTHING else -- no indirect load,
/// no CTX-disp load, no indirect/disp store, no VSP add/sub, no
/// reg-reg add. Stricter than `Vsetvsp` (which still allows the one
/// load-indirect VSP fetch); a body with a real load only ever matches
/// `Vsetvsp`, never this.
pub(super) fn is_vnop_shape(bytecode: &[u8]) -> bool {
    has_indirect_jmp(bytecode)
        && !has_load_indirect(bytecode)
        && !has_load_disp(bytecode)
        && !has_store_indirect(bytecode)
        && !has_store_disp(bytecode)
        && !has_add_reg_imm8(bytecode)
        && !has_sub_reg_imm8(bytecode)
        && !has_add_reg_reg(bytecode)
}

#[cfg(test)]
#[path = "handler_semantic_ext_tests.rs"]
mod tests;
