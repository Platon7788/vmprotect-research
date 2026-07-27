//! Extended VMP-semantic matchers -- Commit L additions, extended
//! further by Commit O.
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
//! `AUDIT_REPORT.md` Q2 / `RESEARCH_GAPS.md` §3.1 (Commit L), plus
//! Commit O's `Ret` (short-body `Vjmp` variant), `Vemit` (raw-literal
//! jump escape, standing in for the statelessly-identical `Vexec`),
//! and `Popstk`/`Pushstk` (CTX-free VM-stack-to-VM-stack transfers).

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

// ---------------------------------------------------------------------
// Group D: `Ret` -- real x86 return via VM (Commit O).
//
// Public writeups (r0da part 3, cyber.wtf) describe the VMP `Ret`
// handler as byte-identical to `Vjmp` (load a VM-stack slot, bump VSP,
// indirect-jump to the loaded value) but consistently the *shortest*
// body in the dispatch table -- it just pops a return address and
// goes, with none of the operand-decrypt or register-role bookkeeping
// a real jump-target handler carries. We approximate that with a
// body-length ceiling plus the `!has_xor_reg_imm` decrypt-absence
// signal already used for `Vemit` below. `classify()` tries this
// BEFORE `is_vjmp_shape` so a short, undecorated body is claimed here
// first; a longer body falls through to the `Vjmp` label as before.
// ---------------------------------------------------------------------

/// Body-length ceiling for `Ret`: public writeups describe it as the
/// shortest handler in the table (load, adjust, jump -- nothing else).
const RET_MAX_LEN: usize = 30;

pub(super) fn is_ret_shape(bytecode: &[u8]) -> bool {
    bytecode.len() < RET_MAX_LEN && super::is_vjmp_shape(bytecode) && !has_xor_reg_imm(bytecode)
}

// ---------------------------------------------------------------------
// Group E: `Vemit` -- raw x86 emit / escape (Commit O).
//
// `Vexec` (nested VM entry) is statelessly indistinguishable from this
// shape -- both are "indirect jump to a VIP-stream-derived address with
// no table lookup" from a single-handler-body view -- so we fold it
// into `Vemit` per the module doc; a future cross-handler pass that
// can tell "lands in a real code section" (Vemit) from "lands on
// another dispatcher prologue" (Vexec) can split it out.
// ---------------------------------------------------------------------

/// Vemit: load-indirect (VIP stream) + indirect JMP, but with NEITHER
/// of the two signals an ordinary table-driven jump handler carries:
/// no XOR-decrypt of the loaded operand, no ADD-from-memory table
/// lookup. `classify()` runs this AFTER `is_vjmp_shape` -- the ordinary
/// jump shape is far more common, so it gets first claim on any body
/// that happens to satisfy both.
pub(super) fn is_vemit_shape(bytecode: &[u8]) -> bool {
    has_load_indirect(bytecode)
        && has_indirect_jmp(bytecode)
        && !has_xor_reg_imm(bytecode)
        && !has_add_reg_mem(bytecode)
}

// ---------------------------------------------------------------------
// Group F: `Popstk` / `Pushstk` -- VM-stack <-> VM-stack transfers
// (Commit O).
//
// Same load/adjust/store skeleton as the register `Pop`/`Push` family,
// but strictly narrower: neither direction touches a CTX slot at all
// (`!has_store_disp && !has_load_disp`), so the transfer stays entirely
// within the VM stack.
//
// `Popstk` is disjoint from `Popreg` (`Popreg` *requires*
// `has_store_disp` via its `is_pop_shape` base check, `Popstk` forbids
// it), so it's reachable through `classify()` right ahead of the
// generic `Pop` fallback, same as any other strict subset.
//
// `Pushstk` is NOT similarly disjoint from `PushImm`: `PushImm` never
// checks `has_store_disp` at all, so whenever `Pushstk`'s shape holds,
// `PushImm`'s (weaker) shape holds too. `classify()` runs `PushImm`
// first (see `handler_semantic.rs` module doc, "`PushImm` vs
// `Pushstk`"), so `Pushstk` is a future-extension slot in the same
// vein as `Str` -- exercised directly against this matcher fn rather
// than through `classify()`.
// ---------------------------------------------------------------------

pub(super) fn is_popstk_shape(bytecode: &[u8]) -> bool {
    has_load_indirect(bytecode)
        && has_add_reg_imm8(bytecode)
        && has_store_indirect(bytecode)
        && !has_store_disp(bytecode)
        && !has_load_disp(bytecode)
}

pub(super) fn is_pushstk_shape(bytecode: &[u8]) -> bool {
    has_load_indirect(bytecode)
        && has_sub_reg_imm8(bytecode)
        && has_store_indirect(bytecode)
        && !has_store_disp(bytecode)
        && !has_load_disp(bytecode)
}

#[cfg(test)]
#[path = "handler_semantic_ext_tests.rs"]
mod tests;
